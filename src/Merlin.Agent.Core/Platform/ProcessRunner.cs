using System.Diagnostics;

namespace Merlin.Agent.Core.Platform;

/// <summary>What happened when a child process was run.</summary>
/// <param name="Started">Whether the process could be started at all.</param>
/// <param name="Exited">Whether it exited within its timeout.</param>
/// <param name="ExitCode">Its exit code, when it exited.</param>
/// <param name="StandardOutput">Everything it wrote to standard output.</param>
/// <param name="StandardError">Everything it wrote to standard error, or why it did not run.</param>
/// <param name="OutputComplete">
/// Whether standard output was read all the way to end-of-file.
/// <b>A truncated read must never be reported as a successful one.</b> The drain is bounded, so a
/// grandchild holding the pipe open leaves <see cref="StandardOutput"/> empty while the process
/// itself exited zero — and without this flag that is indistinguishable from a command that
/// printed nothing. It is not a theoretical difference: the firewall readings ask whether the
/// output CONTAINS a word, so an empty string is read as a definite "no", and the agent asserts
/// that a protection is OFF on a machine where it was merely never observed. Every caller's
/// contract is the opposite — a reading that could not be taken is <c>null</c>, which Merlin reads
/// as not observed.
/// <para>
/// Standard error is deliberately NOT part of this. It carries diagnostics, never a decision, and
/// a daemonising grandchild that holds only the error pipe open would otherwise blank a perfectly
/// good reading.
/// </para>
/// </param>
public sealed record ProcessOutcome(
    bool Started,
    bool Exited,
    int ExitCode,
    string StandardOutput,
    string StandardError,
    bool OutputComplete)
{
    /// <summary>
    /// Whether the process started, exited within its timeout, exited zero, and was read to the end.
    /// </summary>
    public bool Succeeded => Started && Exited && ExitCode == 0 && OutputComplete;
}

/// <summary>
/// THE way this agent runs a child process. One implementation, every caller.
/// </summary>
/// <remarks>
/// <para>
/// <b>Both pipes are drained at once, and every wait is bounded.</b> Reading one stream to the end
/// and then the other is the classic deadlock, and a timeout is no protection from it: a child that
/// fills the stderr buffer while the parent blocks on stdout can never exit, so the parent never
/// REACHES <c>WaitForExit</c> and hangs for good. Redirecting a stream and never reading it at all
/// is the same bug in its guaranteed rather than racy form. The buffer is 4 KB on Windows and 64 KB
/// on Unix, which a warning per query clears without trying.
/// </para>
/// <para>
/// <b>It is one type because it was three, and two of them were wrong.</b> The hazard was found and
/// fixed in the binary probe, and the same shape sat uncorrected in the osquery runner and the
/// command runner — one of them with the reasoning written out beside it and the other two without.
/// A correct implementation that has to be remembered is a correct implementation that will be
/// copied wrongly, so there is now nowhere to copy it from: add a call site instead.
/// </para>
/// <para>
/// <b>Why a hang here is not merely a dead run.</b> The agent holds the machine-wide lock for the
/// whole of a collection. A wedged child therefore holds that lock for ever, the updater can never
/// take it, and it can never put a broken agent back — so the machine stops reporting, permanently
/// and silently, which is indistinguishable from one that was never enrolled.
/// </para>
/// </remarks>
public static class ProcessRunner
{
    /// <summary>
    /// How long a drained pipe is given to reach end-of-file once the process itself has gone.
    /// </summary>
    /// <remarks>
    /// A grandchild that inherited the handles keeps the pipe open after its parent exits, so even
    /// this wait is bounded rather than trusting end-of-file to arrive.
    /// </remarks>
    private static readonly TimeSpan _drainGrace = TimeSpan.FromSeconds(5);

    /// <summary>Runs a command with its arguments passed individually.</summary>
    /// <remarks>
    /// <b>Arguments are a LIST, never a command line.</b> No shell is involved to interpret
    /// anything, so there is nothing for a value to inject into even if one ever stopped being a
    /// compile-time constant.
    /// </remarks>
    /// <param name="fileName">The executable.</param>
    /// <param name="arguments">Its arguments.</param>
    /// <param name="timeout">How long it may take.</param>
    /// <returns>What happened.</returns>
    public static ProcessOutcome Run(string fileName, IEnumerable<string> arguments, TimeSpan timeout)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentNullException.ThrowIfNull(arguments);

        ProcessStartInfo startInfo = Describe(fileName);

        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return Run(startInfo, timeout);
    }

    /// <summary>
    /// Runs a command whose arguments are already a single string.
    /// </summary>
    /// <remarks>
    /// For the one caller that has a literal argument string rather than a list. Prefer the list
    /// overload wherever the arguments are separable.
    /// </remarks>
    /// <param name="fileName">The executable.</param>
    /// <param name="arguments">Its argument string.</param>
    /// <param name="workingDirectory">The working directory, or null for the current one.</param>
    /// <param name="timeout">How long it may take.</param>
    /// <returns>What happened.</returns>
    public static ProcessOutcome Run(
        string fileName,
        string arguments,
        string? workingDirectory,
        TimeSpan timeout)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        ProcessStartInfo startInfo = Describe(fileName);
        startInfo.Arguments = arguments;

        if (!string.IsNullOrWhiteSpace(workingDirectory))
        {
            startInfo.WorkingDirectory = workingDirectory;
        }

        return Run(startInfo, timeout);
    }

    private static ProcessStartInfo Describe(string fileName) => new()
    {
        FileName = fileName,
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true,
    };

    private static ProcessOutcome Run(ProcessStartInfo startInfo, TimeSpan timeout)
    {
        try
        {
            using Process? process = Process.Start(startInfo);

            if (process is null)
            {
                return new ProcessOutcome(
                    false, false, 0, string.Empty, "The process could not be started.", false);
            }

            // Started before the wait, so neither pipe can fill and block the child. See the class
            // remarks: this ordering is the whole point of the type.
            Task<string> reading = process.StandardOutput.ReadToEndAsync();
            Task<string> failing = process.StandardError.ReadToEndAsync();

            if (!process.WaitForExit((int)timeout.TotalMilliseconds))
            {
                Terminate(process);

                // Killing it closes its ends of the pipes, so the reads complete rather than being
                // abandoned. Observed, then discarded: the verdict is already decided.
                Drain(reading);
                Drain(failing);

                return new ProcessOutcome(
                    true, false, 0, string.Empty, "It did not exit within the timeout.", false);
            }

            (bool complete, string output) = Drain(reading);
            (_, string error) = Drain(failing);

            return new ProcessOutcome(true, true, process.ExitCode, output, error, complete);
        }
        catch (Exception exception) when (exception is System.ComponentModel.Win32Exception
            or InvalidOperationException or IOException or UnauthorizedAccessException
            or AggregateException)
        {
            // The binary is not installed on this machine, or cannot be executed. The ordinary case
            // for a firewall front-end this distribution does not use.
            return new ProcessOutcome(false, false, 0, string.Empty, exception.Message, false);
        }
    }

    /// <summary>Ends a process that outstayed its timeout, and its children with it.</summary>
    private static void Terminate(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (Exception exception) when (exception is InvalidOperationException
            or System.ComponentModel.Win32Exception or NotSupportedException
            or AggregateException)
        {
            // Already gone, or the platform refused. The verdict is unchanged either way.
            //
            // AGGREGATEEXCEPTION IS THE ONE THAT IS NOT OBVIOUS, and leaving it out cost the whole
            // collection. Kill(entireProcessTree: true) walks the tree and collects the failures it
            // could not kill into an AggregateException — so ONE un-killable grandchild threw out
            // of here, skipped both drains below, unwound through the collection (which sits
            // outside UpdateTurn's fault boundary) and past Main's own filter, ending a scheduled
            // run in a stack trace. A process we merely failed to kill is not worth any of that:
            // it already outstayed its timeout and the verdict is already decided.
        }
    }

    /// <summary>
    /// Collects what a pipe carried, waiting only <see cref="_drainGrace"/> for it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Never throws and never waits indefinitely.</b> A read that faulted when the process was
    /// killed, or that is still blocked on a handle a grandchild holds open, contributes no output
    /// — which is the honest answer, and strictly better than the caller hanging on it.
    /// </para>
    /// <para>
    /// <b>It reports WHETHER it got to the end, and the caller must carry that.</b> Returning the
    /// empty string alone made "the command printed nothing" and "we gave up reading it" the same
    /// value, which is how a bounded read turned into a false assertion about a security control.
    /// See <see cref="ProcessOutcome.OutputComplete"/>.
    /// </para>
    /// </remarks>
    /// <param name="read">The in-flight read of one pipe.</param>
    /// <returns>Whether the pipe reached end-of-file, and what it carried.</returns>
    private static (bool Complete, string Text) Drain(Task<string> read)
    {
        try
        {
            if (read.Wait(_drainGrace))
            {
                return (true, read.Result);
            }
        }
        catch (AggregateException)
        {
            // The read faulted — most often because killing the process disposed the pipe under
            // it. There is no output to report and no end-of-file was reached.
            return (false, string.Empty);
        }

        // ABANDONED, SO OBSERVE IT. The task outlives this call and the process object is disposed
        // on the way out, so the read can fault afterwards with nobody watching. Left unobserved it
        // is an unhandled-exception surface for any host that opts into that behaviour, and it
        // costs one continuation to close.
        _ = read.ContinueWith(
            static faulted => _ = faulted.Exception,
            CancellationToken.None,
            TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);

        return (false, string.Empty);
    }
}
