using System.Globalization;
using Merlin.Agent.Core.Platform;

namespace Merlin.Agent.Core.Update;

/// <summary>What happened when a binary was run.</summary>
/// <param name="Ran">Whether it started and exited zero.</param>
/// <param name="Output">What it printed, or why it did not run.</param>
public sealed record ProbeResult(bool Ran, string Output);

/// <summary>
/// Runs a binary once and collects what it said.
/// </summary>
/// <remarks>
/// <para>
/// <b>Executing a staged binary before committing to it is the check that matters</b>, and it is
/// the one a hash cannot make: a digest proves the bytes arrived intact and says nothing about
/// whether they run on this machine. An antivirus quarantine, a package built for the wrong
/// architecture and a missing system library all fail here, while the working binary is still in
/// place and the machine is still reporting.
/// </para>
/// <para>
/// <b>It is a seam so the swap routine can be tested at all.</b> A unit test cannot manufacture a
/// NativeAOT executable for four architectures, and the behaviour worth pinning is what the swapper
/// DOES when a binary will not run — nothing replaced, the failure reported — not the mechanics of
/// <see cref="Process"/>. One test on Unix drives the real implementation end to end with a shell
/// script, so the seam is not the only thing ever exercised.
/// </para>
/// <para>
/// <b>Probing never takes the machine lock.</b> The caller already holds it for the whole run, and
/// a probe that tried to take it again would deadlock against its own parent. Only <c>collect</c>
/// and <c>run</c> take the lock; <c>--version</c> is deliberately outside it.
/// </para>
/// </remarks>
public sealed class BinaryProbe
{
    private readonly Func<string, string, TimeSpan, ProbeResult> _execute;

    /// <summary>Initialises a new instance of the <see cref="BinaryProbe"/> class.</summary>
    /// <param name="execute">How to run a binary — path, arguments, timeout.</param>
    public BinaryProbe(Func<string, string, TimeSpan, ProbeResult> execute)
    {
        ArgumentNullException.ThrowIfNull(execute);

        _execute = execute;
    }

    /// <summary>The probe that actually starts a process.</summary>
    public static BinaryProbe Default { get; } = new(Run);

    /// <summary>
    /// Reads a component's version by executing it.
    /// </summary>
    /// <remarks>
    /// <b>Asked of the binary rather than taken from the state file</b>, because the state file
    /// records what was last written and the binary on disk is what actually runs. They disagree
    /// exactly when something has gone wrong, which is the moment the answer matters. A component
    /// that will not execute has no version, and <c>null</c> is reported to Merlin as not-observed
    /// rather than guessed at.
    /// </remarks>
    /// <param name="path">The binary.</param>
    /// <returns>The first line it printed, or null.</returns>
    public string? Version(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        if (!File.Exists(path))
        {
            return null;
        }

        ProbeResult result = Execute(path, "--version", TimeSpan.FromSeconds(30));

        return result.Ran ? FirstLine(result.Output) : null;
    }

    /// <summary>Runs a binary once.</summary>
    /// <param name="path">The binary.</param>
    /// <param name="arguments">Its arguments.</param>
    /// <param name="timeout">How long to allow.</param>
    /// <returns>What happened.</returns>
    public ProbeResult Execute(string path, string arguments, TimeSpan timeout) =>
        _execute(path, arguments, timeout);

    /// <summary>The first non-empty line of some output, or null.</summary>
    /// <param name="output">The output.</param>
    /// <returns>The first line, trimmed, or null.</returns>
    public static string? FirstLine(string? output)
    {
        string? first = output
            ?.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .FirstOrDefault(line => line.Length > 0);

        return string.IsNullOrWhiteSpace(first) ? null : first;
    }

    private static ProbeResult Run(string path, string arguments, TimeSpan timeout)
    {
        // THE SHARED RUNNER, which is where the both-pipes-at-once rule lives. It was written here
        // first, for the deadlock that wedges a SYSTEM process holding the machine lock; the same
        // shape then turned out to be wrong in the osquery runner and the command runner, so the
        // implementation moved somewhere there is only one of it.
        ProcessOutcome outcome = ProcessRunner.Run(
            path, arguments, Path.GetDirectoryName(path), timeout);

        if (!outcome.Started || !outcome.Exited)
        {
            return new ProbeResult(false, outcome.StandardError);
        }

        if (outcome.ExitCode != 0)
        {
            string detail = outcome.StandardError.Trim().Length > 0
                ? outcome.StandardError.Trim()
                : outcome.StandardOutput.Trim();

            return new ProbeResult(false, string.Format(
                CultureInfo.InvariantCulture,
                "It exited with code {0}. {1}",
                outcome.ExitCode,
                detail).Trim());
        }

        return new ProbeResult(true, outcome.StandardOutput);
    }
}
