using Merlin.Agent.Core.Platform;

namespace Merlin.Agent.Collection;

/// <summary>
/// Runs a system command and returns its standard output, or <c>null</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>Arguments are passed as a LIST, never as a command line, and no value is ever interpolated
/// into one.</b> Every argument here is a compile-time constant, so there is nothing to inject —
/// but the shape is what keeps it that way, and <c>UseShellExecute = false</c> means no shell is
/// involved to interpret anything even if that changed.
/// </para>
/// <para>
/// <b>Every failure returns <c>null</c>.</b> A missing binary, a non-zero exit, a timeout and a
/// permission error all mean the same thing to the caller: this reading was not taken. The caller
/// turns that into a <c>null</c> signal, which Merlin reads as not observed — never as a protection
/// being off.
/// </para>
/// </remarks>
public static class CommandRunner
{
    /// <summary>Runs a command, returning its standard output on success.</summary>
    /// <param name="fileName">The executable.</param>
    /// <param name="arguments">Its arguments, passed individually.</param>
    /// <param name="timeout">How long the command may take.</param>
    /// <returns>Standard output, or <c>null</c> when the command could not be run to completion.</returns>
    public static string? Run(string fileName, string[] arguments, TimeSpan timeout)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentNullException.ThrowIfNull(arguments);

        // THE SHARED RUNNER. This used to redirect standard error and then never read it, which is
        // the pipe deadlock in its guaranteed rather than racy form: once the child had written
        // 4 KB (Windows) or 64 KB (Unix) of warnings it could not proceed, and the parent was
        // already blocked reading stdout, so the timeout below was never reached. A collection
        // holds the machine-wide lock, so a wedge here costs the machine its ability to report AND
        // the updater's ability to put a broken agent back.
        ProcessOutcome outcome = ProcessRunner.Run(fileName, arguments, timeout);

        return outcome.Succeeded ? outcome.StandardOutput : null;
    }

    /// <summary>Reads a file's text, or <c>null</c> when it cannot be read.</summary>
    /// <param name="path">The file.</param>
    /// <returns>The contents, or null.</returns>
    public static string? ReadFile(string path)
    {
        try
        {
            return File.Exists(path) ? File.ReadAllText(path) : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }
}
