using Merlin.Agent.Core.State;

namespace Merlin.Agent.Core.Update;

/// <summary>
/// A machine-wide lock, held for the whole of a run by either component.
/// </summary>
/// <remarks>
/// <para>
/// <b>A swapper never swaps a target that is currently running.</b> Both binaries take this lock
/// before they do anything and hold it until they exit, so a scheduled agent collection and a
/// scheduled updater run can never overlap — and the swap therefore never lands on a binary that is
/// mid-execution. On Windows that would fail anyway with a sharing violation; on Unix it would
/// silently succeed and hand the running process an inode nobody can see, which is worse.
/// </para>
/// <para>
/// <b>A lock FILE opened with <see cref="FileShare.None"/>, on every platform.</b> .NET implements
/// that share mode with <c>flock(2)</c> on Unix and with a mandatory OS share lock on Windows, so
/// this IS the mechanism the design calls for. A named mutex was the obvious Windows alternative
/// and was rejected: a mutex is re-entrant for the thread that owns it, so a second acquisition
/// inside the same process SUCCEEDS — which would make the contention guarantee weaker on exactly
/// the platform the fleet mostly runs, and would make the test that proves it vacuous there. One
/// mechanism, one behaviour, one test that means the same thing everywhere.
/// </para>
/// <para>
/// <b>Failing to acquire is not an error.</b> The other component is running; there is nothing
/// wrong and nothing to report. The caller exits quietly and the scheduler fires again.
/// </para>
/// </remarks>
public sealed class MachineLock : IDisposable
{
    private readonly FileStream _handle;

    private MachineLock(FileStream handle) => _handle = handle;

    /// <summary>The lock file's path within a state directory.</summary>
    /// <param name="stateDirectory">The state directory.</param>
    /// <returns>The absolute path.</returns>
    public static string PathIn(string stateDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stateDirectory);

        return Path.Combine(stateDirectory, "merlin-agent.lock");
    }

    /// <summary>
    /// Takes the lock, waiting up to <paramref name="timeout"/> for whoever holds it.
    /// </summary>
    /// <remarks>
    /// The wait exists because an agent collection takes a couple of seconds and an updater that
    /// gave up instantly would skip a whole day's check over a two-second overlap. It is short,
    /// because a component that cannot get in has nothing useful to do while it waits.
    /// </remarks>
    /// <param name="stateDirectory">The directory the lock file lives in.</param>
    /// <param name="timeout">How long to keep trying.</param>
    /// <param name="accessDenied">
    /// Set when the lock could not be taken because this process lacks the RIGHTS to, rather than
    /// because the other component holds it. <b>The two must not look the same to a caller.</b>
    /// Contention is ordinary and the right response is to exit quietly; a permissions failure is
    /// not, and reporting it as "the updater is running" meant an agent started without root or
    /// SYSTEM spun for the full timeout and then exited zero — on every scheduled fire, for ever,
    /// with the machine collecting nothing and looking healthy while it did.
    /// </param>
    /// <returns>The held lock, or <c>null</c> when it could not be taken.</returns>
    public static MachineLock? TryAcquire(
        string stateDirectory,
        TimeSpan timeout,
        out bool accessDenied)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(stateDirectory);

        accessDenied = false;

        // THROUGH THE ONE HELPER, so the lock cannot be what creates this directory loosely. It
        // runs at the top of enrolment now, which makes it the first thing to touch the state
        // directory on a fresh machine — and a plain CreateDirectory there left 0755 behind that
        // nothing afterwards could tighten.
        //
        // It is inside the guard because creating the directory is itself a thing a process
        // without the rights cannot do, and an exception escaping here would be a crash where the
        // caller has a considered answer for exactly this case.
        try
        {
            AgentState.EnsureDirectory(stateDirectory);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or NotSupportedException)
        {
            accessDenied = true;
            return null;
        }

        string path = PathIn(stateDirectory);

        // MONOTONIC, because this wait must be exactly as long as it says. DateTime.UtcNow steps
        // when NTP corrects or a VM resumes — both most likely just after a boot, which is
        // precisely when a scheduled run fires — and a backwards step extends this loop by the size
        // of the step, without bound. It cannot wedge the lock, since none is held yet, but it can
        // hold up the caller far past the two minutes it promises while parking a thread in
        // Thread.Sleep.
        long deadline = Environment.TickCount64 + (long)timeout.TotalMilliseconds;

        while (true)
        {
            // PER ATTEMPT, not sticky. One transient refusal followed by ordinary contention that
            // outlasts the wait would otherwise be reported as a rights failure, and both callers
            // answer that by telling the operator to run as root and exiting non-zero — a red
            // scheduler run and a wrong diagnosis for what was simply a busy machine.
            accessDenied = false;

            try
            {
                MachineLock held = new(new FileStream(
                    path,
                    FileMode.OpenOrCreate,
                    FileAccess.ReadWrite,
                    FileShare.None));

                // Taken in the end, so whatever an earlier attempt saw was contention after all.
                accessDenied = false;

                return held;
            }
            catch (IOException)
            {
                // Held by the other component. Nothing is wrong; wait a moment and try again.
            }
            catch (UnauthorizedAccessException)
            {
                // On some platforms a share violation surfaces this way — but so does a genuine
                // permissions failure, and only one of them is worth waiting out. Retrying costs
                // nothing if it was contention; the flag is what stops the caller reporting a
                // rights problem as a healthy run once the wait is over.
                accessDenied = true;
            }

            if (Environment.TickCount64 >= deadline)
            {
                return null;
            }

            Thread.Sleep(250);
        }
    }

    /// <inheritdoc />
    public void Dispose() => _handle.Dispose();
}
