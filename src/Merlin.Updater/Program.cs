using System.Security.Cryptography;
using Merlin.Agent.Core;
using Merlin.Agent.Core.Crypto;
using Merlin.Agent.Core.Platform;
using Merlin.Agent.Core.State;
using Merlin.Agent.Core.Update;

namespace Merlin.Updater;

/// <summary>
/// The Merlin Agent's companion updater.
/// </summary>
/// <remarks>
/// <para>
/// <b>It replaces the AGENT, and never itself.</b> The agent returns the favour on its own
/// schedule. Each verifies the other's health and can put the other's previous binary back, which
/// is what makes recovery from a bad release real rather than aspirational — and neither can be
/// destroyed by the thing it is installing.
/// </para>
/// <para>
/// <b>Merlin ADVERTISES; it never pushes.</b> This process polls a read-only, device-signed
/// endpoint whose whole answer is a version, an address and a hash. There is no command channel:
/// the server cannot reach a machine that does not call it, and cannot make one do anything except
/// move to a named version — bounded further by a host allowlist compiled into this binary, which
/// no server configuration can move.
/// </para>
/// <para>
/// <b>It shares the agent's identity, not a second one.</b> Same <c>state.json</c>, same device
/// key, same state directory, same SYSTEM or root privilege. A second enrolment would mean a second
/// credential at rest on every machine for no gain.
/// </para>
/// </remarks>
public static class Program
{
    /// <summary>
    /// The shortest gap between two scheduled checks.
    /// </summary>
    /// <remarks>
    /// <b>Not a rate limit on the server's account — a guard against the schedulers' own catch-up
    /// behaviour.</b> A systemd timer with <c>Persistent=true</c>, a launchd <c>StartInterval</c>
    /// and a Windows task with <c>StartWhenAvailable</c> all fire missed runs when a machine comes
    /// back, and a laptop returning from a week away can produce a burst. Downloading the same
    /// archive several times in a minute is pointless; swapping a binary several times in a minute
    /// is worse. <c>run --now</c> bypasses it, because an operator asking is not a scheduler
    /// catching up.
    /// </remarks>
    private static readonly TimeSpan _minimumInterval = TimeSpan.FromHours(1);

    /// <summary>Entry point.</summary>
    /// <param name="args">Command-line arguments.</param>
    /// <returns>Zero on success.</returns>
    public static async Task<int> Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (AgentPlatformInfo.Current == AgentOs.Unsupported)
        {
            Console.Error.WriteLine(
                "merlin-updater supports Windows, macOS and Linux. This machine is none of them.");
            return 1;
        }

        try
        {
            return args.Length == 0
                ? PrintUsage()
                : args[0].ToLowerInvariant() switch
                {
                    "run" => await RunAsync(args).ConfigureAwait(false),
                    "status" => Status(),
                    "--version" or "-v" => Print(AgentVersionInfo.Current),
                    _ => PrintUsage(),
                };
        }

        // UNFILTERED, DELIBERATELY — the same rule as the agent's update turn, and it matters more
        // here. A named list of the expected types reads as the more careful choice and is the
        // weaker one: UriFormatException, NotSupportedException, ObjectDisposedException and a
        // plain OperationCanceledException all walk straight past one. RunAsync has no inner try,
        // so anything that escapes skips its closing AgentState.Write — and that write is what
        // stamps LastUpdaterRunAt, which is the WITNESS a revert requires. A repeatable crash would
        // therefore mean a broken agent could never be put back, which is the failure this whole
        // process exists to prevent.
#pragma warning disable CA1031
        catch (Exception exception)
#pragma warning restore CA1031
        {
            Console.Error.WriteLine($"merlin-updater: {exception.Message}");
            return 1;
        }
    }

    /// <summary>
    /// One update turn.
    /// </summary>
    /// <remarks>
    /// <b>Every failure here is quiet and non-fatal.</b> Nothing this process does is allowed to
    /// leave the machine unable to report — silence in the fleet is indistinguishable from a
    /// machine that was never enrolled, and a failed update that also broke the agent would be the
    /// worst outcome auto-update can produce.
    /// </remarks>
    private static async Task<int> RunAsync(string[] args)
    {
        bool operatorRequested = args.Contains("--now", StringComparer.OrdinalIgnoreCase);

        AgentStateData? state = AgentState.Read();

        if (state is null)
        {
            // Not enrolled: there is no device to ask on behalf of and no server to ask. The
            // installer runs the agent's enrolment before it registers this schedule, so in
            // practice this is a machine mid-install or one that has been uninstalled.
            if (operatorRequested)
            {
                Console.Error.WriteLine(
                    "This machine has not enrolled, so there is nothing to check for.");
            }

            return 0;
        }

        // Captured BEFORE the lock wait, so a swap that lands DURING that wait can be told apart
        // from one that predates this process. See the guard after the re-read.
        DateTimeOffset startedAt = DateTimeOffset.UtcNow;

        // A SWAPPER NEVER SWAPS A TARGET THAT IS CURRENTLY RUNNING. The agent holds this same lock
        // for the whole of a collection, so failing to take it means the agent is mid-run — which
        // is not an error, and the scheduler fires again tomorrow.
        using MachineLock? machineLock = MachineLock.TryAcquire(
            AgentState.Directory, TimeSpan.FromMinutes(2), out bool accessDenied);

        if (machineLock is null)
        {
            if (accessDenied)
            {
                // A rights failure is not contention, and must not be reported as one.
                Console.Error.WriteLine(
                    "merlin-updater could not take the machine lock. It must run as root (or "
                    + "SYSTEM on Windows); nothing was checked.");
                return 1;
            }

            if (operatorRequested)
            {
                Console.Error.WriteLine(
                    "The agent is running. Nothing was changed; the updater will try again on its "
                    + "next scheduled run.");
            }

            return 0;
        }

        // RE-READ UNDER THE LOCK. The snapshot above was taken BEFORE the lock, and the wait is up
        // to two minutes — so every time that wait does its job, the holder we waited for has
        // written state we are still holding a pre-image of. Persisting it would silently erase
        // whatever it just recorded: the swap mark, the version stamped with it, the outcome owed
        // to Merlin, the pending note. The lock protects the FILES; only this protects the
        // read-modify-write cycle, and state.json is the sole authority for every safety rule in
        // this design. Both schedulers fire missed runs on wake, so a laptop opening its lid
        // produces exactly this overlap routinely.
        state = AgentState.Read() ?? state;

        // THIS PROCESS IS NOT EVIDENCE ABOUT A BINARY THAT REPLACED IT. If the agent swapped this
        // updater while we sat waiting for the lock, the image executing here is the one that was
        // replaced — so stamping a run would tell the next agent run that the NEW updater has
        // proved itself, when it has never executed at all. The mark would then be cleared, the
        // revert could never fire, and the no-stacked-swap rule would stop engaging. Exit and let
        // the scheduler start the binary that is actually on disk; it is the only honest witness.
        if (state.SwappedAtOf(AgentComponent.Updater) is { } replacedAt && replacedAt > startedAt)
        {
            if (operatorRequested)
            {
                Console.Error.WriteLine(
                    "This updater was replaced while it waited for the lock. Nothing was done; the "
                    + "new binary runs on the next scheduled check.");
            }

            return 0;
        }

        // The instant used for everything that follows is taken AFTER the wait. The lock wait can
        // be two minutes, and this value is the SIGNED request timestamp — spending a large slice
        // of the skew tolerance before the machine's own drift is even counted invites a refusal
        // and a wasted retry.
        DateTimeOffset now = DateTimeOffset.UtcNow;

        // THE INTERVAL IS JUDGED AFTER THE RE-READ, not before the lock. A run that spent two
        // minutes waiting for the agent would otherwise be measured against a stale stamp, and a
        // burst of catch-up runs is precisely when both of those happen at once.
        if (!operatorRequested
            && state.LastUpdaterRunAt is { } lastRun
            && now - lastRun < _minimumInterval)
        {
            return 0;
        }

        // STAMPED BEFORE ANY NETWORK WORK, exactly as the agent stamps itself at the top of a
        // collection, and for the mirror-image reason: this is the witness the recovery rule reads
        // to decide whether the machine was actually up. Written only at the end of the turn it sat
        // behind a download bounded at ten minutes, so a reboot, a kill or a crash mid-run lost it
        // — and a witness that keeps going missing is a broken agent that never gets put back.
        DateTimeOffset? previousUpdaterRun = state.LastUpdaterRunAt;

        AgentState.Write(state
            .WithLastRun(AgentComponent.Updater, now)
            .WithVersion(AgentComponent.Updater, AgentVersionInfo.Current));

        Action<string> log = operatorRequested
            ? Console.WriteLine
            : _ => { };

        if (operatorRequested)
        {
            Console.WriteLine($"Checking {state.ServerUrl} for a different agent version...");
        }

        (ECDsa key, _) = DeviceKey.OpenOrCreate(AgentState.SoftwareKeyPath);

        using (key)
        {
            using HttpClient http = new() { Timeout = TimeSpan.FromMinutes(10) };
            using UpdateClient client = new(
                state.ServerUrl, key, AgentVersionInfo.Current, state.ClockOffsetSeconds);

            ComponentSwapper swapper = new(AgentComponent.Updater, InstallLayout.Current, http, BinaryProbe.Default, log);

            UpdateRunner runner = new(
                AgentComponent.Updater,
                InstallLayout.Current,
                swapper,
                BinaryProbe.Default,
                UpdateWindows.Default,
                log);

            AgentStateData updated = await runner.RunAsync(
                state,
                // This updater's PREVIOUS run, captured above before the stamp. It is what says the
                // machine was actually up for the window a revert is judged against; a laptop that
                // was merely shut has a working agent, not a broken one.
                previousUpdaterRun,
                token => client.CheckAsync(state.DeviceId, AgentRuntimeIdentifier.Current, now, token),
                now).ConfigureAwait(false);

            AgentState.Write(updated);

            if (operatorRequested)
            {
                Console.WriteLine("Done.");
            }

            return 0;
        }
    }

    private static int Status()
    {
        AgentStateData? state = AgentState.Read();

        Console.WriteLine($"Updater:     {AgentVersionInfo.Current}");
        Console.WriteLine(
            $"Agent:       {BinaryProbe.Default.Version(InstallLayout.Current.PathOf(AgentComponent.Agent)) ?? "not observed"}");

        if (state is null)
        {
            Console.WriteLine("This machine has not enrolled.");
            return 0;
        }

        Console.WriteLine($"Reports to:  {state.ServerUrl}");
        Console.WriteLine($"Last check:  {state.LastUpdaterRunAt?.ToString("yyyy-MM-dd HH:mm") ?? "never"} UTC");

        if (state.LastUpdateOutcome is { } outcome)
        {
            Console.WriteLine(
                $"Last update: {outcome} at {state.LastUpdateAt:yyyy-MM-dd HH:mm} UTC");

            if (state.LastUpdateDetail is { Length: > 0 } detail)
            {
                Console.WriteLine($"             {detail}");
            }
        }

        return 0;
    }

    private static int Print(string text)
    {
        Console.WriteLine(text);
        return 0;
    }

    private static int PrintUsage()
    {
        Console.WriteLine("""
            Merlin Updater — replaces the Merlin Agent when this deployment advertises a different
            version. It never replaces itself; the agent does that.

            Merlin only ever ADVERTISES a version, an address and a hash. There is no remote-command
            channel, and the hosts a package may come from are compiled into this binary.

              merlin-updater run           # what the scheduled job runs
              merlin-updater run --now     # check immediately and say what happened
              merlin-updater status        # both components' versions and the last outcome
            """);

        return 1;
    }
}
