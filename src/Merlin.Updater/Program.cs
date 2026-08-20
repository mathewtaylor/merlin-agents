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
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or CryptographicException or HttpRequestException)
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

        DateTimeOffset now = DateTimeOffset.UtcNow;

        if (!operatorRequested
            && state.LastUpdaterRunAt is { } lastRun
            && now - lastRun < _minimumInterval)
        {
            return 0;
        }

        // A SWAPPER NEVER SWAPS A TARGET THAT IS CURRENTLY RUNNING. The agent holds this same lock
        // for the whole of a collection, so failing to take it means the agent is mid-run — which
        // is not an error, and the scheduler fires again tomorrow.
        using MachineLock? machineLock = MachineLock.TryAcquire(
            AgentState.Directory, TimeSpan.FromMinutes(2));

        if (machineLock is null)
        {
            if (operatorRequested)
            {
                Console.Error.WriteLine(
                    "The agent is running. Nothing was changed; the updater will try again on its "
                    + "next scheduled run.");
            }

            return 0;
        }

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

            ComponentSwapper swapper = new(InstallLayout.Current, http, BinaryProbe.Default, log);

            UpdateRunner runner = new(
                AgentComponent.Updater,
                InstallLayout.Current,
                swapper,
                BinaryProbe.Default,
                UpdateWindows.Default,
                log);

            AgentStateData updated = await runner.RunAsync(
                state,
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
