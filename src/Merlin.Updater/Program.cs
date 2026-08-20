using Merlin.Agent.Core;
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
/// <para>
/// <b>The turn itself lives in <see cref="UpdateTurn"/>, which the agent runs too.</b> This file
/// parses arguments, names the component, and turns the turn's answer into words and an exit code.
/// The ordering that envelope holds — read the state only once the lock is taken, refuse to stamp a
/// run for an image that was replaced while it waited, stamp before anything fallible — was written
/// twice, in two Program.cs files no test could reach, and four consecutive audit rounds each found
/// a different defect in it.
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

        // UNFILTERED, DELIBERATELY — the same rule as the update turn itself, and it matters more
        // here. A named list of the expected types reads as the more careful choice and is the
        // weaker one: UriFormatException, NotSupportedException, ObjectDisposedException and a
        // plain OperationCanceledException all walk straight past one. UpdateTurn catches whatever
        // escapes the update work and reports it as a fault; this catch is what stops anything
        // AROUND that — reading the state, taking the lock, opening the device key — ending a
        // scheduled run in a stack trace nobody reads.
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

        Action<string> log = operatorRequested
            ? Console.WriteLine
            : _ => { };

        UpdateTurn turn = new(
            AgentComponent.Updater,
            InstallLayout.Current,
            () => new DeviceUpdateSession(),
            swapLog: log,
            decisionLog: log,
            minimumInterval: _minimumInterval);

        UpdateTurnResult result = await turn.RunAsync(
            operatorRequested,
            announce: state =>
            {
                if (operatorRequested)
                {
                    Console.WriteLine(
                        $"Checking {state.ServerUrl} for a different agent version...");
                }
            }).ConfigureAwait(false);

        switch (result.Status)
        {
            case UpdateTurnStatus.NotEnrolled:

                // Not enrolled: there is no device to ask on behalf of and no server to ask. The
                // installer runs the agent's enrolment before it registers this schedule, so in
                // practice this is a machine mid-install or one that has been uninstalled.
                if (operatorRequested)
                {
                    Console.Error.WriteLine(
                        "This machine has not enrolled, so there is nothing to check for.");
                }

                return 0;

            case UpdateTurnStatus.RightsRefused:

                // A rights failure is not contention, and must not be reported as one.
                Console.Error.WriteLine(
                    "merlin-updater could not take the machine lock. It must run as root (or "
                    + "SYSTEM on Windows); nothing was checked.");
                return 1;

            case UpdateTurnStatus.Contended:
                if (operatorRequested)
                {
                    Console.Error.WriteLine(
                        "The agent is running. Nothing was changed; the updater will try again on "
                        + "its next scheduled run.");
                }

                return 0;

            case UpdateTurnStatus.Replaced:

                // The image executing here is the one that was replaced while it waited for the
                // lock, so it stamped nothing: a run stamped by it would tell the next agent run
                // that the NEW updater has proved itself, when it has never executed at all.
                if (operatorRequested)
                {
                    Console.Error.WriteLine(
                        "This updater was replaced while it waited for the lock. Nothing was done; "
                        + "the new binary runs on the next scheduled check.");
                }

                return 0;

            case UpdateTurnStatus.TooSoon:
                return 0;

            default:
                if (result.Fault is { } fault)
                {
                    Console.Error.WriteLine($"merlin-updater: {fault}");
                    return 1;
                }

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
