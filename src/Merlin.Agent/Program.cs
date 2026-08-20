using System.Security.Cryptography;
using Merlin.Agent.Collection;
using Merlin.Agent.Core;
using Merlin.Agent.Core.Collection;
using Merlin.Agent.Core.Contracts;
using Merlin.Agent.Core.Crypto;
using Merlin.Agent.Core.Platform;
using Merlin.Agent.Core.State;
using Merlin.Agent.Core.Update;
using Merlin.Agent.Transport;

namespace Merlin.Agent;

/// <summary>
/// The Merlin Agent command line.
/// </summary>
/// <remarks>
/// <para>
/// <b>A one-shot process, not a service.</b> It runs, collects, reports and exits — typically in
/// two or three seconds, every six hours, from the platform's own scheduler. Nothing stays resident,
/// so idle cost is zero and there is no listening socket on an employee machine; a crashed run
/// simply fires again next interval instead of staying dead and looking like a passing check; and
/// the binary is never locked, so updating it is a file swap.
/// </para>
/// <para>
/// <b>It reads facts about the MACHINE and never about the person using it.</b> There is no query
/// for the signed-in user, the session or any mail address, and no configuration that adds one. See
/// <c>packaging/queries/</c> for the complete list of what is read on each platform, or run
/// <c>merlin-agent status --manifest</c> on the machine itself.
/// </para>
/// </remarks>
public static class Program
{
    /// <summary>
    /// This agent's version — the ONE constant, shared with the updater.
    /// </summary>
    /// <remarks>
    /// Both binaries ship in the same archive at the same version, and the update mechanism
    /// compares versions, so two constants free to drift would mean a component that believed it
    /// was current while the other was not.
    /// </remarks>
    private const string Version = AgentVersionInfo.Current;

    /// <summary>Entry point.</summary>
    /// <param name="args">Command-line arguments.</param>
    /// <returns>Zero on success.</returns>
    public static async Task<int> Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

        if (AgentPlatformInfo.Current == AgentOs.Unsupported)
        {
            // Refusing beats falling through to the nearest collector. A platform with no query
            // pack would produce readings taken from files that do not mean what the collector
            // thinks they mean — a report full of confident, wrong observations, which is worse for
            // an ISMS than no report at all.
            Console.Error.WriteLine(
                "merlin-agent supports Windows, macOS and Linux. This machine is none of them, and "
                + "the agent will not guess at how to read it.");
            return 1;
        }

        if (args.Length == 0)
        {
            PrintUsage();
            return 1;
        }

        try
        {
            return args[0].ToLowerInvariant() switch
            {
                "enrol" or "enroll" => await EnrolAsync(args).ConfigureAwait(false),
                "collect" => await CollectAsync().ConfigureAwait(false),
                "status" => Status(args),
                "set-server" => await SetServerAsync(args).ConfigureAwait(false),
                "rotate-key" => await RotateAsync().ConfigureAwait(false),
                "uninstall" => Uninstall(),
                "--version" or "-v" => Print(Version),
                _ => PrintUsage(),
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or CryptographicException or HttpRequestException or TaskCanceledException)
        {
            // Expected operational failures: no network, no permission, no TPM. Reported plainly and
            // with a non-zero exit code so the scheduler's history shows the failure, rather than a
            // stack trace nobody will read. TaskCanceledException is in the list because that is
            // what an HttpClient timeout raises — a server that HANGS is as ordinary as one that
            // refuses, and without it enrol, set-server and rotate-key died with a stack trace.
            Console.Error.WriteLine($"merlin-agent: {exception.Message}");
            return 1;
        }
    }

    private static async Task<int> EnrolAsync(string[] args)
    {
        // Enrolment replaces the state record wholesale, so it must not land while the updater is
        // mid-swap and about to write a mark of its own.
        using MachineLock? enrolLock = MachineLock.TryAcquire(
            AgentState.Directory, TimeSpan.FromMinutes(2));

        if (enrolLock is null)
        {
            Console.Error.WriteLine(
                "The agent or the updater is running. Nothing was changed; try again in a moment.");
            return 1;
        }

        string? server = ArgumentValue(args, "--server");
        string? enrolmentKey = ArgumentValue(args, "--enrolment-key") ?? ArgumentValue(args, "--enrollment-key");

        if (server is null || enrolmentKey is null)
        {
            Console.Error.WriteLine(
                "Usage: merlin-agent enrol --server <url> --enrolment-key <key>");
            return 1;
        }

        (ECDsa key, KeyAttestation attestation) = DeviceKey.OpenOrCreate(AgentState.SoftwareKeyPath);

        using (key)
        {
            AgentReportPayload payload = Collect();

            AgentEnrolRequest request = new(
                DeviceKey.PublicKey(key),
                attestation.ToString(),
                Version,
                AgentPlatformInfo.Wire,
                payload.Hostname,
                payload.MachineGuid,
                payload.SerialNumber,
                payload.Manufacturer,
                payload.Model,
                payload.ChassisType,
                payload.EntraDeviceId,
                payload.EntraTenantId);

            using ReportClient client = new(server, key, Version);

            (TransportResult result, AgentEnrolResponse? response) =
                await client.EnrolAsync(request, enrolmentKey, DateTimeOffset.UtcNow).ConfigureAwait(false);

            if (!result.Succeeded || response is null)
            {
                Console.Error.WriteLine($"Enrolment failed: {result.Detail}");
                return 1;
            }

            AgentState.Write(new AgentStateData(
                server,
                response.DeviceId,
                response.DeviceCode,
                DateTimeOffset.UtcNow,
                client.ClockOffsetSeconds,
                LastReportAt: null,
                LastReportJson: null));

            Console.WriteLine($"Enrolled as {response.DeviceCode} ({response.Status}).");
            Console.WriteLine($"Platform:    {AgentPlatformInfo.DisplayName}");
            Console.WriteLine($"Signing key: {attestation}.");

            if (DeviceKey.ExplainAttestation(attestation) is { Length: > 0 } explanation)
            {
                Console.WriteLine(explanation);
            }

            return 0;
        }
    }

    /// <summary>
    /// Collects, reports, and then takes the agent's turn at replacing the UPDATER.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The report happens FIRST and the update work cannot stop it.</b> A failed update must
    /// never leave a machine unable to report: silence in the fleet is indistinguishable from a
    /// machine that was never enrolled, so the whole update turn sits behind the report and inside
    /// a catch that swallows everything. The outcome it records is sent on the NEXT report, one run
    /// later, which is the price of that ordering and worth paying.
    /// </para>
    /// <para>
    /// <b>The machine-wide lock is taken for the whole run.</b> It is what stops the updater
    /// swapping this binary while it is executing — and, held here rather than around the swap
    /// alone, it also means the updater is never mid-swap when a collection starts.
    /// </para>
    /// </remarks>
    private static async Task<int> CollectAsync()
    {
        AgentStateData? state = AgentState.Read();

        if (state is null)
        {
            Console.Error.WriteLine(
                "This machine has not enrolled. Run: merlin-agent enrol --server <url> --enrolment-key <key>");
            return 1;
        }

        // Not being able to take it means the updater is mid-run and may be replacing this very
        // binary. Reporting anyway would be harmless; collecting into a directory being rewritten
        // would not. The scheduler fires again in six hours.
        using MachineLock? machineLock = MachineLock.TryAcquire(
            AgentState.Directory, TimeSpan.FromMinutes(2));

        if (machineLock is null)
        {
            Console.Error.WriteLine(
                "The updater is running. Nothing was collected; the agent will try again on its "
                + "next scheduled run.");
            return 0;
        }

        // RE-READ UNDER THE LOCK. The snapshot above was taken before the lock was taken, and the
        // wait is up to two minutes — so every time that wait does its job, the holder we waited
        // for has written state we are still holding a pre-image of. Persisting it silently erases
        // whatever it just recorded: the swap mark, the version stamped with it, the outcome owed
        // to Merlin and the pending note. The lock protects the FILES; only this protects the
        // read-modify-write cycle, and state.json is the sole authority for every safety rule here.
        // Both schedulers fire missed runs on wake, so a laptop opening its lid produces exactly
        // this overlap routinely.
        state = AgentState.Read() ?? state;

        // Captured BEFORE the stamp below overwrites it. The update turn needs this agent's
        // PREVIOUS run to judge whether the machine was actually up across a revert window — a
        // laptop that was merely shut for a weekend has a working updater, not a broken one — and
        // once the stamp lands there is nothing left on the record that says so.
        DateTimeOffset? previousAgentRun = state.LastAgentRunAt;

        // Stamped before anything can fail, because this is the signal the UPDATER reads to decide
        // whether a binary it swapped in actually runs. A stamp written only on success would have
        // a network outage read as a broken agent and revert a working one.
        state = state.WithLastRun(AgentComponent.Agent, DateTimeOffset.UtcNow)
            .WithVersion(AgentComponent.Agent, Version);

        AgentState.Write(state);

        (ECDsa key, _) = DeviceKey.OpenOrCreate(AgentState.SoftwareKeyPath);

        using (key)
        {
            AgentReportPayload payload = Collect() with
            {
                // THE OUTCOME IS REPORTED, NEVER INFERRED. A server watching only the agent version
                // cannot tell "updated and rolled back" from "never attempted" — both leave the
                // version unmoved — and a silent failed update is the worst thing auto-update can
                // produce.
                UpdaterVersion = BinaryProbe.Default.Version(
                    InstallLayout.Current.PathOf(AgentComponent.Updater)),
                LastUpdateOutcome = state.LastUpdateOutcome?.ToString(),
            };

            using ReportClient client = new(state.ServerUrl, key, Version);

            // THE ATTEMPT IS TOTAL, so the update turn below is reached whatever the network did.
            // ReportAsync does not catch, so an outage, a DNS failure, a proxy change or an expired
            // certificate threw straight past the turn into Main — and those are three of the four
            // cases the ordering below exists to serve. Only a server REFUSAL was reaching it. A
            // hung server was worse: the client timeout raises TaskCanceledException, which Main
            // did not filter for either, so the agent died with a stack trace. Recovery needs no
            // network at all, so a machine that cannot reach Merlin is precisely the one that must
            // still be able to put a broken updater back.
            TransportResult result;
            string json;

            try
            {
                (result, json) = await client
                    .ReportAsync(payload, state.DeviceId, DateTimeOffset.UtcNow.AddSeconds(state.ClockOffsetSeconds))
                    .ConfigureAwait(false);
            }
            catch (Exception exception) when (exception is HttpRequestException or TaskCanceledException)
            {
                result = new TransportResult(false, exception.Message, null);
                json = state.LastReportJson ?? string.Empty;
            }

            // The payload is persisted whether or not Merlin accepted it, so `status` can always
            // show the operator exactly what this machine tried to send.
            state = state with
            {
                ClockOffsetSeconds = client.ClockOffsetSeconds == 0
                    ? state.ClockOffsetSeconds
                    : client.ClockOffsetSeconds,
                LastReportAt = result.Succeeded ? DateTimeOffset.UtcNow : state.LastReportAt,
                LastReportJson = json,
            };

            AgentState.Write(state);

            // THE UPDATE TURN COMES BEFORE THE EARLY EXIT, and that ordering is load-bearing.
            // Recovery runs before any server call and needs no network whatever — so a machine
            // that cannot reach Merlin, whether from an outage, a proxy change, an expired
            // certificate or a refused signature, is exactly the machine that must still be able to
            // put a broken updater back. Gating this on a successful report made the one failure
            // mode most in need of recovery the one that never got it.
            await MaintainUpdaterAsync(state, previousAgentRun, key).ConfigureAwait(false);

            if (!result.Succeeded)
            {
                Console.Error.WriteLine($"Report refused: {result.Detail}");
                return 1;
            }

            Console.WriteLine(result.Detail);

            return 0;
        }
    }

    /// <summary>
    /// The agent's half of mutual replacement: it looks after the UPDATER, and never itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Every failure here is swallowed.</b> The report has already been ATTEMPTED by the time
    /// this runs — successfully or not, since recovery needs no network and a machine that cannot
    /// reach Merlin still has to be able to put a broken updater back — so nothing this does is
    /// worth failing a collection over, and an exception escaping would give the scheduler a failed
    /// run for a machine that is perfectly healthy.
    /// </para>
    /// <para>
    /// <b>Which is why the catch is unfiltered, deliberately, and must stay that way.</b> A named
    /// list of the expected types reads as the more careful choice and is the weaker one: it was
    /// one, and <c>UriFormatException</c>, <c>NotSupportedException</c>, <c>ObjectDisposedException</c>
    /// and a plain <c>OperationCanceledException</c> all walked straight past it into
    /// <see cref="Main"/>, whose own catch is narrower still. The machine had already reported
    /// successfully; the crash cost it the <c>AgentState.Write</c> that carried the update
    /// bookkeeping — including an outcome that was owed to Merlin — and handed the scheduler a red
    /// run for a healthy machine. Whatever goes wrong in an update turn, the answer is a line on
    /// stderr and exit zero.
    /// </para>
    /// </remarks>
    private static async Task MaintainUpdaterAsync(
        AgentStateData state,
        DateTimeOffset? previousAgentRun,
        ECDsa key)
    {
        try
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;

            using HttpClient http = new() { Timeout = TimeSpan.FromMinutes(10) };
            using UpdateClient client = new(
                state.ServerUrl, key, Version, state.ClockOffsetSeconds);

            ComponentSwapper swapper = new(AgentComponent.Agent, InstallLayout.Current, http, BinaryProbe.Default, Console.WriteLine);

            UpdateRunner runner = new(
                AgentComponent.Agent,
                InstallLayout.Current,
                swapper,
                BinaryProbe.Default,
                UpdateWindows.Default,
                _ => { });

            AgentStateData updated = await runner.RunAsync(
                state,
                previousAgentRun,
                token => client.CheckAsync(state.DeviceId, AgentRuntimeIdentifier.Current, now, token),
                now).ConfigureAwait(false);

            AgentState.Write(updated);
        }
#pragma warning disable CA1031 // See the remarks: an unfiltered catch is the requirement here.
        catch (Exception exception)
#pragma warning restore CA1031
        {
            Console.Error.WriteLine($"  the updater check did not complete: {exception.Message}");
        }
    }

    /// <summary>
    /// Prints exactly what this machine last sent.
    /// </summary>
    /// <remarks>
    /// <b>This is a transparency feature, not a debugging one.</b> The agent is open source, but
    /// "read the code" is a weak promise to somebody who does not read C#. Printing the verbatim
    /// payload — and, with <c>--manifest</c>, every query that produced it — means an employee can
    /// see what left their machine without trusting anybody's summary of it.
    /// </remarks>
    private static int Status(string[] args)
    {
        AgentStateData? state = AgentState.Read();

        if (state is null)
        {
            Console.WriteLine("This machine has not enrolled.");

            // The manifest is still worth printing: somebody deciding whether to ALLOW the agent
            // onto their machine is exactly the person who should be able to read what it would
            // collect, and they will ask before it is enrolled rather than after.
            return args.Contains("--manifest", StringComparer.OrdinalIgnoreCase)
                ? PrintManifest()
                : 0;
        }

        Console.WriteLine($"Device:      {state.DeviceCode} ({state.DeviceId})");
        Console.WriteLine($"Platform:    {AgentPlatformInfo.DisplayName}");
        Console.WriteLine($"Reports to:  {state.ServerUrl}");
        Console.WriteLine($"Enrolled:    {state.EnrolledAt:yyyy-MM-dd HH:mm} UTC");
        Console.WriteLine($"Last report: {state.LastReportAt?.ToString("yyyy-MM-dd HH:mm") ?? "never"} UTC");
        Console.WriteLine($"Agent:       {Version}");

        // BOTH COMPONENTS, always. This machine carries two scheduled binaries that replace each
        // other, and an operator shown only one of them cannot tell a fleet that updates itself
        // from one that stopped a version ago — which is precisely the state a missing or stale
        // updater leaves it in.
        PrintUpdaterStatus(state);

        Console.WriteLine();

        if (args.Contains("--manifest", StringComparer.OrdinalIgnoreCase))
        {
            return PrintManifest();
        }

        if (state.LastReportJson is { Length: > 0 } json)
        {
            Console.WriteLine("The exact payload last sent:");
            Console.WriteLine();
            Console.WriteLine(json);
        }
        else
        {
            Console.WriteLine("Nothing has been sent yet.");
        }

        Console.WriteLine();
        Console.WriteLine("Run 'merlin-agent status --manifest' to see every query this agent runs.");
        return 0;
    }

    /// <summary>
    /// Prints the companion updater's version and what the last swap on this machine did.
    /// </summary>
    /// <remarks>
    /// <b>"not installed" and "would not run" are told apart</b>, because the remedies differ: the
    /// first is a package built before auto-update shipped and is fixed by reinstalling, the second
    /// is a broken binary that the agent itself will put back. Collapsing them into one line would
    /// leave an operator guessing at which they are looking at.
    /// </remarks>
    private static void PrintUpdaterStatus(AgentStateData state)
    {
        string updaterPath = InstallLayout.Current.PathOf(AgentComponent.Updater);

        string updater = !File.Exists(updaterPath)
            ? "not installed — this machine will not update itself"
            : BinaryProbe.Default.Version(updaterPath) ?? "installed, but it would not run";

        Console.WriteLine($"Updater:     {updater}");
        Console.WriteLine(
            $"Last check:  {state.LastUpdaterRunAt?.ToString("yyyy-MM-dd HH:mm") ?? "never"} UTC");

        if (state.LastUpdateOutcome is { } outcome)
        {
            Console.WriteLine($"Last update: {outcome} at {state.LastUpdateAt:yyyy-MM-dd HH:mm} UTC");

            if (state.LastUpdateDetail is { Length: > 0 } detail)
            {
                Console.WriteLine($"             {detail}");
            }
        }
    }

    private static int PrintManifest()
    {
        Console.WriteLine($"Everything this agent reads on {AgentPlatformInfo.DisplayName}:");
        Console.WriteLine();

        foreach ((string name, string sql) in QueryPack.Load())
        {
            Console.WriteLine($"  [{name}]");
            Console.WriteLine($"  {sql}");
            Console.WriteLine();
        }

        // The supplemental readings are NOT in the query pack, so a manifest listing only the pack
        // would understate what the agent touches — which would make this command a worse promise
        // than no command. They are named here for the same reason the pack exists.
        Console.WriteLine("Read outside osquery, because no table exposes them:");
        Console.WriteLine();

        foreach (string item in SupplementalManifest())
        {
            Console.WriteLine($"  {item}");
        }

        Console.WriteLine();
        Console.WriteLine(
            "Nothing else is collected. There is no query for the signed-in user, the session, "
            + "files, browsing or network traffic.");

        return 0;
    }

    private static string[] SupplementalManifest() => AgentPlatformInfo.Current switch
    {
        AgentOs.Windows => ["net accounts — the local password and lockout policy"],
        AgentOs.MacOs => ["pwpolicy -getaccountpolicies — the local password policy"],
        _ =>
        [
            "/etc/security/pwquality.conf and /etc/login.defs — the local password policy",
            "/sys/firmware/efi/efivars/SecureBoot-* — whether Secure Boot is enforced",
            "/sys/class/tpm/tpm0/tpm_version_major — whether a TPM is present",
            "the package database's modification time — when software was last installed",
            "ufw status / firewall-cmd --state / nft list ruleset — the host firewall's state",
        ],
    };

    /// <summary>
    /// Re-points this machine at a different Merlin address.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Exists because the stored address is otherwise permanent.</b> An agent reports to whatever
    /// it was installed from, so a deployment that moves — a custom domain, a rename, a tenant slug
    /// being adopted — would leave every machine posting into the void. They would not error
    /// visibly; they would simply go stale, and the freshness check would fire without saying why.
    /// </para>
    /// <para>
    /// <b>The new address is PROVED before it is kept.</b> A typo would otherwise silently kill the
    /// agent in exactly the way this command exists to prevent, so the collection runs against the
    /// new address first and the old one is restored if it does not accept the report. The device
    /// must already exist at the new address — same database, new hostname — which is what
    /// distinguishes a moved deployment from a different one.
    /// </para>
    /// </remarks>
    private static async Task<int> SetServerAsync(string[] args)
    {
        // THE SAME MACHINE-WIDE LOCK the scheduled commands take, and for the same reason: this
        // reads state, does network work, and writes state back. Without it an operator running
        // this while the updater happens to be mid-swap persists a pre-image and erases the swap
        // mark, which is a broken binary that can never be put back.
        using MachineLock? machineLock = MachineLock.TryAcquire(
            AgentState.Directory, TimeSpan.FromMinutes(2));

        if (machineLock is null)
        {
            Console.Error.WriteLine(
                "The agent or the updater is running. Nothing was changed; try again in a moment.");
            return 1;
        }

        AgentStateData? state = AgentState.Read();

        if (state is null)
        {
            Console.Error.WriteLine("This machine has not enrolled, so there is nothing to re-point.");
            return 1;
        }

        string? server = ArgumentValue(args, "--server");

        if (server is null)
        {
            Console.Error.WriteLine("Usage: merlin-agent set-server --server <url>");
            return 1;
        }

        if (!Uri.TryCreate(server, UriKind.Absolute, out Uri? parsed)
            || (parsed.Scheme != Uri.UriSchemeHttps && parsed.Scheme != Uri.UriSchemeHttp))
        {
            Console.Error.WriteLine($"'{server}' is not an absolute http or https address.");
            return 1;
        }

        if (string.Equals(server.TrimEnd('/'), state.ServerUrl.TrimEnd('/'), StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine($"Already reporting to {state.ServerUrl}.");
            return 0;
        }

        Console.WriteLine($"Testing {server} before switching...");

        (ECDsa key, _) = DeviceKey.OpenOrCreate(AgentState.SoftwareKeyPath);

        using (key)
        {
            AgentReportPayload payload = Collect();

            using ReportClient client = new(server, key, Version);

            // The clock offset is deliberately NOT carried over: it was learned against the old
            // deployment, and a new one may be running a different clock. The client relearns it.
            (TransportResult result, string json) = await client
                .ReportAsync(payload, state.DeviceId, DateTimeOffset.UtcNow)
                .ConfigureAwait(false);

            if (!result.Succeeded)
            {
                Console.Error.WriteLine($"Refused by {server}: {result.Detail}");
                Console.Error.WriteLine($"Still reporting to {state.ServerUrl}. Nothing was changed.");
                return 1;
            }

            AgentState.Write(state with
            {
                ServerUrl = server.TrimEnd('/'),
                ClockOffsetSeconds = client.ClockOffsetSeconds,
                LastReportAt = DateTimeOffset.UtcNow,
                LastReportJson = json,
            });

            Console.WriteLine($"Now reporting to {server}.");
            return 0;
        }
    }

    /// <summary>
    /// Replaces this device's signing key, authenticated by the outgoing one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The incoming key is PERSISTED, and only after Merlin has accepted it.</b> Until 0.2 it was
    /// generated in memory, sent, and then discarded when the method returned: Merlin stored the new
    /// public key, the agent went on signing with the old private one, and every subsequent report
    /// was refused with the same generic message every other refusal uses. The machine went dark
    /// with no error anyone would connect to the rotation, and only a re-enrol recovered it.
    /// Persisting AFTER the response — never before — is what keeps a refused rotation harmless.
    /// </para>
    /// <para>
    /// <b>A TPM-held key cannot be rotated by this command, and it says so rather than downgrading.</b>
    /// The whole value of that key is that it is non-exportable and lives under one fixed container
    /// name, so there is no way to hold the outgoing and incoming keys at once — and the obvious
    /// shortcut, replacing it with a software key, would quietly turn the strongest evidence Merlin
    /// holds about a machine into the weakest without anyone deciding to. Re-enrolling is the honest
    /// path, and it produces a device row an administrator can see and reconcile.
    /// </para>
    /// </remarks>
    private static async Task<int> RotateAsync()
    {
        // THE SAME MACHINE-WIDE LOCK the scheduled commands take, and for the same reason: this
        // reads state, does network work, and writes state back. Without it an operator running
        // this while the updater happens to be mid-swap persists a pre-image and erases the swap
        // mark, which is a broken binary that can never be put back.
        using MachineLock? machineLock = MachineLock.TryAcquire(
            AgentState.Directory, TimeSpan.FromMinutes(2));

        if (machineLock is null)
        {
            Console.Error.WriteLine(
                "The agent or the updater is running. Nothing was changed; try again in a moment.");
            return 1;
        }

        AgentStateData? state = AgentState.Read();

        if (state is null)
        {
            Console.Error.WriteLine("This machine has not enrolled, so there is no key to rotate.");
            return 1;
        }

        (ECDsa outgoing, KeyAttestation attestation) = DeviceKey.OpenOrCreate(AgentState.SoftwareKeyPath);

        using (outgoing)
        {
            if (attestation == KeyAttestation.Tpm)
            {
                Console.Error.WriteLine(
                    "This device's key is held in the TPM and cannot be rotated in place — it is "
                    + "non-exportable, which is the point of it. Re-enrol the machine instead; "
                    + "Merlin will show the new device for you to approve and reconcile.");
                return 1;
            }

            // The incoming key is generated fresh and the request is signed with the OUTGOING one.
            // That signature is the whole security of rotation: it proves the caller is the device
            // that currently holds the enrolment.
            using ECDsa incoming = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            AgentRotateRequest request = new(
                Convert.ToBase64String(incoming.ExportSubjectPublicKeyInfo()),
                KeyAttestation.Software.ToString());

            using ReportClient client = new(state.ServerUrl, outgoing, Version);

            TransportResult result = await client
                .RotateAsync(request, state.DeviceId, DateTimeOffset.UtcNow.AddSeconds(state.ClockOffsetSeconds))
                .ConfigureAwait(false);

            if (!result.Succeeded)
            {
                Console.Error.WriteLine($"Rotation refused: {result.Detail}");
                Console.Error.WriteLine("The existing key is unchanged and this machine keeps reporting.");
                return 1;
            }

            DeviceKey.Replace(AgentState.SoftwareKeyPath, incoming);

            Console.WriteLine("Key rotated.");
            return 0;
        }
    }

    private static int Uninstall()
    {
        DeviceKey.Delete(AgentState.SoftwareKeyPath);
        AgentState.Delete();

        Console.WriteLine("Local agent state and signing key removed.");
        Console.WriteLine(
            "The device remains in Merlin's register with its history intact — retire it there if "
            + "the machine is being decommissioned.");

        return 0;
    }

    /// <summary>
    /// Runs the platform's query pack and folds in the readings osquery cannot take.
    /// </summary>
    /// <remarks>
    /// The platform is resolved once, by <see cref="AgentPlatformInfo"/>, and used to pick the pack
    /// and the normaliser together — so a machine can never read one platform's queries through
    /// another's normaliser, which would produce a report that is internally consistent and wrong.
    /// </remarks>
    private static AgentReportPayload Collect()
    {
        string? osquery = OsqueryRunner.Locate();
        OsqueryResults results;
        string? osqueryVersion = null;

        if (osquery is null)
        {
            // No osquery means no readings at all. Returning an empty result set rather than
            // throwing keeps the report shape valid: every signal becomes "not observed", which is
            // exactly what Merlin should be told, and the device still reports in so it does not
            // silently vanish from the fleet.
            Console.Error.WriteLine(
                "osquery was not found, so no readings could be taken. The report will say so.");

            results = new OsqueryResults();
        }
        else
        {
            OsqueryRunner runner = new(osquery, TimeSpan.FromSeconds(30));
            osqueryVersion = runner.Version();

            results = runner.RunAll(
                QueryPack.Load(),
                (name, detail) => Console.Error.WriteLine($"  query '{name}' failed: {detail}"));
        }

        DateTimeOffset now = DateTimeOffset.UtcNow;

        AgentReportPayload payload = AgentPlatformInfo.Current switch
        {
            AgentOs.Windows => WindowsNormaliser.ToPayload(results, now, Version, osqueryVersion),
            AgentOs.MacOs => MacOsNormaliser.ToPayload(results, now, Version, osqueryVersion),
            _ => LinuxNormaliser.ToPayload(results, now, Version, osqueryVersion),
        };

        return HostReader.Read().MergeInto(payload);
    }

    private static string? ArgumentValue(string[] args, string name)
    {
        for (int index = 0; index < args.Length - 1; index++)
        {
            if (string.Equals(args[index], name, StringComparison.OrdinalIgnoreCase))
            {
                return args[index + 1];
            }
        }

        return null;
    }

    private static int Print(string text)
    {
        Console.WriteLine(text);
        return 0;
    }

    private static int PrintUsage()
    {
        Console.WriteLine("""
            Merlin Agent — reports this machine's security posture to a Merlin ISMS deployment.

            It reads facts about the MACHINE only. It never reads who is signed in.
            Run 'merlin-agent status --manifest' to see every query it runs.

              merlin-agent enrol --server <url> --enrolment-key <key>
              merlin-agent collect
              merlin-agent status [--manifest]
              merlin-agent set-server --server <url>
              merlin-agent rotate-key
              merlin-agent uninstall
            """);

        return 1;
    }
}
