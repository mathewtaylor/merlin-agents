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
        // UNFILTERED, DELIBERATELY — the same rule the updater's Main states, and it was reached
        // there by the same route: a named list reads as the more careful choice and is the weaker
        // one. This list had already grown twice, each time after a type walked past it and ended a
        // scheduled run in a stack trace nobody reads, and it was still short. UriFormatException
        // is the reachable one: a hand-edited or migrated state.json with a malformed ServerUrl
        // throws it out of ReportClient's constructor, inside the collection — which sits OUTSIDE
        // UpdateTurn's own fault boundary by design, so nothing below catches it.
        //
        // UpdateTurn already contains whatever escapes the update work and reports it as a fault.
        // This catch is what stops everything AROUND that — reading the state, taking the lock,
        // opening the device key, the collection itself — costing the operator a stack trace
        // instead of a sentence and an exit code.
#pragma warning disable CA1031
        catch (Exception exception)
#pragma warning restore CA1031
        {
            Console.Error.WriteLine($"merlin-agent: {exception.Message}");
            return 1;
        }
    }

    /// <summary>
    /// Says so, loudly, when a deployment address is plaintext.
    /// </summary>
    /// <remarks>
    /// <b>Plaintext is permitted because a deployment behind a private ingress or on a developer's
    /// machine is a real case — but it is not free, and it used to be silent.</b> The update-check
    /// RESPONSE is not signed: only the request is. So TLS is the only thing standing between an
    /// on-path attacker and the version, address and digest this machine is told to move to. The
    /// compile-time host allowlist still confines the download to the GitHub release hosts, so the
    /// worst case is being pinned to a different genuine release rather than to an attacker's
    /// build — bounded, and not nothing. <c>PackageHosts</c> refuses plaintext outright for exactly
    /// this reason; this address cannot be refused without breaking those deployments, so it warns.
    /// </remarks>
    /// <param name="server">The address as given.</param>
    private static void WarnIfPlaintext(string server)
    {
        if (Uri.TryCreate(server, UriKind.Absolute, out Uri? parsed)
            && parsed.Scheme == Uri.UriSchemeHttp)
        {
            Console.Error.WriteLine(
                $"Warning: {server} is plaintext http. Reports and the update check are not "
                + "protected in transit, and the update answer — the version and hash this machine "
                + "is told to install — is not signed, so anyone on the path can change it. Use "
                + "https unless this is a test deployment.");
        }
    }

    private static async Task<int> EnrolAsync(string[] args)
    {
        // Enrolment replaces the state record wholesale, so it must not land while the updater is
        // mid-swap and about to write a mark of its own.
        using MachineLock? enrolLock = MachineLock.TryAcquire(
            AgentState.Directory, TimeSpan.FromMinutes(2), out bool accessDenied);

        if (enrolLock is null)
        {
            Console.Error.WriteLine(accessDenied
                ? "merlin-agent could not take the machine lock. It must run as root (or SYSTEM on "
                    + "Windows); nothing was done."
                : "The agent or the updater is running. Nothing was changed; try again in a moment.");
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

        WarnIfPlaintext(server);

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

            // MERGED ONTO WHAT IS ALREADY THERE, not written over it. Re-enrolling is an explicitly
            // supported flow — the same public key updates the existing device rather than
            // creating a second one — and it is what an operator does to fix a sick machine, which
            // is the worst possible moment to erase the update bookkeeping. A fresh record defaults
            // every optional field to null, so an outstanding swap mark, the version stamped with
            // it and LastRevertedVersion all vanished, and none of them is re-derivable: the
            // machine would then never put back a binary that does not run, and would happily
            // re-download a release it had already proved broken here.
            //
            // The PENDING NOTE is deliberately cleared, because it names an address and a digest
            // advertised by the deployment being enrolled away from.
            AgentStateData enrolled = AgentState.Read() ?? new AgentStateData(
                server,
                response.DeviceId,
                response.DeviceCode,
                DateTimeOffset.UtcNow,
                client.ClockOffsetSeconds,
                LastReportAt: null,
                LastReportJson: null);

            // A DIFFERENT DEPLOYMENT GETS A CLEAN UPDATE RECORD. Preserving the bookkeeping is
            // right when re-enrolling to the SAME Merlin — that is what stops an operator's
            // reinstall erasing an unproven swap or the memory of a broken release. Carried across
            // a move it is worse than useless: version strings are not global, so a release this
            // machine blocklisted under the old deployment would be refused under a new one that
            // considers it good, with no way to clear it short of editing state.json by hand; and
            // the new deployment's device page would show an outcome for an update it never made.
            bool movedDeployment = !string.Equals(
                enrolled.ServerUrl.TrimEnd('/'), server.TrimEnd('/'), StringComparison.OrdinalIgnoreCase);

            AgentState.Write(enrolled with
            {
                ServerUrl = server,
                LastRevertedVersion = movedDeployment ? null : enrolled.LastRevertedVersion,
                LastUpdateOutcome = movedDeployment ? null : enrolled.LastUpdateOutcome,
                LastUpdateAt = movedDeployment ? null : enrolled.LastUpdateAt,
                LastUpdateDetail = movedDeployment ? null : enrolled.LastUpdateDetail,
                DeviceId = response.DeviceId,
                DeviceCode = response.DeviceCode,
                EnrolledAt = DateTimeOffset.UtcNow,
                ClockOffsetSeconds = client.ClockOffsetSeconds,
                LastReportAt = null,
                LastReportJson = null,
                PendingComponent = null,
                PendingVersion = null,
                PendingPackageEndpoint = null,
                PendingSha256 = null,
            });

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
    /// <b>The envelope is <see cref="UpdateTurn"/>, which the updater runs too.</b> Taking the
    /// machine lock, re-reading the state under it, refusing to stamp a run for an image that was
    /// replaced while it waited, stamping before anything fallible, and persisting afterwards are
    /// all its rules — written once, and under test. This method supplies only what is peculiar to
    /// the agent: the collection and the report, which run INSIDE that lock.
    /// </para>
    /// <para>
    /// <b>The report happens FIRST and the update work cannot stop it.</b> A failed update must
    /// never leave a machine unable to report: silence in the fleet is indistinguishable from a
    /// machine that was never enrolled, so the whole update turn sits behind the report and inside
    /// a fault boundary that swallows everything. The outcome it records is sent on the NEXT
    /// report, one run later, which is the price of that ordering and worth paying.
    /// </para>
    /// <para>
    /// <b>The machine-wide lock is taken for the whole run.</b> It is what stops the updater
    /// swapping this binary while it is executing — and, held across the collection rather than
    /// around the swap alone, it also means the updater is never mid-swap when a collection starts.
    /// That is why the collection is a hook inside the turn and not a step before it.
    /// </para>
    /// </remarks>
    private static async Task<int> CollectAsync()
    {
        // What the report did, read after the turn to decide this process's exit code. The turn
        // itself has no opinion about it: a refused report is a failed run, and a failed update is
        // not.
        TransportResult? report = null;

        UpdateTurn turn = new(
            AgentComponent.Agent,
            InstallLayout.Current,
            () => new DeviceUpdateSession(async (key, state, token) =>
            {
                AgentReportPayload payload = Collect() with
                {
                    // THE OUTCOME IS REPORTED, NEVER INFERRED. A server watching only the agent
                    // version cannot tell "updated and rolled back" from "never attempted" — both
                    // leave the version unmoved — and a silent failed update is the worst thing
                    // auto-update can produce.
                    UpdaterVersion = BinaryProbe.Default.Version(
                        InstallLayout.Current.PathOf(AgentComponent.Updater)),
                    LastUpdateOutcome = state.LastUpdateOutcome?.ToString(),
                };

                // SEEDED WITH THE STORED OFFSET, and handed a RAW instant below. Pre-applying it
                // here as well made the client learn a RESIDUAL, which was then persisted into a
                // field every other reader treats as absolute — see ReportClient's remarks for why
                // that never converges.
                using ReportClient client = new(
                    state.ServerUrl, key, Version, state.ClockOffsetSeconds);

                // THE ATTEMPT IS TOTAL, so the update turn that follows is reached whatever the
                // network did. ReportAsync reports an unreachable Merlin as a failed report rather
                // than throwing — an outage, a DNS failure, a proxy change or an expired
                // certificate used to go straight past the turn into Main, and those are three of
                // the four cases the ordering exists to serve. It is caught THERE rather than here
                // so the JSON it built still comes back with it; catching here left `status`
                // showing the previous payload.
                (TransportResult result, string json) = await client
                    .ReportAsync(payload, state.DeviceId, DateTimeOffset.UtcNow)
                    .ConfigureAwait(false);

                report = result;

                // The payload is persisted whether or not Merlin accepted it, so `status` can
                // always show the operator exactly what this machine tried to send.
                return state with
                {
                    // Written back unconditionally: the client STARTS at the stored value, so an
                    // untouched offset writes itself and a relearned one replaces it. The old
                    // "zero means it learned nothing" test existed only because the client used to
                    // start at zero, and it is wrong once the client is seeded.
                    ClockOffsetSeconds = client.ClockOffsetSeconds,
                    LastReportAt = result.Succeeded ? DateTimeOffset.UtcNow : state.LastReportAt,
                    LastReportJson = json,
                };
            }),

            // A SWAP IS WORTH A LINE EVEN ON AN UNATTENDED RUN, and the turn's own commentary is
            // not. Nobody is watching a scheduled collection, but a replaced binary is the one
            // thing in this process that changes the machine, and the scheduler's own log is where
            // an operator looks for it afterwards.
            swapLog: Console.WriteLine,
            decisionLog: _ => { },

            // NO MINIMUM INTERVAL. The agent collects, and skipping a collection to spare a
            // download would trade the thing this machine exists to do for the thing it does on
            // the side.
            minimumInterval: null);

        UpdateTurnResult outcome = await turn.RunAsync().ConfigureAwait(false);

        switch (outcome.Status)
        {
            case UpdateTurnStatus.NotEnrolled:
                Console.Error.WriteLine(
                    "This machine has not enrolled. Run: merlin-agent enrol --server <url> --enrolment-key <key>");
                return 1;

            case UpdateTurnStatus.RightsRefused:

                // A RIGHTS FAILURE IS NOT CONTENTION, and reporting it as such is how a machine
                // goes quiet while looking healthy: an agent started without root or SYSTEM waited
                // out the whole timeout and then exited ZERO, collecting nothing, on every
                // scheduled fire.
                Console.Error.WriteLine(
                    "merlin-agent could not take the machine lock. It must run as root (or SYSTEM "
                    + "on Windows); nothing was collected.");
                return 1;

            case UpdateTurnStatus.Contended:

                // Not being able to take it means the updater is mid-run and may be replacing this
                // very binary. Reporting anyway would be harmless; collecting into a directory
                // being rewritten would not. The scheduler fires again in six hours.
                Console.Error.WriteLine(
                    "The updater is running. Nothing was collected; the agent will try again on "
                    + "its next scheduled run.");
                return 0;

            case UpdateTurnStatus.Replaced:

                // The updater swapped merlin-agent while this run sat waiting for the lock, so the
                // image executing here is the OLD one, already loaded into memory. Stamping a run
                // would tell the next updater run that the NEW binary has proved itself when it has
                // never executed: the swap mark would be dropped, recovery would short-circuit for
                // ever, and the replaced binary could never be put back. One collection is skipped;
                // the scheduler starts the binary that is actually on disk next interval, and that
                // run is the only honest witness for it.
                Console.Error.WriteLine(
                    "This agent was replaced while it waited for the lock. Nothing was collected; "
                    + "the new binary runs on the next scheduled collection.");
                return 0;

            case UpdateTurnStatus.TooSoon:

                // Unreachable while the agent passes no minimum interval, and handled anyway. It
                // is a live enum member that the updater already answers explicitly, and left to
                // the arm below it would have taken the ONE path there that assumes the collection
                // ran — printing "Report refused:" with an empty detail and exiting 1, which is a
                // healthy machine reported as a failed run on every gated fire. That is the same
                // shape as the rights-failure-reported-as-contention defect, arriving by a
                // different door.
                return 0;

            default:

                // BEFORE THE REPORT'S OWN EXIT CODE, because that is the order the two lines were
                // written in and an update failure is context for the report line rather than a
                // replacement for it.
                if (outcome.Fault is { } fault)
                {
                    Console.Error.WriteLine($"  the updater check did not complete: {fault}");
                }

                // NO REPORT AT ALL IS NOT A REFUSED REPORT. Every status that stops the turn before
                // the collection is answered above, so reaching here with nothing recorded would
                // mean a status added later fell through — and reporting that as a refusal names a
                // failure that did not happen. Say nothing and exit clean; the arm above is where a
                // new member belongs.
                if (report is null)
                {
                    return 0;
                }

                if (!report.Succeeded)
                {
                    Console.Error.WriteLine($"Report refused: {report.Detail}");
                    return 1;
                }

                Console.WriteLine(report.Detail);

                return 0;
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
            // A RIGHTS FAILURE IS NOT AN ABSENCE, and reporting it as one is how this command
            // became misleading to the very person it was written for. The state directory is
            // 0700 and root-owned on macOS and Linux, so an ordinary user cannot traverse it:
            // File.Exists answers false, the read returns null, and the honest answer — "you
            // cannot see it from here" — came out as "there is nothing here". An employee running
            // this to check what their machine sends was told the agent was not enrolled while it
            // was reporting perfectly well.
            Console.WriteLine(
                StateDirectoryIsUnreadable()
                    ? "The state directory exists but cannot be read from this account. Run this "
                        + "as root (or as Administrator on Windows): it is restricted to the "
                        + "superuser because the device key lives beside the state file."
                    : "This machine has not enrolled.");

            // BOTH COMPONENTS, even here. "Not enrolled" and "the updater was never installed" are
            // different faults with different fixes, and a machine that is silent is exactly when
            // an operator needs to tell them apart.
            PrintComponents();

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
    /// <summary>
    /// Whether the state directory is there but shut to this account.
    /// </summary>
    /// <remarks>
    /// <b>Asked by TRYING, not by testing the directory's existence.</b> A directory that exists
    /// and is readable and simply holds no state file is a machine that has not enrolled, and
    /// saying "run as root" to that person sends them after a permission problem they do not have.
    /// Only an enumeration that is actually refused distinguishes the two.
    /// </remarks>
    /// <returns><c>true</c> when the directory exists and this account cannot read it.</returns>
    private static bool StateDirectoryIsUnreadable()
    {
        if (!Directory.Exists(AgentState.Directory))
        {
            return false;
        }

        try
        {
            // EAGER, and the result deliberately discarded. The refusal only surfaces when
            // something actually reads the directory, so a lazy enumerator that is never walked
            // would answer "readable" for a directory nobody can open.
            _ = Directory.GetFileSystemEntries(AgentState.Directory);
            return false;
        }
        catch (UnauthorizedAccessException)
        {
            return true;
        }
        catch (IOException)
        {
            return false;
        }
    }

    /// <summary>Names both installed components, with or without a state file.</summary>
    /// <remarks>
    /// <b>Which binaries are on this machine is a fact about the DISK, not about enrolment</b> —
    /// and the two questions an operator brings to a machine that is not reporting are "is it
    /// enrolled" and "did the updater ever get installed". Printing the components only after the
    /// state file was read answered the second only when the first was already fine, which is the
    /// case where nobody needed to ask.
    /// </remarks>
    private static void PrintComponents()
    {
        string updaterPath = InstallLayout.Current.PathOf(AgentComponent.Updater);

        string updater = !File.Exists(updaterPath)
            ? "not installed — this machine will not update itself"
            : BinaryProbe.Default.Version(updaterPath) ?? "installed, but it would not run";

        Console.WriteLine($"Agent:       {Version}");
        Console.WriteLine($"Updater:     {updater}");
    }

    private static void PrintUpdaterStatus(AgentStateData state)
    {
        PrintComponents();
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
            AgentState.Directory, TimeSpan.FromMinutes(2), out bool accessDenied);

        if (machineLock is null)
        {
            Console.Error.WriteLine(accessDenied
                ? "merlin-agent could not take the machine lock. It must run as root (or SYSTEM on "
                    + "Windows); nothing was done."
                : "The agent or the updater is running. Nothing was changed; try again in a moment.");
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

        WarnIfPlaintext(server);

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
            AgentState.Directory, TimeSpan.FromMinutes(2), out bool accessDenied);

        if (machineLock is null)
        {
            Console.Error.WriteLine(accessDenied
                ? "merlin-agent could not take the machine lock. It must run as root (or SYSTEM on "
                    + "Windows); nothing was done."
                : "The agent or the updater is running. Nothing was changed; try again in a moment.");
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

            using ReportClient client = new(
                state.ServerUrl, outgoing, Version, state.ClockOffsetSeconds);

            TransportResult result = await client
                .RotateAsync(request, state.DeviceId, DateTimeOffset.UtcNow)
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
        // UNDER THE LOCK, like every other command that writes state. Without it an uninstall
        // racing a mid-swap updater is undone by that updater's closing AgentState.Write, which
        // RESURRECTS state.json — pointing at a device whose key has just been deleted. The next
        // collect then creates a fresh key and every report from that machine is refused for ever,
        // which is a considerably worse end state than a failed uninstall.
        using (MachineLock? machineLock = MachineLock.TryAcquire(
            AgentState.Directory, TimeSpan.FromMinutes(2), out bool accessDenied))
        {
            if (machineLock is null)
            {
                Console.Error.WriteLine(accessDenied
                    ? "merlin-agent could not take the machine lock. It must run as root (or "
                        + "SYSTEM on Windows); nothing was removed."
                    : "The agent or the updater is running. Nothing was removed; try again in a "
                        + "moment.");
                return 1;
            }

            DeviceKey.Delete(AgentState.SoftwareKeyPath);
            AgentState.Delete();
        }

        // Only once the lock is released, or the file being removed is the one still held.
        TryRemove(MachineLock.PathIn(AgentState.Directory));
        TryRemoveDirectory(InstallLayout.Current.StagingDirectory);

        Console.WriteLine("Local agent state and signing key removed.");
        Console.WriteLine(
            "The device remains in Merlin's register with its history intact — retire it there if "
            + "the machine is being decommissioned.");

        return 0;
    }

    private static void TryRemove(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Uninstall reports what it removed; a leftover lock file is inert and harmless.
        }
    }

    private static void TryRemoveDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // As above: a leftover staging tree is litter, not a failure worth reporting.
        }
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
