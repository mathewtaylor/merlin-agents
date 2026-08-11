using System.Runtime.Versioning;
using System.Security.Cryptography;
using Merlin.Agent.Collection;
using Merlin.Agent.Core.Collection;
using Merlin.Agent.Core.Contracts;
using Merlin.Agent.Crypto;
using Merlin.Agent.State;
using Merlin.Agent.Transport;

namespace Merlin.Agent;

/// <summary>
/// The Merlin Agent command line.
/// </summary>
/// <remarks>
/// <para>
/// <b>A one-shot process, not a service.</b> It runs, collects, reports and exits — typically in
/// two or three seconds, every six hours, from a scheduled task. Nothing stays resident, so idle
/// cost is zero and there is no listening socket on an employee machine; a crashed run simply fires
/// again next interval instead of staying dead and looking like a passing check; and the binary is
/// never locked, so updating it is a file swap.
/// </para>
/// <para>
/// <b>It reads facts about the MACHINE and never about the person using it.</b> There is no query
/// for the signed-in user, the session or any mail address, and no configuration that adds one. See
/// <c>packaging/queries/windows.json</c> for the complete list of what is read.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class Program
{
    private const string Version = "0.1.0";

    /// <summary>Entry point.</summary>
    /// <param name="args">Command-line arguments.</param>
    /// <returns>Zero on success.</returns>
    public static async Task<int> Main(string[] args)
    {
        ArgumentNullException.ThrowIfNull(args);

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
            or CryptographicException or HttpRequestException)
        {
            // Expected operational failures: no network, no permission, no TPM. Reported plainly and
            // with a non-zero exit code so the scheduled task's history shows the failure, rather
            // than a stack trace nobody will read.
            Console.Error.WriteLine($"merlin-agent: {exception.Message}");
            return 1;
        }
    }

    private static async Task<int> EnrolAsync(string[] args)
    {
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
            OsqueryResults results = Collect(out string? osqueryVersion);
            AgentReportPayload payload = BuildPayload(results, osqueryVersion);

            AgentEnrolRequest request = new(
                DeviceKey.PublicKey(key),
                attestation.ToString(),
                Version,
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
            Console.WriteLine($"Signing key: {attestation}.");

            if (attestation == KeyAttestation.Software)
            {
                Console.WriteLine(
                    "  No usable TPM was found, so the key is held in software. Merlin records this "
                    + "and shows it against the device: a software key is weaker evidence because it "
                    + "can be copied.");
            }

            return 0;
        }
    }

    private static async Task<int> CollectAsync()
    {
        AgentStateData? state = AgentState.Read();

        if (state is null)
        {
            Console.Error.WriteLine(
                "This machine has not enrolled. Run: merlin-agent enrol --server <url> --enrolment-key <key>");
            return 1;
        }

        (ECDsa key, _) = DeviceKey.OpenOrCreate(AgentState.SoftwareKeyPath);

        using (key)
        {
            OsqueryResults results = Collect(out string? osqueryVersion);
            AgentReportPayload payload = BuildPayload(results, osqueryVersion);

            using ReportClient client = new(state.ServerUrl, key, Version);

            (TransportResult result, string json) = await client
                .ReportAsync(payload, state.DeviceId, DateTimeOffset.UtcNow.AddSeconds(state.ClockOffsetSeconds))
                .ConfigureAwait(false);

            // The payload is persisted whether or not Merlin accepted it, so `status` can always
            // show the operator exactly what this machine tried to send.
            AgentState.Write(state with
            {
                ClockOffsetSeconds = client.ClockOffsetSeconds == 0
                    ? state.ClockOffsetSeconds
                    : client.ClockOffsetSeconds,
                LastReportAt = result.Succeeded ? DateTimeOffset.UtcNow : state.LastReportAt,
                LastReportJson = json,
            });

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
            return 0;
        }

        Console.WriteLine($"Device:      {state.DeviceCode} ({state.DeviceId})");
        Console.WriteLine($"Reports to:  {state.ServerUrl}");
        Console.WriteLine($"Enrolled:    {state.EnrolledAt:yyyy-MM-dd HH:mm} UTC");
        Console.WriteLine($"Last report: {state.LastReportAt?.ToString("yyyy-MM-dd HH:mm") ?? "never"} UTC");
        Console.WriteLine($"Agent:       {Version}");
        Console.WriteLine();

        if (args.Contains("--manifest", StringComparer.OrdinalIgnoreCase))
        {
            Console.WriteLine("Everything this agent reads:");
            Console.WriteLine();

            foreach ((string name, string sql) in QueryPack.LoadWindows())
            {
                Console.WriteLine($"  [{name}]");
                Console.WriteLine($"  {sql}");
                Console.WriteLine();
            }

            Console.WriteLine(
                "Nothing else is collected. There is no query for the signed-in user, the session, "
                + "files, browsing or network traffic.");
            return 0;
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
            OsqueryResults results = Collect(out string? osqueryVersion);
            AgentReportPayload payload = BuildPayload(results, osqueryVersion);

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

    private static async Task<int> RotateAsync()
    {
        AgentStateData? state = AgentState.Read();

        if (state is null)
        {
            Console.Error.WriteLine("This machine has not enrolled, so there is no key to rotate.");
            return 1;
        }

        (ECDsa outgoing, _) = DeviceKey.OpenOrCreate(AgentState.SoftwareKeyPath);

        using (outgoing)
        {
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

            Console.WriteLine(result.Detail);
            return result.Succeeded ? 0 : 1;
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

    private static OsqueryResults Collect(out string? osqueryVersion)
    {
        string? osquery = OsqueryRunner.Locate();

        if (osquery is null)
        {
            osqueryVersion = null;

            // No osquery means no readings at all. Returning an empty result set rather than
            // throwing keeps the report shape valid: every signal becomes "not observed", which is
            // exactly what Merlin should be told, and the device still reports in so it does not
            // silently vanish from the fleet.
            Console.Error.WriteLine(
                "osquery was not found, so no readings could be taken. The report will say so.");

            return new OsqueryResults();
        }

        OsqueryRunner runner = new(osquery, TimeSpan.FromSeconds(30));
        osqueryVersion = runner.Version();

        return runner.RunAll(
            QueryPack.LoadWindows(),
            (name, detail) => Console.Error.WriteLine($"  query '{name}' failed: {detail}"));
    }

    private static AgentReportPayload BuildPayload(OsqueryResults results, string? osqueryVersion)
    {
        AgentReportPayload payload = WindowsNormaliser.ToPayload(
            results, DateTimeOffset.UtcNow, Version, osqueryVersion);

        // Password policy is not an osquery table, so it is read separately and merged. Merging
        // here rather than inside the normaliser keeps that function pure and platform-neutral.
        AgentAccountsReading? accounts =
            LocalPasswordPolicy.Read(payload.Accounts?.LocalAdministratorNames);

        return payload with { Accounts = accounts ?? payload.Accounts };
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
