using Merlin.Agent.Core.Contracts;
using static Merlin.Agent.Core.Collection.ReadingParsers;

namespace Merlin.Agent.Core.Collection;

/// <summary>
/// Turns Linux osquery result sets into the wire payload.
/// </summary>
/// <remarks>
/// <para>
/// <b>Pure and static, like its Windows and macOS counterparts.</b> Most of a Linux machine's
/// hardening posture is not in an osquery table at all — Secure Boot, the TPM, the host firewall and
/// the password policy are read from <c>/sys</c>, <c>/etc</c> and the firewall front-end — so those
/// arrive as <see cref="SupplementalReadings"/> and are folded in rather than being read here.
/// </para>
/// <para>
/// <b>Two readings are deliberately left unobserved on Linux.</b> The screen-lock idle timeout is a
/// per-user desktop preference with no machine-scope equivalent, and a pending-security-update count
/// needs a network round trip to the distribution's mirrors that the agent will not make. Both stay
/// <c>null</c>, which Merlin renders as not observed. See <c>docs/collection-manifest.md</c>.
/// </para>
/// </remarks>
public static class LinuxNormaliser
{
    /// <summary>Builds the report payload from a collection run.</summary>
    /// <param name="results">The osquery result sets.</param>
    /// <param name="collectedAt">When the collection ran.</param>
    /// <param name="agentVersion">This agent's version.</param>
    /// <param name="osqueryVersion">The osquery build used.</param>
    /// <returns>The payload.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="results"/> is null.</exception>
    public static AgentReportPayload ToPayload(
        OsqueryResults results,
        DateTimeOffset collectedAt,
        string agentVersion,
        string? osqueryVersion)
    {
        ArgumentNullException.ThrowIfNull(results);

        return new AgentReportPayload(
            CollectedAt: collectedAt,
            AgentVersion: agentVersion,
            OsqueryVersion: osqueryVersion,
            Platform: AgentPlatform.Linux,
            Hostname: results.Value("system_info", "hostname") ?? Environment.MachineName,
            MachineGuid: results.Value("system_info", "uuid"),
            SerialNumber: results.Value("system_info", "hardware_serial"),
            Manufacturer: results.Value("system_info", "hardware_vendor"),
            Model: results.Value("system_info", "hardware_model"),
            ChassisType: null,
            EntraDeviceId: null,
            EntraTenantId: null,
            Os: new AgentOsReading(
                results.Value("os_version", "name"),
                results.Value("os_version", "version"),
                results.Value("kernel", "version"),
                Edition: null,
                // The distribution id (`ubuntu`, `debian`, `rhel`) rather than the pretty name,
                // because that is what Merlin's end-of-life table keys on and it survives a release
                // restyling its marketing name.
                Distribution: results.Value("os_version", "platform")),
            Encryption: Volumes(results),
            // Linux has no platform antimalware posture to read. A machine may be running ClamAV or
            // a commercial agent, and neither registers anywhere queryable — so this is genuinely
            // not observed rather than absent, and Merlin must not read it as "unprotected".
            AntiMalware: null,
            Hardening: null,
            Patching: null,
            Accounts: Accounts(results),
            Capacity: Capacity(results));
    }

    /// <summary>
    /// Reduces the machine's block devices to one encryption reading.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>ANY LUKS volume means the machine is encrypted, and this is a deliberate departure from
    /// the per-volume shape Windows and macOS use.</b> A fully encrypted Linux install still has an
    /// unencrypted <c>/boot</c> — that is how the scheme works, not a misconfiguration — so passing
    /// the raw per-volume rows to Merlin's weakest-volume-wins reduction would report every
    /// correctly encrypted Linux machine as unencrypted. That is a manufactured nonconformity
    /// against the exact configuration the control asks for.
    /// </para>
    /// <para>
    /// The cost is that a machine with an encrypted root and a genuinely unencrypted separate data
    /// volume also reports as encrypted. That is a real limitation, recorded in the manifest, and
    /// the safer of the two errors: it under-reports a second-order risk rather than raising a
    /// false finding against every machine.
    /// </para>
    /// </remarks>
    private static List<AgentVolumeReading>? Volumes(OsqueryResults results)
    {
        IReadOnlyList<Dictionary<string, string>> rows = results.Rows("disk_encryption");

        if (rows.Count == 0)
        {
            return null;
        }

        bool sawReading = false;
        bool anyEncrypted = false;

        foreach (Dictionary<string, string> row in rows)
        {
            bool? encrypted = ParseBool(Column(row, "encrypted"));

            if (encrypted is null)
            {
                continue;
            }

            sawReading = true;
            anyEncrypted |= encrypted.Value;
        }

        if (!sawReading)
        {
            return null;
        }

        return
        [
            new AgentVolumeReading(
                "/",
                anyEncrypted ? DiskEncryptionMethod.Luks : DiskEncryptionMethod.None,
                anyEncrypted,
                null),
        ];
    }

    /// <summary>
    /// Collects the accounts holding administrative rights.
    /// </summary>
    /// <remarks>
    /// <b>Two sources, unioned.</b> Linux has no single administrators group: rights come from
    /// membership of <c>sudo</c>, <c>wheel</c> or <c>admin</c> depending on the distribution, and
    /// separately from any account with uid 0. Reading only one of the two would let a second root
    /// account — the more serious finding of the pair — go uncounted.
    /// </remarks>
    private static AgentAccountsReading? Accounts(OsqueryResults results)
    {
        IReadOnlyList<string>? sudoers = AccountNames(results.Rows("local_admins"), "username");
        IReadOnlyList<string>? roots = AccountNames(results.Rows("root_accounts"), "username");

        if (sudoers is null && roots is null)
        {
            return null;
        }

        List<string> combined =
        [
            .. (sudoers ?? [])
                .Concat(roots ?? [])
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase),
        ];

        return new AgentAccountsReading(combined, null, null, null);
    }

    private static AgentCapacityReading? Capacity(OsqueryResults results)
    {
        long? available = ParseLong(results.Value("system_volume", "blocks_available"));
        long? blocks = ParseLong(results.Value("system_volume", "blocks"));

        return available is null || blocks is null or 0
            ? null
            : new AgentCapacityReading((int)(available.Value * 100 / blocks.Value));
    }
}
