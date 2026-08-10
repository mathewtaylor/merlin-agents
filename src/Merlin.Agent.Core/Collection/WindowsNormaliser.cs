using System.Globalization;
using Merlin.Agent.Core.Contracts;

namespace Merlin.Agent.Core.Collection;

/// <summary>
/// One osquery result set — the rows a named query returned, as string columns.
/// </summary>
/// <remarks>
/// Deliberately untyped. osquery returns every column as a JSON string on Windows, and the value of
/// keeping the raw shape here is that <see cref="WindowsNormaliser"/> becomes a pure function of it,
/// testable without osquery, without Windows and without a network.
/// </remarks>
public sealed class OsqueryResults
{
    private readonly Dictionary<string, IReadOnlyList<Dictionary<string, string>>> _sets =
        new(StringComparer.Ordinal);

    /// <summary>Records the rows a named query returned.</summary>
    /// <param name="queryName">The manifest query name.</param>
    /// <param name="rows">Its rows.</param>
    public void Add(string queryName, IReadOnlyList<Dictionary<string, string>> rows) =>
        _sets[queryName] = rows;

    /// <summary>
    /// The rows a named query returned, or an EMPTY list when it did not run or failed.
    /// </summary>
    /// <remarks>
    /// Empty rather than throwing: a query that could not run must degrade to a null reading, not
    /// take down the whole collection. A machine where one table is unavailable still has fifteen
    /// other readings worth sending.
    /// </remarks>
    /// <param name="queryName">The manifest query name.</param>
    /// <returns>The rows.</returns>
    public IReadOnlyList<Dictionary<string, string>> Rows(string queryName) =>
        _sets.TryGetValue(queryName, out IReadOnlyList<Dictionary<string, string>>? rows) ? rows : [];

    /// <summary>The first row of a named query, or <c>null</c>.</summary>
    /// <param name="queryName">The manifest query name.</param>
    /// <returns>The first row, or null.</returns>
    public Dictionary<string, string>? First(string queryName)
    {
        IReadOnlyList<Dictionary<string, string>> rows = Rows(queryName);
        return rows.Count == 0 ? null : rows[0];
    }

    /// <summary>Reads one column from the first row, or <c>null</c>.</summary>
    /// <param name="queryName">The manifest query name.</param>
    /// <param name="column">The column.</param>
    /// <returns>The value, or null when absent or blank.</returns>
    public string? Value(string queryName, string column)
    {
        Dictionary<string, string>? row = First(queryName);

        if (row is null || !row.TryGetValue(column, out string? value))
        {
            return null;
        }

        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}

/// <summary>
/// Turns osquery result sets into the wire payload.
/// </summary>
/// <remarks>
/// <para>
/// <b>Pure and static.</b> Every not-observed decision in the agent is made here, so all of them are
/// testable against fixture rows without a Windows machine — which matters because the not-observed
/// path is the one that never shows up on a healthy developer laptop and is exactly the path that
/// must not degrade into a false <c>false</c>.
/// </para>
/// <para>
/// <b>The rule, everywhere: absent or unparseable becomes <c>null</c>.</b> Never a default, never a
/// zero, never a <c>false</c>. Merlin reads null as "not observed" and will not fail a control on
/// it; it reads <c>false</c> as an observation that a protection is off, which raises one.
/// </para>
/// </remarks>
public static class WindowsNormaliser
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

        string? edition = results.Value("os_edition", "data");

        return new AgentReportPayload(
            CollectedAt: collectedAt,
            AgentVersion: agentVersion,
            OsqueryVersion: osqueryVersion,
            Hostname: results.Value("system_info", "hostname") ?? Environment.MachineName,
            MachineGuid: results.Value("machine_guid", "data"),
            SerialNumber: results.Value("system_info", "hardware_serial"),
            Manufacturer: results.Value("system_info", "hardware_vendor"),
            Model: results.Value("system_info", "hardware_model"),
            ChassisType: ChassisName(results.Value("chassis", "chassis_types")),
            EntraDeviceId: JoinValue(results, "DeviceId"),
            EntraTenantId: JoinValue(results, "TenantId"),
            Os: new AgentOsReading(
                results.Value("os_version", "name"),
                results.Value("os_version", "version"),
                results.Value("os_version", "build"),
                edition),
            Encryption: Volumes(results, edition),
            AntiMalware: AntiMalware(results),
            Hardening: Hardening(results),
            Patching: Patching(results),
            Accounts: Accounts(results),
            Capacity: Capacity(results));
    }

    /// <summary>
    /// Reads one value out of the Entra join-info rows.
    /// </summary>
    /// <remarks>
    /// The query itself already restricts to <c>DeviceId</c> and <c>TenantId</c>, so no user field
    /// ever reaches this method. This lookup is by name for the same reason: if the query is ever
    /// widened by mistake, nothing here starts forwarding new values.
    /// </remarks>
    private static string? JoinValue(OsqueryResults results, string name)
    {
        foreach (Dictionary<string, string> row in results.Rows("entra_join"))
        {
            if (row.TryGetValue("name", out string? key)
                && string.Equals(key, name, StringComparison.Ordinal)
                && row.TryGetValue("data", out string? data)
                && !string.IsNullOrWhiteSpace(data))
            {
                return data.Trim();
            }
        }

        return null;
    }

    /// <summary>
    /// Normalises per-volume encryption.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The Home-edition case is the whole reason this is not two lines.</b> On Home, BitLocker is
    /// unavailable but Device Encryption may be active, and <c>bitlocker_info</c> is how both are
    /// reported. So an unprotected volume on Home is <see cref="DiskEncryptionMethod.NotSupportedOnEdition"/>
    /// — a licensing fact — while an unprotected volume on Pro is
    /// <see cref="DiskEncryptionMethod.None"/>, which is somebody having switched it off. Merlin
    /// grades only the second.
    /// </para>
    /// <para>
    /// An EMPTY result is <c>null</c>, not an empty list: no rows means the table could not be read
    /// (a common outcome without administrative rights), and reporting that as "no encrypted
    /// volumes" would fail every such machine.
    /// </para>
    /// </remarks>
    private static List<AgentVolumeReading>? Volumes(OsqueryResults results, string? edition)
    {
        IReadOnlyList<Dictionary<string, string>> rows = results.Rows("bitlocker");

        if (rows.Count == 0)
        {
            return null;
        }

        bool isHome = IsHomeEdition(edition);
        List<AgentVolumeReading> volumes = [];

        foreach (Dictionary<string, string> row in rows)
        {
            string volume = Column(row, "drive_letter") ?? "?";
            int? protection = ParseInt(Column(row, "protection_status"));
            int? percent = ParseInt(Column(row, "percentage_encrypted"));

            DiskEncryptionMethod method;

            if (protection is null)
            {
                method = DiskEncryptionMethod.NotObserved;
            }
            else if (protection == 1)
            {
                method = isHome ? DiskEncryptionMethod.DeviceEncryption : DiskEncryptionMethod.BitLocker;
            }
            else
            {
                method = isHome
                    ? DiskEncryptionMethod.NotSupportedOnEdition
                    : DiskEncryptionMethod.None;
            }

            volumes.Add(new AgentVolumeReading(
                volume,
                method,
                protection is null ? null : protection == 1,
                percent));
        }

        return volumes;
    }

    /// <summary>
    /// Whether an <c>EditionID</c> denotes a Home edition.
    /// </summary>
    /// <remarks>
    /// <b>Windows Home's EditionID is literally <c>Core</c>, not <c>Home</c>.</b> Matching on the
    /// word "Home" therefore misses every actual Home machine — which would classify a retail laptop
    /// that cannot encrypt as one where somebody switched encryption off, and raise a nonconformity
    /// against the exact fleet this agent exists to serve. The registry values are
    /// <c>Core</c>, <c>CoreN</c>, <c>CoreSingleLanguage</c> and <c>CoreCountrySpecific</c>; the
    /// friendly product name ("Windows 11 Home") is also accepted because some machines report the
    /// caption here instead.
    /// </remarks>
    private static bool IsHomeEdition(string? edition)
    {
        if (string.IsNullOrWhiteSpace(edition))
        {
            return false;
        }

        string value = edition.Trim();

        return value.StartsWith("Core", StringComparison.OrdinalIgnoreCase)
            || value.Contains("Home", StringComparison.OrdinalIgnoreCase);
    }

    private static AgentAntiMalwareReading? AntiMalware(OsqueryResults results)
    {
        string? product = results.Value("security_products", "name");
        string? state = results.Value("security_products", "state");
        string? centre = results.Value("security_center", "antivirus");

        if (product is null && state is null && centre is null)
        {
            return null;
        }

        // windows_security_products.state is "On"/"Off"; windows_security_center.antivirus is
        // "Good"/"Poor"/"Snoozed"/"Not Monitored". Neither reports signature age directly, so
        // up-to-date is inferred from the security centre's own verdict and left NULL when it says
        // nothing — an inferred false here would fail a working machine.
        bool? enabled = state is null
            ? centre is null ? null : string.Equals(centre, "Good", StringComparison.OrdinalIgnoreCase)
            : string.Equals(state, "On", StringComparison.OrdinalIgnoreCase);

        bool? upToDate = centre switch
        {
            null => null,
            "Good" => true,
            "Poor" => false,
            _ => null,
        };

        return new AgentAntiMalwareReading(product, enabled, upToDate, null);
    }

    private static AgentHardeningReading? Hardening(OsqueryResults results)
    {
        bool? firewall = FirewallAllProfiles(results);
        int? timeout = ParseInt(results.Value("inactivity_timeout", "data"));
        bool? secureBoot = ParseBool(results.Value("secure_boot", "secure_boot"));

        Dictionary<string, string>? tpm = results.First("tpm");
        bool? tpmPresent = tpm is null
            ? null
            : ParseBool(Column(tpm, "enabled")) == true && ParseBool(Column(tpm, "activated")) == true;
        string? tpmVersion = tpm is null ? null : Column(tpm, "spec_version");

        return firewall is null && timeout is null && secureBoot is null && tpmPresent is null
            ? null
            : new AgentHardeningReading(firewall, timeout, secureBoot, tpmPresent, tpmVersion);
    }

    /// <summary>
    /// Whether every firewall profile is enabled.
    /// </summary>
    /// <remarks>
    /// Windows has three profiles and the control is only met when all of them are on, so this is
    /// an AND across the rows. No rows at all is <c>null</c> — the registry read failed — rather
    /// than <c>true</c>, which "all zero of them are enabled" would otherwise vacuously produce.
    /// </remarks>
    private static bool? FirewallAllProfiles(OsqueryResults results)
    {
        IReadOnlyList<Dictionary<string, string>> rows = results.Rows("firewall_profiles");

        if (rows.Count == 0)
        {
            return null;
        }

        bool sawValue = false;
        bool allEnabled = true;

        foreach (Dictionary<string, string> row in rows)
        {
            int? value = ParseInt(Column(row, "data"));

            if (value is null)
            {
                continue;
            }

            sawValue = true;
            allEnabled &= value == 1;
        }

        return sawValue ? allEnabled : null;
    }

    private static AgentPatchingReading? Patching(OsqueryResults results)
    {
        string? installedOn = results.Value("patches", "installed_on");

        // The count of PENDING updates is deliberately absent in v1: osquery has no table for it,
        // and the Windows Update COM API is a dependency this agent does not want. Merlin's patch
        // rule falls back to the age of the last installed update, which IS observable here.
        return installedOn is null
            ? null
            : new AgentPatchingReading(null, ParseDate(installedOn));
    }

    private static AgentAccountsReading? Accounts(OsqueryResults results)
    {
        IReadOnlyList<Dictionary<string, string>> rows = results.Rows("local_admins");

        List<string>? admins = rows.Count == 0
            ? null
            : [.. rows
                .Select(row => Column(row, "username"))
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Select(name => name!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase)];

        // Password policy is filled in by the Windows collector from `net accounts`, not by osquery,
        // which has no table for the local SAM policy. Left null here and merged afterwards.
        return admins is null ? null : new AgentAccountsReading(admins, null, null, null);
    }

    private static AgentCapacityReading? Capacity(OsqueryResults results)
    {
        long? free = ParseLong(results.Value("system_drive", "free_space"));
        long? size = ParseLong(results.Value("system_drive", "size"));

        return free is null || size is null or 0
            ? null
            : new AgentCapacityReading((int)(free.Value * 100 / size.Value));
    }

    /// <summary>
    /// Maps a SMBIOS chassis type code to a name.
    /// </summary>
    /// <remarks>
    /// Only the codes that change how a machine should be read are named; anything else becomes
    /// <c>null</c> rather than a guess, because this value pre-fills an asset record and a wrong
    /// guess would be written into the A.5.9 inventory by whoever accepts it.
    /// </remarks>
    private static string? ChassisName(string? code) => code?.Trim() switch
    {
        "8" or "9" or "10" or "14" or "30" or "31" or "32" => "Laptop",
        "3" or "4" or "5" or "6" or "7" or "15" or "16" => "Desktop",
        "17" or "23" or "28" or "29" => "Server",
        _ => null,
    };

    private static string? Column(Dictionary<string, string> row, string column) =>
        row.TryGetValue(column, out string? value) && !string.IsNullOrWhiteSpace(value)
            ? value.Trim()
            : null;

    private static int? ParseInt(string? value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : null;

    private static long? ParseLong(string? value) =>
        long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsed)
            ? parsed
            : null;

    private static bool? ParseBool(string? value) => value?.Trim().ToUpperInvariant() switch
    {
        "1" or "TRUE" or "YES" or "ON" => true,
        "0" or "FALSE" or "NO" or "OFF" => false,
        _ => null,
    };

    /// <summary>
    /// Parses an osquery date, which is a Unix epoch on some tables and a formatted date on others.
    /// </summary>
    private static DateTimeOffset? ParseDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long epoch)
            && epoch > 0)
        {
            try
            {
                return DateTimeOffset.FromUnixTimeSeconds(epoch);
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
        }

        return DateTimeOffset.TryParse(
            value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset parsed)
            ? parsed
            : null;
    }
}
