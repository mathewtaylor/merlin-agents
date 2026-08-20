using Merlin.Agent.Core.Contracts;
using static Merlin.Agent.Core.Collection.ReadingParsers;

namespace Merlin.Agent.Core.Collection;

/// <summary>
/// Turns macOS osquery result sets into the wire payload.
/// </summary>
/// <remarks>
/// <para>
/// <b>Pure and static, like its Windows counterpart</b>, so every not-observed decision is testable
/// against fixture rows on any machine. That matters more here than on Windows: macOS exposes less
/// of its security posture at machine scope than Windows does, so the not-observed path is the
/// COMMON path rather than the exceptional one, and getting it wrong would mis-grade every Mac in a
/// fleet rather than the occasional one.
/// </para>
/// <para>
/// <b>Three readings are deliberately left unobserved on macOS, and each is a real gap rather than
/// an oversight.</b> Screen-lock idle timeout, patch currency and antimalware signature age have no
/// machine-scope source on an unmanaged Mac — they are per-user preferences or require a network
/// round trip the agent will not make. Merlin renders them as not observed, which is the honest
/// answer; inventing a value would make a Mac look either compliant or non-compliant on evidence
/// that does not exist. See <c>docs/collection-manifest.md</c>.
/// </para>
/// </remarks>
public static class MacOsNormaliser
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
            Platform: AgentPlatform.MacOs,
            Hostname: results.Value("system_info", "hostname") ?? Environment.MachineName,
            MachineGuid: results.Value("system_info", "uuid"),
            SerialNumber: results.Value("system_info", "hardware_serial"),
            Manufacturer: results.Value("system_info", "hardware_vendor") ?? "Apple Inc.",
            Model: results.Value("system_info", "hardware_model"),
            ChassisType: ChassisName(results.Value("system_info", "hardware_model")),
            // A Mac can be Entra-registered through Company Portal, but the identifier lives in the
            // login keychain rather than anywhere machine-readable. Null is correct: the coverage
            // ladder falls through to the asset register, which is where an unmanaged Mac belongs.
            EntraDeviceId: null,
            EntraTenantId: null,
            Os: new AgentOsReading(
                results.Value("os_version", "name"),
                results.Value("os_version", "version"),
                results.Value("os_version", "build"),
                // macOS has no edition. Reporting one would invent a distinction the platform does
                // not have, and Merlin's Windows-only edition rules read this field.
                Edition: null,
                Distribution: null),
            Encryption: Volumes(results),
            AntiMalware: AntiMalware(results),
            Hardening: Hardening(results),
            Patching: null,
            Accounts: Accounts(results),
            Capacity: Capacity(results));
    }

    /// <summary>
    /// Reduces the machine's disks to one FileVault reading.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>FileVault is a whole-machine setting, so this is a machine-level answer rather than a
    /// per-volume one.</b> The obvious alternative — scope the query to the root volume by joining
    /// <c>mounts</c> — does not survive contact with modern macOS, where the system volume is a
    /// sealed snapshot and the data volume is separate, so the join matches nothing on APFS and
    /// every Mac would report encryption as not observed. Passing the raw per-disk rows through
    /// instead would fail a properly encrypted Mac the moment somebody plugged in a USB stick,
    /// because Merlin reduces volumes to the weakest one.
    /// </para>
    /// <para>
    /// <b><c>filevault_status</c> is preferred over <c>encrypted</c>, and the fallback matters.</b>
    /// The first answers the question the control actually asks; the second is true of any
    /// encrypted volume including a mounted disk image. Where neither is readable the answer is
    /// <c>null</c> — never an inferred <c>false</c>.
    /// </para>
    /// </remarks>
    private static List<AgentVolumeReading>? Volumes(OsqueryResults results)
    {
        IReadOnlyList<Dictionary<string, string>> rows = results.Rows("filevault");

        if (rows.Count == 0)
        {
            return null;
        }

        bool? fileVault = null;
        bool sawEncryptedFlag = false;
        bool anyEncrypted = false;

        foreach (Dictionary<string, string> row in rows)
        {
            switch (Column(row, "filevault_status")?.ToUpperInvariant())
            {
                case "ON":
                    fileVault = true;
                    break;

                case "OFF":
                    fileVault ??= false;
                    break;

                default:
                    break;
            }

            if (ParseBool(Column(row, "encrypted")) is bool encrypted)
            {
                sawEncryptedFlag = true;
                anyEncrypted |= encrypted;
            }
        }

        bool? protectedVolume = fileVault ?? (sawEncryptedFlag ? anyEncrypted : null);

        if (protectedVolume is null)
        {
            return null;
        }

        return
        [
            new AgentVolumeReading(
                "/",
                protectedVolume.Value ? DiskEncryptionMethod.FileVault : DiskEncryptionMethod.None,
                protectedVolume,
                null),
        ];
    }

    /// <summary>
    /// Normalises macOS's malware-prevention posture.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Gatekeeper is the signal, and it is not the same thing as an antivirus product.</b> macOS
    /// has no registry of security products to read and no "real-time protection" flag; what it has
    /// is Gatekeeper, which refuses unsigned and un-notarised code, and XProtect, which is always on
    /// and cannot be switched off. Gatekeeper being off IS a genuine A.8.7 finding, so it is
    /// reported as the enabled flag.
    /// </para>
    /// <para>
    /// <b>Currency is left <c>null</c> and must stay that way.</b> XProtect definitions update
    /// silently through a channel with no locally readable "current" version to compare against, so
    /// any freshness verdict here would be invented. Merlin's rule treats an unreported half as
    /// not-failing, which is why this costs nothing.
    /// </para>
    /// <para>
    /// A third-party product on the machine is invisible to this reading, so a Mac running a managed
    /// endpoint agent with Gatekeeper deliberately relaxed reports as failing. That is a false
    /// positive a human resolves, which is the safe direction.
    /// </para>
    /// </remarks>
    private static AgentAntiMalwareReading? AntiMalware(OsqueryResults results)
    {
        bool? gatekeeper = ParseBool(results.Value("gatekeeper", "assessments_enabled"));

        return gatekeeper is null
            ? null
            : new AgentAntiMalwareReading("Gatekeeper + XProtect", gatekeeper, null, null);
    }

    private static AgentHardeningReading? Hardening(OsqueryResults results)
    {
        bool? firewall = Firewall(results);
        int? screenLock = ScreenLock(results);
        bool? sip = ParseBool(results.Value("sip", "enabled"));
        bool? secureEnclave = SecureEnclave(results);

        return firewall is null && screenLock is null && sip is null && secureEnclave is null
            ? null
            : new AgentHardeningReading(
                firewall,
                screenLock,
                sip,
                secureEnclave,
                secureEnclave == true ? "Apple Secure Enclave" : null);
    }

    /// <summary>
    /// Reads the macOS application firewall.
    /// </summary>
    /// <remarks>
    /// <c>alf.global_state</c> is 0 (off), 1 (on, per-service) or 2 (on, block all inbound). Both
    /// non-zero states are the firewall being in force, so the reading is <c>state &gt; 0</c> — the
    /// stricter mode is a configuration choice rather than a different control.
    /// </remarks>
    private static bool? Firewall(OsqueryResults results)
    {
        int? state = ParseInt(results.Value("alf", "global_state"));
        return state is null ? null : state > 0;
    }

    /// <summary>
    /// Reads the screen-lock posture.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Only one of the two possible answers is observable, and the other must stay <c>null</c>.</b>
    /// <c>screenlock.enabled</c> says whether unlocking requires a password, which is machine-scope
    /// and readable. How long the machine sits idle before it locks is a per-user preference in the
    /// console user's own domain, and on an unmanaged Mac there is no machine-wide value at all.
    /// </para>
    /// <para>
    /// So: not requiring a password is reported as <c>0</c> — Merlin's spelling of "never locks",
    /// an observed failure. Requiring one is reported as <c>null</c>, because the criterion is
    /// "locks within fifteen minutes" and the interval genuinely was not observed.
    /// <b>Do not substitute <c>grace_period</c> here.</b> It is the delay AFTER the screensaver
    /// starts, not the idle time before it does, so reporting it as the lock timeout would
    /// understate a machine's exposure — and overstating security is the one direction of error
    /// this agent must not have.
    /// </para>
    /// </remarks>
    private static int? ScreenLock(OsqueryResults results)
    {
        bool? enabled = ParseBool(results.Value("screenlock", "enabled"));

        return enabled switch
        {
            false => 0,
            _ => null,
        };
    }

    /// <summary>
    /// Whether the machine has an Apple security processor holding keys in hardware.
    /// </summary>
    /// <remarks>
    /// <b>A hardware fact read from the CPU, not a guess, and it never reports absence.</b> Every
    /// Apple-silicon Mac has a Secure Enclave; an Intel Mac may or may not have a T2, and no osquery
    /// table exposes it. So an Apple CPU reports <c>true</c> and anything else reports <c>null</c> —
    /// never <c>false</c>, which would assert that a T2-equipped iMac lacks one.
    /// </remarks>
    private static bool? SecureEnclave(OsqueryResults results)
    {
        // FROM ITS OWN QUERY, not from `system_info`. This is the only hardware-security-processor
        // signal macOS exposes, and it was being read out of the inventory query that runs LAST —
        // so a machine that ran out of collection budget gave this reading up before it gave up its
        // hostname, which is the inversion the pack ordering exists to prevent.
        string? cpu = results.Value("secure_enclave", "cpu_brand");

        return cpu is not null && cpu.Contains("Apple", StringComparison.OrdinalIgnoreCase)
            ? true
            : null;
    }

    private static AgentAccountsReading? Accounts(OsqueryResults results)
    {
        IReadOnlyList<string>? admins = AccountNames(results.Rows("local_admins"), "username");

        // The password policy comes from `pwpolicy`, which is not an osquery table, and is merged
        // in by the collector afterwards — the same split the Windows agent uses for `net accounts`.
        return admins is null ? null : new AgentAccountsReading(admins, null, null, null);
    }

    private static AgentCapacityReading? Capacity(OsqueryResults results)
    {
        long? available = ParseLong(results.Value("system_volume", "blocks_available"));
        long? blocks = ParseLong(results.Value("system_volume", "blocks"));

        return available is null || blocks is null or 0
            ? null
            : new AgentCapacityReading((int)(available.Value * 100 / blocks.Value));
    }

    /// <summary>
    /// Maps an Apple hardware model identifier to a chassis type.
    /// </summary>
    /// <remarks>
    /// Prefix matching on the model family, which is stable across generations. Anything
    /// unrecognised is <c>null</c> rather than a guess, because this value pre-fills an asset record
    /// and a wrong guess would be written into the A.5.9 inventory by whoever accepts it.
    /// </remarks>
    private static string? ChassisName(string? model)
    {
        if (string.IsNullOrWhiteSpace(model))
        {
            return null;
        }

        string value = model.Trim();

        if (value.StartsWith("MacBook", StringComparison.OrdinalIgnoreCase))
        {
            return "Laptop";
        }

        return value.StartsWith("iMac", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("Macmini", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("MacPro", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("MacStudio", StringComparison.OrdinalIgnoreCase)
                ? "Desktop"
                : null;
    }
}
