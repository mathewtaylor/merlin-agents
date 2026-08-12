using System.Text.Json.Serialization;

namespace Merlin.Agent.Core.Contracts;

/// <summary>
/// Which operating system produced a report. Mirrors Merlin's <c>DevicePlatform</c> exactly — the
/// values cross the wire by NAME, so the two lists must stay in step.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every criterion that differs by platform is resolved from this and nothing else.</b> Merlin
/// used to infer "Windows" implicitly because Windows was all there was; now that it is not, an
/// unstated platform must not be guessed at from an OS caption or the presence of a machine GUID.
/// A guess here silently mis-grades a whole machine.
/// </para>
/// <para>
/// <b><see cref="Unknown"/> is what a pre-0.2 agent produces</b>, because it predates this field
/// entirely. Merlin reads it as not-observed rather than as Windows: the agents that shipped before
/// this were indeed Windows-only, but encoding that as a fallback would make an ageing assumption
/// load-bearing, and the honest answer costs only an upgrade.
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<AgentPlatform>))]
public enum AgentPlatform
{
    /// <summary>Not reported. A pre-0.2 agent, or one that could not identify its own host.</summary>
    Unknown,

    /// <summary>Microsoft Windows.</summary>
    Windows,

    /// <summary>Apple macOS.</summary>
    MacOs,

    /// <summary>Linux.</summary>
    Linux,
}

/// <summary>
/// How a device volume is encrypted. Mirrors Merlin's <c>DiskEncryptionMethod</c> exactly — the
/// values cross the wire by NAME, so the two lists must stay in step.
/// </summary>
/// <remarks>
/// <para>
/// <b>Windows Home is why this is not a boolean.</b> Home has no BitLocker; it has Device
/// Encryption, and only on hardware meeting the Modern Standby bar. Reporting "not encrypted" for a
/// machine whose edition cannot encrypt would raise a nonconformity against something nobody can
/// fix, and would look identical to a machine where somebody switched encryption off.
/// </para>
/// <para>
/// <b>The mechanism is NAMED rather than reduced to "encrypted".</b> FileVault and LUKS could both
/// have been folded into a single <c>Encrypted</c> member, and the reason not to is the same reason
/// BitLocker and Device Encryption are distinct: an auditor asking "how is that laptop encrypted?"
/// is asking a question the register should be able to answer, and the answer differs in what it is
/// worth. It also keeps the enum honest as platforms are added — a new mechanism gets a new member
/// rather than being quietly absorbed into a word that no longer means one thing.
/// </para>
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<DiskEncryptionMethod>))]
public enum DiskEncryptionMethod
{
    /// <summary>No encryption state could be read. NOT the same as unencrypted.</summary>
    NotObserved,

    /// <summary>Read, and no encryption is in force.</summary>
    None,

    /// <summary>Full BitLocker — Pro, Enterprise, Education, Server.</summary>
    BitLocker,

    /// <summary>Windows Device Encryption — the Home-edition capability.</summary>
    DeviceEncryption,

    /// <summary>The installed edition cannot encrypt this volume at all.</summary>
    NotSupportedOnEdition,

    /// <summary>Apple FileVault 2.</summary>
    FileVault,

    /// <summary>Linux dm-crypt / LUKS.</summary>
    Luks,
}

/// <summary>The enrolment request body, posted once at install.</summary>
/// <param name="PublicKey">Base64 SPKI DER of this device's ECDSA P-256 public key.</param>
/// <param name="KeyAttestation"><c>Tpm</c> or <c>Software</c>.</param>
/// <param name="AgentVersion">This agent's version.</param>
/// <param name="Platform">Which operating system this agent is running on.</param>
/// <param name="Hostname">Machine hostname.</param>
/// <param name="MachineGuid">The machine's stable hardware identifier.</param>
/// <param name="SerialNumber">BIOS serial, which may be an OEM placeholder.</param>
/// <param name="Manufacturer">Hardware manufacturer.</param>
/// <param name="Model">Hardware model.</param>
/// <param name="ChassisType">Chassis type — Laptop, Desktop, Server.</param>
/// <param name="EntraDeviceId">Entra device id where joined, else null.</param>
/// <param name="EntraTenantId">Entra tenant id where joined, else null.</param>
public sealed record AgentEnrolRequest(
    string PublicKey,
    string KeyAttestation,
    string AgentVersion,
    AgentPlatform Platform,
    string Hostname,
    string? MachineGuid,
    string? SerialNumber,
    string? Manufacturer,
    string? Model,
    string? ChassisType,
    string? EntraDeviceId,
    string? EntraTenantId);

/// <summary>The enrolment response.</summary>
/// <param name="DeviceId">Merlin's identifier for this device.</param>
/// <param name="DeviceCode">The register code, e.g. <c>DEV-001</c>.</param>
/// <param name="Status">Lifecycle state, normally <c>PendingApproval</c>.</param>
/// <param name="ServerTime">The server's clock, for offset correction.</param>
public sealed record AgentEnrolResponse(
    Guid DeviceId,
    string DeviceCode,
    string Status,
    DateTimeOffset ServerTime);

/// <summary>A key-rotation request, signed with the OUTGOING key.</summary>
/// <param name="NewPublicKey">Base64 SPKI DER of the incoming public key.</param>
/// <param name="KeyAttestation">Where the incoming key is held.</param>
public sealed record AgentRotateRequest(string NewPublicKey, string KeyAttestation);

/// <summary>The refusal body Merlin returns for every rejected request.</summary>
/// <param name="Message">The single generic message.</param>
/// <param name="ServerTime">The server's clock, as Unix epoch seconds.</param>
public sealed record AgentRefusal(string Message, long ServerTime);

/// <summary>
/// The posture payload, posted on every collection.
/// </summary>
/// <remarks>
/// <b>Every reading is nullable and <c>null</c> means NOT OBSERVED.</b> The agent omits a value it
/// could not read rather than substituting a default — a <c>false</c> invented here would be
/// indistinguishable, by the time it reached a control check, from a genuine observation that a
/// protection is disabled.
/// </remarks>
/// <param name="CollectedAt">When the readings were taken.</param>
/// <param name="AgentVersion">This agent's version.</param>
/// <param name="OsqueryVersion">The osquery build that produced the readings.</param>
/// <param name="Platform">Which operating system this agent is running on.</param>
/// <param name="Hostname">Machine hostname.</param>
/// <param name="MachineGuid">The machine's stable hardware identifier.</param>
/// <param name="SerialNumber">BIOS serial.</param>
/// <param name="Manufacturer">Hardware manufacturer.</param>
/// <param name="Model">Hardware model.</param>
/// <param name="ChassisType">Chassis type.</param>
/// <param name="EntraDeviceId">Entra device id where joined.</param>
/// <param name="EntraTenantId">Entra tenant id where joined.</param>
/// <param name="Os">Operating-system readings.</param>
/// <param name="Encryption">Per-volume encryption readings.</param>
/// <param name="AntiMalware">Antimalware readings.</param>
/// <param name="Hardening">Firewall, screen lock, Secure Boot and TPM readings.</param>
/// <param name="Patching">Update readings.</param>
/// <param name="Accounts">Local account and password-policy readings.</param>
/// <param name="Capacity">Disk capacity readings.</param>
public sealed record AgentReportPayload(
    DateTimeOffset CollectedAt,
    string AgentVersion,
    string? OsqueryVersion,
    AgentPlatform Platform,
    string Hostname,
    string? MachineGuid,
    string? SerialNumber,
    string? Manufacturer,
    string? Model,
    string? ChassisType,
    string? EntraDeviceId,
    string? EntraTenantId,
    AgentOsReading? Os,
    IReadOnlyList<AgentVolumeReading>? Encryption,
    AgentAntiMalwareReading? AntiMalware,
    AgentHardeningReading? Hardening,
    AgentPatchingReading? Patching,
    AgentAccountsReading? Accounts,
    AgentCapacityReading? Capacity);

/// <summary>
/// Operating-system readings.
/// </summary>
/// <remarks>
/// <b>One shape, three meanings, and the end-of-support table is what reads them.</b> Windows
/// reports <c>Caption</c> "Microsoft Windows 11 Pro", <c>Build</c> "26100" and <c>Edition</c>
/// "Professional"; macOS reports <c>Caption</c> "macOS", <c>Version</c> "15.3.1" and no edition;
/// Linux reports <c>Caption</c> "Ubuntu", <c>Version</c> "24.04" and its distribution id in
/// <see cref="Distribution"/>. Each platform's lifecycle is judged from a different one of these,
/// which is why they travel separately rather than being flattened into a display string.
/// </remarks>
/// <param name="Caption">Product name.</param>
/// <param name="Version">Version string — what macOS and Linux end-of-life are judged against.</param>
/// <param name="Build">Build number — what Windows end-of-life is judged against.</param>
/// <param name="Edition">Edition — Home, Pro, Server. Windows only; null elsewhere.</param>
/// <param name="Distribution">
/// The distribution id (<c>ubuntu</c>, <c>debian</c>, <c>rhel</c>). Linux only; null elsewhere.
/// Kept apart from <see cref="Caption"/> because the support table keys on the stable id, not on a
/// pretty name a release can restyle.
/// </param>
public sealed record AgentOsReading(
    string? Caption,
    string? Version,
    string? Build,
    string? Edition,
    string? Distribution);

/// <summary>One fixed volume's encryption reading.</summary>
/// <param name="Volume">Drive letter or mount point.</param>
/// <param name="Method">How the volume is encrypted.</param>
/// <param name="Protected">Whether protection is currently on.</param>
/// <param name="PercentEncrypted">Conversion progress.</param>
public sealed record AgentVolumeReading(
    string Volume,
    DiskEncryptionMethod Method,
    bool? Protected,
    int? PercentEncrypted);

/// <summary>Antimalware readings, from the platform security centre.</summary>
/// <param name="Product">Registered product name.</param>
/// <param name="Enabled">Whether real-time protection is on.</param>
/// <param name="UpToDate">Whether signatures are current.</param>
/// <param name="LastScanAt">When a scan last completed.</param>
public sealed record AgentAntiMalwareReading(
    string? Product,
    bool? Enabled,
    bool? UpToDate,
    DateTimeOffset? LastScanAt);

/// <summary>
/// Hardening readings.
/// </summary>
/// <remarks>
/// <b>The field names are Windows-shaped and the meanings are per-platform</b> — deliberately, so
/// that one criterion grades the whole fleet rather than three that can drift apart.
/// <see cref="FirewallAllProfilesEnabled"/> is every profile on Windows and the single host
/// firewall on macOS and Linux; <see cref="SecureBootEnabled"/> is UEFI Secure Boot on Windows and
/// Linux and the boot security policy on Apple Silicon; <see cref="TpmPresent"/> is a TPM on
/// Windows and Linux and the Secure Enclave on Apple hardware. All three answer the same question —
/// is this protection in force — and each is <c>null</c> wherever it could not be read.
/// </remarks>
/// <param name="FirewallAllProfilesEnabled">Whether the host firewall is fully on.</param>
/// <param name="ScreenLockTimeoutSeconds">Inactivity lock timeout; 0 means never.</param>
/// <param name="SecureBootEnabled">Whether verified boot is enforced.</param>
/// <param name="TpmPresent">Whether a hardware security processor is present and enabled.</param>
/// <param name="TpmVersion">TPM spec version, or the Apple security-processor generation.</param>
public sealed record AgentHardeningReading(
    bool? FirewallAllProfilesEnabled,
    int? ScreenLockTimeoutSeconds,
    bool? SecureBootEnabled,
    bool? TpmPresent,
    string? TpmVersion);

/// <summary>Patch readings.</summary>
/// <param name="PendingSecurityUpdates">Count of pending security updates.</param>
/// <param name="LastUpdateInstalledAt">When an update was last installed.</param>
public sealed record AgentPatchingReading(
    int? PendingSecurityUpdates,
    DateTimeOffset? LastUpdateInstalledAt);

/// <summary>
/// Local account and password-policy readings.
/// </summary>
/// <remarks>
/// <b><see cref="LocalAdministratorNames"/> is the only person-shaped field the agent sends</b>, and
/// it is here because A.8.2 is materially weaker without it: a count says there are four local
/// administrators but not that one of them is unexpected. These are LOCAL ACCOUNT names — machine
/// configuration — not the identity of whoever is signed in, which this agent never reads.
/// </remarks>
/// <param name="LocalAdministratorNames">Local accounts holding administrator rights.</param>
/// <param name="PasswordMinimumLength">Minimum local password length policy.</param>
/// <param name="PasswordComplexityEnabled">Whether complexity is enforced.</param>
/// <param name="LockoutThreshold">Lockout threshold; 0 means no lockout.</param>
public sealed record AgentAccountsReading(
    IReadOnlyList<string>? LocalAdministratorNames,
    int? PasswordMinimumLength,
    bool? PasswordComplexityEnabled,
    int? LockoutThreshold);

/// <summary>Capacity readings.</summary>
/// <param name="SystemDiskFreePercent">Free space on the system volume, as a percentage.</param>
public sealed record AgentCapacityReading(int? SystemDiskFreePercent);
