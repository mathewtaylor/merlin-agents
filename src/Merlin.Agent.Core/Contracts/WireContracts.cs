using System.Text.Json.Serialization;

namespace Merlin.Agent.Core.Contracts;

/// <summary>
/// How a device volume is encrypted. Mirrors Merlin's <c>DiskEncryptionMethod</c> exactly — the
/// values cross the wire by NAME, so the two lists must stay in step.
/// </summary>
/// <remarks>
/// <b>Windows Home is why this is not a boolean.</b> Home has no BitLocker; it has Device
/// Encryption, and only on hardware meeting the Modern Standby bar. Reporting "not encrypted" for a
/// machine whose edition cannot encrypt would raise a nonconformity against something nobody can
/// fix, and would look identical to a machine where somebody switched encryption off.
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
}

/// <summary>The enrolment request body, posted once at install.</summary>
/// <param name="PublicKey">Base64 SPKI DER of this device's ECDSA P-256 public key.</param>
/// <param name="KeyAttestation"><c>Tpm</c> or <c>Software</c>.</param>
/// <param name="AgentVersion">This agent's version.</param>
/// <param name="Hostname">Machine hostname.</param>
/// <param name="MachineGuid">The Windows machine GUID.</param>
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
/// <param name="Hostname">Machine hostname.</param>
/// <param name="MachineGuid">Windows machine GUID.</param>
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

/// <summary>Operating-system readings.</summary>
/// <param name="Caption">Product name.</param>
/// <param name="Version">Version string.</param>
/// <param name="Build">Build number.</param>
/// <param name="Edition">Edition — Home, Pro, Server.</param>
public sealed record AgentOsReading(string? Caption, string? Version, string? Build, string? Edition);

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

/// <summary>Hardening readings.</summary>
/// <param name="FirewallAllProfilesEnabled">Whether every firewall profile is on.</param>
/// <param name="ScreenLockTimeoutSeconds">Inactivity lock timeout; 0 means never.</param>
/// <param name="SecureBootEnabled">Whether Secure Boot is on.</param>
/// <param name="TpmPresent">Whether a TPM is present and enabled.</param>
/// <param name="TpmVersion">TPM spec version.</param>
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
