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
    /// <summary>
    /// No encryption state could be read, <b>or</b> one was read that cannot be GRADED without a
    /// second reading the collection did not obtain. NOT the same as unencrypted.
    /// </summary>
    /// <remarks>
    /// The second half is the Windows edition: unprotected on Home is a licensing fact and
    /// unprotected on Pro is somebody switching encryption off, so without the edition an
    /// unprotected volume cannot be told apart, and one of the two guesses accuses a machine that
    /// cannot comply. Reporting the raw state and withholding the grade is the honest answer.
    /// </remarks>
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
/// What happened the last time a component on this machine tried to replace the other one. Mirrors
/// Merlin's <c>AgentUpdateOutcome</c> exactly — the value crosses the wire by NAME, so the two
/// lists must stay in step.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<AgentUpdateOutcome>))]
public enum AgentUpdateOutcome
{
    /// <summary>The staged binary verified, executed once and replaced the running one.</summary>
    Succeeded,

    /// <summary>
    /// The last attempt did not succeed. <b>It covers FOUR states that this value cannot tell
    /// apart, and a server must not be built as though it can.</b>
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Nothing was replaced.</b> A download failure, a hash mismatch, a non-allowlisted host, a
    /// staged binary that would not execute. The machine is still on what it had; the next
    /// scheduled run tries again and no operator action is needed.
    /// </para>
    /// <para>
    /// <b>A replacement was abandoned part-way through the move.</b> The current binary was moved
    /// aside, the staged one could not be moved in, and the retained one could not be put back — so
    /// there is no binary at the target path and the working one is stranded beside it. No swap
    /// mark is written for a move that never completed, so automatic recovery does not run; the
    /// local detail names the path it was left at. Told apart from the first only by asking the
    /// machine, which is why this list exists.
    /// </para>
    /// <para>
    /// <b>Something is installed that nothing ever ran.</b> Not a lost binary and not a bad
    /// release — the component is present and has never started, which on the upgrade path from any
    /// release predating the updater means its scheduled task, launch daemon or systemd timer was
    /// never created. This is the only one of the three an operator can act on without publishing
    /// anything, and because the missing schedule arrives with the upgrade it is normally
    /// fleet-wide rather than one machine.
    /// </para>
    /// <para>
    /// <b>A component was replaced and cannot be put back.</b> It has not run since, and either
    /// could not be restored or had no retained binary to restore. That is the worst state this
    /// design admits, and it is the same enum value as the other two.
    /// </para>
    /// <para>
    /// The agent records a sentence naming which of the four it was, but it keeps it locally — it
    /// is what <c>merlin-agent status</c> prints and it does not cross the wire. What narrows them
    /// without asking the machine is corroborating evidence the report already carries: the version
    /// of the component that failed. A <see cref="Failed"/> whose <c>agentVersion</c> has not moved
    /// and whose reports then stop is the last case; when it is the UPDATER that failed the agent
    /// keeps reporting normally, and <c>updaterVersion</c> — null when the updater is absent or
    /// will not run — is the field that shows it. See <c>docs/protocol.md</c> § the report.
    /// </para>
    /// </remarks>
    Failed,

    /// <summary>
    /// A swap was made and then undone: the replaced component did not run inside its window, so
    /// the other component restored the previous binary. This is mutual recovery working, and it
    /// is deliberately distinct from <see cref="Failed"/> — a revert means a bad binary reached the
    /// machine and was survived, which is the case staged rollout exists to catch.
    /// </summary>
    Reverted,
}

/// <summary>
/// What Merlin ADVERTISES to a machine asking whether it should be running something else.
/// </summary>
/// <remarks>
/// <para>
/// <b>A version, an address and a hash. Nothing else, ever.</b> This record is the client half of
/// the reason the Endpoints module's "no remote-command channel" deferral still stands: there is no
/// verb here, no arguments, no path, no script and nothing this agent dispatches on. The moment it
/// could say anything except "the version you should be running is X, here, with this hash", this
/// would be a command channel wearing a different hat.
/// </para>
/// <para>
/// <b>The address is still checked against a COMPILE-TIME allowlist before anything is fetched.</b>
/// A server-side allowlist protects nothing against the threat it names, because whoever can set
/// the address can set the allowlist beside it. See <c>PackageHosts</c>.
/// </para>
/// </remarks>
/// <param name="Version">The version this device should be running.</param>
/// <param name="PackageEndpoint">Where to fetch that version's archive for this platform.</param>
/// <param name="Sha256">The archive's expected SHA-256, lower-case hex.</param>
public sealed record AgentUpdateResponse(string Version, string PackageEndpoint, string Sha256);

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
/// <param name="UpdaterVersion">
/// The companion updater's version, or <c>null</c> when the agent could not read one — because no
/// updater is installed, or because the binary would not execute. Both cases are worth knowing and
/// neither is worth guessing at.
/// </param>
/// <param name="LastUpdateOutcome">
/// The NAME of an <see cref="AgentUpdateOutcome"/> member, or <c>null</c> when nothing has been
/// attempted on this machine. <b>Reported, never inferred</b> — a server watching only the agent
/// version cannot tell "updated and rolled back" from "never attempted", because both leave the
/// version unmoved, and a silent failed update is the worst thing auto-update can produce.
/// </param>
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
    AgentCapacityReading? Capacity,
    string? UpdaterVersion = null,
    string? LastUpdateOutcome = null);

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
