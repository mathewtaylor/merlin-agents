using Merlin.Agent.Core.Contracts;

namespace Merlin.Agent.Core.Collection;

/// <summary>
/// The readings that do NOT come from osquery, gathered by the platform collector and folded into
/// the payload by the normaliser.
/// </summary>
/// <remarks>
/// <para>
/// <b>Every one of these exists because osquery has no table for it.</b> Windows reads its local
/// password policy from <c>net accounts</c>; macOS reads its from <c>pwpolicy</c>; Linux reads the
/// host firewall, Secure Boot, TPM presence and package-manager activity straight from
/// <c>/sys</c>, <c>/etc</c> and <c>/var</c>. None of that is available through a query.
/// </para>
/// <para>
/// <b>It is a record folded in by a pure function rather than a mutation at the call site.</b> The
/// merge used to be one <c>payload with { Accounts = … }</c> in the Windows command handler, which
/// meant the one part of collection that is not osquery-shaped was also the one part no test
/// covered. Three platforms make that a bad trade: the merge is where a supplemental <c>null</c>
/// could silently overwrite a good osquery reading, and that is exactly the "not observed became
/// observed-false" failure the whole agent is built to avoid.
/// </para>
/// </remarks>
/// <param name="PasswordMinimumLength">Minimum local password length, where readable.</param>
/// <param name="PasswordComplexityEnabled">Whether complexity is enforced, where readable.</param>
/// <param name="LockoutThreshold">Lockout threshold; <c>0</c> means no lockout.</param>
/// <param name="PasswordHistorySize">Previous passwords that may not be reused; <c>0</c> means none.</param>
/// <param name="PasswordMinimumAgeDays">Days a password must be held before it may be changed.</param>
/// <param name="PasswordMaximumAgeDays">Days before a password expires; <c>-1</c> means never.</param>
/// <param name="LockoutDurationMinutes">
/// Minutes a locked account stays locked; <c>-1</c> means until an administrator unlocks it.
/// </param>
/// <param name="LockoutObservationWindowMinutes">Minutes over which failed attempts accumulate.</param>
/// <param name="FirewallEnabled">Whether the host firewall is in force, where readable.</param>
/// <param name="SecureBootEnabled">Whether verified boot is enforced, where readable.</param>
/// <param name="TpmPresent">Whether a hardware security processor is present.</param>
/// <param name="TpmVersion">Its version, where readable.</param>
/// <param name="LastUpdateInstalledAt">When a package or update was last installed.</param>
public sealed record SupplementalReadings(
    int? PasswordMinimumLength = null,
    bool? PasswordComplexityEnabled = null,
    int? LockoutThreshold = null,
    int? PasswordHistorySize = null,
    int? PasswordMinimumAgeDays = null,
    int? PasswordMaximumAgeDays = null,
    int? LockoutDurationMinutes = null,
    int? LockoutObservationWindowMinutes = null,
    bool? FirewallEnabled = null,
    bool? SecureBootEnabled = null,
    bool? TpmPresent = null,
    string? TpmVersion = null,
    DateTimeOffset? LastUpdateInstalledAt = null)
{
    /// <summary>
    /// Folds these readings into a payload, keeping whichever source actually observed something.
    /// </summary>
    /// <remarks>
    /// <b>A supplemental <c>null</c> NEVER clears an osquery reading, and vice versa.</b> The two
    /// sources overlap on Linux — Secure Boot is readable from <c>/sys/firmware/efi</c> and, on some
    /// distributions, nowhere else — so a naive overwrite would let a collector that failed to open
    /// a file blank a reading osquery had successfully taken. Coalescing in this direction means the
    /// merge can only ever ADD observations.
    /// </remarks>
    /// <param name="payload">The payload built from osquery alone.</param>
    /// <returns>The payload with supplemental readings folded in.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="payload"/> is null.</exception>
    public AgentReportPayload MergeInto(AgentReportPayload payload)
    {
        ArgumentNullException.ThrowIfNull(payload);

        AgentAccountsReading? accounts = MergeAccounts(payload.Accounts);
        AgentHardeningReading? hardening = MergeHardening(payload.Hardening);
        AgentPatchingReading? patching = MergePatching(payload.Patching);

        return payload with
        {
            Accounts = accounts,
            Hardening = hardening,
            Patching = patching,
        };
    }

    private AgentAccountsReading? MergeAccounts(AgentAccountsReading? existing)
    {
        if (existing is null
            && PasswordMinimumLength is null
            && PasswordComplexityEnabled is null
            && LockoutThreshold is null
            && PasswordHistorySize is null
            && PasswordMinimumAgeDays is null
            && PasswordMaximumAgeDays is null
            && LockoutDurationMinutes is null
            && LockoutObservationWindowMinutes is null)
        {
            return null;
        }

        return new AgentAccountsReading(
            existing?.LocalAdministratorNames,
            PasswordMinimumLength ?? existing?.PasswordMinimumLength,
            PasswordComplexityEnabled ?? existing?.PasswordComplexityEnabled,
            LockoutThreshold ?? existing?.LockoutThreshold,
            PasswordHistorySize ?? existing?.PasswordHistorySize,
            PasswordMinimumAgeDays ?? existing?.PasswordMinimumAgeDays,
            PasswordMaximumAgeDays ?? existing?.PasswordMaximumAgeDays,
            LockoutDurationMinutes ?? existing?.LockoutDurationMinutes,
            LockoutObservationWindowMinutes ?? existing?.LockoutObservationWindowMinutes);
    }

    private AgentHardeningReading? MergeHardening(AgentHardeningReading? existing)
    {
        bool? firewall = FirewallEnabled ?? existing?.FirewallAllProfilesEnabled;
        bool? secureBoot = SecureBootEnabled ?? existing?.SecureBootEnabled;
        bool? tpm = TpmPresent ?? existing?.TpmPresent;
        string? tpmVersion = TpmVersion ?? existing?.TpmVersion;
        int? screenLock = existing?.ScreenLockTimeoutSeconds;

        return firewall is null && secureBoot is null && tpm is null && screenLock is null
            ? null
            : new AgentHardeningReading(firewall, screenLock, secureBoot, tpm, tpmVersion);
    }

    private AgentPatchingReading? MergePatching(AgentPatchingReading? existing)
    {
        DateTimeOffset? installed = LastUpdateInstalledAt ?? existing?.LastUpdateInstalledAt;
        int? pending = existing?.PendingSecurityUpdates;

        return installed is null && pending is null
            ? null
            : new AgentPatchingReading(pending, installed);
    }
}
