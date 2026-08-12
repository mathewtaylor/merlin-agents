using Merlin.Agent.Core.Collection;
using Merlin.Agent.Core.Contracts;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// Tests for folding the non-osquery readings into a payload.
/// </summary>
/// <remarks>
/// <b>The merge is where a failed file read could silently blank a good osquery reading.</b> The
/// two sources overlap on Linux, so the rule that matters is that the fold can only ever ADD
/// observations — a supplemental <c>null</c> must never clear something that was successfully
/// collected.
/// </remarks>
public sealed class SupplementalReadingsTests
{
    private static AgentReportPayload Payload(
        AgentAccountsReading? accounts = null,
        AgentHardeningReading? hardening = null,
        AgentPatchingReading? patching = null) =>
        new(
            DateTimeOffset.UnixEpoch,
            "test",
            null,
            AgentPlatform.Linux,
            "host",
            null, null, null, null, null, null, null,
            Os: null,
            Encryption: null,
            AntiMalware: null,
            Hardening: hardening,
            Patching: patching,
            Accounts: accounts,
            Capacity: null);

    [Fact]
    public void AnEmptySupplementLeavesThePayloadAlone()
    {
        AgentReportPayload original = Payload(
            hardening: new AgentHardeningReading(true, 600, true, true, "2.0"));

        AgentReportPayload merged = new SupplementalReadings().MergeInto(original);

        Assert.Equal(original.Hardening, merged.Hardening);
    }

    [Fact]
    public void ASupplementalNullNeverClearsAnObservedReading()
    {
        AgentReportPayload original = Payload(
            hardening: new AgentHardeningReading(
                FirewallAllProfilesEnabled: true,
                ScreenLockTimeoutSeconds: null,
                SecureBootEnabled: true,
                TpmPresent: null,
                TpmVersion: null));

        // The firewall command would not run on this machine, but osquery answered. A naive
        // overwrite here would turn a working reading into "not observed".
        AgentReportPayload merged = new SupplementalReadings(TpmPresent: true, TpmVersion: "2")
            .MergeInto(original);

        Assert.True(merged.Hardening?.FirewallAllProfilesEnabled);
        Assert.True(merged.Hardening?.SecureBootEnabled);
        Assert.True(merged.Hardening?.TpmPresent);
        Assert.Equal("2", merged.Hardening?.TpmVersion);
    }

    [Fact]
    public void ThePasswordPolicyIsAddedWithoutDisturbingTheAdministratorList()
    {
        AgentReportPayload original = Payload(
            accounts: new AgentAccountsReading(["root", "alice"], null, null, null));

        AgentReportPayload merged =
            new SupplementalReadings(PasswordMinimumLength: 12, LockoutThreshold: 5)
                .MergeInto(original);

        Assert.Equal(["root", "alice"], merged.Accounts?.LocalAdministratorNames);
        Assert.Equal(12, merged.Accounts?.PasswordMinimumLength);
        Assert.Equal(5, merged.Accounts?.LockoutThreshold);

        // Never invented: Windows `net accounts` cannot report complexity at all, and a false here
        // would fail every Windows machine in the fleet.
        Assert.Null(merged.Accounts?.PasswordComplexityEnabled);
    }

    [Fact]
    public void ASectionStaysNullWhenNeitherSourceObservedAnything()
    {
        AgentReportPayload merged = new SupplementalReadings().MergeInto(Payload());

        Assert.Null(merged.Accounts);
        Assert.Null(merged.Hardening);
        Assert.Null(merged.Patching);
    }

    [Fact]
    public void SupplementalReadingsCanCreateASectionThatOsqueryLeftEmpty()
    {
        // The Linux case: osquery reads none of the hardening signals, so the whole section is
        // built from the filesystem reads.
        AgentReportPayload merged = new SupplementalReadings(
            FirewallEnabled: false,
            SecureBootEnabled: true,
            TpmPresent: true,
            TpmVersion: "2").MergeInto(Payload());

        Assert.False(merged.Hardening?.FirewallAllProfilesEnabled);
        Assert.True(merged.Hardening?.SecureBootEnabled);
    }

    [Fact]
    public void APackageDatabaseTimestampBecomesTheLastUpdateInstalled()
    {
        DateTimeOffset installed = new(2026, 7, 1, 0, 0, 0, TimeSpan.Zero);

        AgentReportPayload merged = new SupplementalReadings(LastUpdateInstalledAt: installed)
            .MergeInto(Payload());

        Assert.Equal(installed, merged.Patching?.LastUpdateInstalledAt);

        // A pending-update count needs a network round trip the agent will not make, so it stays
        // unobserved and Merlin's fallback rule reasons from the install date instead.
        Assert.Null(merged.Patching?.PendingSecurityUpdates);
    }
}
