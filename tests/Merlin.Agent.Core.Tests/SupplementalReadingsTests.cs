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

    /// <summary>
    /// A TPM nobody could look for is <c>null</c>, and only a machine we could actually examine
    /// reports a definite absence.
    /// </summary>
    /// <remarks>
    /// <b>This is the reading most able to make a confident wrong statement.</b> The flag was once
    /// derived as <c>ReadFile(...) is not null</c>, which reported a definite "no security
    /// processor" for a sysfs node the agent was merely refused. Replacing that with a
    /// <c>Directory.Exists</c> on the device node moved the boundary without closing it:
    /// <c>Directory.Exists</c> RETURNS FALSE for a path it cannot stat rather than throwing, so a
    /// machine with no <c>/sys</c> mounted — a container, a chroot, a lockdown environment — still
    /// came back as a definite <c>false</c>, and the "not observed" answer was returned by no path
    /// at all. The enumeration point is the third input that separates them.
    /// </remarks>
    [Theory]

    // A version we could read proves presence on its own, whatever the directory says.
    [InlineData("2", true, true, true, "2")]
    [InlineData("2", false, false, true, "2")]
    [InlineData("  2\n", true, true, true, "2")]

    // A node we can see whose version we cannot read: present, and honestly undescribed.
    [InlineData(null, true, true, true, null)]
    [InlineData("", true, true, true, null)]
    [InlineData("   ", true, true, true, null)]

    // No node, but sysfs was there to be read. The ordinary answer on a VM or an older board, and
    // a TRUE reading that would be lost by calling it unknown.
    [InlineData(null, false, true, false, null)]

    // Nothing to look in. Not observed — never a protection reported as absent.
    [InlineData(null, false, false, null, null)]
    [InlineData("", false, false, null, null)]
    public void ATpmIsOnlyAbsentOnAMachineWeCouldExamine(
        string? versionMajor,
        bool deviceNodeVisible,
        bool sysfsVisible,
        bool? expectedPresent,
        string? expectedVersion)
    {
        (bool? present, string? version) =
            ReadingParsers.TpmFromSysfs(versionMajor, deviceNodeVisible, sysfsVisible);

        Assert.Equal(expectedPresent, present);
        Assert.Equal(expectedVersion, version);
    }

    /// <summary>
    /// The flag and the version are two halves of ONE observation and can never disagree.
    /// </summary>
    /// <remarks>
    /// They were once derived from two independent reads, which is what let a machine report a TPM
    /// that is present with no version — or a version for a machine reported as having none.
    /// </remarks>
    [Theory]
    [InlineData("2", true, true)]
    [InlineData(null, true, true)]
    [InlineData(null, false, true)]
    [InlineData(null, false, false)]
    public void ATpmVersionIsNeverReportedForAMachineSaidToHaveNoTpm(
        string? versionMajor,
        bool deviceNodeVisible,
        bool sysfsVisible)
    {
        (bool? present, string? version) =
            ReadingParsers.TpmFromSysfs(versionMajor, deviceNodeVisible, sysfsVisible);

        if (version is not null)
        {
            Assert.True(present);
        }

        // And the converse: a definite absence carries nothing to describe.
        if (present is false)
        {
            Assert.Null(version);
        }
    }
}
