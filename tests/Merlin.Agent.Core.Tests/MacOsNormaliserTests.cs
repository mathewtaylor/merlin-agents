using Merlin.Agent.Core.Collection;
using Merlin.Agent.Core.Contracts;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// Tests for the macOS osquery-to-wire normalisation.
/// </summary>
/// <remarks>
/// <b>Weighted towards the not-observed path, and towards the readings macOS genuinely cannot
/// give.</b> Three signals are unobservable at machine scope on an unmanaged Mac — the screen-lock
/// interval, patch currency and antimalware signature age — so the tests that matter most are the
/// ones proving those arrive as <c>null</c> rather than as a confident <c>false</c> that would fail
/// every Mac in a fleet against a control nobody measured.
/// </remarks>
public sealed class MacOsNormaliserTests
{
    private static Dictionary<string, string> Row(params (string Key, string Value)[] cells)
    {
        Dictionary<string, string> row = new(StringComparer.Ordinal);

        foreach ((string key, string value) in cells)
        {
            row[key] = value;
        }

        return row;
    }

    private static AgentReportPayload Build(OsqueryResults results) =>
        MacOsNormaliser.ToPayload(results, DateTimeOffset.UnixEpoch, "test", "5.23.1");

    [Fact]
    public void AnEmptyCollectionReportsEverythingAsNotObserved()
    {
        AgentReportPayload payload = Build(new OsqueryResults());

        Assert.Null(payload.Encryption);
        Assert.Null(payload.AntiMalware);
        Assert.Null(payload.Hardening);
        Assert.Null(payload.Patching);
        Assert.Null(payload.Accounts);
        Assert.Null(payload.Capacity);
    }

    [Fact]
    public void ThePlatformIsStatedOnEveryReport()
    {
        Assert.Equal(AgentPlatform.MacOs, Build(new OsqueryResults()).Platform);
    }

    [Fact]
    public void MacOsReportsNoEditionBecauseItHasNone()
    {
        OsqueryResults results = new();
        results.Add("os_version", [Row(("name", "macOS"), ("version", "15.3.1"), ("build", "24D70"))]);

        AgentOsReading? os = Build(results).Os;

        // Windows' edition rules key on this field. A macOS agent inventing a value — "Sonoma",
        // "Desktop" — would be read by those rules as though it meant something.
        Assert.Null(os?.Edition);
        Assert.Null(os?.Distribution);
        Assert.Equal("15.3.1", os?.Version);
    }

    [Fact]
    public void FileVaultOnAnyDiskMeansTheMachineIsEncrypted()
    {
        OsqueryResults results = new();
        results.Add("filevault",
        [
            Row(("name", "/dev/disk1"), ("filevault_status", "off"), ("encrypted", "0")),
            Row(("name", "/dev/disk3s5"), ("filevault_status", "on"), ("encrypted", "1")),
        ]);

        IReadOnlyList<AgentVolumeReading>? volumes = Build(results).Encryption;

        // One machine-level answer, not one row per disk: FileVault is a whole-machine setting, and
        // per-disk rows would be reduced to the weakest by Merlin and report an encrypted Mac as
        // unencrypted.
        Assert.NotNull(volumes);
        Assert.Single(volumes);
        Assert.Equal(DiskEncryptionMethod.FileVault, volumes[0].Method);
        Assert.True(volumes[0].Protected);
    }

    [Fact]
    public void FileVaultOffIsObservedRatherThanUnobserved()
    {
        OsqueryResults results = new();
        results.Add("filevault", [Row(("name", "/dev/disk1"), ("filevault_status", "off"))]);

        IReadOnlyList<AgentVolumeReading>? volumes = Build(results).Encryption;

        Assert.NotNull(volumes);
        Assert.Equal(DiskEncryptionMethod.None, volumes[0].Method);
    }

    [Fact]
    public void AnUnreadableFileVaultStatusIsNotAnUnencryptedDisk()
    {
        OsqueryResults results = new();
        results.Add("filevault", [Row(("name", "/dev/disk1"), ("filevault_status", "unknown"))]);

        // The row exists but says nothing usable. Reporting `None` here would raise a nonconformity
        // against a machine whose encryption state was never established.
        Assert.Null(Build(results).Encryption);
    }

    [Fact]
    public void TheEncryptedFlagIsUsedOnlyWhenFileVaultStatusIsSilent()
    {
        OsqueryResults results = new();
        results.Add("filevault", [Row(("name", "/dev/disk1"), ("encrypted", "1"))]);

        IReadOnlyList<AgentVolumeReading>? volumes = Build(results).Encryption;

        Assert.NotNull(volumes);
        Assert.Equal(DiskEncryptionMethod.FileVault, volumes[0].Method);
    }

    [Fact]
    public void AScreenThatRequiresAPasswordReportsNoTimeoutRatherThanAFlatteringOne()
    {
        OsqueryResults results = new();
        results.Add("screenlock", [Row(("enabled", "1"), ("grace_period", "0"))]);

        // grace_period is the delay AFTER the screensaver starts, not the idle time before it does.
        // Reporting it as the lock timeout would understate the machine's exposure, and overstating
        // security is the one direction of error this agent must not have.
        Assert.Null(Build(results).Hardening?.ScreenLockTimeoutSeconds);
    }

    [Fact]
    public void AScreenThatNeverLocksIsAnObservedFailure()
    {
        OsqueryResults results = new();
        results.Add("screenlock", [Row(("enabled", "0"))]);

        // Zero is Merlin's spelling of "never locks" — an observation, distinct from null.
        Assert.Equal(0, Build(results).Hardening?.ScreenLockTimeoutSeconds);
    }

    [Fact]
    public void GatekeeperOffIsReportedAsAntiMalwareDisabled()
    {
        OsqueryResults results = new();
        results.Add("gatekeeper", [Row(("assessments_enabled", "0"))]);

        AgentAntiMalwareReading? reading = Build(results).AntiMalware;

        Assert.False(reading?.Enabled);

        // Currency is never claimed: XProtect publishes no locally readable "current" version to
        // compare against, so any freshness verdict would be invented.
        Assert.Null(reading?.UpToDate);
    }

    [Fact]
    public void AppleSiliconReportsASecureEnclaveAndIntelReportsNothing()
    {
        // FROM `secure_enclave`, NOT `system_info`. This is macOS's only hardware-security-processor
        // signal and it used to be read out of the inventory query that runs last, so a machine that
        // exhausted its collection budget dropped this reading before its hostname.
        OsqueryResults apple = new();
        apple.Add("secure_enclave", [Row(("cpu_brand", "Apple M3 Pro"))]);

        OsqueryResults intel = new();
        intel.Add("secure_enclave", [Row(("cpu_brand", "Intel(R) Core(TM) i7-9750H CPU"))]);

        Assert.True(Build(apple).Hardening?.TpmPresent);

        // Never `false`: an Intel Mac may well have a T2, and no table exposes it. Asserting its
        // absence would fail a machine that has one.
        Assert.Null(Build(intel).Hardening?.TpmPresent);

        // And the query it was split OUT of no longer answers for it — otherwise the split would be
        // cosmetic and the reading would still be lost with inventory.
        OsqueryResults inventoryOnly = new();
        inventoryOnly.Add("system_info", [Row(("cpu_brand", "Apple M3 Pro"))]);

        Assert.Null(Build(inventoryOnly).Hardening?.TpmPresent);
    }

    [Fact]
    public void PatchingIsNotObservedOnMacOs()
    {
        OsqueryResults results = new();
        results.Add("os_version", [Row(("name", "macOS"), ("version", "15.3.1"))]);

        // A real gap, not an oversight: macOS exposes no pending-update count or install history
        // without a network round trip the agent will not make.
        Assert.Null(Build(results).Patching);
    }

    [Fact]
    public void AnEmptyAdminGroupIsNotAMachineWithNoAdministrators()
    {
        // No rows means the query could not be answered. Reporting zero administrators would PASS
        // the A.8.2 check on precisely the machines where collection failed.
        Assert.Null(Build(new OsqueryResults()).Accounts);
    }

    [Fact]
    public void TheFirewallIsOnInBothOfItsEnabledStates()
    {
        foreach (string state in new[] { "1", "2" })
        {
            OsqueryResults results = new();
            results.Add("alf", [Row(("global_state", state))]);

            Assert.True(Build(results).Hardening?.FirewallAllProfilesEnabled);
        }

        OsqueryResults off = new();
        off.Add("alf", [Row(("global_state", "0"))]);

        Assert.False(Build(off).Hardening?.FirewallAllProfilesEnabled);
    }

    [Fact]
    public void ChassisIsNamedOnlyForModelsThatAreRecognised()
    {
        Assert.Equal("Laptop", Chassis("MacBookPro18,3"));
        Assert.Equal("Desktop", Chassis("Macmini9,1"));

        // A guess here is written into the A.5.9 asset inventory by whoever accepts the suggestion.
        Assert.Null(Chassis("VirtualMac2,1"));
        Assert.Null(Chassis(""));
    }

    private static string? Chassis(string model)
    {
        OsqueryResults results = new();
        results.Add("system_info", [Row(("hardware_model", model))]);

        return Build(results).ChassisType;
    }
}
