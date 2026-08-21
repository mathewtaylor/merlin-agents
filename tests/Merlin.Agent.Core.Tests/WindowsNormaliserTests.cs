using Merlin.Agent.Core.Collection;
using Merlin.Agent.Core.Contracts;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// Tests for the osquery-to-wire normalisation.
/// </summary>
/// <remarks>
/// <b>These are almost entirely about the NOT-OBSERVED path</b>, because that is the path that never
/// appears on a healthy developer machine and is exactly the one whose failure mode is dangerous: a
/// missing reading that degrades into <c>false</c> raises a nonconformity against a control nobody
/// ever measured.
/// </remarks>
public sealed class WindowsNormaliserTests
{
    private static OsqueryResults Empty() => new();

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
        WindowsNormaliser.ToPayload(results, DateTimeOffset.UnixEpoch, "test", "5.0.0");

    [Fact]
    public void AnEmptyCollectionReportsEverythingAsNotObserved()
    {
        AgentReportPayload payload = Build(Empty());

        // Every section null, not a section full of falses. This is the whole contract with Merlin:
        // a machine where nothing could be read must fail no control.
        Assert.Null(payload.Encryption);
        Assert.Null(payload.AntiMalware);
        Assert.Null(payload.Hardening);
        Assert.Null(payload.Patching);
        Assert.Null(payload.Accounts);
        Assert.Null(payload.Capacity);
    }

    [Fact]
    public void AnUnreadableFirewallIsNotAFirewallThatIsOff()
    {
        AgentReportPayload payload = Build(Empty());

        Assert.Null(payload.Hardening?.FirewallAllProfilesEnabled);
    }

    [Fact]
    public void EveryFirewallProfileMustBeEnabledForTheReadingToBeTrue()
    {
        OsqueryResults results = new();
        results.Add("firewall_profiles",
        [
            Row(("path", @"...\DomainProfile\EnableFirewall"), ("data", "1")),
            Row(("path", @"...\PublicProfile\EnableFirewall"), ("data", "1")),
            Row(("path", @"...\StandardProfile\EnableFirewall"), ("data", "0")),
        ]);

        Assert.False(Build(results).Hardening?.FirewallAllProfilesEnabled);
    }

    [Fact]
    public void AnUnprotectedVolumeOnHomeIsNotSupportedOnEditionRatherThanAFailure()
    {
        // The headline case for the target customer: a retail Home laptop whose hardware does not
        // qualify for Device Encryption. Grading that as "encryption is off" would raise a
        // nonconformity nobody on that machine can clear.
        OsqueryResults results = new();
        results.Add("os_edition", [Row(("data", "Core"))]);
        results.Add("bitlocker", [Row(("drive_letter", "C:"), ("protection_status", "0"))]);

        AgentVolumeReading volume = Assert.Single(Build(results).Encryption!);

        Assert.Equal(DiskEncryptionMethod.NotSupportedOnEdition, volume.Method);
    }

    [Fact]
    public void AnUnprotectedVolumeOnProIsAFailure()
    {
        OsqueryResults results = new();
        results.Add("os_edition", [Row(("data", "Professional"))]);
        results.Add("bitlocker", [Row(("drive_letter", "C:"), ("protection_status", "0"))]);

        AgentVolumeReading volume = Assert.Single(Build(results).Encryption!);

        Assert.Equal(DiskEncryptionMethod.None, volume.Method);
    }

    /// <summary>
    /// An unprotected volume whose EDITION could not be read is not graded either way.
    /// </summary>
    /// <remarks>
    /// <b>This is the case that made a Home laptop look like a Pro machine with encryption switched
    /// off.</b> `os_edition` sat inside the block a spent collection budget discards, and the
    /// edition check answered a blank string with <c>false</c> — so a slow Home machine, which
    /// cannot encrypt at all, was reported as one where somebody had turned it off, which is a
    /// nonconformity raised against the exact fleet this agent exists to serve. Unprotected on Home
    /// is a licensing fact and unprotected on Pro is a finding; without knowing which, asserting
    /// either is a guess, and one of the two guesses is a false accusation. Moving the query into
    /// the posture block fixes the ordering, but the reading must be honest even if it is never
    /// collected at all.
    /// </remarks>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AnUnprotectedVolumeOfUnknownEditionIsNotGraded(string? edition)
    {
        OsqueryResults results = new();

        if (edition is not null)
        {
            results.Add("os_edition", [Row(("data", edition))]);
        }

        results.Add("bitlocker", [Row(("drive_letter", "C:"), ("protection_status", "0"))]);

        AgentVolumeReading volume = Assert.Single(Build(results).Encryption!);

        Assert.Equal(DiskEncryptionMethod.NotObserved, volume.Method);

        // The encryption state ITSELF was read and is still reported — it is only the grading that
        // is withheld.
        Assert.False(volume.Protected);
    }

    /// <summary>
    /// A volume that IS encrypted still reports as encrypted when the edition is unknown.
    /// </summary>
    /// <remarks>
    /// The unknown edition costs the mechanism's NAME, not the reading. Withholding this one would
    /// discard a confirmed protection, which is the opposite error and just as wrong.
    /// </remarks>
    [Fact]
    public void AProtectedVolumeOfUnknownEditionIsStillReportedEncrypted()
    {
        OsqueryResults results = new();
        results.Add("bitlocker", [Row(("drive_letter", "C:"), ("protection_status", "1"))]);

        AgentVolumeReading volume = Assert.Single(Build(results).Encryption!);

        Assert.True(volume.Protected);

        // PINNED, not merely "not one of the two wrong ones". Asserting NotEqual against a couple of
        // members left five wrong answers green — returning Luks here, which cannot exist on
        // Windows, passed the whole suite. Naming BitLocker for an unknown edition is a deliberate
        // and arguable choice (it could as easily be Device Encryption), and pinning it is what
        // makes changing that a reviewed act rather than a silent one.
        Assert.Equal(DiskEncryptionMethod.BitLocker, volume.Method);
    }

    /// <summary>The ordinary machine on the ordinary platform: Pro, protected, BitLocker.</summary>
    /// <remarks>
    /// Nothing pinned this. The same mutation run that exposed the weak assertion above showed a
    /// Pro protected volume could return <c>FileVault</c> and the suite stayed green — the happy
    /// path of the platform most of the fleet runs was the least-tested case in the file.
    /// </remarks>
    [Fact]
    public void AProtectedVolumeOnProIsBitLocker()
    {
        OsqueryResults results = new();
        results.Add("os_edition", [Row(("data", "Professional"))]);
        results.Add("bitlocker", [Row(("drive_letter", "C:"), ("protection_status", "1"))]);

        AgentVolumeReading volume = Assert.Single(Build(results).Encryption!);

        Assert.Equal(DiskEncryptionMethod.BitLocker, volume.Method);
        Assert.True(volume.Protected);
    }

    [Fact]
    public void AProtectedVolumeOnHomeIsDeviceEncryptionNotBitLocker()
    {
        OsqueryResults results = new();
        results.Add("os_edition", [Row(("data", "Home"))]);
        results.Add("bitlocker", [Row(("drive_letter", "C:"), ("protection_status", "1"))]);

        AgentVolumeReading volume = Assert.Single(Build(results).Encryption!);

        Assert.Equal(DiskEncryptionMethod.DeviceEncryption, volume.Method);
        Assert.True(volume.Protected);
    }

    [Fact]
    public void AnUnreadableProtectionStatusIsNotObservedRatherThanUnencrypted()
    {
        OsqueryResults results = new();
        results.Add("os_edition", [Row(("data", "Professional"))]);
        results.Add("bitlocker", [Row(("drive_letter", "C:"), ("protection_status", "not-a-number"))]);

        AgentVolumeReading volume = Assert.Single(Build(results).Encryption!);

        Assert.Equal(DiskEncryptionMethod.NotObserved, volume.Method);
        Assert.Null(volume.Protected);
    }

    [Fact]
    public void OnlyTheDeviceAndTenantIdAreTakenFromTheEntraJoinInfo()
    {
        // The query already restricts to these two names, but the reader is name-based as well, so a
        // widened query cannot start forwarding user fields by accident. This test is the guard on
        // that second line of defence.
        OsqueryResults results = new();
        results.Add("entra_join",
        [
            Row(("name", "DeviceId"), ("data", "1b2c3d4e-0000-0000-0000-000000000001")),
            Row(("name", "TenantId"), ("data", "9f8e7d6c-0000-0000-0000-000000000002")),
            Row(("name", "UserEmail"), ("data", "someone@example.com")),
            Row(("name", "IdpDomain"), ("data", "example.com")),
        ]);

        AgentReportPayload payload = Build(results);

        Assert.Equal("1b2c3d4e-0000-0000-0000-000000000001", payload.EntraDeviceId);
        Assert.Equal("9f8e7d6c-0000-0000-0000-000000000002", payload.EntraTenantId);

        string serialised = System.Text.Json.JsonSerializer.Serialize(payload);

        Assert.DoesNotContain("someone@example.com", serialised, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("IdpDomain", serialised, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AWorkgroupMachineReportsNoEntraIdentifiers()
    {
        AgentReportPayload payload = Build(Empty());

        Assert.Null(payload.EntraDeviceId);
        Assert.Null(payload.EntraTenantId);
    }

    [Fact]
    public void DiskFreePercentageIsComputedFromFreeSpaceAndSize()
    {
        OsqueryResults results = new();
        results.Add("system_drive",
            [Row(("path", "C:"), ("free_space", "25000000000"), ("size", "100000000000"))]);

        Assert.Equal(25, Build(results).Capacity?.SystemDiskFreePercent);
    }

    [Fact]
    public void AZeroSizedDriveDoesNotDivideByZero()
    {
        OsqueryResults results = new();
        results.Add("system_drive", [Row(("path", "C:"), ("free_space", "0"), ("size", "0"))]);

        Assert.Null(Build(results).Capacity);
    }

    [Fact]
    public void LocalAdministratorsAreDeduplicatedAndOrdered()
    {
        OsqueryResults results = new();
        results.Add("local_admins",
        [
            Row(("username", "Zoe")),
            Row(("username", "Administrator")),
            Row(("username", "zoe")),
        ]);

        IReadOnlyList<string> admins = Build(results).Accounts!.LocalAdministratorNames!;

        Assert.Equal(["Administrator", "Zoe"], admins);
    }

    [Theory]
    [InlineData("10", "Laptop")]
    [InlineData("3", "Desktop")]
    [InlineData("23", "Server")]
    [InlineData("2", null)]
    [InlineData("", null)]
    public void ChassisTypeIsNamedOnlyWhenItIsKnown(string code, string? expected)
    {
        OsqueryResults results = new();
        results.Add("chassis", [Row(("chassis_types", code))]);

        // An unknown code becomes null rather than a guess: this value pre-fills an asset record,
        // and a wrong guess ends up written into the A.5.9 inventory by whoever accepts it.
        Assert.Equal(expected, Build(results).ChassisType);
    }
}
