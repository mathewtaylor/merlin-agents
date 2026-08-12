using Merlin.Agent.Core.Collection;
using Merlin.Agent.Core.Contracts;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// Tests for the Linux osquery-to-wire normalisation.
/// </summary>
/// <remarks>
/// The two rules worth pinning here are the ones a reasonable person would get wrong: an
/// unencrypted <c>/boot</c> must not fail an otherwise fully encrypted machine, and an account
/// holding uid 0 must be counted even when it is in no administrators group.
/// </remarks>
public sealed class LinuxNormaliserTests
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
        LinuxNormaliser.ToPayload(results, DateTimeOffset.UnixEpoch, "test", "5.23.1");

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
        Assert.Equal(AgentPlatform.Linux, Build(new OsqueryResults()).Platform);
    }

    [Fact]
    public void AnUnencryptedBootPartitionDoesNotFailAnEncryptedMachine()
    {
        OsqueryResults results = new();
        results.Add("disk_encryption",
        [
            Row(("name", "/dev/sda1"), ("encrypted", "0"), ("type", "")),
            Row(("name", "/dev/sda3"), ("encrypted", "1"), ("type", "crypto_LUKS")),
        ]);

        IReadOnlyList<AgentVolumeReading>? volumes = Build(results).Encryption;

        // Every LUKS install has an unencrypted /boot — that is how the scheme works. Passing the
        // raw rows to Merlin's weakest-volume-wins reduction would report every correctly encrypted
        // Linux machine as unencrypted, which is a manufactured nonconformity against the exact
        // configuration the control asks for.
        Assert.NotNull(volumes);
        Assert.Single(volumes);
        Assert.Equal(DiskEncryptionMethod.Luks, volumes[0].Method);
    }

    [Fact]
    public void AMachineWithNoEncryptedVolumeIsObservedAsUnencrypted()
    {
        OsqueryResults results = new();
        results.Add("disk_encryption", [Row(("name", "/dev/sda1"), ("encrypted", "0"))]);

        IReadOnlyList<AgentVolumeReading>? volumes = Build(results).Encryption;

        Assert.NotNull(volumes);
        Assert.Equal(DiskEncryptionMethod.None, volumes[0].Method);
    }

    [Fact]
    public void RowsThatSayNothingReadableAreNotAnUnencryptedMachine()
    {
        OsqueryResults results = new();
        results.Add("disk_encryption", [Row(("name", "/dev/sda1"), ("encrypted", ""))]);

        Assert.Null(Build(results).Encryption);
    }

    [Fact]
    public void AnAccountHoldingUidZeroIsCountedEvenWhenItIsInNoAdminGroup()
    {
        OsqueryResults results = new();
        results.Add("local_admins", [Row(("username", "alice"))]);
        results.Add("root_accounts", [Row(("username", "root")), Row(("username", "backdoor"))]);

        IReadOnlyList<string>? admins = Build(results).Accounts?.LocalAdministratorNames;

        // A second uid-0 account is the more serious of the two findings. Reading only the group
        // query would let it go entirely uncounted.
        Assert.NotNull(admins);
        Assert.Equal(["alice", "backdoor", "root"], admins);
    }

    [Fact]
    public void TheAdministratorListIsDeduplicatedAcrossBothSources()
    {
        OsqueryResults results = new();
        results.Add("local_admins", [Row(("username", "root")), Row(("username", "alice"))]);
        results.Add("root_accounts", [Row(("username", "root"))]);

        Assert.Equal(["alice", "root"], Build(results).Accounts?.LocalAdministratorNames);
    }

    [Fact]
    public void TheDistributionIdTravelsSeparatelyFromTheMarketingName()
    {
        OsqueryResults results = new();
        results.Add("os_version",
            [Row(("name", "Ubuntu"), ("version", "24.04.1 LTS"), ("platform", "ubuntu"))]);

        AgentOsReading? os = Build(results).Os;

        // Merlin's end-of-life table keys on the stable id; the pretty name is for display and a
        // release can restyle it.
        Assert.Equal("ubuntu", os?.Distribution);
        Assert.Equal("Ubuntu", os?.Caption);
    }

    [Fact]
    public void AntiMalwareIsNotObservedRatherThanAbsent()
    {
        OsqueryResults results = new();
        results.Add("system_info", [Row(("hostname", "buildbox"))]);

        // Linux has no platform antimalware posture to read. Reporting "disabled" would fail every
        // Linux machine in a fleet for a control nobody measured.
        Assert.Null(Build(results).AntiMalware);
    }

    [Fact]
    public void FreeSpaceIsAPercentageOfTheRootFilesystem()
    {
        OsqueryResults results = new();
        results.Add("system_volume",
            [Row(("blocks", "1000"), ("blocks_available", "250"), ("blocks_size", "4096"))]);

        Assert.Equal(25, Build(results).Capacity?.SystemDiskFreePercent);
    }

    [Fact]
    public void AZeroBlockCountDoesNotDivideByZero()
    {
        OsqueryResults results = new();
        results.Add("system_volume", [Row(("blocks", "0"), ("blocks_available", "0"))]);

        Assert.Null(Build(results).Capacity);
    }
}
