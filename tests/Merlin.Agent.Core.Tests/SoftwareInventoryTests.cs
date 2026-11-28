using System.Text.Json;
using Merlin.Agent.Core.Collection;
using Merlin.Agent.Core.Contracts;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// The software inventory each platform reads, and the reduction they share.
/// </summary>
/// <remarks>
/// The rules worth pinning are the privacy ones (only name, version and publisher, and no Debian
/// maintainer) and the one that protects the server's copy: a failed query is <c>null</c>, never an
/// empty list, because Merlin treats an empty list as a reading that replaces what it held.
/// </remarks>
public sealed class SoftwareInventoryTests
{
    private static readonly JsonSerializerOptions _web = new(JsonSerializerDefaults.Web);

    private static Dictionary<string, string> Row(params (string Key, string Value)[] cells)
    {
        Dictionary<string, string> row = new(StringComparer.Ordinal);

        foreach ((string key, string value) in cells)
        {
            row[key] = value;
        }

        return row;
    }

    [Fact]
    public void WindowsSendsNameVersionAndPublisherAndFoldsTheSecondHive()
    {
        OsqueryResults results = new();
        results.Add("software",
        [
            Row(("name", "Example Browser"), ("version", "131.0.1"), ("publisher", "Example Software Ltd")),
            Row(("name", "Example Browser"), ("version", "131.0.1"), ("publisher", "Example Software Ltd")),
            Row(("name", " Example Tool "), ("version", ""), ("publisher", "")),
        ]);

        List<AgentSoftwareItem> software = Assert.IsAssignableFrom<List<AgentSoftwareItem>>(
            WindowsNormaliser.ToPayload(results, DateTimeOffset.UnixEpoch, "test", null).Software);

        Assert.Equal(
            [
                new AgentSoftwareItem("Example Browser", "131.0.1", "Example Software Ltd"),
                new AgentSoftwareItem("Example Tool", null, null),
            ],
            software);
    }

    [Fact]
    public void MacOsDropsTheAppSuffixAndSendsNoPublisher()
    {
        OsqueryResults results = new();
        results.Add("software",
        [
            Row(("name", "Example Browser.app"), ("bundle_short_version", "18.2")),
            Row(("name", "Utility"), ("bundle_short_version", "1.0")),
        ]);

        IReadOnlyList<AgentSoftwareItem>? software =
            MacOsNormaliser.ToPayload(results, DateTimeOffset.UnixEpoch, "test", null).Software;

        Assert.NotNull(software);
        Assert.Equal(
            [new AgentSoftwareItem("Example Browser", "18.2", null), new AgentSoftwareItem("Utility", "1.0", null)],
            software);
    }

    [Fact]
    public void LinuxReadsWhicheverPackageDatabaseHasRowsAndNeverTheDebianMaintainer()
    {
        OsqueryResults debian = new();
        debian.Add("software_deb",
        [
            // A maintainer column would never be selected; it is here to prove that even if the
            // query were widened by mistake, the reader would not forward it.
            Row(("name", "openssl"), ("version", "3.0.13"), ("maintainer", "A Person <person@example.test>")),
        ]);

        OsqueryResults redHat = new();
        redHat.Add("software_rpm", [Row(("name", "openssl"), ("version", "3.0.7"), ("vendor", "Example Distributor"))]);

        Assert.Equal(
            [new AgentSoftwareItem("openssl", "3.0.13", null)],
            LinuxNormaliser.ToPayload(debian, DateTimeOffset.UnixEpoch, "test", null).Software!);
        Assert.Equal(
            [new AgentSoftwareItem("openssl", "3.0.7", "Example Distributor")],
            LinuxNormaliser.ToPayload(redHat, DateTimeOffset.UnixEpoch, "test", null).Software!);
    }

    [Fact]
    public void AQueryThatReturnedNothingIsNotObservedNotAnEmptyList()
    {
        Assert.Null(WindowsNormaliser.ToPayload(new OsqueryResults(), DateTimeOffset.UnixEpoch, "test", null).Software);
        Assert.Null(MacOsNormaliser.ToPayload(new OsqueryResults(), DateTimeOffset.UnixEpoch, "test", null).Software);
        Assert.Null(LinuxNormaliser.ToPayload(new OsqueryResults(), DateTimeOffset.UnixEpoch, "test", null).Software);

        OsqueryResults blankNames = new();
        blankNames.Add("software", [Row(("name", "  "), ("version", "1"), ("publisher", "x"))]);
        Assert.Null(WindowsNormaliser.ToPayload(blankNames, DateTimeOffset.UnixEpoch, "test", null).Software);
    }

    [Fact]
    public void TheListIsBoundedByCount()
    {
        OsqueryResults results = new();
        results.Add("software",
        [
            .. Enumerable.Range(0, SoftwareInventoryReader.MaxItems + 10)
                .Select(index => Row(("name", "Package " + index), ("version", "1"), ("publisher", ""))),
        ]);

        IReadOnlyList<AgentSoftwareItem>? software =
            WindowsNormaliser.ToPayload(results, DateTimeOffset.UnixEpoch, "test", null).Software;

        Assert.Equal(SoftwareInventoryReader.MaxItems, software!.Count);
    }

    [Fact]
    public void TheListIsBoundedBySizeAndEachFieldIsClamped()
    {
        string longName = new('n', 400);
        string longPublisher = new('p', 400);
        OsqueryResults results = new();
        results.Add("software",
        [
            .. Enumerable.Range(0, 2000)
                .Select(index => Row(("name", index + longName), ("version", "1"), ("publisher", longPublisher))),
        ]);

        IReadOnlyList<AgentSoftwareItem>? software =
            WindowsNormaliser.ToPayload(results, DateTimeOffset.UnixEpoch, "test", null).Software;

        Assert.NotNull(software);
        Assert.All(software, item =>
        {
            Assert.Equal(SoftwareInventoryReader.MaxNameLength, item.Name.Length);
            Assert.Equal(SoftwareInventoryReader.MaxPublisherLength, item.Publisher!.Length);
        });
        Assert.True(
            software.Sum(item => item.Name.Length + item.Version!.Length + item.Publisher!.Length)
            <= SoftwareInventoryReader.MaxTotalCharacters);
        Assert.True(software.Count < 2000, "the size budget, not the count, should have stopped it");
    }

    [Fact]
    public void ThePayloadSerialisesTheInventoryUnderSoftwareInCamelCase()
    {
        AgentReportPayload payload = new(
            DateTimeOffset.UnixEpoch, "test", null, AgentPlatform.Windows, "host",
            null, null, null, null, null, null, null, null, null, null, null, null, null, null,
            Software: [new AgentSoftwareItem("Example Browser", "1.0", null)]);

        string json = JsonSerializer.Serialize(payload, _web);

        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement item = document.RootElement.GetProperty("software")[0];
        Assert.Equal("Example Browser", item.GetProperty("name").GetString());
        Assert.Equal("1.0", item.GetProperty("version").GetString());
    }
}
