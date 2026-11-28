using System.Text.Json;
using Merlin.Agent.Core.Collection;
using Merlin.Agent.Core.State;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// Installed software is read only after a server has said yes, and anything short of an explicit
/// yes is off.
/// </summary>
public sealed class SoftwareInventoryGateTests
{
    private static readonly string[] _inventoryTables = ["programs", "apps", "deb_packages", "rpm_packages"];

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("{}")]
    [InlineData("""{"softwareInventoryEnabled":false}""")]
    [InlineData("""{"softwareInventoryEnabled":"true"}""")]
    [InlineData("""{"softwareInventoryEnabled":1}""")]
    [InlineData("""{"softwareInventory":true}""")]
    [InlineData("""{"SoftwareInventoryEnabled":true}""")]
    [InlineData("[true]")]
    [InlineData("<html><body>Sign in to the Wi-Fi</body></html>")]
    public void AnythingButAnExplicitYesIsOff(string? body)
    {
        Assert.False(SoftwareInventoryGate.ReadEnabled(body));
    }

    [Fact]
    public void AnExplicitYesIsOn()
    {
        Assert.True(SoftwareInventoryGate.ReadEnabled("""{"softwareInventoryEnabled":true}"""));
        Assert.True(SoftwareInventoryGate.ReadEnabled("""{"future":1,"softwareInventoryEnabled":true}"""));
    }

    [Theory]
    [InlineData("linux.json")]
    [InlineData("macos.json")]
    [InlineData("windows.json")]
    public void WhileOffNoQueryInThePackReadsInstalledSoftware(string pack)
    {
        IReadOnlyList<KeyValuePair<string, string>> queries = Load(pack);

        // The pack really does carry an inventory query, or the assertion below proves nothing.
        Assert.Contains(queries, query => ReadsInventory(query.Value));

        IReadOnlyList<KeyValuePair<string, string>> run = SoftwareInventoryGate.Filter(queries, enabled: false);

        Assert.DoesNotContain(run, query => ReadsInventory(query.Value));
        Assert.Equal(
            queries.Count(query => !ReadsInventory(query.Value)),
            run.Count);
    }

    [Theory]
    [InlineData("linux.json")]
    [InlineData("macos.json")]
    [InlineData("windows.json")]
    public void WhileOnThePackRunsWholeInOrder(string pack)
    {
        IReadOnlyList<KeyValuePair<string, string>> queries = Load(pack);

        Assert.Equal(queries, SoftwareInventoryGate.Filter(queries, enabled: true));
    }

    [Fact]
    public void ANewStateDefaultsToOff()
    {
        AgentStateData state = new(
            "https://merlin.example", Guid.NewGuid(), "MA-001", DateTimeOffset.UnixEpoch, 0, null, null);

        Assert.False(state.SoftwareInventoryEnabled);
    }

    [Fact]
    public void AStateFileWrittenBeforeTheFieldReadsAsOff()
    {
        string directory = Path.Combine(Path.GetTempPath(), "merlin-gate-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);

        try
        {
            File.WriteAllText(
                Path.Combine(directory, "state.json"),
                """
                {
                  "serverUrl": "https://merlin.example",
                  "deviceId": "6f9619ff-8b86-d011-b42d-00c04fc964ff",
                  "deviceCode": "MA-001",
                  "enrolledAt": "2026-11-01T00:00:00+00:00",
                  "clockOffsetSeconds": 0
                }
                """);

            AgentStateData? state = AgentState.ReadFrom(directory);

            Assert.NotNull(state);
            Assert.False(state.SoftwareInventoryEnabled);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void TheSwitchSurvivesARestart()
    {
        string directory = Path.Combine(Path.GetTempPath(), "merlin-gate-" + Guid.NewGuid().ToString("N"));

        try
        {
            AgentState.WriteTo(directory, new AgentStateData(
                "https://merlin.example", Guid.NewGuid(), "MA-001", DateTimeOffset.UnixEpoch, 0, null, null,
                SoftwareInventoryEnabled: true));

            Assert.True(AgentState.ReadFrom(directory)?.SoftwareInventoryEnabled);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static bool ReadsInventory(string sql) =>
        _inventoryTables.Any(table => sql.Contains($"FROM {table}", StringComparison.OrdinalIgnoreCase));

    private static List<KeyValuePair<string, string>> Load(string pack)
    {
        string path = Path.Combine(AppContext.BaseDirectory, "queries", pack);

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(path));

        return
        [
            .. document.RootElement.GetProperty("queries").EnumerateObject()
                .Select(query => new KeyValuePair<string, string>(
                    query.Name, query.Value.GetProperty("sql").GetString() ?? string.Empty)),
        ];
    }
}
