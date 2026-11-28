using System.Text.Json;

namespace Merlin.Agent.Core.Collection;

/// <summary>
/// Decides whether this machine reads its installed software at all.
/// </summary>
/// <remarks>
/// <para>
/// <b>OFF UNTIL A SERVER HAS SAID YES.</b> Merlin answers every accepted report with
/// <c>{"softwareInventoryEnabled": true|false}</c>, read live from the deployment's own switch. The
/// agent keeps the last answer in its state file and, while it is off, removes the inventory queries
/// from the pack before osquery runs — so the list is not even read locally, let alone sent.
/// </para>
/// <para>
/// <b>Anything other than an explicit <c>true</c> is off.</b> An older server answers with no body,
/// a proxy may answer with HTML, a future server may rename the field: none of those is an
/// administrator switching inventory on, so none of them turns it on.
/// </para>
/// <para>
/// <b>A change reaches the machine one report late.</b> The report that carries the answer was
/// collected before it arrived, so the first list is read on the run after the switch went on.
/// </para>
/// </remarks>
public static class SoftwareInventoryGate
{
    /// <summary>The response member that carries the switch.</summary>
    public const string ResponseProperty = "softwareInventoryEnabled";

    /// <summary>The query names, across all three packs, that read installed software.</summary>
    public static IReadOnlySet<string> QueryNames { get; } =
        new HashSet<string>(StringComparer.Ordinal) { "software", "software_deb", "software_rpm" };

    /// <summary>Removes the inventory queries from a pack unless inventory is switched on.</summary>
    /// <param name="pack">The platform's query pack, in order.</param>
    /// <param name="enabled">Whether the server last said inventory is on.</param>
    /// <returns>The pack to run.</returns>
    public static IReadOnlyList<KeyValuePair<string, string>> Filter(
        IReadOnlyList<KeyValuePair<string, string>> pack,
        bool enabled)
    {
        ArgumentNullException.ThrowIfNull(pack);

        return enabled ? pack : [.. pack.Where(query => !QueryNames.Contains(query.Key))];
    }

    /// <summary>Reads the switch from the body of an accepted report.</summary>
    /// <param name="responseBody">The response body, possibly empty.</param>
    /// <returns><c>true</c> only when the body is a JSON object whose member is <c>true</c>.</returns>
    public static bool ReadEnabled(string? responseBody)
    {
        if (string.IsNullOrWhiteSpace(responseBody))
        {
            return false;
        }

        try
        {
            using JsonDocument document = JsonDocument.Parse(responseBody);

            return document.RootElement.ValueKind == JsonValueKind.Object
                && document.RootElement.TryGetProperty(ResponseProperty, out JsonElement value)
                && value.ValueKind == JsonValueKind.True;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}
