using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Merlin.Agent.Collection;

/// <summary>
/// Loads the collection manifest — the complete, human-readable list of what the agent reads.
/// </summary>
/// <remarks>
/// <b>The manifest ships as data, not code, on purpose.</b> An administrator can open
/// <c>queries/windows.json</c>, read every query, paste any of them into <c>osqueryi</c> and get
/// identical output. That is a far stronger assurance than "read our source and trust it", and it is
/// the main reason collection is delegated to osquery at all. Adding a platform means adding a pack,
/// not changing this loader.
/// </remarks>
[SupportedOSPlatform("windows")]
public static class QueryPack
{
    /// <summary>Loads the Windows manifest from beside the executable.</summary>
    /// <returns>Query name to SQL, in manifest order.</returns>
    /// <exception cref="FileNotFoundException">When the manifest is missing.</exception>
    /// <exception cref="InvalidOperationException">When the manifest cannot be parsed.</exception>
    public static IReadOnlyDictionary<string, string> LoadWindows()
    {
        string path = Path.Combine(AppContext.BaseDirectory, "queries", "windows.json");

        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                "The collection manifest is missing. The agent will not invent queries to run in its "
                + "absence — reinstall so that queries/windows.json sits beside the executable.",
                path);
        }

        QueryPackFile? pack = JsonSerializer.Deserialize(
            File.ReadAllText(path), QueryPackJsonContext.Default.QueryPackFile);

        if (pack?.Queries is null || pack.Queries.Count == 0)
        {
            throw new InvalidOperationException(
                "The collection manifest contains no queries. Reinstall the agent.");
        }

        Dictionary<string, string> queries = new(StringComparer.Ordinal);

        foreach ((string name, QueryPackEntry entry) in pack.Queries)
        {
            if (!string.IsNullOrWhiteSpace(entry.Sql))
            {
                queries[name] = entry.Sql;
            }
        }

        return queries;
    }
}

/// <summary>The manifest file's shape.</summary>
/// <param name="Version">Manifest version.</param>
/// <param name="Queries">The queries, keyed by name.</param>
public sealed record QueryPackFile(int Version, Dictionary<string, QueryPackEntry>? Queries);

/// <summary>One manifest entry.</summary>
/// <param name="Sql">The osquery SQL.</param>
/// <param name="Purpose">Why it is collected — shown by <c>merlin-agent status --manifest</c>.</param>
public sealed record QueryPackEntry(string? Sql, string? Purpose);

/// <summary>Source-generated JSON context for the manifest.</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(QueryPackFile))]
public sealed partial class QueryPackJsonContext : JsonSerializerContext;
