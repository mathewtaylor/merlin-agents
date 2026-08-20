using System.Text.Json;
using System.Text.Json.Serialization;
using Merlin.Agent.Core.Platform;

namespace Merlin.Agent.Collection;

/// <summary>
/// Loads the collection manifest — the complete, human-readable list of what the agent reads.
/// </summary>
/// <remarks>
/// <b>The manifest ships as data, not code, on purpose.</b> An administrator can open
/// <c>queries/&lt;platform&gt;.json</c>, read every query, paste any of them into <c>osqueryi</c>
/// and get identical output. That is a far stronger assurance than "read our source and trust it",
/// and it is the main reason collection is delegated to osquery at all. Adding a platform means
/// adding a pack and a normaliser, not changing this loader.
/// </remarks>
public static class QueryPack
{
    /// <summary>Loads the manifest for the platform this agent is running on.</summary>
    /// <returns>Query name and SQL, in manifest order.</returns>
    /// <exception cref="FileNotFoundException">When the manifest is missing.</exception>
    /// <exception cref="InvalidOperationException">When the manifest cannot be parsed.</exception>
    public static IReadOnlyList<KeyValuePair<string, string>> Load() => Load(AgentPlatformInfo.QueryPackName);

    /// <summary>Loads a named manifest from beside the executable.</summary>
    /// <remarks>
    /// <b>An ordered LIST, because the order is load-bearing and a dictionary does not promise
    /// one.</b> A collection is bounded, so whatever has not run when the bound is reached is
    /// reported as not observed — which makes manifest order the order in which readings are
    /// sacrificed, and the packs are written security-posture first for exactly that reason.
    /// <c>Dictionary&lt;TKey, TValue&gt;</c> documents its enumeration order as undefined; it
    /// happens to be insertion order today, and stops being so after a single <c>Remove</c> or a
    /// switch to <c>FrozenDictionary</c>. Returning a list makes the guarantee something the type
    /// keeps rather than something a comment asserts.
    /// </remarks>
    /// <param name="fileName">The manifest file name, e.g. <c>macos.json</c>.</param>
    /// <returns>Query name and SQL, in manifest order.</returns>
    /// <exception cref="FileNotFoundException">When the manifest is missing.</exception>
    /// <exception cref="InvalidOperationException">When the manifest cannot be parsed.</exception>
    public static IReadOnlyList<KeyValuePair<string, string>> Load(string fileName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);

        string path = Path.Combine(AppContext.BaseDirectory, "queries", fileName);

        if (!File.Exists(path))
        {
            throw new FileNotFoundException(
                $"The collection manifest is missing. The agent will not invent queries to run in "
                + $"its absence — reinstall so that queries/{fileName} sits beside the executable.",
                path);
        }

        QueryPackFile? pack = JsonSerializer.Deserialize(
            File.ReadAllText(path), QueryPackJsonContext.Default.QueryPackFile);

        if (pack?.Queries is null || pack.Queries.Count == 0)
        {
            throw new InvalidOperationException(
                "The collection manifest contains no queries. Reinstall the agent.");
        }

        List<KeyValuePair<string, string>> queries = [];

        foreach ((string name, QueryPackEntry entry) in pack.Queries)
        {
            if (!string.IsNullOrWhiteSpace(entry.Sql))
            {
                queries.Add(new KeyValuePair<string, string>(name, entry.Sql));
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
/// <param name="Purpose">
/// Why it is collected. <b>Read by a person opening the manifest, not by this agent</b> — it is
/// deliberately not loaded or printed, because the thing <c>status --manifest</c> exists to show
/// is the SQL that actually runs, and a rationale printed beside it invites reading the rationale
/// instead of the query.
/// </param>
public sealed record QueryPackEntry(string? Sql, string? Purpose);

/// <summary>Source-generated JSON context for the manifest.</summary>
[JsonSourceGenerationOptions(PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(QueryPackFile))]
public sealed partial class QueryPackJsonContext : JsonSerializerContext;
