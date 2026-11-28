using Merlin.Agent.Core.Contracts;

namespace Merlin.Agent.Core.Collection;

/// <summary>
/// Turns the platform's inventory rows into the software list the report carries.
/// </summary>
/// <remarks>
/// <para>
/// <b>One reader for all three platforms</b>, because the reduction is the same everywhere: trim,
/// drop a row with no name, fold duplicates, bound the size. Only the column names differ, and each
/// normaliser says which ones it read.
/// </para>
/// <para>
/// <b>No rows is <c>null</c>, never an empty list.</b> Every real machine has installed software,
/// so an empty result means the query failed, timed out or the table does not exist on this build —
/// and Merlin treats an empty list as a READING that replaces what it held. Sending <c>[]</c> for a
/// failed query would wipe a device's inventory on the server every time osquery stumbled.
/// </para>
/// <para>
/// <b>Bounded by count AND by size.</b> Merlin refuses a whole report over its body limit, so an
/// inventory that grew past it would cost the machine its posture readings too — the thing the
/// report exists to carry. A list cut short here loses the tail of an inventory; a report refused
/// there loses everything.
/// </para>
/// </remarks>
public static class SoftwareInventoryReader
{
    /// <summary>The most items one report carries. Matches Merlin's own per-device cap.</summary>
    public const int MaxItems = 5000;

    /// <summary>
    /// The most characters the list may add up to — about half of Merlin's 1 MiB body limit,
    /// leaving the rest of the report, JSON punctuation and escaping well inside it.
    /// </summary>
    public const int MaxTotalCharacters = 450_000;

    /// <summary>Longest name sent. Matches Merlin's column.</summary>
    public const int MaxNameLength = 256;

    /// <summary>Longest version sent. Matches Merlin's column.</summary>
    public const int MaxVersionLength = 128;

    /// <summary>Longest publisher sent. Matches Merlin's column.</summary>
    public const int MaxPublisherLength = 256;

    /// <summary>
    /// Reads one or more inventory queries into a software list.
    /// </summary>
    /// <param name="results">The osquery result sets.</param>
    /// <param name="sources">
    /// Each query to read, with the columns holding the name, the version and (where the platform
    /// has one worth sending) the publisher.
    /// </param>
    /// <param name="trimName">An optional clean-up of the name, such as dropping macOS's <c>.app</c>.</param>
    /// <returns>The list, or <c>null</c> when no query returned a usable row.</returns>
    public static List<AgentSoftwareItem>? Read(
        OsqueryResults results,
        IReadOnlyList<SoftwareSource> sources,
        Func<string, string>? trimName = null)
    {
        ArgumentNullException.ThrowIfNull(results);
        ArgumentNullException.ThrowIfNull(sources);

        List<AgentSoftwareItem> items = [];
        HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        int characters = 0;

        foreach (SoftwareSource source in sources)
        {
            foreach (Dictionary<string, string> row in results.Rows(source.Query))
            {
                string? name = Clean(Column(row, source.NameColumn), MaxNameLength);

                if (name is not null && trimName is not null)
                {
                    name = Clean(trimName(name), MaxNameLength);
                }

                if (name is null)
                {
                    continue;
                }

                string? version = Clean(Column(row, source.VersionColumn), MaxVersionLength);
                string? publisher = source.PublisherColumn is null
                    ? null
                    : Clean(Column(row, source.PublisherColumn), MaxPublisherLength);

                // Windows lists a program once per hive it is registered in, so the same install
                // arrives twice; the server folds duplicates too, but sending them costs budget.
                if (!seen.Add(name + "\u0000" + version + "\u0000" + publisher))
                {
                    continue;
                }

                int size = name.Length + (version?.Length ?? 0) + (publisher?.Length ?? 0);

                if (items.Count >= MaxItems || characters + size > MaxTotalCharacters)
                {
                    return items;
                }

                characters += size;
                items.Add(new AgentSoftwareItem(name, version, publisher));
            }
        }

        return items.Count == 0 ? null : items;
    }

    /// <summary>Drops a trailing <c>.app</c> from a macOS bundle name.</summary>
    /// <param name="name">The bundle's file name, e.g. <c>Example Browser.app</c>.</param>
    /// <returns>The display name, e.g. <c>Example Browser</c>.</returns>
    public static string WithoutAppSuffix(string name)
    {
        ArgumentNullException.ThrowIfNull(name);

        return name.EndsWith(".app", StringComparison.OrdinalIgnoreCase) ? name[..^4] : name;
    }

    private static string? Column(Dictionary<string, string> row, string column) =>
        row.TryGetValue(column, out string? value) ? value : null;

    private static string? Clean(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        string trimmed = value.Trim();
        return trimmed.Length <= maxLength ? trimmed : trimmed[..maxLength];
    }
}

/// <summary>One inventory query and the columns the reader takes from it.</summary>
/// <param name="Query">The query-pack name.</param>
/// <param name="NameColumn">The column holding the name.</param>
/// <param name="VersionColumn">The column holding the version.</param>
/// <param name="PublisherColumn">The column holding the publisher, or <c>null</c> to send none.</param>
public sealed record SoftwareSource(
    string Query,
    string NameColumn,
    string VersionColumn,
    string? PublisherColumn);
