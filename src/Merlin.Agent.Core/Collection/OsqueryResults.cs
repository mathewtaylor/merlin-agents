namespace Merlin.Agent.Core.Collection;

/// <summary>
/// One collection run's osquery result sets — the rows each named query returned, as string columns.
/// </summary>
/// <remarks>
/// Deliberately untyped. osquery returns every column as a JSON string, and the value of keeping the
/// raw shape here is that each platform's normaliser becomes a pure function of it, testable without
/// osquery, without that platform and without a network.
/// </remarks>
public sealed class OsqueryResults
{
    private readonly Dictionary<string, IReadOnlyList<Dictionary<string, string>>> _sets =
        new(StringComparer.Ordinal);

    /// <summary>Records the rows a named query returned.</summary>
    /// <param name="queryName">The manifest query name.</param>
    /// <param name="rows">Its rows.</param>
    public void Add(string queryName, IReadOnlyList<Dictionary<string, string>> rows) =>
        _sets[queryName] = rows;

    /// <summary>
    /// The rows a named query returned, or an EMPTY list when it did not run or failed.
    /// </summary>
    /// <remarks>
    /// Empty rather than throwing: a query that could not run must degrade to a null reading, not
    /// take down the whole collection. A machine where one table is unavailable still has fifteen
    /// other readings worth sending.
    /// </remarks>
    /// <param name="queryName">The manifest query name.</param>
    /// <returns>The rows.</returns>
    public IReadOnlyList<Dictionary<string, string>> Rows(string queryName) =>
        _sets.TryGetValue(queryName, out IReadOnlyList<Dictionary<string, string>>? rows) ? rows : [];

    /// <summary>The first row of a named query, or <c>null</c>.</summary>
    /// <param name="queryName">The manifest query name.</param>
    /// <returns>The first row, or null.</returns>
    public Dictionary<string, string>? First(string queryName)
    {
        IReadOnlyList<Dictionary<string, string>> rows = Rows(queryName);
        return rows.Count == 0 ? null : rows[0];
    }

    /// <summary>Reads one column from the first row, or <c>null</c>.</summary>
    /// <param name="queryName">The manifest query name.</param>
    /// <param name="column">The column.</param>
    /// <returns>The value, or null when absent or blank.</returns>
    public string? Value(string queryName, string column)
    {
        Dictionary<string, string>? row = First(queryName);

        if (row is null || !row.TryGetValue(column, out string? value))
        {
            return null;
        }

        return string.IsNullOrWhiteSpace(value) ? null : value.Trim();
    }
}
