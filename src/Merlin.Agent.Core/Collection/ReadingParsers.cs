using System.Globalization;

namespace Merlin.Agent.Core.Collection;

/// <summary>
/// The value parsers every platform normaliser shares.
/// </summary>
/// <remarks>
/// <para>
/// <b>The rule, everywhere: absent or unparseable becomes <c>null</c>.</b> Never a default, never a
/// zero, never a <c>false</c>. Merlin reads null as "not observed" and will not fail a control on
/// it; it reads <c>false</c> as an observation that a protection is off, which raises one.
/// </para>
/// <para>
/// <b>Shared rather than copied into each normaliser deliberately.</b> Three private copies of
/// <c>ParseBool</c> is three chances for one of them to start treating an unrecognised string as
/// <c>false</c> — which is the single defect class this agent must not have, and the one least
/// likely to be noticed, since it only shows on machines where a reading failed.
/// </para>
/// </remarks>
public static class ReadingParsers
{
    /// <summary>Reads a column from a row, or <c>null</c> when absent or blank.</summary>
    /// <param name="row">The row.</param>
    /// <param name="column">The column.</param>
    /// <returns>The trimmed value, or null.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="row"/> is null.</exception>
    public static string? Column(Dictionary<string, string> row, string column)
    {
        ArgumentNullException.ThrowIfNull(row);

        return row.TryGetValue(column, out string? value) && !string.IsNullOrWhiteSpace(value)
            ? value.Trim()
            : null;
    }

    /// <summary>Parses an integer, or <c>null</c>.</summary>
    /// <param name="value">The raw value.</param>
    /// <returns>The parsed integer, or null.</returns>
    public static int? ParseInt(string? value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : null;

    /// <summary>Parses a long, or <c>null</c>.</summary>
    /// <param name="value">The raw value.</param>
    /// <returns>The parsed long, or null.</returns>
    public static long? ParseLong(string? value) =>
        long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long parsed)
            ? parsed
            : null;

    /// <summary>
    /// Parses a boolean from the several spellings the platforms use, or <c>null</c>.
    /// </summary>
    /// <remarks>
    /// The unrecognised case is <c>null</c>, not <c>false</c>. macOS <c>defaults</c> emits
    /// <c>1</c>/<c>0</c>, <c>socketfilterfw</c> emits prose, osquery emits <c>1</c>/<c>0</c>, and
    /// <c>mokutil</c> emits <c>enabled</c>/<c>disabled</c> — a spelling nobody anticipated must read
    /// as "we did not understand this", never as "the protection is off".
    /// </remarks>
    /// <param name="value">The raw value.</param>
    /// <returns>The parsed boolean, or null.</returns>
    public static bool? ParseBool(string? value) => value?.Trim().ToUpperInvariant() switch
    {
        "1" or "TRUE" or "YES" or "ON" or "ENABLED" => true,
        "0" or "FALSE" or "NO" or "OFF" or "DISABLED" => false,
        _ => null,
    };

    /// <summary>
    /// Parses an osquery date, which is a Unix epoch on some tables and a formatted date on others.
    /// </summary>
    /// <param name="value">The raw value.</param>
    /// <returns>The parsed instant, or null.</returns>
    public static DateTimeOffset? ParseDate(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        if (long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out long epoch)
            && epoch > 0)
        {
            try
            {
                return DateTimeOffset.FromUnixTimeSeconds(epoch);
            }
            catch (ArgumentOutOfRangeException)
            {
                return null;
            }
        }

        return DateTimeOffset.TryParse(
            value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset parsed)
            ? parsed
            : null;
    }

    /// <summary>
    /// Collects distinct, sorted account names from a query's rows, or <c>null</c> when none ran.
    /// </summary>
    /// <remarks>
    /// <b>Empty rows are <c>null</c>, not an empty list.</b> "The privileged-accounts query returned
    /// nothing" almost always means the table could not be read, and reporting it as "this machine
    /// has zero administrators" would pass the A.8.2 check on the machines where collection failed.
    /// </remarks>
    /// <param name="rows">The rows.</param>
    /// <param name="column">The column holding the account name.</param>
    /// <returns>The names, or null.</returns>
    public static IReadOnlyList<string>? AccountNames(
        IReadOnlyList<Dictionary<string, string>> rows,
        string column)
    {
        ArgumentNullException.ThrowIfNull(rows);

        if (rows.Count == 0)
        {
            return null;
        }

        List<string> names =
        [
            .. rows
                .Select(row => Column(row, column))
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Select(name => name!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Order(StringComparer.OrdinalIgnoreCase),
        ];

        return names.Count == 0 ? null : names;
    }
}
