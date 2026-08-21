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

    /// <summary>
    /// Decides a TPM reading from the three things Linux sysfs can be asked about it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The absence of the device node is only an OBSERVED absence when sysfs is itself
    /// visible</b>, and that third input is the whole reason this is a function rather than two
    /// lines at the call site. <c>Directory.Exists</c> RETURNS FALSE — it does not throw — for a
    /// path it cannot stat, so a caller that asks only about <c>tpm0</c> cannot tell "the kernel
    /// bound no TPM" from "there is no <c>/sys</c> here to look in", and reports the first for
    /// both. On a machine with no sysfs mounted — a container, a chroot, a lockdown environment —
    /// that is a positive assertion that the machine has no security processor, made about a node
    /// nobody could have read. It is the defect this file's own opening rule names: never a
    /// default, never a <c>false</c>.
    /// </para>
    /// <para>
    /// <b>Asked as ONE reading, not two.</b> The flag and the version string are two halves of one
    /// observation; deriving them from independent probes lets them disagree and report a TPM that
    /// is present with no version, or a version for a machine reported as having no TPM.
    /// </para>
    /// </remarks>
    /// <param name="versionMajor">
    /// The contents of <c>tpm0/tpm_version_major</c>, or <c>null</c> when it could not be read —
    /// which, per <c>CommandRunner.ReadFile</c>, means absent OR refused and so decides nothing on
    /// its own.
    /// </param>
    /// <param name="deviceNodeVisible">Whether <c>/sys/class/tpm/tpm0</c> could be seen.</param>
    /// <param name="sysfsVisible">
    /// Whether <c>/sys/class</c> — the sysfs class enumeration point — could be seen. When it could
    /// not, nothing whatever was established and the answer is <c>null</c>. <b>NOT
    /// <c>/sys/class/tpm</c>:</b> that directory is itself absent when no TPM driver ever
    /// registered, so passing it would collapse the ordinary no-TPM answer on a virtual machine or
    /// an older board from a true <c>false</c> into "not observed", losing a real reading.
    /// </param>
    /// <returns>Whether a TPM is present, and its major version when that could be read.</returns>
    public static (bool? Present, string? Version) TpmFromSysfs(
        string? versionMajor,
        bool deviceNodeVisible,
        bool sysfsVisible)
    {
        // A version we could read is proof of presence on its own, whatever the directory says.
        if (!string.IsNullOrWhiteSpace(versionMajor))
        {
            return (true, versionMajor.Trim());
        }

        // A node that exists whose version we could not read is a TPM we can see and cannot
        // describe: present, version unknown.
        if (deviceNodeVisible)
        {
            return (true, null);
        }

        // No node, but sysfs is there to be read — the ordinary answer on a virtual machine or an
        // older board, and a true reading that would be lost by calling it unknown. Without sysfs
        // in view, nothing whatever was established.
        return sysfsVisible ? (false, null) : (null, null);
    }
}
