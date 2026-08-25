using System.Globalization;

namespace Merlin.Agent.Core.Collection;

/// <summary>
/// Turns the text <c>net accounts</c> prints into the local password and lockout policy.
/// </summary>
/// <remarks>
/// <para>
/// <b>osquery has no table for this, and the LOCAL policy is the one that matters here.</b> A
/// workgroup machine gets none of a directory's password rules, and a workgroup machine is exactly
/// what an organisation without an MDM tends to be running — so leaving this uncollected would gut
/// A.5.17 for the fleet the agent exists to reach.
/// </para>
/// <para>
/// <b>Seven values, ONE command — five of them were always in this output and were thrown away.</b>
/// Reporting the minimum length alone let an administrator confirm one line of a password policy and
/// guess at the rest, which is the weakest possible answer to "is this machine configured the way we
/// said it is". Reading history, both ages and both lockout timings costs no new command, no new
/// privilege and no new dependency.
/// </para>
/// <para>
/// <b>It is a pure function in Core rather than a private method beside the command call, for the
/// reason <see cref="SupplementalReadings.MergeInto"/> is.</b> The part of collection that is not
/// osquery-shaped was also the part no test could reach, and the sentinel handling below is
/// precisely where a "not observed" would quietly become an observed number. Running the command
/// stays in the platform project; deciding what its output means lives here, where canned text can
/// drive it.
/// </para>
/// <para>
/// <b>The labels are matched in English, which is a real limit and not a new one.</b> A machine
/// running a localised Windows prints localised labels, every match misses, and the whole section
/// reports <c>null</c> — not observed, which is the honest degradation rather than a wrong reading.
/// Closing it properly means <c>NetUserModalsGet</c>, which returns the same seven values as a
/// struct with no text to parse; that is a larger change than this one.
/// </para>
/// </remarks>
public static class WindowsPasswordPolicy
{
    /// <summary>
    /// Parses <c>net accounts</c> output.
    /// </summary>
    /// <remarks>
    /// Every value is independently nullable: a line this does not recognise leaves its field
    /// unobserved rather than defaulting it, so a future Windows build that renames one label costs
    /// one reading instead of the whole policy.
    /// </remarks>
    /// <param name="output">Exactly what <c>net accounts</c> wrote to standard output.</param>
    /// <returns>The readings, all null when nothing was recognised.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="output"/> is null.</exception>
    public static SupplementalReadings Parse(string output)
    {
        ArgumentNullException.ThrowIfNull(output);

        int? minimumLength = null;
        int? lockoutThreshold = null;
        int? historySize = null;
        int? minimumAgeDays = null;
        int? maximumAgeDays = null;
        int? lockoutDuration = null;
        int? observationWindow = null;

        foreach (string line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            int separator = line.LastIndexOf(':');

            if (separator < 0)
            {
                continue;
            }

            string label = line[..separator].Trim();
            string value = line[(separator + 1)..].Trim();

            if (label.Contains("Minimum password length", StringComparison.OrdinalIgnoreCase))
            {
                minimumLength = ParseCount(value);
            }
            else if (label.Contains("Length of password history", StringComparison.OrdinalIgnoreCase))
            {
                // "None" is an OBSERVATION that reuse is unrestricted, not a failure to read.
                historySize = Sentinel(value, "None", 0) ?? ParseCount(value);
            }
            else if (label.Contains("Minimum password age", StringComparison.OrdinalIgnoreCase))
            {
                minimumAgeDays = ParseCount(value);
            }
            else if (label.Contains("Maximum password age", StringComparison.OrdinalIgnoreCase))
            {
                // "Unlimited" means passwords never expire. That is a POSITION an organisation can
                // hold deliberately — NIST SP 800-63B argues for it — so it is reported as the -1
                // secedit itself writes rather than collapsed to "could not read". Merlin renders
                // it as "never expires"; it must never reach a reader as the number -1.
                maximumAgeDays = Sentinel(value, "Unlimited", -1) ?? ParseCount(value);
            }
            else if (label.Contains("Lockout threshold", StringComparison.OrdinalIgnoreCase))
            {
                // "Never" means no lockout is enforced, which is an OBSERVATION of zero rather than
                // an absence of data — distinct from a line that could not be parsed at all.
                lockoutThreshold = Sentinel(value, "Never", 0) ?? ParseCount(value);
            }
            else if (label.Contains("Lockout observation window", StringComparison.OrdinalIgnoreCase))
            {
                observationWindow = ParseCount(value);
            }
            else if (label.Contains("Lockout duration", StringComparison.OrdinalIgnoreCase))
            {
                // -1 is "until an administrator unlocks it" — the STRICTER setting, and the one a
                // policy demanding administrator intervention will have chosen. It reaches here
                // either as the literal -1 or, on some builds, as a word.
                lockoutDuration = Sentinel(value, "Never", -1) ?? ParseCount(value);
            }
        }

        return new SupplementalReadings(
            PasswordMinimumLength: minimumLength,
            LockoutThreshold: lockoutThreshold,
            PasswordHistorySize: historySize,
            PasswordMinimumAgeDays: minimumAgeDays,
            PasswordMaximumAgeDays: maximumAgeDays,
            LockoutDurationMinutes: lockoutDuration,
            LockoutObservationWindowMinutes: observationWindow);
    }

    /// <summary>
    /// Maps one of <c>net accounts</c>'s word-shaped values to the number it stands for.
    /// </summary>
    /// <remarks>
    /// Returns <c>null</c> when the value is not that word, so the caller falls through to a plain
    /// integer parse — and <c>null</c> again if that fails too, which is the not-observed answer.
    /// </remarks>
    private static int? Sentinel(string value, string word, int meaning) =>
        value.StartsWith(word, StringComparison.OrdinalIgnoreCase) ? meaning : null;

    private static int? ParseCount(string value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : null;
}
