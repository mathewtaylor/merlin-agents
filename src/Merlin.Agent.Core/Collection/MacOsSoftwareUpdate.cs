using static Merlin.Agent.Core.Collection.ReadingParsers;

namespace Merlin.Agent.Core.Collection;

/// <summary>
/// Turns macOS's software-update preferences into a patch-currency reading.
/// </summary>
/// <remarks>
/// <para>
/// <b>It answers "when did this machine last take an update", never "is it fully patched".</b>
/// That is the same fallback Windows already relies on — <c>patches</c> gives the date of the last
/// installed update and Merlin's patch check grades its AGE — so macOS now lands on the same
/// question rather than on nothing at all. A machine that has not updated in six months is
/// actionable; a machine about which nothing is known is not.
/// </para>
/// <para>
/// <b><c>LastSuccessfulDate</c>, and deliberately NOT the install history.</b>
/// <c>/Library/Receipts/InstallHistory.plist</c> is machine-scope and readable too, but it records
/// every installer that has ever run — a third-party app update or an XProtect config-data drop
/// would refresh the date on a machine that has never taken an OS update. That is precisely the
/// weakness the Linux reading already documents about package-manager activity, and there is no
/// reason to reproduce it here when a narrower source exists.
/// </para>
/// <para>
/// <b>The PENDING count is deliberately not reported, though the file carries one.</b>
/// <c>LastUpdatesAvailable</c> is the result of the last background scan, so its truth depends
/// entirely on when that scan ran, and it counts updates of every kind rather than security ones —
/// which is the field Merlin would be filling. Reporting it as a pending SECURITY count would state
/// something this reading cannot establish, which is the failure the whole not-observed rule exists
/// to prevent.
/// </para>
/// <para>
/// <b>Pure and static, like <c>WindowsPasswordPolicy</c>, and for the same reason.</b> Running the
/// command lives in the host reader; deciding what its output MEANS lives here, where a fixture can
/// reach it from any machine.
/// </para>
/// </remarks>
public static class MacOsSoftwareUpdate
{
    /// <summary>
    /// Reads the last successful software-update date out of what <c>defaults</c> printed.
    /// </summary>
    /// <remarks>
    /// <b>Anything unrecognised is <c>null</c>.</b> The command already returns nothing when the key
    /// is absent or the file cannot be read, so the only way to reach this with junk is a format
    /// change — and a machine whose date cannot be read has not been observed, which is a different
    /// claim from one that has never updated.
    /// </remarks>
    /// <param name="output">Standard output from <c>defaults read … LastSuccessfulDate</c>.</param>
    /// <returns>The readings, carrying the date where one was found.</returns>
    public static SupplementalReadings Parse(string? output) =>
        new(LastUpdateInstalledAt: ParseDate(output?.Trim()));
}
