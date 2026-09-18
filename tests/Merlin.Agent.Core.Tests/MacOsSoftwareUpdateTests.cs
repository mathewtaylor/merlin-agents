using Merlin.Agent.Core.Collection;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// Tests for the macOS patch-currency reading.
/// </summary>
/// <remarks>
/// <b>The dangerous failure is not a crash, it is a date that parses to the wrong instant.</b> A
/// machine that last updated six months ago is a finding; one whose date silently landed a year out
/// either manufactures a finding or hides one, and nothing about the register would look wrong. The
/// offset form <c>defaults</c> prints has no colon in it, which is exactly the shape a naive
/// round-trip mis-reads.
/// </remarks>
public sealed class MacOsSoftwareUpdateTests
{
    /// <summary>What <c>defaults</c> prints for the key, verbatim, including its trailing newline.</summary>
    private const string RealOutput = "2026-09-17 16:59:22 +0000\n";

    /// <summary>The date is read, and read as the instant it names rather than as local time.</summary>
    [Fact]
    public void TheLastSuccessfulDateIsReadAsTheInstantItNames()
    {
        SupplementalReadings readings = MacOsSoftwareUpdate.Parse(RealOutput);

        Assert.Equal(
            new DateTimeOffset(2026, 9, 17, 16, 59, 22, TimeSpan.Zero),
            readings.LastUpdateInstalledAt);
    }

    /// <summary>
    /// A non-zero offset is honoured rather than dropped.
    /// </summary>
    /// <remarks>
    /// The key is written in UTC on every machine seen so far, but the format carries an offset and
    /// a reading that ignored one would be eight hours wrong on a machine that wrote a local time —
    /// which is under a day, so it would never look absurd enough to notice.
    /// </remarks>
    [Fact]
    public void AnOffsetIsHonoured()
    {
        SupplementalReadings readings = MacOsSoftwareUpdate.Parse("2026-09-18 00:59:22 +0800");

        Assert.Equal(
            new DateTimeOffset(2026, 9, 17, 16, 59, 22, TimeSpan.Zero),
            readings.LastUpdateInstalledAt?.ToUniversalTime());
    }

    /// <summary>
    /// Nothing readable is NOT OBSERVED, never a machine that has never updated.
    /// </summary>
    /// <remarks>
    /// <c>CommandRunner</c> returns null for a missing key, an unreadable file, a timeout and a
    /// missing binary alike, so this is the common path on any machine the reading does not suit.
    /// A machine whose date could not be read has not been observed; reporting an epoch or a
    /// <c>default(DateTimeOffset)</c> would say it last updated in 0001 and fail every patch check
    /// in the fleet.
    /// </remarks>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("(null)")]
    [InlineData("The domain/default pair does not exist")]
    public void UnreadableOutputIsNotObserved(string? output)
    {
        SupplementalReadings readings = MacOsSoftwareUpdate.Parse(output);

        Assert.Null(readings.LastUpdateInstalledAt);
    }

    /// <summary>
    /// It reports the date and NOTHING else — no password policy, no pending count.
    /// </summary>
    /// <remarks>
    /// The readings record is merged by coalescing, so a stray non-null here would not be ignored:
    /// it would ADD an observation this reading never took. The pending-update count is the live
    /// temptation — the same plist carries <c>LastUpdatesAvailable</c> — and it counts updates of
    /// every kind, from a scan of unknown age, into a field Merlin reads as pending SECURITY
    /// updates.
    /// </remarks>
    [Fact]
    public void ItReportsTheDateAndNothingElse()
    {
        SupplementalReadings readings = MacOsSoftwareUpdate.Parse(RealOutput);

        Assert.NotNull(readings.LastUpdateInstalledAt);
        Assert.Null(readings.PasswordMinimumLength);
        Assert.Null(readings.PasswordComplexityEnabled);
        Assert.Null(readings.FirewallEnabled);
        Assert.Null(readings.SecureBootEnabled);
        Assert.Null(readings.TpmPresent);
    }
}
