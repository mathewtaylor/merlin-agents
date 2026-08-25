using Merlin.Agent.Core.Collection;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// Tests for the <c>net accounts</c> reading.
/// </summary>
/// <remarks>
/// <b>These are mostly about the three values that are words rather than numbers.</b> "Unlimited",
/// "Never" and "None" each stand for a real setting somebody chose, and the dangerous failure is not
/// a crash — it is one of them silently becoming <c>null</c>, which Merlin renders as "not observed"
/// and an administrator reads as "the agent could not see my policy" when in fact the policy is
/// there and deliberate.
/// </remarks>
public sealed class WindowsPasswordPolicyTests
{
    /// <summary>A hardened machine: exactly what the Oligo endpoint policy script leaves behind.</summary>
    private const string Hardened = """
        Force user logoff how long after time expires?:       Never
        Minimum password age (days):                          0
        Maximum password age (days):                          Unlimited
        Minimum password length:                              12
        Length of password history maintained:                5
        Lockout threshold:                                    5
        Lockout duration (minutes):                           30
        Lockout observation window (minutes):                 30
        Computer role:                                        WORKSTATION
        The command completed successfully.
        """;

    /// <summary>A stock machine that has never been configured.</summary>
    private const string Stock = """
        Force user logoff how long after time expires?:       Never
        Minimum password age (days):                          0
        Maximum password age (days):                          42
        Minimum password length:                              0
        Length of password history maintained:                None
        Lockout threshold:                                    Never
        Lockout duration (minutes):                           30
        Lockout observation window (minutes):                 30
        Computer role:                                        WORKSTATION
        """;

    [Fact]
    public void EverySettingTheHardeningScriptAppliesIsReadBack()
    {
        SupplementalReadings readings = WindowsPasswordPolicy.Parse(Hardened);

        Assert.Equal(12, readings.PasswordMinimumLength);
        Assert.Equal(5, readings.PasswordHistorySize);
        Assert.Equal(0, readings.PasswordMinimumAgeDays);
        Assert.Equal(5, readings.LockoutThreshold);
        Assert.Equal(30, readings.LockoutDurationMinutes);
        Assert.Equal(30, readings.LockoutObservationWindowMinutes);
    }

    [Fact]
    public void NoExpiryIsReportedAsMinusOneRatherThanAsNotObserved()
    {
        // The whole point of the distinction. An organisation following NIST SP 800-63B sets no
        // scheduled rotation ON PURPOSE, and a null here would render that decision identically to
        // an agent that failed to read the line at all.
        Assert.Equal(-1, WindowsPasswordPolicy.Parse(Hardened).PasswordMaximumAgeDays);
    }

    [Fact]
    public void NoLockoutAndNoHistoryAreObservedZeroesRatherThanSilence()
    {
        SupplementalReadings readings = WindowsPasswordPolicy.Parse(Stock);

        // "Never" and "None" are observations of an absent control, which is a finding. Reading them
        // as null would let an entirely unconfigured machine escape the check by reporting nothing.
        Assert.Equal(0, readings.LockoutThreshold);
        Assert.Equal(0, readings.PasswordHistorySize);
        Assert.Equal(42, readings.PasswordMaximumAgeDays);
    }

    [Fact]
    public void TheLockoutDurationAndItsObservationWindowAreNotConfusedForEachOther()
    {
        // They hold the same number on a stock machine, so a mix-up is invisible there and wrong on
        // exactly the machines somebody has configured deliberately.
        SupplementalReadings readings = WindowsPasswordPolicy.Parse("""
            Lockout duration (minutes):                           45
            Lockout observation window (minutes):                 15
            """);

        Assert.Equal(45, readings.LockoutDurationMinutes);
        Assert.Equal(15, readings.LockoutObservationWindowMinutes);
    }

    [Fact]
    public void AdministratorUnlockOnlyIsReadAsMinusOne()
    {
        SupplementalReadings readings = WindowsPasswordPolicy.Parse(
            "Lockout duration (minutes):                           -1");

        Assert.Equal(-1, readings.LockoutDurationMinutes);
    }

    [Fact]
    public void ALocalisedOrUnreadableOutputReportsNotObserved()
    {
        // Every label match misses on a non-English Windows. The honest answer is that nothing was
        // observed — never a zero, which would read as "no policy is set" and raise a nonconformity
        // against a machine that may be configured perfectly.
        SupplementalReadings readings = WindowsPasswordPolicy.Parse("""
            Mindestkennwortlänge:                                 12
            Sperrschwelle:                                        5
            """);

        Assert.Null(readings.PasswordMinimumLength);
        Assert.Null(readings.PasswordHistorySize);
        Assert.Null(readings.PasswordMaximumAgeDays);
        Assert.Null(readings.LockoutThreshold);
        Assert.Null(readings.LockoutDurationMinutes);
    }

    [Fact]
    public void ComplexityIsNeverInventedFromThisOutput()
    {
        // `net accounts` has no complexity line at all. A false here would fail every Windows
        // machine in the fleet against a value nobody ever measured.
        Assert.Null(WindowsPasswordPolicy.Parse(Hardened).PasswordComplexityEnabled);
    }
}
