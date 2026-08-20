using System.Globalization;
using Merlin.Agent.Core.Crypto;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// The rule that decides whether a refusal's <c>serverTime</c> becomes this machine's correction.
/// </summary>
/// <remarks>
/// <b>Every failure this rule has had was permanent and silent, which is why it is tested this
/// hard.</b> The correction is persisted and applied to every request the machine signs, so a wrong
/// value is not a bad run — it is a machine that stops reporting and stops checking for updates
/// together, with no route back on the machine itself. It has been wrong three ways already: a
/// residual stored as an absolute, an absolute compared against zero instead of against the
/// correction in force, and an unbounded value adopted from whatever answered the request.
/// </remarks>
public sealed class ClockSkewTests
{
    private static readonly DateTimeOffset _now = new(2026, 8, 20, 3, 0, 0, TimeSpan.Zero);

    private static long At(long secondsFromNow) => _now.ToUnixTimeSeconds() + secondsFromNow;

    /// <summary>A machine with no correction learns the whole of one.</summary>
    [Fact]
    public void AFreshMachineLearnsTheWholeCorrection()
    {
        Assert.True(ClockSkew.TryLearn(At(3600), _now, applied: 0, out long learned));
        Assert.Equal(3600, learned);
    }

    /// <summary>
    /// A correction that is already right is not relearned, so a refusal about something else
    /// costs one request rather than two.
    /// </summary>
    /// <remarks>
    /// The server's time agrees with the stamp we sent, so the clock is not why it was refused.
    /// Retrying here is the doubled load the threshold exists to prevent.
    /// </remarks>
    [Fact]
    public void ACorrectionThatIsAlreadyRightIsNotRelearned()
    {
        Assert.False(ClockSkew.TryLearn(At(3600), _now, applied: 3600, out long learned));
        Assert.Equal(3600, learned);
    }

    /// <summary>
    /// A machine whose clock has been FIXED gives up the correction it no longer needs.
    /// </summary>
    /// <remarks>
    /// <b>The case a threshold measured against zero can never reach.</b> The correct offset is now
    /// zero, which reads as "too small to act on" — so the machine keeps stamping an hour out, is
    /// refused every time, and the value it must forget is the one it is being told to forget.
    /// </remarks>
    [Fact]
    public void AStaleCorrectionIsGivenUpOnceTheClockIsRight()
    {
        Assert.True(ClockSkew.TryLearn(At(0), _now, applied: 3600, out long learned));
        Assert.Equal(0, learned);
    }

    /// <summary>A clock wrong the other way is learned just the same.</summary>
    [Fact]
    public void ACorrectionCanBeNegative()
    {
        Assert.True(ClockSkew.TryLearn(At(-7200), _now, applied: 0, out long learned));
        Assert.Equal(-7200, learned);
    }

    /// <summary>A difference below the threshold is not worth a second request.</summary>
    [Theory]
    [InlineData(0)]
    [InlineData(29)]
    [InlineData(-29)]
    public void ADifferenceBelowTheThresholdIsIgnored(int drift)
    {
        Assert.False(ClockSkew.TryLearn(At(3600 + drift), _now, applied: 3600, out long learned));
        Assert.Equal(3600, learned);
    }

    /// <summary>At the threshold it is worth acting on.</summary>
    [Fact]
    public void ADifferenceAtTheThresholdIsLearned()
    {
        Assert.True(ClockSkew.TryLearn(At(3630), _now, applied: 3600, out long learned));
        Assert.Equal(3630, learned);
    }

    /// <summary>
    /// An absurd <c>serverTime</c> is refused rather than adopted — it is the difference between a
    /// wasted request and a machine that never speaks again.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Both of these were reproduced against the unbounded version.</b> A value past
    /// <c>253402300799</c> made <c>DateTimeOffset.FromUnixTimeSeconds</c> throw straight out of the
    /// client, which filters only transport exceptions. A value just INSIDE the range was worse: it
    /// was learned, persisted, and from the next run onward the caller's own
    /// <c>now.AddSeconds(offset)</c> overflowed and threw BEFORE the request was built — so nothing
    /// could ever relearn it, and the only repair was editing <c>state.json</c> as root.
    /// </para>
    /// <para>
    /// The refusal body is whatever answered the request, and plaintext deployments are supported
    /// (and warned about) — so this is one crafted reply away, not a theoretical shape.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(253402300799L)]
    [InlineData(253402300800L)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    [InlineData(0L)]
    [InlineData(-1L)]
    public void AnImplausibleServerTimeIsRefusedWithoutThrowing(long serverTime)
    {
        Assert.False(ClockSkew.TryLearn(serverTime, _now, applied: 0, out long learned));
        Assert.Equal(0, learned);
    }

    /// <summary>
    /// The machines whose clocks are actually wrong are the ones the bound must admit.
    /// </summary>
    /// <remarks>
    /// <b>These are named cases, not round numbers, because a bound expressed in years is easy to
    /// pick too tight and impossible to notice.</b> The real causes are not drift — they are a
    /// clock that never had the right time: a dead CMOS battery drops a machine to its BIOS
    /// default, a board with no RTC starts at the Unix epoch, a FAT-era default is 1980. From this
    /// test's own "now" those are decades out, and the first draft of the bound refused every one
    /// of them — which would have meant the most common real cause of a wrong clock could never
    /// learn its correction, and the machine would go silent for ever.
    /// </remarks>
    [Theory]
    [InlineData("1970-01-01T00:00:00Z")]   // no RTC — the Unix epoch
    [InlineData("1980-01-01T00:00:00Z")]   // FAT-era BIOS default
    [InlineData("2000-01-01T00:00:00Z")]   // the classic dead-CMOS-battery landing
    [InlineData("2015-01-01T00:00:00Z")]   // a board default a decade back
    public void AClockThatNeverHadTheRightTimeIsStillCorrected(string machineClock)
    {
        DateTimeOffset wrong = DateTimeOffset.Parse(machineClock, CultureInfo.InvariantCulture);

        // The machine's own clock is `wrong`; the server tells it the truth, which is `_now`.
        Assert.True(
            ClockSkew.TryLearn(_now.ToUnixTimeSeconds(), wrong, applied: 0, out long learned));

        Assert.Equal(_now.ToUnixTimeSeconds() - wrong.ToUnixTimeSeconds(), learned);
    }

    /// <summary>
    /// A <c>serverTime</c> near the end of the representable range is an answer, not a clock.
    /// </summary>
    /// <remarks>
    /// This is what the bound is actually for: adopt it and the caller's own <c>AddSeconds</c>
    /// throws on every subsequent run, before any request is built and therefore before anything
    /// can relearn it.
    /// </remarks>
    [Fact]
    public void ACorrectionOfCenturiesIsRefused()
    {
        Assert.False(ClockSkew.TryLearn(At(200L * 365 * 24 * 3600), _now, applied: 0, out _));
        Assert.False(ClockSkew.TryLearn(253402300799L, _now, applied: 0, out _));
    }

    /// <summary>
    /// No input can make the rule throw, including the ones that break <c>Math.Abs</c>.
    /// </summary>
    /// <remarks>
    /// <b><c>Math.Abs(long.MinValue)</c> throws</b> — its negation does not fit in a <c>long</c> —
    /// so a bound check written the obvious way turns into the exception it exists to prevent, on
    /// exactly the input most likely to reach it. Both arguments here come from outside: the server
    /// time from a refusal body, and the applied correction from a file. This caught a real defect
    /// in the first draft of the guard.
    /// </remarks>
    [Theory]
    [InlineData(long.MinValue, 0L)]
    [InlineData(long.MaxValue, 0L)]
    [InlineData(long.MinValue, long.MinValue)]
    [InlineData(long.MaxValue, long.MaxValue)]
    [InlineData(0L, long.MinValue)]
    [InlineData(1786000000L, long.MinValue)]
    [InlineData(1786000000L, long.MaxValue)]
    public void NoInputMakesTheRuleThrow(long serverTime, long applied)
    {
        // The answer is not what is under test — that it RETURNS one is.
        _ = ClockSkew.TryLearn(serverTime, _now, applied, out _);
        _ = ClockSkew.TryLearn(serverTime, DateTimeOffset.MinValue, applied, out _);
        _ = ClockSkew.TryLearn(serverTime, DateTimeOffset.MaxValue, applied, out _);
        _ = ClockSkew.Sanitise(applied);
    }

    /// <summary>
    /// A machine already carrying an impossible correction heals itself.
    /// </summary>
    /// <remarks>
    /// <b>Bounding what is LEARNED prevents the poisoning; this is what recovers from it.</b> The
    /// correction is read from <c>state.json</c> and applied before the request is built, so an
    /// absurd stored value throws there — before anything is sent, and therefore before anything
    /// can relearn it. Validating only new values leaves such a machine exactly as stuck as it was,
    /// with a root-owned file as the only repair. Zero is the right substitute: an unusable
    /// correction is no better than none, and none is a state the machine knows how to leave.
    /// </remarks>
    [Theory]
    [InlineData(251615078085L)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    [InlineData(-251615078085L)]
    public void AnImpossibleStoredCorrectionIsDiscarded(long stored)
    {
        Assert.Equal(0, ClockSkew.Sanitise(stored));
    }

    /// <summary>A correction that could have come from a clock is kept exactly as stored.</summary>
    [Theory]
    [InlineData(0L)]
    [InlineData(3600L)]
    [InlineData(-3600L)]
    [InlineData(315360000L)]
    public void APlausibleStoredCorrectionIsKept(long stored)
    {
        Assert.Equal(stored, ClockSkew.Sanitise(stored));
    }

    /// <summary>
    /// The threshold must stay below the server's skew tolerance, or there is a band in which the
    /// server refuses and the agent declines to learn.
    /// </summary>
    /// <remarks>
    /// <b>A permanent wedge, and nothing else in the codebase states the coupling.</b> Every skew
    /// refusal implies an error larger than the tolerance; the agent only relearns when the implied
    /// change clears the threshold. Order them the wrong way round and the two guards leave a gap
    /// that nothing on the machine can climb out of. Documented in <c>docs/protocol.md</c> § Bounds.
    /// </remarks>
    [Fact]
    public void TheLearnThresholdSitsWellBelowTheServersSkewTolerance()
    {
        const long serverSkewToleranceSeconds = 300;

        Assert.True(ClockSkew.LearnThresholdSeconds < serverSkewToleranceSeconds);
    }
}
