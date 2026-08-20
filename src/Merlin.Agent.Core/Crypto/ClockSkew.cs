namespace Merlin.Agent.Core.Crypto;

/// <summary>
/// THE rule for learning this machine's clock correction from a refusal.
/// </summary>
/// <remarks>
/// <para>
/// <b>One implementation, two clients.</b> It was written twice — once in the update client and
/// once in the report client — as the same twenty lines and the same comment, and the two halves
/// were free to drift. They already had: the report client learned a RESIDUAL where the update
/// client learned an ABSOLUTE, which produced a machine that alternated between two wrong offsets
/// for ever. Only one of the two lives in a project the test project can reference, so a duplicated
/// rule is also a rule that is half tested by construction.
/// </para>
/// <para>
/// <b>The offset is ABSOLUTE: it is the whole correction, not what is left of one.</b> The caller
/// signs with <c>now + offset</c> where <c>now</c> is this machine's raw clock, so the value
/// returned here is what to stamp with and what to persist.
/// </para>
/// </remarks>
public static class ClockSkew
{
    /// <summary>
    /// How far a new correction must move the current one before it is worth a retry.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Measured against the correction ALREADY IN FORCE, never against zero.</b> Asking whether
    /// the new offset is small refuses to learn exactly when the answer is "you no longer need
    /// one": a machine carrying an hour of correction whose clock is then fixed is told the
    /// correct offset is zero, discards that as beneath the threshold, and goes on stamping an
    /// hour out — refused for ever, with the value it needs to forget being the one it is being
    /// told to forget.
    /// </para>
    /// <para>
    /// <b>It must stay well below the server's skew tolerance</b> (300 s by default, and
    /// configurable — see <c>docs/protocol.md</c> § Bounds). The two together are what guarantee no
    /// dead band: any refusal that IS about the clock implies an error larger than the tolerance,
    /// which is therefore larger than this, so the guard always fires for a genuine skew refusal.
    /// Raise this above the tolerance and there is a band in which the server refuses and the agent
    /// declines to learn — a permanent wedge.
    /// </para>
    /// </remarks>
    public const long LearnThresholdSeconds = 30;

    /// <summary>
    /// The largest correction that is a wrong clock rather than a wrong answer.
    /// </summary>
    /// <remarks>
    /// Ten years. A machine can be a decade out — a dead CMOS battery lands in 2000, and a fresh
    /// board with no RTC lands at the epoch — but nothing beyond that is a clock, so nothing beyond
    /// that is worth stamping a request with.
    /// </remarks>
    public const long MaximumPlausibleSeconds = 10L * 365 * 24 * 3600;

    /// <summary>
    /// Decides whether a refusal's <c>serverTime</c> is worth adopting as this machine's correction.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The bound is not tidiness — an unbounded value BRICKS the agent, permanently, from one
    /// refusal.</b> The refusal body is whatever answered the request, which on a plaintext
    /// deployment (supported, and warned about at enrolment) is anyone on the path. Two distinct
    /// failures, both reproduced:
    /// </para>
    /// <para>
    /// A value past <c>253402300799</c> makes <c>DateTimeOffset.FromUnixTimeSeconds</c> THROW, and
    /// the clients filter only <c>HttpRequestException</c> and <c>TaskCanceledException</c>, so it
    /// walks out past every catch. Computing in <see cref="long"/> arithmetic removes that throw
    /// site outright rather than catching it.
    /// </para>
    /// <para>
    /// Worse, a value just INSIDE the range is accepted, learned, and persisted — and from the next
    /// run onwards the caller's own <c>now.AddSeconds(offset)</c> overflows and throws BEFORE the
    /// request is built and therefore before anything can relearn it. The machine stops reporting
    /// and stops checking for updates together, and the only repair is editing <c>state.json</c> as
    /// root. That is the silent-machine outcome the whole design exists to prevent, reachable by
    /// one crafted reply.
    /// </para>
    /// </remarks>
    /// <param name="serverTime">The instant the refusal reported, in Unix seconds.</param>
    /// <param name="now">This machine's RAW clock — uncorrected.</param>
    /// <param name="applied">The correction currently being applied.</param>
    /// <param name="learned">The correction to adopt, or <paramref name="applied"/> unchanged.</param>
    /// <returns><c>true</c> when the caller should adopt <paramref name="learned"/> and retry.</returns>
    public static bool TryLearn(long serverTime, DateTimeOffset now, long applied, out long learned)
    {
        learned = applied;

        if (serverTime <= 0)
        {
            return false;
        }

        long here = now.ToUnixTimeSeconds();

        // BOUNDED BEFORE THE SUBTRACTION, so the subtraction itself cannot overflow — a serverTime
        // of long.MaxValue against a pre-epoch clock would otherwise wrap silently and produce a
        // small, plausible-looking offset out of a nonsense one.
        if (serverTime > here + MaximumPlausibleSeconds || serverTime < here - MaximumPlausibleSeconds)
        {
            return false;
        }

        long offset = serverTime - here;

        if (Math.Abs(offset - applied) < LearnThresholdSeconds)
        {
            return false;
        }

        learned = offset;
        return true;
    }
}
