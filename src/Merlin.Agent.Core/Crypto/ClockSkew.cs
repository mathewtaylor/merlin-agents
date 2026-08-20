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
    /// A stored correction, or zero when it is not one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Bounding what is LEARNED only stops the poisoning; this is what heals a machine already
    /// poisoned.</b> The correction is read back from <c>state.json</c> at the top of every run and
    /// applied by <c>now.AddSeconds(...)</c> before the request is built — so a state file carrying
    /// an absurd value throws there, before anything is sent and therefore before anything can
    /// relearn it. A fix that only validates new values leaves such a machine exactly as stuck as
    /// it was, and the file it needs edited is root-owned.
    /// </para>
    /// <para>
    /// Zero is the right answer rather than a refusal to run: an unusable correction is no better
    /// than none, and starting from none is a state the machine knows how to leave — the next skew
    /// refusal teaches it the real one, which is then persisted over the nonsense.
    /// </para>
    /// </remarks>
    /// <param name="offset">The correction as stored.</param>
    /// <returns>The correction, or zero when it could not have come from a clock.</returns>
    public static long Sanitise(long offset) =>

        // COMPARED, NOT Math.Abs'd. Math.Abs(long.MinValue) THROWS — its negation does not fit in
        // a long — so the one input most likely to reach a bound check is the one that would have
        // turned this guard into the exception it exists to prevent. A stored offset is read from a
        // file, so long.MinValue is not a hypothetical.
        offset > MaximumPlausibleSeconds || offset < -MaximumPlausibleSeconds ? 0 : offset;

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
        // SANITISED FIRST, so the subtraction below is between two bounded values. This is public
        // API in a library both binaries link, and the caller's own value comes from a file.
        applied = Sanitise(applied);
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
