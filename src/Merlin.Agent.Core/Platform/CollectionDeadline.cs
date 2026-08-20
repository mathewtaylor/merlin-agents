namespace Merlin.Agent.Core.Platform;

/// <summary>
/// The single wall-clock bound on one collection.
/// </summary>
/// <remarks>
/// <para>
/// <b>It lives beside <see cref="ProcessRunner"/> because it is the same kind of thing</b> — the
/// rules about not letting a child process cost more than it is worth — and because putting it
/// here is what lets a test reach it. Every earlier attempt to bound this collection was written
/// in a project the test project cannot reference, which is the structural reason that layer kept
/// being wrong in a different way each round.
/// </para>
/// <para>
/// <b>A per-command timeout does not bound a collection, and the difference is what starves the
/// updater.</b> The agent holds the machine-wide lock for the whole of a run, and the updater waits
/// two minutes for that lock before giving up and reporting contention — so a collection that
/// outlasts the wait is a collection during which nothing can put a broken agent back. Sixteen
/// Windows queries at thirty seconds each, plus the osquery version probe, plus up to three
/// firewall and policy commands at ten seconds each, is minutes: every individual step bounded,
/// and the total unbounded in any way that matters.
/// </para>
/// <para>
/// <b>One deadline covers the WHOLE collection, not one loop.</b> Bounding only the query pack
/// leaves the two phases either side of it — the version probe and the supplemental host readings —
/// outside the bound, which is how a budget can be added and the property still not hold. Every
/// step clamps its own timeout to what is left, so the last command cannot overshoot by its own
/// full timeout the way a check that only gates ENTRY to a step allows.
/// </para>
/// <para>
/// <b>Monotonic, so a clock correction cannot extend it.</b> A machine coming back from sleep is
/// exactly when a scheduled collection fires and exactly when the wall clock can step.
/// </para>
/// <para>
/// <b>Running out is reported as NOT OBSERVED, never as a negative reading</b> — the same answer a
/// missing table gives, which every normaliser already turns into a null. The query packs are
/// ordered security-posture first for this reason: what a bound sacrifices should be the hostname,
/// not the disk encryption.
/// </para>
/// </remarks>
public sealed class CollectionDeadline
{
    /// <summary>
    /// How long a whole collection may take.
    /// </summary>
    /// <remarks>
    /// Chosen against <c>UpdateTurn.LockWait</c> (two minutes) with room for the drain grace a
    /// killed child is still given: a step may finish exactly at the deadline and then spend up to
    /// ten seconds collecting what its pipes carried, so the true worst case is this plus ten
    /// seconds, which must stay under the wait. A healthy collection takes two or three seconds, so
    /// nothing legitimate is anywhere near it.
    /// </remarks>
    public static readonly TimeSpan Default = TimeSpan.FromSeconds(100);

    private readonly long _expiresAt;

    /// <summary>Initialises a new instance of the <see cref="CollectionDeadline"/> class.</summary>
    /// <remarks>The clock starts here, so it is created once at the top of a collection.</remarks>
    /// <param name="budget">How long the collection may take, or null for <see cref="Default"/>.</param>
    public CollectionDeadline(TimeSpan? budget = null)
    {
        TimeSpan window = budget ?? Default;

        // A zero or negative budget would skip every step and report an entirely unobserved machine
        // with nothing but per-query notes to say why — a silent, complete loss of the collection
        // from a value that can only be a mistake.
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(window, TimeSpan.Zero);

        _expiresAt = Environment.TickCount64 + (long)window.TotalMilliseconds;
    }

    /// <summary>How long is left, never negative.</summary>
    public TimeSpan Remaining =>
        TimeSpan.FromMilliseconds(Math.Max(0, _expiresAt - Environment.TickCount64));

    /// <summary>Whether there is no time left to start anything else.</summary>
    public bool Passed => Remaining <= TimeSpan.Zero;

    /// <summary>
    /// A step's own timeout, or what is left of the collection, whichever is shorter.
    /// </summary>
    /// <param name="timeout">The step's configured timeout.</param>
    /// <returns>The timeout to actually use.</returns>
    public TimeSpan Clamp(TimeSpan timeout) => timeout < Remaining ? timeout : Remaining;
}
