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
/// <b>A per-command timeout does not bound a collection.</b> Sixteen Windows queries at thirty
/// seconds each, plus the osquery version probe, plus up to three firewall and policy commands at
/// ten seconds each, is minutes — every individual step bounded, and the total unbounded in any way
/// that matters. All of it runs while the agent holds the machine-wide lock, and the updater waits
/// two minutes for that lock before giving up, so every minute a broken osquery costs is a minute
/// in which nothing can put a broken agent back.
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
    /// <para>
    /// A healthy collection takes two or three seconds, so nothing legitimate is anywhere near
    /// this. The true worst case is this plus about ten seconds: a step may finish exactly at the
    /// deadline and then spend up to two drain graces collecting what its pipes carried.
    /// </para>
    /// <para>
    /// <b>It bounds the COLLECTION. It does not bound the lock hold, and claiming otherwise would
    /// be the same mistake this class was written to correct.</b> The machine lock is held across
    /// the whole turn — the collection, the report, and the update — and the update legitimately
    /// includes a package download bounded at ten minutes. So a run can exceed the updater's
    /// two-minute <c>LockWait</c>, and that is by design rather than an oversight: an updater that
    /// cannot take the lock reports contention and tries again, which is a documented non-error,
    /// whereas a download killed at two minutes would make large packages permanently
    /// uninstallable on slow links. What this bound removes is the case with no such justification
    /// — a sick osquery or a hung firewall command turning a two-second collection into minutes
    /// for no benefit at all.
    /// </para>
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
