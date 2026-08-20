using Merlin.Agent.Core.Contracts;
using Merlin.Agent.Core.State;
using Merlin.Agent.Core.Update;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// The envelope around an update turn — gate, lock, re-read, stamp, run, persist.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the layer that produced a defect every audit round, and it had no tests because it
/// lived in two <c>Program.cs</c> files the test project cannot reference.</b> Three of the seven
/// Criticals found on this branch were introduced by an earlier round's own fix to it. The ordering
/// it holds is not obvious from reading it — the whole point of several steps is what happens when
/// two processes overlap — so every rule below is asserted against a state store and a lock that a
/// test can interleave, rather than against a comment.
/// </para>
/// <para>
/// Each test here was verified to FAIL with its own behaviour deliberately removed, and the removal
/// then reverted. A guard that still passes with the behaviour deleted reads as coverage and is
/// worse than no guard at all.
/// </para>
/// </remarks>
public sealed class UpdateTurnTests
{
    private static readonly DateTimeOffset _now = new(2026, 8, 20, 3, 0, 0, TimeSpan.Zero);

    /// <summary>
    /// The state is read once the lock is HELD, and the pre-lock snapshot is thrown away.
    /// </summary>
    /// <remarks>
    /// <b>The wait is up to two minutes by design, so every time it does its job the holder we
    /// waited for has written state we hold a pre-image of.</b> Persisting that pre-image silently
    /// erases what it just recorded — the swap mark, the version stamped with it, the outcome owed
    /// to Merlin, the pending note — and <c>state.json</c> is the sole authority for every safety
    /// rule in this design. The lock protects the FILES; only the re-read protects the
    /// read-modify-write cycle. Both schedulers fire missed runs on wake, so a laptop opening its
    /// lid produces this overlap routinely.
    /// </remarks>
    [Fact]
    public async Task TheStateIsReadOnlyOnceTheLockIsHeld()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "agent");

        StateStore store = new(Enrolled());

        // What the holder wrote while this run sat in TryAcquire. Nothing in the turn touches
        // LastRevertedVersion, so it survives to the end iff the re-read happened.
        MachineLockAttempt Acquire()
        {
            store.Value = Enrolled() with { LastRevertedVersion = "9.9.9" };
            return new MachineLockAttempt(new FakeLock(), false);
        }

        UpdateTurn turn = Build(
            kit, AgentComponent.Updater, store, new StubSession(NothingToDo), Acquire);

        UpdateTurnResult result = await turn.RunAsync();

        Assert.Equal(UpdateTurnStatus.Completed, result.Status);

        // Null here is the round-3 Critical: a waiter overwriting the holder's own work.
        Assert.Equal("9.9.9", store.Value!.LastRevertedVersion);
    }

    /// <summary>
    /// A component replaced and not seen to run since is not replaced AGAIN.
    /// </summary>
    /// <remarks>
    /// <b>Stacking an unproven swap on an unproven one breaks recovery twice over.</b> It resets
    /// the mark a revert is timed from, so the window restarts every run and the revert never
    /// fires; and the commit retains only the IMMEDIATELY preceding binary, so the second swap
    /// overwrites the retained copy with the unproven one and the last binary known to work is
    /// gone. Asserted here through the whole envelope, because the envelope is what decides which
    /// state the rule is applied to.
    /// </remarks>
    [Fact]
    public async Task AnUnprovenSwapIsNeverStackedOnAnotherOne()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "quarantined agent");
        File.WriteAllText(kit.Layout.PreviousPathOf(AgentComponent.Agent), "the last agent that ran");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");

        StateStore store = new(Enrolled() with
        {
            // Replaced an hour ago and not seen to run. The installed binary answers no version —
            // it has been quarantined — so the advertised version never matches and the naive path
            // downloads and swaps it all over again, every day, for ever.
            AgentSwappedAt = _now.AddHours(-1),
            LastAgentRunAt = _now.AddHours(-3),
            LastUpdaterRunAt = _now.AddHours(-24),
        });

        UpdateTurn turn = Build(
            kit,
            AgentComponent.Updater,
            store,
            new StubSession(() => Advertising("9.9.9", UpdateTestKit.Digest(archive))),
            probe: UpdateTestKit.ProbeByPath(_ => null),
            archive: archive);

        await turn.RunAsync();

        Assert.Null(store.Value!.LastUpdateOutcome);
        Assert.Equal("quarantined agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));

        // The retained binary is still the one that last actually ran, and the mark still dates
        // from the ORIGINAL swap rather than restarting.
        Assert.Equal(
            "the last agent that ran",
            File.ReadAllText(kit.Layout.PreviousPathOf(AgentComponent.Agent)));
        Assert.Equal(_now.AddHours(-1), store.Value.AgentSwappedAt);
    }

    /// <summary>
    /// An image replaced while it waited for the lock stamps nothing and does nothing.
    /// </summary>
    /// <remarks>
    /// <b>A run by the PRE-SWAP binary is not evidence that the post-swap binary works.</b> The
    /// process executing here was already loaded into memory when the file underneath it changed,
    /// so stamping a run would tell the next turn that the NEW binary has proved itself when it has
    /// never executed at all. The mark would then be cleared, the revert could never fire, and the
    /// no-stacked-swap rule would stop engaging — execute-before-commit defeated by a stamp rather
    /// than by anything going wrong. It exits and lets the scheduler start the binary that is
    /// actually on disk; that run is the only honest witness.
    /// </remarks>
    [Fact]
    public async Task AnImageReplacedDuringTheLockWaitDoesNotStampARun()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "agent");

        StateStore store = new(Enrolled() with { LastUpdaterRunAt = _now.AddHours(-24) });

        MachineLockAttempt Acquire()
        {
            // The agent swapped merlin-updater forty seconds into this run's lock wait.
            store.Value = store.Value! with { UpdaterSwappedAt = _now.AddSeconds(40) };
            return new MachineLockAttempt(new FakeLock(), false);
        }

        StubSession session = new(NothingToDo);

        UpdateTurn turn = Build(kit, AgentComponent.Updater, store, session, Acquire);

        UpdateTurnResult result = await turn.RunAsync();

        Assert.Equal(UpdateTurnStatus.Replaced, result.Status);

        // Nothing stamped, nothing written, nothing asked of Merlin.
        Assert.Empty(store.Writes);
        Assert.Equal(_now.AddHours(-24), store.Value!.LastUpdaterRunAt);
        Assert.Equal(0, session.Checks);
    }

    /// <summary>
    /// A mark far in the future is a wrong clock, not a concurrent swap.
    /// </summary>
    /// <remarks>
    /// <b>The guard needs an upper bound or a backwards clock correction makes it permanent.</b>
    /// Every previously stored instant then looks like the future, so the guard would fire on every
    /// scheduled run and the machine would stop collecting entirely until real time caught up.
    /// Beyond the bound the timestamp is evidence of a wrong clock, and carrying on is the safer
    /// reading: the worst case is one honest run against a binary replaced a while ago, against a
    /// machine that never reports again.
    /// </remarks>
    [Fact]
    public async Task AMarkBeyondTheWindowIsAWrongClockRatherThanASwap()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "agent");

        StateStore store = new(Enrolled() with
        {
            // Ten minutes ahead: outside the five-minute window, so not a swap this run can have
            // raced. A clock stepped backwards produces exactly this shape.
            UpdaterSwappedAt = _now.AddMinutes(10),
            LastUpdaterRunAt = _now.AddHours(-24),
        });

        UpdateTurn turn = Build(kit, AgentComponent.Updater, store, new StubSession(NothingToDo));

        UpdateTurnResult result = await turn.RunAsync();

        Assert.Equal(UpdateTurnStatus.Completed, result.Status);
        Assert.Equal(_now, store.Value!.LastUpdaterRunAt);
    }

    /// <summary>
    /// A revert names the release it undid, run after run after run.
    /// </summary>
    /// <remarks>
    /// <b><c>LastRevertedVersion</c> came out null on every revert that mattered.</b> The recovery
    /// witness guarantees at least one intervening run, and that run re-probes the target and
    /// persists the answer — so a binary that will not execute writes null over the recorded
    /// version, and the identity of the release to block was destroyed before anything read it. The
    /// anti-oscillation guard was then dead code for exactly its own case: reinstall, revert, be
    /// advertised the same version, for ever. Three real turns, with the state carried between them
    /// exactly as three scheduled processes carry it.
    /// </remarks>
    [Fact]
    public async Task ARevertNamesTheVersionItUndid()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "working agent");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");

        bool replaced = false;

        BinaryProbe probe = UpdateTestKit.ProbeByPath(path =>
            !path.StartsWith(kit.Layout.InstallDirectory, StringComparison.Ordinal) ? "9.9.9"
            : replaced ? null
            : "0.2.0");

        StateStore store = new(Enrolled() with { LastUpdaterRunAt = _now.AddHours(-24) });

        DateTimeOffset clock = _now;

        async Task TurnAsync()
        {
            UpdateTurn turn = Build(
                kit,
                AgentComponent.Updater,
                store,
                new StubSession(() => Advertising("9.9.9", UpdateTestKit.Digest(archive))),
                clock: () => clock,
                probe: probe,
                archive: archive);

            await turn.RunAsync();
        }

        // Turn one — the swap.
        await TurnAsync();
        replaced = true;

        Assert.Equal(AgentUpdateOutcome.Succeeded, store.Value!.LastUpdateOutcome);

        // Turn two — no witness yet, so no revert, and the re-probe nulls the recorded version.
        clock = _now.AddHours(24);
        await TurnAsync();

        Assert.Null(store.Value.AgentVersionInstalled);

        // Turn three — the witness is in and the window has passed.
        clock = _now.AddHours(48);
        await TurnAsync();

        Assert.Equal(AgentUpdateOutcome.Reverted, store.Value.LastUpdateOutcome);
        Assert.Equal("working agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));

        // THE ASSERTION THIS EXISTS FOR. Null here is an infinite reinstall loop.
        Assert.Equal("9.9.9", store.Value.LastRevertedVersion);
    }

    /// <summary>
    /// The recovery witness is the PREVIOUS run, never the stamp this turn just wrote.
    /// </summary>
    /// <remarks>
    /// <b>Wall clock passes while a laptop is shut, and the elapsed window alone cannot tell the
    /// difference.</b> A machine closed straight after a swap comes back with the window long gone
    /// and the replaced binary — which is perfectly good — never having run. Something has to say
    /// the machine was actually UP for that window, and this component's own previous run is the
    /// only such record. Capture it after the stamp instead of before and it reads "now" on every
    /// turn: the witness becomes vacuous, and a fleet strands itself one closed laptop at a time,
    /// permanently, because a false revert writes <c>LastRevertedVersion</c> and nothing clears it.
    /// </remarks>
    [Fact]
    public async Task TheWitnessIsCapturedBeforeThisTurnStampsItself()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "new agent");
        File.WriteAllText(kit.Layout.PreviousPathOf(AgentComponent.Agent), "old agent");

        StateStore store = new(Enrolled() with
        {
            AgentVersionInstalled = "9.9.9",

            // Swapped, then the lid closed. NOTHING has run on this machine since — including the
            // updater now asking the question, whose own last run IS the swap.
            AgentSwappedAt = _now.AddHours(-96),
            LastAgentRunAt = _now.AddHours(-97),
            LastUpdaterRunAt = _now.AddHours(-96),
        });

        UpdateTurn turn = Build(
            kit,
            AgentComponent.Updater,
            store,
            new StubSession(NothingToDo),
            probe: UpdateTestKit.ProbeReporting("9.9.9"));

        await turn.RunAsync();

        Assert.Null(store.Value!.LastUpdateOutcome);
        Assert.Null(store.Value.LastRevertedVersion);
        Assert.Equal("new agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));

        // The mark stays, so the question is asked again next run — by which time this updater has
        // a run of its own after the swap to answer it with.
        Assert.Equal(_now.AddHours(-96), store.Value.AgentSwappedAt);
    }

    /// <summary>
    /// The run stamp is on disk before anything that can fail, and a fault cannot take it back.
    /// </summary>
    /// <remarks>
    /// <b>The stamp is the WITNESS a revert requires, and it used to sit behind a download bounded
    /// at ten minutes.</b> A reboot, a kill or a crash mid-run lost it — and a witness that keeps
    /// going missing is a broken component that never gets put back, which is the one failure this
    /// whole design exists to prevent. The fault is reported rather than thrown for the same
    /// reason: nothing an update turn does may leave a machine unable to report.
    /// </remarks>
    [Fact]
    public async Task AFaultInTheUpdateWorkCannotLoseTheRunStamp()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "agent");

        StateStore store = new(Enrolled() with
        {
            LastUpdaterRunAt = _now.AddHours(-24),
            LastRevertedVersion = "1.2.3",
        });

        StubSession session = new(() => throw new InvalidOperationException("the sky fell in"));

        UpdateTurn turn = Build(kit, AgentComponent.Updater, store, session);

        // It returns rather than throwing: whatever goes wrong, the answer is a line the caller
        // writes and a machine that keeps working.
        UpdateTurnResult result = await turn.RunAsync();

        Assert.Equal(UpdateTurnStatus.Completed, result.Status);
        Assert.Equal("the sky fell in", result.Fault);

        // Stamped, and the bookkeeping that was already there is intact.
        Assert.Equal(_now, store.Value!.LastUpdaterRunAt);
        Assert.Equal("1.2.3", store.Value.LastRevertedVersion);
        Assert.NotEmpty(store.Writes);
    }

    /// <summary>
    /// The machine lock is held for the WHOLE turn, not merely around the swap.
    /// </summary>
    /// <remarks>
    /// <b>A swapper never swaps a target that is currently running.</b> Held around the swap alone,
    /// the agent could be mid-collection when the updater replaced its binary — on Windows that
    /// fails with a sharing violation, and on Unix it silently succeeds and hands the running
    /// process an inode nobody can see, which is worse. This drives the DEFAULT acquisition, so it
    /// is the real lock file in the real state directory rather than the seam.
    /// </remarks>
    [Fact]
    public async Task TheMachineLockIsHeldForTheWholeTurn()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "agent");

        StateStore store = new(Enrolled() with { LastUpdaterRunAt = _now.AddHours(-24) });
        bool? contendedDuringTheTurn = null;

        StubSession session = new(() =>
        {
            using MachineLock? second = MachineLock.TryAcquire(
                kit.StateDirectory, TimeSpan.FromMilliseconds(50), out bool denied);

            contendedDuringTheTurn = second is null && !denied;

            return NothingToDo();
        });

        UpdateTurn turn = Real(kit, store, session);

        UpdateTurnResult result = await turn.RunAsync();

        Assert.Equal(UpdateTurnStatus.Completed, result.Status);

        // Asked from inside the turn, which is the only moment the answer means anything.
        Assert.True(contendedDuringTheTurn);
    }

    /// <summary>
    /// The machine lock is released however the turn ends.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>A process that never lets go of this lock silences the machine permanently.</b> Both
    /// binaries take it for the whole of a run, so one that keeps it means the agent never collects
    /// and the updater never checks again — no error, no report, and nothing on the machine able to
    /// put anything back. The pipe deadlock that produced exactly that is pinned by
    /// <c>UpdateOrchestrationTests.TheSharedProcessRunnerSurvivesAFloodedPipe</c>; this is the other
    /// half, on the path most likely to skip a release — an exception out of the update work.
    /// </para>
    /// <para>
    /// <b>Asserted through the seam rather than by re-acquiring the real lock afterwards, and that
    /// is not a shortcut.</b> A leaked <see cref="FileStream"/> is unreachable the moment the turn
    /// returns, so its finaliser releases the handle at whatever point the next collection happens —
    /// which made the re-acquisition PASS against a build with the release deleted. A guard that
    /// still passes with its own behaviour removed reads as coverage and is worse than none.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheMachineLockIsReleasedEvenWhenTheUpdateWorkFaults()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "agent");

        StateStore store = new(Enrolled() with { LastUpdaterRunAt = _now.AddHours(-24) });
        FakeLock held = new();

        UpdateTurn turn = Build(
            kit,
            AgentComponent.Updater,
            store,
            new StubSession(() => throw new InvalidOperationException("wedged")),
            () => new MachineLockAttempt(held, false));

        UpdateTurnResult result = await turn.RunAsync();

        Assert.Equal("wedged", result.Fault);
        Assert.True(held.Disposed);
    }

    /// <summary>
    /// A scheduled run inside the minimum interval does nothing at all.
    /// </summary>
    /// <remarks>
    /// <b>Not a rate limit on the server's account — a guard against the schedulers' own catch-up
    /// behaviour.</b> A systemd timer with <c>Persistent=true</c>, a launchd <c>StartInterval</c>
    /// and a Windows task with <c>StartWhenAvailable</c> all fire missed runs when a machine comes
    /// back. Downloading the same archive several times in a minute is pointless; swapping a binary
    /// several times in a minute is worse.
    /// </remarks>
    [Fact]
    public async Task AScheduledRunInsideTheMinimumIntervalDoesNothing()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "agent");

        StateStore store = new(Enrolled() with { LastUpdaterRunAt = _now.AddMinutes(-20) });

        StubSession session = new(NothingToDo);

        UpdateTurn turn = Build(
            kit, AgentComponent.Updater, store, session, minimumInterval: TimeSpan.FromHours(1));

        UpdateTurnResult result = await turn.RunAsync();

        Assert.Equal(UpdateTurnStatus.TooSoon, result.Status);
        Assert.Empty(store.Writes);
        Assert.Equal(0, session.Checks);
    }

    /// <summary>
    /// An operator asking is not a scheduler catching up.
    /// </summary>
    [Fact]
    public async Task AnOperatorRequestedRunIgnoresTheMinimumInterval()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "agent");

        StateStore store = new(Enrolled() with { LastUpdaterRunAt = _now.AddMinutes(-20) });

        StubSession session = new(NothingToDo);

        UpdateTurn turn = Build(
            kit, AgentComponent.Updater, store, session, minimumInterval: TimeSpan.FromHours(1));

        UpdateTurnResult result = await turn.RunAsync(operatorRequested: true);

        Assert.Equal(UpdateTurnStatus.Completed, result.Status);
        Assert.Equal(1, session.Checks);
    }

    /// <summary>
    /// The interval is judged against the stamp read UNDER the lock, not the one read before it.
    /// </summary>
    /// <remarks>
    /// <b>A run that spent two minutes waiting for the other component would otherwise be measured
    /// against a stale stamp</b> — and a burst of catch-up runs on a machine coming back from sleep
    /// is precisely when a long wait and a fresh stamp happen at once, which is the case the gate
    /// exists for.
    /// </remarks>
    [Fact]
    public async Task TheIntervalIsJudgedAgainstTheStampReadUnderTheLock()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "agent");

        StateStore store = new(Enrolled() with { LastUpdaterRunAt = _now.AddHours(-24) });

        MachineLockAttempt Acquire()
        {
            // The run we waited for stamped itself seconds ago.
            store.Value = store.Value! with { LastUpdaterRunAt = _now.AddMinutes(-1) };
            return new MachineLockAttempt(new FakeLock(), false);
        }

        StubSession session = new(NothingToDo);

        UpdateTurn turn = Build(
            kit,
            AgentComponent.Updater,
            store,
            session,
            Acquire,
            minimumInterval: TimeSpan.FromHours(1));

        UpdateTurnResult result = await turn.RunAsync();

        Assert.Equal(UpdateTurnStatus.TooSoon, result.Status);
        Assert.Equal(0, session.Checks);
    }

    /// <summary>
    /// A caller with no interval has no gate — not a zero-length one.
    /// </summary>
    /// <remarks>
    /// <b>The agent collects, and skipping a collection to spare a download would trade the thing
    /// the machine exists to do for the thing it does on the side.</b> A zero <see cref="TimeSpan"/>
    /// would not be the same answer: under a clock corrected backwards the elapsed gap is negative,
    /// which is less than zero, so a zero gate skips runs on exactly the machine already in trouble.
    /// </remarks>
    [Fact]
    public async Task AnAgentTurnHasNoMinimumIntervalAtAll()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "updater");

        // Stamped in the FUTURE, as a clock stepped backwards leaves it.
        StateStore store = new(Enrolled() with { LastAgentRunAt = _now.AddHours(2) });

        StubSession session = new(NothingToDo);

        UpdateTurn turn = Build(kit, AgentComponent.Agent, store, session);

        UpdateTurnResult result = await turn.RunAsync();

        Assert.Equal(UpdateTurnStatus.Completed, result.Status);
        Assert.Equal(1, session.Checks);
    }

    /// <summary>
    /// A rights failure and contention are different answers and never look the same.
    /// </summary>
    /// <remarks>
    /// <b>Reporting a permissions failure as "the other component is running" is how a machine goes
    /// quiet while looking healthy</b> — an agent started without root or SYSTEM waits out the whole
    /// timeout and then exits ZERO, collecting nothing, on every scheduled fire, for ever.
    /// </remarks>
    [Theory]
    [InlineData(true, UpdateTurnStatus.RightsRefused)]
    [InlineData(false, UpdateTurnStatus.Contended)]
    public async Task ALockThatCouldNotBeTakenSaysWhichItWas(bool accessDenied, UpdateTurnStatus expected)
    {
        using UpdateTestKit kit = new();

        StateStore store = new(Enrolled());
        StubSession session = new(NothingToDo);

        UpdateTurn turn = Build(
            kit,
            AgentComponent.Updater,
            store,
            session,
            () => new MachineLockAttempt(null, accessDenied));

        UpdateTurnResult result = await turn.RunAsync();

        Assert.Equal(expected, result.Status);

        // Nothing was read under a lock, so nothing may be written.
        Assert.Empty(store.Writes);
        Assert.Equal(0, session.Checks);
    }

    /// <summary>
    /// A machine that has not enrolled never takes the lock and never opens a session.
    /// </summary>
    /// <remarks>
    /// The installer runs enrolment before it registers either schedule, so in practice this is a
    /// machine mid-install or one that has been uninstalled. There is no device to ask on behalf of
    /// and no server to ask.
    /// </remarks>
    [Fact]
    public async Task AMachineThatHasNotEnrolledStopsBeforeTheLock()
    {
        using UpdateTestKit kit = new();

        StateStore store = new(null);
        bool acquired = false;

        UpdateTurn turn = Build(
            kit,
            AgentComponent.Updater,
            store,
            new StubSession(NothingToDo),
            () =>
            {
                acquired = true;
                return new MachineLockAttempt(new FakeLock(), false);
            });

        UpdateTurnResult result = await turn.RunAsync();

        Assert.Equal(UpdateTurnStatus.NotEnrolled, result.Status);
        Assert.False(acquired);
        Assert.Empty(store.Writes);
    }

    /// <summary>
    /// The caller's own work runs under the lock, after the stamp and before the update check.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>This is the agent's collection and report, and the order is the whole of the contract.</b>
    /// The stamp goes first so a crash mid-collection still counts as having run; the report's
    /// bookkeeping is persisted before the update turn so a fault there cannot cost it; and the
    /// update turn comes last so a machine that cannot reach Merlin can still put a broken updater
    /// back.
    /// </para>
    /// <para>
    /// <b>The check's instant is a SECOND reading, taken after the work.</b> It is the signed
    /// request timestamp, and spending a collection's worth of the skew tolerance before the
    /// machine's own drift is even counted invites a refusal and a wasted retry.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheCallersWorkIsPersistedBetweenTheStampAndTheCheck()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "updater");

        StateStore store = new(Enrolled());
        List<string> order = [];

        DateTimeOffset clock = _now;

        StubSession session = new(
            () =>
            {
                order.Add("check");
                return NothingToDo();
            },
            state =>
            {
                order.Add("work");
                clock = _now.AddSeconds(3);
                return state with { LastReportJson = "{\"sent\":true}" };
            });

        UpdateTurn turn = Build(
            kit, AgentComponent.Agent, store, session, clock: () => clock);

        await turn.RunAsync();

        Assert.Equal(["work", "check"], order);

        // Two writes before the update turn: the stamp, then what the work produced.
        Assert.Equal(_now, store.Writes[0].LastAgentRunAt);
        Assert.Null(store.Writes[0].LastReportJson);
        Assert.Equal("{\"sent\":true}", store.Writes[1].LastReportJson);

        // And the check was signed with an instant taken after the work, not with the stamp's.
        Assert.Equal(_now.AddSeconds(3), session.CheckedAt);
    }

    private static UpdateTurn Build(
        UpdateTestKit kit,
        AgentComponent self,
        StateStore store,
        IUpdateSession session,
        Func<MachineLockAttempt>? acquire = null,
        Func<DateTimeOffset>? clock = null,
        BinaryProbe? probe = null,
        byte[]? archive = null,
        TimeSpan? minimumInterval = null) =>
        new(
            self,
            kit.Layout,
            () => session,
            swapLog: _ => { },
            decisionLog: _ => { },
            minimumInterval: minimumInterval,
            clock: clock ?? (() => _now),
            readState: store.Read,
            writeState: store.Write,
            acquireLock: acquire ?? (() => new MachineLockAttempt(new FakeLock(), false)),
            transport: () => UpdateTestKit.Serving(archive ?? []),
            probe: probe ?? UpdateTestKit.ProbeReporting(AgentVersionInfo.Current));

    private static UpdateTurn Real(UpdateTestKit kit, StateStore store, IUpdateSession session) =>
        new(
            AgentComponent.Updater,
            kit.Layout,
            () => session,
            swapLog: _ => { },
            decisionLog: _ => { },
            minimumInterval: null,
            clock: () => _now,
            readState: store.Read,
            writeState: store.Write,
            transport: () => UpdateTestKit.Serving([]),
            probe: UpdateTestKit.ProbeReporting(AgentVersionInfo.Current));

    private static AgentStateData Enrolled() => new(
        "https://isms.example.com",
        Guid.NewGuid(),
        "DEV-001",
        _now.AddDays(-30),
        ClockOffsetSeconds: 0,
        LastReportAt: _now.AddHours(-1),
        LastReportJson: null);

    private static UpdateCheck NothingToDo() =>
        new(UpdateCheckStatus.NothingToDo, null, "nothing to do", 0);

    private static UpdateCheck Advertising(string version, string digest) =>
        new(
            UpdateCheckStatus.Advertised,
            new AgentUpdateResponse(version, UpdateTestKit.AllowedEndpoint, digest),
            "advertised",
            0);

    /// <summary>The state file, as a thing a test can interleave two processes against.</summary>
    private sealed class StateStore
    {
        public StateStore(AgentStateData? initial) => Value = initial;

        public AgentStateData? Value { get; set; }

        public List<AgentStateData> Writes { get; } = [];

        public AgentStateData? Read() => Value;

        public void Write(AgentStateData state)
        {
            Value = state;
            Writes.Add(state);
        }
    }

    /// <summary>A held lock that records its own release.</summary>
    /// <remarks>
    /// The release has to be OBSERVED rather than inferred from a later re-acquisition: a leaked
    /// real handle is unreachable once the turn returns, so its finaliser frees it at an
    /// unpredictable moment and a re-acquisition test passes against a build that never releases.
    /// </remarks>
    private sealed class FakeLock : IDisposable
    {
        public bool Disposed { get; private set; }

        public void Dispose() => Disposed = true;
    }

    private sealed class StubSession : IUpdateSession
    {
        private readonly Func<UpdateCheck> _answer;
        private readonly Func<AgentStateData, AgentStateData?>? _work;

        public StubSession(
            Func<UpdateCheck> answer,
            Func<AgentStateData, AgentStateData?>? work = null)
        {
            _answer = answer;
            _work = work;
        }

        public int Checks { get; private set; }

        public DateTimeOffset? CheckedAt { get; private set; }

        public Task<AgentStateData?> WorkAsync(
            AgentStateData state,
            CancellationToken cancellationToken) =>
            Task.FromResult(_work?.Invoke(state));

        public Task<UpdateCheck> CheckAsync(
            AgentStateData state,
            DateTimeOffset now,
            CancellationToken cancellationToken)
        {
            Checks++;
            CheckedAt = now;

            return Task.FromResult(_answer());
        }

        public void Dispose()
        {
            // Nothing held.
        }
    }
}
