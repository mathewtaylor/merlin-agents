using Merlin.Agent.Core;
using Merlin.Agent.Core.Contracts;
using Merlin.Agent.Core.State;
using Merlin.Agent.Core.Update;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// Tests for one component's whole update turn.
/// </summary>
/// <remarks>
/// <b>The decision table is the feature.</b> The swap itself is a file move; what decides whether a
/// fleet updates itself, sits still, or oscillates between a broken binary and a working one is
/// this class — and every branch of it runs unattended on a machine nobody is watching.
/// </remarks>
public sealed class UpdateRunnerTests
{
    private static readonly DateTimeOffset _now = new(2026, 8, 20, 3, 0, 0, TimeSpan.Zero);

    [Fact]
    public async Task NothingToDoIsNotAnError()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "agent");

        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Updater,
            Enrolled(),
            NothingToDo(),
            UpdateTestKit.ProbeReporting(AgentVersionInfo.Current));

        // 204 is the ORDINARY answer: already current, ring not due, or no version configured.
        // Recording a failure for it would have a healthy fleet reporting a broken update daily.
        Assert.Null(after.LastUpdateOutcome);
        Assert.Equal("agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));
    }

    [Fact]
    public async Task AServerWithNoUpdateEndpointChangesNothing()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "agent");

        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Updater,
            Enrolled(),
            Answering(new UpdateCheck(
                UpdateCheckStatus.NotOffered, null, "no update surface", 0)),
            UpdateTestKit.ProbeReporting("0.2.0"));

        // An older Merlin, or one with the agent surface switched off. The machine keeps reporting
        // exactly as before; a 404 is not a failure and must never be recorded as one.
        Assert.Null(after.LastUpdateOutcome);
        Assert.Equal("agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));
    }

    [Fact]
    public async Task AnAdvertisedVersionMovesTheTargetAndNotesTheCallersOwnBinary()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "old agent");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");

        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Updater,
            Enrolled(),
            Advertising("9.9.9", UpdateTestKit.Digest(archive)),
            kit.ProbeInstalledAndStaged("0.2.0", "9.9.9"),
            archive);

        Assert.Equal(AgentUpdateOutcome.Succeeded, after.LastUpdateOutcome);
        Assert.Equal("new agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));
        Assert.Equal(_now, after.AgentSwappedAt);
        Assert.Equal("9.9.9", after.AgentVersionInstalled);

        // THE PENDING NOTE. Merlin stops advertising the moment the device reports the desired
        // agent version, so this run is the last one that will ever know what it is — and the
        // updater, which cannot replace itself, would otherwise be stranded a version behind
        // forever.
        Assert.Equal(AgentComponent.Updater, after.PendingComponent);
        Assert.Equal("9.9.9", after.PendingVersion);
    }

    [Fact]
    public async Task ThePendingNoteIsHonouredWhenTheServerHasGoneQuiet()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");

        // The version the agent is ALREADY on — which is exactly why Merlin has gone quiet. Once
        // the device reports the desired agent version the advertisement stops for good, and an
        // updater still a version behind would never hear about it again.
        string desired = AgentVersionInfo.Current;

        AgentStateData state = Enrolled() with
        {
            PendingComponent = AgentComponent.Updater,
            PendingVersion = desired,
            PendingPackageEndpoint = UpdateTestKit.AllowedEndpoint,
            PendingSha256 = UpdateTestKit.Digest(archive),
        };

        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Agent,
            state,
            NothingToDo(),
            kit.ProbeInstalledAndStaged("0.2.0", desired),
            archive);

        Assert.Equal(AgentUpdateOutcome.Succeeded, after.LastUpdateOutcome);
        Assert.Equal("new updater", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Updater)));

        // Both components are now on it, so the note has done its job and is cleared.
        Assert.Null(after.PendingComponent);
    }

    [Fact]
    public async Task AComponentNeverActsOnANotePointingAtItself()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "agent");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");

        AgentStateData state = Enrolled() with
        {
            PendingComponent = AgentComponent.Updater,
            PendingVersion = "9.9.9",
            PendingPackageEndpoint = UpdateTestKit.AllowedEndpoint,
            PendingSha256 = UpdateTestKit.Digest(archive),
        };

        // The UPDATER's turn, with a note naming the updater. It must not act on it: a process that
        // overwrites its own running image with a binary that will not execute leaves nothing on
        // the machine able to put the old one back.
        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Updater,
            state,
            NothingToDo(),
            UpdateTestKit.ProbeReporting("9.9.9"),
            archive);

        Assert.Null(after.LastUpdateOutcome);
        Assert.Equal("agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));
        Assert.Equal(AgentComponent.Updater, after.PendingComponent);
    }

    [Fact]
    public async Task TheUpdaterRestoresAnAgentThatHasNotRunSinceItWasReplaced()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "broken agent");
        File.WriteAllText(kit.Layout.PreviousPathOf(AgentComponent.Agent), "working agent");

        AgentStateData state = Enrolled() with
        {
            AgentVersionInstalled = "9.9.9",
            AgentSwappedAt = _now.AddHours(-30),
            LastAgentRunAt = _now.AddHours(-40),

            // This updater completed a run AFTER the swap, so the machine was demonstrably up and
            // the agent still did not start. That is the difference between a broken binary and a
            // closed laptop; see AClosedLaptopIsNotABrokenBinary.
            LastUpdaterRunAt = _now.AddHours(-24),
        };

        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Updater,
            state,
            // The check is never reached: recovery runs BEFORE any download, because a machine
            // whose replaced component is silent has a problem worth fixing before it is handed a
            // second new binary to fail at.
            _ => throw new InvalidOperationException("the server must not be asked"),
            UpdateTestKit.ProbeByPath(_ => null));

        Assert.Equal(AgentUpdateOutcome.Reverted, after.LastUpdateOutcome);
        Assert.Equal("working agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));
        Assert.Null(after.AgentSwappedAt);

        // The version that was put ON is blocked, not the one restored. Without this the machine
        // oscillates: swap in, revert, be advertised the same version tomorrow, revert again.
        Assert.Equal("9.9.9", after.LastRevertedVersion);
    }

    [Fact]
    public async Task TheAgentRestoresAnUpdaterOnTheSameRule()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "broken updater");
        File.WriteAllText(kit.Layout.PreviousPathOf(AgentComponent.Updater), "working updater");

        AgentStateData state = Enrolled() with
        {
            UpdaterVersionInstalled = "9.9.9",
            UpdaterSwappedAt = _now.AddHours(-100),
            LastUpdaterRunAt = _now.AddHours(-120),

            // The agent collects four times a day, so its own witness costs hours rather than the
            // extra day it costs the updater.
            LastAgentRunAt = _now.AddHours(-6),
        };

        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Agent,
            state,
            _ => throw new InvalidOperationException("the server must not be asked"),
            UpdateTestKit.ProbeByPath(_ => null));

        Assert.Equal(AgentUpdateOutcome.Reverted, after.LastUpdateOutcome);
        Assert.Equal("working updater", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Updater)));
    }

    [Fact]
    public async Task AComponentThatHasRunSinceItsSwapIsLeftAlone()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "new agent");
        File.WriteAllText(kit.Layout.PreviousPathOf(AgentComponent.Agent), "old agent");

        AgentStateData state = Enrolled() with
        {
            AgentVersionInstalled = "9.9.9",
            AgentSwappedAt = _now.AddHours(-30),
            LastAgentRunAt = _now.AddHours(-1),
        };

        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Updater,
            state,
            NothingToDo(),
            UpdateTestKit.ProbeReporting("9.9.9"));

        Assert.Null(after.LastUpdateOutcome);
        Assert.Equal("new agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));

        // The mark is cleared once the swap has proved itself, so the state file an administrator
        // reads says what is actually true of this machine.
        Assert.Null(after.AgentSwappedAt);
    }

    [Fact]
    public async Task AnOfflineMachineIsNotMistakenForABrokenBinary()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "new agent");
        File.WriteAllText(kit.Layout.PreviousPathOf(AgentComponent.Agent), "old agent");

        // It has RUN since the swap; it simply has not managed to report. Reverting here would
        // trade a working binary for a network outage — which is why the window reads the last RUN
        // and not the last successful report.
        AgentStateData state = Enrolled() with
        {
            AgentVersionInstalled = "9.9.9",
            AgentSwappedAt = _now.AddHours(-30),
            LastAgentRunAt = _now.AddHours(-2),
            LastReportAt = _now.AddDays(-9),
        };

        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Updater,
            state,
            NothingToDo(),
            UpdateTestKit.ProbeReporting("9.9.9"));

        Assert.Null(after.LastUpdateOutcome);
        Assert.Equal("new agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));
    }

    [Fact]
    public async Task AVersionThatWasRevertedIsNeverInstalledAgain()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "working agent");

        byte[] archive = UpdateTestKit.BuildArchive("bad agent", "new updater");

        AgentStateData state = Enrolled() with { LastRevertedVersion = "9.9.9" };

        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Updater,
            state,
            Advertising("9.9.9", UpdateTestKit.Digest(archive)),
            UpdateTestKit.ProbeReporting("0.2.0"),
            archive);

        Assert.Null(after.LastUpdateOutcome);
        Assert.Equal("working agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));
    }

    [Fact]
    public async Task AnAdvertisementFromAnUnlistedHostIsRecordedAsAFailedUpdate()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "working agent");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");

        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Updater,
            Enrolled(),
            Answering(new UpdateCheck(
                UpdateCheckStatus.Advertised,
                new AgentUpdateResponse(
                    "9.9.9",
                    "https://mirror.example.com/merlin/pkg.tar.gz",
                    UpdateTestKit.Digest(archive)),
                "advertised",
                0)),
            UpdateTestKit.ProbeReporting("0.2.0"),
            archive);

        // Reported, never inferred: the operator sees a failed update on /admin/agent rather than a
        // machine that quietly never moved.
        Assert.Equal(AgentUpdateOutcome.Failed, after.LastUpdateOutcome);
        Assert.Equal("working agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));
    }

    [Fact]
    public async Task TheCallersOwnVersionAndRunTimeAreAlwaysStamped()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "agent");

        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Updater,
            Enrolled(),
            NothingToDo(),
            UpdateTestKit.ProbeReporting("0.2.0"));

        // The stamp is what the OTHER component reads to decide whether this one is alive.
        Assert.Equal(AgentVersionInfo.Current, after.UpdaterVersionInstalled);
        Assert.Equal(_now, after.LastUpdaterRunAt);
        Assert.Equal("0.2.0", after.AgentVersionInstalled);
    }

    /// <summary>
    /// A machine that was SWITCHED OFF across the window keeps the binary it was given.
    /// </summary>
    /// <remarks>
    /// <b>Wall clock passes while a laptop is shut, and the elapsed window alone cannot tell the
    /// difference.</b> A machine closed on Friday afternoon straight after a swap comes back on
    /// Tuesday with the window long gone and the replaced agent — which is perfectly good — never
    /// having run. Reverting there is not a missed opportunity that the next run puts right: it
    /// writes <c>LastRevertedVersion</c>, which nothing ever clears, so that device refuses that
    /// version for good and sits a version behind until somebody pins it elsewhere by hand. One
    /// closed laptop at a time, a fleet strands itself.
    /// </remarks>
    [Fact]
    public async Task AClosedLaptopIsNotABrokenBinary()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "new agent");
        File.WriteAllText(kit.Layout.PreviousPathOf(AgentComponent.Agent), "old agent");

        AgentStateData state = Enrolled() with
        {
            AgentVersionInstalled = "9.9.9",

            // Swapped, and then the lid closed. NOTHING has run on this machine since — including
            // the updater now asking the question, whose own last run is the swap itself.
            AgentSwappedAt = _now.AddHours(-96),
            LastAgentRunAt = _now.AddHours(-97),
            LastUpdaterRunAt = _now.AddHours(-96),
        };

        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Updater,
            state,
            NothingToDo(),
            UpdateTestKit.ProbeReporting("9.9.9"));

        Assert.Null(after.LastUpdateOutcome);
        Assert.Null(after.LastRevertedVersion);
        Assert.Equal("new agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));

        // The mark stays, so the question is asked again on the next run — by which time this
        // updater will have a run of its own after the swap to answer it with.
        Assert.Equal(_now.AddHours(-96), after.AgentSwappedAt);
    }

    /// <summary>
    /// A component that was replaced and has not run since is not replaced AGAIN.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Stacking an unproven swap on an unproven swap breaks recovery in two ways at once.</b>
    /// It resets the mark a revert is timed from, so the window restarts every run and the revert
    /// never fires — an antivirus engine that quarantines the installed binary but not the freshly
    /// downloaded one produces exactly that, and the machine re-downloads and re-swaps daily for
    /// ever. And <c>Commit</c> retains only the IMMEDIATELY preceding binary, so the second swap
    /// overwrites the retained copy with the unproven one: the last binary known to work is gone,
    /// and a revert would put back something that never ran either.
    /// </para>
    /// <para>
    /// Refusing here is what keeps the retained <c>.previous</c> a binary that has actually
    /// executed on this machine, which is the entire premise of mutual recovery.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task AnUnprovenSwapIsNeverStackedOnAnotherOne()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "quarantined agent");
        File.WriteAllText(kit.Layout.PreviousPathOf(AgentComponent.Agent), "the last agent that ran");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");

        AgentStateData state = Enrolled() with
        {
            // Replaced an hour ago and not seen to run. The installed binary will not report a
            // version — it has been quarantined — so the advertised version does not match and
            // the naive path would download and swap it all over again.
            AgentSwappedAt = _now.AddHours(-1),
            LastAgentRunAt = _now.AddHours(-3),
            LastUpdaterRunAt = _now.AddHours(-24),
        };

        AgentStateData after = await RunAsync(
            kit,
            AgentComponent.Updater,
            state,
            Advertising("9.9.9", UpdateTestKit.Digest(archive)),
            UpdateTestKit.ProbeByPath(_ => null),
            archive);

        Assert.Null(after.LastUpdateOutcome);

        // Nothing moved, and — the point of the rule — the retained binary is still the one that
        // last actually ran, rather than having been overwritten by the unproven one.
        Assert.Equal("quarantined agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));
        Assert.Equal(
            "the last agent that ran",
            File.ReadAllText(kit.Layout.PreviousPathOf(AgentComponent.Agent)));

        // The mark is untouched, so the revert window keeps running from the ORIGINAL swap rather
        // than restarting. That is what stops the machine live-locking.
        Assert.Equal(_now.AddHours(-1), after.AgentSwappedAt);
    }

    private static AgentStateData Enrolled() => new(
        "https://isms.example.com",
        Guid.NewGuid(),
        "DEV-001",
        _now.AddDays(-30),
        ClockOffsetSeconds: 0,
        LastReportAt: _now.AddHours(-1),
        LastReportJson: null);

    private static Func<CancellationToken, Task<UpdateCheck>> NothingToDo() =>
        Answering(new UpdateCheck(UpdateCheckStatus.NothingToDo, null, "nothing to do", 0));

    private static Func<CancellationToken, Task<UpdateCheck>> Advertising(string version, string digest) =>
        Answering(new UpdateCheck(
            UpdateCheckStatus.Advertised,
            new AgentUpdateResponse(version, UpdateTestKit.AllowedEndpoint, digest),
            "advertised",
            0));

    private static Func<CancellationToken, Task<UpdateCheck>> Answering(UpdateCheck answer) =>
        _ => Task.FromResult(answer);

    private static async Task<AgentStateData> RunAsync(
        UpdateTestKit kit,
        AgentComponent self,
        AgentStateData state,
        Func<CancellationToken, Task<UpdateCheck>> check,
        BinaryProbe probe,
        byte[]? archive = null)
    {
        using HttpClient http = UpdateTestKit.Serving(archive ?? []);

        ComponentSwapper swapper = new(kit.Layout, http, probe, _ => { });
        UpdateRunner runner = new(self, kit.Layout, swapper, probe, UpdateWindows.Default, _ => { });

        // The state handed in is the state as READ, so its own last-run stamp is genuinely the
        // previous one — which is exactly what the updater passes in production. The agent has to
        // carry the value separately because it stamps itself before it gets here.
        return await runner.RunAsync(state, state.LastRunOf(self), check, _now);
    }
}
