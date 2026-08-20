using Merlin.Agent.Core.Contracts;
using Merlin.Agent.Core.State;

namespace Merlin.Agent.Core.Update;

/// <summary>How long a component may be silent after being replaced before it is put back.</summary>
/// <param name="Agent">
/// The agent collects every six hours, so twenty-four is four missed runs — long enough that a
/// laptop shut for a night is never mistaken for a broken binary, short enough that a machine which
/// really has gone dark comes back the next day.
/// </param>
/// <param name="Updater">
/// The updater runs daily, so seventy-two is three missed runs. Wider than the agent's on purpose:
/// a machine off for a weekend is ordinary, and a spurious revert costs a working binary.
/// </param>
public sealed record UpdateWindows(TimeSpan Agent, TimeSpan Updater)
{
    /// <summary>The windows both binaries ship with.</summary>
    public static UpdateWindows Default { get; } =
        new(TimeSpan.FromHours(24), TimeSpan.FromHours(72));

    /// <summary>The window for one component.</summary>
    /// <param name="component">The component.</param>
    /// <returns>Its window.</returns>
    public TimeSpan For(AgentComponent component) =>
        component == AgentComponent.Agent ? Agent : Updater;
}

/// <summary>
/// One component's whole update turn: observe, recover, resolve, swap at most once.
/// </summary>
/// <remarks>
/// <para>
/// <b>Both binaries run this, and the ONLY difference is which component they are.</b> The agent
/// runs it as <see cref="AgentComponent.Agent"/> and therefore may only touch the updater; the
/// updater runs it as <see cref="AgentComponent.Updater"/> and may only touch the agent. Two
/// callers, one implementation — so the never-replace-yourself rule and the one-swap-per-run rule
/// cannot be true of one binary and false of the other.
/// </para>
/// <para>
/// <b>Recovery is checked BEFORE any download.</b> A machine whose replaced component is not
/// running has a problem worth fixing before it is given a second new binary to fail at.
/// </para>
/// <para>
/// <b>A pending swap exists because the advertisement goes quiet at the worst moment.</b> Merlin
/// stops advertising as soon as the device REPORTS the desired agent version — so the run that
/// moves the agent is the last one that will ever be told what the version is, and an updater a
/// version behind would never learn of it. Whichever component swaps the other therefore records
/// what still needs moving, while it still knows.
/// </para>
/// </remarks>
public sealed class UpdateRunner
{
    private readonly AgentComponent _self;
    private readonly InstallLayout _layout;
    private readonly ComponentSwapper _swapper;
    private readonly BinaryProbe _probe;
    private readonly UpdateWindows _windows;
    private readonly Action<string> _log;

    /// <summary>Initialises a new instance of the <see cref="UpdateRunner"/> class.</summary>
    /// <param name="self">Which component is running.</param>
    /// <param name="layout">Where the binaries live.</param>
    /// <param name="swapper">The shared swap routine.</param>
    /// <param name="probe">How the other component's version is read.</param>
    /// <param name="windows">How long a replaced component may stay silent.</param>
    /// <param name="log">Where progress is written.</param>
    public UpdateRunner(
        AgentComponent self,
        InstallLayout layout,
        ComponentSwapper swapper,
        BinaryProbe probe,
        UpdateWindows windows,
        Action<string> log)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(swapper);
        ArgumentNullException.ThrowIfNull(probe);
        ArgumentNullException.ThrowIfNull(windows);
        ArgumentNullException.ThrowIfNull(log);

        _self = self;
        _layout = layout;
        _swapper = swapper;
        _probe = probe;
        _windows = windows;
        _log = log;
    }

    /// <summary>
    /// Takes this component's turn and returns the state to persist.
    /// </summary>
    /// <param name="state">The state as read.</param>
    /// <param name="previousSelfRunAt">
    /// When THIS component last completed a run, before this one. <b>It is a parameter rather than
    /// a read of <paramref name="state"/> because the agent has already stamped itself by the time
    /// it gets here</b> — the stamp is written to disk before collection so that a crash mid-run
    /// still counts as having run — so <c>state.LastRunOf(self)</c> would read as "now" and the
    /// witness in <see cref="ShouldRestore"/> would be vacuous for the agent. Callers pass the
    /// value they read before stamping.
    /// </param>
    /// <param name="check">
    /// Asks Merlin what this device should be running. A delegate rather than a client, so the whole
    /// decision table can be exercised without a server.
    /// </param>
    /// <param name="now">The current instant.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The state to persist.</returns>
    public async Task<AgentStateData> RunAsync(
        AgentStateData state,
        DateTimeOffset? previousSelfRunAt,
        Func<CancellationToken, Task<UpdateCheck>> check,
        DateTimeOffset now,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(state);
        ArgumentNullException.ThrowIfNull(check);

        AgentComponent target = InstallLayout.Target(_self);

        // Captured BEFORE the re-probe below. A binary that will not execute has no version to
        // read, so the probe returns null — and null is the honest thing to report to Merlin, but
        // it is useless as the identity of the release that has to be blocked from coming back. The
        // version recorded when the swap succeeded is what names it.
        string? versionAtSwap = state.VersionOf(target);

        // What is actually on this machine, asked of the binaries rather than believed from the
        // file. This component knows its own version; the other one is asked for its.
        state = state
            .WithVersion(_self, AgentVersionInfo.Current)
            .WithLastRun(_self, now)
            .WithVersion(target, _probe.Version(_layout.PathOf(target)));

        state = ClearSettledBookkeeping(state, target);

        if (ShouldRestore(state, target, previousSelfRunAt, now))
        {
            return Recover(state, target, versionAtSwap, now);
        }

        UpdateCheck answer = await check(cancellationToken).ConfigureAwait(false);

        state = state with { ClockOffsetSeconds = answer.ClockOffsetSeconds };

        (string? version, string? endpoint, string? sha256) = Desired(state, target, answer);

        if (version is null)
        {
            _log($"  {answer.Detail}");
            return state;
        }

        if (AgentVersionInfo.Matches(state.VersionOf(target), version))
        {
            // The component this process may replace is already there. Anything still outstanding
            // is this process's OWN binary, which it must not touch.
            return NoteWhatIsStillOutstanding(state, version, endpoint, sha256);
        }

        // A version installed here once and reverted is never installed again. Without this the
        // recovery loop is infinite: swap in a bad binary, revert it, be advertised the same
        // version tomorrow, and oscillate forever.
        if (AgentVersionInfo.Matches(version, state.LastRevertedVersion))
        {
            _log($"  {version} was installed here before and had to be reverted. It will not be "
                + "installed again; pin this device to a different version in Merlin.");

            return state;
        }

        SwapResult result = await _swapper
            .SwapAsync(target, version, endpoint!, sha256!, cancellationToken)
            .ConfigureAwait(false);

        _log($"  {result.Detail}");

        state = result.Outcome switch
        {
            AgentUpdateOutcome.Succeeded => state
                .WithVersion(target, result.InstalledVersion)
                .WithSwappedAt(target, now)
                with
            {
                LastUpdateOutcome = AgentUpdateOutcome.Succeeded,
                LastUpdateAt = now,
                LastUpdateDetail = result.Detail,
            },
            AgentUpdateOutcome.Failed => state with
            {
                LastUpdateOutcome = AgentUpdateOutcome.Failed,
                LastUpdateAt = now,
                LastUpdateDetail = result.Detail,
            },
            _ => state,
        };

        return result.Outcome == AgentUpdateOutcome.Succeeded
            ? NoteWhatIsStillOutstanding(state, version, endpoint, sha256)
            : state;
    }

    /// <summary>
    /// Resolves the version this component should move its target to.
    /// </summary>
    /// <remarks>
    /// The advertisement first, and a recorded pending swap second. A <c>204</c> means Merlin has
    /// nothing to say — which, once the agent has reported the desired version, is what it says
    /// forever, including to an updater still a version behind.
    /// </remarks>
    private static (string? Version, string? Endpoint, string? Sha256) Desired(
        AgentStateData state,
        AgentComponent target,
        UpdateCheck answer)
    {
        if (answer is { Status: UpdateCheckStatus.Advertised, Advertisement: { } advertisement })
        {
            return (advertisement.Version, advertisement.PackageEndpoint, advertisement.Sha256);
        }

        return state.PendingComponent == target
            && !string.IsNullOrWhiteSpace(state.PendingVersion)
            ? (state.PendingVersion, state.PendingPackageEndpoint, state.PendingSha256)
            : (null, null, null);
    }

    /// <summary>
    /// Records what the OTHER component still needs, or clears the note once it is satisfied.
    /// </summary>
    private AgentStateData NoteWhatIsStillOutstanding(
        AgentStateData state,
        string version,
        string? endpoint,
        string? sha256)
    {
        if (AgentVersionInfo.Matches(state.VersionOf(_self), version)
            || string.IsNullOrWhiteSpace(endpoint)
            || string.IsNullOrWhiteSpace(sha256))
        {
            return state with
            {
                PendingComponent = null,
                PendingVersion = null,
                PendingPackageEndpoint = null,
                PendingSha256 = null,
            };
        }

        _log($"  this {InstallLayout.FileName(_self)} is on "
            + $"{state.VersionOf(_self) ?? "an unknown version"} and cannot replace itself. "
            + $"{InstallLayout.FileName(InstallLayout.Target(_self))} will move it to {version}.");

        return state with
        {
            PendingComponent = _self,
            PendingVersion = version,
            PendingPackageEndpoint = endpoint,
            PendingSha256 = sha256,
        };
    }

    /// <summary>
    /// Whether the component this process may replace has failed to run since it was replaced.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Reads when the binary last EXECUTED, not when it last reported successfully.</b> The
    /// question is whether the swapped-in image runs at all; a machine that has been offline for a
    /// day has a working agent and a broken network, and reverting it would trade a real binary for
    /// an imagined fault.
    /// </para>
    /// <para>
    /// <b>The elapsed window alone is not evidence, because wall clock passes while a laptop is
    /// shut.</b> A machine switched off for a weekend straight after a swap comes back with the
    /// window long expired and the replaced binary — which is perfectly good — never having run,
    /// which is indistinguishable from a broken one unless something says the machine was actually
    /// UP for that window. This component's own previous run is that witness: it means "I completed
    /// a run since the swap, on this machine, and the other component still has not". The state
    /// file holds no other record of uptime, and inventing one would be a second clock to keep
    /// honest.
    /// </para>
    /// <para>
    /// <b>Getting this wrong is not a missed revert, it is a permanent one.</b> A false revert
    /// writes <c>LastRevertedVersion</c>, which nothing ever clears, so the device refuses that
    /// version for good and sits a version behind until an operator pins it elsewhere by hand. The
    /// price of the witness is one extra cycle before a genuinely broken binary is put back — up to
    /// a second updater run for the agent, and a matter of hours the other way round, since the
    /// agent runs four times as often. A day's later recovery beats a fleet quietly stranding
    /// itself one closed laptop at a time.
    /// </para>
    /// </remarks>
    private bool ShouldRestore(
        AgentStateData state,
        AgentComponent target,
        DateTimeOffset? previousSelfRunAt,
        DateTimeOffset now)
    {
        if (state.SwappedAtOf(target) is not { } swappedAt)
        {
            return false;
        }

        if (state.LastRunOf(target) is { } lastRun && lastRun > swappedAt)
        {
            return false;
        }

        if (previousSelfRunAt is not { } witness || witness <= swappedAt)
        {
            return false;
        }

        return now - swappedAt > _windows.For(target)
            && File.Exists(_layout.PreviousPathOf(target));
    }

    private AgentStateData Recover(
        AgentStateData state,
        AgentComponent target,
        string? versionAtSwap,
        DateTimeOffset now)
    {
        SwapResult result = _swapper.Restore(target);

        _log($"  {result.Detail}");

        if (result.Outcome != AgentUpdateOutcome.Reverted)
        {
            return state;
        }

        return state
            .WithVersion(target, result.InstalledVersion)
            .WithSwappedAt(target, null)
            with
        {
            // The version that was put ON is the one blocked, not the one restored.
            LastRevertedVersion = versionAtSwap ?? state.LastRevertedVersion,
            LastUpdateOutcome = AgentUpdateOutcome.Reverted,
            LastUpdateAt = now,
            LastUpdateDetail = result.Detail,
            PendingComponent = null,
            PendingVersion = null,
            PendingPackageEndpoint = null,
            PendingSha256 = null,
        };
    }

    /// <summary>
    /// Drops bookkeeping that has done its job — a swap the component has since run after, and a
    /// pending note for a version this component is already on.
    /// </summary>
    /// <remarks>
    /// Left in place it is merely untidy, but it is untidy in the file an administrator reads to
    /// work out what a machine has been doing, which is where untidy becomes misleading.
    /// </remarks>
    private AgentStateData ClearSettledBookkeeping(AgentStateData state, AgentComponent target)
    {
        if (state.SwappedAtOf(target) is { } swappedAt
            && state.LastRunOf(target) is { } lastRun
            && lastRun > swappedAt)
        {
            state = state.WithSwappedAt(target, null);
        }

        if (state.PendingComponent == _self
            && AgentVersionInfo.Matches(state.VersionOf(_self), state.PendingVersion))
        {
            state = state with
            {
                PendingComponent = null,
                PendingVersion = null,
                PendingPackageEndpoint = null,
                PendingSha256 = null,
            };
        }

        return state;
    }
}
