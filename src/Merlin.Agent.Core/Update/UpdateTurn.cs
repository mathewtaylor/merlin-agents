using System.Security.Cryptography;
using Merlin.Agent.Core.Crypto;
using Merlin.Agent.Core.State;

namespace Merlin.Agent.Core.Update;

/// <summary>Why a turn stopped, or that it reached the end.</summary>
/// <remarks>
/// <b>Each caller maps these to its own message and exit code, and nothing else does.</b> The two
/// binaries say different things about the same situation — the agent collected nothing, the updater
/// checked nothing — and only one of them has an operator standing in front of it. Putting the words
/// here would force one vocabulary onto both; putting the DECISION in the caller is what let five
/// rounds of audit find a different defect in each copy of it.
/// </remarks>
public enum UpdateTurnStatus
{
    /// <summary>There is no state file: this machine has not enrolled.</summary>
    NotEnrolled,

    /// <summary>
    /// The machine lock could not be taken for want of RIGHTS.
    /// <b>Not the same as contention and must never be reported as it</b> — an agent started
    /// without root or SYSTEM otherwise waits out the whole timeout and exits zero, collecting
    /// nothing, on every scheduled fire, while looking healthy.
    /// </summary>
    RightsRefused,

    /// <summary>
    /// The other component holds the machine lock. Ordinary, and never an error: a swapper never
    /// swaps a target that is currently running, and the scheduler fires again.
    /// </summary>
    Contended,

    /// <summary>
    /// This process is the image that was replaced while it waited for the lock, so it stamped
    /// nothing and did nothing. See <see cref="UpdateTurn"/> for why that matters.
    /// </summary>
    Replaced,

    /// <summary>The minimum interval between scheduled checks has not elapsed.</summary>
    TooSoon,

    /// <summary>The turn ran to the end. <see cref="UpdateTurnResult.Fault"/> may still be set.</summary>
    Completed,
}

/// <summary>What trying to take the machine lock produced.</summary>
/// <remarks>
/// A seam, so the three outcomes a caller must tell apart — held, contended, refused for want of
/// rights — can be exercised without a second process and without dropping privileges.
/// </remarks>
/// <param name="Held">The held lock, or <c>null</c> when it could not be taken.</param>
/// <param name="AccessDenied">Whether the refusal was a rights failure rather than contention.</param>
public sealed record MachineLockAttempt(IDisposable? Held, bool AccessDenied);

/// <summary>What one update turn did.</summary>
/// <param name="Status">Why it stopped, or that it reached the end.</param>
/// <param name="State">The state as it stands, or <c>null</c> when nothing was read.</param>
/// <param name="Fault">
/// The message of whatever escaped the update work, or <c>null</c>.
/// <b>A fault is reported rather than thrown</b>, because nothing an update turn does is allowed to
/// leave a machine unable to report — but the caller still decides what it costs, and the two
/// binaries decide differently: the updater has nothing else to do and exits non-zero, while the
/// agent has already collected and reported and must not hand the scheduler a red run for it.
/// </param>
public sealed record UpdateTurnResult(
    UpdateTurnStatus Status,
    AgentStateData? State,
    string? Fault);

/// <summary>
/// The work a turn does under the machine lock, beyond the update itself.
/// </summary>
/// <remarks>
/// <para>
/// <b>The agent's collection and report sit INSIDE this envelope, not beside it.</b> The lock is
/// held for the whole of a run — that is what stops the updater swapping the agent's binary while it
/// executes — so a collection cannot be lifted out and run before the turn without giving up the
/// guarantee. It is a seam rather than a branch so that the updater, which has no such work, shares
/// the identical ordering rather than a similar one.
/// </para>
/// <para>
/// <b>The device key is opened once and passed in.</b> The agent signs its report and its update
/// check with the same key from the same state directory; opening it twice would be two TPM or DPAPI
/// round trips for one credential, and on a fresh machine two chances to create it.
/// </para>
/// </remarks>
public interface IUpdateSession : IDisposable
{
    /// <summary>
    /// Does whatever this component does under the lock before it takes its update turn.
    /// </summary>
    /// <param name="state">The state as stamped for this run.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>The state to persist, or <c>null</c> when there was nothing to do.</returns>
    Task<AgentStateData?> WorkAsync(AgentStateData state, CancellationToken cancellationToken);

    /// <summary>
    /// Asks Merlin what this device should be running.
    /// </summary>
    /// <param name="state">The state as stamped for this run.</param>
    /// <param name="now">The instant to sign the request with.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>What Merlin said.</returns>
    Task<UpdateCheck> CheckAsync(
        AgentStateData state,
        DateTimeOffset now,
        CancellationToken cancellationToken);
}

/// <summary>
/// The production session: this machine's own device key, and the signed update endpoint.
/// </summary>
/// <remarks>
/// <para>
/// <b>The key is opened in the constructor and the client is built on first use.</b> The two are
/// deliberately not opened together: a caller's work — the agent's report — needs the key before
/// anything asks Merlin anything, and building the client eagerly would move a failure caused by a
/// malformed stored address in FRONT of the report. A failed update must never leave a machine
/// unable to report, and that is the ordering which makes it true rather than intended.
/// </para>
/// <para>
/// <b>One enrolment, one credential.</b> Both binaries read the same <c>state.json</c> and the same
/// device key from the same state directory; a second enrolment would mean a second credential at
/// rest on every machine for no gain.
/// </para>
/// </remarks>
public sealed class DeviceUpdateSession : IUpdateSession
{
    private readonly ECDsa _key;
    private readonly Func<ECDsa, AgentStateData, CancellationToken, Task<AgentStateData?>>? _work;
    private UpdateClient? _client;

    /// <summary>Initialises a new instance of the <see cref="DeviceUpdateSession"/> class.</summary>
    /// <param name="work">
    /// What this component does under the lock before its update turn, or <c>null</c> when it has
    /// none. It is handed the shared device key.
    /// </param>
    public DeviceUpdateSession(
        Func<ECDsa, AgentStateData, CancellationToken, Task<AgentStateData?>>? work = null)
    {
        (ECDsa key, _) = DeviceKey.OpenOrCreate(AgentState.SoftwareKeyPath);

        _key = key;
        _work = work;
    }

    /// <inheritdoc />
    public Task<AgentStateData?> WorkAsync(AgentStateData state, CancellationToken cancellationToken) =>
        _work is null
            ? Task.FromResult<AgentStateData?>(null)
            : _work(_key, state, cancellationToken);

    /// <inheritdoc />
    public Task<UpdateCheck> CheckAsync(
        AgentStateData state,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(state);

        _client ??= new UpdateClient(
            state.ServerUrl, _key, AgentVersionInfo.Current, state.ClockOffsetSeconds);

        return _client.CheckAsync(
            state.DeviceId, AgentRuntimeIdentifier.Current, now, cancellationToken);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _client?.Dispose();
        _key.Dispose();
    }
}

/// <summary>
/// The envelope around one component's update turn: gate, lock, re-read, run, persist.
/// </summary>
/// <remarks>
/// <para>
/// <b>Both binaries run this, and the only difference is which component they are.</b> The agent
/// runs it as <see cref="AgentComponent.Agent"/> and may therefore only touch the updater; the
/// updater runs it as <see cref="AgentComponent.Updater"/> and may only touch the agent. It exists
/// because this envelope lived in two <c>Program.cs</c> files that no test could reach, and four
/// consecutive audit rounds each found a different defect in it — including three introduced by an
/// earlier round's own fix. Two copies of an ordering this subtle is two chances to get it wrong and
/// no way to prove either is right.
/// </para>
/// <para>
/// <b>The state is read AFTER the lock is taken, never before.</b> There is a pre-lock read, because
/// a machine that has not enrolled has nothing to lock for — but the value it produces is thrown
/// away the moment the lock is held. The wait is up to two minutes by design, so every time that
/// wait does its job the holder we waited for has written state we are holding a pre-image of, and
/// persisting it silently erases whatever it just recorded: the swap mark, the version stamped with
/// it, the outcome owed to Merlin, the pending note. The lock protects the FILES; only the re-read
/// protects the read-modify-write cycle, and <c>state.json</c> is the sole authority for every
/// safety rule in this design. Both schedulers fire missed runs on wake, so a laptop opening its lid
/// produces exactly this overlap routinely.
/// </para>
/// <para>
/// <b>A process is not evidence about a binary that replaced it.</b> If the other component swapped
/// this one while it sat waiting for the lock, the image executing here is the one that was
/// replaced — so stamping a run would tell the next turn that the NEW binary has proved itself when
/// it has never executed at all. The mark would then be cleared, the revert could never fire, and
/// the no-stacked-swap rule would stop engaging. The turn exits without stamping and lets the
/// scheduler start the binary that is actually on disk; it is the only honest witness.
/// </para>
/// <para>
/// <b>The run stamp is written before anything fallible happens.</b> It is the witness the recovery
/// rule reads to decide whether the machine was actually up, and it sat behind a download bounded at
/// ten minutes until a reboot, a kill or a crash mid-run kept losing it — a witness that keeps going
/// missing is a broken component that never gets put back.
/// </para>
/// </remarks>
public sealed class UpdateTurn
{
    /// <summary>
    /// How long to wait for whoever holds the machine lock.
    /// </summary>
    /// <remarks>
    /// An agent collection takes a couple of seconds, and a component that gave up instantly would
    /// skip a whole scheduled run over a two-second overlap. It is short, because a component that
    /// cannot get in has nothing useful to do while it waits.
    /// </remarks>
    public static readonly TimeSpan LockWait = TimeSpan.FromMinutes(2);

    /// <summary>
    /// How far after this process started a swap can plausibly have landed during its lock wait.
    /// </summary>
    /// <remarks>
    /// <b>The was-I-replaced guard needs an upper bound or a backwards clock makes it permanent.</b>
    /// It compares a stored instant against this run's start, which is sound while the clock moves
    /// forward — the swap can only have happened during the lock wait, which is at most two minutes.
    /// But a clock corrected BACKWARDS makes every previously stored instant look like the future,
    /// so the guard would fire on every scheduled run and the machine would stop collecting entirely
    /// until real time caught up. Beyond this bound the timestamp is not evidence of a concurrent
    /// swap, it is evidence of a wrong clock — and carrying on is the safer reading, because the
    /// worst case is one honest run against a binary that was replaced a while ago, against a
    /// machine that never reports again.
    /// </remarks>
    public static readonly TimeSpan ConcurrentSwapWindow = TimeSpan.FromMinutes(5);

    private readonly AgentComponent _self;
    private readonly InstallLayout _layout;
    private readonly Func<IUpdateSession> _session;
    private readonly Action<string> _swapLog;
    private readonly Action<string> _decisionLog;
    private readonly TimeSpan? _minimumInterval;
    private readonly TimeSpan _concurrentSwapWindow;
    private readonly Func<DateTimeOffset> _clock;
    private readonly Func<AgentStateData?> _readState;
    private readonly Action<AgentStateData> _writeState;
    private readonly Func<MachineLockAttempt> _acquireLock;
    private readonly Func<HttpClient> _transport;
    private readonly BinaryProbe _probe;
    private readonly UpdateWindows _windows;

    /// <summary>Initialises a new instance of the <see cref="UpdateTurn"/> class.</summary>
    /// <param name="self">Which component is running.</param>
    /// <param name="layout">Where the binaries and the state file live.</param>
    /// <param name="session">
    /// Opens this run's device key and update client, once the turn has decided to proceed. It is
    /// created OUTSIDE the fault boundary, exactly where each binary opened its key before: a key
    /// store that refuses is a real failure with a real exit code, not an update that quietly did
    /// nothing.
    /// </param>
    /// <param name="swapLog">Where progress while a binary is being replaced is written.</param>
    /// <param name="decisionLog">Where the turn's own commentary is written.</param>
    /// <param name="minimumInterval">
    /// The shortest gap between two scheduled checks, or <c>null</c> for no gate at all.
    /// <b>Not a rate limit on the server's account — a guard against the schedulers' own catch-up
    /// behaviour.</b> A systemd timer with <c>Persistent=true</c>, a launchd <c>StartInterval</c>
    /// and a Windows task with <c>StartWhenAvailable</c> all fire missed runs when a machine comes
    /// back, and a laptop returning from a week away can produce a burst. Downloading the same
    /// archive several times in a minute is pointless; swapping a binary several times in a minute
    /// is worse. It is <c>null</c> rather than <see cref="TimeSpan.Zero"/> for a caller that has no
    /// gate, because a zero gate still fires under a clock corrected backwards.
    /// </param>
    /// <param name="clock">Reads the current instant.</param>
    /// <param name="readState">Reads the state file.</param>
    /// <param name="writeState">Writes the state file.</param>
    /// <param name="acquireLock">Takes the machine lock.</param>
    /// <param name="transport">
    /// Builds the transport a package is downloaded over. Ten minutes, because a slow link on a
    /// laptop is not a failure.
    /// </param>
    /// <param name="probe">How a component's version is read.</param>
    /// <param name="windows">How long a replaced component may stay silent.</param>
    /// <param name="concurrentSwapWindow">
    /// Overrides <see cref="ConcurrentSwapWindow"/>. Tests only.
    /// </param>
    public UpdateTurn(
        AgentComponent self,
        InstallLayout layout,
        Func<IUpdateSession> session,
        Action<string> swapLog,
        Action<string> decisionLog,
        TimeSpan? minimumInterval,
        Func<DateTimeOffset>? clock = null,
        Func<AgentStateData?>? readState = null,
        Action<AgentStateData>? writeState = null,
        Func<MachineLockAttempt>? acquireLock = null,
        Func<HttpClient>? transport = null,
        BinaryProbe? probe = null,
        UpdateWindows? windows = null,
        TimeSpan? concurrentSwapWindow = null)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(session);
        ArgumentNullException.ThrowIfNull(swapLog);
        ArgumentNullException.ThrowIfNull(decisionLog);

        _self = self;
        _layout = layout;
        _session = session;
        _swapLog = swapLog;
        _decisionLog = decisionLog;
        _minimumInterval = minimumInterval;
        _concurrentSwapWindow = concurrentSwapWindow ?? ConcurrentSwapWindow;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _readState = readState ?? (() => AgentState.ReadFrom(layout.StateDirectory));
        _writeState = writeState ?? (state => AgentState.WriteTo(layout.StateDirectory, state));
        _acquireLock = acquireLock ?? (() => Acquire(layout.StateDirectory));
        _transport = transport ?? (() => new HttpClient { Timeout = TimeSpan.FromMinutes(10) });
        _probe = probe ?? BinaryProbe.Default;
        _windows = windows ?? UpdateWindows.Default;
    }

    /// <summary>
    /// Takes this component's turn.
    /// </summary>
    /// <remarks>
    /// <b>Every failure inside the update work is quiet and non-fatal.</b> Nothing this does is
    /// allowed to leave the machine unable to report — silence in the fleet is indistinguishable
    /// from a machine that was never enrolled, and a failed update that also broke the agent would
    /// be the worst outcome auto-update can produce.
    /// </remarks>
    /// <param name="operatorRequested">
    /// Whether a person asked for this run. It bypasses the minimum-interval gate, because an
    /// operator asking is not a scheduler catching up.
    /// </param>
    /// <param name="announce">
    /// Called once the turn has decided to proceed and stamped itself, before any network work.
    /// </param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>What the turn did.</returns>
    public async Task<UpdateTurnResult> RunAsync(
        bool operatorRequested = false,
        Action<AgentStateData>? announce = null,
        CancellationToken cancellationToken = default)
    {
        // Read before the lock ONLY to answer "has this machine enrolled?". There is nothing to
        // lock for on a machine mid-install or one that has been uninstalled, and the value is
        // discarded the moment the lock is held.
        AgentStateData? read = _readState();

        if (read is null)
        {
            return new UpdateTurnResult(UpdateTurnStatus.NotEnrolled, null, null);
        }

        // Captured BEFORE the lock wait, so a swap that lands DURING that wait can be told apart
        // from one that predates this process. See the guard after the re-read.
        DateTimeOffset startedAt = _clock();

        // A SWAPPER NEVER SWAPS A TARGET THAT IS CURRENTLY RUNNING. The other component holds this
        // same lock for the whole of its run, so failing to take it means that component is
        // mid-run — which is not an error, and the scheduler fires again.
        MachineLockAttempt attempt = _acquireLock();

        using IDisposable? held = attempt.Held;

        if (held is null)
        {
            return new UpdateTurnResult(
                attempt.AccessDenied ? UpdateTurnStatus.RightsRefused : UpdateTurnStatus.Contended,
                null,
                null);
        }

        // RE-READ UNDER THE LOCK. See the remarks on this class: the pre-lock snapshot is a
        // pre-image every time the wait does its job, and persisting it erases what the holder
        // just recorded.
        AgentStateData state = _readState() ?? read;

        // THIS PROCESS IS NOT EVIDENCE ABOUT A BINARY THAT REPLACED IT.
        if (state.SwappedAtOf(_self) is { } replacedAt
            && replacedAt > startedAt
            && replacedAt - startedAt <= _concurrentSwapWindow)
        {
            return new UpdateTurnResult(UpdateTurnStatus.Replaced, state, null);
        }

        // The instant used for everything that follows is taken AFTER the wait. The lock wait can
        // be two minutes, and this value is what the run stamp records — measuring anything against
        // an instant captured before a two-minute wait is measuring the wait.
        DateTimeOffset now = _clock();

        // THE INTERVAL IS JUDGED AFTER THE RE-READ, not before the lock. A run that spent two
        // minutes waiting for the other component would otherwise be measured against a stale
        // stamp, and a burst of catch-up runs is precisely when both of those happen at once.
        if (!operatorRequested
            && _minimumInterval is { } interval
            && state.LastRunOf(_self) is { } lastRun
            && now - lastRun < interval)
        {
            return new UpdateTurnResult(UpdateTurnStatus.TooSoon, state, null);
        }

        // Captured BEFORE the stamp below overwrites it. The update turn needs this component's
        // PREVIOUS run to judge whether the machine was actually up across a revert window — a
        // laptop that was merely shut for a weekend has a working binary, not a broken one — and
        // once the stamp lands there is nothing left on the record that says so.
        DateTimeOffset? previousSelfRun = state.LastRunOf(_self);

        // STAMPED BEFORE ANYTHING CAN FAIL, because this is the signal the OTHER component reads to
        // decide whether a binary it swapped in actually runs. A stamp written only on success would
        // have a network outage read as a broken binary and revert a working one.
        state = state.WithLastRun(_self, now).WithVersion(_self, AgentVersionInfo.Current);
        _writeState(state);

        announce?.Invoke(state);

        // OUTSIDE the fault boundary below, exactly where each binary opened its key before.
        using IUpdateSession session = _session();

        // The caller's own work under the lock — the agent's collection and report. Also outside
        // the fault boundary: a collection that throws is a failed run and should say so, and it is
        // Main's own catch that decides what that costs.
        if (await session.WorkAsync(state, cancellationToken).ConfigureAwait(false) is { } worked)
        {
            state = worked;
            _writeState(state);
        }

        try
        {
            // THE UPDATE TURN COMES AFTER THE WORK AND IS NOT GATED ON IT. Recovery runs before any
            // server call and needs no network whatever — so a machine that cannot reach Merlin,
            // whether from an outage, a proxy change, an expired certificate or a refused
            // signature, is exactly the machine that must still be able to put a broken component
            // back.
            //
            // A SECOND READING, taken after the work rather than reused from the stamp. The agent
            // collects and reports in between, and this value is the SIGNED request timestamp —
            // spending a slice of the skew tolerance on a collection before the machine's own drift
            // is even counted invites a refusal and a wasted retry.
            DateTimeOffset updateNow = _clock();

            using HttpClient http = _transport();

            ComponentSwapper swapper = new(_self, _layout, http, _probe, _swapLog);

            UpdateRunner runner = new(
                _self,
                _layout,
                swapper,
                _probe,
                _windows,
                _decisionLog,
                _clock,
                _writeState);

            AgentStateData updated = await runner.RunAsync(
                state,
                previousSelfRun,
                token => session.CheckAsync(state, updateNow, token),
                updateNow,
                cancellationToken).ConfigureAwait(false);

            _writeState(updated);

            return new UpdateTurnResult(UpdateTurnStatus.Completed, updated, null);
        }

        // UNFILTERED, DELIBERATELY, and it must stay that way. A named list of the expected types
        // reads as the more careful choice and is the weaker one: it was one, and
        // UriFormatException, NotSupportedException, ObjectDisposedException and a plain
        // OperationCanceledException all walked straight past it into Main. Whatever goes wrong in
        // an update turn, the answer is a line the caller writes and a machine that keeps working.
        //
        // The run stamp is already on disk, and a swap that landed persisted its own mark the
        // moment it was recorded — so what a fault costs is this turn's closing bookkeeping, never
        // the witness a revert depends on.
#pragma warning disable CA1031
        catch (Exception exception)
#pragma warning restore CA1031
        {
            return new UpdateTurnResult(UpdateTurnStatus.Completed, state, exception.Message);
        }
    }

    private static MachineLockAttempt Acquire(string stateDirectory)
    {
        MachineLock? held = MachineLock.TryAcquire(stateDirectory, LockWait, out bool accessDenied);

        return new MachineLockAttempt(held, accessDenied);
    }
}
