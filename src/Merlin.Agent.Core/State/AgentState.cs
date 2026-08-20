using System.Text.Json;
using System.Text.Json.Serialization;
using Merlin.Agent.Core.Contracts;
using Merlin.Agent.Core.Platform;
using Merlin.Agent.Core.Update;

namespace Merlin.Agent.Core.State;

/// <summary>
/// What the agent remembers between runs.
/// </summary>
/// <remarks>
/// Deliberately tiny. It holds no secret — the signing key lives in the TPM or in a separately
/// protected file — so this file can be read by anyone curious about what the agent is doing,
/// which is the point.
/// </remarks>
/// <param name="ServerUrl">The Merlin deployment this machine reports to.</param>
/// <param name="DeviceId">Merlin's identifier for this device.</param>
/// <param name="DeviceCode">The register code, for display.</param>
/// <param name="EnrolledAt">When enrolment succeeded.</param>
/// <param name="ClockOffsetSeconds">
/// The correction to apply to this machine's clock when stamping a request.
/// </param>
/// <param name="LastReportAt">When a report was last accepted.</param>
/// <param name="LastReportJson">The last payload sent, verbatim, for <c>merlin-agent status</c>.</param>
/// <param name="AgentVersionInstalled">
/// The agent binary's own version, as it last stated it. Written by the agent about itself and by
/// the updater about what it just installed.
/// </param>
/// <param name="UpdaterVersionInstalled">The updater binary's version, on the same terms.</param>
/// <param name="LastAgentRunAt">
/// When the agent binary last EXECUTED — stamped at the top of a run, before anything can fail.
/// <b>This, and not <see cref="LastReportAt"/>, is what mutual recovery reads.</b> The question a
/// revert answers is "does the replaced binary run at all", and reading the last successful report
/// instead would revert a perfectly good agent for a twelve-hour network outage.
/// </param>
/// <param name="LastUpdaterRunAt">When the updater binary last executed, on the same terms.</param>
/// <param name="AgentSwappedAt">When the agent binary was last replaced, or null.</param>
/// <param name="UpdaterSwappedAt">When the updater binary was last replaced, or null.</param>
/// <param name="AgentSwappedToVersion">
/// The version the agent binary was replaced WITH, as advertised, or null.
/// <b>It is a field of its own because the probed version cannot survive to be read.</b>
/// <see cref="AgentVersionInstalled"/> is re-asked of the binary on every run, and a binary that
/// will not execute has no version to give, so it is overwritten with null — while a revert can
/// never happen in the same run as the swap, because the recovery witness requires an intervening
/// run. The identity of the release that has to be blocked was therefore always gone by the time
/// anything needed it, and <see cref="LastRevertedVersion"/> was null on every revert that
/// mattered. Stamped from the ADVERTISED string, because that is what the block compares against.
/// </param>
/// <param name="UpdaterSwappedToVersion">The same, for the updater binary.</param>
/// <param name="AgentSwapHadFallback">
/// Whether a working agent binary was retained when the agent was replaced.
/// <b>It is what tells "a working binary was lost" apart from "there was never one here".</b>
/// Recovery refuses a release that was installed and then could not be put back — correct when
/// something was lost, and wrong for a FIRST installation, where nothing was retained because
/// nothing was there and the version is not what failed. That case is the ordinary upgrade path
/// from a release before the updater existed: the agent installs an updater, nothing on the machine
/// is scheduled to run it yet, and the release would otherwise be blocklisted on every machine in
/// the fleet that had not been reinstalled.
/// </param>
/// <param name="UpdaterSwapHadFallback">The same, for the updater binary.</param>
/// <param name="PendingComponent">
/// The component that still needs moving to <see cref="PendingVersion"/>, or null.
/// <b>This exists because the advertisement goes quiet at exactly the wrong moment.</b> Merlin
/// stops advertising once the device REPORTS the desired agent version — so the run that moves the
/// agent is the last one that will ever be told what the version is, and the updater sitting a
/// version behind would never learn of it. So the swapper records what the OTHER component still
/// needs, while it still knows, and the other component picks it up on its next run.
/// </param>
/// <param name="PendingVersion">The version the pending component should move to.</param>
/// <param name="PendingPackageEndpoint">Where to fetch it. Re-checked against the host allowlist.</param>
/// <param name="PendingSha256">Its expected digest. Re-verified before anything executes.</param>
/// <param name="LastUpdateOutcome">
/// What happened the last time a component replaced the other one. Reported on the next report and
/// deliberately NOT cleared once sent — Merlin decides whether an outcome is news.
/// </param>
/// <param name="LastUpdateAt">When that outcome was recorded.</param>
/// <param name="LastUpdateDetail">A sentence describing it, for <c>status</c>.</param>
/// <param name="LastRevertedVersion">
/// A version that was installed and then reverted on this machine.
/// <b>It is never installed again.</b> Without this the recovery loop is infinite: the updater
/// swaps in a bad agent, reverts it a day later, is advertised the same version the day after, and
/// the machine oscillates between a working agent and a broken one forever.
/// </param>
public sealed record AgentStateData(
    string ServerUrl,
    Guid DeviceId,
    string DeviceCode,
    DateTimeOffset EnrolledAt,
    long ClockOffsetSeconds,
    DateTimeOffset? LastReportAt,
    string? LastReportJson,
    string? AgentVersionInstalled = null,
    string? UpdaterVersionInstalled = null,
    DateTimeOffset? LastAgentRunAt = null,
    DateTimeOffset? LastUpdaterRunAt = null,
    DateTimeOffset? AgentSwappedAt = null,
    DateTimeOffset? UpdaterSwappedAt = null,
    string? AgentSwappedToVersion = null,
    string? UpdaterSwappedToVersion = null,
    bool AgentSwapHadFallback = false,
    bool UpdaterSwapHadFallback = false,
    AgentComponent? PendingComponent = null,
    string? PendingVersion = null,
    string? PendingPackageEndpoint = null,
    string? PendingSha256 = null,
    AgentUpdateOutcome? LastUpdateOutcome = null,
    DateTimeOffset? LastUpdateAt = null,
    string? LastUpdateDetail = null,
    string? LastRevertedVersion = null)
{
    /// <summary>The recorded installed version of one component.</summary>
    /// <param name="component">The component.</param>
    /// <returns>The version, or null when it has never been observed.</returns>
    public string? VersionOf(AgentComponent component) => component == AgentComponent.Agent
        ? AgentVersionInstalled
        : UpdaterVersionInstalled;

    /// <summary>When one component's binary last executed.</summary>
    /// <param name="component">The component.</param>
    /// <returns>The instant, or null.</returns>
    public DateTimeOffset? LastRunOf(AgentComponent component) => component == AgentComponent.Agent
        ? LastAgentRunAt
        : LastUpdaterRunAt;

    /// <summary>When one component's binary was last replaced.</summary>
    /// <param name="component">The component.</param>
    /// <returns>The instant, or null.</returns>
    public DateTimeOffset? SwappedAtOf(AgentComponent component) => component == AgentComponent.Agent
        ? AgentSwappedAt
        : UpdaterSwappedAt;

    /// <summary>Records a component's installed version.</summary>
    /// <param name="component">The component.</param>
    /// <param name="version">The version, or null when it could not be read.</param>
    /// <returns>The updated state.</returns>
    public AgentStateData WithVersion(AgentComponent component, string? version) =>
        component == AgentComponent.Agent
            ? this with { AgentVersionInstalled = version }
            : this with { UpdaterVersionInstalled = version };

    /// <summary>Records when a component's binary last executed.</summary>
    /// <param name="component">The component.</param>
    /// <param name="instant">The instant.</param>
    /// <returns>The updated state.</returns>
    public AgentStateData WithLastRun(AgentComponent component, DateTimeOffset instant) =>
        component == AgentComponent.Agent
            ? this with { LastAgentRunAt = instant }
            : this with { LastUpdaterRunAt = instant };

    /// <summary>The version a component's binary was replaced with, as advertised.</summary>
    /// <param name="component">The component.</param>
    /// <returns>The version, or null when nothing is outstanding.</returns>
    public string? SwappedToVersionOf(AgentComponent component) =>
        component == AgentComponent.Agent ? AgentSwappedToVersion : UpdaterSwappedToVersion;

    /// <summary>Whether a working binary was retained when a component was replaced.</summary>
    /// <param name="component">The component.</param>
    /// <returns><c>true</c> when there was something to fall back to.</returns>
    public bool SwapHadFallbackOf(AgentComponent component) =>
        component == AgentComponent.Agent ? AgentSwapHadFallback : UpdaterSwapHadFallback;

    /// <summary>
    /// Records that a component's binary was replaced, or clears the mark.
    /// </summary>
    /// <remarks>
    /// <b>The instant and the version move together, always.</b> They answer one question — is
    /// there an unproven swap outstanding, and which release is it — and two setters would let a
    /// caller record half of it. The mark decides whether a revert is due; the version decides what
    /// is blocked afterwards, and a mark with no version is what made the anti-oscillation guard
    /// dead code.
    /// </remarks>
    /// <param name="component">The component.</param>
    /// <param name="instant">The instant, or null to clear.</param>
    /// <param name="version">The advertised version installed, or null to clear.</param>
    /// <returns>The updated state.</returns>
    /// <param name="hadFallback">Whether a working binary was retained by that swap.</param>
    public AgentStateData WithSwap(
        AgentComponent component,
        DateTimeOffset? instant,
        string? version,
        bool hadFallback = false) =>
        component == AgentComponent.Agent
            ? this with
            {
                AgentSwappedAt = instant,
                AgentSwappedToVersion = version,
                AgentSwapHadFallback = hadFallback,
            }
            : this with
            {
                UpdaterSwappedAt = instant,
                UpdaterSwappedToVersion = version,
                UpdaterSwapHadFallback = hadFallback,
            };
}

/// <summary>
/// Reads and writes the agent's state file.
/// </summary>
/// <remarks>
/// <para>
/// <b>The last report is stored verbatim so a person can see exactly what left their machine.</b>
/// That is what <c>merlin-agent status</c> prints. An open-source agent that an employee cannot
/// actually inspect the output of is a weaker promise than it looks, and this closes it for people
/// who will not read C#.
/// </para>
/// <para>
/// <b>Losing this file is recoverable and losing the key is not.</b> State can be rebuilt by
/// re-enrolling with the same key, which Merlin treats as an update rather than a new device. That
/// asymmetry is why the two are stored separately.
/// </para>
/// </remarks>
public static class AgentState
{
    /// <summary>
    /// The directory the agent keeps its state in — each platform's own convention.
    /// </summary>
    /// <remarks>
    /// <b>Hard-coded per platform rather than taken from <c>SpecialFolder.CommonApplicationData</c>,
    /// which resolves to <c>/usr/share</c> on both Unix targets.</b> That is a package-managed
    /// directory the agent has no business writing device keys into, and on a machine where it
    /// happened to be writable the state would sit somewhere no administrator would think to look.
    /// </remarks>
    public static string Directory => AgentPlatformInfo.Current switch
    {
        AgentOs.Windows => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Merlin Agent"),
        AgentOs.MacOs => "/Library/Application Support/Merlin Agent",
        _ => "/var/lib/merlin-agent",
    };

    /// <summary>The state file path.</summary>
    public static string StatePath => Path.Combine(Directory, "state.json");

    /// <summary>The software-key file path, used where no hardware key store is available.</summary>
    public static string SoftwareKeyPath => Path.Combine(Directory, "device.key");

    /// <summary>Reads the state, or <c>null</c> when this machine has not enrolled.</summary>
    /// <returns>The state, or null.</returns>
    public static AgentStateData? Read() => ReadFrom(Directory);

    /// <summary>
    /// Reads the state from a named directory.
    /// </summary>
    /// <remarks>
    /// The directory is a parameter so the swap routine can be exercised against a temporary tree.
    /// Both binaries call the parameterless overload; nothing in production names a directory.
    /// </remarks>
    /// <param name="directory">The state directory.</param>
    /// <returns>The state, or null.</returns>
    public static AgentStateData? ReadFrom(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        string path = Path.Combine(directory, "state.json");

        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(File.ReadAllText(path), AgentStateJsonContext.Default.AgentStateData);
        }
        catch (JsonException)
        {
            // A corrupt state file is recoverable by re-enrolling, so it must not be fatal — the
            // machine would otherwise stop reporting permanently over a truncated write.
            return null;
        }
    }

    /// <summary>Writes the state.</summary>
    /// <param name="state">The state to persist.</param>
    public static void Write(AgentStateData state)
    {
        EnsureDirectory();
        WriteTo(Directory, state);
    }

    /// <summary>Writes the state into a named directory.</summary>
    /// <param name="directory">The state directory.</param>
    /// <param name="state">The state to persist.</param>
    public static void WriteTo(string directory, AgentStateData state)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);
        ArgumentNullException.ThrowIfNull(state);

        EnsureDirectory(directory);

        // Written to a temporary file and moved into place, so an interrupted write cannot leave a
        // half-written state file behind.
        string path = Path.Combine(directory, "state.json");
        string temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(state, AgentStateJsonContext.Default.AgentStateData));
        File.Move(temporary, path, overwrite: true);
    }

    /// <summary>Removes the state file.</summary>
    public static void Delete()
    {
        if (File.Exists(StatePath))
        {
            File.Delete(StatePath);
        }
    }

    /// <summary>
    /// Creates the state directory, restricting it to the superuser on Unix.
    /// </summary>
    /// <remarks>
    /// <b>The mode is what protects the software key on macOS and Linux</b>, where there is no DPAPI
    /// equivalent to encrypt it with. <c>0700</c> on the directory and <c>0600</c> on the key file
    /// means only root can read it — and the agent already runs as root, so anything that could
    /// bypass the mode could equally read the process's memory. The honest statement is in
    /// <c>docs/security.md</c>: on those platforms the key is protected by file permissions rather
    /// than by encryption at rest.
    /// </remarks>
    public static void EnsureDirectory() => EnsureDirectory(Directory);

    /// <summary>
    /// Creates a named state directory, restricting it to the superuser on Unix.
    /// </summary>
    /// <remarks>
    /// <b>The mode is applied even when the directory already exists, and that is the whole point
    /// of this overload.</b> <c>Directory.CreateDirectory(path, mode)</c> applies its mode only at
    /// CREATION and silently does nothing to a directory that is already there — so whichever code
    /// path happens to run first decides the permissions for ever. That is not hypothetical: the
    /// machine lock creates this directory too, and once it began being taken at the top of
    /// enrolment it started winning the race, leaving <c>0755</c> behind and making this method a
    /// no-op on exactly the install it was written for. Setting the mode every time is idempotent,
    /// costs nothing, and heals a directory that was created loosely by anything else.
    /// </remarks>
    /// <param name="directory">The directory to create and restrict.</param>
    public static void EnsureDirectory(string directory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(directory);

        if (OperatingSystem.IsWindows())
        {
            System.IO.Directory.CreateDirectory(directory);
            return;
        }

        const UnixFileMode ownerOnly =
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute;

        System.IO.Directory.CreateDirectory(directory, ownerOnly);

        try
        {
            File.SetUnixFileMode(directory, ownerOnly);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Not ours to tighten. The key file inside carries 0600 in its own right, so this is a
            // defence in depth rather than the only thing standing between a key and a reader.
        }
    }
}

/// <summary>
/// Source-generated JSON context. NativeAOT trims reflection-based serialisation, so every type that
/// crosses a serialiser needs an entry here.
/// </summary>
[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(AgentStateData))]
public sealed partial class AgentStateJsonContext : JsonSerializerContext;
