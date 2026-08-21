using System.Text.Json.Serialization;
using Merlin.Agent.Core.State;

namespace Merlin.Agent.Core.Update;

/// <summary>Which of the two scheduled binaries something refers to.</summary>
/// <remarks>
/// Persisted into <c>state.json</c> by NAME, so an added member can never re-point an existing
/// machine's pending swap at the wrong binary.
/// </remarks>
[JsonConverter(typeof(JsonStringEnumConverter<AgentComponent>))]
public enum AgentComponent
{
    /// <summary>
    /// <c>merlin-agent</c> — collects and reports every six hours, and replaces the updater.
    /// </summary>
    Agent,

    /// <summary>
    /// <c>merlin-updater</c> — checks daily whether Merlin advertises a different version, and
    /// replaces the agent.
    /// </summary>
    Updater,
}

/// <summary>
/// Where the two binaries live on this machine, and what the archive calls them.
/// </summary>
/// <remarks>
/// <para>
/// <b>Both are resolved from ONE directory, which the schedulers point at by absolute path.</b> The
/// installer registers a scheduled task, launch daemon or systemd unit naming
/// <c>&lt;install&gt;/merlin-agent</c> and <c>&lt;install&gt;/merlin-updater</c>, so a swap that
/// wrote anywhere else would leave the scheduler running the old binary forever while the state
/// file happily reported the new version. The paths are the contract; the swap moves files
/// underneath them.
/// </para>
/// <para>
/// <b>The directory is DISCOVERED from the running process, not hard-coded.</b>
/// <see cref="AppContext.BaseDirectory"/> is where this binary actually is, which is the only
/// answer that stays true for a machine installed to a non-default path, and it is what
/// <c>QueryPack</c> and <c>OsqueryRunner</c> already resolve against. A constructed instance is
/// what makes the swap routine testable at all — every test in this area points one at a temporary
/// directory.
/// </para>
/// </remarks>
public sealed class InstallLayout
{
    /// <summary>Initialises a new instance of the <see cref="InstallLayout"/> class.</summary>
    /// <param name="installDirectory">The directory both binaries live in.</param>
    /// <param name="stateDirectory">The directory holding <c>state.json</c> and the device key.</param>
    public InstallLayout(string installDirectory, string stateDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(installDirectory);
        ArgumentException.ThrowIfNullOrWhiteSpace(stateDirectory);

        InstallDirectory = installDirectory;
        StateDirectory = stateDirectory;
    }

    /// <summary>The layout of the machine this process is running on.</summary>
    public static InstallLayout Current { get; } =
        new(AppContext.BaseDirectory, AgentState.Directory);

    /// <summary>The directory both binaries live in.</summary>
    public string InstallDirectory { get; }

    /// <summary>The directory holding <c>state.json</c> and the device key.</summary>
    public string StateDirectory { get; }

    /// <summary>The staging directory a downloaded archive is unpacked into.</summary>
    /// <remarks>
    /// <para>
    /// <b>Under the INSTALL directory, because a file that is about to become an installed binary
    /// must be staged somewhere exactly as protected as the binaries themselves.</b> The installer
    /// puts those in <c>%ProgramFiles%\Merlin Agent</c>, <c>/opt/merlin-agent</c> or
    /// <c>/usr/local/merlin-agent</c> — administrator- or root-only. Anyone who can write there can
    /// already replace the binary outright, so staging there adds no exposure that does not already
    /// exist.
    /// </para>
    /// <para>
    /// <b>It was under the state directory, and that was wrong on Windows.</b>
    /// <c>%ProgramData%\Merlin Agent</c> inherits its parent's access control, which grants
    /// ordinary users the right to create entries in the tree — harmless while that directory held
    /// only a state file and a DPAPI-protected key, and not harmless once it became the place a
    /// SYSTEM process extracts a binary and then EXECUTES it. The window between extracting and
    /// executing is a local privilege escalation for anyone who can win it.
    /// </para>
    /// <para>
    /// A dedicated SUBDIRECTORY, not the install directory itself, so the original reason for the
    /// old location still holds: a half-finished swap never leaves a stray executable beside the
    /// ones the schedulers point at.
    /// </para>
    /// </remarks>
    public string StagingDirectory => Path.Combine(InstallDirectory, ".staging");

    /// <summary>The file name a component carries, with the platform's executable suffix.</summary>
    /// <param name="component">The component.</param>
    /// <returns>The file name, as it appears in the archive and on disk.</returns>
    public static string FileName(AgentComponent component)
    {
        string stem = component == AgentComponent.Agent ? "merlin-agent" : "merlin-updater";

        return OperatingSystem.IsWindows() ? stem + ".exe" : stem;
    }

    /// <summary>The component the OTHER one is allowed to replace.</summary>
    /// <remarks>
    /// <b>Neither component ever replaces its own running image</b>, which is the whole safety
    /// property: a process that overwrote itself with a binary that cannot execute would leave
    /// nothing on the machine able to put the old one back.
    /// </remarks>
    /// <param name="component">The running component.</param>
    /// <returns>The component it may replace.</returns>
    public static AgentComponent Target(AgentComponent component) =>
        component == AgentComponent.Agent ? AgentComponent.Updater : AgentComponent.Agent;

    /// <summary>The installed path of a component.</summary>
    /// <param name="component">The component.</param>
    /// <returns>The absolute path.</returns>
    public string PathOf(AgentComponent component) =>
        Path.Combine(InstallDirectory, FileName(component));

    /// <summary>
    /// The path the outgoing binary is retained at, so the other component can put it back.
    /// </summary>
    /// <param name="component">The component.</param>
    /// <returns>The absolute path.</returns>
    public string PreviousPathOf(AgentComponent component) =>
        PathOf(component) + ".previous";
}
