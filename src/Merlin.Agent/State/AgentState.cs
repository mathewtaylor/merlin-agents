using System.Text.Json;
using System.Text.Json.Serialization;
using Merlin.Agent.Platform;

namespace Merlin.Agent.State;

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
public sealed record AgentStateData(
    string ServerUrl,
    Guid DeviceId,
    string DeviceCode,
    DateTimeOffset EnrolledAt,
    long ClockOffsetSeconds,
    DateTimeOffset? LastReportAt,
    string? LastReportJson);

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
    public static AgentStateData? Read()
    {
        if (!File.Exists(StatePath))
        {
            return null;
        }

        try
        {
            return JsonSerializer.Deserialize(File.ReadAllText(StatePath), AgentStateJsonContext.Default.AgentStateData);
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
        ArgumentNullException.ThrowIfNull(state);

        EnsureDirectory();

        // Written to a temporary file and moved into place, so an interrupted write cannot leave a
        // half-written state file behind.
        string temporary = StatePath + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(state, AgentStateJsonContext.Default.AgentStateData));
        File.Move(temporary, StatePath, overwrite: true);
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
    public static void EnsureDirectory()
    {
        if (OperatingSystem.IsWindows())
        {
            System.IO.Directory.CreateDirectory(Directory);
            return;
        }

        System.IO.Directory.CreateDirectory(
            Directory,
            UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
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
