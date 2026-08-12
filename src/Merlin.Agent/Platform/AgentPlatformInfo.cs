using Merlin.Agent.Core.Contracts;

namespace Merlin.Agent.Platform;

/// <summary>Which operating system this process is running on.</summary>
public enum AgentOs
{
    /// <summary>An operating system this agent has no collector for.</summary>
    Unsupported,

    /// <summary>Microsoft Windows.</summary>
    Windows,

    /// <summary>Apple macOS.</summary>
    MacOs,

    /// <summary>Linux.</summary>
    Linux,
}

/// <summary>
/// Resolves the host platform once, and is the only place the agent asks what it is running on.
/// </summary>
/// <remarks>
/// <para>
/// <b>One decision point, consulted by five subsystems</b> — the state directory, the key store, the
/// osquery search path, the query pack and the normaliser. Scattering
/// <c>OperatingSystem.IsMacOS()</c> across all five is how a machine ends up reading a macOS query
/// pack while writing to a Linux state path, and the resulting report would be internally
/// inconsistent in a way no single call site looks wrong.
/// </para>
/// <para>
/// <b>An unrecognised platform is <see cref="AgentOs.Unsupported"/>, and the agent refuses to run
/// rather than guessing.</b> FreeBSD would satisfy neither <c>IsLinux()</c> nor <c>IsMacOS()</c>,
/// and falling through to the Linux collector there would produce readings taken from files that do
/// not mean what the collector thinks they mean — a report full of confident, wrong observations,
/// which is strictly worse than no report.
/// </para>
/// </remarks>
public static class AgentPlatformInfo
{
    /// <summary>The host platform.</summary>
    public static AgentOs Current { get; } = Detect();

    /// <summary>The wire value for the host platform.</summary>
    public static AgentPlatform Wire => Current switch
    {
        AgentOs.Windows => AgentPlatform.Windows,
        AgentOs.MacOs => AgentPlatform.MacOs,
        AgentOs.Linux => AgentPlatform.Linux,
        _ => AgentPlatform.Unknown,
    };

    /// <summary>The query-pack file name for the host platform.</summary>
    public static string QueryPackName => Current switch
    {
        AgentOs.Windows => "windows.json",
        AgentOs.MacOs => "macos.json",
        _ => "linux.json",
    };

    /// <summary>A human-readable platform name, for console output.</summary>
    public static string DisplayName => Current switch
    {
        AgentOs.Windows => "Windows",
        AgentOs.MacOs => "macOS",
        AgentOs.Linux => "Linux",
        _ => "an unsupported operating system",
    };

    private static AgentOs Detect()
    {
        if (OperatingSystem.IsWindows())
        {
            return AgentOs.Windows;
        }

        if (OperatingSystem.IsMacOS())
        {
            return AgentOs.MacOs;
        }

        return OperatingSystem.IsLinux() ? AgentOs.Linux : AgentOs.Unsupported;
    }
}
