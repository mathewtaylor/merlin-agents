using System.Runtime.InteropServices;

namespace Merlin.Agent.Core.Update;

/// <summary>
/// This machine's .NET runtime identifier, as Merlin spells it.
/// </summary>
/// <remarks>
/// <para>
/// <b>Computed from the OS and the process architecture, NOT read from
/// <see cref="RuntimeInformation.RuntimeIdentifier"/>.</b> That property returns whatever RID the
/// app was built or resolved for, which on a framework-dependent developer build can be a
/// version-qualified form such as <c>osx.15-arm64</c>. Merlin's package table is keyed by the five
/// portable identifiers below and matches them exactly, so an unrecognised spelling would silently
/// mean "no package configured for this platform" — a machine that polls forever and is never
/// offered anything, with nothing anywhere saying why.
/// </para>
/// <para>
/// The value is SIGNED into the update-check request, because it decides which architecture's
/// binary is advertised.
/// </para>
/// </remarks>
public static class AgentRuntimeIdentifier
{
    /// <summary>Windows on x64.</summary>
    public const string WindowsX64 = "win-x64";

    /// <summary>macOS on Apple silicon.</summary>
    public const string MacOsArm64 = "osx-arm64";

    /// <summary>macOS on Intel.</summary>
    public const string MacOsX64 = "osx-x64";

    /// <summary>Linux on x64.</summary>
    public const string LinuxX64 = "linux-x64";

    /// <summary>Linux on arm64.</summary>
    public const string LinuxArm64 = "linux-arm64";

    /// <summary>Every identifier Merlin can serve a package for.</summary>
    public static IReadOnlyList<string> All { get; } =
        [WindowsX64, MacOsArm64, MacOsX64, LinuxX64, LinuxArm64];

    /// <summary>
    /// This machine's identifier, or <c>null</c> on a platform or architecture nothing is built for.
    /// </summary>
    /// <remarks>
    /// <b>Null rather than a guess.</b> An unstated runtime identifier reaches Merlin as an
    /// unconfigured platform and is answered with silence, which is the correct outcome for a
    /// machine no package exists for — and strictly better than naming the nearest architecture and
    /// having it download a binary that cannot execute.
    /// </remarks>
    public static string? Current { get; } = Detect();

    private static string? Detect()
    {
        string? os = OperatingSystem.IsWindows() ? "win"
            : OperatingSystem.IsMacOS() ? "osx"
            : OperatingSystem.IsLinux() ? "linux"
            : null;

        if (os is null)
        {
            return null;
        }

        string? architecture = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            _ => null,
        };

        if (architecture is null)
        {
            return null;
        }

        string candidate = $"{os}-{architecture}";

        return All.Contains(candidate, StringComparer.Ordinal) ? candidate : null;
    }
}
