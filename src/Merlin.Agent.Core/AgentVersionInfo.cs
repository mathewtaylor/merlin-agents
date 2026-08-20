using System.Reflection;

namespace Merlin.Agent.Core;

/// <summary>
/// The one version string both binaries report.
/// </summary>
/// <remarks>
/// <para>
/// <b>One constant, two components, one archive.</b> The agent and the updater ship in the same
/// package for the same version, so a machine can never be running halves that were never tested
/// together — and the whole update mechanism compares versions, so two constants free to drift
/// would mean a component that believed it was current while the other was not.
/// </para>
/// <para>
/// <b>It must equal the assembly version that <c>Directory.Build.props</c> sets</b>, because that
/// is what the release tag is cut from and what an operator pastes into
/// <c>Merlin:Endpoints:AgentVersion</c>. <c>AgentVersionInfoTests</c> fails the build if the two
/// disagree, which is cheaper than discovering it as a fleet that re-downloads the same archive
/// every night because the string it compares never matches.
/// </para>
/// </remarks>
public static class AgentVersionInfo
{
    /// <summary>The version both binaries report and compare against.</summary>
    public const string Current = "0.3.0";

    /// <summary>
    /// The version recorded in this assembly's metadata, for the test that pins the two together.
    /// </summary>
    /// <returns>The assembly version, without its build and revision fields.</returns>
    public static string AssemblyVersion()
    {
        Version? version = typeof(AgentVersionInfo).Assembly.GetName().Version;

        return version is null
            ? string.Empty
            : $"{version.Major}.{version.Minor}.{version.Build}";
    }

    /// <summary>
    /// Compares two version strings the way every caller in this codebase means it.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Equality, never order.</b> Ordering would need semver parsing, would be wrong for any
    /// scheme that is not semver, and would turn a deliberate rollback — the whole point of pinning
    /// a device back to yesterday's version — into a refusal to "downgrade". The server compares
    /// the same way, for the same reason.
    /// </para>
    /// <para>
    /// <b>A leading <c>v</c> is stripped.</b> The release tag is <c>v0.3.0</c> and the binaries
    /// report <c>0.3.0</c>, so an operator who pastes the tag into
    /// <c>Merlin:Endpoints:AgentVersion</c> would otherwise have every machine in the fleet decide
    /// it was permanently out of date and re-download the same archive nightly. The release notes
    /// now emit the bare version, and this is the belt to that braces: a comparison that fails
    /// over a prefix is not a comparison anybody wants to depend on.
    /// </para>
    /// </remarks>
    /// <param name="left">One version string, or null.</param>
    /// <param name="right">The other version string, or null.</param>
    /// <returns><c>true</c> when the two name the same version.</returns>
    public static bool Matches(string? left, string? right)
    {
        string first = Normalise(left);
        string second = Normalise(right);

        return first.Length > 0
            && second.Length > 0
            && string.Equals(first, second, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Trims a version string and drops a leading <c>v</c>.</summary>
    /// <param name="version">The version string, or null.</param>
    /// <returns>The normalised form, or an empty string.</returns>
    public static string Normalise(string? version)
    {
        string trimmed = version?.Trim() ?? string.Empty;

        return trimmed.Length > 1 && (trimmed[0] == 'v' || trimmed[0] == 'V')
            ? trimmed[1..]
            : trimmed;
    }
}
