using System.Collections.Frozen;

namespace Merlin.Agent.Core.Update;

/// <summary>
/// The COMPILE-TIME allowlist of hosts a package may be downloaded from.
/// </summary>
/// <remarks>
/// <para>
/// <b>This is the real supply-chain control, and it is deliberately not configurable.</b> Merlin
/// checks the configured address against its own allowlist too, but that catches a typo and nothing
/// else: whoever can set <c>PackageEndpoint</c> can set the allowlist beside it, so a server-side
/// list protects nothing against the threat it names. Baking the list into both binaries means
/// <b>server configuration alone cannot redirect a fleet</b> — a compromised or misconfigured
/// Merlin can name a version and an address, and an address outside this list is refused before a
/// single byte is fetched.
/// </para>
/// <para>
/// <b>There is no override — not by configuration, not by an environment variable, not by anything
/// the server sends, and not by a parameter on <see cref="IsAllowed"/>.</b> An override is the same
/// hole reopened by a different route, and it would be added by somebody who needed a mirror for an
/// afternoon. The cost is real and accepted: a self-hoster mirroring the binaries elsewhere needs a
/// rebuilt agent. <c>PackageHostTests</c> holds the shape shut by reflection.
/// </para>
/// <para>
/// <b>This is a partial stand-in for code signing and is weaker than it</b> — it pins the
/// distribution CHANNEL where a signature pins the PUBLISHER. Anyone who can publish a release on
/// these hosts is trusted by it.
/// </para>
/// <para>
/// <b>Hosts are compared by parsed <see cref="Uri.Host"/>, never by string prefix.</b>
/// <c>https://github.com.attacker.example/</c> is the family of bypass this refuses, and a
/// <c>StartsWith</c> would wave it through.
/// </para>
/// </remarks>
public static class PackageHosts
{
    /// <summary>
    /// The only hosts a package may come from.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The GitHub release hosts, because that is where CI publishes — <c>github.com</c> issues the
    /// download and redirects to whichever asset host is serving that day, so the redirect targets
    /// are needed here too or every download fails on the redirect.
    /// </para>
    /// <para>
    /// <b>GITHUB MOVED THE ASSET HOST AND KILLED EVERY FLEET'S AUTO-UPDATE.</b> A release download
    /// now redirects to <c>release-assets.githubusercontent.com</c>; <c>objects.githubusercontent.com</c>
    /// has left the chain entirely. Every installed agent refused every package with
    /// <see cref="Refusal"/> and stayed on the version it had. <b>This failure is unrecoverable
    /// from the fleet side</b> — the updater is the component that is broken, so the fix cannot be
    /// delivered by an update and every machine needs a manual reinstall. That asymmetry is why
    /// <c>objects.githubusercontent.com</c> is RETAINED rather than swept out under the
    /// buys-nothing rule below: it is the same publisher on the same trust boundary, so keeping a
    /// host GitHub may route back to costs nothing worth measuring, while removing one it turns
    /// out to still use costs a hand reinstall of every machine in every deployment.
    /// </para>
    /// <para>
    /// <b>A pinned distribution CHANNEL is a pin on infrastructure somebody else moves.</b> That
    /// is the standing cost of this control and it is accepted, not solved — code signing is what
    /// removes it. Until then, changing this list is a release, and an agent that cannot download
    /// cannot be told about the new one.
    /// </para>
    /// <para>
    /// <b>Nothing else, and a host is not added here because some other part of the product
    /// fetches from it.</b> <c>pkg.osquery.io</c> was on this list and no code path reached it: the
    /// only consumer of the allowlist is <c>ComponentSwapper</c>, and the installer that downloads
    /// osquery is a shell script that never sees it. Every entry here is a host a compromised or
    /// misconfigured Merlin can point the whole fleet's SYSTEM binary at, so an entry that buys
    /// nothing costs exactly what it is worth. It also made <c>docs/security.md</c> §5 and the
    /// release notes — both of which say a package comes only from the GitHub release hosts —
    /// untrue.
    /// </para>
    /// <para>
    /// <b>A <see cref="FrozenSet{T}"/> because the collection expression behind an
    /// <c>IReadOnlyList</c> is a plain array</b>, which anything in the process can cast back and
    /// write to — and this XML doc says the list cannot be moved. Code already running in this
    /// process has won regardless, but a control documented as unassailable should not have a
    /// one-line bypass sitting behind an interface. It also carries the comparer, so a caller
    /// cannot compare case-sensitively by forgetting to pass one.
    /// </para>
    /// </remarks>
    public static FrozenSet<string> Allowed { get; } = FrozenSet.Create(
        StringComparer.OrdinalIgnoreCase,
        "github.com",
        "objects.githubusercontent.com",
        "release-assets.githubusercontent.com");

    /// <summary>
    /// Whether an address may be downloaded from.
    /// </summary>
    /// <remarks>
    /// <b>Both halves are required.</b> The scheme must be <c>https</c> — an allowlisted host
    /// reached over plaintext is a host anybody on the path can impersonate, and the hash pinning
    /// would then be verifying an attacker's own archive against an attacker's own digest.
    /// </remarks>
    /// <param name="endpoint">The address, as advertised.</param>
    /// <returns><c>true</c> when the address is https and its host is on the list.</returns>
    public static bool IsAllowed(string? endpoint)
    {
        if (string.IsNullOrWhiteSpace(endpoint)
            || !Uri.TryCreate(endpoint, UriKind.Absolute, out Uri? parsed))
        {
            return false;
        }

        return parsed.Scheme == Uri.UriSchemeHttps
            && Allowed.Contains(parsed.Host);
    }

    /// <summary>A sentence naming why an address was refused, for the console and the log.</summary>
    /// <param name="endpoint">The refused address.</param>
    /// <returns>The explanation.</returns>
    public static string Refusal(string? endpoint) =>
        $"'{endpoint}' is not an https address on this agent's built-in host allowlist "
        + $"({string.Join(", ", Allowed)}). Nothing was downloaded.";
}
