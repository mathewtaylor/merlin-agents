using System.Reflection;
using Merlin.Agent.Core;
using Merlin.Agent.Core.Crypto;
using Merlin.Agent.Core.State;
using Merlin.Agent.Core.Update;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// The guards that stand between a Merlin deployment and unattended code execution on a fleet.
/// </summary>
public sealed class PackageHostTests
{
    [Theory]
    [InlineData("https://github.com/mathewtaylor/merlin-agents/releases/download/v0.3.0/pkg.tar.gz")]
    [InlineData("https://objects.githubusercontent.com/whatever")]
    [InlineData("https://GITHUB.COM/mathewtaylor/merlin-agents/pkg.zip")]
    public void TheReleaseHostsAreAllowed(string endpoint) =>
        Assert.True(PackageHosts.IsAllowed(endpoint));

    [Theory]
    // A host the PRODUCT fetches from is not thereby a host a PACKAGE may come from. osquery's
    // distribution host was on this list and nothing ever reached it — the installer that downloads
    // osquery is a shell script, and the only consumer of the allowlist is the component swapper.
    // Every entry is a host a compromised Merlin can point the fleet's SYSTEM binary at.
    [InlineData("https://pkg.osquery.io/darwin/osquery.pkg")]
    // The bypass family the parsed-host comparison exists to refuse. A StartsWith would wave the
    // first two straight through.
    [InlineData("https://github.com.attacker.example/merlin/pkg.tar.gz")]
    [InlineData("https://attacker.example/github.com/pkg.tar.gz")]
    [InlineData("https://raw.githubusercontent.com/mathewtaylor/merlin-agents/pkg.tar.gz")]
    // An allowlisted host over plaintext is a host anybody on the path can impersonate, and the
    // hash pinning would then verify an attacker's archive against an attacker's digest.
    [InlineData("http://github.com/mathewtaylor/merlin-agents/pkg.tar.gz")]
    [InlineData("file:///tmp/pkg.tar.gz")]
    [InlineData("not an address")]
    [InlineData("")]
    [InlineData(null)]
    public void EverythingElseIsRefused(string? endpoint) =>
        Assert.False(PackageHosts.IsAllowed(endpoint));

    /// <summary>
    /// The allowlist may not be overridden — not by configuration, not by an environment variable,
    /// not by anything the server sends, and not by an argument.
    /// </summary>
    /// <remarks>
    /// <b>This is the whole point of a COMPILE-TIME list.</b> Merlin checks the configured address
    /// against its own allowlist too, but that catches a typo and nothing else: whoever can set the
    /// address can set the allowlist beside it. An override here would be the same hole reopened by
    /// a different route, and it would be added by somebody who needed a mirror for an afternoon.
    /// </remarks>
    [Fact]
    public void TheAllowlistCannotBeReplacedFromOutside()
    {
        Assert.DoesNotContain(
            typeof(PackageHosts).GetProperties(BindingFlags.Public | BindingFlags.Static),
            property => property.CanWrite);

        Assert.DoesNotContain(
            typeof(PackageHosts).GetFields(BindingFlags.Public | BindingFlags.Static),
            field => !field.IsInitOnly && !field.IsLiteral);

        // No method takes an allowlist, a host list or anything else that could stand in for one.
        Assert.DoesNotContain(
            typeof(PackageHosts)
                .GetMethods(BindingFlags.Public | BindingFlags.Static | BindingFlags.DeclaredOnly)
                .SelectMany(method => method.GetParameters()),
            parameter => parameter.ParameterType != typeof(string));
    }
}

/// <summary>
/// The machine-wide lock that keeps a swapper away from a component that is currently running.
/// </summary>
public sealed class MachineLockTests
{
    [Fact]
    public void OnlyOneHolderAtATime()
    {
        string directory = Path.Combine(
            Path.GetTempPath(), "merlin-lock-tests", Guid.NewGuid().ToString("N"));

        try
        {
            using MachineLock? first = MachineLock.TryAcquire(directory, TimeSpan.Zero, out _);

            Assert.NotNull(first);

            // A SECOND HOLDER IS REFUSED, and this assertion is only meaningful because the lock is
            // a file handle rather than a named mutex: a mutex is re-entrant for the thread that
            // owns it, so this would succeed and the test would prove nothing.
            using MachineLock? second = MachineLock.TryAcquire(directory, TimeSpan.Zero, out _);

            Assert.Null(second);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void ReleasingLetsTheNextRunIn()
    {
        string directory = Path.Combine(
            Path.GetTempPath(), "merlin-lock-tests", Guid.NewGuid().ToString("N"));

        try
        {
            MachineLock? first = MachineLock.TryAcquire(directory, TimeSpan.Zero, out _);
            Assert.NotNull(first);
            first.Dispose();

            using MachineLock? second = MachineLock.TryAcquire(directory, TimeSpan.Zero, out _);

            Assert.NotNull(second);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void TheLockLivesInTheSharedStateDirectory()
    {
        // Both binaries must take the SAME lock. A per-component lock file would serialise nothing.
        Assert.Equal(
            Path.Combine("/somewhere", "merlin-agent.lock"),
            MachineLock.PathIn("/somewhere"));
    }
}

/// <summary>
/// The update-check signature, which the server verifies byte for byte.
/// </summary>
/// <remarks>
/// <b>A frozen vector, and it looks trivial on purpose.</b> The server's
/// <c>Merlin.Endpoints.Application.Services.AgentSignature.CanonicalUpdate</c> must build the same
/// string from the same inputs, and the two implementations live in different repositories. If
/// either side is "tidied" — a separator changed, a field reordered, the context label dropped —
/// every updater in the field is refused, and this is what makes that a failing test rather than a
/// fleet that silently stops updating.
/// </remarks>
public sealed class UpdateSignatureTests
{
    [Fact]
    public void TheUpdateCanonicalStringMatchesTheServersConstruction()
    {
        string canonical = AgentSignature.CanonicalUpdate(
            "5f2a8c1e-0000-4000-8000-000000000001", "1786000000", "nonce", "win-x64");

        Assert.Equal(
            "update\n5f2a8c1e-0000-4000-8000-000000000001\n1786000000\nnonce\nwin-x64",
            canonical);
    }

    [Fact]
    public void ThereIsNoBodyHashBecauseThereIsNoBody()
    {
        // A GET. Five fields, and the last is the runtime identifier rather than a digest.
        Assert.Equal(
            5,
            AgentSignature.CanonicalUpdate("device", "1", "n", "linux-arm64").Split('\n').Length);
    }

    [Fact]
    public void AnAbsentRuntimeIdentifierIsAnEmptyFieldRatherThanAMissingOne()
    {
        // The server joins `runtimeIdentifier ?? string.Empty`, so a null here must still produce
        // five fields — otherwise a machine on an architecture nothing is built for signs a string
        // the server cannot reconstruct, and is refused instead of being told there is nothing for
        // it.
        Assert.Equal("update\ndevice\n1\nn\n", AgentSignature.CanonicalUpdate("device", "1", "n", null));
    }

    [Fact]
    public void AnUpdateSignatureCannotBePresentedAsAReportSignature()
    {
        // Domain separation. Without the leading context label these two would be the same string
        // for a device whose id happened to be the literal "update".
        Assert.NotEqual(
            AgentSignature.CanonicalUpdate("device", "1", "n", "win-x64"),
            AgentSignature.CanonicalReport("device", "1", "n", "win-x64"));
    }

    [Fact]
    public void TheRuntimeIdentifierHeaderIsNamedAsTheServerReadsIt() =>
        Assert.Equal("Merlin-Agent-Rid", AgentSignature.RuntimeIdentifierHeader);

    [Fact]
    public void ThisMachinesRuntimeIdentifierIsOneMerlinCanServe()
    {
        // Merlin's package table is keyed by these five exactly. An unrecognised spelling reaches
        // the server as an unconfigured platform and is answered with silence, forever, with
        // nothing anywhere saying why.
        Assert.Contains(AgentRuntimeIdentifier.Current, AgentRuntimeIdentifier.All);
    }
}

/// <summary>The version constant both binaries compare against.</summary>
public sealed class AgentVersionInfoTests
{
    [Fact]
    public void TheConstantMatchesTheAssemblyVersion() =>
        // Directory.Build.props sets the assembly version and the release tag is cut from it, so a
        // constant that drifted from it would have every machine in the fleet decide it was
        // permanently out of date and re-download the same archive nightly.
        Assert.Equal(AgentVersionInfo.Current, AgentVersionInfo.AssemblyVersion());

    [Theory]
    [InlineData("0.3.0", "0.3.0")]
    [InlineData("v0.3.0", "0.3.0")]
    [InlineData("0.3.0", "V0.3.0")]
    [InlineData(" 0.3.0 ", "0.3.0")]
    public void AVersionMatchesItselfWhicheverWayItIsSpelt(string left, string right) =>
        Assert.True(AgentVersionInfo.Matches(left, right));

    [Theory]
    [InlineData("0.3.0", "0.3.1")]
    [InlineData(null, "0.3.0")]
    [InlineData("0.3.0", null)]
    [InlineData("", "")]
    public void AnythingElseDoesNot(string? left, string? right) =>
        Assert.False(AgentVersionInfo.Matches(left, right));
}

/// <summary>The state file's new per-component bookkeeping.</summary>
public sealed class UpdateStateTests
{
    [Fact]
    public void TheBookkeepingSurvivesARoundTripThroughTheStateFile()
    {
        string directory = Path.Combine(
            Path.GetTempPath(), "merlin-state-tests", Guid.NewGuid().ToString("N"));

        try
        {
            AgentStateData written = new(
                "https://isms.example.com",
                Guid.NewGuid(),
                "DEV-001",
                DateTimeOffset.UtcNow,
                ClockOffsetSeconds: 12,
                LastReportAt: DateTimeOffset.UtcNow,
                LastReportJson: null,
                AgentVersionInstalled: "0.3.0",
                UpdaterVersionInstalled: "0.2.0",
                LastAgentRunAt: DateTimeOffset.UtcNow,
                LastUpdaterRunAt: DateTimeOffset.UtcNow,
                AgentSwappedAt: DateTimeOffset.UtcNow,
                UpdaterSwappedAt: null,
                PendingComponent: AgentComponent.Updater,
                PendingVersion: "0.3.0",
                PendingPackageEndpoint: UpdateTestKit.AllowedEndpoint,
                PendingSha256: new string('a', 64),
                LastUpdateOutcome: Contracts.AgentUpdateOutcome.Reverted,
                LastUpdateAt: DateTimeOffset.UtcNow,
                LastUpdateDetail: "reverted",
                LastRevertedVersion: "0.3.0");

            AgentState.WriteTo(directory, written);

            AgentStateData? read = AgentState.ReadFrom(directory);

            Assert.NotNull(read);
            Assert.Equal(AgentComponent.Updater, read.PendingComponent);
            Assert.Equal(Contracts.AgentUpdateOutcome.Reverted, read.LastUpdateOutcome);
            Assert.Equal("0.3.0", read.LastRevertedVersion);

            // The enum crosses the wire and the disk by NAME, matching Merlin's own persistence
            // rule — an added member must never re-point an existing machine's pending swap at the
            // wrong binary.
            Assert.Contains("\"Updater\"", File.ReadAllText(Path.Combine(directory, "state.json")), StringComparison.Ordinal);
            Assert.Contains("\"Reverted\"", File.ReadAllText(Path.Combine(directory, "state.json")), StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void AStateFileFromBeforeAutoUpdateStillReads()
    {
        string directory = Path.Combine(
            Path.GetTempPath(), "merlin-state-tests", Guid.NewGuid().ToString("N"));

        try
        {
            Directory.CreateDirectory(directory);

            // Exactly what a 0.2.0 machine has on disk. It must keep reporting after the swap that
            // installs 0.3.0 — a state file it cannot read would be a fleet that has to re-enrol.
            File.WriteAllText(
                Path.Combine(directory, "state.json"),
                """
                {
                  "serverUrl": "https://isms.example.com",
                  "deviceId": "5f2a8c1e-0000-4000-8000-000000000001",
                  "deviceCode": "DEV-001",
                  "enrolledAt": "2026-08-01T00:00:00+00:00",
                  "clockOffsetSeconds": 0,
                  "lastReportAt": "2026-08-19T00:00:00+00:00"
                }
                """);

            AgentStateData? read = AgentState.ReadFrom(directory);

            Assert.NotNull(read);
            Assert.Equal("DEV-001", read.DeviceCode);
            Assert.Null(read.UpdaterVersionInstalled);
            Assert.Null(read.PendingComponent);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public void NeitherComponentIsEverItsOwnTarget()
    {
        Assert.Equal(AgentComponent.Updater, InstallLayout.Target(AgentComponent.Agent));
        Assert.Equal(AgentComponent.Agent, InstallLayout.Target(AgentComponent.Updater));
    }
}
