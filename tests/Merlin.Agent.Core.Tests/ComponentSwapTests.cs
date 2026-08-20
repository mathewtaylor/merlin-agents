using System.Net;
using Merlin.Agent.Core.Contracts;
using Merlin.Agent.Core.Update;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// Tests for the shared component-swap routine.
/// </summary>
/// <remarks>
/// <b>Every one of these is a case where the machine must end up on the binary it already had.</b>
/// The routine replaces a SYSTEM binary unattended, on a machine nobody is watching, so the
/// interesting assertions are all negative: the running component is untouched, the previous one is
/// retained, and the failure is reported rather than swallowed.
/// </remarks>
public sealed class ComponentSwapTests
{
    [Fact]
    public async Task ASuccessfulSwapReplacesTheTargetAndRetainsThePrevious()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");
        using HttpClient http = UpdateTestKit.Serving(archive);

        ComponentSwapper swapper = new(
            AgentComponent.Agent,
            kit.Layout, http, UpdateTestKit.ProbeReporting("0.9.9"), _ => { });

        SwapResult result = await swapper.SwapAsync(
            AgentComponent.Updater,
            "0.9.9",
            UpdateTestKit.AllowedEndpoint,
            UpdateTestKit.Digest(archive));

        Assert.Equal(AgentUpdateOutcome.Succeeded, result.Outcome);
        Assert.Equal("0.9.9", result.InstalledVersion);
        Assert.Equal("new updater", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Updater)));
        Assert.Equal("old updater", File.ReadAllText(kit.Layout.PreviousPathOf(AgentComponent.Updater)));

        // The component that was NOT named is never touched — this is the running image of whoever
        // called, and overwriting it is the single point of failure the design exists to remove.
        Assert.False(File.Exists(kit.Layout.PathOf(AgentComponent.Agent)));
    }

    [Fact]
    public async Task AZipArchiveWorksTooBecauseWindowsShipsOne()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        byte[] archive = UpdateTestKit.BuildZipArchive("new agent", "new updater");
        using HttpClient http = UpdateTestKit.Serving(archive);

        ComponentSwapper swapper = new(
            AgentComponent.Agent,
            kit.Layout, http, UpdateTestKit.ProbeReporting("0.9.9"), _ => { });

        SwapResult result = await swapper.SwapAsync(
            AgentComponent.Updater,
            "0.9.9",
            UpdateTestKit.AllowedEndpoint,
            UpdateTestKit.Digest(archive));

        Assert.Equal(AgentUpdateOutcome.Succeeded, result.Outcome);
        Assert.Equal("new updater", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Updater)));
    }

    [Fact]
    public async Task AHashMismatchInstallsNothing()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");
        using HttpClient http = UpdateTestKit.Serving(archive);

        ComponentSwapper swapper = new(
            AgentComponent.Agent,
            kit.Layout, http, UpdateTestKit.ProbeReporting("0.9.9"), _ => { });

        SwapResult result = await swapper.SwapAsync(
            AgentComponent.Updater,
            "0.9.9",
            UpdateTestKit.AllowedEndpoint,
            new string('a', 64));

        Assert.Equal(AgentUpdateOutcome.Failed, result.Outcome);
        Assert.Contains("Hash mismatch", result.Detail, StringComparison.Ordinal);
        Assert.Equal("old updater", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Updater)));
        Assert.False(File.Exists(kit.Layout.PreviousPathOf(AgentComponent.Updater)));
    }

    [Fact]
    public async Task AnAddressOffTheAllowlistIsRefusedBeforeAnythingIsFetched()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");
        using HttpClient http = UpdateTestKit.Serving(archive);

        ComponentSwapper swapper = new(
            AgentComponent.Agent,
            kit.Layout, http, UpdateTestKit.ProbeReporting("0.9.9"), _ => { });

        // The hash is CORRECT. The point is that a valid archive from an unlisted host is refused
        // anyway — a compromised or misconfigured Merlin can name an address, and this is the check
        // that means naming one achieves nothing.
        SwapResult result = await swapper.SwapAsync(
            AgentComponent.Updater,
            "0.9.9",
            "https://github.com.attacker.example/merlin/pkg.tar.gz",
            UpdateTestKit.Digest(archive));

        Assert.Equal(AgentUpdateOutcome.Failed, result.Outcome);
        Assert.Contains("host allowlist", result.Detail, StringComparison.Ordinal);
        Assert.Equal("old updater", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Updater)));
    }

    [Fact]
    public async Task AStagedBinaryThatWillNotExecuteLeavesTheRunningOneInPlace()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "quarantined");
        using HttpClient http = UpdateTestKit.Serving(archive);

        ComponentSwapper swapper = new(
            AgentComponent.Agent,
            kit.Layout, http, UpdateTestKit.ProbeThatWillNotRun(), _ => { });

        SwapResult result = await swapper.SwapAsync(
            AgentComponent.Updater,
            "0.9.9",
            UpdateTestKit.AllowedEndpoint,
            UpdateTestKit.Digest(archive));

        // Download fine, hash fine, extraction fine — and still nothing is replaced, because a
        // digest proves the bytes arrived and says nothing about whether they run here.
        Assert.Equal(AgentUpdateOutcome.Failed, result.Outcome);
        Assert.Contains("would not execute", result.Detail, StringComparison.Ordinal);
        Assert.Equal("old updater", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Updater)));
        Assert.False(File.Exists(kit.Layout.PreviousPathOf(AgentComponent.Updater)));
    }

    /// <summary>
    /// A staged binary that runs but names no version is not installed.
    /// </summary>
    /// <remarks>
    /// <b>The recorded version used to fall back to the ADVERTISED string, which is the operator's
    /// own input.</b> That is the field the never-install-this-again rule compares against, so a
    /// binary that identified itself as nothing was recorded as whatever Merlin had been told to
    /// expect — and the mismatch warning could never fire, because the value it compares had just
    /// been copied from the thing it is compared to. Execute-before-commit asks two questions, and
    /// the second one is what is it.
    /// </remarks>
    [Fact]
    public async Task AStagedBinaryThatNamesNoVersionIsNotInstalled()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "silent");
        using HttpClient http = UpdateTestKit.Serving(archive);

        // It RUNS — this is not the would-not-execute case — and says nothing.
        ComponentSwapper swapper = new(
            AgentComponent.Agent,
            kit.Layout, http, UpdateTestKit.ProbeByPath(_ => "   "), _ => { });

        SwapResult result = await swapper.SwapAsync(
            AgentComponent.Updater,
            "0.9.9",
            UpdateTestKit.AllowedEndpoint,
            UpdateTestKit.Digest(archive));

        Assert.Equal(AgentUpdateOutcome.Failed, result.Outcome);
        Assert.Contains("printed no version", result.Detail, StringComparison.Ordinal);

        // The working binary is untouched, and nothing was recorded under a borrowed version.
        Assert.Equal("old updater", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Updater)));
        Assert.Null(result.InstalledVersion);
    }

    [Fact]
    public async Task AnArchiveWithoutTheNamedComponentInstallsNothing()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        // An archive built before auto-update shipped: the agent alone. It downloads and verifies
        // perfectly, and there is still nothing in it to install.
        byte[] archive = UpdateTestKit.BuildAgentOnlyArchive("new agent");

        using HttpClient http = UpdateTestKit.Serving(archive);

        ComponentSwapper swapper = new(
            AgentComponent.Agent,
            kit.Layout, http, UpdateTestKit.ProbeReporting("0.9.9"), _ => { });

        SwapResult result = await swapper.SwapAsync(
            AgentComponent.Updater,
            "0.9.9",
            UpdateTestKit.AllowedEndpoint,
            UpdateTestKit.Digest(archive));

        Assert.Equal(AgentUpdateOutcome.Failed, result.Outcome);
        Assert.Contains("carries no", result.Detail, StringComparison.Ordinal);
        Assert.Equal("old updater", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Updater)));
    }

    [Fact]
    public async Task ADownloadThatFailsInstallsNothing()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        using HttpClient http = UpdateTestKit.Refusing(HttpStatusCode.ServiceUnavailable);

        ComponentSwapper swapper = new(
            AgentComponent.Agent,
            kit.Layout, http, UpdateTestKit.ProbeReporting("0.9.9"), _ => { });

        SwapResult result = await swapper.SwapAsync(
            AgentComponent.Updater,
            "0.9.9",
            UpdateTestKit.AllowedEndpoint,
            new string('a', 64));

        Assert.Equal(AgentUpdateOutcome.Failed, result.Outcome);
        Assert.Equal("old updater", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Updater)));
    }

    [Fact]
    public async Task NeverBothComponentsInOneRun()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "old agent");
        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");
        using HttpClient http = UpdateTestKit.Serving(archive);

        ComponentSwapper swapper = new(
            AgentComponent.Agent,
            kit.Layout, http, UpdateTestKit.ProbeReporting("0.9.9"), _ => { });

        SwapResult first = await swapper.SwapAsync(
            AgentComponent.Updater,
            "0.9.9",
            UpdateTestKit.AllowedEndpoint,
            UpdateTestKit.Digest(archive));

        SwapResult second = await swapper.SwapAsync(
            AgentComponent.Agent,
            "0.9.9",
            UpdateTestKit.AllowedEndpoint,
            UpdateTestKit.Digest(archive));

        Assert.Equal(AgentUpdateOutcome.Succeeded, first.Outcome);

        // Refused, and refused for the STRONGER of the two reasons. This swapper is the agent, so
        // the second call asks it to overwrite its own running image — which it now knows about and
        // declines, rather than relying on the one-move-per-run counter to catch it by accident. A
        // big-bang swap of both would reintroduce the single point of failure the two-binary design
        // exists to remove.
        Assert.Equal(AgentUpdateOutcome.Failed, second.Outcome);
        Assert.Contains("own running image", second.Detail, StringComparison.Ordinal);
        Assert.Equal("old agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));
        Assert.Equal("new updater", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Updater)));
    }

    [Fact]
    public void RestorePutsThePreviousBinaryBackAndKeepsTheBrokenOne()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "broken agent");
        File.WriteAllText(kit.Layout.PreviousPathOf(AgentComponent.Agent), "working agent");

        using HttpClient http = UpdateTestKit.Serving([]);

        ComponentSwapper swapper = new(
            AgentComponent.Updater,
            kit.Layout, http, UpdateTestKit.ProbeReporting("0.2.0"), _ => { });

        SwapResult result = swapper.Restore(AgentComponent.Agent);

        Assert.Equal(AgentUpdateOutcome.Reverted, result.Outcome);
        Assert.Equal("0.2.0", result.InstalledVersion);
        Assert.Equal("working agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));

        // The failed binary is kept, not deleted. Somebody has to be able to work out what went
        // wrong on the one machine that hit it.
        Assert.Equal(
            "broken agent",
            File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent) + ".failed"));
    }

    [Fact]
    public void RestoreWithNothingRetainedChangesNothing()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "the only agent");

        using HttpClient http = UpdateTestKit.Serving([]);

        ComponentSwapper swapper = new(
            AgentComponent.Updater,
            kit.Layout, http, UpdateTestKit.ProbeReporting("0.2.0"), _ => { });

        SwapResult result = swapper.Restore(AgentComponent.Agent);

        Assert.Null(result.Outcome);
        Assert.Equal("the only agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));
    }

    [Fact]
    public async Task ARestoreAlsoCountsAsThisRunsOneMove()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Agent, "broken agent");
        kit.PlaceComponent(AgentComponent.Updater, "old updater");
        File.WriteAllText(kit.Layout.PreviousPathOf(AgentComponent.Agent), "working agent");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");
        using HttpClient http = UpdateTestKit.Serving(archive);

        ComponentSwapper swapper = new(
            AgentComponent.Updater,
            kit.Layout, http, UpdateTestKit.ProbeReporting("0.9.9"), _ => { });

        swapper.Restore(AgentComponent.Agent);

        // The same component again, which is the only shape this can take in production: a swapper
        // may only ever touch the one component that is not itself.
        SwapResult afterwards = await swapper.SwapAsync(
            AgentComponent.Agent,
            "0.9.9",
            UpdateTestKit.AllowedEndpoint,
            UpdateTestKit.Digest(archive));

        Assert.Null(afterwards.Outcome);
        Assert.Equal("working agent", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Agent)));
    }

    /// <summary>
    /// Drives the REAL <see cref="BinaryProbe"/> end to end, so the seam every other test uses is
    /// not the only thing ever exercised.
    /// </summary>
    /// <remarks>
    /// Unix only, and deliberately: a shell script with a shebang is a genuine executable there,
    /// where Windows would need a compiled <c>.exe</c> a unit test cannot manufacture for four
    /// architectures. The CI core job runs on Linux, so this runs on every push.
    /// </remarks>
    [Fact]
    public async Task TheRealProbeExecutesAStagedBinaryBeforeAnythingIsCommitted()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        byte[] archive = UpdateTestKit.BuildArchive(
            "#!/bin/sh\necho 9.9.9\n",
            "#!/bin/sh\necho 9.9.9\n");

        using HttpClient http = UpdateTestKit.Serving(archive);

        ComponentSwapper swapper = new(
            AgentComponent.Agent, kit.Layout, http, BinaryProbe.Default, _ => { });

        SwapResult result = await swapper.SwapAsync(
            AgentComponent.Updater,
            "9.9.9",
            UpdateTestKit.AllowedEndpoint,
            UpdateTestKit.Digest(archive));

        Assert.Equal(AgentUpdateOutcome.Succeeded, result.Outcome);
        Assert.Equal("9.9.9", result.InstalledVersion);
    }

    [Fact]
    public async Task TheRealProbeRefusesAStagedBinaryThatCannotRun()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        // Not a program. This is what a corrupted download, a wrong-architecture binary or a
        // quarantined file looks like at the moment of execution.
        byte[] archive = UpdateTestKit.BuildArchive("nope", "not a program at all");

        using HttpClient http = UpdateTestKit.Serving(archive);

        ComponentSwapper swapper = new(
            AgentComponent.Agent, kit.Layout, http, BinaryProbe.Default, _ => { });

        SwapResult result = await swapper.SwapAsync(
            AgentComponent.Updater,
            "9.9.9",
            UpdateTestKit.AllowedEndpoint,
            UpdateTestKit.Digest(archive));

        Assert.Equal(AgentUpdateOutcome.Failed, result.Outcome);
        Assert.Equal("old updater", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Updater)));
    }

    /// <summary>
    /// A binary that floods stderr and says nothing on stdout does not wedge the probe.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Reading one pipe to the end and then the other is the classic deadlock, and the probe's
    /// timeout is no protection from it.</b> The child blocks writing to a full stderr buffer, so
    /// it never exits and never closes stdout; the parent blocks in <c>ReadToEnd</c> and therefore
    /// never REACHES <c>WaitForExit</c>. The buffer is 4 KB on Windows and 64 KB on Unix, which a
    /// quarantine notice or a loader dump clears without trying.
    /// </para>
    /// <para>
    /// <b>The consequence is the one thing the two-binary design exists to prevent.</b> The wedged
    /// process is holding the machine lock, so the agent can never take it again and the machine
    /// stops reporting — permanently, and silently, because silence is indistinguishable from a
    /// machine that was never enrolled. This test therefore runs on every platform: the failure is
    /// likelier on Windows, where the buffer is smallest.
    /// </para>
    /// </remarks>
    [Fact]
    public void ANoisyBinaryDoesNotWedgeTheProbe()
    {
        using UpdateTestKit kit = new();

        string noise = Path.Combine(kit.Layout.StateDirectory, "noise.txt");

        Directory.CreateDirectory(kit.Layout.StateDirectory);
        File.WriteAllText(noise, string.Concat(Enumerable.Repeat("boom boom boom boom\n", 40_000)));

        // A shell rather than a staged binary, because the point is what the PROBE does with a
        // chatty child and a unit test cannot manufacture a NativeAOT executable for four
        // architectures.
        (string command, string arguments) = OperatingSystem.IsWindows()
            ? ("cmd.exe", $"/c type \"{noise}\" 1>&2")
            : ("/bin/sh", $"-c \"cat '{noise}' >&2\"");

        ProbeResult? result = null;

        Thread worker = new(() =>
            result = BinaryProbe.Default.Execute(command, arguments, TimeSpan.FromSeconds(10)))
        {
            IsBackground = true,
        };

        worker.Start();

        Assert.True(
            worker.Join(TimeSpan.FromSeconds(60)),
            "BinaryProbe.Execute never returned: the probe deadlocked on a full stderr pipe.");

        // It exited zero, so the probe reports it ran. What it printed to stderr is not the
        // verdict; that a chatty binary cannot hang the machine is.

        // On Windows the secondary assertion is deliberately skipped: the shell invocation is not
        // verifiable from this developer's machine, and a quoting difference must not turn a
        // regression guard into a red build for the wrong reason. The property under test — that
        // the call RETURNS — is asserted on every platform and is what a deadlock breaks. Windows
        // is where it matters most, since its pipe buffer is the smallest.

        if (!OperatingSystem.IsWindows())
        {
            Assert.True(result!.Ran);
        }
    }
}
