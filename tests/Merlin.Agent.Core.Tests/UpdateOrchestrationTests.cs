using System.Net;
using System.Text;
using Merlin.Agent.Core;
using Merlin.Agent.Core.Contracts;
using Merlin.Agent.Core.Crypto;
using Merlin.Agent.Core.Platform;
using Merlin.Agent.Core.State;
using Merlin.Agent.Core.Update;
using System.Security.Cryptography;
using Xunit;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// The rules that hold the two components together — and the ones that were found broken in the
/// layer BELOW the state machine, where a decision-table test cannot reach.
/// </summary>
public sealed class UpdateOrchestrationTests
{
    /// <summary>
    /// A retained fallback is always a binary that has actually run on this machine.
    /// </summary>
    /// <remarks>
    /// <b>"There is no previous" is a state recovery handles; "there is a previous that does not
    /// work" is one it cannot.</b> It would put that binary back and call the machine recovered.
    /// The case is reachable: a component released from an unrecoverable swap is one that never
    /// ran, and the next swap would otherwise quietly promote it to the fallback.
    /// </remarks>
    [Fact]
    public async Task ASwapNeverRetainsABinaryThatWillNotRun()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "an updater that never ran");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");
        using HttpClient http = UpdateTestKit.Serving(archive);

        // The INSTALLED binary will not execute; the staged one will.
        BinaryProbe probe = UpdateTestKit.ProbeByPath(path =>
            path.StartsWith(kit.Layout.StagingDirectory, StringComparison.Ordinal) ? "9.9.9" : null);

        ComponentSwapper swapper = new(AgentComponent.Agent, kit.Layout, http, probe, _ => { });

        SwapResult result = await swapper.SwapAsync(
            AgentComponent.Updater,
            "9.9.9",
            UpdateTestKit.AllowedEndpoint,
            UpdateTestKit.Digest(archive));

        Assert.Equal(AgentUpdateOutcome.Succeeded, result.Outcome);
        Assert.Equal("new updater", File.ReadAllText(kit.Layout.PathOf(AgentComponent.Updater)));

        // Not promoted to the fallback: a revert must never restore a binary that never ran.
        Assert.False(File.Exists(kit.Layout.PreviousPathOf(AgentComponent.Updater)));
    }

    /// <summary>
    /// An unprovable outgoing binary is not promoted — and the fallback already held is not lost.
    /// </summary>
    /// <remarks>
    /// <b>The probe cannot tell "ran and refused" from "could not be asked".</b> A
    /// process-creation failure and a thirty-second timeout under an antivirus scan both come back
    /// as no version, so deleting the outgoing binary on that evidence can destroy the only working
    /// copy on the machine — a worse failure than the one the rule exists to prevent. Nothing is
    /// ever deleted: whatever is already retained stays exactly where it is.
    /// </remarks>
    [Fact]
    public async Task AnUnprovableSwapLeavesTheExistingFallbackAlone()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "an updater that cannot be asked");
        File.WriteAllText(
            kit.Layout.PreviousPathOf(AgentComponent.Updater), "the last updater that ran");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");
        using HttpClient http = UpdateTestKit.Serving(archive);

        BinaryProbe probe = UpdateTestKit.ProbeByPath(path =>
            path.StartsWith(kit.Layout.StagingDirectory, StringComparison.Ordinal) ? "9.9.9" : null);

        ComponentSwapper swapper = new(AgentComponent.Agent, kit.Layout, http, probe, _ => { });

        SwapResult result = await swapper.SwapAsync(
            AgentComponent.Updater,
            "9.9.9",
            UpdateTestKit.AllowedEndpoint,
            UpdateTestKit.Digest(archive));

        Assert.Equal(AgentUpdateOutcome.Succeeded, result.Outcome);

        // THE ASSERTION THIS EXISTS FOR: the binary that did run is still the fallback.
        Assert.Equal(
            "the last updater that ran",
            File.ReadAllText(kit.Layout.PreviousPathOf(AgentComponent.Updater)));
    }

    /// <summary>
    /// A swap prunes staging it did not clean up last time.
    /// </summary>
    /// <remarks>
    /// A reboot or a kill mid-download leaves a partial package of up to 256 MB behind, and since
    /// staging sits beside the binaries that is litter in <c>%ProgramFiles%</c> or <c>/opt</c> that
    /// nothing else would ever collect.
    /// </remarks>
    [Fact]
    public async Task ASwapPrunesStagingLeftBehindByAnEarlierRun()
    {
        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        string orphan = Path.Combine(kit.Layout.StagingDirectory, "abandoned");

        Directory.CreateDirectory(orphan);
        File.WriteAllText(Path.Combine(orphan, "package"), "half a download");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");
        using HttpClient http = UpdateTestKit.Serving(archive);

        ComponentSwapper swapper = new(
            AgentComponent.Agent, kit.Layout, http, UpdateTestKit.ProbeReporting("9.9.9"), _ => { });

        await swapper.SwapAsync(
            AgentComponent.Updater,
            "9.9.9",
            UpdateTestKit.AllowedEndpoint,
            UpdateTestKit.Digest(archive));

        Assert.False(Directory.Exists(orphan));
    }

    /// <summary>
    /// An install directory that cannot be written to is a reported outcome, never a throw.
    /// </summary>
    /// <remarks>
    /// <b>"The outcome is REPORTED, never inferred" has to hold for the boring failures too.</b>
    /// Creating the staging tree sat outside the try that turns failures into a result, so an
    /// unwritable install directory threw out of the swap: no outcome recorded, nothing reaching
    /// Merlin, and the updater exiting non-zero on every scheduled run for ever.
    /// </remarks>
    [Fact]
    public async Task AnUnwritableInstallDirectoryIsReportedRatherThanThrown()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        using UpdateTestKit kit = new();

        kit.PlaceComponent(AgentComponent.Updater, "old updater");

        byte[] archive = UpdateTestKit.BuildArchive("new agent", "new updater");
        using HttpClient http = UpdateTestKit.Serving(archive);

        ComponentSwapper swapper = new(
            AgentComponent.Agent, kit.Layout, http, UpdateTestKit.ProbeReporting("9.9.9"), _ => { });

        UnixFileMode original = File.GetUnixFileMode(kit.Layout.InstallDirectory);

        File.SetUnixFileMode(
            kit.Layout.InstallDirectory, UnixFileMode.UserRead | UnixFileMode.UserExecute);

        try
        {
            SwapResult result = await swapper.SwapAsync(
                AgentComponent.Updater,
                "9.9.9",
                UpdateTestKit.AllowedEndpoint,
                UpdateTestKit.Digest(archive));

            Assert.Equal(AgentUpdateOutcome.Failed, result.Outcome);
        }
        finally
        {
            File.SetUnixFileMode(kit.Layout.InstallDirectory, original);
        }
    }

    /// <summary>
    /// A lock that cannot be taken for want of RIGHTS is not reported as contention.
    /// </summary>
    /// <remarks>
    /// The two look identical to a caller unless the lock says which it was — and an agent started
    /// without root or SYSTEM then waited out the whole timeout, printed "the updater is running"
    /// and exited ZERO, collecting nothing, on every scheduled fire.
    /// </remarks>
    [Fact]
    public void ALockRefusedForWantOfRightsSaysSo()
    {
        if (OperatingSystem.IsWindows() || Environment.UserName == "root")
        {
            return;
        }

        string root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));

        // The state directory does not exist and its parent cannot be written to — which is what a
        // non-root agent meets on a machine installed by root, and the case where the directory
        // cannot even be CREATED, let alone locked.
        string directory = Path.Combine(root, "state");

        Directory.CreateDirectory(root);
        File.SetUnixFileMode(root, UnixFileMode.UserRead | UnixFileMode.UserExecute);

        try
        {
            using MachineLock? held = MachineLock.TryAcquire(
                directory, TimeSpan.Zero, out bool accessDenied);

            Assert.Null(held);
            Assert.True(accessDenied, "A permissions failure was reported as contention.");
        }
        finally
        {
            File.SetUnixFileMode(
                root,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            Directory.Delete(root, recursive: true);
        }
    }

    /// <summary>
    /// A runner and a swapper built for different components refuse to be paired.
    /// </summary>
    /// <remarks>
    /// <b>A mismatch is not a partial failure but a silent total one.</b> Every swap would come
    /// back as a self-swap refusal, no update would land anywhere in the fleet, and no test could
    /// see it, because each half is individually correct. Two constructor arguments in two files
    /// have to agree and nothing else makes them.
    /// </remarks>
    [Fact]
    public void ARunnerAndASwapperMustBeTheSameComponent()
    {
        using UpdateTestKit kit = new();
        using HttpClient http = UpdateTestKit.Serving([]);

        BinaryProbe probe = UpdateTestKit.ProbeReporting("0.3.0");
        ComponentSwapper swapper = new(AgentComponent.Agent, kit.Layout, http, probe, _ => { });

        ArgumentException thrown = Assert.Throws<ArgumentException>(() => new UpdateRunner(
            AgentComponent.Updater, kit.Layout, swapper, probe, UpdateWindows.Default, _ => { },
            () => DateTimeOffset.UtcNow, _ => { }));

        Assert.Contains("same component", thrown.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// An advertisement missing its address or its digest is not an advertisement.
    /// </summary>
    /// <remarks>
    /// <b>Only the version used to be checked.</b> A 200 carrying a blank endpoint or digest came
    /// back as Advertised, and when the target already matched, the note of what the OTHER
    /// component still needs was overwritten with those blanks and cleared. Merlin goes quiet once
    /// the agent reports the desired version, so there is nothing left to re-learn the note from
    /// and the two components stay split across versions for good.
    /// </remarks>
    [Theory]
    [InlineData("""{"version":"0.4.0","packageEndpoint":"","sha256":"abc"}""")]
    [InlineData("""{"version":"0.4.0","packageEndpoint":"https://github.com/x.tar.gz","sha256":""}""")]
    [InlineData("""{"version":"","packageEndpoint":"https://github.com/x.tar.gz","sha256":"abc"}""")]
    [InlineData("not json at all")]
    public async Task AnIncompleteAdvertisementIsNotActedOn(string body)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using HttpClient http = new(new BodyHandler(HttpStatusCode.OK, body))
        {
            BaseAddress = new Uri("https://isms.example.com/"),
        };

        UpdateCheck answer = await CheckWith(http, key);

        Assert.Equal(UpdateCheckStatus.Refused, answer.Status);
        Assert.Null(answer.Advertisement);
    }

    /// <summary>
    /// <c>204</c> and <c>404</c> are ordinary answers, asserted against the client itself.
    /// </summary>
    /// <remarks>
    /// The decision table already covers what the runner does with them, but this is the only
    /// implementation of the frozen wire contract in this repository and it was untested.
    /// </remarks>
    [Theory]
    [InlineData(HttpStatusCode.NoContent, UpdateCheckStatus.NothingToDo)]
    [InlineData(HttpStatusCode.NotFound, UpdateCheckStatus.NotOffered)]
    [InlineData(HttpStatusCode.InternalServerError, UpdateCheckStatus.Refused)]
    public async Task TheClientReadsMerlinsOrdinaryAnswers(
        HttpStatusCode status,
        UpdateCheckStatus expected)
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using HttpClient http = new(new BodyHandler(status, string.Empty))
        {
            BaseAddress = new Uri("https://isms.example.com/"),
        };

        UpdateCheck answer = await CheckWith(http, key);

        Assert.Equal(expected, answer.Status);
    }

    /// <summary>
    /// A run whose output was not read to the end is not a successful run.
    /// </summary>
    /// <remarks>
    /// <b>"The command printed nothing" and "we gave up reading it" were the same value, and the
    /// difference is a security control's state.</b> The drain is bounded, so a grandchild holding
    /// the output pipe open leaves the text empty while the process itself exited zero. Every
    /// caller then reads that empty string as a definite answer: <c>LinuxFirewall</c> asks whether
    /// the output CONTAINS "Status: active", so an unread <c>ufw status</c> was reported to Merlin
    /// as a firewall that is OFF — a confident, wrong fact about a machine, which is the one thing
    /// the collection contract says never to produce. The rule belongs on the record rather than in
    /// each caller, because there are three of them and they were written months apart.
    /// </remarks>
    [Fact]
    public void ATruncatedReadIsNeverASuccessfulRun()
    {
        // Exited zero, read to the end, said nothing. That IS an observation of "nothing".
        Assert.True(
            new ProcessOutcome(true, true, 0, string.Empty, string.Empty, OutputComplete: true)
                .Succeeded);

        // Exited zero, and we never reached end-of-file. Indistinguishable from the line above by
        // its text alone, and it must NOT be reported as a reading.
        Assert.False(
            new ProcessOutcome(true, true, 0, string.Empty, string.Empty, OutputComplete: false)
                .Succeeded);

        // A complete read of a non-zero exit is still not a success, and neither is a process that
        // never exited — the flag narrows the rule, it does not replace it.
        Assert.False(
            new ProcessOutcome(true, true, 1, "text", string.Empty, OutputComplete: true).Succeeded);
        Assert.False(
            new ProcessOutcome(true, false, 0, "text", string.Empty, OutputComplete: true).Succeeded);
    }

    /// <summary>
    /// A grandchild holding the output pipe open produces an incomplete read, not an empty one.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The rule above is only worth having if <see cref="ProcessRunner"/> actually sets the
    /// flag</b>, and this is the shape that sets it: a shell that exits immediately after
    /// backgrounding a child which inherited its standard output. The process is gone, so
    /// <c>WaitForExit</c> returns at once and the run looks entirely healthy — but the pipe has no
    /// end-of-file until the grandchild lets go, which is exactly the case the bounded drain exists
    /// for and exactly the case that used to be reported as success.
    /// </para>
    /// <para>
    /// <b>Unix only, deliberately, on the precedent of the flooded-pipe test below.</b> Backgrounding
    /// a process that keeps one inherited handle and drops the other is a shell-specific
    /// incantation, and a quoting difference on Windows would turn a regression guard into a red
    /// build for the wrong reason. The rule itself is asserted on every platform by the test above.
    /// </para>
    /// </remarks>
    [Fact]
    public void AGrandchildHoldingTheOutputPipeYieldsAnIncompleteRead()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        // `sleep` inherits stdout — the pipe — and sends its own stderr to /dev/null, so standard
        // error reaches end-of-file at once and only the OUTPUT drain times out. The shell itself
        // exits the moment it has echoed.
        ProcessOutcome outcome = ProcessRunner.Run(
            "/bin/sh",
            // Fifteen seconds against a five-second drain grace. The test still finishes in five —
            // it ends when the drain gives up, not when the sleep does — so the margin is free, and
            // a loaded machine cannot stall its way into the pipe closing early and passing for the
            // wrong reason.
            ["-c", "sleep 15 2>/dev/null & echo hello"],
            TimeSpan.FromSeconds(30));

        // It started and exited cleanly. Everything the old rule looked at says "success".
        Assert.True(outcome.Started);
        Assert.True(outcome.Exited);
        Assert.Equal(0, outcome.ExitCode);

        // And yet the output was never read to the end, so it is not a reading.
        Assert.False(outcome.OutputComplete);
        Assert.False(outcome.Succeeded);
    }

    /// <summary>
    /// A child that floods one pipe cannot wedge the shared process runner.
    /// </summary>
    /// <remarks>
    /// <b>The osquery runner and the command runner both had this bug after it was fixed in the
    /// probe</b> — one reading stdout to the end before stderr, the other redirecting stderr and
    /// never reading it at all. They now share one implementation, so this pins all three. A wedge
    /// costs more than a dead run: a collection holds the machine-wide lock, so the updater could
    /// never take it and never put a broken agent back.
    /// </remarks>
    [Fact]
    public void TheSharedProcessRunnerSurvivesAFloodedPipe()
    {
        using UpdateTestKit kit = new();

        string noise = Path.Combine(kit.Layout.StateDirectory, "noise.txt");

        Directory.CreateDirectory(kit.Layout.StateDirectory);
        File.WriteAllText(noise, string.Concat(Enumerable.Repeat("boom boom boom boom\n", 40_000)));

        (string command, string[] arguments) = OperatingSystem.IsWindows()
            ? ("cmd.exe", new[] { "/c", $"type \"{noise}\" 1>&2" })
            : ("/bin/sh", new[] { "-c", $"cat '{noise}' >&2" });

        ProcessOutcome? outcome = null;

        Thread worker = new(() =>
            outcome = ProcessRunner.Run(command, arguments, TimeSpan.FromSeconds(10)))
        {
            IsBackground = true,
        };

        worker.Start();

        Assert.True(
            worker.Join(TimeSpan.FromSeconds(60)),
            "ProcessRunner.Run never returned: it deadlocked on a full pipe.");

        // On Windows the secondary assertion is deliberately skipped: the shell invocation is not
        // verifiable from this developer's machine, and a quoting difference must not turn a
        // regression guard into a red build for the wrong reason. The property under test — that
        // the call RETURNS — is asserted on every platform and is what a deadlock breaks. Windows
        // is where it matters most, since its pipe buffer is the smallest.

        if (!OperatingSystem.IsWindows())
        {
            Assert.True(outcome!.Exited);
        }
    }

    /// <summary>
    /// Taking the machine lock does not leave the state directory readable by everyone.
    /// </summary>
    /// <remarks>
    /// <b>Whichever code path creates this directory first decides its permissions for ever</b> —
    /// <c>Directory.CreateDirectory(path, mode)</c> applies its mode only at creation and does
    /// nothing to a directory already there. The lock began being taken at the top of enrolment,
    /// which made it the first thing to touch the directory on a fresh machine, and a plain create
    /// left <c>0755</c> that the key store's later call could no longer tighten. The key file
    /// carries <c>0600</c> in its own right, so this is defence in depth — but
    /// <c>docs/security.md</c> states 0700 on the directory, and a statement in that document is
    /// either true or it should not be there.
    /// </remarks>
    [Fact]
    public void TakingTheLockLeavesTheStateDirectoryOwnerOnly()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        string directory = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"), "state");

        try
        {
            using (MachineLock? held = MachineLock.TryAcquire(directory, TimeSpan.FromSeconds(1), out _))
            {
                Assert.NotNull(held);
            }

            UnixFileMode mode = File.GetUnixFileMode(directory);

            Assert.Equal(
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute,
                mode);
        }
        finally
        {
            if (Directory.Exists(directory))
            {
                Directory.Delete(Path.GetDirectoryName(directory)!, recursive: true);
            }
        }
    }

    /// <summary>
    /// A machine whose clock was WRONG and has since been FIXED corrects itself.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>The stored offset outlives the fault it was learned for, and nothing else can clear
    /// it.</b> Once a machine has recorded, say, an hour of correction, every request it signs is
    /// stamped an hour away from its own clock — so the day somebody fixes the clock, or the laptop
    /// syncs NTP for the first time in months, that correction becomes the entire error. The
    /// request is refused for skew, and the refusal carries exactly what is needed to put it right.
    /// </para>
    /// <para>
    /// <b>The guard on whether a correction is worth applying must compare it against the one
    /// already in force, not against zero.</b> Asking only whether the NEW offset is small refuses
    /// to learn precisely when the answer is "you no longer need one" — the machine keeps stamping
    /// an hour out, is refused every time, and never reports or checks for an update again. There
    /// is no path back on the machine itself: the value it needs to forget is the one it is being
    /// told to forget.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task AStaleClockOffsetIsUnlearnedOnceTheClockIsRight()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        DateTimeOffset now = new(2026, 8, 20, 3, 0, 0, TimeSpan.Zero);

        // The server's clock and ours AGREE. The only thing wrong is the hour of correction this
        // machine is still carrying from when they did not.
        SkewHandler handler = new(now.ToUnixTimeSeconds());

        using HttpClient http = new(handler) { BaseAddress = new Uri("https://isms.example.com/") };
        using UpdateClient client = new(http, key, AgentVersionInfo.Current, 3600);

        UpdateCheck answer = await client.CheckAsync(
            Guid.NewGuid(), AgentRuntimeIdentifier.WindowsX64, now);

        // It was refused once, relearned, and retried — rather than giving up because the
        // correction it needs happens to be zero.
        Assert.Equal(2, handler.Requests);
        Assert.Equal(UpdateCheckStatus.NothingToDo, answer.Status);

        // And the correction that no longer applies is GONE, so the next run starts clean. Leaving
        // 3600 here is a machine that never speaks to Merlin again.
        Assert.Equal(0, answer.ClockOffsetSeconds);
        Assert.Equal(0, client.ClockOffsetSeconds);
    }

    /// <summary>
    /// A refusal that is not about the clock does not cost a second request.
    /// </summary>
    /// <remarks>
    /// The other half of the same guard: when the correction in force is already right, the server's
    /// time matches the stamp and there is nothing to relearn. Retrying every refusal would double
    /// the load a misconfigured fleet puts on the server for no gain.
    /// </remarks>
    [Fact]
    public async Task ARefusalThatIsNotAboutTheClockIsNotRetried()
    {
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

        DateTimeOffset now = new(2026, 8, 20, 3, 0, 0, TimeSpan.Zero);

        // This machine really is an hour slow and really is correcting for it, so the stamp the
        // server saw was right and its clock agrees with the corrected one.
        SkewHandler handler = new(now.AddSeconds(3600).ToUnixTimeSeconds());

        using HttpClient http = new(handler) { BaseAddress = new Uri("https://isms.example.com/") };
        using UpdateClient client = new(http, key, AgentVersionInfo.Current, 3600);

        UpdateCheck answer = await client.CheckAsync(
            Guid.NewGuid(), AgentRuntimeIdentifier.WindowsX64, now);

        Assert.Equal(1, handler.Requests);
        Assert.Equal(UpdateCheckStatus.Refused, answer.Status);
        Assert.Equal(3600, client.ClockOffsetSeconds);
    }

    /// <summary>Refuses the first request for skew, then answers 204.</summary>
    private sealed class SkewHandler(long serverTime) : HttpMessageHandler
    {
        public int Requests { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests++;

            if (Requests > 1)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NoContent)
                {
                    RequestMessage = request,
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.BadRequest)
            {
                RequestMessage = request,
                Content = new StringContent(
                    $"{{\"message\":\"timestamp outside tolerance\",\"serverTime\":{serverTime}}}",
                    Encoding.UTF8,
                    "application/json"),
            });
        }
    }

    private static async Task<UpdateCheck> CheckWith(HttpClient http, ECDsa key)
    {
        using UpdateClient client = new(http, key, AgentVersionInfo.Current, 0);

        return await client.CheckAsync(
            Guid.NewGuid(), AgentRuntimeIdentifier.WindowsX64, DateTimeOffset.UtcNow);
    }

    private sealed class BodyHandler(HttpStatusCode status, string body) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(status)
            {
                RequestMessage = request,
                Content = new StringContent(body, Encoding.UTF8, "application/json"),
            });
    }
}
