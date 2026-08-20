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

        // The broken one is gone rather than kept as the thing a revert would restore.
        Assert.False(File.Exists(kit.Layout.PreviousPathOf(AgentComponent.Updater)));
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
            AgentComponent.Updater, kit.Layout, swapper, probe, UpdateWindows.Default, _ => { }));

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

        Assert.True(outcome!.Exited);
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
