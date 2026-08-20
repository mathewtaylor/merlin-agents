using System.Security.Cryptography;
using Merlin.Agent.Core.Contracts;

namespace Merlin.Agent.Core.Update;

/// <summary>The result of one attempted component swap.</summary>
/// <param name="Outcome">
/// What happened, or <c>null</c> when nothing was attempted and there is nothing to report.
/// </param>
/// <param name="Detail">A sentence for the console and for <c>status</c>.</param>
/// <param name="InstalledVersion">The version now installed, when a swap succeeded.</param>
public sealed record SwapResult(AgentUpdateOutcome? Outcome, string Detail, string? InstalledVersion)
{
    /// <summary>Nothing was attempted.</summary>
    /// <param name="detail">Why.</param>
    /// <returns>The result.</returns>
    public static SwapResult NothingToDo(string detail) => new(null, detail, null);

    /// <summary>Nothing was replaced.</summary>
    /// <param name="detail">Why.</param>
    /// <returns>The result.</returns>
    public static SwapResult Failed(string detail) =>
        new(AgentUpdateOutcome.Failed, detail, null);

    /// <summary>The component was replaced.</summary>
    /// <param name="detail">What happened.</param>
    /// <param name="version">The version now installed.</param>
    /// <returns>The result.</returns>
    public static SwapResult Succeeded(string detail, string version) =>
        new(AgentUpdateOutcome.Succeeded, detail, version);
}

/// <summary>
/// THE component-swap routine. One implementation, two callers.
/// </summary>
/// <remarks>
/// <para>
/// <b>The updater replaces the AGENT; the agent replaces the UPDATER. Neither ever replaces its own
/// running image.</b> That is the core safety property of the whole design, and it is enforced here
/// — in <see cref="SwapAsync"/> and in <see cref="Restore"/>, against the component named at
/// construction — rather than trusted to callers. A single self-updating binary has one
/// unrecoverable failure: if the image it swaps in cannot execute there is nothing left running on
/// the machine to put the old one back. The constructor takes the running component for no other
/// reason; without it this sentence was describing something two call sites happened to do.
/// </para>
/// <para>
/// <b>The order is download → verify → extract → EXECUTE → swap → retain the previous.</b> Running
/// the staged binary once, before anything is committed, is what catches an antivirus quarantine, a
/// wrong architecture and a missing dependency <b>while the working binary is still in place</b>. A
/// swap that verified only the hash would prove the bytes arrived intact and nothing about whether
/// they run on this machine.
/// </para>
/// <para>
/// <b>The host allowlist is checked here, before any download</b>, so no caller can route around
/// it. See <see cref="PackageHosts"/> for why a server-side list is not the control it looks like.
/// </para>
/// <para>
/// <b>One swap per run, per process.</b> If both components are out of date, one moves now and the
/// other on a later run — enforced by <see cref="_swapped"/> rather than left to callers, because a
/// big-bang swap of both reintroduces the single point of failure the two-binary design exists to
/// remove.
/// </para>
/// </remarks>
public sealed class ComponentSwapper
{
    /// <summary>The largest archive that will be downloaded, as a sanity bound.</summary>
    private const long MaximumArchiveBytes = 256L * 1024 * 1024;

    private readonly AgentComponent _self;
    private readonly InstallLayout _layout;
    private readonly HttpClient _http;
    private readonly BinaryProbe _probe;
    private readonly Action<string> _log;

    private bool _swapped;

    /// <summary>Initialises a new instance of the <see cref="ComponentSwapper"/> class.</summary>
    /// <param name="self">
    /// Which component is running. <b>It is here so the never-replace-your-own-image rule is
    /// actually enforced by this class rather than merely described by it.</b> Without it the
    /// swapper cannot tell whose image it is overwriting, so the property rested entirely on two
    /// call sites passing the right argument — and this is public API in a library both binaries
    /// link, so the next caller would have believed the comment.
    /// </param>
    /// <param name="layout">Where the binaries live.</param>
    /// <param name="http">The client used to fetch a package.</param>
    /// <param name="probe">How a staged binary is executed before anything is committed.</param>
    /// <param name="log">Where progress and refusals are written.</param>
    public ComponentSwapper(
        AgentComponent self,
        InstallLayout layout,
        HttpClient http,
        BinaryProbe probe,
        Action<string> log)
    {
        ArgumentNullException.ThrowIfNull(layout);
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(probe);
        ArgumentNullException.ThrowIfNull(log);

        _self = self;
        _layout = layout;
        _http = http;
        _probe = probe;
        _log = log;
    }

    /// <summary>
    /// The refusal issued when something asks this process to replace its own running image.
    /// </summary>
    /// <param name="component">The component that was asked for.</param>
    /// <returns>The explanation.</returns>
    public static string SelfSwapRefusal(AgentComponent component) =>
        $"{InstallLayout.FileName(component)} is the binary making this call and will not replace "
        + "its own running image. The other component does that.";

    /// <summary>
    /// Replaces one component with a named version, or explains why it did not.
    /// </summary>
    /// <param name="component">
    /// The component to replace. <b>Never the caller's own</b> — callers pass
    /// <see cref="InstallLayout.Target"/> of what they are.
    /// </param>
    /// <param name="version">The version being installed.</param>
    /// <param name="packageEndpoint">Where to fetch the archive.</param>
    /// <param name="sha256">The archive's expected digest, lower-case hex.</param>
    /// <param name="cancellationToken">Cancellation.</param>
    /// <returns>What happened.</returns>
    public async Task<SwapResult> SwapAsync(
        AgentComponent component,
        string version,
        string packageEndpoint,
        string sha256,
        CancellationToken cancellationToken = default)
    {
        // NEVER BOTH IN ONE RUN. If the agent and the updater are both behind, one moves now and
        // the other on a later run — after this one has proved itself by running. Enforced here so
        // no caller can decide otherwise.
        // THE RULE, ENFORCED RATHER THAN ASSUMED. A process that overwrote its own image with one
        // that cannot execute would leave nothing running here able to put the old one back, which
        // is the single unrecoverable failure the two-binary design exists to remove.
        if (component == _self)
        {
            return SwapResult.Failed(SelfSwapRefusal(component));
        }

        if (_swapped)
        {
            return SwapResult.NothingToDo(
                "A component was already replaced in this run. The other one moves on a later run, "
                + "after this one has proved it runs.");
        }

        if (string.IsNullOrWhiteSpace(version))
        {
            return SwapResult.Failed("No version was named, so nothing was fetched.");
        }

        // THE COMPILE-TIME ALLOWLIST, before a single byte is fetched. Merlin can name a version
        // and an address; it cannot name an address this agent will download from.
        if (!PackageHosts.IsAllowed(packageEndpoint))
        {
            return SwapResult.Failed(PackageHosts.Refusal(packageEndpoint));
        }

        if (string.IsNullOrWhiteSpace(sha256))
        {
            return SwapResult.Failed(
                "The advertisement carried no SHA-256, so nothing could be verified and nothing "
                + "was installed.");
        }

        string fileName = InstallLayout.FileName(component);
        string staging = Path.Combine(_layout.StagingDirectory, Guid.NewGuid().ToString("N"));

        Directory.CreateDirectory(staging);

        try
        {
            string archivePath = Path.Combine(staging, "package");

            _log($"  fetching {version} for {fileName}...");

            string? downloadFailure = await DownloadAsync(packageEndpoint, archivePath, cancellationToken)
                .ConfigureAwait(false);

            if (downloadFailure is not null)
            {
                return SwapResult.Failed(downloadFailure);
            }

            string actual = Digest(archivePath);

            if (!string.Equals(actual, sha256.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                return SwapResult.Failed(
                    $"Hash mismatch for {packageEndpoint}. Expected {sha256.Trim()} but got "
                    + $"{actual}. Nothing was installed.");
            }

            string stagedBinary = Path.Combine(staging, fileName);

            if (!PackageArchive.TryExtract(archivePath, fileName, stagedBinary))
            {
                return SwapResult.Failed(
                    $"The {version} package carries no {fileName}. Nothing was installed.");
            }

            MakeExecutable(stagedBinary);

            // EXECUTE BEFORE COMMIT. A quarantined, wrong-architecture or dependency-missing binary
            // fails here, with the working one still in place and the machine still reporting.
            ProbeResult probed = _probe.Execute(stagedBinary, "--version", TimeSpan.FromSeconds(60));

            if (!probed.Ran)
            {
                return SwapResult.Failed(
                    $"The staged {fileName} would not execute, so nothing was replaced. "
                    + probed.Output.Trim());
            }

            string reported = BinaryProbe.FirstLine(probed.Output) ?? version;

            if (!AgentVersionInfo.Matches(reported, version))
            {
                // A warning, not a refusal. The advertised string is whatever an operator typed
                // into Merlin, and refusing over a spelling would strand a fleet on a working
                // binary it is not allowed to install. The version RECORDED below is the one the
                // binary itself stated, which is the only one that is true.
                _log($"  note: the package advertised {version} but the binary reports {reported}.");
            }

            string failure = Commit(component, stagedBinary);

            if (failure.Length > 0)
            {
                return SwapResult.Failed(failure);
            }

            _swapped = true;

            return SwapResult.Succeeded(
                $"{fileName} replaced with {reported}. The previous binary is retained beside it.",
                reported);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException
            or HttpRequestException or InvalidDataException or TaskCanceledException)
        {
            return SwapResult.Failed($"{fileName} was not replaced: {exception.Message}");
        }
        finally
        {
            TryDeleteDirectory(staging);
        }
    }

    /// <summary>
    /// Puts a component's previous binary back.
    /// </summary>
    /// <remarks>
    /// <b>The other half of mutual recovery.</b> Called when the component that was replaced has
    /// not run inside its window — which, for a scheduled invocation rather than a resident daemon,
    /// is the only evidence available that a swapped-in binary does not work. It counts against the
    /// one-swap-per-run rule for the same reason a swap does.
    /// </remarks>
    /// <param name="component">The component to restore.</param>
    /// <returns>What happened.</returns>
    public SwapResult Restore(AgentComponent component)
    {
        string fileName = InstallLayout.FileName(component);
        string previous = _layout.PreviousPathOf(component);
        string current = _layout.PathOf(component);

        // Restoring your own image is the same prohibition as swapping it: the file being replaced
        // is the one this process is running out of.
        if (component == _self)
        {
            return SwapResult.Failed(SelfSwapRefusal(component));
        }

        if (_swapped)
        {
            return SwapResult.NothingToDo("A component was already moved in this run.");
        }

        if (!File.Exists(previous))
        {
            return SwapResult.NothingToDo(
                $"There is no retained previous {fileName} to restore.");
        }

        try
        {
            string broken = current + ".failed";
            bool movedAside = false;

            if (File.Exists(current))
            {
                File.Move(current, broken, overwrite: true);
                movedAside = true;
            }

            try
            {
                File.Move(previous, current, overwrite: true);
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // Put the broken one back rather than leaving NOTHING there. It does not work, but
                // a component that is absent cannot even be diagnosed, and on the agent that is up
                // to a day of silence before anything looks at this machine again. Commit already
                // reasons this way for the same reason.
                if (movedAside && !File.Exists(current))
                {
                    TryMoveBack(broken, current);
                }

                throw;
            }

            MakeExecutable(current);

            _swapped = true;

            string? restored = _probe.Version(current);

            return new SwapResult(
                AgentUpdateOutcome.Reverted,
                $"{fileName} did not run inside its window, so the previous binary "
                + $"({restored ?? "unknown version"}) was restored. The one that failed is kept "
                + $"beside it as {Path.GetFileName(broken)}.",
                restored);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return SwapResult.Failed($"{fileName} could not be restored: {exception.Message}");
        }
    }

    /// <summary>
    /// Moves the staged binary into place, retaining the outgoing one.
    /// </summary>
    /// <remarks>
    /// <b>Move the current one aside, then move the new one in.</b> Overwriting in place would fail
    /// on Windows for a binary anything holds open, and — worse — a failure halfway would leave no
    /// copy of the working binary anywhere. Renaming first means the previous image survives every
    /// failure mode, and is what the OTHER component restores from.
    /// </remarks>
    private string Commit(AgentComponent component, string stagedBinary)
    {
        string current = _layout.PathOf(component);
        string previous = _layout.PreviousPathOf(component);
        bool retained = false;

        try
        {
            if (File.Exists(current))
            {
                File.Move(current, previous, overwrite: true);
                retained = true;
            }

            File.Move(stagedBinary, current);
            MakeExecutable(current);

            return string.Empty;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            if (retained && !File.Exists(current))
            {
                // Put it back. A half-finished swap that left no binary at all is the one outcome
                // this whole design exists to prevent.
                try
                {
                    File.Move(previous, current, overwrite: true);
                }
                catch (IOException)
                {
                    return $"{InstallLayout.FileName(component)} could not be replaced "
                        + $"({exception.Message}) and the previous binary could not be put back "
                        + $"either. It is at {previous}.";
                }
            }

            return $"{InstallLayout.FileName(component)} was not replaced: {exception.Message}";
        }
    }

    private async Task<string?> DownloadAsync(
        string endpoint,
        string destination,
        CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await _http
            .GetAsync(new Uri(endpoint), HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            return $"{endpoint} returned {(int)response.StatusCode}. Nothing was installed.";
        }

        // A redirect off the allowlist is a redirect off the allowlist. HttpClient follows them by
        // default, so the final address is re-checked — github.com hands every download to
        // objects.githubusercontent.com, and both are on the list precisely because of it.
        string? finalAddress = response.RequestMessage?.RequestUri?.ToString();

        if (finalAddress is not null && !PackageHosts.IsAllowed(finalAddress))
        {
            return PackageHosts.Refusal(finalAddress);
        }

        if (response.Content.Headers.ContentLength is > MaximumArchiveBytes)
        {
            return $"{endpoint} offered {response.Content.Headers.ContentLength} bytes, which is "
                + "larger than any agent package. Nothing was installed.";
        }

        await using FileStream file = File.Create(destination);
        await using Stream body = await response.Content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);

        byte[] buffer = new byte[81920];
        long total = 0;
        int read;

        while ((read = await body.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            total += read;

            if (total > MaximumArchiveBytes)
            {
                return $"{endpoint} is larger than any agent package. Nothing was installed.";
            }

            await file.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        return null;
    }

    private static string Digest(string path)
    {
        using FileStream stream = File.OpenRead(path);

        return Convert.ToHexStringLower(SHA256.HashData(stream));
    }

    /// <summary>
    /// Sets the executable bit, and never throws.
    /// </summary>
    /// <remarks>
    /// <b>It must not be able to fail a swap that has already landed.</b> Called after the move, a
    /// throw was caught as "the component was not replaced" — while the new binary was in fact in
    /// place. The swap mark was then never recorded, so the no-stacked-swap rule did not engage,
    /// and the next run replaced it again and overwrote the retained copy with an unproven binary:
    /// the exact hole that rule closed, reopened by another route. Every path that needs the bit
    /// has a check downstream that catches the consequence honestly — the probe for a staged
    /// binary, the other component's revert for an installed one — so swallowing here loses no
    /// signal.
    /// </remarks>
    private static void MakeExecutable(string path)
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        try
        {
            File.SetUnixFileMode(
                path,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute
                | UnixFileMode.GroupRead | UnixFileMode.GroupExecute
                | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The move preserves the mode already set on the staged file, so this is belt to that
            // braces. If the bit really is missing, the binary will not run and the component that
            // is watching it will put the previous one back.
        }
    }

    /// <summary>Moves a file back, swallowing a second failure.</summary>
    /// <remarks>
    /// Reached only while already handling a failure, where there is nothing further to try and the
    /// caller's own message is the one worth reporting.
    /// </remarks>
    private static void TryMoveBack(string from, string to)
    {
        try
        {
            File.Move(from, to, overwrite: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // Nothing further to try.
        }
    }

    private static void TryDeleteDirectory(string path)
    {
        try
        {
            if (Directory.Exists(path))
            {
                Directory.Delete(path, recursive: true);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // A staging directory left behind is untidy, never harmful — it sits under the state
            // directory and the next run writes its own.
        }
    }
}
