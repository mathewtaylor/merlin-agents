using System.Formats.Tar;
using System.IO.Compression;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Merlin.Agent.Core.Update;

namespace Merlin.Agent.Core.Tests;

/// <summary>
/// A temporary install tree, plus the pieces needed to drive a swap without a server.
/// </summary>
/// <remarks>
/// The swap routine touches four things a unit test cannot otherwise supply — an install directory,
/// a state directory, an HTTP endpoint on an ALLOWLISTED host, and a binary that can be executed.
/// The first two are temporary directories, the third is a stub handler, and the fourth is
/// <see cref="BinaryProbe"/>'s seam. The allowlist is deliberately not injectable, so the test
/// endpoint has to be a real allowlisted host name and the stub answers for it.
/// </remarks>
internal sealed class UpdateTestKit : IDisposable
{
    /// <summary>An address on an allowlisted host, so tests exercise the guard rather than bypass it.</summary>
    public const string AllowedEndpoint = "https://github.com/mathewtaylor/merlin-agents/releases/download/v9.9.9/pkg.tar.gz";

    private readonly string _root;

    public UpdateTestKit()
    {
        _root = Path.Combine(Path.GetTempPath(), "merlin-agent-tests", Guid.NewGuid().ToString("N"));

        InstallDirectory = Path.Combine(_root, "install");
        StateDirectory = Path.Combine(_root, "state");

        Directory.CreateDirectory(InstallDirectory);
        Directory.CreateDirectory(StateDirectory);

        Layout = new InstallLayout(InstallDirectory, StateDirectory);
    }

    public string InstallDirectory { get; }

    public string StateDirectory { get; }

    public InstallLayout Layout { get; }

    /// <summary>Writes a stand-in for an installed component.</summary>
    public string PlaceComponent(AgentComponent component, string contents)
    {
        string path = Layout.PathOf(component);
        File.WriteAllText(path, contents);
        return path;
    }

    /// <summary>Builds a tar.gz carrying both binaries and a query pack, as CI does.</summary>
    public static byte[] BuildArchive(string agentContents, string updaterContents)
    {
        using MemoryStream compressed = new();

        using (GZipStream gzip = new(compressed, CompressionLevel.Fastest, leaveOpen: true))
        using (TarWriter writer = new(gzip, leaveOpen: true))
        {
            // "./" prefixed, exactly as `tar -czf archive -C dir .` writes them. Entry names are
            // matched on the file name for this reason: the Windows zip is flat and the Unix tar is
            // not, and they have been different since the first release.
            Add(writer, "./" + InstallLayout.FileName(AgentComponent.Agent), agentContents);
            Add(writer, "./" + InstallLayout.FileName(AgentComponent.Updater), updaterContents);
            Add(writer, "./queries/linux.json", "{}");
        }

        return compressed.ToArray();
    }

    /// <summary>Builds an archive carrying the agent alone, as CI did before auto-update.</summary>
    public static byte[] BuildAgentOnlyArchive(string agentContents)
    {
        using MemoryStream compressed = new();

        using (GZipStream gzip = new(compressed, CompressionLevel.Fastest, leaveOpen: true))
        using (TarWriter writer = new(gzip, leaveOpen: true))
        {
            Add(writer, "./" + InstallLayout.FileName(AgentComponent.Agent), agentContents);
        }

        return compressed.ToArray();
    }

    /// <summary>Builds a zip carrying both binaries, as CI does on Windows.</summary>
    public static byte[] BuildZipArchive(string agentContents, string updaterContents)
    {
        using MemoryStream buffer = new();

        using (ZipArchive archive = new(buffer, ZipArchiveMode.Create, leaveOpen: true))
        {
            Write(archive, InstallLayout.FileName(AgentComponent.Agent), agentContents);
            Write(archive, InstallLayout.FileName(AgentComponent.Updater), updaterContents);
        }

        return buffer.ToArray();
    }

    /// <summary>The lower-case hex SHA-256 of some bytes.</summary>
    public static string Digest(byte[] bytes) => Convert.ToHexStringLower(SHA256.HashData(bytes));

    /// <summary>An <see cref="HttpClient"/> that serves fixed bytes for any address.</summary>
    public static HttpClient Serving(byte[] payload) => new(new StubHandler(payload));

    /// <summary>An <see cref="HttpClient"/> that answers every address with a status.</summary>
    public static HttpClient Refusing(HttpStatusCode status) => new(new StubHandler(status));

    /// <summary>A probe that reports a version and always runs.</summary>
    public static BinaryProbe ProbeReporting(string version) =>
        new((_, _, _) => new ProbeResult(true, version + "\n"));

    /// <summary>A probe whose staged binary will not execute.</summary>
    public static BinaryProbe ProbeThatWillNotRun() =>
        new((_, _, _) => new ProbeResult(false, "It exited with code 134. Killed: 9"));

    /// <summary>
    /// A probe that answers one version for what is INSTALLED and another for what is STAGED.
    /// </summary>
    /// <remarks>
    /// The distinction is the whole point of the update path: the runner compares the installed
    /// binary's version against what Merlin advertises, and the swapper then asks the staged binary
    /// what it is before committing to it. A probe answering the same thing for both would make
    /// every "is this already current?" branch untestable.
    /// </remarks>
    public BinaryProbe ProbeInstalledAndStaged(string installed, string staged) =>
        new((path, _, _) => new ProbeResult(
            true,

            // STAGING IS TESTED FIRST, because it now sits UNDER the install directory — a staged
            // path therefore also starts with the install path, and asking the looser question
            // first quietly answered "installed" for both. The staging directory moved there
            // deliberately: a file about to become an installed binary has to be staged somewhere
            // exactly as protected as the binaries themselves.
            path.StartsWith(Layout.StagingDirectory, StringComparison.Ordinal) ? staged
            : path.StartsWith(InstallDirectory, StringComparison.Ordinal) ? installed
            : staged));

    /// <summary>A probe that answers per path, for the two-component cases.</summary>
    public static BinaryProbe ProbeByPath(Func<string, string?> version) =>
        new((path, _, _) => version(path) is { } answer
            ? new ProbeResult(true, answer)
            : new ProbeResult(false, "no"));

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_root))
            {
                Directory.Delete(_root, recursive: true);
            }
        }
        catch (IOException)
        {
            // A leftover temporary directory is not worth failing a test over.
        }
    }

    private static void Add(TarWriter writer, string name, string contents)
    {
        PaxTarEntry entry = new(TarEntryType.RegularFile, name)
        {
            DataStream = new MemoryStream(Encoding.UTF8.GetBytes(contents)),
        };

        writer.WriteEntry(entry);
    }

    private static void Write(ZipArchive archive, string name, string contents)
    {
        using StreamWriter writer = new(archive.CreateEntry(name).Open());
        writer.Write(contents);
    }

    private sealed class StubHandler : HttpMessageHandler
    {
        private readonly byte[]? _payload;
        private readonly HttpStatusCode _status;

        public StubHandler(byte[] payload)
        {
            _payload = payload;
            _status = HttpStatusCode.OK;
        }

        public StubHandler(HttpStatusCode status)
        {
            _payload = null;
            _status = status;
        }

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(request);

            HttpResponseMessage response = new(_status)
            {
                // Echoed back so the swapper's re-check of the FINAL address after redirects has
                // something to read — the real one follows github.com to objects.githubusercontent.com.
                RequestMessage = request,
                Content = _payload is null
                    ? new ByteArrayContent([])
                    : new ByteArrayContent(_payload),
            };

            return Task.FromResult(response);
        }
    }
}
