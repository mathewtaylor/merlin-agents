using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text.Json;
using System.Text.Json.Serialization;
using Merlin.Agent.Core.Collection;

namespace Merlin.Agent.Collection;

/// <summary>
/// Runs the collection manifest through <c>osqueryi</c>, one query at a time.
/// </summary>
/// <remarks>
/// <para>
/// <b><c>osqueryi</c>, never <c>osqueryd</c>.</b> The daemon's distinctive value is scheduled query
/// packs and evented ETW tables, and nothing downstream reads either: Merlin records one check run
/// per day. Running the shell one-shot costs about a second, leaves nothing resident, and means
/// there is no second service to keep patched on every employee machine.
/// </para>
/// <para>
/// <b>One query per process, and a failure is contained to its own reading.</b> Batching would be
/// faster, but a single unavailable table would then take down the whole collection — and the
/// tables most likely to be unavailable (TPM, BitLocker, Secure Boot) are exactly the ones on the
/// hardware this agent exists to reach. A query that fails contributes no rows, which the normaliser
/// turns into a null reading rather than a false one.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class OsqueryRunner
{
    private static readonly JsonSerializerOptions _json = new()
    {
        TypeInfoResolver = OsqueryJsonContext.Default,
    };

    private readonly string _osqueryPath;
    private readonly TimeSpan _timeout;

    /// <summary>Initialises a new instance of the <see cref="OsqueryRunner"/> class.</summary>
    /// <param name="osqueryPath">Full path to <c>osqueryi.exe</c>.</param>
    /// <param name="timeout">How long a single query may take.</param>
    public OsqueryRunner(string osqueryPath, TimeSpan timeout)
    {
        _osqueryPath = osqueryPath;
        _timeout = timeout;
    }

    /// <summary>
    /// Locates <c>osqueryi.exe</c>, preferring the copy installed beside the agent.
    /// </summary>
    /// <returns>The path, or <c>null</c> when osquery is not installed.</returns>
    public static string? Locate()
    {
        string beside = Path.Combine(AppContext.BaseDirectory, "osquery", "osqueryi.exe");

        if (File.Exists(beside))
        {
            return beside;
        }

        string programFiles = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "osquery",
            "osqueryi.exe");

        return File.Exists(programFiles) ? programFiles : null;
    }

    /// <summary>Reads the installed osquery version, or <c>null</c>.</summary>
    /// <returns>The version string.</returns>
    public string? Version()
    {
        (string? output, _) = Execute("--version");

        return output?.Trim() is { Length: > 0 } text ? text : null;
    }

    /// <summary>Runs every query in the manifest and collects the rows.</summary>
    /// <param name="queries">Query name to SQL.</param>
    /// <param name="onQueryFailed">Called with the query name and failure detail.</param>
    /// <returns>The results.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="queries"/> is null.</exception>
    public OsqueryResults RunAll(
        IReadOnlyDictionary<string, string> queries,
        Action<string, string>? onQueryFailed = null)
    {
        ArgumentNullException.ThrowIfNull(queries);

        OsqueryResults results = new();

        foreach ((string name, string sql) in queries)
        {
            (string? output, string? error) = Execute("--json", sql);

            if (output is null)
            {
                onQueryFailed?.Invoke(name, error ?? "no output");
                continue;
            }

            try
            {
                List<Dictionary<string, string>>? rows =
                    JsonSerializer.Deserialize(output, OsqueryJsonContext.Default.ListDictionaryStringString);

                results.Add(name, rows ?? []);
            }
            catch (JsonException exception)
            {
                onQueryFailed?.Invoke(name, exception.Message);
            }
        }

        return results;
    }

    private (string? Output, string? Error) Execute(params string[] arguments)
    {
        ProcessStartInfo startInfo = new()
        {
            FileName = _osqueryPath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        foreach (string argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        try
        {
            using Process? process = Process.Start(startInfo);

            if (process is null)
            {
                return (null, "osquery did not start");
            }

            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();

            if (!process.WaitForExit((int)_timeout.TotalMilliseconds))
            {
                // A hung query must not hold the scheduled task open. Killing the child is safe:
                // osqueryi is a read-only shell that owns no state.
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                    // Already gone between the timeout and the kill.
                }

                return (null, "timed out");
            }

            return process.ExitCode == 0
                ? (output, null)
                : (null, string.IsNullOrWhiteSpace(error) ? $"exit code {process.ExitCode}" : error.Trim());
        }
        catch (System.ComponentModel.Win32Exception exception)
        {
            return (null, exception.Message);
        }
    }
}

/// <summary>Source-generated JSON context for osquery output.</summary>
[JsonSerializable(typeof(List<Dictionary<string, string>>))]
public sealed partial class OsqueryJsonContext : JsonSerializerContext;
