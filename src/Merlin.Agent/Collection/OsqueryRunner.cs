using System.Text.Json;
using System.Text.Json.Serialization;
using Merlin.Agent.Core.Collection;
using Merlin.Agent.Core.Platform;

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
public sealed class OsqueryRunner
{
    private static readonly JsonSerializerOptions _json = new()
    {
        TypeInfoResolver = OsqueryJsonContext.Default,
    };

    private readonly string _osqueryPath;
    private readonly TimeSpan _timeout;
    private readonly CollectionDeadline _deadline;

    /// <summary>Initialises a new instance of the <see cref="OsqueryRunner"/> class.</summary>
    /// <param name="osqueryPath">Full path to <c>osqueryi.exe</c>.</param>
    /// <param name="timeout">How long a single query may take.</param>
    /// <param name="deadline">
    /// The bound on the WHOLE collection, shared with everything else that runs under the same
    /// machine lock. <b>It is passed in rather than created here precisely because a per-loop
    /// budget is the version of this that does not work</b> — the version probe below and the
    /// supplemental host readings that follow the pack are part of the same lock hold, so a bound
    /// that covers only this class leaves them outside it and the property still fails. Null
    /// creates one, for a caller with nothing else to coordinate with.
    /// </param>
    public OsqueryRunner(string osqueryPath, TimeSpan timeout, CollectionDeadline? deadline = null)
    {
        _osqueryPath = osqueryPath;
        _timeout = timeout;
        _deadline = deadline ?? new CollectionDeadline();
    }

    /// <summary>
    /// Locates <c>osqueryi</c>, preferring the copy the installer placed beside the agent.
    /// </summary>
    /// <remarks>
    /// <b>Beside the agent first, on every platform.</b> The installer stages its own pinned,
    /// hash-verified copy there, and that is the one whose provenance this deployment actually
    /// knows. The system locations are searched afterwards so a machine where an administrator
    /// already runs osquery is not made to carry a second copy — but they are the fallback, not the
    /// preference, because nothing pins what is in them.
    /// </remarks>
    /// <returns>The path, or <c>null</c> when osquery is not installed.</returns>
    public static string? Locate()
    {
        string executable = OperatingSystem.IsWindows() ? "osqueryi.exe" : "osqueryi";
        string beside = Path.Combine(AppContext.BaseDirectory, "osquery", executable);

        if (File.Exists(beside))
        {
            return beside;
        }

        foreach (string candidate in SystemLocations(executable))
        {
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        return null;
    }

    private static IEnumerable<string> SystemLocations(string executable)
    {
        switch (AgentPlatformInfo.Current)
        {
            case AgentOs.Windows:
                yield return Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                    "osquery",
                    executable);
                break;

            case AgentOs.MacOs:
                // The official package installs an app bundle, so the binary is not on PATH and is
                // several levels below the directory an administrator would think to look in.
                yield return "/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryi";
                yield return "/usr/local/bin/osqueryi";
                yield return "/opt/homebrew/bin/osqueryi";
                break;

            default:
                yield return "/usr/bin/osqueryi";
                yield return "/opt/osquery/bin/osqueryi";
                yield return "/usr/local/bin/osqueryi";
                break;
        }
    }

    /// <summary>Reads the installed osquery version, or <c>null</c>.</summary>
    /// <returns>The version string.</returns>
    public string? Version()
    {
        // A SHORT TIMEOUT OF ITS OWN, because this runs FIRST and is worth the least. It is
        // metadata about the collector rather than a reading about the machine, and on the slow
        // machine the budget exists for it would otherwise take up to a third of that budget
        // before the first security query starts — spending the bound on the one thing the
        // ordering rule says to sacrifice first.
        (string? output, _) = Execute(_versionTimeout, "--version");

        return output?.Trim() is { Length: > 0 } text ? text : null;
    }

    /// <summary>Runs every query in the manifest and collects the rows.</summary>
    /// <param name="queries">
    /// Query name and SQL, IN THE ORDER THEY SHOULD RUN. The collection is bounded, so this is
    /// also the order in which readings are sacrificed when it runs out — which is why the packs
    /// are written security-posture first, and why this is a list rather than a dictionary.
    /// </param>
    /// <param name="onQueryFailed">Called with the query name and failure detail.</param>
    /// <returns>The results.</returns>
    /// <exception cref="ArgumentNullException">When <paramref name="queries"/> is null.</exception>
    public OsqueryResults RunAll(
        IReadOnlyList<KeyValuePair<string, string>> queries,
        Action<string, string>? onQueryFailed = null)
    {
        ArgumentNullException.ThrowIfNull(queries);

        OsqueryResults results = new();

        foreach ((string name, string sql) in queries)
        {
            if (_deadline.Passed)
            {
                // NOT OBSERVED, never a false reading — the same answer a missing table gives, and
                // the normaliser already turns it into a null rather than a negative. Reported per
                // query so the operator sees which readings were skipped and why.
                onQueryFailed?.Invoke(name, "the collection budget was exhausted before this query ran");
                continue;
            }

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

    /// <summary>
    /// How long the collector may take to state its own version.
    /// </summary>
    /// <remarks>
    /// A binary printing a compiled-in string. If it cannot manage that in five seconds the
    /// readings that follow are the ones worth spending the remaining time on.
    /// </remarks>
    private static readonly TimeSpan _versionTimeout = TimeSpan.FromSeconds(5);

    private (string? Output, string? Error) Execute(params string[] arguments) =>
        Execute(_timeout, arguments);

    private (string? Output, string? Error) Execute(TimeSpan timeout, params string[] arguments)
    {
        // THE SHARED RUNNER. This used to read stdout to the end and then stderr, which is the
        // deadlock the binary probe documents: osqueryi writes a glog warning per query, and a
        // child that fills the stderr buffer while the parent blocks on stdout can never exit — so
        // the parent never reaches the timeout at all. It matters more than a dead run, because a
        // collection holds the machine-wide lock: a wedged osqueryi means the updater can never
        // take that lock and can never put a broken agent back, and the machine goes silent.
        // CLAMPED, not merely gated. Checking only whether there is time to START a query lets the
        // last one overshoot by its whole timeout — thirty seconds past a bound chosen to fit
        // inside the updater's lock wait, which is the difference between a bound that holds and
        // one that nearly does.
        ProcessOutcome outcome = ProcessRunner.Run(
            _osqueryPath, arguments, _deadline.Clamp(timeout));

        if (!outcome.Started)
        {
            return (null, outcome.StandardError);
        }

        if (!outcome.Exited)
        {
            // A hung query must not hold the scheduled task open. Killing the child is safe:
            // osqueryi is a read-only shell that owns no state.
            return (null, "timed out");
        }

        // Succeeded, NOT a hand-rolled exit-code test. It also requires that standard output was
        // read to the END, which matters here: a truncated read leaves the JSON empty, and empty
        // JSON is not "osquery returned no rows" — it is "we never saw what it returned". The
        // deserialise below would turn it into a not-observed reading by accident; this makes it
        // one on purpose, and says why.
        if (outcome.Succeeded)
        {
            return (outcome.StandardOutput, null);
        }

        // BOTH HALVES, because they are not alternatives. A query can exit non-zero AND have had
        // its output truncated, and reporting only the truncation drops the exit code and the
        // stderr — which is the actionable half and the reason the operator is reading this line.
        string reason = string.IsNullOrWhiteSpace(outcome.StandardError)
            ? $"exit code {outcome.ExitCode}"
            : outcome.StandardError.Trim();

        return (null, outcome.OutputComplete
            ? reason
            : $"{reason}; its output could not be read to the end");
    }
}

/// <summary>Source-generated JSON context for osquery output.</summary>
[JsonSerializable(typeof(List<Dictionary<string, string>>))]
public sealed partial class OsqueryJsonContext : JsonSerializerContext;
