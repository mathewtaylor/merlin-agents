using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using Merlin.Agent.Core.Contracts;

namespace Merlin.Agent.Collection;

/// <summary>
/// Reads the machine's LOCAL password policy from <c>net accounts</c>.
/// </summary>
/// <remarks>
/// <para>
/// <b>osquery has no table for this, and the local policy is the one that matters here.</b> A
/// workgroup machine gets none of a directory's password rules, and a workgroup machine is exactly
/// what an organisation without an MDM tends to be running — so leaving this uncollected would gut
/// A.5.17 for the fleet the agent exists to reach.
/// </para>
/// <para>
/// <b>Complexity is deliberately NOT reported.</b> <c>net accounts</c> does not expose it; only
/// <c>secedit /export</c> does, which writes a temporary file containing far more of the security
/// policy than is wanted. Reporting <c>null</c> here is honest, and Merlin's rule treats an
/// unreported half as not-failing rather than inventing a <c>false</c> that would fail every
/// machine.
/// </para>
/// </remarks>
[SupportedOSPlatform("windows")]
public static class LocalPasswordPolicy
{
    /// <summary>Reads the local policy, or <c>null</c> when it could not be read.</summary>
    /// <param name="administrators">Local administrator names already collected by osquery.</param>
    /// <returns>The accounts reading, or null.</returns>
    public static AgentAccountsReading? Read(IReadOnlyList<string>? administrators)
    {
        string? output = Execute();

        if (output is null)
        {
            return administrators is null
                ? null
                : new AgentAccountsReading(administrators, null, null, null);
        }

        int? minimumLength = null;
        int? lockoutThreshold = null;

        foreach (string line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            int separator = line.LastIndexOf(':');

            if (separator < 0)
            {
                continue;
            }

            string label = line[..separator].Trim();
            string value = line[(separator + 1)..].Trim();

            if (label.Contains("Minimum password length", StringComparison.OrdinalIgnoreCase))
            {
                minimumLength = ParseCount(value);
            }
            else if (label.Contains("Lockout threshold", StringComparison.OrdinalIgnoreCase))
            {
                // "Never" means no lockout is enforced, which is an OBSERVATION of zero rather than
                // an absence of data — distinct from a line that could not be parsed at all.
                lockoutThreshold = value.StartsWith("Never", StringComparison.OrdinalIgnoreCase)
                    ? 0
                    : ParseCount(value);
            }
        }

        return minimumLength is null && lockoutThreshold is null && administrators is null
            ? null
            : new AgentAccountsReading(administrators, minimumLength, null, lockoutThreshold);
    }

    private static int? ParseCount(string value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : null;

    private static string? Execute()
    {
        try
        {
            using Process? process = Process.Start(new ProcessStartInfo
            {
                FileName = "net",
                ArgumentList = { "accounts" },
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });

            if (process is null)
            {
                return null;
            }

            string output = process.StandardOutput.ReadToEnd();

            if (!process.WaitForExit(10_000))
            {
                try
                {
                    process.Kill(entireProcessTree: true);
                }
                catch (InvalidOperationException)
                {
                    // Already exited.
                }

                return null;
            }

            return process.ExitCode == 0 ? output : null;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }
}
