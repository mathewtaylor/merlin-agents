using System.Globalization;
using System.Runtime.Versioning;
using Merlin.Agent.Core.Collection;
using Merlin.Agent.Core.Platform;

namespace Merlin.Agent.Collection;

/// <summary>
/// Reads the signals that no osquery table exposes, from whatever this platform does expose them
/// through.
/// </summary>
/// <remarks>
/// <para>
/// <b>Everything here is a deliberate exception to "collection is osquery".</b> Each reading below
/// was checked against osquery's schema first and added only because there is no table for it —
/// the local password policy on all three platforms, and the host firewall, Secure Boot state and
/// package-manager activity on Linux. Keeping the exceptions in one file, rather than scattered
/// through the collectors, is what makes them auditable as a set: the manifest can say exactly what
/// the agent reads OUTSIDE the query packs, and that list is this class.
/// </para>
/// <para>
/// <b>Nothing here reads a person.</b> No command takes a username, no file read touches a home
/// directory, and no output is parsed for an identity.
/// </para>
/// </remarks>
public static class HostReader
{
    private static readonly TimeSpan _timeout = TimeSpan.FromSeconds(10);

    /// <summary>Reads the supplemental signals for the host platform.</summary>
    /// <remarks>
    /// <b>These run under the same machine lock as the query pack, so they share its deadline.</b>
    /// They are the phase most easily forgotten when a collection is bounded — they sit after the
    /// pack rather than inside it — and on Linux they are also the most expensive, running up to
    /// three separate firewall front-ends at ten seconds each. A bound that stops at the pack is a
    /// bound the updater can still be starved past.
    /// </remarks>
    /// <param name="deadline">The bound on the whole collection.</param>
    /// <returns>The readings; every field is <c>null</c> where nothing could be read.</returns>
    public static SupplementalReadings Read(CollectionDeadline deadline)
    {
        ArgumentNullException.ThrowIfNull(deadline);

        return AgentPlatformInfo.Current switch
        {
            AgentOs.Windows when OperatingSystem.IsWindows() => ReadWindows(deadline),
            AgentOs.MacOs => ReadMacOs(deadline),
            AgentOs.Linux => ReadLinux(deadline),
            _ => new SupplementalReadings(),
        };
    }

    /// <summary>
    /// Reads the Windows local password policy from <c>net accounts</c>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>osquery has no table for this, and the LOCAL policy is the one that matters here.</b> A
    /// workgroup machine gets none of a directory's password rules, and a workgroup machine is
    /// exactly what an organisation without an MDM tends to be running — so leaving this uncollected
    /// would gut A.5.17 for the fleet the agent exists to reach.
    /// </para>
    /// <para>
    /// <b>Complexity is deliberately NOT reported.</b> <c>net accounts</c> does not expose it; only
    /// <c>secedit /export</c> does, which writes a temporary file containing far more of the
    /// security policy than is wanted. Reporting <c>null</c> here is honest, and Merlin's rule
    /// treats an unreported half as not-failing rather than inventing a <c>false</c> that would fail
    /// every machine.
    /// </para>
    /// </remarks>
    [SupportedOSPlatform("windows")]
    private static SupplementalReadings ReadWindows(CollectionDeadline deadline)
    {
        string? output = CommandRunner.Run("net", ["accounts"], deadline.Clamp(_timeout));

        if (output is null)
        {
            return new SupplementalReadings();
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

        return new SupplementalReadings(
            PasswordMinimumLength: minimumLength,
            LockoutThreshold: lockoutThreshold);
    }

    /// <summary>
    /// Reads the macOS local password policy from <c>pwpolicy</c>.
    /// </summary>
    /// <remarks>
    /// <b>An unrecognised or empty policy set reports <c>null</c>, NOT a minimum length of zero.</b>
    /// A stock Mac with no MDM enforces no password policy, and it is tempting to report that as an
    /// observed zero — which would fail A.5.17 for every unmanaged Mac. The reason not to is that
    /// <c>pwpolicy</c> exits successfully in several situations that are not "no policy": a
    /// directory-bound Mac whose policy lives upstream, a format this parser does not recognise, an
    /// MDM profile expressing the rule some other way. Reporting zero would state a fact about the
    /// machine that this reading cannot establish, so the length is reported only when it is
    /// positively found.
    /// </remarks>
    private static SupplementalReadings ReadMacOs(CollectionDeadline deadline)
    {
        string? output = CommandRunner.Run("/usr/bin/pwpolicy", ["-getaccountpolicies"], deadline.Clamp(_timeout));

        return output is null
            ? new SupplementalReadings()
            : new SupplementalReadings(
                PasswordMinimumLength: FindKeyedInteger(output, "policyAttributeMinimumLength"));
    }

    /// <summary>
    /// Reads the Linux signals that live in the filesystem rather than in a table.
    /// </summary>
    /// <remarks>
    /// Four file reads and one command, all of them machine-scope and none of them touching a home
    /// directory. Each is independently <c>null</c>-able: a machine with no EFI variables still
    /// reports its password policy, and one with no <c>pwquality</c> still reports its TPM.
    /// </remarks>
    private static SupplementalReadings ReadLinux(CollectionDeadline deadline)
    {
        (int? minimumLength, bool? complexity) = LinuxPasswordPolicy();

        // ONE READING, ASKED ONCE. It was asked twice — once for the flag and once for the string —
        // which is two independent observations deciding two halves of one fact, free to disagree
        // and report a TPM that is present with no version.
        (bool? present, string? version) = LinuxTpm();

        return new SupplementalReadings(
            PasswordMinimumLength: minimumLength,
            PasswordComplexityEnabled: complexity,
            FirewallEnabled: LinuxFirewall(deadline),
            SecureBootEnabled: LinuxSecureBoot(),
            TpmPresent: present,
            TpmVersion: version,
            LastUpdateInstalledAt: LinuxLastPackageChange());
    }

    /// <summary>
    /// Reads the local password policy from <c>pwquality.conf</c>, falling back to
    /// <c>login.defs</c>.
    /// </summary>
    /// <remarks>
    /// <b><c>pwquality.conf</c> first, because <c>login.defs</c>' <c>PASS_MIN_LEN</c> is inert on
    /// any modern distribution.</b> It is still present in the file and still parsed by tools that
    /// do not know better, but PAM ignores it wherever <c>pam_pwquality</c> is in the stack — which
    /// is everywhere that matters. Reading it first would report the value in the file rather than
    /// the rule in force, which is a confident wrong answer instead of a missing one.
    /// </remarks>
    private static (int? MinimumLength, bool? Complexity) LinuxPasswordPolicy()
    {
        string? pwquality = CommandRunner.ReadFile("/etc/security/pwquality.conf");

        if (pwquality is not null)
        {
            int? minimumLength = FindConfigInteger(pwquality, "minlen");
            int? classes = FindConfigInteger(pwquality, "minclass");

            // Complexity is reported ONLY when minclass positively requires more than one character
            // class. The per-class credit settings (dcredit, ucredit…) express the same idea in a
            // form whose default is "no requirement", and reading their absence as "complexity off"
            // would fail machines whose policy is expressed the other way.
            bool? complexity = classes is null ? null : classes > 1;

            if (minimumLength is not null || complexity is not null)
            {
                return (minimumLength, complexity);
            }
        }

        string? loginDefs = CommandRunner.ReadFile("/etc/login.defs");

        return loginDefs is null
            ? (null, null)
            : (FindConfigInteger(loginDefs, "PASS_MIN_LEN"), null);
    }

    /// <summary>
    /// Reads the host firewall's state from whichever front-end this distribution uses.
    /// </summary>
    /// <remarks>
    /// <b>Tried in order, and an unrecognised stack is <c>null</c>.</b> There is no single answer to
    /// "is the firewall on" across distributions: Ubuntu answers through <c>ufw</c>, Red Hat through
    /// <c>firewalld</c>, and a hand-rolled machine through <c>nftables</c> alone. A machine using
    /// none of the three reports not-observed rather than "off", because plenty of correctly
    /// firewalled machines sit behind a rule set none of these tools can see.
    /// </remarks>
    private static bool? LinuxFirewall(CollectionDeadline deadline)
    {
        string? ufw = CommandRunner.Run("/usr/sbin/ufw", ["status"], deadline.Clamp(_timeout));

        if (ufw is not null)
        {
            return ufw.Contains("Status: active", StringComparison.OrdinalIgnoreCase);
        }

        string? firewalld = CommandRunner.Run("/usr/bin/firewall-cmd", ["--state"], deadline.Clamp(_timeout));

        if (firewalld is not null)
        {
            return firewalld.Trim().Equals("running", StringComparison.OrdinalIgnoreCase);
        }

        string? nft = CommandRunner.Run("/usr/sbin/nft", ["list", "ruleset"], deadline.Clamp(_timeout));

        // An empty ruleset is an observed absence of filtering; a command that would not run at all
        // tells us nothing.
        return nft is null ? null : nft.Contains("chain", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Reads UEFI Secure Boot state straight from the EFI variable.
    /// </summary>
    /// <remarks>
    /// <b>Read from <c>/sys</c> rather than through <c>mokutil</c>, which is not installed by
    /// default on most distributions.</b> The variable's payload is a four-byte attribute prefix
    /// followed by one byte holding the flag; anything shorter than five bytes is a variable this
    /// parser does not understand, which reports <c>null</c>. A machine that booted without UEFI has
    /// no such file at all, which is also <c>null</c> — legacy BIOS boot means the question does not
    /// apply, not that Secure Boot is switched off.
    /// </remarks>
    private static bool? LinuxSecureBoot()
    {
        const string path =
            "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            byte[] value = File.ReadAllBytes(path);

            return value.Length >= 5 ? value[4] == 1 : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    /// <summary>
    /// Reads whether this machine has a TPM, and which version.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>"No TPM" and "we could not look" are different answers, and only one of them was being
    /// reported.</b> The flag was derived as <c>ReadFile(...) is not null</c>, and
    /// <see cref="CommandRunner.ReadFile"/> returns null both for a file that is not there and for
    /// one it was refused — so a sysfs node the agent could not open came back as a definite
    /// <c>false</c>: a machine reported as having no security processor when nobody had
    /// established that. <c>TpmPresent</c> is <c>bool?</c> on both the reading and the wire
    /// precisely so the third answer can be given, and <see cref="CommandRunner"/>'s own remarks
    /// state the rule — a reading that could not be taken is null, never a protection reported as
    /// absent.
    /// </para>
    /// <para>
    /// The directory is what separates them: <c>/sys/class/tpm/tpm0</c> exists if and only if the
    /// kernel bound a TPM driver, and it needs no read permission on the file inside to test.
    /// </para>
    /// </remarks>
    /// <returns>Whether a TPM is present, and its major version when that could be read.</returns>
    private static (bool? Present, string? Version) LinuxTpm()
    {
        const string device = "/sys/class/tpm/tpm0";

        string? major = CommandRunner.ReadFile($"{device}/tpm_version_major")?.Trim();

        if (!string.IsNullOrWhiteSpace(major))
        {
            return (true, major);
        }

        try
        {
            // No device node at all is an OBSERVED absence — this is the ordinary answer on a
            // virtual machine or an older board, and reporting it as unknown would lose a true
            // reading. A node that exists whose version we could not read is a TPM we can see and
            // cannot describe: present, version unknown.
            return Directory.Exists(device) ? (true, null) : (false, null);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // We could not even determine that much. Not observed.
            return (null, null);
        }
    }

    /// <summary>
    /// Reads when software was last installed, from the package database's modification time.
    /// </summary>
    /// <remarks>
    /// <b>A proxy, and recorded as one.</b> No Linux package manager keeps a queryable "last
    /// security update" timestamp, and asking the distribution's mirrors would mean a network round
    /// trip the agent will not make on a user's machine. The database's mtime moves whenever
    /// anything is installed or upgraded, so it answers the question Merlin's fallback patch rule
    /// actually asks — "has this machine stopped being maintained" — rather than the narrower one it
    /// cannot. It will read as current on a machine that installs unrelated packages and never
    /// patches; that is the limitation, and it is in the manifest.
    /// </remarks>
    private static DateTimeOffset? LinuxLastPackageChange()
    {
        string[] databases =
        [
            "/var/lib/dpkg/status",
            "/var/lib/rpm/rpmdb.sqlite",
            "/var/lib/rpm/Packages",
            "/var/lib/pacman/local",
        ];

        DateTimeOffset? newest = null;

        foreach (string path in databases)
        {
            try
            {
                if (!File.Exists(path) && !Directory.Exists(path))
                {
                    continue;
                }

                DateTimeOffset written = File.GetLastWriteTimeUtc(path);

                if (newest is null || written > newest)
                {
                    newest = written;
                }
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                // Unreadable is not "never updated" — skip it and let another database answer.
            }
        }

        return newest;
    }

    private static int? ParseCount(string value) =>
        int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed)
            ? parsed
            : null;

    /// <summary>
    /// Finds <c>&lt;key&gt; = &lt;integer&gt;</c> in a configuration file, ignoring comments.
    /// </summary>
    private static int? FindConfigInteger(string content, string key)
    {
        foreach (string raw in content.Split('\n'))
        {
            string line = raw.Trim();

            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            int separator = line.IndexOfAny(['=', ' ', '\t']);

            if (separator <= 0)
            {
                continue;
            }

            if (!line[..separator].Trim().Equals(key, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            string value = line[(separator + 1)..].Trim().TrimStart('=').Trim();
            int end = value.IndexOfAny([' ', '\t', '#']);

            if (end > 0)
            {
                value = value[..end];
            }

            int? parsed = ParseCount(value);

            if (parsed is not null)
            {
                return parsed;
            }
        }

        return null;
    }

    /// <summary>
    /// Finds the integer following a named key in <c>pwpolicy</c>'s plist output.
    /// </summary>
    /// <remarks>
    /// A scan rather than a plist parse: the agent is NativeAOT and pulling in a property-list
    /// reader for one integer would be a poor trade. Anything it does not recognise yields
    /// <c>null</c>, which is the correct answer for an unparsed format.
    /// </remarks>
    private static int? FindKeyedInteger(string content, string key)
    {
        int keyIndex = content.IndexOf(key, StringComparison.Ordinal);

        if (keyIndex < 0)
        {
            return null;
        }

        ReadOnlySpan<char> tail = content.AsSpan(keyIndex + key.Length);
        int start = -1;

        for (int index = 0; index < tail.Length; index++)
        {
            if (char.IsDigit(tail[index]))
            {
                start = index;
                break;
            }

            // A second key before any digit means this occurrence carried no value — give up rather
            // than reading a number belonging to a different setting.
            if (tail[index] is '<' && start < 0 && index > 0 && tail[..index].Contains("key>", StringComparison.Ordinal))
            {
                break;
            }
        }

        if (start < 0)
        {
            return null;
        }

        int length = 0;

        while (start + length < tail.Length && char.IsDigit(tail[start + length]))
        {
            length++;
        }

        return ParseCount(tail.Slice(start, length).ToString());
    }
}
