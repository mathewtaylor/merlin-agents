# Collection manifest

The complete list of what the agent reads lives in
[`packaging/queries/`](../packaging/queries/), as osquery SQL — one pack per platform:

| Platform | Pack |
|---|---|
| Windows | [`windows.json`](../packaging/queries/windows.json) |
| macOS | [`macos.json`](../packaging/queries/macos.json) |
| Linux | [`linux.json`](../packaging/queries/linux.json) |

**Those files are the authority, not this page.** All three ship beside the executable, and
`merlin-agent status --manifest` prints the one for the platform it is running on, from the
installed copy — so what an administrator reads is what that machine actually runs, rather than what
a document claims it runs.

Every query can be pasted into `osqueryi` and will produce identical output:

```powershell
& "C:\Program Files\Merlin Agent\osquery\osqueryi.exe" --json "SELECT * FROM bitlocker_info;"
```

```bash
/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryi --json "SELECT * FROM alf;"   # macOS
osqueryi --json "SELECT * FROM disk_encryption;"                                   # Linux
```

## Reading it

Each entry carries `sql` and `purpose`. A query that fails or returns nothing produces a **null**
reading, never a false one — Merlin treats null as *not observed* and will not fail a control on it.

## Read outside osquery

A handful of signals have no osquery table and are read directly. They are listed here because a
manifest covering only the packs would understate what the agent touches, which would make it a
worse promise than no manifest. `merlin-agent status --manifest` prints this list too.

| Platform | Source | What it gives |
|---|---|---|
| Windows | `net accounts` | Minimum password length, password history size, minimum and maximum password age, lockout threshold, lockout duration, lockout observation window |
| macOS | `pwpolicy -getaccountpolicies` | Minimum password length |
| Linux | `/etc/security/pwquality.conf`, `/etc/login.defs` | Minimum password length, complexity |
| Linux | `/sys/firmware/efi/efivars/SecureBoot-*` | Whether Secure Boot is enforced |
| Linux | `/sys/class/tpm/tpm0/tpm_version_major` | Whether a TPM is present, and its version |
| Linux | Package database mtime | When software was last installed |
| Linux | `ufw status` / `firewall-cmd --state` / `nft list ruleset` | Host firewall state |

None of these takes a username, touches a home directory, or is parsed for an identity. No value is
interpolated into a command line; arguments are passed as a list and no shell is involved.

## Known gaps

Recorded here rather than papered over. A gap means Merlin shows the signal as **not observed** — it
never becomes a pass or a failure.

### All platforms

- **Installed software is not collected.** Deliberate — see [privacy.md](privacy.md).

### Windows

- **Pending security updates are not counted.** osquery has no table for it, and the Windows Update
  COM API is a dependency this agent avoids. `patches` gives the date of the last installed update
  instead, and Merlin's patch check falls back to that age — which is observable and actionable,
  where an invented count would not be.
- **Password complexity IS read, and only a 0 or a 1 counts.** It comes from osquery's
  `security_profile_info`, which calls the SCE API behind `secedit` in process rather than running
  the CLI that would leave a file behind. osquery clamps SCE's "no value" sentinel to `-1`, so a
  machine whose policy could not be read reports `-1` and the agent sends null — never false, which
  would fail it against a value nobody measured. The numeric half of the policy is deliberately not
  taken from that table; see the query's own comment in `packaging/queries/windows.json`.
- **The `net accounts` labels are matched in English.** A localised Windows prints localised labels,
  every match misses, and the whole section reports null — not observed, which is the honest
  degradation rather than a wrong reading, but it does mean a non-English fleet gets no password
  policy at all. `NetUserModalsGet` returns the same seven values as a struct with no text to parse
  and is the proper fix.
- **Antimalware signature age is inferred**, from the platform security centre's own verdict, rather
  than read directly. Where the centre says nothing, the reading is null.

### macOS

macOS exposes materially less of its security posture at machine scope than Windows does, and
several of these gaps are structural rather than temporary.

- **The screen-lock idle interval is not observed, and usually neither is the screen lock at all.**
  osquery's `screenlock` table reads the *current logged-in user's* context, and the agent runs as
  root from a launch daemon, which has none — so it typically returns no rows. Even when it does, it
  reports `grace_period`, the delay after the screensaver starts, not the idle time before it does.
  Reporting that as the lock timeout would understate the machine's exposure, so it is not reported.
  Only "the screen never requires a password" is sent, as an observed failure.
- **Patch currency is not observed.** macOS exposes no pending-update count and no install history
  through osquery, and `softwareupdate --list` needs a network round trip the agent will not make on
  a user's machine.
- **Antimalware currency is not observed.** Gatekeeper's on/off state is read and is a genuine A.8.7
  signal, but XProtect definitions update through a channel with no locally readable "current"
  version to compare against. A third-party product on the machine is invisible to this reading.
- **The password policy is reported only when positively found.** A stock Mac enforces none, and it
  is tempting to report that as an observed zero — but `pwpolicy` exits successfully in several
  situations that are not "no policy" (a directory-bound Mac, an MDM profile expressing the rule
  another way, a format this parser does not recognise), so a zero would state a fact this reading
  cannot establish.
- **Secure Enclave presence is inferred from the CPU, and never reported absent.** Every
  Apple-silicon Mac has one; an Intel Mac may or may not have a T2 and no table exposes it, so an
  Intel Mac reports null rather than false.
- **Entra device id is not available.** A Mac can be Entra-registered through Company Portal, but
  the identifier lives in the login keychain. Fleet coverage falls through to the asset register.

### Linux

- **Encryption is reported as one machine-level reading, not per volume.** A fully encrypted install
  still has an unencrypted `/boot`, so passing the raw per-volume rows into Merlin's
  weakest-volume-wins reduction would report every correctly encrypted machine as unencrypted. The
  cost is that an encrypted root plus a genuinely unencrypted data volume also reports as encrypted.
- **The screen-lock interval is not observed.** It is a per-user desktop preference (GNOME, KDE)
  with no machine-scope equivalent on an unmanaged machine.
- **Antimalware is not observed at all.** There is no platform antimalware posture to read, and a
  machine running ClamAV or a commercial agent registers nowhere queryable.
- **"Last update installed" is a proxy** — the package database's modification time, which moves
  whenever anything is installed or upgraded. It answers "has this machine stopped being
  maintained", not "is it fully patched", and will read as current on a machine that installs
  unrelated packages and never patches.
- **Pending updates are not counted**, for the same reason as macOS: it needs a network round trip.
- **The host firewall is read from whichever front-end is installed.** A machine using none of
  `ufw`, `firewalld` or `nftables` reports not-observed rather than "off" — plenty of correctly
  firewalled machines sit behind a rule set none of those tools can see.

## Adding a platform

Add a pack with the same entry shape, a normaliser alongside `WindowsNormaliser` /
`MacOsNormaliser` / `LinuxNormaliser`, a branch in `AgentPlatformInfo`, and a matrix entry in the
build workflow. Nothing in the transport, signing or enrolment path changes: that separation is why
collection is delegated to osquery in the first place.

## What a slow machine gives up

A collection holds the agent's machine-wide lock for its whole duration, and the updater abandons
that lock after two minutes and reports contention — so every minute a sick osquery costs is a
minute in which nothing on the machine can put a broken agent back. The whole collection is
therefore bounded at 100 seconds (plus up to 10 seconds of pipe drain for a step killed at the
deadline), shared across the osquery version probe, the query pack and the host readings that
follow it. A healthy collection takes two or three seconds; nothing legitimate approaches the bound.

That bound covers the collection, not the whole lock hold: the report and the update turn are held
under the same lock, and the update legitimately includes a package download bounded at ten
minutes. A run may therefore exceed the updater's wait, which is by design — an updater that cannot
take the lock reports contention and tries again, whereas a download killed at two minutes would
make large packages permanently uninstallable on a slow link.

**When it is reached, whatever has not run is reported as NOT OBSERVED** — the same null a missing
table produces, never a negative reading. **The packs are therefore ordered security-posture first
and inventory last**, so what a slow machine gives up is its hostname and chassis type rather than
its disk encryption or its firewall. The order in `queries/<platform>.json` is the order they run
in, and `merlin-agent status --manifest` prints them in that order.
