# Merlin Agent

A small, open-source agent that reports a **Windows, macOS or Linux** machine's security posture to
a [Merlin](https://github.com/mathewtaylor/merlin) ISMS deployment, so an ISO 27001 auditor can be
shown evidence for disk encryption, antimalware, patching and endpoint hardening without anybody
taking screenshots.

**It is not MDM.** It configures nothing, enforces nothing, and has no remote-command channel. It
reads state and reports it.

**It reports facts about the MACHINE, never about the person using it.** There is no query for the
signed-in user, the session, files, browsing or network traffic — and no setting that adds one. See
[docs/privacy.md](docs/privacy.md), and run `merlin-agent status --manifest` on any machine to see
the complete list of what it reads.

---

## Install

One line. Your Merlin deployment serves the script and pins the SHA-256 of every binary it
downloads.

**Windows** — an elevated PowerShell prompt:

```powershell
& ([scriptblock]::Create((irm https://isms.example.com/agent/install.ps1))) -EnrolmentKey 'MRLN-...'
```

**macOS and Linux** — a root shell. One script serves both; it detects the platform and
architecture and fetches the matching package:

```bash
curl -fsSL https://isms.example.com/agent/install.sh | sudo sh -s -- --enrolment-key 'MRLN-...'
```

Get the enrolment key from **Admin → Merlin Agent** in Merlin, which shows the exact command for
each platform you have configured. The installer:

1. downloads and hash-verifies the agent and osquery,
2. enrols the machine (generating a signing key that never leaves it),
3. registers a scheduled task (Windows), launch daemon (macOS) or systemd timer (Linux) that
   collects every six hours, and a second one that checks daily for a new version,
4. runs one collection immediately, so the device appears straight away.

The device then waits for an administrator to approve it. Until approved it counts towards no
control.

**The agent learns where to report from the address it was installed from** — the script bakes in
the host that served it, so one binary works for every deployment with nothing to configure. If a
deployment later moves, `merlin-agent set-server` re-points a machine; it proves the new address
accepts a report before keeping it, so a typo cannot silently take the machine offline.

## Keeping itself up to date

**Two binaries that replace each other, and neither ever replaces itself.** `merlin-agent` runs
every six hours and replaces `merlin-updater`; `merlin-updater` runs daily and replaces
`merlin-agent`. Each can put the other's previous binary back if the one it installed does not run.

A single self-updating binary has one unrecoverable failure: if the image it swaps in cannot
execute, nothing is left running on the machine to put the old one back — and this agent is a
scheduled invocation, not a resident daemon, so that means silence until somebody visits it. Mutual
replacement is what makes recovery real rather than aspirational.

**Merlin only ever ADVERTISES.** The updater asks a read-only, device-signed endpoint what version
this machine should be running, and the whole answer is *a version, an address and a hash*. There is
no remote-command channel, no remote wipe and no auto-remediation — the server cannot reach a
machine that does not call it, and cannot make one do anything except move to a named version.
Whether anything is advertised at all is a setting in Merlin, so switching automatic updates on or
off never means visiting a machine.

Four things stand between an advertisement and a swap, and each is there for a failure that has
happened to somebody:

| | |
|---|---|
| **Compile-time host allowlist** | packages come only from the GitHub release hosts, whatever a deployment is configured to advertise. Server configuration alone cannot redirect a fleet. A self-hoster mirroring the binaries needs a rebuilt agent. |
| **SHA-256 verification** | the archive is checked against the digest Merlin pinned, before anything is extracted |
| **Execute before commit** | the staged binary is run once *while the working one is still in place*. This is what catches an antivirus quarantine, a wrong architecture or a missing library — none of which a hash can see. |
| **Never both in one run** | if the agent and the updater are both behind, one moves now and the other on a later run, after this one has proved itself |

**Rolling back is a pin.** An administrator pins a device — or the whole fleet — to an earlier
version and the updater downgrades it on its next run, provided that version's package entry is
still configured. Releases stage across rings so a bad one reaches one or two machines rather than
all of them.

**The outcome is reported, never inferred.** The next report carries the updater's version and what
the last swap did — `Succeeded`, `Failed` or `Reverted` — because a server watching only the agent
version cannot tell "updated and rolled back" from "never attempted", and a silent failed update is
the worst thing this can produce.

The residual case is both binaries broken at once — a release bad in both, or an antivirus engine
quarantining both. Nothing on the machine recovers from that and it needs a manual reinstall, which
is why staged rollout is not optional.

## Commands

```
merlin-agent enrol --server <url> --enrolment-key <key>
merlin-agent collect                 # what the scheduled task runs
merlin-agent status                  # both components, and the exact payload last sent
merlin-agent status --manifest       # every query this agent runs
merlin-agent set-server --server <url>
merlin-agent rotate-key
merlin-agent uninstall
merlin-agent --version               # the version string; also how the other component probes it

merlin-updater run                   # what the daily scheduled job runs; no-ops within 1 h of the last
merlin-updater run --now             # check immediately, bypassing that hour, and say what happened
merlin-updater status                # both components' versions and the last outcome
merlin-updater --version             # as above
```

`--version` is not cosmetic. Before either component commits a swap it EXECUTES the staged binary
with exactly this flag and reads the first line back — that is what catches an antivirus
quarantine, a wrong architecture or a missing dependency while the working binary is still in
place. Changing what it prints changes what the update mechanism believes is installed.

## How it works

**osquery does the collection; this agent does enrolment, signing and transport.** That split is
deliberate. osquery is a mature, widely-audited engine that already knows how to read BitLocker
state on a Windows Home laptop, and delegating to it means the collection manifest is *a list of
SQL* — an administrator can paste any query into `osqueryi` and get identical output. That is a far
stronger assurance than reading anybody's collector code.

**`osqueryi`, one-shot — never the `osqueryd` daemon.** The daemon's distinctive value is scheduled
query packs and evented tables, and nothing downstream reads either: Merlin records one check result
per day. So the agent shells out for about a second, six times a day, and exits.

**A scheduled run, not a service.** Zero resident footprint, no listening socket, and the binary is
never file-locked so an update is a swap. A crashed run fires again next interval instead of staying
dead and looking like a passing check. A machine-wide lock keeps the two components from ever
overlapping, so a swapper never touches a binary that is currently running.

**Each platform is read on its own terms.** macOS and Linux expose less of their security posture at
machine scope than Windows does, and the gaps are left as gaps rather than filled with guesses — a
signal that cannot be read is reported as *not observed*, which Merlin will not fail a control on.
[docs/collection-manifest.md](docs/collection-manifest.md) lists every one of them.

| | |
|---|---|
| Idle footprint | 0 MB, 0% CPU — no resident process |
| Active | ~2–3 s every 6 hours; each collection also takes an update turn, and the updater takes one daily |
| Install size | ~12 MB agent + ~7 MB updater + osquery |
| Platforms | Windows (Home, Pro, Enterprise, Server), macOS (Apple silicon), Linux |
| Architectures | `win-x64`, `osx-arm64`, `linux-x64`, `linux-arm64` |
| Runtime | none — single self-contained NativeAOT executable |

## Security

Every request is signed with an ECDSA P-256 key created on the machine at enrolment. On Windows it
is held in the **TPM and non-exportable** where one is available, and in a DPAPI-protected file
where it is not. On macOS and Linux it is held in a root-only file — this agent does not yet reach
the Secure Enclave or a TPM there, and **reports the attestation it actually has rather than the one
the hardware could support**. Merlin records which, and shows it against the device.

**A signature proves provenance, not truth.** It proves a report arrived intact from a holder of the
enrolled key. It does *not* prove the machine told the truth — a local administrator can modify this
agent and have it sign whatever they like. Every agent-based compliance product has this property;
[docs/security.md](docs/security.md) sets out what follows from it and what Merlin does instead of
pretending otherwise.

## Building

```bash
dotnet build                                    # any platform
dotnet test                                     # any platform — the core is platform-neutral
dotnet publish src/Merlin.Agent   -r osx-arm64 -c Release   # NativeAOT, this machine's architecture
dotnet publish src/Merlin.Updater -r osx-arm64 -c Release
```

Both binaries ship in **one archive per platform**, with one SHA-256, so they can never be on
versions that were never tested together. The swapper extracts only the component it is replacing.

**NativeAOT cannot be cross-compiled**, so each shippable binary is produced by CI on a runner of
that architecture.

**Intel Macs (`osx-x64`) are not currently published.** They need an Intel-hosted macOS runner and
cannot be built on Apple silicon; `macos-13` was the last GitHub-hosted Intel image and no longer
picks jobs up. The source builds for `osx-x64` unchanged — run the publish command above on an
Intel Mac if you need one — but no release asset is produced, so Merlin does not offer an Intel-Mac
install command. Restoring it means a self-hosted runner and putting the matrix entry back.

`Merlin.Agent.Core` targets `net10.0` and holds everything platform-neutral
— the wire contracts, the signature envelope, and all three osquery normalisers — so the logic that
decides what counts as *not observed* is testable on any machine, for every platform.

## Repository layout

```
src/Merlin.Agent.Core/     wire contracts · signature envelope · per-platform normalisers
                           device key · state file · the shared component-swap routine
src/Merlin.Agent/          osquery runner · host readers · transport · CLI
src/Merlin.Updater/        the companion updater — no osquery, no collection, one job
packaging/queries/         the collection manifests — the complete list of what is read
docs/                      protocol · security · privacy · collection manifest
```

`Merlin.Agent.Core` holds everything BOTH binaries need. The swap routine lives there for the same
reason: one implementation with two callers is what makes "neither component ever replaces its own
running image" a property of the code rather than of two places agreeing.

## Licence

Apache 2.0. osquery is redistributed under the same licence.
