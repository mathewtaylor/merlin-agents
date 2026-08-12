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
   collects every six hours,
4. runs one collection immediately, so the device appears straight away.

The device then waits for an administrator to approve it. Until approved it counts towards no
control.

**The agent learns where to report from the address it was installed from** — the script bakes in
the host that served it, so one binary works for every deployment with nothing to configure. If a
deployment later moves, `merlin-agent set-server` re-points a machine; it proves the new address
accepts a report before keeping it, so a typo cannot silently take the machine offline.

## Commands

```
merlin-agent enrol --server <url> --enrolment-key <key>
merlin-agent collect                 # what the scheduled task runs
merlin-agent status                  # the exact payload last sent
merlin-agent status --manifest       # every query this agent runs
merlin-agent set-server --server <url>
merlin-agent rotate-key
merlin-agent uninstall
```

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
dead and looking like a passing check.

**Each platform is read on its own terms.** macOS and Linux expose less of their security posture at
machine scope than Windows does, and the gaps are left as gaps rather than filled with guesses — a
signal that cannot be read is reported as *not observed*, which Merlin will not fail a control on.
[docs/collection-manifest.md](docs/collection-manifest.md) lists every one of them.

| | |
|---|---|
| Idle footprint | 0 MB, 0% CPU — no resident process |
| Active | ~2–3 s every 6 hours |
| Install size | ~12 MB agent + osquery |
| Platforms | Windows (Home, Pro, Enterprise, Server), macOS, Linux |
| Architectures | `win-x64`, `osx-arm64`, `osx-x64`, `linux-x64`, `linux-arm64` |
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
dotnet publish src/Merlin.Agent -r osx-arm64 -c Release   # NativeAOT, this machine's architecture
```

**NativeAOT cannot be cross-compiled**, so each shippable binary is produced by CI on a runner of
that architecture — including `osx-x64`, which needs an Intel-hosted macOS runner and cannot be
built on Apple silicon. `Merlin.Agent.Core` targets `net10.0` and holds everything platform-neutral
— the wire contracts, the signature envelope, and all three osquery normalisers — so the logic that
decides what counts as *not observed* is testable on any machine, for every platform.

## Repository layout

```
src/Merlin.Agent.Core/     wire contracts · signature envelope · per-platform normalisers
src/Merlin.Agent/          key stores · osquery runner · host readers · transport · CLI
packaging/queries/         the collection manifests — the complete list of what is read
docs/                      protocol · security · privacy · collection manifest
```

## Licence

Apache 2.0. osquery is redistributed under the same licence.
