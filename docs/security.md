# Security model

Written for the person who has to defend this to an auditor, and for the person deciding whether to
let it onto their machine.

---

## 1. What a signature proves, and what it does not

Every request the agent sends is signed with an ECDSA P-256 key generated on the machine at
enrolment. The private half never leaves.

**It proves provenance.** A report that verifies came from a holder of that key and was not altered
in transit. An attacker who cannot obtain the key cannot forge a report for that device, cannot
replay an old one outside a five-minute window, and cannot tamper with one in flight.

**It does not prove truth.** The agent signs whatever it collected. A local administrator on that
machine can modify the agent, intercept the osquery process, or point it at a fake provider, and the
result is a perfectly valid signature over a lie.

This is inherent to *all* agent-based compliance monitoring — Vanta, Drata and Kandji have exactly
the same property. The difference is that Merlin says so: it appears in the rationale of every
agent-backed check, and on the device page in the product.

### What follows from it

Three things, in descending order of strength:

1. **TPM-held keys narrow it.** Where a TPM is available the key is created inside it with
   `ExportPolicy = None`, so it cannot be extracted even by an administrator on that machine. A
   report signed with such a key provably came from *that physical device* rather than from an
   attacker's box replaying its identity. It still does not stop the legitimate holder lying.
2. **Coverage is a first-class check.** The cheapest attack on any agent system is not to run it, so
   Merlin compares the reporting fleet against a source the agent does not control — Entra
   registered devices, or the asset register — and reports a machine that is *not* reporting as a
   failing control. With no independent source available it reports **not observed**, never full
   coverage.
3. **Divergence is visible.** Where a second observer exists, disagreement between it and the agent
   is itself the signal, and Merlin shows both rather than reconciling them silently.

### What is deliberately not built

Remote attestation of the agent binary, anti-tamper, and process protection. Each is defeatable by
the same local administrator, and each makes the agent heavier and harder to audit — trading the
property actually being sold (you can read this code) for the appearance of one.

---

## 2. Keys

| | |
|---|---|
| Algorithm | ECDSA P-256, SHA-256, IEEE P1363 signatures |
| Reported to Merlin | `Tpm` or `Software`, on every enrolment |

| Platform | Storage | Attestation reported |
|---|---|---|
| Windows | TPM via CNG `Microsoft Platform Crypto Provider`, `ExportPolicy = None`, machine scope | `Tpm` |
| Windows (no usable TPM) | File, DPAPI `LocalMachine` scope | `Software` |
| macOS | File in `/Library/Application Support/Merlin Agent`, mode `0600`, root-owned | `Software` |
| Linux | File in `/var/lib/merlin-agent`, mode `0600`, root-owned | `Software` |

**P-256 rather than Ed25519** because TPM and Secure Enclave support for it is universal and
Ed25519's is not.

**Only Windows currently reaches a hardware key store, and that is a limitation of this agent
rather than of the hardware.** Apple silicon has a Secure Enclave and most Linux machines have a
TPM 2.0; both can hold a non-exportable P-256 key. Reaching them means P/Invoking
`Security.framework` and speaking to `/dev/tpmrm0` respectively, neither of which .NET exposes, so
it is not built yet. **The attestation reported is a statement about where the key actually is, not
about what the machine is capable of** — a Mac reporting `Tpm` while holding its key in a file would
be exactly the unearned assurance this design refuses everywhere else. Merlin shows the difference
against each device.

**On macOS and Linux the key is protected by file permissions, not by encryption at rest.** There is
no DPAPI equivalent worth the name: the Keychain and the kernel keyring both hold the key under the
same root identity the agent already runs as, so encrypting with them would protect it from an
attacker who is by construction already root and can read the process's memory. Saying "0600,
root-owned" is the accurate description; calling it "encrypted at rest" would be theatre. The
permissions are applied when the file is created, not afterwards, so the key is never briefly
world-readable.

**The software fallback is not optional.** The organisations this agent is built for run consumer
hardware, and a machine with no usable TPM is common rather than exceptional. Refusing to enrol it
would leave it entirely unmonitored — strictly worse than monitoring it with a weaker key and saying
so. Merlin shows the attestation beside the device precisely so the difference is visible rather
than averaged away.

**Rotation** is authenticated by the *outgoing* key, and the incoming key is written only after
Merlin has accepted it — a refused rotation leaves the machine reporting exactly as before. A device
that has lost its key cannot rotate and must re-enrol, producing a second device row for an
administrator to reconcile: the honest outcome, since from Merlin's side an unrecoverable key is
indistinguishable from a different machine.

**A TPM-held key cannot be rotated in place, and the command refuses rather than downgrading.** Its
value is that it is non-exportable and lives under one fixed container name, so the outgoing and
incoming keys cannot both exist; the obvious shortcut — replacing it with a software key — would
quietly turn the strongest evidence Merlin holds about a machine into the weakest without anyone
deciding to. Re-enrolling is the supported path.

---

## 3. The wire

Full specification in [protocol.md](protocol.md). The security-relevant properties:

- **The signature covers a hash of the raw request bytes**, never a re-serialised object. Any scheme
  that re-encodes a payload before hashing opens a gap between what was signed and what will be
  acted on, which is a well-worn source of signature-bypass bugs.
- **Replay is bounded by timestamp plus nonce**, not a counter. A ±5-minute window makes a captured
  request useless outside it, and a per-device nonce cache covers the window itself. A monotonic
  counter was rejected: an agent that loses its state file but keeps its TPM key would restart at
  zero and be refused forever, which on an unmanaged fleet is one support call per machine.
- **Clock skew is corrected, not fatal.** Merlin returns its own time when it refuses a request; the
  agent applies the offset and retries once, then persists it. The observed skew is stored on the
  report, because a machine drifting minutes is a mild hygiene signal in its own right.
- **Every rejection returns one generic message.** Unknown device, bad signature, stale timestamp,
  replayed nonce, expired enrolment key, unapproved device — all identical. Distinguishing them
  would tell a prober which half of a forged request to fix and confirm whether a device id exists.
  The real reason is logged and audited server-side.
- **The body is capped** (256 KB by default) and read with the cap enforced *while* reading, since
  `Content-Length` is caller-controlled and absent under chunked encoding.

---

## 4. Enrolment

An enrolment key is a **bearer credential**, and the design does not pretend otherwise: anyone
holding one can enrol a fabricated device. Four things bound that, and the fourth is the one that
matters:

1. a short expiry (30 days by default),
2. an optional use cap,
3. revocation,
4. **an enrolled device lands `PendingApproval` and counts towards nothing** until a human approves
   it.

Auto-approval exists for the "walk round the office with a USB stick" afternoon and defaults **off**.
Left on, a leaked key silently adds fabricated machines to the fleet.

The enrolment request is also **signed by the very key it announces**, so a caller cannot enrol a
public key whose private half it does not hold.

---

## 5. Installation integrity

The install script is served over TLS by the customer's own Merlin deployment and **pins the SHA-256
of every binary it downloads**, verifying before executing anything. A compromised release host
therefore cannot ship a different agent to a given deployment.

**Code signing is an open item on every platform.** Unsigned, Windows SmartScreen warns on a
SYSTEM-level security agent, and macOS Gatekeeper refuses a quarantined binary outright. The install
script clears the quarantine attribute from the download it made itself — which covers the scripted
install, and deliberately nothing else: a binary a user downloaded by hand still needs clearing by
hand, because the script vouches only for what it verified against a pinned hash. Signing (Azure
Trusted Signing for Windows, an Apple Developer ID for macOS) is worth resolving before wide
distribution.

### Unattended updates

The same reasoning applies with more weight once a machine can replace its own binaries without
anyone present, and **`merlin-updater` is now the higher-value target of the two** — it is the
process that replaces a SYSTEM binary. Four properties bound it:

1. **Merlin advertises; it never pushes.** The whole response is a version, an address and a hash.
   There is no verb the machine dispatches on, and the server cannot reach a machine that does not
   call it.
2. **A compile-time host allowlist in both binaries.** Packages are fetched only from the GitHub
   release hosts, whatever a deployment is configured to advertise, and the final address is
   re-checked after redirects. A SERVER-side allowlist would protect nothing against the threat it
   names — whoever can set the address can set the allowlist beside it — so the list is baked in and
   **server configuration alone cannot redirect a fleet**. This pins the distribution CHANNEL where
   a signature pins the PUBLISHER, and is weaker than signing: anyone who can publish a release on
   those hosts is trusted by it. The cost is that mirroring the binaries elsewhere needs a rebuilt
   agent.
3. **The staged binary is executed once before the running one is replaced.** A digest proves the
   bytes arrived intact and says nothing about whether they run here.
4. **Neither component ever replaces its own running image**, so whatever a bad release breaks,
   something on the machine is still running that can put the previous binary back. A component
   that has been replaced and not yet seen to run is not replaced again either — the retained copy
   is only ever one binary deep, so a second unproven swap would discard the last one known to
   work.

The residual is both binaries broken at once — a release bad in both, or an antivirus engine
quarantining both. Nothing on the machine recovers and it needs a manual reinstall; staged rollout
is what bounds that to one or two machines instead of the fleet, and is not optional for that
reason.

---

## 6. What the agent can reach

The agent runs with administrative rights — SYSTEM on Windows, root on macOS and Linux — which is
what reading disk-encryption state and the local security policy requires. It makes outbound HTTPS
requests to exactly one host — the Merlin deployment it enrolled with, recorded in its state file —
and listens on nothing.

It makes one further outbound request, on the updater's daily schedule: a signed `GET` to the same
deployment asking what version it should be running, and — only if it is told a different one — a
download from an allowlisted release host. Nothing else is contacted, ever.

It writes to that same directory per platform:

| Platform | Directory |
|---|---|
| Windows | `%ProgramData%\Merlin Agent` |
| macOS | `/Library/Application Support/Merlin Agent` |
| Linux | `/var/lib/merlin-agent` |

`state.json` holds no secret and is readable by anyone curious — that is the point of it, and it is
what `merlin-agent status` prints. It also records what each component is running, when each last
ran, and what the last swap did, which is what makes an unattended update inspectable on the machine
rather than only in Merlin. `device.key` exists only where the key is software-held, and is
protected as described in § 2. `merlin-agent.lock` is what keeps the two components from ever
running at once, and a `staging/` directory is used and removed during a swap.

**The updater uses the agent's identity, not a second one.** Same state file, same device key, same
directory, same privilege. A second enrolment would put a second credential at rest on every machine
for no gain.
