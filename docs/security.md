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
| Preferred storage | TPM via CNG `Microsoft Platform Crypto Provider`, `ExportPolicy = None`, machine scope |
| Fallback | Software key, DPAPI `LocalMachine` scope |
| Reported to Merlin | `Tpm` or `Software`, on every enrolment |

**P-256 rather than Ed25519** because TPM support for it is universal and Ed25519's is not.

**The software fallback is not optional.** The organisations this agent is built for run consumer
hardware, and a machine with no usable TPM is common rather than exceptional. Refusing to enrol it
would leave it entirely unmonitored — strictly worse than monitoring it with a weaker key and saying
so. Merlin shows the attestation beside the device precisely so the difference is visible rather
than averaged away.

**Rotation** is authenticated by the *outgoing* key. A device that has lost its key cannot rotate
and must re-enrol, producing a second device row for an administrator to reconcile — the honest
outcome, since from Merlin's side an unrecoverable key is indistinguishable from a different
machine.

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

**Authenticode signing is an open item.** Unsigned, SmartScreen will warn on a SYSTEM-level security
agent — a poor first impression for an ISMS product, and worth resolving before wide distribution.

---

## 6. What the agent can reach

The agent runs as SYSTEM, which is what reading BitLocker state and the local security policy
requires. It makes outbound HTTPS requests to exactly one host — the Merlin deployment it enrolled
with, recorded in its state file — and listens on nothing.

It writes to two places: `%ProgramData%\Merlin Agent\state.json` (no secrets; readable by anyone
curious) and, on machines with no TPM, `device.key` (DPAPI-protected).
