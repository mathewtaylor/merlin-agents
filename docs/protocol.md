# Wire protocol

The contract between this agent and a Merlin deployment. Both halves are small and dependency-free
so that agreement between them is checkable by reading them side by side:

- client — `src/Merlin.Agent.Core/Crypto/AgentSignature.cs` (this repository)
- server — `Merlin.Endpoints.Application.Services.AgentSignature` (the Merlin repository)

Frozen vectors for the canonical strings live in `tests/Merlin.Agent.Core.Tests/AgentSignatureTests.cs`.
**If either side is "tidied" — a separator changed, a field reordered, a timestamp reformatted —
every agent in the field stops being able to report.** Those tests are what makes that a build
failure rather than a production outage.

---

## Envelope

Every request carries these headers:

| Header | Value |
|---|---|
| `Merlin-Device-Id` | the device GUID. Absent on enrolment. |
| `Merlin-Timestamp` | request instant, **Unix epoch seconds** |
| `Merlin-Nonce` | 128 bits, Base64Url |
| `Merlin-Signature` | Base64, ECDSA P-256 / SHA-256, IEEE P1363 (fixed 64-byte r‖s) |
| `Merlin-Agent-Version` | semver |

### The canonical string

```
report / rotate:   deviceId  \n  timestamp  \n  nonce  \n  sha256hex(body)
enrol:             "enrol"   \n  timestamp  \n  nonce  \n  sha256hex(body)
```

Joined with `\n` (0x0A). Signed as UTF-8. Three properties are load-bearing:

**The body hash is over the RAW BYTES.** The agent hashes exactly the bytes it is about to send; the
server hashes exactly the bytes it received. No JSON canonicalisation is involved anywhere. Any
scheme that re-encodes a payload before hashing creates a gap between what was signed and what will
be acted on.

**The timestamp is signed as the literal header characters.** Unix epoch seconds, invariant. Signing
a re-rendered timestamp would let two correct implementations disagree about whether an instant is
`...T07:00:00Z` or `...T07:00:00.000Z` and fail a signature for nobody's fault.

**The device id is bound in.** A signature captured from one device cannot be replayed against
another's endpoint. Enrolment uses a fixed context label in its place, which also domain-separates
the two signature kinds.

---

## `POST /api/agent/enrol`

`Authorization: Bearer <enrolment key>`, plus the envelope above with no device id.

The body announces the device's public key and hardware identity, and **is signed by that very key**
— proof of possession, so a caller cannot enrol a public key whose private half it does not hold.

```jsonc
{
  "publicKey": "MFkwEwYHKoZI...",   // Base64 SPKI DER, ECDSA P-256
  "keyAttestation": "Tpm",           // or "Software"
  "agentVersion": "0.1.0",
  "hostname": "LAPTOP-MT",
  "machineGuid": "…", "serialNumber": "…", "manufacturer": "…", "model": "…",
  "chassisType": "Laptop",
  "entraDeviceId": "…",              // null on a workgroup machine
  "entraTenantId": "…"
}
```

**200** → `{ deviceId, deviceCode, status, serverTime }`. `status` is normally `PendingApproval`.

Re-enrolling with the **same public key** updates the existing device rather than creating a second
one, so a re-run installer or a lost response cannot produce a duplicate.

## `POST /api/agent/report`

The posture payload. Every reading is nullable, and **`null` means NOT OBSERVED** — the agent omits
a value it could not read rather than substituting a default. A `false` invented on the device would
be indistinguishable, by the time it reached a control check, from a genuine observation that a
protection is disabled.

**202** on acceptance.

## `POST /api/agent/rotate`

`{ newPublicKey, keyAttestation }`, signed with the **outgoing** key. **204** on success.

---

## Refusals

Every rejection is **400** with one body:

```json
{ "message": "The request could not be accepted. …", "serverTime": 1786345200 }
```

The message is identical for every cause — unknown device, bad signature, stale timestamp, replayed
nonce, expired enrolment key, unapproved or retired device. Distinguishing them would tell a prober
which half of a forged request to fix and confirm whether a given device id exists. The real reason
is logged and audited server-side.

`serverTime` is the one thing safely returned: a machine with a wrong clock cannot otherwise
discover why it is refused, and it reveals nothing that the HTTP `Date` header does not. The agent
applies the offset and retries once when the difference exceeds 30 seconds.

**404** means the deployment does not have the agent surface switched on.

---

## Bounds

| | Default |
|---|---|
| Timestamp skew tolerance | ±300 s |
| Nonce cache window | the skew tolerance |
| Maximum body | 256 KB |
| Report cadence | every 6 h, jittered |
| Enrolment key lifetime | 30 days |

Replay defence is **timestamp plus nonce, not a counter.** A monotonic counter was rejected because
an agent that loses its state file but keeps its TPM key would restart at zero and be refused
forever — on an unmanaged fleet, one support call per machine, for a failure the user did nothing to
cause.
