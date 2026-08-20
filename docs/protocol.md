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

## Addressing

The agent stores the base address it was installed from and appends the fixed relative paths below.
It treats that base as **opaque**, so the server may qualify it without the agent knowing anything
about tenancy:

```
https://acme.merlinassure.com                 subdomain-per-tenant — the planned model
https://app.merlinassure.com/t/acme           reserved, for one shared hostname over
                                              database-per-tenant
```

Both are served. The second exists because the ingest resolves a device by `Merlin-Device-Id`, and
under a shared hostname it would have to choose a tenant's database *before* it could look that
device up. A mismatched slug is **404**, not a refusal — a routing error rather than an
authentication failure.

**The stored address is effectively permanent**, which is why the shape is fixed now: an agent uses
it forever, and changing it later means re-pointing every machine. `merlin-agent set-server` is the
escape hatch, and it proves the new address before keeping it.

## Envelope

Every request carries these headers:

| Header | Value |
|---|---|
| `Merlin-Device-Id` | the device GUID. Absent on enrolment. |
| `Merlin-Timestamp` | request instant, **Unix epoch seconds** |
| `Merlin-Nonce` | 128 bits, Base64Url |
| `Merlin-Signature` | Base64, ECDSA P-256 / SHA-256, IEEE P1363 (fixed 64-byte r‖s) |
| `Merlin-Agent-Version` | semver |
| `Merlin-Agent-Rid` | this machine's runtime identifier. **Update check only.** |

### The canonical string

```
report / rotate:   deviceId  \n  timestamp  \n  nonce  \n  sha256hex(body)
enrol:             "enrol"   \n  timestamp  \n  nonce  \n  sha256hex(body)
update:            "update"  \n  deviceId   \n  timestamp  \n  nonce  \n  rid
```

Joined with `\n` (0x0A). Signed as UTF-8. Four properties are load-bearing:

**The body hash is over the RAW BYTES.** The agent hashes exactly the bytes it is about to send; the
server hashes exactly the bytes it received. No JSON canonicalisation is involved anywhere. Any
scheme that re-encodes a payload before hashing creates a gap between what was signed and what will
be acted on.

**The timestamp is signed as the literal header characters.** Unix epoch seconds, invariant. Signing
a re-rendered timestamp would let two correct implementations disagree about whether an instant is
`...T07:00:00Z` or `...T07:00:00.000Z` and fail a signature for nobody's fault.

**The device id is bound in.** A signature captured from one device cannot be replayed against
another's endpoint. Enrolment uses a fixed context label in its place, which also domain-separates
the signature kinds — and the update check carries BOTH, so an update-check signature can never be
presented as a report signature for a device whose id happened to be the literal `update`.

**The update check has no body hash and signs the runtime identifier instead.** It is a `GET`, so
there is nothing to hash; and the runtime identifier decides which architecture's binary is
advertised, so leaving it outside the signature would let anything between the machine and Merlin
change which package the machine is pointed at. Where the machine's architecture is one nothing is
built for, the field is signed as an EMPTY string rather than omitted — the server joins
`rid ?? ""`, so a missing field would produce a string it cannot reconstruct and the machine would
be refused instead of told there is nothing for it.

---

## `POST /api/agent/enrol`

`Authorization: Bearer <enrolment key>`, plus the envelope above with no device id.

The body announces the device's public key and hardware identity, and **is signed by that very key**
— proof of possession, so a caller cannot enrol a public key whose private half it does not hold.

```jsonc
{
  "publicKey": "MFkwEwYHKoZI...",   // Base64 SPKI DER, ECDSA P-256
  "keyAttestation": "Tpm",           // or "Software"
  "agentVersion": "0.2.0",
  "platform": "Windows",             // or "MacOs", "Linux"
  "hostname": "LAPTOP-MT",
  "machineGuid": "…", "serialNumber": "…", "manufacturer": "…", "model": "…",
  "chassisType": "Laptop",
  "entraDeviceId": "…",              // null on a workgroup machine, and on macOS and Linux
  "entraTenantId": "…"
}
```

**200** → `{ deviceId, deviceCode, status, serverTime }`. `status` is normally `PendingApproval`.

Re-enrolling with the **same public key** updates the existing device rather than creating a second
one, so a re-run installer or a lost response cannot produce a duplicate.

### `platform`

Added in 0.2, and **Merlin must not infer it**. Every criterion that differs by operating system —
which end-of-support table applies, whether an edition means anything, what "Secure Boot" names — is
resolved from this field and nothing else.

An agent older than 0.2 omits it, and Merlin reads the absence as `Unknown` rather than as
`Windows`. The pre-0.2 agents were indeed Windows-only, so the fallback would be *correct today*;
it is refused because encoding it makes an ageing assumption load-bearing, and the cost of the
honest answer is one agent upgrade. A device reporting `Unknown` keeps reporting every other signal
and shows its platform as not observed.

## `POST /api/agent/report`

The posture payload, carrying `platform` alongside the readings. Every reading is nullable, and
**`null` means NOT OBSERVED** — the agent omits a value it could not read rather than substituting a
default. A `false` invented on the device would be indistinguishable, by the time it reached a
control check, from a genuine observation that a protection is disabled.

Three fields carry a platform-dependent meaning, and it is the same criterion in each case rather
than three that can drift apart:

| Field | Windows | macOS | Linux |
|---|---|---|---|
| `hardening.firewallAllProfilesEnabled` | every profile on | application firewall on | `ufw` / `firewalld` / `nftables` active |
| `hardening.secureBootEnabled` | UEFI Secure Boot | System Integrity Protection | UEFI Secure Boot |
| `hardening.tpmPresent` | TPM present and enabled | Apple Secure Enclave | TPM present |

Two further fields are about the agent itself rather than the machine:

| Field | Meaning |
|---|---|
| `updaterVersion` | the companion updater's version, or `null` when it is absent or would not run |
| `lastUpdateOutcome` | `Succeeded`, `Failed`, `Reverted`, or `null` when nothing has been attempted |

**The outcome is REPORTED, never inferred.** A server watching only `agentVersion` cannot tell
"updated and rolled back" from "never attempted", because both leave the version unmoved — and a
silent failed update is the worst thing auto-update can produce. `Reverted` is deliberately distinct
from `Failed`: a revert means a bad binary reached the machine and was survived, which is the case a
staged rollout exists to catch, whereas `Failed` means nothing was replaced at all.

**202** on acceptance.

## `GET /api/agent/update`

The only READ on this surface, and the only thing Merlin ever says to a machine that looks
unprompted. Device-signed with the `update` canonical string above, no body, and it changes nothing
about the device.

**200** — the version this device should be running:

```json
{ "version": "0.3.0", "packageEndpoint": "https://github.com/…/merlin-agent-win-x64.zip",
  "sha256": "…" }
```

**A version, an address and a hash. Nothing else, ever.** There is no verb, no arguments, no path,
no script and nothing the machine dispatches on. The moment the response can say anything except
"the version you should be running is X, here, with this hash", this is a remote-command channel
wearing a different hat — which the agent does not have and is not getting.

**204** — nothing to do. The machine is already where it should be, its rollout ring is not due yet,
or the deployment has named no version at all. **This is the ORDINARY answer and is never an
error.** Treating it as one would have a healthy fleet reporting a broken update every day.

**404** — this deployment does not offer updates: an older Merlin, or the agent surface switched
off. The machine keeps reporting exactly as before.

The agent applies two guards to whatever comes back, and neither is negotiable:

- **A compile-time host allowlist**, checked before a single byte is fetched and re-checked on the
  final address after redirects. Merlin has its own allowlist, but that catches a typo and nothing
  else — whoever can set `packageEndpoint` can set the server's allowlist beside it. Baking the list
  into the binaries is what means **server configuration alone cannot redirect a fleet**. It pins
  the distribution channel where a signature would pin the publisher, and is weaker than signing.
- **The staged binary is EXECUTED once before the running one is replaced.** A digest proves the
  bytes arrived intact and says nothing about whether they run on this machine; a quarantine, a
  wrong architecture and a missing library all fail here, with the working binary still in place.

## `POST /api/agent/rotate`

`{ newPublicKey, keyAttestation }`, signed with the **outgoing** key. **204** on success.

The agent persists the incoming key only after this call succeeds, so a refused rotation leaves the
machine reporting exactly as before. A TPM-held key is not rotated at all — see
[security.md](security.md) § 2.

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
| Update-check cadence | daily, jittered by up to 2 h |
| Maximum package archive | 256 MB |
| Silence before a replaced agent is put back | 24 h — four missed collections |
| Silence before a replaced updater is put back | 72 h — three missed checks |
| Corroboration required before either is put back | one completed run by the OTHER component, after the swap |
| Enrolment key lifetime | 30 days |

**A component that was replaced and has not run since is not replaced AGAIN**, however far behind
it is. Stacking an unproven swap on an unproven one restarts the window a revert is timed from, so
the revert never fires; and only the immediately preceding binary is retained, so the second swap
overwrites the last copy known to have worked and leaves recovery restoring something that never
ran either. An antivirus engine that quarantines the installed binary but not the freshly
downloaded one produces exactly this, daily and for ever. The rule is what keeps the retained
binary one that has actually executed on this machine.

**A window on its own is not evidence, because wall clock passes while a laptop is shut.** A
machine closed straight after a swap comes back with the window long expired and the replaced
binary — which is perfectly good — never having run, which is indistinguishable from a broken one.
So a revert also requires that the component asking the question completed a run of its OWN after
the swap: that is what says the machine was actually up while the other one stayed silent. It costs
up to one extra updater run before a genuinely broken agent is put back, and a few hours the other
way round since the agent runs four times as often. The alternative is worse than slow: a revert
records the version it undid and that version is never installed on that device again, so a false
revert strands the machine a version behind until somebody re-pins it by hand.

Replay defence is **timestamp plus nonce, not a counter.** A monotonic counter was rejected because
an agent that loses its state file but keeps its TPM key would restart at zero and be refused
forever — on an unmanaged fleet, one support call per machine, for a failure the user did nothing to
cause.
