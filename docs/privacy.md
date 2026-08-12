# Privacy

This agent runs on employees' machines. What it reads is a product decision, not an implementation
detail, so it is written down here and enforced in the code.

---

## The rule

**The agent reports facts about the MACHINE, never about the person using it.**

It does not read the signed-in user, the session, the console owner, or any mail address. There is
no configuration flag that turns that on, and no field on the wire that could carry it. Attributing
a device to a person is something an administrator does inside Merlin, later, by hand.

This is a *structural* property rather than a setting, and that distinction is the whole point: the
answer to "can it see what I'm doing?" is not "it is currently configured not to" — it is "it never
asks".

It is enforced three ways:

1. No collection manifest — Windows, macOS or Linux — contains a query for a user identity.
2. Every query that goes near a user field names the columns it wants, so the others are never
   returned to the agent at all. There are three such queries, and the restriction is enforced by
   the query rather than by the agent remembering to ignore what it was sent:
   - the Windows Entra join info, whose registry key also holds user-identifying values;
   - `disk_encryption` on **macOS and Linux**, which also carries `uid` and `user_uuid` — the
     person who unlocked the volume;
   - `screenlock` on macOS, which osquery resolves from the console user's own preferences and
     returns with no username, uid or session attached.
3. An architecture test in the Merlin repository fails the build if any wire contract gains a
   member named for a session, user, owner or email.

---

## What is collected

Signals a platform cannot expose at machine scope are simply not collected there, and Merlin shows
them as *not observed*. [collection-manifest.md](collection-manifest.md) lists every gap.

| Signal | Why | Annex A | Windows | macOS | Linux |
|---|---|---|---|---|---|
| Hostname, serial, manufacturer, model, chassis | Identify the machine; reconcile with the asset register | A.5.9 | ✓ | ✓ | ✓ |
| OS name, version, build, edition | Vendor support and patch state | A.8.8, A.8.19 | ✓ | ✓ | ✓ |
| Disk encryption | Lost-laptop protection | A.8.24, A.5.33 | per volume | whole machine | whole machine |
| Antimalware product and status | Malware protection | A.8.7 | ✓ | Gatekeeper only | — |
| Firewall state | Host network control | A.8.20, A.8.21 | per profile | ✓ | ✓ |
| Screen-lock inactivity timeout | Clear screen | A.7.7 | ✓ | — | — |
| Verified boot, security processor | Platform integrity | A.8.1, A.8.9 | Secure Boot, TPM | SIP, Secure Enclave | Secure Boot, TPM |
| Last update installed | Patch currency | A.8.8 | ✓ | — | proxy |
| Local administrator account names | Privileged access | A.8.2 | ✓ | ✓ | ✓ |
| Local password policy (minimum length, lockout) | Authentication | A.5.17, A.8.5 | ✓ | where set | ✓ |
| System volume free space | Capacity | A.8.6 | ✓ | ✓ | ✓ |
| Entra device and tenant id (where joined) | Fleet-coverage join key | A.5.9 | ✓ | — | — |

## What is not collected

**And no setting adds any of it:**

- who is signed in, the session, or any mail address
- file names, paths or contents
- browser history, bookmarks or extensions
- keystrokes, screenshots or screen contents
- document titles
- network traffic, DNS queries or visited hosts
- process command lines
- geolocation

**Installed-software inventory is deliberately held back.** It is genuinely useful for A.8.19, and
it is also the most privacy-sensitive item on the list — a list of everything on someone's machine
says a great deal about them. If it ships it will be an explicit per-deployment opt-in with its own
consent copy, not a quiet addition to the default manifest.

---

## The one item worth arguing about

**Local administrator account names.** These are the only person-shaped values the agent sends.

They are on the right side of the rule: they are *local account* names — machine configuration —
not the identity of whoever is signed in. And A.8.2 is materially weaker without them, because a
count tells an administrator there are four local administrators but not that one of them is
unexpected, which is the entire point of looking.

On Linux this means two queries rather than one — group membership *and* any account holding uid 0,
because a second root account is the more serious finding of the pair and belongs to no group.

They are flagged here, and in every manifest, rather than buried. Dropping to a count-only form is a
one-line change to the query pack for a deployment that prefers it.

---

## Seeing it for yourself

On any machine with the agent installed:

```
merlin-agent status              # the exact payload last sent, verbatim
merlin-agent status --manifest   # every query the agent runs, on this platform
```

The manifest command also lists the handful of readings taken outside osquery, because a list
covering only the query packs would understate what the agent touches.

The manifest is a list of SQL. Paste any of it into `osqueryi` and you will get identical output.
That is deliberately stronger than "read the source and trust it" — it is checkable by somebody who
does not read C#.

---

## For the organisation deploying this

Two things worth doing before rollout, neither of which the software can do for you:

- **Tell people it is being installed, and what it reads.** This page is written to be forwarded.
- **Record the lawful basis.** In most jurisdictions endpoint security monitoring of corporate
  devices rests on legitimate interests, and the assessment is materially easier when the collection
  boundary is this narrow and this checkable. Merlin's Privacy module is where that record belongs.
