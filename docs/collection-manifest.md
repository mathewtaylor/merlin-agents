# Collection manifest

The complete list of what the agent reads lives in
[`packaging/queries/windows.json`](../packaging/queries/windows.json), as osquery SQL.

**That file is the authority, not this page.** It ships beside the executable, and
`merlin-agent status --manifest` prints it from the installed copy — so what an administrator reads
is what that machine actually runs, rather than what a document claims it runs.

Every query can be pasted into `osqueryi` and will produce identical output:

```powershell
& "C:\Program Files\Merlin Agent\osquery\osqueryi.exe" --json "SELECT * FROM bitlocker_info;"
```

## Reading it

Each entry carries `sql` and `purpose`. A query that fails or returns nothing produces a **null**
reading, never a false one — Merlin treats null as *not observed* and will not fail a control on it.

## Known gaps in v1

Recorded here rather than papered over:

- **Pending security updates are not counted.** osquery has no table for it, and the Windows Update
  COM API is a dependency this agent avoids. `patches` gives the date of the last installed update
  instead, and Merlin's patch check falls back to that age — which is observable and actionable,
  where an invented count would not be.
- **Password complexity is not read.** `net accounts` does not expose it; only `secedit /export`
  does, which writes a file containing far more of the security policy than is wanted. Minimum
  length and lockout threshold are read; complexity is reported as not observed, and Merlin's rule
  treats an unreported half as not-failing rather than inventing a `false`.
- **Antimalware signature age is inferred**, from the platform security centre's own verdict, rather
  than read directly. Where the centre says nothing, the reading is null.
- **Installed software is not collected.** Deliberate — see [privacy.md](privacy.md).

## Adding a platform

Add a pack (`macos.json`, `linux.json`) with the same entry shape and a normaliser alongside
`WindowsNormaliser`. Nothing in the transport, signing or enrolment path changes: that separation is
why collection is delegated to osquery in the first place.
