# Claude SMR — #1917 increment B plan v1, round 1

**Verdict: PLAN-NEEDS-REVISION** (no kill; the A1+B1+C1+D1 direction is
sound and endorsed, but one confirmed ordering race + three
under-specified items must be folded before PLAN-READY).

## Confirmed load-bearing facts (verified against code)

- No re-attach: `ensureProcessLocked` spawns a fresh helper and clears the
  XSKMAP (`process.go:24/64-71`). A standalone cut IS a multi-second gap.
  Plan §3 states this honestly. ✔
- Fatal-on-parse floor is real and unshipped: `daemon_run.go:190`
  `slog.Warn("failed to load config from db")` then `:197`
  `bootstrapFromFile()`. Plan §6.4 owns the fix. ✔
- HA drain hooks exist: `ForceSecondary()`/`ResetFailover()`
  (`failover.go:121/148`). ✔

## BLOCKING — B1 (confirmed ordering race, not just an open question)

**The respawn-mismatch window is REAL and the plan under-states it as
"closed structurally by the matched-set lockstep."** It is NOT closed by
lockstep alone. Worked counter-example:

- `findBinary` (`process.go:168-191`) resolves the helper via
  `filepath.Join(filepath.Dir(os.Args[0]), "xpf-userspace-dp")`. Go does
  NOT resolve symlinks in `os.Args[0]`, so for a daemon launched as
  `/usr/local/sbin/xpfd` (the live symlink), `dir(os.Args[0])` is
  `/usr/local/sbin` and the helper resolves to
  `/usr/local/sbin/xpf-userspace-dp` — the FLIPPED symlink.
- A LIVE old xpfd respawns its helper on TWO triggers that fire
  independently of the cut: helper ping unhealthy → restart
  (`process.go:33-35`), and a binding-plan change → `stopLocked()` +
  `ensureProcessLocked()` (`process.go:307-316`).
- Therefore: if `xpf-upgrade` flips the symlinks (state FLIPPED) and the
  old xpfd respawns its helper BEFORE its own `systemctl restart`
  (state RESTARTED), the old (version-N) xpfd spawns the version-(N+1)
  helper → `ProtocolVersion` mismatch (`protocol.go:11` =3 vs a future 4)
  AND/OR an XSKMAP/state churn under a daemon that thinks it is still N.

This is a data-corruption-class window. The lockstep guarantees xpfd and
helper SHIP together; it does NOT guarantee a RUNNING xpfd resolves the
helper of its OWN version once the shared symlink is flipped. The plan
MUST adopt one of (and say which):

1. **Versioned `ExecStart`** (Option A2, currently folded as a vague
   "hardening"): launch xpfd as
   `/var/lib/xpf/versions/<ver>/xpfd` so `dir(os.Args[0])` is the
   version dir and a respawn resolves the MATCHING-version helper, never
   the flipped symlink. This structurally closes the race. The symlink
   flip then only affects `cli`/day-0 (operator tools), not the running
   daemon's helper resolution. **This should be the recommended design,
   not a footnote.**
2. OR flip-AFTER-stop ordering: `systemctl stop xpfd` → flip → start. But
   that widens the gap (stop before the new binary is even live) and does
   not protect against the binding-plan respawn during the window between
   flip and the daemon noticing — versioned ExecStart is cleaner.

The increment-A postinst comment already anticipates this ("a running old
xpfd that respawns its helper would resolve the NEW helper (protocol
mismatch)"). The plan must resolve it, not restate it as OQ#2.

## BLOCKING — verify-dataplane isolation (OQ#4 must be answered IN the plan)

The plan asserts verify runs "without disturbing the LIVE dataplane"
because it loads anonymous maps with no attach. That needs proof in the
plan, not an open question, because `verify_userspace_shim.go` and the
helper share named/pinned resources. The plan must state explicitly: the
verify path (a) creates NO pinned maps under the live pin dir, (b) opens
NO live control socket / event socket / state file, (c) runs the
candidate xpfd's verify subcommand in a mode that touches only anonymous
collections. If the candidate `versions/<ver>/xpfd --verify-dataplane`
shares the live control-socket path or state-file path by default, the
gate is unsafe. Pin this down (likely: pass a throwaway
`--control-socket`/`--state-file` to the verify invocation).

## BLOCKING — config envelope: WHERE does it live, and does it gate rollback?

§6.4 says the envelope carries min-reader/schema versions but does not say
whether it is embedded in `active.json` (rev-8 codex-review-010's
resolution) or a sidecar manifest. rev-8 converged on EMBED-in-active.json
via an old-reader-rejecting encoding. Plan v1 must state that explicitly
and reconcile with `readTree` (`db.go:124` `json.Unmarshal(data, tree)`):
a top-level JSON array or `#`-magic header makes that `Unmarshal` ERROR
(fail closed), whereas an object empty-loads. Also: §6.1 auto-rollback
(state RESTARTED→re-flip previous) must be GATED on "the new version did
not advance the state-format floor" — else rolling back the binary
strands a forward-format `active.json` the previous binary can't read.
rev-8 had this gate; plan v1 dropped it. Re-add.

## MINOR / fold

- §6.2 step 5 "verify the upgraded node forwards while still passive" is
  hand-wavy — specify the probe (synthetic flow through the secondary
  path, or a brief promote-check). The `make test-failover` harness
  already drives iperf3; reuse it.
- §6.3 disk-full mid-COPY (OQ#7): the COPY state must pre-check free space
  ≥ size(staged) and fail BEFORE mutating, so a full disk aborts in
  COPIED-not-reached, never a half-copied version dir.
- N=3 retention is fine; just assert GC never runs before COMMITTED.

## Endorsed without change

- The honest multi-second standalone gap framing + M-mech-2 deferral.
- B1 controlled-drain over B2 naive restart; B3 image-replace fallback on
  session-sync break.
- C1 dogfood with `XPF_DEPLOY_FAST` escape + build-outside-lock.
- D1 fatal-on-parse + old-reader-rejecting envelope as the FLOOR release.
