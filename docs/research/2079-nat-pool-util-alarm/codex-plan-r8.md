# Codex hostile plan review r8 — #2079

Agent: ac521b4e53a237581 (~4.5 min). Dispatched against r8; read the on-disk r9
(noted in its NIT #4).

## Verdict: PLAN-REVISE (2 MAJOR + 1 MINOR + 1 NIT)

### MAJOR #1/#2 — the r9 `HelperCaughtUp == lastSnapshot.Generation` is TOO STRICT
`BumpFIBGeneration` advances `m.lastSnapshot.Generation` (`manager.go:1163-1166`)
but sends only `bump_fib_generation`; the helper updates only
`last_fib_generation` there (`snapshot.rs:164`) and sets `last_snapshot_generation`
ONLY on a full `apply_snapshot` (`snapshot.rs:63`). Likewise
`RegenerateNeighborSnapshot` bumps generation + publishedSnapshot
(`manager.go:1305-1312`) while Rust `update_neighbors` doesn't bump
`last_snapshot_generation` (`neighbors.rs:32-33`), and content-dedup no-ops
advance `publishedSnapshot` without an apply (`process.go:331-339`, hash excludes
Generation, `builder.go:79-90`). Net: after any FIB/neighbor/no-op bump,
`lastSnapshot.Generation` > helper `last_snapshot_generation` FOREVER → r9's
equality never true → alarm never fires. (publishedSnapshot is the opposite —
too loose.) FIX: track the last helper-APPLIED snapshot config/generation, compare
helper status to THAT.

### MINOR #3 — `Available==false` HOLD contradicts "every withdrawal emits a clear"
for disabled/nil config when the helper is down. FIX: state clears are DEFERRED
during unavailable-HOLD (not silently dropped), or a config-only clear path.

### NIT #4 — doc was dispatched as r8 but on-disk is r9; stale r8 changelog line
still says HelperCaughtUp == published snapshot.

## r10 resolution
All folded: r10 adds `m.appliedSnapshot {Config, Generation}` captured ONLY on the
full apply_snapshot path; `dp.AppliedNATView()` sources Config + matching counters
from the applied generation; `HelperCoherent := status gen == appliedSnapshot gen`
(neither too loose nor too strict). #3 → §6.4 "clears deferred during
unavailable/mid-apply HOLD, not silently dropped". #4 → changelog corrected.
