# Claude SMR — Hostile Plan Review r10 — #2079

Reviewing plan.md r10 after folding Codex r8's PLAN-REVISE (#1/#2 too-strict
generation, #3 deferred-clear wording, #4 stale changelog).

## Verdict: PLAN-READY

Codex r8 found the mirror of AGY r8: r9's `lastSnapshot.Generation` comparand was
too STRICT just as r8's `publishedSnapshot` was too loose. I verified the
generation-tracking and agree the r10 applied-snapshot source is the correct
resolution.

- **#1/#2 (too-strict generation):** Verified `BumpFIBGeneration` advances
  `m.lastSnapshot.Generation` (`manager.go:1166`) but the helper only sets
  `last_fib_generation` on the bump path (`snapshot.rs:164`) and
  `last_snapshot_generation` only on full apply (`snapshot.rs:63`). So
  `lastSnapshot.Generation` permanently exceeds `last_snapshot_generation` after
  any FIB/neighbor/no-op bump → r9's equality is never satisfiable → numericEval
  false forever → alarm never fires. r10 sources the view from
  `m.appliedSnapshot` (Config+Generation captured ONLY on the full apply_snapshot
  path, the gen the helper echoes), so Config and counters are the applied
  generation and FIB/neighbor bumps never touch it. `HelperCoherent := status gen
  == appliedSnapshot gen`. This is the unique correct comparand between the
  too-loose published and too-strict lastSnapshot. RESOLVED.
- **#3 (deferred clear):** §6.4 now states clears are DEFERRED (active set
  retained, emitted on the next coherent tick), not silently dropped, during
  unavailable/mid-apply HOLD. This is the right call — clearing from a
  control-plane-only view while the dataplane state is unknown would reintroduce
  the split-source skew. RESOLVED.
- **#4 (stale changelog):** the r8/r9 changelog lines are marked superseded; the
  risk-table row updated to the applied-snapshot invariant. RESOLVED.

## Independent re-trace
- View source: `m.appliedSnapshot` (apply-path only). Config + Pools same applied
  gen. ✓
- `!Available` → HOLD-all; `!HelperCoherent` (mid-apply) → HOLD-all; cfg nil /
  disabled → clear-all (deferred if not coherent). ✓
- Once Available+HelperCoherent: numericEval unconditionally true (coherent). ✓
- Eligibility rule-referenced from applied Config; dedup in view; raise/clear/
  updatePct; prune; lock discipline; both render sites; commit validation; uint
  cast. ✓
- FIB/neighbor bump does NOT gate (appliedSnapshot untouched). ✓ (the r9 failure
  mode is closed)

## Implementation note
r10 adds a Go-side `m.appliedSnapshot` field + `AppliedNATView()` accessor (no
Rust change — the helper already echoes `last_snapshot_generation`). This is the
one new dataplane-manager seam the design needs; it is captured exactly where the
full apply already happens, so it is low-risk.

## New issues from r10 — none
The applied-snapshot source is the natural fixed point: it is precisely "the
config whose pool counters the helper is currently reporting". PLAN-READY.

## Convergence note
The finding layers have descended from monitor-loop (r2-r6) → commit ordering
(r7-r8) → generation-tracking semantics (r8-r10), and r10 lands on the exact
applied-generation invariant. AGY and Codex bracketed the correct comparand from
both sides (too-loose / too-strict); r10 is between them and provably coherent.
