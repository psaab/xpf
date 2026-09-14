# Adversarial PLAN review — psaab/xpf#9522 Design B (`docs/pr/9522-designB/plan.md` v1 @ 4720981f, base 7ef226474)

All source citations verified by reading this worktree. STEP-0 factual claims re-checked and hold: protocol is v16 (`protocol/control.rs:131`), unknown-verb refusal (`server/handlers/mod.rs:360-363`), Go-owned bump via shim (`manager_generation.go:60-155`), 30s actuate (`pkg/coalesce/coalesce.go:43`), gap-key Go-side (`routes.go:878`), cap on count not bytes (`routes.go:785-789`, `learned_route_cap_8355.go:129-147`), overlay recompute of the capped flag (`manager_overlay.go:201-207`), digest gate (`snapshot.rs:135-161`), digest clear-on-mutation (`neighbors.rs:54-59`).

## Does v1 implement the round-1 prescription?

| Round-1 finding | Plan item | Verdict |
|---|---|---|
| F1 clear-at-chunk-0 / mixed window | Shadow staging, swap at complete, abort retains old view (§5-1.2–1.4) | ✓ closed **for the transfer path** — but reopened at every *apply* path, see R1-F1 |
| F2 linear scan at 1M | Phase 0 LPM in scope, gated, kill-switch | ✓ closed |
| F3 dual carrier | Single carrier, snapshots exclude learned (§5-1.6) | ✓ specified Go-side, **incomplete helper-side** (R1-F1) |
| F4 v10 skew | v17 + loud refusal (§5-Phase-3) | ✓ closed (matrix inconsistency, R1-F5) |
| F5 helper self-bump | Commit-ACK → Go bumps shim → `bump_fib_generation` (§5-1.5) | ✓ closed, matches the AGY r2-1 ordering contract |
| F6 digest at divergence | "Restamp at swap" (§5-1.4) | ✗ **wrong mechanism** — R1-F2 |
| F7 30s actuate vs chunk streams | Converge-or-new-transfer + M1 measurement | partially — livelock unaddressed (R1-F3) |
| F8 per-chunk clone/rotation | One `publish_runtime_view` per transfer (§5-1.4) | ✓ closed |
| F9 helper-side coverage | Suppression precedes chunking (§7-6) | ✓ for chunks — **reopened at apply time** (R1-F1) |

The shape is right. Three specification holes keep it from proceeding.

## Findings

### R1-F1 — MAJOR (architecture gap): every non-transfer publish wipes the learned FIB; the plan's own availability-parity acceptance is violated by its own rewire

Single carrier means Go's snapshots carry no learned routes (plan §5-1.6). But `apply_snapshot` is a **full rebuild from the incoming snapshot only** — `ForwardingState::default()` → `populate_routes` (`forwarding_build/mod.rs:555-594`); the stored snapshot is consulted only for generation/digest gating (`snapshot.rs:135-161`), never as a content source. Same for the overlay path: `next := *m.lastSnapshot; next.Routes = buildRouteSnapshots(...)` (`manager_overlay.go:197-207`) — a config-only `next.Routes`. Therefore, after Phase 1:

- Every config commit (policy edit, interface change) → `apply_snapshot` → live FIB loses **all** learned routes until the follow-up transfer completes ("full republish = new transfer", §5-1.6).
- Worse: the overlay path is the **#7437 churn path itself** (`daemon_route_listener.go:229-263` → `PublishRouteOverlaySnapshot`), so under BGP churn the learned table is wiped and re-transferred *per actuation*.
- During each such window every learned destination resolves `NoRoute` → on a default-deny box, dropped. That is exactly the posture the issue rejected and the plan's own §2 pins: "no transfer window drops or delegates anything the pre-transfer table would not have."

The plan never specifies a helper-side retention mechanism. Item 4's "fold the staged set into the stored snapshot's routes" happens only at *swap* time and only affects the stored snapshot — nothing re-introduces learned content into the next apply's build. Note also that naive retention is insufficient: a config change that **adds** a route covering a learned prefix must re-suppress that learned route (gap-fill precedence is Go-build-time today, `routes.go:838-846`; the helper has no covered-rule, and round-1 F9 explicitly forbade implying one), and learned bare-gateway next-hops must re-resolve against the *new* `iface_ctx` (#4446). And the plan's language wavers between a "learned partition" of `ForwardingState` (§5-Phase-2 "live learned partition"…

**Required before PLAN-READY:** pick and specify one of (a) apply-time splice — the apply handler re-plays the retained learned `RouteSnapshot`s through `populate_routes` with the incoming snapshot, which requires a Rust-side gap-key coverage filter parity-pinned against `canonicalRoutePrefix`; or (b) a genuine learned partition in `ForwardingState` that apply does not rebuild, with a lookup integration rule that preserves exact-prefix config-wins (gap-fill) and cross-prefix LPM semantics. Add the M2 cell: config commit mid-life on a full-table deny box must not drop learned-routed traffic. Also state the restart matrix (helper restart re-applies Go's learned-less `lastSnapshot` → a fresh transfer must be a re-arm trigger).

### R1-F2 — MAJOR (mechanism incoherence): digest "restamp over the FULL new content at swap" cannot work under single-carrier; the precedented answer is the clear

The installed `content_digest` exists so Go's same-generation retry can prove identity; Go computes it as a SHA-256 over the **JSON encoding of its own struct** (`builder.go:187-205`). Two facts make the restamp as specified (§5-1.4, Q5) incoherent:

1. The helper cannot "recompute" that digest without reproducing Go's JSON encoding byte-for-byte across languages — a non-starter.
2. Even a Go-stamped digest carried in `route_complete` fails: Go hashes its learned-**less** snapshot, while item 4 folds learned into the helper's stored snapshot — the stored digest and every future Go digest of the "same" config can never agree. Consequence: every same-generation apply retry is refused as a content conflict and forced into the republish-at-next-generation loop (`apply_snapshot_identity_9520.go:71-100`) — the #4036/#9520 fast path is permanently burned, and the digest never does what §7-4 claims ("enforced content never diverges from the installed digest").

The correct mechanism already ships: `update_neighbors` **clears** the installed digest when it changes enforced content (`neighbors.rs:54-59`), and an empty digest is defined to vouch for nothing (`snapshot.rs:140-147`). Clear-at-swap is one line, zero CPU at 1M, and exactly preserves #9520 semantics. Q5's three options (rehash / incremental / trust-bitmap) all miss it. **Required:** replace restamp with clear-at-swap; if a content-identity check at commit is wanted, it is a *transfer-internal* check (Go sends a hash of the full learned set in `route_complete`; helper compares against its staged set) — a different object from `content_digest`, not a restamp of it.

### R1-F3 — MAJOR (protocol ownership): the transfer sender has no serialization/ownership story; supersede-on-new-transfer livelocks under sustained churn

Releasing `m.mu` between chunks (§5-1.7) means the status tick, HA reconcile, and the actuator interleave with the sender. Nothing in the plan establishes: (a) that exactly one transfer is in flight (two goroutines can each mint `routeTransferGen+1`); (b) that new demand while a transfer is in flight *queues* rather than *pre-empts*. As written, "the actuator retry starts a NEW transfer (old staging superseded)" plus `transfer > last_seen ⇒ abort` means a box whose churn-mark period is shorter than transfer convergence (plausible at 1M: ~100 chunks × per-chunk validate ≈ tens of seconds vs the 3s throttle, `coalesce.go:41-43`) **never completes a transfer** — permanently serving a staler-and-staler table with no bound. The 30s actuate timeout rest…

### R1-F4 — Phase 2 should be KILLED; anti-entropy folds into Phase 1

Three independent reasons:

1. **Batch atomicity is unspecified and non-trivial.** Deltas mutate `self.forwarding`'s learned partition directly (§5-Phase-2). `publish_runtime_view` clones `self.forwarding` wholesale (`coordinator/mod.rs:1590-1598`); a delta batch that fails validation mid-way leaves a half-applied `self.forwarding` that the *next unrelated* publish (bump, neighbor path, apply) makes worker-visible. "Each delta is self-consistent" (per-delta) is not batch atomicity — this is the mixed-state class round-1 killed, at batch granularity. Fixable (pre-validate whole batch, then mutate, then publish once), but it is a new atomicity surface.
2. **The anti-entropy justification evaporates.** Periodic full transfer with the existing content-hash skip is anti-entropy without deltas; to make it real against helper-side drift, echo the installed transfer generation + learned-set hash (Go-stamped, carried in `route_complete`, mirrored in `ProcessStatus`) — the `manager_neighbor_generation` precedent (`manager_generation.go:120-140`). Cheap, precedented, belongs in Phase 1.
3. **Value unproven.** With serialized transfers (R1-F3), steady-state staleness under churn ≈ one transfer duration — vastly better than today's above-cap *infinite* staleness, and the issue's acceptance criteria are policy-result and availability parity, not convergence latency. The plan's own §3/Q2 invite the kill. Take it; file deltas as a future issue gated on measured diff-size distribution.

### R1-F5 — MINOR: Phase-3 matrix contradicts the version-gate claim it sits next to

"Mixed pairings refuse loudly per the existing version gate" (exact equality, both directions: `snapshot.rs:28-35`, `manager_compile.go:1039-1047`) is irreconcilable with the matrix cells "Old helper …: Go keeps the OLD cap path with the OLD delegation semantics" — under the gate that pairing fail-closes commits and disarms, it never reaches any per-verb fallback. Over-refusal is the safe, doctrine-conformant direction, but the matrix describes unreachable states and will mislead rollout planning. Also state the deployment fact that bounds the blast radius: the daemon spawns the helper from the same package (`process_identity_restart_8899_test.go:30`, `/usr/sbin/xpf-userspace-dp`), so pairings are atomic per node and long-lived mixed pairings require …

### R1-F6 — MINOR (in the plan's favor): LPM blast radius is overstated; semantic-identity set verified

Production readers of `routes_v4` are: the two lookup sites (`fib.rs:429` + v6 twin), the warmer sweep (`coordinator/mod.rs:1309`), and the build/sort write side (`forwarding_build/fib.rs:82,168`) — the rest of the ~30 refs are tests/logs. Signatures-preserving is feasible as claimed. I verified the identity set the corpus must pin, all real in source: prefix-len DESC → preference ASC → stable insertion (`forwarding_build/fib.rs:160-180`); connected-vs-static tiebreak at `conn.prefix_len() >= route.prefix_len()` (`fib.rs`, `choose_v4_route`); table-scoped connected (`fib.rs:429-437` region, #2388); discard/next-table/cycle arms; ECMP whole-slice identity (`select_route_next_hop` bitmask, order-stable). Corpus additions worth naming: same-length disj…

## Answers to the ten verification questions

1. **Phase order:** LPM-first is correct. Transfer-first behind a retained cap ships zero issue value (the cap is count-vs-time, not lookup-bound — `routes.go:785`, `learned_route_cap_8355.go:19-23`), and creates a dual-carrier window for learned. Phase 0 standalone-shippable with its own gates and kill-switch is the right shape.
2. **Phase 2 worth:** No — kill it (R1-F4); fold anti-entropy into Phase 1 via hash-skip periodic transfer + status echo.
3. **Staging memory:** Acceptable. Two FIBs during staging plus one clone at swap at 1M is tens-of-MB cold-path cost, M1-measured; the alternative (delta-apply-then-checksum on live) reintroduces live-mutation review — rightly rejected.
4. **Envelope:** Stop-and-wait is correct — and not merely simplest: the control connection is serial request/response, so windowing would require new pipelining in the server loop for little gain (helper processes serially regardless). Staleness is bounded by sender serialization (R1-F3), not by windowing.
5. **Digest:** Clear-at-swap (neighbors precedent), not restamp (R1-F2).
6. **#946-Phase-2 pattern:** Not a match for Phases 0/1 — that kill was hidden order-coupling on the packet path (`issue-history.md:20202`); this machinery is explicit-state, cold-path, fenced, and precedented at neighbor scale. Phase 2 *is* the over-mechanization shape — another reason to kill it.
7. **v17 blast radius:** Doctrine-conformant; fix the matrix and state the same-package deployment coupling (R1-F5). No compat window.
8. **LPM identity/blast radius:** Verified (R1-F6); corpus list sufficient with the three named additions.
9. **Delta live-partition mutation:** As specified, it *does* reintroduce an atomicity problem — at batch granularity (R1-F4.1). Moot if Phase 2 is killed.
10. **Mid-transfer config change:** The epoch-abort is stated, but the abort story presupposes the old learned table survives the apply that carried the config change — which is exactly what the plan fails to specify (R1-F1).

## Verdict

**NEEDS-MAJOR**

The architecture matches the round-1 prescription and is the right one: shadow staging, single publish, single carrier, Go-owned bump, LPM-first with gates. But v1 is not implementable-as-written to its own acceptance criteria: the apply/overlay path as rewired wipes the learned table at every non-transfer publish (R1-F1), the digest-at-commit mechanism is incoherent under single-carrier (R1-F2), and the transfer sender has no ownership/serialization story, with a live livelock mode under sustained churn (R1-F3). All three are closable inside the existing shape — none requires re-architecture. Required for the next revision:

1. Specify learned-route FIB representation + apply-time retention with coverage and `iface_ctx` re-resolution, plus the M2 no-wipe-on-config-commit cell and the restart matrix (R1-F1).
2. Replace digest restamp with clear-at-swap; move any commit-time content check to a transfer-internal Go-stamped hash in `route_complete` (R1-F2).
3. Serialize the transfer sender; dirty-flag instead of pre-empt; pre-empt only on epoch change; add convergence-under-churn to M1 (R1-F3).
4. Kill Phase 2; fold anti-entropy (periodic hash-skip full transfer + status echo of installed transfer identity) into Phase 1 (R1-F4).
5. Reconcile the Phase-3 matrix with the version gate; document same-package pairing (R1-F5).
