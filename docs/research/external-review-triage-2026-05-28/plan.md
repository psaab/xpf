# External codebase review (2026-05-28) — triage + prioritized action plan

**Revision**: r1
**Mode**: `/research` (research-only; STOP at PLAN-READY; no production code)
**Source**: `/tmp/latest-review.md` (576 lines: §1 bugs/security 1.1–1.10, §2 modularization 2.1–2.11, §3 test-coverage gaps)
**Verification base**: `origin/master` @ `0e5bb3812` (docs drift fixes #1639/#1644/#1645 via #1647)
**Reviewers**: Codex + AGY + Claude SMR (3-way at research; Copilot joins at `/engineer`)

---

## 1. Problem framing

An external static-analysis pass produced 10 bug/security findings (§1), 11
modularization opportunities (§2), and a test-coverage gap inventory (§3). The
job is **hostile triage**, not acceptance: verify each finding against
`origin/master` and the issue/PR history, then classify as REAL-actionable /
FALSE-POSITIVE / ALREADY-FILED / PLAN-KILLED / INTENTIONAL-BY-DESIGN. The
deliverable is a converged, prioritized action plan of only the REAL items.

The review's raw facts are mostly accurate where spot-checked (grep counts for
duplicated constants, `Result<_, String>`, `#[ignore]`d tests, missing
`proptest`/fuzz all verified true). The *framing/severity* is where it
over-reaches: several "CRITICAL/HIGH" bugs are documented contract guards,
stack-copy clones mislabeled as heap allocs, or not-yet-wired pending work.
The genuinely high-value NEW signal is §3 (server/ control-plane + worker
loop_body have zero unit tests).

## 2. Verified blast radius

| Claim | Review says | Verified at origin/master | Verdict |
|---|---|---|---|
| `unsafe` blocks in afxdp/ w/o SAFETY | ~180 | plausible; sampled lines are mmap raw-ptr derefs | discipline gap |
| `unreachable!()` in cos_classify | 6 (489/494/527/544/599/626) | confirmed; all match the *other* known 2-variant after constructing one | contract guards |
| service.rs unreachable | 2 (451/617) | confirmed `"prepared CoS queues do not drain local mirror clones"` | contract guards |
| dispatch unreachable | 1 (188) | confirmed `PendingForwardFrame::Prebuilt(_) => unreachable!()` | needs read |
| `stage_flow_cache_hit` params | 22 | 21 counted (close) | real |
| `worker_loop` params | 34 | ~37 — but it is the **thread-spawn entry**, called ONCE/worker, all `Arc` handles | misframed as "hot path" |
| `Rc::get_mut().expect()` umem | line 107 | confirmed line 106–108 `.expect("single-owner umem")` | real but low-risk |
| wg `.unwrap()` on locks | 10+ | 18 in engine.rs | real; **but wg not wired to hot path** |
| `Result<_, String>` | 51 | 51 exactly | real, style |
| `PROTO_TCP` duplication | 5+ | 8 sites | real, low-risk |
| wg `#![allow(dead_code)]` | ~3500L | confirmed module-level; "not yet wired" comment present | pending #1432/#1434 |
| `ForwardingState` fields | **111** | **44** (review counted nested struct fields) | overcounted ~2.5× |
| `Coordinator` lines | ~1114 | 1458 | undercounted |
| poll_descriptor lines | 2906 | 2906 | exact |
| session/mod.rs lines | 1335 | 1335 | exact |
| policy.rs lines | 1086 | 1086 | exact |
| server/ tests | 0 | 0 (`#[cfg(test)]` in helpers.rs is a test-only *helper*, not a test) | confirmed gap |
| worker/loop_body tests | 0 | 0 | confirmed gap |
| `#[ignore]`d tests | 2 (queue_ops 912/1113) | confirmed | real |
| no proptest/fuzz | 0 | confirmed (none in Cargo.toml) | real |
| neighbor.rs:721-731 "commented-out code" | remove | it is an **explanatory comment** documenting CPU-pin behavior, not dead code | FALSE-POSITIVE |

## 3. Per-finding triage table

### §1 Bugs & Security

| # | Finding | Classification | Evidence (origin/master) | Disposition |
|---|---|---|---|---|
| 1.1 | `unsafe` without `// SAFETY:` (~180) | **REAL-actionable (discipline, MINOR)** | mmap raw-ptr derefs in afxdp/poll_descriptor, tx/rings, frame/* | Documentation sweep, not a bug. Prior full-codebase review did NOT file as a bug. Worth a bounded "annotate hot-path unsafe" PR; low urgency. |
| 1.2 | `unreachable!()` "in hot path match arms" | **INTENTIONAL-BY-DESIGN** (6 cos_classify + 2 service) / needs-verify (1 dispatch) | cos_classify.rs:488-494 etc match `Err(Prepared)` *after constructing `Local`* — the Local/Prepared asymmetry from #1207. service.rs:451/617 `"prepared CoS queues do not drain local mirror clones"` per #913 R4/#925 | These are believed-unreachable contract guards on a closed 2-variant enum, NOT a `#[non_exhaustive]` wildcard risk. Adding a variant is a compile error at the *construction* site too. Recommend: leave as-is; optionally add `// guard:` doc comments. dispatch/mod.rs:188 bare `unreachable!()` w/o message → tiny REAL nit (add message). |
| 1.3 | 22-/16-param functions | **REAL-actionable** (overlaps §2.3) | flow_cache_hit.rs:64 (21 params), poll_descriptor:440 (16) | Real testability blocker. Fold into the §2.4 poll_descriptor scratch-struct work; not a standalone bug. |
| 1.4 | WG lock `.unwrap()` poisoning | **PARTIAL — misframed** | 18 in wg/engine.rs; wg has 0 references in poll_descriptor (NOT on hot path) | wg is the not-yet-wired #1432/#1434 module. A panic-poison crash is a real robustness concern *if/when wired*, but "crashes the dataplane hot path" is false today. Fold into #1432/#1434 hardening; do not file standalone. |
| 1.5 | `Result<_, String>` (51) | **REAL-actionable (style, LOW)** | 51 confirmed | Typed-error refactor is legitimate cleanup but large surface, low urgency. Backlog candidate; not ship-blocking. |
| 1.6 | Protocol constants duplicated | **REAL-actionable (QUICK WIN)** | 8 `const PROTO_TCP` sites | Centralize into one `pub(crate)` module. ~0.5d, low-risk. Good first action item. |
| 1.7 | `Rc::get_mut().expect()` umem | **REAL but LOW-risk / arguably INTENTIONAL** | umem/mod.rs:106 `.expect("single-owner umem")` | The `.expect()` *is* the single-owner invariant assertion — `make_mut()` would silently clone the entire UMEM (catastrophic). The expect is correct fail-fast. Optionally add `debug_assert_eq!(strong_count,1)` for earlier detection. NEEDS-NO-FIX leaning. |
| 1.8 | `#[allow(dead_code)]` on WG (~3500L) | **ALREADY-EXPLAINED (pending #1432/#1434)** | wg/mod.rs:28 `#![allow(dead_code)] // Most of this module is not yet wired` | Not dead — pending integration. event_stream/producer.rs:1 similar ("status surfaces consume only part"). Periodic `deny(dead_code)` CI gate is a reasonable suggestion but low ROI now. Relate to #1432/#1434; do not file. |
| 1.9 | `clone()` in per-packet hot path | **MOSTLY FALSE-POSITIVE** | `SessionKey` (key.rs:9) derives `Clone` NOT `Copy`, contains `IpAddr` — **stack memcpy ~40B, no allocator call**. `flow_key`/`forward_key` clones are stack copies. The mirror `.to_vec()` (flow_cache_hit) is plan-killed #1545. | Per-tuple-key clones are not heap allocs; "10 Mpps × alloc" cost claim is wrong. `binding.interface.clone()` (:817) needs per-site check. Net: ~no real per-packet heap alloc here; the one real alloc (mirror to_vec) is PLAN-KILLED #1545. |
| 1.10 | WG scratch `RefCell<Vec<u8>>` realloc | **PARTIAL — pending #1432/#1434** | scratch.rs:30 `vec![0u8; max_frame]` pre-sized to max_frame | Pre-sized to max frame; realloc only if a write exceeds max_frame (shouldn't happen). wg not wired. ArrayVec swap is reasonable hardening folded into #1432/#1434. Not standalone. |

### §2 Modularization

| # | Finding | Classification | Evidence | Disposition |
|---|---|---|---|---|
| 2.1 | `ForwardingState` god object | **REAL but OVERSTATED** | 44 fields (not 111), 349-line file (not ~500) | Decomp into RouteState/NatState/InterfaceState/ScreenState/CoSState has a LIVE consumer (independent unit testing of NAT/route/screen). Viable, but re-scope to the real 44 fields. Medium ROI. Note scaffolding-toward-dead-consumer risk: the sub-structs must be consumed by new tests, else low-value. |
| 2.2 | `Coordinator` god object | **REAL** | 1458 lines; sub-managers (NeighborManager/SessionManager/WorkerManager/SharedCoSState) already exist | Incremental delegation continues #1189 Phase-1 pattern (shipped). Real but Phase-2 follow-ups were deferred; pursue only with a live test consumer. |
| 2.3 | `worker_loop` 34 params | **REAL-actionable but MISFRAMED** | ~37 params; thread-spawn ENTRY (called once/worker), all Arc handles | "Makes hot path testable" is wrong — it's the spawn entry, not per-tick. Grouping Arc handles into config structs improves call-site readability (real win) but does NOT unlock hot-path unit testing. Re-scope the justification. |
| 2.4 | poll_descriptor 2906L stage extraction | **REAL, HIGH-VALUE** | 2906L confirmed; comment "blocked by mutable-locals coupling" | The genuine hot path. Scratch-struct extraction (mirror WorkerScratch) is the right pattern; this is where §1.3 (22-param fn) belongs. Highest-effort but highest test-unlock. |
| 2.5 | checksum.rs L4Protocol trait | **REAL, MEDIUM** | 7 match sites (278/307/367/417/444/471/506) | Trait-based dispatch eliminates dup. Caution: trait dispatch must stay monomorphized/inlined (no dyn on hot path per engineering-style). Viable if `<P: L4Protocol>` generic, NOT `dyn`. |
| 2.6 | filter/eval.rs v4/v6 generic | **REAL, MEDIUM** | 6 near-identical fn pairs | Generic over addr family. Same monomorphization caveat. |
| 2.7 | frame NAT v4/v6 twins | **REAL, MEDIUM** | apply_nat_ipv4/v6 structural twins | Generic `apply_nat<T: IpHeader>`. Monomorphization caveat. |
| 2.8 | SessionTable decompose | **REAL, MEDIUM** | session/mod.rs 1335L, 17 fields | Indices/delta/expiry split. Relate to #1047 (slab work already done). Live consumer = isolated GC/index tests. |
| 2.9 | policy.rs error/parser/eval/book split | **REAL, MEDIUM** | 1086L confirmed | Standard module split with test consumer. |
| 2.10 | cold_path_hist.rs TSC split | **REAL, LOW (quick win)** | 1303L; relates to #1621/#1635 | #1635 is OPEN and proposes a bucket-layout *redesign* of this exact file — coordinate to avoid churn-then-rewrite. Defer split until #1635 lands or explicitly de-conflict. |
| 2.11 | server/helpers.rs split | **REAL, LOW** | 727L | cli/sync/state_io split pairs naturally with §3.1 server tests (write tests against the split). |

### §3 Test Coverage

| # | Finding | Classification | Evidence | Disposition |
|---|---|---|---|---|
| 3.1 | Zero-test modules (~12kL) | **REAL — HIGHEST-VALUE NEW SIGNAL** | server/ 0 tests confirmed; worker/loop_body 0 tests confirmed | server/ (control-plane Go<->Rust comms) + worker/loop_body are genuine blind spots. Roadmap is the real deliverable. |
| 3.2 | Thin coverage (protocol/ 0.32×) | **REAL** | protocol tests only in tests.rs; binding/control/snapshot untested directly | Real; protocol is the wire contract (see `feedback_wire_protocol_both_sides`). High value. |
| 3.3 | No fuzz/proptest, 2 #[ignore], TODO#1499 | **REAL (mixed urgency)** | confirmed: no proptest/fuzz; ignore at 912/1113; wg/tests.rs:437 TODO#1499 | proptest for prefix_set/NAT/protocol round-trips is high-value. Fuzz frame/inspect is high-value. Document the 2 ignores. |
| 3.4 | Test organization | **POSITIVE (no action)** | review itself says org is good | No action — acknowledged strength. |

## 4. Dedupe / already-filed cross-check

- §1.9 mirror `.to_vec()` → **PLAN-KILLED #1545** (mirror clone alloc elim).
- §1.4/§1.8/§1.10 WireGuard → **#1432/#1434** (pending integration). Fold hardening there.
- §2.2 Coordinator → continues **#1189** Phase-1 (shipped); Phase-2 deferred.
- §2.4 poll_descriptor → relates to **#946** (Phase-2 batched-pipeline PLAN-KILLED; but per-stage *extraction* is a different, viable scope — #946 kill was about batched iteration, not extraction).
- §2.8 SessionTable → relates to **#1047** (slab done).
- §2.10 cold_path_hist → **#1635 OPEN** proposes redesign of this file — coordinate.
- §1.3/§2.3 param counts → no existing issue; new.
- prior review already filed: #1641 (NAT64 padding), #1642 (status parity), #1643 (seqlock fence, #1630/#1650), #1646 (frr write), #1638 (dead scaffolding), #1639/#1644/#1645 (docs, merged #1647) — none re-filed here.

## 5. Honest scorecard

Of ~10 §1 bug findings + 11 §2 + ~7 §3 sub-findings (≈28 total):

- **REAL-actionable**: §1.1 (discipline), §1.3, §1.5, §1.6, §2.1, §2.2, §2.3 (re-scoped), §2.4, §2.5, §2.6, §2.7, §2.8, §2.9, §2.10 (coordinate w/#1635), §2.11, §3.1, §3.2, §3.3 — **~18**
- **FALSE-POSITIVE / misframed-to-near-false**: §1.9 (stack clones not allocs), neighbor.rs:721 "commented code" (it's a doc comment), §1.2 framing (contract guards not variant-growth risk) — **~3**
- **INTENTIONAL-BY-DESIGN / NEEDS-NO-FIX**: §1.2 (the 8 CoS guards), §1.7 (single-owner expect is correct fail-fast) — **~2**
- **PLAN-KILLED**: §1.9 mirror to_vec (#1545) — **1**
- **ALREADY-PENDING (not standalone)**: §1.4, §1.8, §1.10 (all WG → #1432/#1434) — **~3**
- **POSITIVE / no-action**: §3.4 — **1**

Headline: **the test-coverage roadmap (§3) is the real prize.** Most §1 "CRITICAL/HIGH" bugs are discipline/style or documented guards. §2 is known refactor-backlog territory; recommend only decomps with a live test consumer.

## 6. Prioritized action plan (REAL items only)

**Tier A — bugs/correctness (small, do first)**
1. §1.6 Centralize protocol constants (8→1) — 0.5d, low-risk QUICK WIN.
2. §1.2 dispatch/mod.rs:188 — add a message to the bare `unreachable!()` (nit). Add `// guard:` doc comments to the 8 CoS contract-guard `unreachable!`s clarifying they are believed-unreachable on a closed enum (documentation, not behavior change).
3. §1.1 Bounded SAFETY-comment sweep on the hottest afxdp/ unsafe blocks (poll_descriptor, tx/rings, frame/*). Discipline PR, no behavior change.

**Tier B — test coverage (highest value)**
4. §3.1 server/ control-plane tests (~20 tests) — pairs with §2.11 helpers split.
5. §3.2 protocol/ binding/control/snapshot direct tests + round-trip (wire contract).
6. §3.1 worker/loop_body harness — coordinate with §2.4 poll_descriptor scratch extraction (testability is gated on the refactor).
7. §3.3 Add `proptest` for prefix_set/NAT/protocol round-trips; fuzz target for frame/inspect; document the 2 `#[ignore]`d queue_ops tests.

**Tier C — refactors WITH a live consumer (medium, ROI-gated)**
8. §2.5/2.6/2.7 trait-based de-dup (checksum L4Protocol, filter v4/v6, frame NAT) — each MUST stay generic-monomorphized (no `dyn` on hot path). Each ~2-3d.
9. §2.1 ForwardingState decomp (re-scoped to 44 fields) — only if §2.1 tests consume the new sub-structs.
10. §2.4 poll_descriptor stage extraction — highest effort; unlocks #6.
11. §2.8/2.9/2.11 SessionTable / policy / server-helpers splits — pair each with its test consumer.

**Tier D — backlog (low urgency)**
12. §1.5 typed-error refactor (51 sites) — large surface, low risk, do incrementally.
13. §2.2 Coordinator continued delegation (#1189 Phase-2).
14. §2.10 cold_path_hist split — DEFER until #1635 (redesign) resolves to avoid churn.

**Do NOT action**: §1.9 (stack-copy clones — false), §1.7 (correct fail-fast), §1.4/§1.8/§1.10 standalone (→ #1432/#1434), neighbor.rs:721 (doc comment), §1.9 mirror to_vec (#1545 killed).

## 7. Multiple-path note

Only §2.4/§2.1 carry a genuine design fork: (a) full scratch-struct extraction
enabling per-stage tests (high effort, high unlock) vs (b) leave inline and
test loop_body via integration harness only. The plan recommends (a) for
poll_descriptor because the test-unlock is the stated goal, but flags that if
the scratch struct ends up with no test consumer it repeats the
scaffolding-toward-dead-consumer anti-pattern (#1638). Each refactor item
becomes its own scoped `/engineer` PR; reviewers gate the consumer at that time.

## 8. Test/validation strategy

This is research-only — no code. Validation of the *plan* = 3-reviewer
convergence. At `/engineer` time, each Tier item becomes a scoped PR with:
its own test consumer (refactors), `make test` green, and for any hot-path
touch (§2.5/2.6/2.7) a disasm/inline check + smoke on loss userspace cluster
(v4+v6 × push/-R × CoS-on/off).

## 9. Risks

- **Scaffolding-toward-dead-consumer** (#1638 pattern): every §2 decomp must
  ship with the test that consumes it, or it is net-negative.
- **Monomorphization regressions** (§2.5/2.6/2.7): trait dispatch on the hot
  path must stay generic/inlined; a `dyn` slip is a per-packet indirect call.
- **#1635 churn collision** (§2.10): redesign-then-split wastes work.
- **Over-counting** in the source review (111→44 fields) means effort
  estimates (review's "5 days") are inflated; re-estimate per scoped PR.

## 10. Rollout

Each REAL item → its own GitHub sub-issue or scoped PR at `/engineer` time.
Tier A first (quick, low-risk), then Tier B (highest value), Tier C ROI-gated,
Tier D backlog. No big-bang.

## 11. Open questions for the user

1. Is the test-coverage roadmap (§3, Tier B) the priority, or the bug
   discipline sweep (§1.1, Tier A)?
2. Should the `dataplane` label be created (it does not exist; only
   `refactor`/`perf`/`jit`)? This umbrella is filed under `refactor`.
3. For §2 decomps: confirm the "ship the test consumer with the refactor" gate.
