# Adversarial PLAN review — ROUND 2 (GLM)
**Target:** `docs/pr/9522-designB/plan.md` v2 @ `3e1da97` (branch `fix/9522-learned-route-cap`, base `7ef226474`)
**Note:** round-1 raws are not yet in-tree (plan §1 says "to be saved with v2's dispatch"); I verified v2's *claims* about R1 closure against head, not against the R1 text.

---

## A. Round-1 closure verification (hostile)

**R1-F1 retention — CLOSED in mechanism.** The v1 hole was real and v2's closure is mechanically sound against head: the apply paths genuinely rebuild config-only tables from the incoming snapshot (`coordinator/reconcile/snapshot.rs:538` reconcile apply; `server/handlers/snapshot.rs:296-346` same-plan legs → `refresh_runtime_snapshot[_disarmed]`), so single-carrier v17 without retention would wipe learned at every apply/overlay. Replay through `populate_routes` (`forwarding_build/fib.rs:37`) re-resolves next-hops against the new state per #4446 (`infer_connected_route_target_v4`, `fib.rs:396+`), and replay cannot newly fail the fail-closed checks (preference/family/destination are content-intrinsic — `fib.rs:46-135`). Exact-key suppression mirrors G…

**R1-F2 digest — CLOSED.** Clear-at-swap matches the #9520 clear-on-mutation precedent exactly (`server/handlers/neighbors.rs:58-66`, `server/handlers/mod.rs:226-236` for fabrics), and the empty-installed-digest refusal arm (`server/handlers/snapshot.rs:147-160`) makes the cleared state safe: a same-generation retry is refused with the conflict prefix that "proves to Go that this helper HOLDS the generation" — the existing #9520 recovery semantics apply unchanged. Transfer-internal hash never touches the gate. Clean.

**R1-F3 serialization — CLOSED in mechanism, one residual (R2-6).** One in-flight + dirty-not-preempt + epoch-preempt-only is coherent, and the target workload (kernel route churn) does *not* bump config identity — neighbor churn rides `update_neighbors` (own verb, `manager_neighbor.go:100-112`), overlay applies only on overlay-content change — so the churn-abort livelock is bounded in practice. But K=3 bounds only *Go-side* restarts; helper-side aborts on config-identity change (§5-1.2 "EVERY chunk checked…mismatch ⇒ abort") are unbounded by construction and correct-by-binding. The plan should say so and add a config-change-during-transfer leg to the M1 convergence cell.

**R1-F4 Phase 2 killed — CLOSED.** Anti-entropy as echo-per-tick (§5-1.5) + hash-skip periodic transfer is coherent; see R2-8 for the cadence framing.

**R1-F5 matrix — NOT closed. See R2-2 (required).**

**Astra extras:** joint commit via the one choke point is real (`store_runtime_view` `coordinator/mod.rs:1564`, `publish_runtime_view:1595`, `<`-fence admitting equal at `:1690-1701`); recovery state table and numeric M0/M1 gates present; `choose_v4_route` composition verified at `forwarding/fib.rs:862-881`; version constant confirmed 16 (`protocol/control.rs:131`).

---

## B. New findings

### REQUIRED (round-3 admission blockers — spec gaps, not redesign)

**R2-1. Pre-bump concurrency is unspecified and revives a disposed lost-update race.** The shim bump is an unsynchronized read-modify-write on `fib_gen_map` (`maps_fabric.go:90-108`), and `userspace.Manager.BumpFIBGeneration` calls it *before* taking `m.mu` (`manager_generation.go:56-57`). The only reason this was dispositioned not-material (`docs/reviews/reports/result-gemini-review-047.md:96-103`) is "no concurrent caller exists": the live callers are serialized under `d.applySem` (ipmon `pendingFIBBump`) and the CompileConfig tail (`compiler_fibgen.go:44-53`). v17 adds a **new** bump site (transfer pre-bump) on a sender that §5-1.9 deliberately runs with `m.mu` released between chunks and whose execution context (applySem? own goroutine? status-tick d…

This also answers **Q1** (enumerate the pre-bump→commit gap consumers):
- Snapshot builders stamping `readFIBGeneration()` (`manager_compile.go:258`, `manager_overlay.go:193`, `manager_worker_arm_5134.go:65`) — benign: helper gates are monotone-≥ (`server/handlers/snapshot.rs:92-103`) and v17 applies replay retained learned, so an early G+1 apply is an ordinary advance.
- BPF `session.fib_gen` vs map — self-healing: BPF re-runs lookup and re-stamps from the map on mismatch (`maps_fabric.go:73-76`, `xpf_maps.h:329-341`), so map-ahead costs one extra lookup per session, not a blackhole.
- The RMW race above — the one real hazard.
- Rejected-commit residue (map ahead, helper behind until re-transfer): the plan must add a re-pair rule — on NAK, send `bump_fib_generation` with the *current map value* (equality admitted by the `<`-fence, `coordinator/mod.rs:1690-1701`) instead of waiting for the next transfer/anti-entropy window.

**R2-2. Phase-3 matrix contains a row that is false under one of its two only readings.** "New helper + old Go: capped snapshots honored by the gate (byte-identical, no blackhole)" — but the snapshot version gate is exact-equality lockstep by design (`control.rs:131`, `protocol.go:13-18`: "a helper at ANY other version refuses the snapshot outright"). If v17 bumps `CONFIG_SNAPSHOT_PROTOCOL_VERSION` to 17, a new helper *refuses* old Go's v16 snapshots — the row is wrong and the pairing is a loud fail-closed state, not "honored". If v17 keeps the constant at 16 (additive verb only — the unknown-type refusal arm at `server/handlers/mod.rs:339-342` handles old helpers per-verb), then "Go learns the helper version from status BEFORE choosing the path" ha…
  - **(a) recommended:** keep snapshot version 16, add an omitempty `RouteTransferProtocolVersion`-style status field (the mixed-version precedent used throughout `protocol_status.go`); the matrix row then becomes true as written, old-helper detection is positive (no refusal storm), and the #4626 additive-field lesson is respected because the new fields ride a *new verb*, not the snapshot.
  - (b) bump to 17 and rewrite the row as "refused loudly; unreachable via same-package spawn coupling + `ensure*ProtocolLocked` disarm discipline" — and then the rollout contract's "Go-first safe" leg must lean on `process_identity_restart_8899_test.go` explicitly rather than on gate acceptance.

### MINOR (should-fix; not blocking)

**R2-3. Retention replay must enumerate all three rebuild paths.** Plan names `apply_snapshot` and "overlay path"; the actual sites are the reconcile apply (`coordinator/reconcile/snapshot.rs:538`), the armed same-plan refresh (`refresh_runtime_snapshot`, `server/handlers/snapshot.rs:296-322`), and the **disarmed twin** (`refresh_runtime_snapshot_disarmed`, `snapshot.rs:313-317`). Missing the disarmed variant re-opens the wipe on disarmed-then-armed transitions. The M2 no-wipe cell should pin all three.

**R2-4. Suppression-key parity is under-specified, and Q3 is "chosen" and "open" simultaneously.** §5-1.7 presents Rust-side suppression as chosen; Q3 re-opens it. Adjudication: **keep it Rust-side** — the Go-side-carried alternative is unbuildable at apply time (Go cannot know the helper's retained set after a daemon restart, and carrying a full covered-key list per apply is a 1M-string payload for a cold event). But the ban-scoping must be recorded: the round-1 helper-coverage ban applies to *transfer-time gap-fill* (kernel-table policy, cap semantics — stays Go-computed per `routes.go:789-792`); apply-time suppression is exact-key equality over Go-authored snapshot content, a different and mechanical object. Also: the parity corpus pins destinatio…

**R2-5. The commit must update the status pair, not just `ValidationState`.** The apply/bump gates read `guard.status.last_fib_generation` as "the authoritative published pair the armed flow-cache's ValidationState is derived from" (`server/handlers/snapshot.rs:36-40`). §5-1.4 assigns `self.validation.fib_generation` + publish only. I traced the lag as benign (healthy Go only sends fib ≥ shim value, so no gate can regress), but the invariant comment says the two never disagree — the commit verb should set `guard.status.last_fib_generation` in the same critical section, one line.

**R2-6. K=3 measures the wrong churn without a config-abort leg.** Add to the M1 convergence cell: a config-identity change mid-transfer (helper aborts at chunk ingest), and state the convergence bound honestly — one quiet window ≥ one transfer duration — plus the argument that the target workload (kernel route churn) does not move config identity.

**R2-7. "Sticky first-refusal" is a Go-side latch, not helper behavior.** The Rust unknown-type arm is stateless per request (`server/handlers/mod.rs:339-342`). Fine as designed under resolution R2-2(a) (positive status detection makes the latch a backstop); say so.

**R2-8. Anti-entropy framing:** the *primary* drift detector is the echo-compare on every status tick (§5-1.5); M=30min is a backstop for hash-parity divergence, not the detection bound. State it that way and Q5 dissolves (drift requires a code-bug in the replay path, detected within one tick by the echo, bounded by M for full re-transfer).

---

## C. Remaining open questions (Q2, Q4, Q6, Q7)

- **Q2 (staleness bound):** accept "≤ next transfer"; a synchronous re-issue on every apply would couple config-commit latency to a 1M-route rebuild for a table that actuation will re-transfer anyway. Record it as the bound.
- **Q4 (iface_ctx abort rate):** acceptable — link churn aborts a transfer but cannot livelock it (abort ⇒ re-arm, and link-churn storms are bounded events); keep the M1 measurement.
- **Q6:** proceed. Phase 0/1 shippable independently, Phase 2 killed; the remaining mass is justified by the acceptance framing. Not a #946-pattern violation as scoped.
- **Q7:** with R2-2(a), same-package coupling + positive status detection + loud refusal is sufficient; a verb-ignored compat window is not required and would reintroduce the hole by design.

---

## Verdict

**NEEDS-MINOR** — two required, localized spec closures (R2-1 pre-bump serialization + NAK re-pair rule; R2-2 version-identity fork with matrix row made truthful), plus six minor precision items. All five round-1 majors are genuinely closed in mechanism against head; nothing found requires architectural rework. Round 3 may proceed once R2-1/R2-2 are written into the plan.
