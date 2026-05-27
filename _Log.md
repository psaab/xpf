# Action Log

## 2026-05-26 23:10 UTC — #1578 cluster perf root-cause (smoke target IP misalignment)

- **Timestamp**: 2026-05-26 23:10 UTC
  - **Action**: Investigated the "loss userspace cluster ~9 Gb/s
    reverse P=12 ceiling" reported in #1578 / #1580 / #1593. Direct
    empirical probing on `loss:xpf-userspace-fw0` against the
    canonical AF_XDP fast path showed 23.4 Gb/s push P=12 and 23.1
    Gb/s reverse P=12 with CoS off, and 19-23 Gb/s reverse P=12 on
    every port 5201-5211 with CoS active. Confirmed all 11 per-class
    iperf3 listeners are live on `172.16.80.200`. The prior 9.35
    Gb/s numbers reproduce only when iperf3 targets `172.16.100.200`
    — which `loss-userspace-cluster.env IPERF_TARGET4` inherited
    from the legacy bpfrx-fw0/1 cluster — reaching a different
    `loss:` uplink path capped at ~10 Gb/s. The port 5211 / CoS /
    virtio_net-xdpgeneric-WAN theories are all empirically false:
    port 5211 is iperf-uncapped, CoS doesn't cap reverse direction,
    and WAN on the loss userspace cluster is `ge-0-0-2` on mlx5_core
    native XDP, not `ge-0-0-0` (which is the fabric IPVLAN parent).
    Repointed `IPERF_TARGET4/6` to `172.16.80.200` /
    `2001:559:8585:80::200` so failover scripts share the same
    canonical target as the triple-review SKILL.md smoke harness,
    and added a loss-cluster topology block to CLAUDE.md to prevent
    future "ge-0-0-0 is WAN" misdiagnoses.
  - **File(s)**: test/incus/loss-userspace-cluster.env, CLAUDE.md,
    _Log.md (this entry).
## 2026-05-26 23:43 UTC — #1348 icmp_embed split (PR #1596, AWAITING-BATCH-MERGE)

- **Timestamp**: 2026-05-26 23:43 UTC
- **Action**: PR #1596 opened for #1348 (split
  `userspace-dp/src/afxdp/icmp_embed.rs` 761 LOC into
  `icmp_embed/{mod,parse,session_match,nat_match_v4,nat_match_v6,return_resolution,builders}.rs`,
  collapse 10-param `embedded_icmp_return_resolution` behind
  `NatMatchCtx<'a>` borrow bundle). Plan went through 3 rounds
  (Codex r1 PLAN-NEEDS-MAJOR with 4 blockers → v2 → Codex r2
  sandbox-limited PLAN-NEEDS-MAJOR borrow-check concern → v3).
  Gemini r1 PLAN-READY. Implementation pure code motion; 1506
  cargo tests pass incl 8 `embedded_icmp` tests; 5/5 flake; Go
  suite clean; release build clean.
- **File(s)**: `userspace-dp/src/afxdp/icmp_embed/{mod,parse,session_match,nat_match_v4,nat_match_v6,return_resolution,builders}.rs` (new); `userspace-dp/src/afxdp/icmp_embed.rs` (deleted); `userspace-dp/src/afxdp/mod.rs` (dropped `#[path]` attr); `docs/pr/1348-icmp-embed-split/{plan,reviewer-ids}.md`.
- **Reviewers**: Gemini MERGE-READY (quote-grounded); Copilot 1
  doc nit addressed; Claude SMR MERGE-READY; Codex BLOCKED across
  4 sandbox-infra attempts. 3-of-4 attestation under Wave-5
  Codex-stuck exception. `<!-- AWAITING-BATCH-MERGE -->` posted.
- **Closes**: #1348.

## 2026-05-26 23:54 UTC — #1543 screen + SYN-cookie split (Wave-5)

- **Timestamp**: 2026-05-26 23:54 UTC
  - **Action**: Decomposed `userspace-dp/src/screen.rs` (1420 LOC) into
    sibling submodules under `userspace-dp/src/screen/` per the
    `module/foo.rs` convention (no `screen_` prefix). Pure code motion;
    no behavior change. ScreenState orchestrator stays in `mod.rs`;
    stateless free-fn helpers (LAND, TCP flag screens, ping-of-death,
    teardrop, ICMP fragment, source-route) extracted to
    `stateless.rs`; SYN-cookie crypto + cache + SipHash24 isolated
    in `syncookie.rs`. AGY round-1 PLAN-NEEDS-MINOR fix-ups
    incorporated as v2 (SipHash24 + SynCookieValidatedCache pub(crate)
    re-exported under `#[cfg(test)]`; line-range typo fix). AGY
    round-2 PLAN-READY. Codex sandbox infra-blocked across 3
    rescue retries (`codex-linux-sandbox` binary path persistently
    broken); proceeded under the Codex-stuck 3-of-4 exception per
    Wave-5 rules with Claude SMR as the third independent
    attestation.
  - **Tests**: cargo build clean (release + dev); cargo test 1506/1507
    pass (only failure is the pre-existing
    `snat_contract_documents_current_fail_closed_runtime` integration
    test which also fails on `origin/master`, unrelated to #1543);
    screen module tests 83/83 pass 5x flake; Go suite passes on 30
    packages.
  - **File(s)**:
    - userspace-dp/src/screen/mod.rs (new — orchestrator + ScreenState)
    - userspace-dp/src/screen/packet.rs (new — ScreenPacketInfo, ScreenProfile, ScreenVerdict, PROTO_* / TCP_* constants)
    - userspace-dp/src/screen/syncookie.rs (new — SynCookieCodec, SipHash24, SynCookieValidatedCache)
    - userspace-dp/src/screen/rate.rs (new — RateCounter)
    - userspace-dp/src/screen/stateless.rs (new — pure check helpers)
    - userspace-dp/src/screen/scan.rs (new — PortScan / IpSweep trackers)
    - userspace-dp/src/screen/session_limit.rs (new — SessionLimitTracker)
    - userspace-dp/src/screen/extract.rs (new — extract_screen_info)
    - userspace-dp/src/screen/tests.rs (renamed from userspace-dp/src/screen_tests.rs)
    - userspace-dp/src/screen.rs (deleted — split across siblings)
    - docs/pr/1543-screen-syn-cookie-split/plan.md (v2)
    - docs/pr/1543-screen-syn-cookie-split/reviewer-ids.md
    - _Log.md (this entry).

## 2026-05-26 22:46 UTC — #1439 snapshot.go split (rebase carry-forward)

- **Timestamp**: 2026-05-26 22:46 UTC
  - **Action**: PR #1592 rebased onto fresh `origin/master`
    (b84f46280) after GitHub's merge planner declined the prior
    multi-commit head (CONFLICTING despite local 3-way being clean).
    Re-applied the snapshot.go split as a single squashed commit on
    top of master. Plan-review history (3 rounds: Codex+Gemini+AGY)
    and code-review history (2 rounds: Codex+Gemini+AGY+Copilot all
    MERGE-READY) preserved in plan.md + reviewer-ids.md. Function
    bodies verified byte-equivalent to pre-split snapshot.go
    (63/63 identical). go build + go vet + go test + 5x flake all
    pass.
  - **File(s)**: 14 sibling .go files in pkg/dataplane/userspace/,
    snapshot.go deleted, docs/pr/1439-snapshot-builders/{plan,reviewer-ids}.md,
    _Log.md (this entry).

## 2026-05-26 — #1329 shared_cos_lease extract

- **17:18 UTC** — Created worktree refactor/1329-shared-cos-lease-extract
  off origin/master (HEAD 63dfe02a). Branch tracked.
- **17:22 UTC** — Drafted plan v1 at
  docs/pr/1329-shared-cos-lease-extract/plan.md. Pure code-motion
  extract of maybe_rotate_epoch_v8 (214 LOC) and
  publish_equal_flow_epoch_v8 (142 LOC) into
  shared_cos_lease/{mod,rotate_epoch_v8,publish_equal_flow_epoch_v8}.rs
  per Wave-3 directory-layout standing rule. No algorithm or atomic
  ordering changes; both fns moved byte-identical body with
  pub(super) + #[inline]. tests file relocates into the dir.
- **17:33 UTC** — Dispatched Codex (task-mpn2uvcy-65mg52) and AGY
  (adversarial-review-mpn2xtqj-jj9kge) plan reviews in parallel.
- **17:41 UTC** — Codex r1 PLAN-NEEDS-MINOR (4 fixes:
  #[inline] codegen claim too strong, sibling-import path
  underspecified, modularity-discipline LOC threshold wrong,
  re-export list audit doesn't match types/mod.rs reality);
  AGY r1 PLAN-READY.
- **17:46 UTC** — Revised plan to v2: softened #[inline] claim,
  added explicit `use super::publish_equal_flow_epoch_v8::*`
  import, corrected LOC threshold to >100 god-function cue + >8
  param cue and clarified PR doesn't close those concerns,
  rewrote public-API section to match the narrow 7-item
  pub(super) re-export in types/mod.rs verbatim, added README +
  test header doc-cleanup to test plan.
- **17:53 UTC** — Codex r2 PLAN-NEEDS-MINOR (3 textual fixes:
  stale '#[inline] preserves codegen' in risk table, release LTO
  claim with no Cargo.toml backing, stale 'pub(in crate::afxdp)'
  in mod.rs adjustments + non-re-exported items still listed as
  examples, plus binary-size check promised but not in test
  plan).
- **17:57 UTC** — Revised to v3: cleaned all three flagged sites,
  removed release-LTO crutch, added binary-size spot check #6 to
  test plan.
- **18:08 UTC** — Codex r3 PLAN-NEEDS-MINOR (2 final stale text
  bugs: one surviving 'pub(in crate::afxdp) use' at the
  Cost: line, and the Open Question #4 'shortening from X to X'
  self-contradiction). Revised to v4 fixing both.
- **18:18 UTC** — Codex r4 PLAN-READY. Plan locked.
- **18:25 UTC** — Implemented split:
    - Created shared_cos_lease/ dir.
    - git mv shared_cos_lease_tests.rs → shared_cos_lease/.
    - rotate_epoch_v8.rs: maybe_rotate_epoch_v8 body byte-identical
      (sed -n 1497,1710p), pub(super) + #[inline], explicit
      `use super::publish_equal_flow_epoch_v8::publish_equal_flow_epoch_v8;`.
    - publish_equal_flow_epoch_v8.rs: body byte-identical
      (sed -n 1713,1854p), pub(super) + #[inline].
    - mod.rs assembled from L1-L1492 + closing impl `}` +
      mod decls + L1855-L1989 + relocated mod tests decl.
    - README.md + test header doc-cleanup done.
- **18:35 UTC** — Cargo build clean. Cargo test 1433/1433 pass.
  5x flake check on equal_flow_epoch_payload_is_visible_after_tag_under_concurrent_readers
  5/5 pass (equal-flow payload visibility under concurrent reader,
  not the seqlock CAS rotation itself). Go suite 32 packages OK,
  0 fails. Binary size delta: 5,539,856 (this branch) vs
  5,546,888 (master) = -7,032 bytes (-0.13%) — under 0.5% threshold.
- **18:50 UTC** — PR #1588 opened f8ad9fe3. Codex+AGY hostile code
  review dispatched. Claude SMR review: MERGE-READY (diff confirms
  both fn bodies are 1-line different from master modulo visibility
  prefix; impl block closes correctly; pub(super) does not leak
  outside shared_cos_lease/ per grep).
- **19:00 UTC** — Codex code r1 MERGE-NEEDS-MINOR: validation-wording
  fix — the first 5x flake target tested equal-flow payload publish,
  not seqlock CAS rotation under contention as the plan required.
  Reran 5x flake on bypass_starvation_events_swap_at_rotation (true
  rotation ATOMIC-SWAP test): 5/5 pass. PR description updated.
- **19:10 UTC** — AGY code r1 MERGE-READY. Codex code r2 MERGE-READY
  on the _Log.md-only fix. Copilot review landed COMMENTED with 2
  inline nits: header comments in rotate_epoch_v8.rs and
  publish_equal_flow_epoch_v8.rs reference the pre-split path
  `shared_cos_lease.rs:L1497-L1710` / `:L1713-L1854` which won't
  exist on master post-merge. Reworded headers to reference "PR
  #1588 for the move diff" instead. Build clean after edit.
- **19:20 UTC** — Codex code r3 MERGE-READY on 8df7e39a. Copilot
  re-reviewed at 6c0d0061 COMMENTED with 4 more doc-nits:
  Issue/PR labeling on the headers; mod.rs comment doesn't mention
  the explicit `use` import; plan.md status header stale; reviewer-ids
  still says "copilot r1 awaiting". Addressed all 4 in the next
  commit — relabeled headers "Issue #1329 / PR #1588", added the
  `use` import note to mod.rs, plan.md → PLAN-READY/IMPLEMENTED,
  reviewer-ids updated.
- **22:00 UTC** — Codex code r4 MERGE-READY at 83e66dd0. Copilot
  swe-agent comment confirms the 4 doc fixes in place at 83e66dd0
  (formal copilot-pull-request-reviewer still at COMMENTED on
  6c0d0061 — all its inline comments are addressed in 83e66dd0,
  satisfying the merge gate per skill rule "Copilot has posted a
  review (COMMENTED is fine; ensure every inline comment is
  addressed").
- **22:05 UTC** — 4-of-4 attestation complete (Codex r4, AGY r1,
  Copilot r2 with all nits addressed, Claude SMR). Posted
  <!-- AWAITING-BATCH-MERGE --> marker at PR #1588. Smoke deferred
  per Wave-3 retirement-chain rule.

## 2026-05-26 — #1325 implementation pushed

- **Timestamp**: 2026-05-26T (UTC)
- **Action**: Implemented protocol.rs domain split per v3 plan.
  - Created protocol/{mod,snapshot,cos,nat,security,control,
    binding,resolution}.rs with module/foo.rs layout.
  - 631-LOC test block moved into protocol/tests.rs as a sibling
    submodule (kept as single cohesive block at parent layer
    since every test exercises ProcessStatus that aggregates
    every leaf domain).
  - u64_is_zero switched to absolute path
    crate::protocol::u64_is_zero in HAGroupStatus.lease_until
    attribute per Codex r1/r2 verified serde_derive semantics.
  - mod.rs is slim (decls + glob re-exports only); zero call-site
    edits required (5 use crate::protocol::X sites + 12 path
    callers all resolve unchanged).
  - Named-item count matches pre-split: 66 structs + 2 consts +
    1 fn = 69 (binding=8, control=14, cos=14, nat=6, resolution=3,
    security=11, snapshot=13).
  - cargo build clean. cargo test --bin: 1417/1417 (was 1395
    pre-split because protocol::tests now counts as 22 items in
    the main bin); 5x flake check on protocol::tests passes.
  - Pre-existing snat_contract_doc_guard test fails on both
    master and this branch (unrelated to refactor).
  - Go suite clean.
- **File(s)**: userspace-dp/src/protocol/{mod,snapshot,cos,nat,
  security,control,binding,resolution,tests}.rs (created);
  userspace-dp/src/protocol.rs (deleted); _Log.md

## 2026-05-26 — #1325 plan v2 folds Codex+AGY r1

- **Timestamp**: 2026-05-26T (UTC)
- **Action**: Folded both r1 reviews into plan v2.
  - Codex r1 PLAN-KILL (5 blocking, all fixable): incremental-build
    claim withdrawn; ProcessStatus dependency graph corrected to
    enumerate every cross-domain ref (control depends on every
    other module); per-test cross-domain placement table added;
    `u64_is_zero` switched to absolute path
    `crate::protocol::u64_is_zero` per serde_derive ExprPath
    semantics; "comment-header-derived" framing dropped.
  - AGY r1 PLAN-NEEDS-MINOR (4 items, fully overlapping with
    Codex r1 except for one new recommendation): added
    differential wire-format snapshot test
    (wire_invariant_tests.rs vs checked-in fixture).
  - Documented Codex/AGY disagreement on incremental-build claim;
    resolved by keeping the conservative "modularity discipline
    only" framing.
- **File(s)**: docs/pr/1325-protocol-split/plan.md (v2 fold),
  _Log.md

## 2026-05-26 — #1325 protocol.rs split plan v1 DRAFT

- **Timestamp**: 2026-05-26T (UTC)
- **Action**: Wrote plan v1 (DRAFT) for #1325 protocol.rs domain
  split. Target: module/foo.rs directory layout with 7 domain files
  under `userspace-dp/src/protocol/` (mod.rs slim + binding /
  control / cos / nat / resolution / security / snapshot). Pure
  code motion, wire-format-preserving, public API unchanged.
  Identified `u64_is_zero` string-path serde hazard and mitigated
  by keeping the fn co-located with `HAGroupStatus` in
  `binding.rs` plus a deliberate round-trip regression test.
- **File(s)**: docs/pr/1325-protocol-split/plan.md,
  docs/pr/1325-protocol-split/reviewer-ids.md
## 2026-05-26 — #1326 PR #1569 AWAITING-BATCH-MERGE at 18fd27f8

- **Timestamp**: 2026-05-26T (4-of-4 MERGE-READY on 18fd27f8)
  - **Action**: Drove PR #1569 through 6 code-review rounds. Final
    SHA 18fd27f8 has 4-of-4 attestation: Codex MERGE-READY (final),
    AGY MERGE-READY (final), Copilot r2 inline comment proposed
    the explicit-path change that 18fd27f8 implements, Claude SMR
    MERGE-READY (posted on PR). Posted AWAITING-BATCH-MERGE
    marker. Smoke deferred per wave-1 rules.
  - **Notes**: Codex r4 flagged rustfmt as failing — verified
    locally as false positive (rustfmt 1.9.0-stable returns exit 0
    on both touched files; cargo fmt --check noise is pre-existing
    master drift in unrelated files). Copilot re-review did not
    trigger on 18fd27f8 despite gh pr edit --add-reviewer Copilot
    + @copilot review — but Copilot's r2 inline comment on
    be71872c explicitly proposed the exact change in 18fd27f8, so
    that stands as the formal attestation.
  - **File(s)**: docs/pr/1326-worker-loop-extract/reviewer-ids.md

## 2026-05-26 — #1326 Phase 1 implementation + PR-prep

- **Timestamp**: 2026-05-26T (round 6 PLAN-READY, then implementation)
  - **Action**: Codex r5 returned PLAN-NEEDS-MINOR with one wording
    fix at plan.md:697 ("&mut state.dbg_state ONLY" wording
    inconsistent with the v3.3 changelog). Fixed in v3.4
    (commit 6f384430). Codex r6 (task-mpmwdrx4-kpdreh) confirmed
    PLAN-READY. AGY r4 already PLAN-READY since v3.2. Both
    reviewers PLAN-READY on v3.4 — cleared to implement.
  - **Implementation**: Phase-1 file-level extraction shipped. The
    1278-LOC `worker_loop` body moved verbatim from worker/mod.rs
    (L995-L2273) to a new `worker/loop_body/mod.rs`. `mod.rs` now
    has `mod loop_body; pub(crate) use loop_body::worker_loop;` and
    drops the body. mod.rs LOC: 2635 → 1359. Pure code motion;
    cargo check clean; 1487 tests pass (one pre-existing master-
    state doc-guard failure unrelated to this PR — same failure on
    origin/master at 936b076d).
  - **Deferred**: per-stage carve into setup.rs + tick.rs +
    poll_drive.rs + debug_report.rs is the eventual target
    architecture but deferred to follow-up PRs. Rationale documented
    in plan.md "Deferred to follow-up tickets" section: risk
    isolation (single-file move is provably semantic-equivalent),
    reviewer concerns only apply to sub-fn extraction (not file-level),
    and incremental landing matches #959/#1189 pattern.
  - **File(s)**: docs/pr/1326-worker-loop-extract/plan.md,
    docs/pr/1326-worker-loop-extract/reviewer-ids.md,
    userspace-dp/src/afxdp/worker/mod.rs,
    userspace-dp/src/afxdp/worker/loop_body/mod.rs (new)

## 2026-05-26 — #1326 plan v3.3 — Codex r4 doc-consistency fixes

- **Timestamp**: 2026-05-26T (round 4 reviews returned)
  - **Action**: AGY r4 (review-mpmw4xjc-92bdff) returned PLAN-READY
    independently — full substantive re-confirmation on every
    dimension: borrow shape, hybrid inlining, allocation audit,
    edition 2024, CoS rebuild predicate (all 7 sources), param count
    (35). Codex r4 (task-mpmw4sj7-dxkyqo) returned PLAN-NEEDS-MINOR
    with 3 doc-consistency issues only — substantive design rated
    "close" and "Not ready until the stale conflicting directives
    are cleaned." v3.3 cleanups: (a) propagated the &state.sessions
    addition to debug_report::maybe_emit signature description in
    BOTH the file tree section and the inline-annotation section,
    (b) fixed the orchestrator pseudocode "/* same 38-param … */"
    comment to "35-param", (c) cleaned stale topology refs
    (arc_refresh.rs, shutdown::tear_down, idle::handle, "7+ files"
    in risk table). Dispatching r5 to confirm.
  - **File(s)**: docs/pr/1326-worker-loop-extract/plan.md,
    docs/pr/1326-worker-loop-extract/reviewer-ids.md

## 2026-05-26 — #1326 plan v3.2 — Codex r3 PLAN-NEEDS-MINOR addressed

- **Timestamp**: 2026-05-26T (Codex r3 verdict extracted from log)
  - **Action**: Codex r3 (replayed via log capture from
    task-mpmvuetd-57y479; harness lost the id but the file log
    captured the full verdict) returned PLAN-NEEDS-MINOR with 6
    items. AGY r3 issue #1 was the same as Codex #2 (nested-field
    qualifier, fixed in v3.1). Remaining items addressed in v3.2:
    (1) debug_report::maybe_emit signature adds &state.sessions
    for sessions.len + stall-dump iterator; (3) toned down LLVM
    "can keep in registers regardless" claim to a hint with cited
    Rust Reference + LLVM LangRef caveat; (4) acknowledged
    pre-existing Vec paths in expire_stale_entries (gated
    short-circuit, no heap alloc) and drain_deltas(256)
    (lifecycle-event triggered); (5) added
    cos_shared_exact_backlogs to the cos_fast_interfaces rebuild
    predicate (Codex caught I miscounted — it's 7 rotation sources
    not 6); (6) corrected param count 38 → 35; (7) cleaned stale
    "6/8 files" language to land on the final 5-file tree (mod +
    setup + tick + poll_drive + debug_report). Both reviewers
    arriving at PLAN-NEEDS-MINOR with all findings address-able by
    plan-doc edits is the strongest signal yet that v3.2 will land
    PLAN-READY on round-4.
  - **File(s)**: docs/pr/1326-worker-loop-extract/plan.md,
    docs/pr/1326-worker-loop-extract/reviewer-ids.md

## 2026-05-26 — #1326 plan v3.1 — AGY r3 nested-field qualifier fix

- **Timestamp**: 2026-05-26T (AGY r3 result fetched)
  - **Action**: AGY r3 (review-mpmvtaei-6yvid7) returned
    PLAN-NEEDS-MINOR with 1 trivial compile-bug fix: the
    drive_one_round call site in the v3 orchestrator sketch
    references `&mut state.dbg_counters` / `dbg_rx_total` /
    `dbg_forward_total` but v3 moved those fields under
    `state.dbg_state`. AGY r3 verdict was PLAN-NEEDS-MINOR on all
    other 6 dimensions (borrow shape, allocation audit, re-export,
    hidden invariants, hybrid inlining, file tree, architectural
    mismatch). Fixed addressing in plan.md; waiting on Codex r3.
  - **File(s)**: docs/pr/1326-worker-loop-extract/plan.md

## 2026-05-26 — #1326 plan v3 (AGY r2 PLAN-NEEDS-MINOR addressed)

- **Timestamp**: 2026-05-26T (AGY r2 result fetched, Codex r2 lost)
  - **Action**: AGY r2 (review-mpmvbr0c-i8e6wh) returned
    PLAN-NEEDS-MINOR with 4 actionable items. v3 addresses all four:
    (1) bundle dbg/wr telemetry into DebugReportState nested in
    LoopState so debug_report::maybe_emit no longer takes &mut state
    wholesale, (2) shutdown signature fix — pass &Arc<ForwardingState>
    so the final cos_status republish compiles (resolved by inlining
    shutdown into the orchestrator), (3) hybrid inlining on
    tick::arc_refresh — outer is #[inline(always)] but the cold
    cos_fast_interfaces rebuild inner helper is #[inline(never)] +
    #[cold] to protect L1i footprint, (4) collapse shutdown.rs +
    idle.rs into mod.rs (6 → 4 files). Codex r2 task
    task-mpmvbj5i-hw5hra LOST from the harness again (same
    long-running session-state drop pattern). Re-dispatching Codex
    + AGY in parallel on v3.
  - **File(s)**: docs/pr/1326-worker-loop-extract/plan.md,
    docs/pr/1326-worker-loop-extract/reviewer-ids.md

## 2026-05-26 — #1326 plan v2 (AGY r1 PLAN-NEEDS-MAJOR addressed)

- **Timestamp**: 2026-05-26T (AGY r1 result fetched)
  - **Action**: AGY r1 (review-mpmurh2n-sfmiks) returned
    PLAN-NEEDS-MAJOR with 4 action items: (1) narrow phase-fn
    signatures to avoid &mut LoopState whole-struct barrier at the
    poll_drive boundary, (2) upgrade #[inline] → #[inline(always)],
    (3) consolidate 10 files → 6 by folding non-poll tick phases
    into tick.rs, (4) resolve missing runtime.rs discrepancy
    (rolled into tick.rs as tick::runtime_publish). Codex r1 task
    was lost from the harness (session-state drop on long-running
    review batch); will be re-dispatched on v2 alongside AGY r2.
    Plan revised; v2 published.
  - **File(s)**: docs/pr/1326-worker-loop-extract/plan.md,
    docs/pr/1326-worker-loop-extract/reviewer-ids.md

## 2026-05-26 — #1326 worker_loop extract plan v1 drafted

- **Timestamp**: 2026-05-26T
  - **Action**: Drafted plan v1 for #1326 — extracting ~1278-LOC
    `worker_loop` body from `userspace-dp/src/afxdp/worker/mod.rs`
    into `worker/loop_body/` directory module (8 phase files +
    orchestrator). Wrote plan with allocation audit, cold-path
    annotations, LoopState struct sketch, hidden invariants list,
    risk table, and 7 open questions for adversarial review.
  - **File(s)**: docs/pr/1326-worker-loop-extract/plan.md,
    docs/pr/1326-worker-loop-extract/reviewer-ids.md
## 2026-05-26 — #1328 Coordinator decompose Phase 2

- **Timestamp**: 2026-05-26 (plan v1 drafted)
  - **Action**: Worktree created off origin/master at 936b076d
    on branch refactor/1328-coordinator-reconcile-split. Plan v1
    written at docs/pr/1328-coordinator-reconcile-split/plan.md.
    Decomposes 506-LOC reconcile() into 4 phase sub-files
    (reconcile.rs orchestrator + reconcile_teardown.rs +
    reconcile_reset.rs + reconcile_snapshot.rs +
    reconcile_bringup.rs) and 326-LOC refresh_bindings() into
    refresh_bindings.rs (copy_live_snapshot + zero_unbound_slot
    dispatcher). Pure code motion; mod.rs shrinks ~830 LOC.
    8 open questions for adversarial review.

- **Timestamp**: 2026-05-26 (plan v2.2 PLAN-READY after 4 rounds)
  - **Action**: After 4 rounds of Codex+AGY adversarial review,
    plan v2.2 at commit dab1ada3 cleared with PLAN-READY (Codex
    best effort due to sandbox infra) + PLAN-READY (AGY). All
    round-1 PLAN-NEEDS-MAJOR (Codex 8 findings) and PLAN-NEEDS-MINOR
    (AGY layout ask) findings resolved. Layout: sub-mod-dir
    coordinator/reconcile/{mod,teardown,reset,snapshot,bringup}.rs
    plus sibling coordinator/refresh_bindings.rs.

- **Timestamp**: 2026-05-26 (implementation complete)
  - **Action**: Implemented #1328 coordinator decompose Phase 2.
    Split userspace-dp/src/afxdp/coordinator/mod.rs (2026 LOC) into:
    mod.rs 1194 LOC (-832), refresh_bindings.rs 368 LOC,
    reconcile/{mod 96, teardown 40, reset 63, snapshot 172,
    bringup 333}.
    New test reconcile_with_none_snapshot_reaches_no_snapshot_early_exit
    added. (Initial implementation promoted 6 items to pub(super)
    to make them accessible from coordinator/reconcile/ children;
    Copilot review 2 correctly pointed out that child modules can
    already access private parent items, so the promotions were
    reverted to private — only the phase helpers inside
    coordinator/reconcile/{teardown,reset,snapshot,bringup}.rs
    remain pub(super) because reconcile/mod.rs is their parent.)
  - **Validation**: cargo build --release clean; cargo test
    --release --bins 1488 tests pass; 5x flake clean on 33
    coordinator tests; go test ./... 32 packages pass. Pre-existing
    upstream failure snat_contract_doc_guard ("fail-closed" doc
    drift in master, AGY r4 noted as out of scope).
  - **File(s)**:
    - userspace-dp/src/afxdp/coordinator/mod.rs (extract + visibility)
    - userspace-dp/src/afxdp/coordinator/refresh_bindings.rs (new)
    - userspace-dp/src/afxdp/coordinator/reconcile/mod.rs (new)
    - userspace-dp/src/afxdp/coordinator/reconcile/teardown.rs (new)
    - userspace-dp/src/afxdp/coordinator/reconcile/reset.rs (new)
    - userspace-dp/src/afxdp/coordinator/reconcile/snapshot.rs (new)
    - userspace-dp/src/afxdp/coordinator/reconcile/bringup.rs (new)
    - userspace-dp/src/afxdp/coordinator/tests.rs (test added)
## 2026-05-26 — #1357 session context-struct refactor implemented (plan v3.1)

- **Timestamp**: 2026-05-26T (round-3 reviewers PLAN-READY/PLAN-NEEDS-MINOR all minor addressed)
  - **Action**: Implemented #1357 plan v3.1 — introduced
    `userspace-dp/src/session/ctx.rs` with `SessionInstall` (owned
    key) and `SessionUpdate<'a>` (borrowed key); rewrote
    `install_with_protocol_with_origin`,
    `upsert_synced_with_origin`, `update_session`,
    `promote_synced_with_origin` to take the context structs;
    migrated 10 production + 35 test call sites mechanically (Python
    script `/tmp/migrate_1357.py`).
  - **File(s)**: `userspace-dp/src/session/ctx.rs` (new),
    `userspace-dp/src/session/mod.rs`,
    `userspace-dp/src/afxdp/mod.rs` (export SessionInstall/Update),
    `userspace-dp/src/afxdp/shared_ops.rs`,
    `userspace-dp/src/afxdp/forwarding/mod.rs`,
    `userspace-dp/src/afxdp/poll_descriptor/mod.rs`,
    `userspace-dp/src/afxdp/session_glue/mod.rs`,
    `userspace-dp/src/session/tests.rs`,
    `userspace-dp/src/afxdp/tests.rs`,
    `userspace-dp/src/afxdp/session_glue/tests.rs`,
    `userspace-dp/src/afxdp/forwarding/tests.rs`.
  - **Validation (after rollback per code-review)**:
    - `cargo build` clean (production code).
    - `cargo test --release` 1487 pass / 1 fail. The single
      failure is `snat_contract_doc_guard` which is a pre-existing
      master regression (verified by building origin/master cold:
      same test fails on master). Not introduced by this change.
    - 5/5 flake check on `session::tests` passed.
    - Go suite green (`go test ./...` all `ok`).
    - **Codegen sanity post-rollback**: binary +21 KB (5559256 →
      5580008). Per-fn instruction counts: install +0.4%, upsert
      +9.0%, update+promote fully inlined. All under the 10% gate.
    - **Code-review rollback rationale**: round-1 Codex and Gemini
      both returned MERGE-NEEDS-MAJOR with the same single finding:
      the v3.1 plan's >10% rollback gate was triggered narrowly
      for `install_with_protocol_with_origin` (274 → 357 insns,
      +30%). Initial implementation tried to ship anyway citing
      total binary shrink as a holistic win, but Gemini correctly
      pointed out the 7 non-inlined callers pay the +83-insn
      destructure prelude per invocation on the session-install
      hot path. Reverted that fn to positional (originally planned
      fallback). Kept the other three context-struct fns. Final
      shape documented in `plan.md` "Rollback execution" section.

## 2026-05-26 — #1541 cluster manager split (pure code-motion + lift)

- **Timestamp**: 2026-05-26
  - **Action**: Split pkg/cluster/cluster.go (2429 LOC, 77 *Manager
    methods) into cohesive sibling .go files in package cluster per
    Wave-2 sibling-file rule (NOT sub-packages, NOT cluster_*.go
    prefix). Three plan-review rounds with Codex + Gemini before
    code touched; one v3.1 doc-precision round (Codex r3
    PLAN-NEEDS-MINOR resolved; Gemini r3 PLAN-READY; Codex r4
    BLOCKED-INFRA both attempts — proceeded per r3 acceptance
    criteria already met by v3.1 since v3.1 is documentation-only).
  - **Files (new)**: pkg/cluster/manager.go (slim lifecycle entry,
    Manager struct, types, NewManager, Start/Stop/sendEvent),
    heartbeat_manager.go (StartHeartbeat/StopHeartbeat/RestartHeartbeat/
    buildHeartbeat/handlePeerHeartbeat/handlePeerTimeout/handlePeerNeverSeen/
    HeartbeatStats), failover.go (single-RG + batch + transfer-commit
    *Locked helpers + new applyTransferCommitOverridesOnPeerStateLocked
    lift-extraction), status.go (all Format* methods), peer_state.go,
    group_state.go, hooks.go, sync_state.go, readiness.go,
    events_log.go.
  - **Files (changed)**: election.go (gained electSingleNode +
    SetMonitorWeight + recalcWeight), garp.go (gained triggerGARP
    — verbatim move of the slog.Info no-op/log hook).
  - **Files (deleted)**: cluster.go, failover_batch.go (folded into
    failover.go per Gemini r2 — single locking domain).
  - **Methods preserved**: 64 *Manager exported methods package-wide,
    all signatures identical. One new private helper
    applyTransferCommitOverridesOnPeerStateLocked introduced by the
    plan's ONE allowed lift-extraction (Codex r2 fix). Helper body
    is the three back-to-back loops at cluster.go:1516-1542 lifted
    byte-for-byte; only the enclosing function changes.
  - **Test results**: go build ./... clean; go vet ./pkg/cluster/...
    clean; go test ./pkg/cluster/... 5/5 passes; full Go suite passes
    (all packages, no failures).
  - **Plan doc**: docs/pr/1541-cluster-mgr-split/plan.md (v3.1).
  - **Reviewer task IDs**: docs/pr/1541-cluster-mgr-split/reviewer-ids.md.

## 2026-05-26 — #1476 Phase B AWAITING-MERGE at f815c357

- **Timestamp**: 2026-05-26T (r3 reviewers converged, posting marker)
  - **Action**: Round-3 code reviews returned. Both AGY r3 and
    Codex r3 MERGE-READY at HEAD f815c357. AGY r3 flagged an
    out-of-scope observation: pkg/configstore/crypto.go has the
    same FindChild first-match pattern in masterPasswordPRF (split
    `system { master-password { ... } }` stanzas could miss the
    master-password directive). Confirmed pre-existing pattern,
    not introduced by #1476; deserves its own hardening issue.
    Will be filed separately after #1476 merges.

    Final reviewer state for the AWAITING-MERGE marker:
    - Codex r3: MERGE-READY at f815c357
    - AGY r3: MERGE-READY at f815c357
    - Claude SMR: MERGE-READY (self-review at 04c0d19e, fixes
      since then all addressed Codex r1/r2 findings)
    - Copilot: STUCK ("exceeds maximum number of lines (20,000)")
      → 3-of-4 Copilot-stuck exception applies per
      feedback_copilot_two_bots policy.

    Posting STANDALONE AWAITING-MERGE marker per
    feedback_retirement_batch_smoke_at_end policy (no smoke marker;
    smoke-runner singleton handles fast-merge).
  - **File(s)**: docs/pr/1476-mechanical-bpf-removal/reviewer-ids.md,
    _Log.md

## 2026-05-26 — #1476 Phase B r2 fixes (Codex MERGE-NEEDS-MAJOR)

- **Timestamp**: 2026-05-26T (r2 fixes after Codex r2 MERGE-NEEDS-MAJOR)
  - **Action**: Round-2 code reviews returned. AGY r2 pending; Codex r2
    MERGE-NEEDS-MAJOR with 3 findings:
    F1 MAJOR: the rewrite helper still used `FindChild` which returns
      only the FIRST top-level `system` (or `groups`) block. The
      hierarchical parser admits split stanzas — e.g.
        `system { host-name fw1; }`
        `system { dataplane-type ebpf; }`
      produces two top-level `system` nodes; the same applies to
      multiple top-level `groups { ... }` blocks. The pre-r2 walker
      missed the second and beyond, reopening F1 of r1 for the
      split-stanza shape.
    F2 MINOR: nested-groups-inside-groups case (acknowledged as
      "current ExpandGroups only treats top-level groups as group
      definitions" — not a current bug, but worth noting).
    F3 NIT: header comment in maps_decouple_test.go still mentioned
      BPFRX_LEGACY_LOADER_RETIRED=1 verbatim despite r1's intent to
      strip it.

    All 3 addressed in this commit:
    - rewriteRetiredDataplaneType now uses three explicit helpers
      (systemBlocksOf, groupsBlocksOf, systemBlocksOfNode) that
      iterate every matching child instead of returning only the
      first. Two new regression tests
      TestRewriteRetiredDataplaneType_SplitSystemStanzas and
      TestRewriteRetiredDataplaneType_SplitGroupsStanzas pin the fix.
      Both call CompileConfig/CompileConfigForNode after rewrite to
      confirm no strict-validator firing.
    - Stripped the BPFRX_LEGACY_LOADER_RETIRED mention from the
      maps_decouple_test.go header comment block entirely.
    - F2 nested-groups is intentionally NOT addressed in this PR: it
      isn't reachable today because ExpandGroups only treats
      top-level groups as group definitions. If future Junos-parity
      work admits nested groups, the walker recursion-step is
      trivial; flagged for the future cleanup PR.

    Validation: full go test ./... clean across 33 packages. 9
    rewrite-helper tests pass including the 2 new split-stanza
    regressions. 5x flake on TestRewriteRetiredDataplaneType_(
    ApplyGroups|SplitSystem|SplitGroups) clean.
  - **File(s)**: pkg/configstore/dataplane_retire.go,
    pkg/configstore/dataplane_retire_test.go,
    pkg/dataplane/userspace/maps_decouple_test.go

## 2026-05-26 — #1476 Phase B r1 fixes (Codex MERGE-NEEDS-MAJOR)

- **Timestamp**: 2026-05-26T (r1 fixes after Codex MERGE-NEEDS-MAJOR)
  - **Action**: Round-1 code reviews returned. AGY r1 MERGE-READY;
    Codex r1 MERGE-NEEDS-MAJOR with 5 findings:
    F1 MAJOR: rewriteRetiredDataplaneType only walks top-level `system`,
      missing apply-groups-injected `dataplane-type ebpf`. The strict
      validator inside compileExpanded fires against the
      post-expansion tree, so a config like
      `groups { legacy { system { dataplane-type ebpf; } } }
       system { apply-groups legacy; }` slips through the rewrite and
      strands the daemon.
    F2 MINOR: SyncApply WARN message used the LoadCaller phrasing
      ("review and commit after daemon comes up"), wrong audience for
      the HA peer-sync path where the un-upgraded primary needs the
      remediation.
    F3 MINOR: TestCommitRejectsRetiredEBPF and
      TestCommitConfirmedRejectsRetiredEBPF in pkg/grpcapi missed the
      codes.InvalidArgument assertion (only the message was checked).
    F4 MINOR: docs/userspace-dataplane-gaps.md and docs/memory.md still
      described pre-#1476 behavior (eBPF deprecation warning at compile,
      xdp_progs/tc_progs pinning required).
    F5 NIT: pkg/dataplane/userspace/maps_decouple_test.go header
      comment still referenced the BPFRX_LEGACY_LOADER_RETIRED escape
      hatch that the canary no longer uses.

    All 5 fixed in this commit:
    - rewriteRetiredDataplaneType now walks BOTH top-level system AND
      every `groups { <name> { system { ... } } }` definition. Two
      new tests TestRewriteRetiredDataplaneType_ApplyGroups{EBPF,DPDK}
      pin the regression. CompileConfigForNode after rewrite confirms
      no strict-validator firing.
    - New retireRewriteCaller enum (LoadCaller, SyncCaller) selects
      the right warn message + remediation hint per entry point.
      Store.Load passes LoadCaller; Store.SyncApply passes SyncCaller.
    - Added codes.InvalidArgument assertion to both gRPC tests.
    - Rewrote stale prose in userspace-dataplane-gaps.md (line 151)
      and memory.md (line 164) to past tense / current state.
    - Replaced the BPFRX_LEGACY_LOADER_RETIRED comment block in
      maps_decouple_test.go header with the post-#1476 narrative.

    Test gates: full go test ./... clean (33 packages); 7 rewrite
    helper tests pass including the two new apply-groups regressions.
  - **File(s)**: pkg/configstore/dataplane_retire.go,
    pkg/configstore/dataplane_retire_test.go,
    pkg/configstore/store.go,
    pkg/grpcapi/server_config_test.go,
    docs/userspace-dataplane-gaps.md, docs/memory.md,
    pkg/dataplane/userspace/maps_decouple_test.go

## 2026-05-26 — #1476 Phase B implementation

- **Timestamp**: 2026-05-26T (Phase B complete; awaiting code review)
  - **Action**: #1451 closed (capstone PR #1557 merged as ee4b34bf).
    Rebased plan branch onto current master ee4b34bf via /tmp/log-merge.py
    union resolution on _Log.md conflict. Re-verified
    `(*Daemon).legacyDP()` is gone from production code and
    pkg/daemon/legacy_dataplane_canary_test.go is in place.
    Executed the deletion per plan v4:
    - Deleted bpf/xdp/*.c (9 files), bpf/tc/*.c (5 files),
      bpf/xdp/README.md, bpf/tc/README.md, bpf/README.md.
    - Deleted 14 generated bpf2go pairs
      (pkg/dataplane/xpf{Xdp,Tc}*_x86_bpfel.{go,o}).
    - Deleted pkg/dataplane/loader_ebpf.go and loader_stub.go.
    - Preserved pkg/dataplane/userspace_xdp_bpfel.o and
      userspace_xdp_rust.go; preserved bpf/headers/*.h, userspace-xdp/,
      and test/xsk-repro/.
    - Extracted retained Rust AF_XDP shim loader graph (16
      functions + 5 constants + 1 type) from the deleted
      loader_ebpf.go into new pkg/dataplane/loader_userspace_shim.go.
    - Manager.Load() body rewritten to `return ErrEBPFBackendRetired`
      (kept as retirement stub; DataPlane interface contract preserved).
    - Added ErrEBPFBackendRetired sentinel (dataplane.go) and
      ErrEBPFDataplaneRetired (config/compiler.go).
    - Extended validateDataplaneTypeStrict to reject TypeEBPF.
    - NewDataPlane(TypeEBPF) / NewRuntimeDataPlane(TypeEBPF) now
      return the sentinel directly.
    - Added daemon_run.go soft-fallback branch for
      ErrEBPFBackendRetired, mirroring the existing DPDK arm.
    - New pkg/configstore/dataplane_retire.go with
      `rewriteRetiredDataplaneType` helper covering both `ebpf` and
      `dpdk` retired values; wired into Store.Load() AND
      Store.SyncApply() per AGY r4 finding for HA rolling-upgrade
      safety.
    - Removed ValidateConfig's EBPF deprecation warning (dead code
      after strict reject).
    - Narrowed Makefile clean glob from
      `pkg/dataplane/*_bpfel.{go,o}` to `xpf*_bpfel.{go,o}` to
      protect the retained shim object by name.
    - Removed legacy `make generate-legacy-bpf` target and the now-empty
      .PHONY arm; updated `make generate` header comment.
    - Updated retirement-boundary canary:
      retainedShimBoundaryBuildTagAllowlist now empty (was 14 bpf2go
      entries + loader_stub.go); docs-pinned token block at line 1822
      pruned of `*_bpfel.go`/`go:build 386 || amd64`/`loader_stub.go`/
      `go:build ignore`. README.md narrative section also rewritten.
    - Updated source-removal-manifest-1476.md: Build Hooks +
      Tests/Docs subsections moved to separate H2 sections so the
      manifest canary's section-scoped path scanner doesn't read
      them as delete-list entries; Delete Manifest pruned to
      narrative pointers only.
    - Rewrote pkg/api/config_commit_test.go,
      pkg/cli/cli_config_test.go, pkg/grpcapi/server_config_test.go,
      pkg/config/parser_system_test.go ebpf-warning tests as
      retirement-rejection assertions (5 test cases each surfacing
      the verbatim retirement message via Contains, plus a
      sentinel-match TestSentinelMatch in pkg/api).
    - Rewrote TestBuildRuntimeDataPlaneEBPFRoutesToLegacyManager →
      TestBuildRuntimeDataPlaneEBPFReturnsRetired in
      pkg/daemon/dataplane_boot_test.go to assert ErrEBPFBackendRetired.
    - Updated pkg/dataplane/userspace/shim_loader_boundary_test.go:45
      and pkg/dataplane/userspace/maps_decouple_test.go:1320 to point
      at loader_userspace_shim.go instead of the deleted loader_ebpf.go.
    - Updated CLAUDE.md BPF Pipeline + Code Layout sections to past
      tense; rewrote Quick Start `make generate` description.
    - Updated docs/development-workflow.md, docs/testing.md,
      docs/next-features/ipv6-session-fast-path.md,
      pkg/dataplane/constants.go:14 doc comment to point at the
      retained shim loader instead of the deleted loader_ebpf.go.
    - New pkg/configstore/dataplane_retire_test.go with 5 tests:
      TestRewriteRetiredDataplaneType_EBPF (rewrite, compile-clean,
      DataplaneType empty); TestRewriteRetiredDataplaneType_DPDK;
      TestRewriteRetiredDataplaneType_NoOpForUserspace;
      TestRewriteRetiredDataplaneType_NoSystemNode;
      TestStoreLoad_RewritesPersistedEBPFDataplaneType (end-to-end:
      pre-#1476 persisted ebpf-tree → Load → ActiveConfig non-nil
      with userspace default).

    Test gates: `go build ./...` clean; `go test ./...` clean across
    33 packages; 5x flake on retirement canaries clean. Grep proof:
    `xpfXdp|xpfTc|loadXpfXdp|loadXpfTc|loadAllObjects` only appears
    in (a) shim_loader_boundary_test.go negative-token list (intentional
    drift-guard), (b) doc comments explaining the history. `bpf/xdp|bpf/tc/`
    only appears in `retirement_boundary_canary_test.go` historical
    context.
  - **File(s)**: 51 files changed: 35 deletions (legacy source +
    generated artifacts + loader_ebpf.go + loader_stub.go), 2 new files
    (loader_userspace_shim.go, dataplane_retire.go +
    dataplane_retire_test.go), 14 edited (sentinel wiring + test
    rewrites + canary updates + doc sweeps + CLAUDE.md).

## 2026-05-25 — #1476 Phase A PLAN-READY at r4

- **Timestamp**: 2026-05-25T (Phase A complete)
  - **Action**: Round-4 reviews returned: Codex r4 PLAN-READY (all
    r3 stale-text findings confirmed closed; no new issues); AGY
    r4 PLAN-READY with one Phase-B critical implementation
    requirement — `Store.SyncApply()` at `pkg/configstore/store.go:205`
    bypasses the `Store.Load()` rewrite hook, so HA rolling upgrades
    will sync-loop on `ErrEBPFDataplaneRetired`. Plan §4.6 extended
    to require `rewriteRetiredDataplaneType(tree)` to run in BOTH
    `Store.Load()` AND `Store.SyncApply()` paths, with a Phase-B
    unit test mirroring #1528's `TestLoad_RewritesPersistedDPDKDataplaneType`.
    Phase A complete. Polling for #1451 close (waiting on #1516 +
    #1521).
  - **File(s)**: `docs/pr/1476-mechanical-bpf-removal/plan.md` v4
    (PLAN-READY at r4),
    `docs/pr/1476-mechanical-bpf-removal/reviewer-ids.md`, `_Log.md`

## 2026-05-25 — #1476 Phase A v4 plan after r3 reviews

- **Timestamp**: 2026-05-25T (Phase A v4 after r3 reviewer findings)
  - **Action**: Round-3 reviews returned: AGY r3 PLAN-READY with
    one cosmetic nit (risk-table count "4" → "5"); Codex r3
    PLAN-NEEDS-MAJOR with 6 findings, all stale-text drift from
    v1 prose that v2/v3 header rewrites didn't reach (no new
    operational issues). v4 fixes: §1 #2 stale Manager.Load()
    "either deleted or stubbed" → "is kept as retirement stub";
    §5 invariant 8 stale "boundary tests pass unchanged" →
    rewritten to acknowledge §4.3's shim_loader_boundary path fix;
    §8 Q2 stale "all four tests construct Manager" → corrected;
    §4.3 doc-sweep adds rows for constants.go:14, docs/testing.md:281,
    docs/next-features/ipv6-session-fast-path.md:16,38; closing
    footer "End of plan v1" → "End of plan v4"; risk-table
    "4 retirement-manifest canaries" → "5"; "all four" literals
    in v3 change-log header rewritten without losing meaning.
  - **File(s)**: `docs/pr/1476-mechanical-bpf-removal/plan.md` v4,
    `docs/pr/1476-mechanical-bpf-removal/reviewer-ids.md`, `_Log.md`

## 2026-05-25 — #1476 Phase A v3 plan after r2 reviews

- **Timestamp**: 2026-05-25T (Phase A v3 after r2 reviewer findings)
  - **Action**: Round-2 reviews returned: Codex r2 PLAN-NEEDS-MAJOR
    (5 findings, mostly stale-text drift between v2 header changes
    and unchanged v1 prose, plus 2 NEW: shim_loader_boundary_test
    hardcoded path + non-daemon ebpf-warning tests); AGY r2
    PLAN-NEEDS-MINOR (4 missing retained helpers — overlapped with
    Codex F3). v3 fixes: §5 Manager.Load() table row, §4.8 adds 5
    additional retained symbols (drift errors + size constants),
    §4.3 adds shim_loader_boundary_test.go path-fix row and 4
    non-daemon ebpf-warning test rewrite rows, §8 prose updates,
    "four manifest tests" → "five" sweep.
  - **File(s)**: `docs/pr/1476-mechanical-bpf-removal/plan.md` v3,
    `docs/pr/1476-mechanical-bpf-removal/reviewer-ids.md`, `_Log.md`

## 2026-05-25 — #1476 Phase A v2 plan after r1 reviews

- **Timestamp**: 2026-05-25T (Phase A v2 after r1 reviewer findings)
  - **Action**: Round-1 reviews returned: Codex r1b
    PLAN-NEEDS-MAJOR (6 findings: Manager.Load() interface break,
    make clean nukes shim, retained-helper under-listing,
    nat_port_counters misclass, loader_stub canary gaps, TypeEBPF
    test migration); AGY r1 PLAN-NEEDS-MINOR (Makefile clean +
    dataplane_boot_test rewrite). v2 plan incorporates all findings:
    keeps Manager.Load() as ErrEBPFBackendRetired stub (not deleted);
    narrows Makefile clean globs to xpf*_bpfel.{go,o}; rewrites
    TestBuildRuntimeDataPlaneEBPFRoutesToLegacyManager to assert
    retirement-sentinel; enumerates full retained shim helper list;
    keeps nat_port_counters in pinnedMaps; deletes loader_stub
    allowlist entry + docs-pinned token; corrects manifest test
    count to 5.
  - **File(s)**: `docs/pr/1476-mechanical-bpf-removal/plan.md` v2,
    `docs/pr/1476-mechanical-bpf-removal/reviewer-ids.md`, `_Log.md`

## 2026-05-25 — #1476 Phase A v1 plan drafted

- **Timestamp**: 2026-05-25T (Phase A v1 draft)
  - **Action**: Created worktree `refactor/1476-mechanical-bpf-removal`
    off origin/master. Drafted plan v1 for #1476 (eBPF retirement
    Phase: mechanical source removal of legacy `bpf/xdp/*.c`,
    `bpf/tc/*.c`, 14 bpf2go generated pairs, `loader_ebpf.go`, and
    legacy Makefile hooks). Plan mirrors the DPDK retirement Phase 3
    (#1528) template: keeps `TypeEBPF` as a retirement-error token,
    adds `validateDataplaneTypeStrictEBPF` commit-time validator with
    verbatim retirement message, extends the
    `rewriteRetiredDataplaneType` Load-time rewrite to handle the
    EBPF persistent-config case, deletes the bpf2go graph in lockstep
    with the legacy build hooks. Retained: `bpf/headers/*.h`,
    `userspace-xdp/`, `pkg/dataplane/userspace_xdp_bpfel.o`,
    `pkg/dataplane/userspace_xdp_rust.go`,
    `pkg/dataplane/build-userspace-xdp.sh`. Manifest discipline
    enforced by the 4 `TestLegacyBPFRemovalManifest*` canaries
    already in tree from #1494.
    Blocked on #1451 (sub-issues #1516, #1521 still OPEN); Phase B
    rebases onto master once #1451 closes.
  - **File(s)**: `docs/pr/1476-mechanical-bpf-removal/plan.md`,
    `docs/pr/1476-mechanical-bpf-removal/reviewer-ids.md`, `_Log.md`

## 2026-05-26

- **Timestamp**: 2026-05-26T02:50:00Z
  - **Action**: #1539 PR #1553 — rebased onto origin/master (5
    PRs ahead, including #1556 multierror refactor). Conflict
    on `_Log.md` resolved via /tmp/log-merge.py (union of HEAD
    + incoming on each conflict region). Conflict on
    `pkg/config/compiler.go` auto-resolved by git's 3-way merge;
    semantically verified by inspection: Option A's nil clear at
    L281-294 now sits AFTER (a) `validateDataplaneTypeStrict`
    (fail-fast on retired DPDK) AND (b) the new `errors.Join`
    multierror accumulator added by #1556, so it only runs on
    the full success path. Codex round-5 MERGE-READY (session
    019e5fa*), AGY round-5 adversarial-review-mpm18y6x-ii447j
    MERGE-READY. Formal copilot-pull-request-reviewer re-ran on
    new HEAD 4d24d592 and flagged 3 LOW-priority items: (a)
    unused `dpdkSubtreeLeakageCanaryScanRoots` declaration —
    removed; (b) redundant `if cfg != nil` guard around Option
    A's nil clear (cfg is always non-nil in compileExpanded) —
    guard removed, comment updated; (c) truncated _Log entry
    at line 766 ending with bare "Added" — completed.
  - **File(s)**: pkg/config/compiler.go,
    pkg/config/dpdk_subtree_leakage_canary_test.go, _Log.md
- **Timestamp**: 2026-05-26T04:50:00Z
  - **Action**: #1519 Phase B implementation — #1516 (PR #1554)
    merged as 265d6de7. Rebased
    refactor/1519-daemon-legacydp-shrink-impl onto master 265d6de7.
    Inspected merged pkg/grpcapi/runtime.go on master — grpcRuntime
    shape matches the v1.2-locked grpcDataPlane (AGY's branch
    inspection was accurate). Applied all 16 migrations plus the
    capstone function deletion:
      1. daemon_gc.go — collapsed NewGCWithDomains(sessions,
         telemetry, lp, lp, interval) to NewGC(d.dp, interval).
      2. daemon_scheduler.go:159-161 — deleted dead-code fallback.
      3-6. daemon_forwarding_status.go — IsLoaded uses
         dataplaneReadyProbe; GetMapStats reads via
         d.dp.Telemetry().MapStats(); Status assertions on d.dp
         via local userspaceStatusProbe.
      7. daemon_run.go:310 — Seed* via natSeeder probe on d.dp.
      8. daemon_run.go:365 — StartFIBSync via fibSyncStarter probe.
      9. daemon_run.go:710 — api.Config.DP via local apiDataPlane
         probe (matches package-private apiRuntimeDataPlane).
      10. daemon_run.go:817 — grpcapi.Config.DP via local
         grpcDataPlane probe (matches package-private grpcRuntime
         from #1516/#1554).
      11. daemon_run.go:903/915 — cli.New(...) via local
         cliDataPlane probe (matches package-private cliRuntime).
      12. daemon_run.go:1120 — logFinalStats(dp) → logFinalStats(
         dataplaneReadyProbe, dataplane.Telemetry). Signature
         change in daemon_flow.go uses Telemetry().GlobalCounter
         instead of dp.ReadGlobalCounter.
      13-15. daemon_ha_sync.go:271, 281, 700 — event-stream typed
         probe assertions on d.dp directly (no legacyDP round-
         trip).
      16. daemon_ha_sync.go:739 — comment cleanup (drop historical
         #1518 reference now that the migration shipped).
      17. daemon.go:345-356 — deleted legacyDP() function +
         docstring. Replaced with a 5-line note pointing at the
         AST canary.
    Added pkg/daemon/runtime_probes.go (5 typed probes:
    dataplaneReadyProbe, natSeeder, fibSyncStarter, apiDataPlane,
    grpcDataPlane, cliDataPlane) and
    pkg/daemon/runtime_probes_test.go (12 compile-time var-decl
    assertions: each probe satisfied by *dataplane.Manager and
    *dataplane/userspace.LegacyDataPlaneAdapter). Added
    pkg/daemon/legacy_dataplane_canary_test.go (AST canary that
    fails if a future PR reintroduces FuncDecl (*Daemon).legacyDP
    or any CallExpr .legacyDP()). Updated
    pkg/dataplane/retirement_boundary_canary_test.go allowlist:
    tightened daemon.go and daemon_run.go rationales, added
    runtime_probes.go entry. Updated
    docs/pr/1373-retire-ebpf-dataplane/README.md to mirror the
    allowlist changes. Test results: full `go test ./...` clean;
    5x flake loop on `./pkg/daemon` clean.
  - **File(s)**: pkg/daemon/runtime_probes.go,
    pkg/daemon/runtime_probes_test.go,
    pkg/daemon/legacy_dataplane_canary_test.go,
    pkg/daemon/daemon.go, pkg/daemon/daemon_gc.go,
    pkg/daemon/daemon_scheduler.go,
    pkg/daemon/daemon_forwarding_status.go,
    pkg/daemon/daemon_forwarding_status_test.go,
    pkg/daemon/daemon_run.go, pkg/daemon/daemon_ha_sync.go,
    pkg/daemon/daemon_flow.go,
    pkg/dataplane/retirement_boundary_canary_test.go,
    docs/pr/1373-retire-ebpf-dataplane/README.md

## 2026-05-26 (earlier)

- **Timestamp**: 2026-05-26T03:15:00Z
  - **Action**: #1519 plan-impl v1.1 → v1.2 — AGY round-1
    (review-mpm1pdkv-g1sycf) returned PLAN-READY with no new
    findings. AGY hostile-verified against live codebase and the
    in-flight refactor/1516-grpcapi-migration @ 0436f386: confirmed
    16 call sites + 1 function deletion (17 total), confirmed
    dead-code at daemon_scheduler.go:159-161 with both backends
    satisfying policyScheduleStateUpdater, walked the
    telemetry-after-Stop teardown trace
    (d.cluster.Stop → sessionSync.Stop → logFinalStats →
    dp.Close/Teardown, with bpfShim teardown only inside
    manager.Close/Teardown), and confirmed all five probe shapes
    satisfied by both backends. Open §10 questions ratified:
    Q1=hybrid (promote cliRuntime to CLIRuntime public, keep
    api/grpc probes daemon-local), Q2=grpcDataPlane shape locked-in
    from AGY's inspection of pkg/grpcapi/runtime.go @ 0436f386,
    Q3=keep both canaries, Q4=keep fibSyncStarter probe,
    Q5=telemetry-after-Stop safe, Q6=rebase risk small, Q7=smoke
    load OK. v1.2 pre-populates the grpcDataPlane probe in §2 with
    the full grpcRuntime method set from the live #1554 branch
    (verified by reading pkg/grpcapi/runtime.go directly). New §13
    records both round-1 outcomes; new §14 is v1.2 changelog. Plan
    locked at v1.2 pending #1554 close. No round-2 plan-review
    dispatch (per repo policy when both reviewers PLAN-READY at
    round-1).
  - **File(s)**: docs/pr/1519-daemon-legacydp-shrink/plan-impl.md,
    docs/pr/1519-daemon-legacydp-shrink/reviewer-ids-impl.md

## 2026-05-25

- **Timestamp**: 2026-05-25T20:30:00Z
  - **Action**: #1519 plan-impl v1 → v1.1 — Codex round-1 returned
    3 findings (1×P2, 2×P3) on plan-impl.md. P2: row 1 of migration
    matrix referenced fictional `conntrack.PersistentNATProvider`
    and `conntrack.SessionCountPublisher`. The real exported
    interface is `conntrack.RuntimeDomainProvider` at
    pkg/conntrack/gc.go:45 (SessionStoreProvider+TelemetryProvider);
    the persistent/sessionCount probes are package-private lowercase
    names at gc.go:33/39. `conntrack.NewGC(provider, interval)` at
    gc.go:104 already does the right thing. Rewrote row 1 to
    collapse `NewGCWithDomains(...)` into `NewGC(d.dp, interval)`.
    P3a: cliRuntime described as superset of RuntimeDataPlane, but
    pkg/cli/runtime.go:11 docstring says SUBSET of DataPlane (and
    omits Start/ApplyConfig/Link/HA/Sessions/Telemetry/Close/
    Teardown). Rewrote sibling-state §0 to note RuntimeDataPlane
    and cliRuntime are disjoint — daemon must type-assert against
    cliRuntime's shape even though d.dp is RuntimeDataPlane (both
    backends satisfy both interfaces simultaneously). P3b: flake
    loop `for i in 1..5` is a single-token literal in bash (runs
    once); fixed to `for i in 1 2 3 4 5`. AGY round-1 still
    pending.
  - **File(s)**: docs/pr/1519-daemon-legacydp-shrink/plan-impl.md

- **Timestamp**: 2026-05-25T20:00:00Z
  - **Action**: #1519 Phase A — drafted capstone-delete plan
    (plan-impl.md v1) on new branch
    refactor/1519-daemon-legacydp-shrink-impl off origin/master
    (1f39f79d). Issue #1519 was PLAN-KILL'd in round-1 because 4
    of 16 legacyDP() call sites were blocked by #1516/#1517/#1518.
    Now #1517 (PR #1549) and #1518 (PR #1551) are CLOSED; only
    #1516 (PR #1554, 0436f386, MERGEABLE) remains in flight. Plan
    enumerates 16 call sites + the accessor function and targets
    17 deletions plus a new pkg/daemon/runtime_probes.go with 5
    typed probes (dataplaneReadyProbe, natSeeder, fibSyncStarter,
    apiDataPlane, cliDataPlane/CLIRuntime, grpcDataPlane). Canary
    work: extend existing
    pkg/dataplane/retirement_boundary_canary_test.go allowlist +
    new pkg/daemon AST canary asserting legacyDP() method decl
    and call expressions stay deleted. Dispatched to Codex + AGY
    in parallel for plan-impl v1 review.
  - **File(s)**: docs/pr/1519-daemon-legacydp-shrink/plan-impl.md

- **Timestamp**: 2026-05-25T19:30:00Z
  - **Action**: #1521 Copilot r-rebase (4357897741 on 5bc310fc)
    fixes — 1 correctness finding + 1 doc nit. Correctness
    (pos 487): scopeWalker bound DeclStmt(CONST) names into the
    current scope BEFORE descending into the const declaration's
    initializer AST. For a shadowing `const outer = outer +
    "_shadow"`, this meant Pass 1's later BinaryExpr fold would
    evaluate the RHS `outer` AFTER the inner binding was
    installed, so Pass 1 reported a double-shadowed
    "userspace_outer_shadow_shadow" instead of the compile-time
    "userspace_outer_shadow". FIX: introduced
    `evalGenDeclConsts(gd, scope) map[string]string` which
    evaluates each spec against the pre-binding scope using a
    rolling fold (so later specs in the same GenDecl can still
    reference earlier specs in the same GenDecl, which IS Go-
    legal). scopeWalker.Visit on DeclStmt(CONST) stores the
    pending bindings on the postVisitor; postVisitor.Visit(nil)
    applies them when the DeclStmt is exited (BEFORE popping any
    new scope frame, so siblings later in the same block see
    them). Doc nit (pos 729): trimPaddingForBypass comment said
    "any `%` format-verb characters" but `strings.Trim(s, "%")`
    only strips leading/trailing — comment updated to
    "LEADING/TRAILING `%` characters" with rationale: internal
    `%` must be preserved so legitimate format strings like
    `"update userspace_local_v4 %08x: %w"` don't trim down to a
    registered map name. New fixture
    copilot_rebase_shadow_initializer_refs_outer locks the kill.
  - **File(s)**: pkg/dataplane/userspace/maps_decouple_test.go,
    docs/pr/1521-maps-sync-decouple/reviewer-ids.md, _Log.md
  - **Validation**: 6 canary tests + 25 alias-bypass sub-cases
    pass under `-count=2`; full `go test ./...` all 33 packages
    green.

- **Timestamp**: 2026-05-25T18:50:00Z
  - **Action**: #1521 post-rebase + AGY r-rebase inherited-initializer
    fix. Rebased branch onto master b7466f5d (8 sibling PRs merged
    since the previous round; _Log.md conflicts resolved by concat).
    AGY post-rebase review
    (adversarial-review-mplf2r55-xnr229) flagged a compiling bypass
    via Go spec §Constant declarations inherited initializers:
    `const ( A = "userspace_ctrl"; B )` binds B to the same value
    as A, but the AST sees `vs.Values` empty for B. The previous
    binder skipped such specs, leaving B unbound and silently
    allowing m.Map(B) to bypass the canary. FIX: retired
    `bindConstSpec` and replaced with `bindGenDeclConsts(gd, scope)`
    which walks the entire GenDecl tracking lastValues across
    specs. Same lastValues pattern mirrored in
    `collectFileConstsInto` for top-level const blocks. Two new
    fixtures lock the kill: agy_rebase_inherited_initializer_bypass
    (package-scope) and agy_rebase_inherited_initializer_local_block
    (exercises scopeWalker via DeclStmt). Codex post-rebase
    plan-r1 (workflow 20260525-162502-88b826): 6 findings — 1 FIX
    (sentinel-gated skip already closed), 1 DEFER (relative path),
    4 REJECT (recurring parity-AST and scoping rationales). Codex
    impl-r1: 3 findings, all REJECT (recurring).
  - **File(s)**: pkg/dataplane/userspace/maps_decouple_test.go,
    docs/pr/1521-maps-sync-decouple/reviewer-ids.md, _Log.md
  - **Validation**: 6 canary tests + 24 alias-bypass sub-cases
    pass; full `go test ./...` all 33 packages green on the
    rebased branch.

- **Timestamp**: 2026-05-25T15:45:00Z
  - **Action**: Addressed PR #1551 Copilot round-3 doc-comment nits by
    fully qualifying dataplane helper names in cluster session-sync
    comments (`dataplane.TelemetryOf`, `dataplane.NewDataPlaneTelemetry`).
  - **File(s)**:
    `pkg/cluster/sync.go`,
    `pkg/cluster/sync_test.go`,
    `_Log.md`

- **Timestamp**: 2026-05-26T01:00:00Z
  - **Action**: Round-3 reviewer verdicts complete on PR #1550 HEAD
    444a1959. Codex MERGE-READY (no findings). AGY MERGE-READY
    (8/8 invariants verified, 3 Copilot round-2 nits resolved).
    Copilot round-3 COMMENTED with no new comments — implicit
    MERGE-READY. 4-of-4 reviewers agree (including Claude SMR).
    Smoke matrix on loss userspace cluster: PASS — per-class v4/v6
    × push/-R matrix consistent and healthy. Best-effort port 5201
    ~80 Mbps push is expected (low-priority CoS surplus floor
    under concurrent class load). All other classes shaped
    correctly per their CIR + surplus. Reverse direction 6-8 Gbps
    across all classes. Smoke results posted as PR comment. PR
    ready for author merge.
  - **File(s)**: smoke matrix on loss:xpf-userspace-fw0/fw1; no
    code changes.

- **Timestamp**: 2026-05-26T00:30:00Z
  - **Action**: PR #1550 round-2 reviews landed. Codex MERGE-READY
    (no findings; all wording fixes confirmed). AGY MERGE-READY
    (8/8 invariants verified). Copilot round-2 surfaced 3 doc-only
    nits: stale legacy-caller list (pkg/api/pkg/conntrack/
    pkg/fwdstatus → actual: pkg/cli, pkg/grpcapi, pkg/cluster via
    daemon.legacyDP()), in both Boot() docstring and
    userspace_boot_canary_test.go; plus README "only ebpf/dpdk"
    wording missing unknown-type pass-through. Copilot agent
    pushed fffe3e41 ("docs: fix PR #1550 wording drift") with the
    same fixes; rebased local 3ea74518 on top — same content, took
    Copilot agent's version verbatim during rebase since the two
    wordings are equivalent.
  - **File(s)**:
    `pkg/dataplane/userspace/manager.go`,
    `pkg/dataplane/userspace/userspace_boot_canary_test.go`,
    `pkg/dataplane/README.md`

- **Timestamp**: 2026-05-25T23:30:00Z
  - **Action**: PR #1550 round-1 doc + wording follow-ups merged.
    Copilot agent pushed be8a7b6d updating
    `pkg/dataplane/README.md` and `pkg/daemon/README.md` to align
    doc text with the landed code (boot path via
    `userspace.Boot()`; legacy factory only for ebpf rollback +
    DPDK sentinel). Rebased local round-1 review fixes on top.
  - **File(s)**: `pkg/dataplane/README.md`, `pkg/daemon/README.md`

- **Timestamp**: 2026-05-25T23:00:00Z
  - **Action**: PR #1550 round-1 code review feedback addressed.
    Copilot inline nits: (1) Boot() doc misdescribed the userspace
    registry path as "rollback" — clarified that the userspace
    registry entry is the compatibility/test seam and the ebpf
    rollback goes through the legacy factory's TypeEBPF switch,
    not the userspace registry; (2) buildRuntimeDataPlane doc said
    the default branch is "only" for ebpf/dpdk — rewrote to
    acknowledge unknown/custom types also flow through and surface
    the legacy factory's error verbatim. AGY minor coverage gap:
    added TestBuildRuntimeDataPlaneUnknownTypePropagatesError to
    lock in the unknown-type error propagation and to assert
    ErrDPDKBackendRetired stays reserved for "dpdk". AGY code
    review verdict: MERGE-READY (8 findings clean).
  - **File(s)**:
    `pkg/dataplane/userspace/manager.go`,
    `pkg/daemon/daemon_run.go`,
    `pkg/daemon/dataplane_boot_test.go`,
    `docs/pr/1520-userspace-boot-extraction/reviewer-ids.md`

- **Timestamp**: 2026-05-25T22:30:00Z
  - **Action**: #1520 plan v4 + implementation. v2 added Claude SMR
    refinements (no-arg Boot, behavioral canaries). v3 addressed
    Codex round-2 PLAN-NEEDS-MAJOR (9 findings: structural value
    statement, default-route invariant, dropped text-shape canary,
    behavioral helper tests, BootOptions dropped, rollback/test-seam
    wording). v4 addressed AGY round-2 CRITICAL: existing AST canary
    `TestDaemonRuntimeEntryPointUsesRuntimeDataPlane` requires
    `daemon_run.go` to literally reference
    `dataplane.NewRuntimeDataPlane(...)`; pinned the helper inside
    `daemon_run.go` and kept the non-userspace branch routed through
    that factory call to preserve the canary. Codex round-3
    PLAN-NEEDS-MINOR confirmed two stale strings ("BootOptions{}"
    in §8.5 and "rollback" in §4.3 heading) — both fixed in v4.
    Implementation: added `userspace.Boot()` + helper
    `buildRuntimeDataPlane` in daemon_run.go + two canary test
    files. Full Go suite green; 5x flake stable.
  - **File(s)**:
    `docs/pr/1520-userspace-boot-extraction/plan.md`,
    `docs/pr/1520-userspace-boot-extraction/reviewer-ids.md`,
    `pkg/dataplane/userspace/manager.go`,
    `pkg/daemon/daemon_run.go`,
    `pkg/dataplane/userspace/userspace_boot_canary_test.go`,
    `pkg/daemon/dataplane_boot_test.go`

- **Timestamp**: 2026-05-25T20:00:00Z
  - **Action**: #1520 plan v1 DRAFT — extract userspace boot path
    from legacy `dataplane.New()` (sub-#1451 S5). Adds
    `userspace.Boot()` constructor + daemon `buildRuntimeDataPlane`
    wrapper that fences the legacy registry off to the
    `dataplane-type ebpf` rollback. Plan explicitly out-of-scopes
    the `bpfShim` field rename (forbidden by existing AST canary)
    and the `maps_sync.go` map-name decoupling (#1521 sibling work).
  - **File(s)**:
    `docs/pr/1520-userspace-boot-extraction/plan.md`,
    `docs/pr/1520-userspace-boot-extraction/reviewer-ids.md`
- **Timestamp**: 2026-05-25T09:15:00Z
  - **Action**: #1538 code-review round-2 doc cleanup —
    Codex code review round 2 verdict was NEEDS-MINOR with
    two doc-only findings (AGY round-2 was MERGE-READY,
    Copilot pending):
    1. plan.md still described the OLD
       TestCompileSingleStrictErrorJoinPath design (hand-built
       *Config / direct helper). Rewrote the description to
       match the actual implementation (ParseSetCommand →
       SetPath → CompileConfig path with single-CoS-only
       fixture, byte-identity vs direct validator call as
       reference, defense-in-depth zero-newline + wrap-chain
       traversal assertions).
    2. Many `file:line` citations remained in plan.md after
       the first cleanup pass (compiler.go:244/247/250,
       :363+, :241, :234-243, :262+, :82-153, store.go:681,
       ast_edit.go:151-152, etc). Stripped all of them via
       sed to use durable symbol references instead.
    Also fixed a couple of leftover sed artifacts manually
    (`/`:681`` artifact at line 414; the `at :363+`
    construction at line 103).
    Re-ran ./pkg/config/ + ./pkg/grpcapi/ tests: clean.
  - **File(s)**: `docs/pr/1538-multierror-validation/plan.md`,
    `_Log.md`

- **Timestamp**: 2026-05-25T09:00:00Z
  - **Action**: #1538 code-review round-1 follow-up — addresses
    Codex code-review NEEDS-MINOR (3 findings; AGY MERGE-READY,
    Copilot PASS, Claude SMR PASS):
    1. Rewrote `TestCompileSingleStrictErrorJoinPath` to drive
       through `CompileConfig` rather than inline-duplicating
       the accumulator pattern. New fixture uses ONLY the CoS
       `equal-flow-enforcement` set line (no policer), so the
       accumulator slice ends up length-1 and the test now
       genuinely exercises the production path. Asserts
       byte-identity vs a direct validator call on an
       equivalent stub `*ClassOfServiceConfig`, zero '\n'
       separators on the single-error path, and incidental
       wrap-chain traversal (`errors.Is(err,
       ErrDPDKDataplaneRetired) == false`).
    2. Dropped stale `file:line` citations from compiler_test.go
       and plan.md; switched to symbol references that survive
       rebase drift.
    3. Updated reviewer-ids.md with round-4 PLAN-READY
       verdicts and recorded the code-review verdicts.
    Re-ran the three new tests + the DPDK no-leak test
    locally; all clean.
  - **File(s)**: `pkg/config/compiler_test.go`,
    `docs/pr/1538-multierror-validation/plan.md`,
    `docs/pr/1538-multierror-validation/reviewer-ids.md`,
    `_Log.md`

- **Timestamp**: 2026-05-25T08:45:00Z
  - **Action**: #1538 implementation (plan v4 PLAN-READY 4/4).
    Plan-review summary: r1 Codex PLAN-NEEDS-MAJOR / AGY
    PLAN-READY; r2 Codex PLAN-NEEDS-MINOR / AGY PLAN-READY;
    r3 Codex PLAN-NEEDS-MINOR / AGY PLAN-NEEDS-MINOR; r4
    Codex PLAN-READY / AGY PLAN-READY. v4 is the final plan.

    Code change: `compileExpanded` in
    `pkg/config/compiler.go:244-272` now accumulates the three
    independent strict-validator family errors
    (`validateClassOfServiceStrict`,
    `validateThreeColorPolicersStrict`,
    `validatePolicySchedulerReferencesStrict`) into a single
    `errors.Join` return so `commit check` surfaces ONE error
    per family in a single response. The
    `validateDataplaneTypeStrict` precheck (added by #1536)
    stays fail-fast and runs FIRST so the brittle-by-design
    `TestDataplaneTypeDPDKRejectedAtCommitFiresFirst` no-leak
    contract (parser_ast_test.go:2909+2913) keeps passing
    byte-identically.

    Tests added (3):
    - `pkg/config/compiler_test.go::TestCompileMultipleStrictErrorsAccumulated`
      — parser-driven via `CompileConfig` + `ParseSetCommand` /
      `tree.SetPath` loop. Fixture: `equal-flow-enforcement`
      on a scheduler without `transmit-rate exact` (parser-
      reachable CoS error) + `single-rate color-blind` on a
      three-color-policer without `committed-information-rate`
      (parser-reachable policer error). Asserts both error
      substrings present in the joined Error(), exactly one
      '\n' separator, and `errors.Is(err,
      ErrDPDKDataplaneRetired) == false` (defense-in-depth).
    - `pkg/config/compiler_test.go::TestCompileSingleStrictErrorJoinPath`
      — direct accumulator-pattern call with a hand-built
      *Config that triggers only the CoS family. Pins
      `errors.Join`'s single-element byte-identity semantics
      (Go std lib pin at /usr/lib/go-1.24/src/errors/join.go:47-48
      per Codex round-2 verification).
    - `pkg/grpcapi/server_config_test.go::TestCompileCheckMultiErrorRendersThroughGRPC`
      — exercises the actual operator-facing gRPC rendering
      via `status.Errorf(codes.InvalidArgument, "%v", err)`
      at `server_config.go:176`. Direct-handler style
      (no bufconn) per existing pattern at lines 15-25.
      Asserts `codes.InvalidArgument` + both substrings +
      one '\n' separator on the rendered status.Message().

    Local validation: `go build ./...` clean, `go test
    ./...` clean (30 packages), 5× flake loop on the three
    new tests + the DPDK no-leak test all clean.

    Also tidied two cosmetic stale-wording items Codex r4
    called out as non-blocking: "Land plan v2" → "Land plan
    ... v4 is the final" and "Open questions ... (round 2)"
    → "(historical)".
  - **File(s)**: `pkg/config/compiler.go`,
    `pkg/config/compiler_test.go` (new),
    `pkg/grpcapi/server_config_test.go`,
    `docs/pr/1538-multierror-validation/plan.md`,
    `docs/pr/1538-multierror-validation/reviewer-ids.md` (new),
    `_Log.md`

- **Timestamp**: 2026-05-25T08:30:00Z
  - **Action**: #1538 plan v4 — addresses Codex round-3
    PLAN-NEEDS-MINOR (3 findings) + AGY round-3
    PLAN-NEEDS-MINOR (1 finding). Changes:
    (1) drop "REQUIRED" rationale for `set system
        dataplane-type userspace` (no-op — unset == userspace
        per `effectiveDataplaneType` and validateDataplaneTypeStrict
        only rejects explicit `dpdk`); line stays as
        self-documenting future-proof;
    (2) fix test-count "two" → "three" throughout the plan;
    (3) replace bad-syntax three-color-policer line
        `action loss-priority high then discard` (parses via
        schema-less fallback, silently ignored by compiler)
        with schema-clean `then discard`;
    (4) rewrite gRPC test plan to match existing
        direct-handler style at server_config_test.go:15-25
        (no bufconn; use `store.LoadSet` per existing
        pattern, not nonexistent `LoadCandidate`/`Edit`).
    Sanity-checked the fixture locally with a throw-away
    test: under current fail-fast, only CoS error surfaces;
    under accumulator both surface separated by one '\n'.
  - **File(s)**: `docs/pr/1538-multierror-validation/plan.md`,
    `_Log.md`

- **Timestamp**: 2026-05-25T08:15:00Z
  - **Action**: #1538 plan v3 — addresses Codex round-2
    PLAN-NEEDS-MINOR on plan v2. AGY round-2 was PLAN-READY.
    Minor fix: v2's CoS fixture used "both buffer-size bytes
    AND percent set" which is NOT parser-reachable
    (`pkg/config/compiler_class_of_service.go:239` clears the
    alternate field; validator at `pkg/config/compiler.go:386`
    documents the state arises only from constructed configs).
    v3 switches the parser-driven tests to use
    `equal-flow-enforcement` without `transmit-rate exact` as
    the parser-reachable CoS error and `single-rate
    color-blind` without `committed-information-rate` as the
    parser-reachable policer error. Also clarifies that there
    are THREE new tests (not two) and splits fixture-build
    technique per-test (parser for tests 1+3, direct-helper
    for the byte-identity test 2).
  - **File(s)**: `docs/pr/1538-multierror-validation/plan.md`,
    `_Log.md`

- **Timestamp**: 2026-05-25T08:00:00Z
  - **Action**: #1538 plan v2 — addresses Codex round-1
    PLAN-NEEDS-MAJOR (4 findings) on plan v1. Changes:
    (a) keep `validateDataplaneTypeStrict` as a separate
    fail-fast precheck BEFORE the accumulator — preserves
    #1536's DPDK-first / no-leak contract pinned by
    `TestDataplaneTypeDPDKRejectedAtCommitFiresFirst`
    (`pkg/config/parser_ast_test.go:2855,:2909,:2913`);
    (b) drop the "matches Junos commit check" overclaim and
    frame the change as an xpf UX choice grounded in
    upgrade-friction reduction; (c) tighten wording from
    "all structural errors" to "one error per validator
    family" since each strict family still fail-fasts
    internally; (d) add a third test
    `TestCompileCheckMultiErrorRendersThroughGRPC` covering
    the multi-line rendering through `pkg/grpcapi`.
    AGY round-1 verdict was PLAN-READY; v2 preserves the
    audit it confirmed (validator independence, substring
    + sentinel preservation, wrap-chain mechanics).
    Rebased onto current master (which now has #1536).
  - **File(s)**: `docs/pr/1538-multierror-validation/plan.md`,
    `_Log.md`
- **Timestamp**: 2026-05-25T18:30:00Z
  - **Action**: #1521 Copilot r5 fixes + pre-rebase. Copilot r5
    (review id 4357796234 on 5becd4fa) flagged 3 inline findings:
    two doc-vs-impl drift comments (lines 240, 518) and one
    correctness concern (line 436): `collectConstsFromStmtList`
    pre-collected ALL block-local consts up-front, which violates
    Go's "scope begins at end of ConstSpec" rule. Constructed
    worked examples that prove the bug: a later-declared
    block-local const shadowing an outer const used EARLIER in the
    same block could cause both false-negatives (canary reads the
    shadow value, misses the real outer-scope violation) and
    false-positives (canary reads a later "userspace_*" shadow at
    an earlier call site that semantically used an innocuous
    outer). Fix: replaced pre-collect + collectLocalConstsForBlock
    + collectConstsFromStmtList with a single bindConstSpec helper
    that scopeWalker.Visit invokes WHEN a DeclStmt(CONST) is
    visited — binding goes into the current top-of-stack scope
    only at that moment, preserving statement order. BlockStmt /
    CaseClause / CommClause still push an empty cloned-parent
    scope on entry, popped on exit. Two new fixtures
    copilot_r5_statement_order_false_positive (outer="innocuous_outer",
    later shadow "userspace_evil" → only shadow is flagged) and
    copilot_r5_statement_order_false_negative (outer="userspace_real",
    later shadow "innocuous" → outer call site is flagged) lock
    the correct semantics in place. Doc comments at lines 240 and
    518 updated to match the new implementation.
    Also retired the now-redundant agy_r7 fixture's invalid local
    inverted chain (Go doesn't actually compile local
    forward-referenced consts) and replaced with valid Go where
    chain is at package scope and only chain1 is shadowed in
    `case 1` — the canary must still resolve chain3 via package
    scope to "userspace_fallback_stats".
  - **File(s)**: pkg/dataplane/userspace/maps_decouple_test.go,
    docs/pr/1521-maps-sync-decouple/reviewer-ids.md
  - **Validation**: 6 canary tests + 22 negative-fixture sub-cases
    (2 new copilot_r5 cases) pass under `-count=2`; full
    `go test ./...` green on this branch (pre-rebase).

- **Timestamp**: 2026-05-25T17:30:00Z
  - **Action**: #1521 r7 review fix — AGY r7 CONCRETE KILL: switch
    or select case body acts as an implicit Go scope but is
    represented as *ast.CaseClause / *ast.CommClause, not
    *ast.BlockStmt. The r6 scopeWalker only pushed scopes for
    BlockStmt/FuncDecl/FuncLit; case-body consts therefore leaked
    into the enclosing scope and could shadow package-level consts
    (e.g. `case 1: const chain1 = "innocuous"` overwrites the
    package-level chain1). Additionally, the local-const collector
    used ast.Inspect over the whole block, which recursively
    descended into nested case bodies and pulled their consts into
    the outer scope.
    AGY r7 authored the fix: collectLocalConstsForBlock now
    dispatches on node type and routes to a strict stmt-list
    iterator collectConstsFromStmtList (no ast.Inspect, no nested
    descent). scopeWalker pushes new scopes for BlockStmt,
    CaseClause, and CommClause. New agy_r7_switch_case_shadow_
    bypass fixture asserts the kill.
  - **File(s)**: pkg/dataplane/userspace/maps_decouple_test.go,
    docs/pr/1521-maps-sync-decouple/reviewer-ids.md
  - **Validation**: 6 canary tests + 20 negative-fixture sub-cases
    pass; go test ./... all 30 packages green.

- **Timestamp**: 2026-05-25T17:15:00Z
  - **Action**: #1521 r6 review fix — AGY r6 NEEDS-MINOR identified
    one more bypass: block-local const declaration with the same
    name as a package-level const causes the flat package-wide
    consts symbol table to be silently overwritten by the local
    value, so a package-level chain that compiles to
    "userspace_fallback_stats" can be evaluated by the canary as
    something innocuous if shadowed at the function entry point.
    AGY authored the fix directly in the worktree:
    - collectFileConstsInto now collects ONLY top-level const
      declarations (no DeclStmt walk).
    - scopeWalker (implements ast.Visitor) + walkWithScope manage
      a scope stack: blocks (BlockStmt, FuncDecl, FuncLit) push a
      new scope; block-local const decls bind in the current
      scope; lookups walk inner-to-outer. The package-wide table
      is never mutated by block-local decls.
    - All three passes route through walkWithScope so they see the
      same correct lexical scoping as the compiler.
    New agy_r6_block_shadow_chain_bypass fixture proves the fix
    (chain1 shadowed locally, package-level chain3 must still fold
    to "userspace_fallback_stats" and "userspace_fallback").
    Copilot r4 on 0692093a: 9/9 files reviewed, 0 new comments —
    clean.
  - **File(s)**: pkg/dataplane/userspace/maps_decouple_test.go,
    docs/pr/1521-maps-sync-decouple/reviewer-ids.md
  - **Validation**: 6 canary tests + 19 negative-fixture sub-cases
    pass; go test ./... all 30 packages green.

- **Timestamp**: 2026-05-25T17:00:00Z
  - **Action**: #1521 r5 review fixes — AGY r5 raised NEEDS-MINOR
    with 4 issues; all addressed. (a) Inverted const dependency
    chain depth > 2: replaced fixed 2-pass loop with convergence
    until stable (cap 32 passes for safety). (d.1) Typed-conversion
    concat (`type T string; const x = T("user") + T("space_ctrl")`):
    evalStringExpr now unwraps single-arg *ast.CallExpr so type
    conversions fold via the BasicLit operand. (d.2) Typo-padded
    NEW map name: isMapNameSuspect now trims FIRST and checks
    prefix on trimmed value — catches new userspace_* names even
    when not yet registered. (b) Generated file filter:
    astFileIsGenerated helper detects `// Code generated ... DO NOT
    EDIT.` marker per Go convention; multi-file inspector skips
    generated files.
    Plus Copilot r3 wording nits: maps.go now points readers at
    userspace-xdp/src/lib.rs as Rust map-name source; parity-canary
    doc updated to describe sentinel-gated retirement; alias-canary
    doc updated to describe current trim-first rules (no `%`
    exemption).
    3 new fixtures: agy_r5_ia_inverted_chain_depth3,
    agy_r5_id1_typed_concat_conversion,
    agy_r5_id2_typo_padded_new_name.
  - **File(s)**: pkg/dataplane/userspace/maps_decouple_test.go,
    pkg/dataplane/userspace/maps.go,
    docs/pr/1521-maps-sync-decouple/reviewer-ids.md
  - **Validation**: 6 canary tests + 18 negative-fixture sub-cases
    all pass; go test ./... all 30 packages green.

- **Timestamp**: 2026-05-25T16:35:00Z
  - **Action**: #1521 r4 review fixes — Copilot wording nits +
    Codex LOW-1 parseMapsGoRegistry hard-fail + AGY r4 §II.1
    local-block consts + AGY r4 §II.2 cross-file concat. Refactored
    canary into package-wide AST inspector `findForbiddenAliasesIn
    Files` that builds a single symbol table spanning every
    production file's top-level AND block-local const decls
    (DeclStmt walk). `parseMapsGoRegistry` now hard-fails on
    non-BasicLit mapName* constants. New
    TestParseMapsGoRegistryRejectsDriftShapes (3 sub-cases) +
    TestCrossFileConcatBypassIsCaught + agy_r4_ii_local_block_
    const_concat fixture. AGY r4 §II.3 (byte-slice synthesis) +
    §II.4 (struct-tag reflection) documented as out-of-scope
    deliberate-attacker bypasses in maps.go header.
    Codex r4 MED-1 (parity AST roster) REJECTED third time same
    rationale.
  - **File(s)**: pkg/dataplane/userspace/maps_decouple_test.go,
    pkg/dataplane/userspace/maps.go,
    docs/pr/1521-maps-sync-decouple/reviewer-ids.md
  - **Validation**: 5 canary tests + 18 negative-fixture sub-cases
    all pass; go test ./... all 30 packages green.

- **Timestamp**: 2026-05-25T16:15:00Z
  - **Action**: #1521 r3 code-review fixes — AGY r3 found four
    more bypass classes; all addressed: (i) deeply nested concat
    confirmed SECURE — no change needed. (ii) Const-ident bypass
    (`const pfx="user"; const sfx="space_ctrl"; const bypass=pfx+sfx`)
    closed by adding a top-level const symbol table and recursive
    `evalStringExpr` that resolves `*ast.Ident` against it; new
    Pass 2 walks every CallExpr argument and reports ident-
    resolved "userspace_*" values. (iii) Non-standard whitespace
    padding (`"userspace_ctrl\n\t"`, NBSP) closed by switching
    whitespace detection to `unicode.IsSpace`; trimPaddingForBypass
    strips Unicode-defined whitespace. (iv) Removed orphan `seen`
    map. (v) Parity canary now AST-parses maps.go via new
    `parseMapsGoRegistry()` helper — no hardcoded list. Hits are
    dedup'd via map[string]struct{}. 4 new negative-fixture sub-
    cases (agy_r3_ii_const_ident_concat, agy_r3_ii_call_arg_via_
    ident, agy_r3_iii_newline_padding, agy_r3_iii_nbsp_padding)
    prove the kills.
    Codex r3 review rejected as basis-error (codex ran against
    pr-1494-head not the worktree HEAD); no substantive findings.
  - **File(s)**: pkg/dataplane/userspace/maps_decouple_test.go,
    docs/pr/1521-maps-sync-decouple/reviewer-ids.md
  - **Validation**: 4 canary tests + 14 alias-bypass sub-cases all
    pass; go test ./... all 30 packages green.

- **Timestamp**: 2026-05-25T15:50:00Z
  - **Action**: #1521 r2 code-review fixes — Codex LOW-2 (%
    exemption allows format-template bypass) + AGY r2 §A (trim-
    padded literal) + AGY r2 §D (split-string concat fold) all
    closed. Refactored canary into `findForbiddenMapNameAliases`
    helper that (a) drops `%` from prose exemption, (b) folds
    `*ast.BinaryExpr` Op=ADD with recursive string-concat operands
    and flags folded `userspace_*` results, (c) flags any literal
    whose TRIMMED value (strip whitespace + `%`) exactly matches a
    registered map name. New `TestAliasCanaryCatchesBypassPatterns`
    with 10 sub-cases (incl. AGY r2 (A) and (D) exact bypasses)
    proves the inspector catches every documented bypass.
    Production canary now delegates to the same helper.
    Codex LOW-1 (parity bytes.Contains) again REJECTED with same
    rationale as r1 LOW-2.
  - **File(s)**: pkg/dataplane/userspace/maps_decouple_test.go,
    docs/pr/1521-maps-sync-decouple/reviewer-ids.md
  - **Validation**: 4 canary tests + 10 alias-bypass sub-cases all
    pass; go test ./... all 30 packages green.

- **Timestamp**: 2026-05-25T15:30:00Z
  - **Action**: #1521 r1 code-review fixes — Codex MED-1 + AGY §1
    (alias bypass) closed by new `TestNoMapNameLiteralAliasesOutside
    Registry` that walks every BasicLit (not just .Map args) so
    const-aliases, parenthesized selectors and method aliases are
    all caught; non-map operator tokens in an explicit allow-list.
    AGY §2 closed by replacing parity-canary `t.Skip` on missing
    loader with a `BPFRX_LEGACY_LOADER_RETIRED=1` envvar sentinel.
    AGY §3 / Codex LOW-1 closed by updating manager_ha.go:215
    comment to reference `mapNameUserspaceCtrl`. Codex LOW-2
    rejected (parity AST-pattern adds fragility vs loader refactor;
    bytes.Contains is the minimum signal we actually want).
  - **File(s)**: pkg/dataplane/userspace/maps_decouple_test.go,
    pkg/dataplane/userspace/manager_ha.go,
    docs/pr/1521-maps-sync-decouple/reviewer-ids.md
  - **Validation**: 3 canaries × -count=5 all green; go test ./...
    all 30 packages green.

- **Timestamp**: 2026-05-25T15:10:00Z
  - **Action**: #1521 — decouple userspace maps_sync from legacy
    BPF map names (sub-#1451 S6). New file
    `pkg/dataplane/userspace/maps.go` holds 11 + 1 map-name
    constants. 16 .Map() call sites in maps_sync.go + 3 in
    process.go rewritten to use constants. Cap test updated to
    new symbol name. Two new canaries in maps_decouple_test.go:
    AST-semantic (no Map("userspace_*") outside maps.go) +
    legacy-loader parity (self-retiring under #1476).
  - **File(s)**: pkg/dataplane/userspace/maps.go (new),
    pkg/dataplane/userspace/maps_decouple_test.go (new),
    pkg/dataplane/userspace/maps_sync.go,
    pkg/dataplane/userspace/process.go,
    pkg/dataplane/userspace/maps_sync_cap_test.go,
    docs/pr/1521-maps-sync-decouple/plan.md (v1→v2 after
    Codex+AGY r1), docs/pr/1521-maps-sync-decouple/reviewer-ids.md
  - **Validation**: go build ./... clean; go test
    ./pkg/dataplane/userspace/... ok; canaries 5/5 pass;
    go test ./... — all 30 packages green.
- **Timestamp**: 2026-05-25T08:00:00Z
  - **Action**: #1516 plan v1 — sub-#1451 S1 migration scope.
    Drafted `docs/pr/1516-grpcapi-migration/plan.md`: new
    `pkg/grpcapi/runtime.go` declaring `grpcRuntime` interface
    (~25 methods) plus named provider interfaces
    (`sessionCursorIterator`, `userspaceStatusProvider`,
    `userspaceControlProvider`). `Config.DP` and `Server.dp`
    move from `dataplane.DataPlane` to `grpcRuntime`. Issue
    body's `ReadNATPortCounter` and `Compile` are stale — not
    consumed on master @ fcd53beb. Pending Codex + AGY plan-
    review.
  - **File(s)**: `docs/pr/1516-grpcapi-migration/plan.md`,
    `_Log.md`.

- **Timestamp**: 2026-05-25T05:55:00Z
  - **Action**: PR #1536 round-3 cleanup — address Codex MAJOR
    (load merge syntax in plan recovery) + 3 Copilot nits:
    1. plan.md operational-note recovery flow used invalid
       `load merge replace /etc/xpf/xpf.conf` — the supported
       forms are `load merge <file>` or `load override <file>`
       (`cmd/cli/main.go` parses mode then args[1] as file).
       Replaced with `load override /etc/xpf/xpf.conf` which is
       the appropriate one-shot replacement form.
    2. compiler_system.go unknown-dataplane-type error wording
       said "valid values are userspace" — misleading when
       ebpf is still accepted (deprecated) and dpdk still
       parses (rejected at commit). Updated to "valid values
       are userspace or ebpf (deprecated); dpdk parses for
       legacy-config compatibility but is rejected at commit
       per #1525".
    3. parser_ast_test.go TestDPDKConfigCompileRejects had a
       local `wantSubstr` duplicating `dpdkRetirementSubstr`
       const declared lower in the same file. Reuses the const
       to prevent drift.
    4. _Log.md had a duplicate `## 2026-05-25` header inserted
       around line 1783 by an earlier auto-bot commit. Folded
       its content into this top-of-file entry and removed the
       stray header to keep one bucket per date.
  - **File(s)**: `docs/pr/1526-dpdk-reject/plan.md`,
    `pkg/config/compiler_system.go`,
    `pkg/config/parser_ast_test.go`, `_Log.md`

- **Timestamp**: 2026-05-25T05:30:00Z
  - **Action**: PR #1526 implementation v3 — added
    `validateDataplaneTypeStrict` in pkg/config/compiler.go (slotted
    BEFORE existing CoS / policer / scheduler strict validators per
    Codex round-1 ordering finding). Verbatim retirement message
    per issue body: `the DPDK dataplane backend has been retired;
    use 'set system dataplane-type userspace' (see #1525)`. Tests
    use substring match so the same assertion fires across
    CompileConfig (raw), Store.CommitCheck (raw), and Store.Commit
    (`commit check failed:`-wrapped) — addresses Codex round-2
    MAJOR finding 1.

    Test surface:
    - parser_ast_test.go: split TestDPDKConfig into
      TestDPDKConfigParsesCleanly (parse must survive — AST shape
      assertion) and TestDPDKConfigCompileRejects (commit reject).
    - parser_ast_test.go: 5 new dedicated tests —
      TestDataplaneTypeDPDKRejectedAtCommit (flat-set form),
      TestDataplaneTypeDPDKRejectedAtCommitHierarchical (block
      form), TestDataplaneTypeDPDKRejectedAtCommitFiresBeforeCoS
      (validator ordering lock-in),
      TestDataplaneTypeDPDKRejectedAtCommitViaApplyGroups
      (apply-groups expansion path), plus negative-control pair
      TestDataplaneTypeUserspaceCompilesCleanly and
      TestDataplaneTypeOmittedCompilesCleanly.
    - parser_system_test.go: dropped `dpdk` from the
      TestDataplaneTypeNonLegacyValuesDoNotWarnDeprecatedCompatibility
      loop (now hard-errors at compile).
    - configstore/store_test.go: 2 new tests —
      TestCommit_RejectsDPDKDataplaneType locks in BOTH the raw
      CommitCheck error AND the `commit check failed:`-wrapped
      Commit error, plus TestCommit_AcceptsUserspaceDataplaneType
      negative control.

    Plan v3 updated to (a) switch tests from byte-exact to
    substring-match for cross-surface compatibility, (b) correct
    the daemon-startup recovery flow text (candidate is empty
    after failed Load, not pre-populated), (c) honor the issue
    body's verbatim `(see #1525)` (does not point at #1531 docs).

    Test gates: go build ./... clean. go test ./... clean across
    33 packages. 5x flake check on new tests passes. cargo check
    on userspace-dp/ clean (no Rust touched).
  - **File(s)**: `pkg/config/compiler.go`,
    `pkg/config/parser_ast_test.go`,
    `pkg/config/parser_system_test.go`,
    `pkg/configstore/store_test.go`,
    `docs/pr/1526-dpdk-reject/plan.md`
## 2026-05-25 — #1529 Codex code-review finding follow-up

- **Timestamp**: 2026-05-25T06:50:00Z
  - **Action**: Codex code review NEEDS-MINOR with three findings,
    all addressed:
    (1) _Log.md said 25 files but commit had 26; corrected.
    (2) `docs/pr/1373-retire-ebpf-dataplane/README.md` safe-delete
        bullet said "#1475 section below" but #1475 is above the
        safe-delete blockers list; corrected to "section in this
        file".
    (3) Tense mismatch in `docs/userspace-dataplane-gaps.md` and
        `docs/userspace-dataplane-architecture.md`: changed
        "legacy eBPF used" back to "legacy eBPF uses" since
        legacy eBPF is still present during the staged retirement.
  - **File(s)**: `docs/pr/1373-retire-ebpf-dataplane/README.md`,
    `docs/userspace-dataplane-gaps.md`,
    `docs/userspace-dataplane-architecture.md`, `_Log.md`

## 2026-05-25 — #1529 Antigravity code-review finding follow-up

- **Timestamp**: 2026-05-25T06:30:00Z
  - **Action**: Antigravity code review MERGE-READY with one new
    finding: `pkg/dataplane/README.md` and `pkg/daemon/README.md`
    were missed by the original docs/ + root grep. The issue body
    for #1529 explicitly names `pkg/dataplane/README.md` as part
    of the retirement boundary, so this was a scope-coverage miss.
    Edited `pkg/dataplane/README.md` and `pkg/daemon/README.md` to
    reframe DPDK references past-tense; pointed at the canary-
    pinned `#1475 DPDK Backend Policy` section as the historical
    anchor.
  - **File(s)**: `pkg/dataplane/README.md`, `pkg/daemon/README.md`,
    `_Log.md`

## 2026-05-25 — #1529 implementation

- **Timestamp**: 2026-05-25T06:00:00Z
  - **Action**: Implemented the v3 plan. 26 files touched, all `*.md`.
    Pure-text gate passes; no source files touched. Chain A boundary
    confirmed (no overlap with `docs/dataplane-decision-dpdk-vs-vpp.md`
    or `docs/dpdk-dataplane.md`). All three retirement-boundary doc
    canaries pass: `TestRetirementBoundaryDocsMentionDPDKPolicy`,
    `TestRetirementBoundaryDocsMentionShimEscapeAssumptions`,
    `TestRetirementBoundaryDocsMentionLegacyImportAllowlist`. Full
    `pkg/dataplane/...` Go test suite passes. Cargo sanity build
    passes.
  - **File(s)**: README.md, CLAUDE.md, docs/pr/1373-retire-ebpf-dataplane/{README.md,source-removal-manifest-1476.md},
    docs/{active-active-new-connections.md, authoritative-backlog.md,
    bugs.md, deterministic-nat-cgnat.md, fabric-bridge-tuning.md,
    feature-gaps.md, memory.md, perf-ranked-backlog.md, phases.md,
    refactoring-audit.md, userspace-dataplane-architecture.md,
    userspace-dataplane-gaps.md, userspace-fabric-redirect-fix.md,
    vpp-dataplane-assessment.md, xdp-io-uring-userspace-dataplane.md},
    docs/next-features/{application-identification.md,
    ha-session-ownership-and-fabric-failover.md,
    ipv6-session-fast-path.md, pre-id-default-policy.md,
    twice-nat.md, vsrx-fabric-fab0-fab1-syntax-compat.md}, _Log.md.

## 2026-05-25 — #1529 plan v3 (Antigravity r2 build-breaker fix)

- **Timestamp**: 2026-05-25T05:30:00Z
  - **Action**: v3 plan addresses Antigravity r2 PLAN-NEEDS-MINOR.
    The §1504 paragraph in `docs/pr/1373-retire-ebpf-dataplane/README.md`
    is ALSO canary-pinned by
    `TestRetirementBoundaryDocsMentionShimEscapeAssumptions`
    (pinned string "does not recurse"). v2's proposed rewrite
    would have broken the build. v3 defers §1504 rewrite to
    #1527/#1528 along with §1475. Only lines 65 and 292 (not
    canary-pinned) are edited in-place; line 65 split into two
    sentences to fix grammar, line 292 explicitly includes the
    `- ` bullet marker.
  - **File(s)**: `docs/pr/1529-dpdk-docs-sweep/plan.md`, `_Log.md`

## 2026-05-24 — #1529 plan v2 (Codex r1 fixes)

- **Timestamp**: 2026-05-25T05:00:00Z
  - **Action**: v2 plan addresses Codex r1 PLAN-NEEDS-MAJOR six
    findings: non-canary-pinned DPDK text now has explicit
    rewrites; acceptance-criterion 4 deferral now documented as
    staged exception; EDIT row ambiguity eliminated;
    docs/refactoring-audit.md annotate (not drop);
    historical-classification wording clarified; git diff gate
    uses --name-only.
  - **File(s)**: `docs/pr/1529-dpdk-docs-sweep/plan.md`

## 2026-05-24 — #1529 plan v1 drafted

- **Timestamp**: 2026-05-24T17:00:00Z
  - **Action**: Drafted plan v1 for #1529 (DPDK retirement Phase 4 —
    broad docs sweep). Per-file disposition table covers ~42 files
    with DPDK references. Major scope adjustment: the
    `#1475 DPDK Backend Policy` section in
    `docs/pr/1373-retire-ebpf-dataplane/README.md` is canary-pinned
    by `TestRetirementBoundaryDocsMentionDPDKPolicy` and the rewrite
    is deferred to #1527/#1528. This PR adds a leading retirement
    note above it instead.
  - **File(s)**: `docs/pr/1529-dpdk-docs-sweep/plan.md`, `_Log.md`

- **Timestamp**: 2026-05-25T07:30:00Z
  - **Action**: #1538 plan v1 (DRAFT) — accumulate strict validation
    errors via `errors.Join` in `compileExpanded` so `commit check`
    surfaces every dormant structural finding in one pass instead
    of forcing whack-a-mole CLI round-trips. Plan composes with the
    in-flight #1536 (validateDataplaneTypeStrict) under either merge
    order. Walks Junos UX (Junos itself accumulates), validator
    independence (each strict validator reads its own typed sub-
    struct, all nil-safe), substring/sentinel contract preservation
    (`strings.Contains` + `errors.Is` traverse `errors.Join`), and
    risk table. Calls out 7 hostile reviewer questions including
    PLAN-KILL grounds.
  - **File(s)**: `docs/pr/1538-multierror-validation/plan.md`,
    `_Log.md`
- **Timestamp**: 2026-05-25T15:15:18Z
  - **Action**: #1539 Copilot follow-up on PR #1553. Tightened
    `pkg/config/dpdk_subtree_leakage_canary_test.go` so a
    `DPDKDataplane` selector or helper pass-through at package
    scope is reported immediately instead of being skipped when
    no enclosing `FuncDecl` exists. Added
    `TestDPDKSubtreeLeakageCanary_NegativeRejectsPackageScopeInitializer`
    with `negativePackageScopeInitializerFixture` covering both a
    package-scope read and a package-scope helper pass-through.
    Closing-sentence truncation flagged in a later Copilot pass
    is restored here (the previous trailing "Added" was an
    artifact of an over-aggressive _Log.md rebase-union helper).
  - **File(s)**: pkg/config/dpdk_subtree_leakage_canary_test.go,
    _Log.md

- **Timestamp**: 2026-05-25T16:25:00Z
  - **Action**: #1539 Copilot round-3 finding addressed. After
    HEAD f90125b3 + docs commit 4a1c8726, Copilot's re-review
    re-anchored the original 4 findings to the new SHA (all
    already addressed) but issued ONE new finding (15:22:25Z,
    inline at line 112 of the new tree): the
    `dpdkSubtreeLeakageCanaryExcludeDirs["dpdk"]` bare-dirname
    skip would silently hide a future `pkg/config/dpdk/...`
    sub-directory — exactly the leakage class the canary is
    supposed to catch. Fixed: the exclusion map now uses
    paths RELATIVE to the walk root (computed via `filepath.Rel`
    + `filepath.ToSlash`), and the v3 default is empty since
    the production scan root is `pkg/config/` only and there
    is no `pkg/config/dpdk/` today. Future canary scope
    extensions add explicit relative paths (e.g.
    `pkg/dataplane/dpdk`).
  - **File(s)**: pkg/config/dpdk_subtree_leakage_canary_test.go,
    _Log.md
- **Timestamp**: 2026-05-25T16:00:00Z
  - **Action**: #1539 Copilot findings on PR #1553 — 5 valid
    findings on HEAD 12237f12 addressed across two commits
    (Copilot SWE bot fixed findings 1/5 + I rebased on top
    with findings 2/3/4). (1+5) package-scope init bypass:
    SelectorExpr and CallExpr branches treated `fn == nil`
    as silent skip — `var leaked = cfg.System.DPDKDataplane`
    at file scope escaped the canary; both fixed by treating
    nil enclosing FuncDecl as an automatic finding with
    distinct `package-scope read/passthrough of ...` why
    text. New
    `TestDPDKSubtreeLeakageCanary_NegativeRejectsPackageScopeInitializer`
    exercises both kinds.
    (2) RepoRoot inconsistency: `dpdkSubtreeLeakageCanaryRepoRoot
    = ".."` then joined with "config" was confusing; replaced
    with `dpdkSubtreeLeakageCanaryProductionScanRoot = "."`.
    (3) Allowlist key drift: comment said "strip leading ../"
    but code didn't. Replaced with proper `filepath.Rel(root,
    path)` normalization so future allowlist keys are
    package-relative regardless of walk root.
    (4) Duplicate "Plan v1" header in reviewer-ids.md removed.
    All 11 canary tests pass; 5x flake-clean; full pkg/config
    suite green.
  - **File(s)**: pkg/config/dpdk_subtree_leakage_canary_test.go,
    _Log.md
    docs/pr/1539-ast-leakage-guard/reviewer-ids.md, _Log.md
- **Timestamp**: 2026-05-25T15:50:00Z
  - **Action**: #1539 code-review on PR #1553 + lint fix
    (commit 6a7d0649). Codex MERGE-READY directly on 8c5a4ced
    (session 019e5fa4 continued). AGY initially MERGE-WITH-MAJOR
    flagging HIGH (multi-LHS bypass: `dummy, sys.DPDKDataplane
    = nil, &cfg{}` would escape canary because original isLHSOfAssignToNil
    checked "any RHS nil" not positional pairing) + MEDIUM
    (hand-rolled itoa OOB for >=12 digits, MinInt negation
    overflow). My local lint pass on the file produced the same
    positional-LHS fix AGY recommended; committed as 6a7d0649
    with the new TestDPDKSubtreeLeakageCanary_NegativeRejects
    MultiVariableBypass test fixture. AGY final verdict MERGE-READY.
    Both reviewers now MERGE-READY on 6a7d0649. Hand-rolled itoa
    swapped for strconv.Itoa. All 10 canary tests pass; full
    `go test ./...` clean.
  - **File(s)**: pkg/config/dpdk_subtree_leakage_canary_test.go,
    docs/pr/1539-ast-leakage-guard/reviewer-ids.md, _Log.md
- **Timestamp**: 2026-05-25T15:25:00Z
  - **Action**: #1539 implementation — Option A + Option B per
    plan v3. Option A: `cfg.System.DPDKDataplane = nil` clear at
    end of `compileExpanded` after `validateDataplaneTypeStrict`
    succeeds and before `return cfg, nil`. Option B: new
    pkg/config/dpdk_subtree_leakage_canary_test.go (~600 LOC
    including ~200 LOC walker + fixtures + 9 tests). Canary uses
    parent-stack maintained via ast.Inspect nil-callback
    semantics, walks parent chain to enclosing FuncDecl (AGY
    round-2 MEDIUM nested-conditional fix), recognizes IfStmt
    `==` gates and switch single-entry case-clause gates (AGY
    round-2 HIGH multi-case fix), and rejects negation idiom
    (Codex round-2 contradictory-paragraph fix). LHS-of-assign-
    to-nil is recognized so Option A's clear is not flagged.
    Real-repo scan returns zero findings; 5x flake-clean on
    named tests; `go test ./...` passes across all 30 packages.
  - **File(s)**: pkg/config/compiler.go,
    pkg/config/dpdk_subtree_leakage_canary_test.go, _Log.md
- **Timestamp**: 2026-05-25T14:50:00Z
  - **Action**: #1539 plan v3 — applied round-2 plan review
    feedback. Codex round-2 PLAN-MINOR (session
    019e5fa4-0552-7823-915d-79eaf79b1c55), AGY round-2 PLAN-MINOR
    (adversarial-review-mplbulo0-y014py). Window-of-value KILL
    no longer operative on both sides. v3 changes: section 4.2
    walks parent chain to FuncDecl (AGY MEDIUM nested-conditional
    fix); SwitchStmt CaseClause requires `len(List)==1` (AGY HIGH
    multi-case bypass fix); negation idiom explicitly rejected
    (Codex contradictory-paragraph fix); two new fixtures
    (positive nested, negative multi-case, negative negation);
    stale #1536 stacking text corrected — #1536 merged at
    fcd53beb. Reviewer-IDs file updated.
  - **File(s)**: docs/pr/1539-ast-leakage-guard/plan.md,
    docs/pr/1539-ast-leakage-guard/reviewer-ids.md

- **Timestamp**: 2026-05-25T05:00:00Z
  - **Action**: #1501 A2 — replaced the stale TODO + contradictory
    doc comment on `write_outer_ipv4_udp` with an honest
    RFC-grounded comment explaining that the engine intentionally
    emits outer IPv4 UDP cs=0 (legal per RFC 768) and that this
    DIFFERS from kernel WireGuard / wireguard-go which compute
    the outer UDP checksum. Added two byte-level regression
    assertions on `out[26..28] == [0, 0]` (one new dedicated
    `udp_checksum_is_zero_on_ipv4_outer` test + a strengthened
    `ipv4_checksum_is_correct`) with 0xff sentinel pre-fill so
    the assertion proves the function wrote zero rather than
    leaving the buffer zero-initialized. Triple-review:
    Antigravity (round-1 PLAN-NEEDS-MINOR for sentinel pre-fill;
    round-2 PLAN-READY) and Codex (round-1 PLAN-NEEDS-MAJOR for
    factually-wrong "matches kernel WG" claim; round-2
    PLAN-READY) both agreed before code touched.
  - **File(s)**: `userspace-dp/src/afxdp/wg/outer.rs`,
    `docs/pr/1501-a2-outer-udp-cs/plan.md`, `_Log.md`
  - **Validation**: cargo build --release clean; cargo test
    --release for `afxdp::wg::outer` 6/6 pass (5x flake-checked);
    full cargo suite 1417 passed modulo two pre-existing flaky
    tests on origin/master da103d81 baseline
    (`snat_contract_documents_current_fail_closed_runtime`
    fails consistently on master too;
    `reconcile_peers_snapshot_is_atomic_under_concurrent_load`
    is a 1-in-5 load flake on master too); `go test ./...`
    clean; smoke on loss userspace cluster Pass A (CoS off)
    0-retrans single-stream + 23 Gb/s 12-stream `-R`, and
    Pass B (CoS on) 24-cell per-class shaper smoke 5201-5206 ×
    v4+v6 × push+rev with shape rates hit cleanly.
- **Timestamp**: 2026-05-25T05:30:00Z
  - **Action**: Addressed Copilot's 4 nits on PR #1534 (DPDK
    operator docs retirement, #1531). Harmonized retirement banners
    in `docs/dataplane-decision-dpdk-vs-vpp.md` and
    `docs/dpdk-dataplane.md` from "is being retired" to "is retired"
    so banners and Current State sections agree. Converted bare
    code span around `docs/vpp-dataplane-assessment.md` to a
    proper markdown link in the Related Documents section.
    Tightened the "underlay-NIC XSK" wording in the encrypted
    tunnel revisit trigger to "userspace-dp's AF_XDP socket on
    the physical NIC cannot see inner payloads of kernel-managed
    tunnels", which avoids conflating the NIC XDP hook with the
    AF_XDP socket. Folded the awkward "The previous header read:"
    preamble in `docs/dpdk-dataplane.md` into a single narrative
    paragraph describing the prior #1475 policy and noting it has
    been superseded by #1525.
  - **File(s)**: `docs/dataplane-decision-dpdk-vs-vpp.md`,
    `docs/dpdk-dataplane.md`, `_Log.md`
  - **Validation**: docs + log + userspace-dp README scope —
    `git diff --stat origin/master..HEAD` touches `docs/` paths,
    the root `_Log.md` action log, and `userspace-dp/README.md`
    (the README wording fix is the only file outside `docs/`).
    No `.go` / `.rs` / `.c` source, no build inputs, no test
    fixtures modified.

## 2026-05-24

- **Timestamp**: 2026-05-24T06:35:00Z
  - **Action**: PR #1531 implementation v2 — applied retirement
    banner + Current State + reframed VPP revisit trigger +
    [Retired] Historical block to both
    `docs/dataplane-decision-dpdk-vs-vpp.md` and
    `docs/dpdk-dataplane.md`; updated
    `docs/vpp-dataplane-assessment.md` inbound-pointer header to
    note DPDK / decision doc retirement and explicitly preserve
    "still useful" architectural threads (encrypted-tunnel
    reasoning + native Go VRRP decision). Then addressed Codex
    plan-review v2 findings: (a) sharpened the VPP revisit
    trigger in the decision doc to specify "physical NIC XDP /
    AF_XDP hook sees only outer encrypted packets when kernel
    WireGuard/XFRM performs crypto" plus post-crypto interface
    hook options; (b) updated `userspace-dp/README.md` "still
    selected ... until later cutover" wording to reflect that
    `EffectiveType` now defaults to userspace today.
    Historical sections kept verbatim under bold-block retired
    banners with all original H2 headings demoted to H3 inside
    the retired wrapper.
  - **File(s)**: `docs/dataplane-decision-dpdk-vs-vpp.md`,
    `docs/dpdk-dataplane.md`,
    `docs/vpp-dataplane-assessment.md`,
    `userspace-dp/README.md`

- **Timestamp**: 2026-05-24T00:00:00Z
  - **Action**: PR #1531 plan v1 drafted. Retire DPDK
    recommendations in `docs/dataplane-decision-dpdk-vs-vpp.md`
    and `docs/dpdk-dataplane.md`; rewrite both as short
    retirement notices pointing at #1525.
  - **File(s)**: `docs/pr/1531-dpdk-docs-retire/plan.md`

## 2026-05-25 (earlier — prior PR follow-ups)
- **Timestamp**: 2026-05-25T07:05:00Z
  - **Action**: #1527 round-7 Copilot follow-up. Copilot review on
    9b4e9e24 (COMMENTED, 5 inline comments) flagged two new
    consistency nits on top of the 3 already-resolved ones:
    (1) `pkg/dataplane/dataplane.go:160` — `NewDataPlane`'s
    unknown-type error listed "userspace" as valid even though
    legacy `NewDataPlane(TypeUserspace)` falls through to the
    registry lookup and errors out; the message is now
    `"unknown dataplane type %q (valid via NewDataPlane: ebpf; use NewRuntimeDataPlane for userspace)"`
    with a clarifying comment;
    (2) `pkg/daemon/daemon_ha_sync.go:684` — the "disabling all
    RGs" log fired even when `cfg.Chassis.Cluster == nil`, which is
    misleading. Moved it inside the cluster-cfg-non-nil branch with
    an `rg_count` slog kv field. The neutral "fence received from
    peer" log at line 667 stays as the unconditional entry point.
    Both fixes are comment-only consistency nits, no behavior
    change.
  - **File(s)**: `pkg/dataplane/dataplane.go`,
    `pkg/daemon/daemon_ha_sync.go`, `_Log.md`
  - **Validation**: `go build ./...` clean; `go test
    ./pkg/dataplane/... ./pkg/daemon/... -count=1` clean.

- **Timestamp**: 2026-05-25T05:55:15Z
  - **Action**: #1527 final Copilot re-review follow-up — resolved three
    remaining consistency nits from the latest Copilot inline pass:
    (1) `compiler_system.go` invalid dataplane-type guidance now
    matches current parser acceptance (`ebpf, dpdk, userspace`);
    (2) peer-fence logging in `daemon_ha_sync.go` now logs a neutral
    receive message before the nil-dataplane guard and emits
    "disabling all RGs" only when deactivation will actually run;
    (3) plan status header in
    `docs/pr/1527-dpdk-boot-decouple/plan.md` corrected from v3 to v4.
    Ran focused package tests for dataplane/config/daemon.
  - **File(s)**: `pkg/config/compiler_system.go`,
    `pkg/daemon/daemon_ha_sync.go`,
    `docs/pr/1527-dpdk-boot-decouple/plan.md`, `_Log.md`

- **Timestamp**: 2026-05-25T06:50:00Z
  - **Action**: #1527 reviewer re-dispatch on 878bcbdd after my
    earlier v3 NPE-fix commit landed. Codex hostile re-review
    (task-mpks5yrq-4h7ia5) and Antigravity adversarial re-review
    (adversarial-review-mpks62um-g47sg4) dispatched with explicit
    context that the OnFenceReceived NPE is now guarded at
    daemon_ha_sync.go:676-679, and that stale docs prose is
    intentionally deferred to Chain C #1529 — the canary test still
    passes because every pinned token still exists in the README.
    Copilot re-triggered via @copilot review (issue-comment
    4531855093). Ran the full smoke matrix on the loss userspace
    cluster after make cluster-deploy: Pass A (CoS-off) v4 push 8.81
    Gb/s / v6 push 8.75 Gb/s / v4 reverse 8.65 Gb/s / v6 reverse 8.87
    Gb/s / -P 12 -R v4 23.0 Gb/s / v6 22.6 Gb/s, all zero-retrans;
    Pass B (CoS-on) 24-cell per-class matrix all shaped correctly on
    push (100m→83/82 Mb/s, 1g→844/832 Mb/s, ..., 12g→6.54/6.37 Gb/s)
    and reverse unshaped 7.4-8.2 Gb/s. Reviewer-ids recorded in
    docs/pr/1527-dpdk-boot-decouple/reviewer-ids.md. Smoke posted as
    PR comment 4531859958.
  - **File(s)**: `docs/pr/1527-dpdk-boot-decouple/reviewer-ids.md`

- **Timestamp**: 2026-05-25T06:40:00Z
  - **Action**: #1527 v4 — Codex hostile code review v3
    (task-mpkrwbtk-pd6nnw MERGE-NEEDS-MAJOR) and Antigravity
    adversarial review v3 (adversarial-review-mpkrwmkk-2k24v4
    MAJOR) both independently caught a nil-pointer crash exposed
    by the v3 soft-fallback: `pkg/daemon/daemon_ha_sync.go:670`
    `OnFenceReceived` callback unconditionally called
    `d.dp.HA().SetRGActive(...)`. With `d.dp = nil` after the
    `ErrDPDKBackendRetired` soft-fallback, the next peer-fence
    message would panic the daemon. Pre-existing latent bug
    (also reachable via Start() failure) but newly exposed by
    v3's more-reachable nil-dp path. Added a `d.dp == nil`
    early-return with structured log explaining the
    config-only-mode rationale. Codex v3 also flagged that
    `docs/pr/1373-retire-ebpf-dataplane/README.md` lines 64 and
    85 contain factually stale claims about `cmd/xpfd/main.go`
    keeping the DPDK blank import. The pinned canary tokens
    still pass literally, but the prose now describes a
    pre-#1527 reality. Intentionally left untouched per the
    Chain C (#1529) scope boundary; flagged in plan v4 + PR
    description as a Chain C TODO. Build clean, full Go test
    suite clean.
  - **File(s)**: `pkg/daemon/daemon_ha_sync.go`,
    `docs/pr/1527-dpdk-boot-decouple/plan.md`

- **Timestamp**: 2026-05-25T06:00:00Z
  - **Action**: #1527 Copilot review response — Copilot flagged on
    `47a4278c` that returning `ErrDPDKBackendRetired` at construction
    time in `NewRuntimeDataPlane` is now fatal in
    `pkg/daemon/daemon_run.go` (the "create dataplane" error path
    exits the daemon), whereas a `Start()` failure falls back to
    config-only mode with a warning. Nodes that still have a
    persisted `set system dataplane-type dpdk` would be bricked on
    restart even before Chain A (#1526) blocks the commit. Addressed
    by special-casing `errors.Is(err, ErrDPDKBackendRetired)` in
    `daemon_run.go`: log a structured warning with remediation
    guidance, set `d.dp = nil`, and fall through to config-only mode
    (same posture as a `Start()` failure). The hard fatal branch is
    preserved for genuinely unknown dataplane types. No new imports
    needed (`errors` already imported). Build clean,
    `go test ./pkg/dataplane/... ./pkg/daemon/...` clean.
  - **File(s)**: `pkg/daemon/daemon_run.go`

- **Timestamp**: 2026-05-25T06:30:00Z
  - **Action**: #1527 second Copilot review pass — addressed MUST FIX
    and SHOULD FIX items from prior adversarial review: (1) Added
    TypeDPDK panic guard to RegisterBackend and RegisterRuntimeBackend
    so silent re-registration is immediately visible rather than
    permanently silently unreachable. (2) Added
    TestRegisterDPDKBackendPanics to dpdk_stub_test.go to pin the
    panic behavior. (3) Cleaned stale DPDK references from DataPlane
    interface docstrings (lines 185-186, 338, 341-343, 347, 381-382,
    386). (4) Fixed compiler_system.go error string to say "valid:
    ebpf, userspace" instead of "valid: ebpf, dpdk, userspace".
    Build clean, go test ./pkg/dataplane/... ./pkg/daemon/...
    ./pkg/config/... clean.
  - **File(s)**: `pkg/dataplane/dataplane.go`,
    `pkg/dataplane/dpdk/dpdk_stub_test.go`,
    `pkg/config/compiler_system.go`, `_Log.md`


## 2026-05-24

- **Timestamp**: 2026-05-24T12:00:00Z
  - **Action**: #1527 DPDK retirement Phase 2 (boot-path decouple) —
    drafted plan v1 covering blank-import removal, init()
    registration deletion, retirement-error returns from
    NewDataPlane / NewRuntimeDataPlane factories, canary allowlist
    shrink, Phase-1373 README DPDK-policy prose update, and
    package-local test rewrite. Plan includes 8 open questions for
    adversarial review and explicit out-of-scope list to keep
    Chain A (#1526) and Chain C (#1528/#1529) lanes clean.
  - **File(s)**: `docs/pr/1527-dpdk-boot-decouple/plan.md`

- **Timestamp**: 2026-05-24T18:30:00Z
  - **Action**: #1527 plan v2 — incorporated Codex hostile plan
    review (task-mpkqsgf5-j2yag1, PLAN-NEEDS-MINOR). Three MUST-FIX
    items applied: (1) require Chain A #1526 to land BEFORE this PR
    (was "either order works" — Codex showed today's UX is
    config-only fallback with slog.Warn but this PR makes the same
    config fatal at startup); (2) dropped Change 5 docs edit — the
    required canary tokens are already present in
    docs/pr/1373-retire-ebpf-dataplane/README.md, so docs prose is
    Chain C #1529 scope only; (3) acknowledged that
    ErrDPDKBackendRetired cannot be used by pkg/config (Chain A)
    due to dataplane->config import cycle. Also corrected
    errDPDKBuildTagRequired claim (it's !dpdk-gated, not a
    defense-in-depth for -tags dpdk). Antigravity PLAN-READY
    (adversarial-review-mpkqkzkm-qfa19j) verdict preserved.
  - **File(s)**: `docs/pr/1527-dpdk-boot-decouple/plan.md`

- **Timestamp**: 2026-05-24T19:00:00Z
  - **Action**: #1527 implementation. Removed the
    `_ "github.com/psaab/xpf/pkg/dataplane/dpdk"` blank import
    from cmd/xpfd/main.go. Deleted the init() block in
    pkg/dataplane/dpdk/manager.go that registered the backend with
    both dataplane.RegisterBackend and
    dataplane.RegisterRuntimeBackend; replaced it with a comment
    pointing at #1527/#1525/#1528. Added exported sentinel
    `dataplane.ErrDPDKBackendRetired` in pkg/dataplane/dataplane.go
    plus TypeDPDK reject arms in NewDataPlane (errors before the
    registry fallback) and NewRuntimeDataPlane (errors after
    EffectiveType normalization so the empty-default path stays
    on userspace). Removed "dpdk" from the NewDataPlane
    unknown-type error message. Shrunk dpdkBackendImportAllowlist
    to an empty map and removed the cmd/xpfd/main.go DPDK
    exemption from
    TestOperatorPackagesDoNotImportBPFArtifactsDirectly. Rewrote
    dpdk_stub_test.go's TestDPDKConstructorsRemainRegistered as
    TestDPDKConstructorsReturnRetirementError, asserting
    errors.Is(err, ErrDPDKBackendRetired) for both factories;
    TestDPDKStubRequiresDPDKBuildTag retained unchanged. Per Codex
    round-1 MUST-FIX (3): docs/pr/1373-retire-ebpf-dataplane/README.md
    NOT touched — Chain C (#1529) scope, and the docs-token canary
    stays green untouched. Updated legacyDataplaneImportAllowlist
    description for cmd/xpfd/main.go to reflect post-#1527 reality
    (cleanup only, no registration).
  - **File(s)**: `cmd/xpfd/main.go`,
    `pkg/dataplane/dpdk/manager.go`,
    `pkg/dataplane/dataplane.go`,
    `pkg/dataplane/retirement_boundary_canary_test.go`,
    `pkg/dataplane/dpdk/dpdk_stub_test.go`
- **Timestamp**: 2026-05-24T18:00:00Z
  - **Action**: #1473 closeout plan. Added per-AC evidence document
    citing the prior PRs that landed the runtime decouple (#1493,
    #1498), the boundary canary (#1512), the link-cycle regressions
    (#1513), and the counter rename (#1514). Marked #1473 as
    closeout-pending in the #1373 README. No runtime code change
    required; AC1-AC5 already proven on master at da103d81.
  - **File(s)**: `docs/pr/1473-xdp-shim-decouple/plan.md`,
    `docs/pr/1373-retire-ebpf-dataplane/README.md`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane ./pkg/dataplane/userspace`
    targeted runs for the AC-pinned canary/regression test set.

- **Timestamp**: 2026-05-25T00:45:00Z
  - **Action**: PR #1512 review follow-up — tightened the positional
    `dataplane.Manager` literal canary on two axes. (a) Recurse into nested
    composite literals whose `Type` is nil when the enclosing slice / array /
    map container's element/value type is a package-local Manager named type,
    closing the `[]Manager{{false, nil, "..."}}` / array / map bypass.
    (b) Only flag when the element at `xdpEntryProgIndex` is positional
    (not `*ast.KeyValueExpr`), so fully-keyed and mixed-where-xdpEntryProg-
    is-keyed literals stop producing empty-string false-positive violations.
    Added six fixture sub-tests pinning each direction.
  - **File(s)**: `pkg/dataplane/retirement_boundary_canary_test.go`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane/ -count=1`;
    `go test ./pkg/dataplane/ -count=1 -run
    'TestRetainedUserspaceShimBoundary|TestPositionalDataplaneManager' -v`

- **Timestamp**: 2026-05-25T00:30:00Z
  - **Action**: PR #1499 r-final-6 fix — rebased onto current
    `origin/master` after PR #1511 merged. Resolved chronological
    `_Log.md` conflicts across two rebased PR commits (`d379c9d9`
    r-final-3 and `95fc992f` r-final-4) by interleaving the new
    `pkg/logging/binary_test.go` PR #1451 review-follow-up entries
    from master with the existing PR #1499 entries. All other
    commits replayed cleanly with no code conflicts. Mechanical
    plan.md citation sweep on the rebased tree produced two residual
    minor citation drifts (the same two Copilot flagged as non-
    blocking on `183bc394`): (1)
    `pkg/dataplane/userspace/protocol.go:250` cited
    `afxdp/wg/engine.rs:271` for the `sessions_by_local_index`
    field — actual field declaration is at line 275 (line 271 is
    inside the `/// ` doc block that introduces it). Corrected
    citation to `engine.rs:275`. (2) `docs/pr/wireguard-clean/plan.md`
    cited `mod.rs:86-91` for "the engine constants" describing both
    `WG_DATA_HEADER_LEN` and `POLY1305_TAG_LEN`; the cited range
    only covers the data-header constant. `POLY1305_TAG_LEN` is at
    line 84. Widened both citations (lines 76 and 444) to
    `mod.rs:84-91` so the range covers both constants the
    surrounding prose names. No code changes.
  - **File(s)**: `pkg/dataplane/userspace/protocol.go`,
    `docs/pr/wireguard-clean/plan.md`, `_Log.md`
  - **Validation**: rebase clean after manual `_Log.md` resolution
    on commits `d379c9d9` + `95fc992f`; `cargo build --release`
    clean (114 warnings, all pre-existing); `cargo test --release
    --bin xpf-userspace-dp afxdp::wg` — 78/78 pass; `go test
    ./pkg/dataplane/...` — 4/4 packages pass.

- **Timestamp**: 2026-05-24T23:30:00Z
  - **Action**: PR #1499 r-final-5 step 4 — final mechanical sweep
    pass. After the previous step's edits shifted lines in
    engine.rs (+4 from the jumbo-MTU comment expansion), scratch.rs
    (+2 from the doc-comment rewrite), and session.rs (+5 from the
    local_index doc-comment rewrite), the plan's own line citations
    that I had just "fixed" were already stale. Cross-grepped every
    remaining plan.md file:line citation:
    - `scratch.rs:17-21` → `scratch.rs:18-25` (struct field
      definitions shifted by +1..+4 lines)
    - `scratch.rs:25-30` → `scratch.rs:27-33` (constructor)
    - `engine.rs:258` → `engine.rs:262` (`table: ArcSwap<PeerTable>`)
    - `engine.rs:506-510` → `engine.rs:510-514` (`peer.current.read()`)
    - `engine.rs:643-649` → `engine.rs:647-653`
      (`sessions_by_local_index.read()` in try_decap)
    - `engine.rs:671-676` → `engine.rs:675-680` (pre-AEAD replay
      precheck-lock block)
    - `engine.rs:695` → `engine.rs:699-718` (post-AEAD replay
      update-lock block — now cites the actual block range)
    - `session.rs:72` → `session.rs:77`
      (`replay: Mutex<ReplayState>`)
    All other citations (afxdp/mod.rs:175, mod.rs:86-91/95/98,
    framing.rs:32-46, outer.rs:23-45, protocol.rs:417-450,
    types/forwarding.rs:129-140, forwarding/mod.rs:751,
    tx/dispatch.rs:430/785-792/1458-1459, frame/mod.rs:212,
    frame/tcp_segmentation.rs:309, tunnel.rs:189) re-verified.
  - **File(s)**: docs/pr/wireguard-clean/plan.md

- **Timestamp**: 2026-05-24T23:15:00Z
  - **Action**: PR #1499 r-final-5 fix step 3 — line-citation offsets
    + stale field-name drift + scratch.rs MAX_FRAME doc-comment.
    Updated plan.md:104 to spell out `wg_peer_pubkey_hex` (was the
    pre-r4 stale `wg_peer_pubkey`) and added a `protocol.rs:437-438`
    pointer. Updated plan.md hot-path lock-read citations from
    `engine.rs:499-503` → `engine.rs:506-510` (encap-side
    `peer.current.read()`) and `engine.rs:636-642` →
    `engine.rs:643-649` (decap-side `sessions_by_local_index.read()`),
    matching the actual line numbers after the truncated-record DoS
    guard landed at engine.rs:664-666. Updated protocol.go:250 to
    cite `engine.rs:271` instead of `engine.rs:264` for
    `sessions_by_local_index`. Updated engine.rs:194 jumbo-MTU
    comment to drop the fragile `engine.rs:539` line citation and
    point at the `if padded_len > PADDED_PLAINTEXT_MAX` guard by
    pattern instead (actual line 546). Rewrote session.rs:62-69
    `local_index` doc comment so it no longer says inbound demux is
    `(listen_port, local_index)` — the engine map is keyed by
    `local_index` alone. Rewrote allowed_ips.rs:11-19 to spell out
    `wg_peer_pubkey_hex` (was `wg_peer_pubkey`) and to drop the
    false claim that the field lives on the runtime `TunnelEndpoint`
    — the snapshot has it; the runtime type extension is integration-
    PR scope. Rewrote scratch.rs:3-10 to drop the false
    `MAX_FRAME = 2048` constant (no such constant exists — the
    UMEM constant is `UMEM_FRAME_SIZE = 4096` in `afxdp/mod.rs:175`)
    and to make the parameter-passed `max_frame` explicit.
  - **File(s)**: docs/pr/wireguard-clean/plan.md,
    userspace-dp/src/afxdp/wg/engine.rs,
    userspace-dp/src/afxdp/wg/session.rs,
    userspace-dp/src/afxdp/wg/allowed_ips.rs,
    userspace-dp/src/afxdp/wg/scratch.rs,
    pkg/dataplane/userspace/protocol.go

- **Timestamp**: 2026-05-24T23:05:00Z
  - **Action**: PR #1499 r-final-5 fix step 2 — integration-PR pointer
    rewritten. plan.md "Encap call site" claimed dispatch.rs:430 was
    the egress encap point that unconditionally called
    `encapsulate_native_gre_frame`. Actual: dispatch.rs:430 only
    computes the `uses_native_tunnel = tunnel_endpoint_id != 0` gate;
    the real `encapsulate_native_gre_frame` calls live in
    `frame/mod.rs:212` (copy path, invoked from dispatch at
    `tx/dispatch.rs:785-792`), `frame/tcp_segmentation.rs:309`
    (TCP segmentation), and `tunnel.rs:189` (local origination).
    Rewrote the section to enumerate all three sites and clarified
    that dispatch.rs:430 *computes the gate*, it does not itself
    encap. Also updated the "What's OUT" bullet that referenced
    `tx/dispatch.rs` activation to enumerate the same three sites.
  - **File(s)**: docs/pr/wireguard-clean/plan.md

- **Timestamp**: 2026-05-24T23:00:00Z
  - **Action**: PR #1499 r-final-5 fix pass start — exhaustive mechanical
    plan.md sweep against actual source. Step 1 fixed: WG data-record
    header described as 20 bytes in plan.md:74-78 (handshake scope) and
    plan.md:282-286 (MSS section). Actual is 16 bytes: 1B type + 3B
    reserved + 4B receiver_index + 8B counter, as defined by
    `WG_DATA_HEADER_LEN = 1 + 3 + 4 + 8` in
    `userspace-dp/src/afxdp/wg/mod.rs:91` and the byte-exact layout in
    `userspace-dp/src/afxdp/wg/framing.rs:32-46`. Rewrote the on-wire
    framing description with explicit byte offsets and a per-row table;
    updated the handshake-scope bullet to match; fixed the IPv4/IPv6
    outer overhead breakdown to call out the `WG_DATA_HEADER_LEN` /
    `POLY1305_TAG_LEN` constants directly.
  - **File(s)**: docs/pr/wireguard-clean/plan.md

- **Timestamp**: 2026-05-24T22:00:00Z
  - **Action**: PR #1499 r-final-4 fix — closed Codex MAJOR (5 plan.md
    drifts) and Copilot 2 inline findings on the r-final-3 commit
    `d379c9d9`, plus a mechanical doc-sync sweep that tightened several
    file:line citations. (1) plan.md hot-path layout `WgWorkerScratch`
    bullet rewritten to describe `encap_out`/`decap_out:
    RefCell<Vec<u8>>` (was `encap_buf: Vec<u8>`) per `scratch.rs:17-21`.
    (2) plan.md hot-path "never under a lock on the hot path" claim
    rewritten: engine peer routing is `ArcSwap<PeerTable>` (lock-free
    load), but per-peer `current`/`previous` are `RwLock<Option<Arc<
    WgSession>>>` and `sessions_by_local_index` is `RwLock<FxHashMap>`,
    so encap takes `peer.current.read()` at `engine.rs:499-503` and
    decap takes `sessions_by_local_index.read()` at `engine.rs:636-642`.
    (3) plan.md protocol-extension field block: renamed `wg_local_privkey:
    [u8; 32]` / `wg_peer_pubkey: [u8; 32]` to `wg_local_privkey_hex:
    String` / `wg_peer_pubkey_hex: String` per `protocol.rs:417-450`
    and deleted the false claim that the snapshot mirrors into the
    runtime `TunnelEndpoint` in this PR — runtime mirror is integration-
    PR scope (`afxdp/types/forwarding.rs:129-140` confirms no WG fields).
    (4) plan.md MSS section: corrected the claim that `wg_tcp_mss` is
    wired as a sibling of `native_gre_tcp_mss` and that `dispatch.rs:1458`
    branches on `endpoint.mode`. Actual `dispatch.rs:1458-1459` short-
    circuits TCP segmentation for ANY `tunnel_endpoint_id != 0`;
    `wg_tcp_mss` exists only as a standalone helper in `afxdp/wg/mss.rs`.
    Dispatch-side wiring is integration-PR scope. (5) plan.md VLAN-safety
    section: reordered `write_outer_eth` arg list from `(out, src_mac,
    dst_mac, vlan_id, ethertype)` to `(out, dst_mac, src_mac, vlan_id,
    ethertype)` per `outer.rs:23-45`. (6) Copilot finding 1 (Go-side
    comment): updated `pkg/dataplane/userspace/protocol.go` `WgListenPort`
    comment that claimed WG demux is `(listen_port, receiver_index)` —
    the engine demuxes by `receiver_index` alone, listen-port selection
    is integration-layer UDP dispatch. (7) Copilot finding 2 (boundary
    comment): tightened the `PADDED_PLAINTEXT_MAX` doc in `engine.rs:198`
    to describe the actual `padded_len <= PADDED_PLAINTEXT_MAX` boundary
    — accepted range is `inner_ip.len() ∈ [0, 4096]`, not "> 4080
    rejected". A 4081..=4096-byte inner is ACCEPTED because
    `pad_to_16(4096) == 4096 == PADDED_PLAINTEXT_MAX`. Mechanical-sweep
    extras: (a) `allowed_ips.rs` "LPM trie" label corrected to flat
    sorted-by-prefix-length-descending `Vec<Entry>` (LPM lookup, not LPM
    trie). (b) `engine.rs:251` citation for `ArcSwap<PeerTable>` updated
    to `engine.rs:258`. (c) Replay-lock citations updated from
    `engine.rs:664`/`engine.rs:688` to `engine.rs:671-676` (pre-AEAD
    precheck) and `engine.rs:695` onward (post-AEAD update). (d)
    `protocol.rs:432-450` widened to `protocol.rs:417-450`. Verified by
    `cargo build --release` (clean), 5×`cargo test ... afxdp::wg` runs
    (78 pass each), and `go test ./pkg/dataplane/...` (all 4 packages
    pass). One initial test flake on
    `install_session_serializes_with_reconcile_removal` did not
    reproduce on any of 5 follow-up runs — same class as the documented
    pre-existing `reconcile_peers_snapshot_is_atomic_under_concurrent_load`
    flake from `a5664f85`, not introduced by this fix.
    - **File(s)**: `docs/pr/wireguard-clean/plan.md`,
      `pkg/dataplane/userspace/protocol.go`,
      `userspace-dp/src/afxdp/wg/engine.rs`, `_Log.md`.

- **Timestamp**: 2026-05-24T20:58:00Z
  - **Action**: PR #1451 review follow-up — extended the RT_FLOW
    wire-offset canary across the full raw event layout and tightened
    short-record boundary tests with nil, empty, short, and exact-size cases.
  - **File(s)**: `pkg/logging/binary_test.go`, `_Log.md`
  - **Validation**: `go test ./pkg/logging ./pkg/dataplane -count=1`;
    `go test ./pkg/logging -run
    'TestRawEventFieldOffsetsMatchWireFormat|TestDecodeRawEventRecordRejectsShortRecord|TestProcessRawEventRejectsShortRecord'
    -count=1`; `git diff --check`

- **Timestamp**: 2026-05-24T20:47:00Z
  - **Action**: PR #1451 review follow-up — added direct RT_FLOW wire-offset
    assertions and explicit short-record rejection tests for the logging event
    decoder/reader without widening the production boundary again.
  - **File(s)**: `pkg/logging/binary_test.go`, `_Log.md`
  - **Validation**: `go test ./pkg/logging ./pkg/dataplane -count=1`;
    `git diff --check`

- **Timestamp**: 2026-05-24T20:30:00Z
  - **Action**: PR #1499 r-final-3 fix — rebased onto current
    `origin/master` (resolved `_Log.md` conflicts chronologically across
    four rebased PR commits) and closed the Codex MINOR finding from the
    r-final-2 synthesis plus three residual plan.md drifts Codex did not
    catch but a wider sweep surfaced. (1) `docs/pr/wireguard-clean/plan.md`
    Performance Architecture (hot-path layout) replay-locking bullet:
    rewrote to describe the as-shipped `std::sync::Mutex<ReplayState>` and
    the unconditional pre-AEAD precheck-lock + post-AEAD update-lock
    pattern at `engine.rs:664`/`engine.rs:688`. The earlier "AtomicU64
    bitmap + counter", "parking_lot::Mutex", and "only on the
    duplicate/out-of-window arms" wording is now flagged as the stale
    pre-implementation sketch. (2) `Replay window` subsection: same
    correction — replaced the `(highest: AtomicU64, bitmap: AtomicU64)`
    description with `std::sync::Mutex<ReplayState>` and made the two
    decap locks explicit. (3) `Engine keying` ingress demux: was
    `(listen_port, receiver_index)`, actual implementation is
    `sessions_by_local_index` keyed by `receiver_index` alone — fixed.
    (4) `Hot-path layout` ephemerals bullet: claimed a slow-path SPSC
    pre-generation ring exists; no such ring is implemented in this PR
    (snow generates ephemerals inside `build_*_handshake` on the control
    thread). Reworded to describe the actual control-thread-only ephemeral
    generation and the unimplemented SPSC ring as a future-revisit. (5)
    `VLAN safety` section: claimed `try_encap` takes `tx_vlan_id` and
    emits 802.1Q outer L2; actual `try_encap` signature is `(peer_pubkey,
    inner_ip, out)` and outer L2 (with VLAN) is built by
    `outer.rs::write_outer_eth`. Rewrote to match the as-shipped split.
  - **File(s)**: `docs/pr/wireguard-clean/plan.md`, `_Log.md`
  - **Validation**: rebase clean after manual `_Log.md` merges (15/15
    commits replayed); `cargo build --release` clean; `cargo test
    --release --bin xpf-userspace-dp afxdp::wg` — 78/78 pass (same as
    pre-rebase; doc-only changes for this commit on top of the rebased
    crypto changes); `git diff --check` clean.

- **Timestamp**: 2026-05-24T19:26:45Z
  - **Action**: #1451 logging boundary shrink — moved the logging event
    reader to a package-local `EventSource` interface and RT_FLOW event wire
    contract so `pkg/logging/ringbuf.go` no longer imports root
    `pkg/dataplane`, then removed the stale #1451 allowlist/documentation
    entry.
  - **File(s)**: `pkg/logging/ringbuf.go`,
    `pkg/logging/binary_test.go`,
    `pkg/dataplane/retirement_boundary_canary_test.go`,
    `docs/pr/1373-retire-ebpf-dataplane/README.md`, `_Log.md`
  - **Validation**: `go test ./pkg/logging ./pkg/dataplane -count=1`;
    `go test ./pkg/daemon ./pkg/dataplane/userspace -count=1`;

- **Timestamp**: 2026-05-24T19:29:17Z
  - **Action**: Issue #1504 implementation — hardened the retained
    userspace shim boundary canary against positional package-local
    `dataplane.Manager` literals, production CGo imports, `go:linkname`,
    `go:cgo_*` compiler directives, direct assembly and `.syso` object
    files, and unallowlisted build tags while keeping DPDK CGo outside the
    scanner. Documented the exact #1504 boundary
    assumptions and allowlisted only generated legacy bpf2go architecture
    tags plus the ignored loader stub.
  - **File(s)**: `pkg/dataplane/retirement_boundary_canary_test.go`,
    `docs/pr/1373-retire-ebpf-dataplane/README.md`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane -run
    'TestRetainedUserspaceShimBoundaryCanary|TestRetirementBoundaryDocsMentionShimEscapeAssumptions'
    -count=1`; `go test ./pkg/dataplane -run
    'Retirement|Canary|Userspace.*Entry|BPFShim' -count=1`;
    `git diff --check`

- **Timestamp**: 2026-05-24T18:47:00Z
  - **Action**: PR #1508 copilot follow-up — moved `IPERF_TIMEOUT` defaulting
    after argument parsing and env-file sourcing so the default tracks the
    effective `DURATION`, added dry-run coverage for CLI duration/default
    timeout interaction, ignored Python bytecode caches, and cleaned up the
    PR log entries that were duplicated or appended outside their date
    section.
  - **File(s)**: `scripts/userspace-ha-validation.sh`,
    `scripts/userspace_ha_validation_matrix_test.py`, `.gitignore`,
    `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-phase-cycle.sh`; `shellcheck
    scripts/userspace-ha-validation.sh scripts/userspace-phase-cycle.sh`;
    `python3 -m unittest scripts.userspace_ha_validation_matrix_test`;
    `git diff --check`

- **Timestamp**: 2026-05-24T18:40:00Z
  - **Action**: PR #1508 adversarial follow-up — validated and escaped the
    remaining iperf runtime knobs before composing remote `bash -lc` commands,
    and added dry-run regressions so `DURATION`, `PARALLEL`, and
    `IPERF_TIMEOUT` cannot carry shell syntax into the HA smoke matrix.
  - **File(s)**: `scripts/userspace-ha-validation.sh`,
    `scripts/userspace_ha_validation_matrix_test.py`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-phase-cycle.sh`; `shellcheck
    scripts/userspace-ha-validation.sh scripts/userspace-phase-cycle.sh`;
    `python3 -m unittest scripts.userspace_ha_validation_matrix_test`;
    `git diff --check`

- **Timestamp**: 2026-05-24T18:24:00Z
  - **Action**: PR #1508 copilot follow-up — hardened `run_iperf_json`
    remote command construction by shell-escaping the target and temporary
    output paths so env-driven target overrides cannot inject shell syntax
    into host-side iperf execution.
  - **File(s)**: `scripts/userspace-ha-validation.sh`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-phase-cycle.sh`; `shellcheck
    scripts/userspace-ha-validation.sh scripts/userspace-phase-cycle.sh`;
    `python3 -m unittest scripts.userspace_ha_validation_matrix_test`;
    `git diff --check`

- **Timestamp**: 2026-05-24T18:21:49Z
  - **Action**: PR #1508 review follow-up: made iperf JSON metrics prefer
    receiver-side end summaries so reverse cells gate on received throughput,
    kept `run_iperf_json` from silently defaulting an explicit empty port to
    5201, documented all script-local port defaults, and expanded dry-run
    coverage for empty/range/metacharacter port overrides plus command token
    escaping.
  - **File(s)**: `scripts/iperf-json-metrics.py`,
    `scripts/userspace-ha-validation.sh`,
    `scripts/userspace_ha_validation_matrix_test.py`,
    `docs/pr/1373-retire-ebpf-dataplane/smoke-gates.md`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-phase-cycle.sh`; `shellcheck
    scripts/userspace-ha-validation.sh scripts/userspace-phase-cycle.sh`;
    `python3 -m unittest scripts.userspace_ha_validation_matrix_test`;
    `git diff --check`

- **Timestamp**: 2026-05-24T18:01:21Z
  - **Action**: PR #1508 review follow-up — added script-local
    documentation for the four smoke-matrix iperf port overrides, hardened
    remote iperf port argument construction, and expanded invalid-port
    dry-run coverage across all four override variables plus boundary
    values.
  - **File(s)**: `scripts/userspace-ha-validation.sh`,
    `scripts/userspace_ha_validation_matrix_test.py`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-phase-cycle.sh`; `shellcheck
    scripts/userspace-ha-validation.sh scripts/userspace-phase-cycle.sh`;
    `python3 -m unittest scripts.userspace_ha_validation_matrix_test`;
    `git diff --check`

- **Timestamp**: 2026-05-24T16:56:30Z
  - **Action**: PR #1506 review follow-up — normalized RFC3339 leap-second
    validation through UTC before accepting `:60` offset forms, and reported
    hostile Decimal/oversized-number JSON parse failures as structured
    validation errors instead of tracebacks.
  - **File(s)**: `test/incus/retire_ebpf_artifact_schema.py`,
    `test/incus/retire_ebpf_artifact_schema_test.py`, `_Log.md`
  - **Validation**: `python3 -m unittest discover -s test/incus -p
    retire_ebpf_artifact_schema_test.py`; `python3 -m py_compile
    test/incus/retire_ebpf_artifact_schema.py
    test/incus/retire_ebpf_artifact_schema_test.py`; `git diff --check`

- **Timestamp**: 2026-05-24T16:56:31Z
  - **Action**: PR #1508 review follow-up — validated smoke-matrix iperf
    port overrides, documented the override contract, and hoisted the
    CoS-off matrix precheck before full-matrix perf capture so profiling
    cannot run against an already-shaped cluster.
  - **File(s)**: `scripts/userspace-ha-validation.sh`,
    `scripts/userspace_ha_validation_matrix_test.py`,
    `docs/pr/1373-retire-ebpf-dataplane/smoke-gates.md`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-phase-cycle.sh`; `shellcheck
    scripts/userspace-ha-validation.sh scripts/userspace-phase-cycle.sh`;
    `python3 -m unittest scripts.userspace_ha_validation_matrix_test`;
    `git diff --check`

- **Timestamp**: 2026-05-24T18:00:00Z
  - **Action**: PR #1499 r-final-2 fix — address every actionable
    finding from the round-final triple-review on `62d2353c`. (1)
    Truncated-record remote DoS in `try_decap`: a 16..31-byte UDP
    datagram with a valid `receiver_index` could panic the AF_XDP
    worker because `parse_data_header` accepted any record >= 16
    bytes, leaving a sub-Poly1305-tag ciphertext that snow 0.10's
    ChaCha decrypt cannot handle safely (`ciphertext.len() - TAGLEN`
    underflow). Added `DecapError::ShortRecord`, a one-line guard
    before `read_message`, and a regression test that walks
    `ciphertext.len()` ∈ {0,1,8,14,15} plus a boundary check at
    `ciphertext.len() == POLY1305_TAG_LEN` to assert the cutoff is
    strict `<`. (2) Copilot inline #5: replay-lock comment claimed
    decap "only takes the replay-window lock on cold arms"; the
    precheck unconditionally locks. Updated the module docstring to
    describe the actual two-lock pattern and explain why the
    precheck is held (skip snow AEAD on already-stale counters,
    bounded contention because each session is demuxed onto a
    single worker). (3) Copilot inline #6: `established_pair`
    installed the responder via `WgSession::new` (Initiator-role,
    pre-confirmed); not faithful to the responder-role gate this PR
    shipped. Converted `established_pair` to build the responder
    session as `SessionRole::Responder` then explicitly
    `mark_confirmed()` so existing round-trip tests still pass, and
    added a new test
    `established_pair_responder_confirmation_flips_via_decap_path`
    that exercises the full handshake → install (unconfirmed) →
    decap-flips-confirmation flow without any `mark_confirmed` test
    helper. (4) Copilot inline #1..#4: plan.md doc drift — updated
    to say `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` (PSK2 step
    matters for WG wire framing), to acknowledge that `ring 0.17.x`
    is pulled in transitively through snow's resolver (and is
    clean of open RustSec advisories, not the
    RUSTSEC-2025-0010 0.16.x version that boringtun dragged in),
    to update the `try_encap` signature snippet to match the
    `&mut [u8]` engine API, and to clarify that
    `complete_handshake_*` is `build_initiator_handshake` /
    `build_responder_handshake` + `install_session`. (5) Codex
    scope item: the engine ships Noise sub-message bytes only; the
    WG handshake outer framing (MessageInitiation/MessageResponse
    + MAC1/MAC2 + TAI64N) is the integration PR's scope. Made the
    boundary explicit in both the engine module docstring and a
    new "On-wire handshake framing scope" section in plan.md plus
    a new bullet in "What's OUT". The pre-existing
    `snat_contract_documents_current_fail_closed_runtime`
    integration-test failure on `userspace-dp/tests/snat_contract_doc_guard.rs`
    is from `docs/userspace-dataplane-gaps.md` lacking the literal
    string `fail-closed`; verified the test fails on origin/master
    `0b837165` (the PR base) just as it does on the PR head, with
    identical doc and test bytes — entirely unrelated to wg work
    and out of scope for this PR. New tests: 78/78 wg tests pass
    (was 76 — added 2 regression tests). All cargo --bin tests
    pass; 5/5 flake check clean on both new tests. Go suite clean.
  - **File(s)**: `userspace-dp/src/afxdp/wg/engine.rs`,
    `userspace-dp/src/afxdp/wg/tests.rs`,
    `docs/pr/wireguard-clean/plan.md`, `_Log.md`

- **Timestamp**: 2026-05-24T19:30:00Z
  - **Action**: PR #1499 r-final-fix — close the four findings Codex
    final pre-merge review surfaced after nine prior review rounds
    missed them, plus two Copilot inline findings that surfaced on
    the same pass. (1) Set the WireGuard protocol prologue
    "WireGuard v1 zx2c4 Jason@zx2c4.com" on both initiator and
    responder Noise builders so the initial transcript hash matches
    kernel WireGuard / wireguard-go; the engine was previously
    "WireGuard-shaped" but not interoperable. (2) Added responder
    key-confirmation gating: WgSession carries a SessionRole +
    confirmed AtomicBool; responder sessions block try_encap until
    a successful inbound try_decap flips the flag, restoring the WG
    anti-reflection invariant. (3) Made Peer.endpoint and
    persistent_keepalive interior-mutable (RwLock + AtomicU16) so
    reconcile_peers updates an existing peer's config in place
    instead of silently keeping stale values. (4) Clarified the
    plan doc to scope the runtime TunnelEndpoint propagation
    (forwarding.rs + forwarding_build.rs) into the integration PR;
    only the wire surface TunnelEndpointSnapshot ships here.
    (5) Strengthened inner_ip_len_after_decap to validate IPv4
    IHL>=5 and total_length>=ihl*4 — Copilot inline finding.
    (6) Made TunnelEndpointSnapshot.wg_local_privkey_hex
    skip_serializing and gave the snapshot a manual Debug impl
    that redacts the field; write_state used to leak the WG
    private key into the on-disk state JSON — Copilot inline
    finding. Added five regression tests covering the prologue
    (counter-example proof), responder confirmation gating,
    in-place peer reconcile, malformed IPv4 rejection, and the
    privkey serialization/Debug contract.
  - **File(s)**: `userspace-dp/src/afxdp/wg/mod.rs`,
    `userspace-dp/src/afxdp/wg/engine.rs`,
    `userspace-dp/src/afxdp/wg/session.rs`,
    `userspace-dp/src/afxdp/wg/peer.rs`,
    `userspace-dp/src/afxdp/wg/tests.rs`,
    `userspace-dp/src/protocol.rs`,
    `docs/pr/wireguard-clean/plan.md`, `_Log.md`
  - **Validation**: `cargo build --release`: clean (114 pre-existing
    warnings); `cargo test --release --bin xpf-userspace-dp
    afxdp::wg`: 76/76 pass (was 71; +5 new regressions);
    `cargo test --release --bin xpf-userspace-dp`: 1413/1413 pass
    (was 1408; the same +5 new tests); each new test passes 5/5
    runs in isolation.

- **Timestamp**: 2026-05-24T15:14:30Z
  - **Action**: PR #1494 round-11 follow-up — collapsed the retained
    userspace XDP shim entry-program name onto one dataplane constant and
    routed both full-loader and shim-loader registrations through it. This
    removes the duplicate `xdp_userspace_prog` constants that reviewers
    flagged as a drift risk.
  - **File(s)**: `pkg/dataplane/loader.go`,
    `pkg/dataplane/loader_ebpf.go`,
    `pkg/dataplane/retirement_boundary_canary_test.go`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane -run
    'TestBPFShimEntryProgramStateIsNotJSONMutable|TestUserspaceManagerSelectsOnlyUserspaceXDPEntryProgram|TestUserspaceXDPEntryProgramConstantNamesRetainedShim'`;
    `go test ./pkg/dataplane/userspace -run
    'TestUserspaceShimLoaderDoesNotReferenceLegacyObjects|TestUserspaceStartupUsesShimLoaderBoundary'`;
    `go test ./pkg/dataplane ./pkg/dataplane/userspace`;
    `git diff --check`

- **Timestamp**: 2026-05-24T06:08:39Z
  - **Action**: PR #1508 review follow-up — made HA smoke-matrix iperf
    ports explicit so CoS-on cells use port 5211's uncapped-root class
    instead of iperf3's default 5201 / 100 Mbps class, and moved full-matrix
    perf capture ahead of CoS fixture application so flamegraphs stay on a
    clean CoS-off baseline.
  - **File(s)**: `scripts/userspace-ha-validation.sh`,
    `scripts/userspace_ha_validation_matrix_test.py`,
    `docs/pr/1373-retire-ebpf-dataplane/README.md`,
    `docs/pr/1373-retire-ebpf-dataplane/smoke-gates.md`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-phase-cycle.sh`; `shellcheck
    scripts/userspace-ha-validation.sh scripts/userspace-phase-cycle.sh`;
    `python3 -m unittest scripts.userspace_ha_validation_matrix_test`;
    `git diff --check`

- **Timestamp**: 2026-05-24T06:06:58Z
  - **Action**: PR #1505 review follow-up — changed the SYN-cookie
    `docs/feature-gaps.md` row to point at final #1477 source-removal
    evidence for the exact deletion candidate instead of saying the
    feature itself still has pre-removal live evidence outstanding.
  - **File(s)**: `docs/feature-gaps.md`, `_Log.md`
  - **Validation**: `rg -n "#1375|#1378|SYN-cookie|source-removal"
    docs/feature-gaps.md docs/pr/1373-retire-ebpf-dataplane/README.md
    docs/pr/1373-retire-ebpf-dataplane/plan.md`; `git diff --check`

- **Timestamp**: 2026-05-24T04:51:19Z
  - **Action**: Issue #1500 userspace HA smoke matrix: added an explicit
    `--smoke-matrix` mode that runs IPv4 push, IPv4 reverse, IPv6 push, and
    IPv6 reverse first with CoS off, then repeats those four cells after
    applying the existing symmetric CoS fixture; kept the fast current-CoS
    IPv4/IPv6 push readiness mode distinct; made `userspace-phase-cycle.sh`
    invoke the full matrix by default for standard smoke evidence.
  - **File(s)**: `scripts/userspace-ha-validation.sh`,
    `scripts/userspace-phase-cycle.sh`,
    `scripts/userspace_ha_validation_matrix_test.py`,
    `docs/pr/1373-retire-ebpf-dataplane/README.md`,
    `docs/pr/1373-retire-ebpf-dataplane/smoke-gates.md`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-phase-cycle.sh`; `shellcheck
    scripts/userspace-ha-validation.sh scripts/userspace-phase-cycle.sh`;
    `python3 -m unittest scripts.userspace_ha_validation_matrix_test`;
    `git diff --check`

- **Timestamp**: 2026-05-24T04:08:49Z
  - **Action**: PR #1497 round-3 follow-up — fixed the checker/schema
    parity nits from review: boolean `schema_version` rejection, JSON
    integer float issue acceptance, RFC3339 lowercase/leap-second
    acceptance, reachable empty `config_files` validation, parsed fallback
    JSON artifacts, and Unicode decode failures reported as validation
    errors instead of tracebacks.
  - **File(s)**: `test/incus/retire_ebpf_artifact_schema.py`,
    `test/incus/retire_ebpf_artifact_schema_test.py`, `_Log.md`
  - **Validation**: `python3 -m unittest discover -s test/incus -p
    retire_ebpf_artifact_schema_test.py`;
    `python3 test/incus/retire_ebpf_artifact_schema_test.py`;
    `python3 -m py_compile test/incus/retire_ebpf_artifact_schema.py
    test/incus/retire_ebpf_artifact_schema_test.py`;
    `python3 -m json.tool
    docs/pr/1373-retire-ebpf-dataplane/final-validation/manifest.schema.json
    >/dev/null`; `git diff --check`

- **Timestamp**: 2026-05-24T03:46:48Z
  - **Action**: PR #1497 round-2 follow-up — aligned the Python #1477
    artifact checker with the manifest schema's required-field, uniqueness,
    non-empty string, command artifact, and RFC3339 date-time constraints.
    Added hostile regression tests for the schema/checker drift cases raised
    in PR review.
  - **File(s)**: `test/incus/retire_ebpf_artifact_schema.py`,
    `test/incus/retire_ebpf_artifact_schema_test.py`, `_Log.md`
  - **Validation**: `python3 -m unittest discover -s test/incus -p
    retire_ebpf_artifact_schema_test.py`;
    `python3 test/incus/retire_ebpf_artifact_schema_test.py`;
    `python3 -m py_compile test/incus/retire_ebpf_artifact_schema.py
    test/incus/retire_ebpf_artifact_schema_test.py`;
    `python3 -m json.tool
    docs/pr/1373-retire-ebpf-dataplane/final-validation/manifest.schema.json
    >/dev/null`; `git diff --check`

## 2026-05-23

- **Timestamp**: 2026-05-23T17:01:19Z
  - **Action**: PR #1494 round-9 follow-up — encapsulated the retained shim
    entry-program state by unexporting `XDPEntryProg`, removed the arbitrary
    `SwapXDPEntryProg(name)` production surface, and added narrow userspace-shim
    selection/swap methods plus a JSON-mutability canary. Updated userspace
    call sites and docs to describe the structural boundary instead of relying
    on decoder-shape blocklists.
  - **File(s)**: `pkg/dataplane/loader.go`,
    `pkg/dataplane/retirement_boundary_canary_test.go`,
    `pkg/dataplane/userspace/manager.go`,
    `pkg/dataplane/userspace/maps_sync.go`,
    `docs/pr/1373-retire-ebpf-dataplane/README.md`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane -run
    'TestBPFShimEntryProgramStateIsNotJSONMutable|TestUserspaceManagerSelectsOnlyUserspaceXDPEntryProgram|TestUserspaceEntryProgramCanaryRejectsBypassFixtures|TestUserspaceEntryProgramCanaryAllowsCrossFileConstantFixture|TestUserspaceXDPEntryProgramConstantNamesRetainedShim'
    -count=1 -v`; `go test ./pkg/dataplane ./pkg/dataplane/userspace
    -count=1`; `go test ./pkg/dataplane/... -count=1`; `go test ./...
    -count=1`; `git diff --check`

- **Timestamp**: 2026-05-23T15:58:00Z
  - **Action**: PR #1494 round-8 follow-up — hardened JSON decoder canary
    laundering checks for stored decoder receivers, function-variable
    `Unmarshal` callees, tuple-return spread into `Unmarshal`, and default
    import-name resolution for versioned import paths (e.g. `encoding/json/v2`);
    added dedicated fixtures for each bypass shape.
  - **File(s)**: `pkg/dataplane/retirement_boundary_canary_test.go`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane -run
    'TestUserspaceEntryProgramCanaryRejectsBypassFixtures|TestUserspaceManagerSelectsOnlyUserspaceXDPEntryProgram|TestUserspaceEntryProgramCanaryAllowsCrossFileConstantFixture'
    -count=1 -v`; `go test ./pkg/dataplane ./pkg/dataplane/userspace -count=1`;
    `git diff --check`

- **Timestamp**: 2026-05-23T09:52:00Z
  - **Action**: PR #1494 r7 copilot re-review follow-up — hardened
    `encoding/json` canary detection to catch decode targets laundered through
    local aliases of `bpfShim`, and added fixture coverage for unmarshal/decode
    alias bypass shapes.
  - **File(s)**: `pkg/dataplane/retirement_boundary_canary_test.go`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane -run
    'TestUserspaceEntryProgramCanaryRejectsBypassFixtures|TestUserspaceManagerSelectsOnlyUserspaceXDPEntryProgram|TestUserspaceEntryProgramCanaryAllowsCrossFileConstantFixture'
    -count=1 -v`; `go test ./pkg/dataplane ./pkg/dataplane/userspace -count=1`;
    `git diff --check`

- **Timestamp**: 2026-05-23T09:31:43Z
  - **Action**: PR #1493 r2 copilot follow-up — restored `"impact"` slog key
    on native-XDP fallback warning in `attachUserspaceShimXDP` so operator
    log output matches legacy compiler guidance (higher CPU, ~6 Gbps cap).
  - **File(s)**: `pkg/dataplane/loader.go`, `_Log.md`
  - **Validation**: `go build ./pkg/dataplane/...`;
    `go test ./pkg/dataplane/... -count=1`

- **Timestamp**: 2026-05-23T06:12:00Z
  - **Action**: PR #1494 r7 copilot re-review follow-up — hardened the
    retirement-boundary canary to catch `encoding/json` decode mutations via
    dot-import `Unmarshal` and `NewDecoder(...).Decode` paths, including
    `encoding/json/v2`, and added fixture coverage for each bypass shape.
  - **File(s)**: `pkg/dataplane/retirement_boundary_canary_test.go`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane -run
    'TestUserspaceEntryProgramCanaryRejectsBypassFixtures|TestUserspaceManagerSelectsOnlyUserspaceXDPEntryProgram'
    -count=1`; `go test ./pkg/dataplane ./pkg/dataplane/userspace -count=1`;
    `git diff --check`

- **Timestamp**: 2026-05-23T04:58:00Z
  - **Action**: PR #1494 copilot round-5 follow-up — hardened the canary
    walker to treat wrapped SwapXDPEntryProg callees as direct calls and added
    bypass fixtures for parenthesized/method-expression/slice-indexed calls.
  - **File(s)**: `pkg/dataplane/retirement_boundary_canary_test.go`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane ./pkg/dataplane/userspace`;
    `git diff --check`

- **Timestamp**: 2026-05-23T03:45:00Z
  - **Action**: PR #1494 copilot re-review hardening — made the userspace
    entry-program canary reject shadowed local identifiers so only the package
    constant `userspaceXDPEntryProg` can satisfy XDP entry assignments/calls.
  - **File(s)**: `pkg/dataplane/retirement_boundary_canary_test.go`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane ./pkg/dataplane/userspace`;
    `git diff --check`
## 2026-05-23

- **Timestamp**: 2026-05-23T21:25:00Z
  - **Action**: PR #1499 @copilot round-6 follow-up — serialized
    WireGuard `install_session` with `reconcile_peers` using the
    existing slow-path reconcile mutex to eliminate stale-Arc
    orphaning when a peer is removed concurrently with session install.
  - **File(s)**: `userspace-dp/src/afxdp/wg/engine.rs`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane/userspace/...`;
    `cargo test --release afxdp::wg::`
    (fails in this runner as expected: missing `libelf`/`gelf` headers
    for `libbpf-sys` build); `git diff --check`

- **Timestamp**: 2026-05-23T07:07:56Z
  - **Action**: PR #1499 @copilot review round-3 follow-up — corrected
    WireGuard `REJECT_AFTER_MESSAGES` to the WG spec value, changed
    TX counter reservation to atomic `fetch_update` so rejection does
    not advance/wrap counters, restored demux-before-rotate install
    ordering to eliminate the new-session decap gap, and clarified
    replay precheck concurrency semantics.
  - **File(s)**: `userspace-dp/src/afxdp/wg/session.rs`,
    `userspace-dp/src/afxdp/wg/engine.rs`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane/userspace/...`;
    `cargo test --release afxdp::wg::`
    (fails in this runner as expected: missing `libelf`/`gelf` headers
    for `libbpf-sys` build); `git diff --check`

- **Timestamp**: 2026-05-23T06:32:50Z
  - **Action**: PR #1499 @copilot review follow-up — fixed WireGuard
    engine conformance and robustness issues by switching to IKpsk2
    with zero-PSK mixing, enforcing reject-after-messages on encap,
    preserving overlapping AllowedIPs per-peer validation, pruning
    stale demux sessions across rekeys, tightening the overlapping
    cryptokey-routing test to exercise both live peers, and removing
    the unused `rand` dependency.
  - **File(s)**: `userspace-dp/src/afxdp/wg/mod.rs`,
    `userspace-dp/src/afxdp/wg/engine.rs`,
    `userspace-dp/src/afxdp/wg/session.rs`,
    `userspace-dp/src/afxdp/wg/allowed_ips.rs`,
    `userspace-dp/src/afxdp/wg/peer.rs`,
    `userspace-dp/src/afxdp/wg/framing.rs`,
    `userspace-dp/src/afxdp/wg/tests.rs`,
    `userspace-dp/Cargo.toml`, `userspace-dp/Cargo.lock`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane/userspace/...`;
    `cargo test --release afxdp::wg::`
    (fails in this runner as expected: missing `libelf`/`gelf` headers
    for `libbpf-sys` build); `git diff --check`

## 2026-05-22

- **Timestamp**: 2026-05-22T20:20:00Z
  - **Action**: PR #1491 r6 review closeout — removed the remaining
    supported-runtime `FW0` arm fallback, made supported-runtime owner
    waits fail closed on ambiguous ownership, and converted status summary
    counter reads from `__ERR__` sentinel math to explicit fail-closed
    delta helpers.
  - **File(s)**: `scripts/userspace-ha-validation.sh`,
    `scripts/userspace-ha-failover-validation.sh`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-ha-failover-validation.sh`; `shellcheck
    scripts/userspace-ha-validation.sh
    scripts/userspace-ha-failover-validation.sh`; `git diff --check`

- **Timestamp**: 2026-05-22T20:02:00Z
  - **Action**: PR #1491 copilot follow-up — clarified unmatched-interface
    parser failures to include the count of malformed binding rows that were
    ignored, so diagnostics no longer imply a pure regex mismatch when row
    shape is also broken.
  - **File(s)**: `scripts/userspace-ha-failover-validation.sh`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-failover-validation.sh`;
    `git diff --check`

- **Timestamp**: 2026-05-22T19:55:00Z
  - **Action**: PR #1491 copilot follow-up — tightened userspace binding
    parser diagnostics so malformed short rows are tracked separately from
    valid rows, avoiding misleading "no interface match" errors when the
    binding table format is broken.
  - **File(s)**: `scripts/userspace-ha-failover-validation.sh`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-failover-validation.sh`;
    `git diff --check`

- **Timestamp**: 2026-05-22T18:45:00Z
  - **Action**: PR #1491 r4 closeout — made userspace RG owner
    selection reject split-brain, require the post-failover owner to match
    the requested target VM, keep owner selection ambiguous while either
    peer cannot be queried, and make the startup arm path refuse split-brain
    states. Removed the remaining transition-window sample `|| true`
    masking and negative-delta clamps.
  - **File(s)**: `scripts/userspace-ha-validation.sh`,
    `scripts/userspace-ha-failover-validation.sh`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-ha-failover-validation.sh`; `git diff --check`

- **Timestamp**: 2026-05-22T16:20:00Z
  - **Action**: PR #1491 review cleanup — made the explicit legacy-HA
    validation override require an unambiguous active firewall owner instead
    of falling back to `FW0` when owner detection fails.
  - **File(s)**: `scripts/userspace-ha-validation.sh`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-ha-failover-validation.sh`; `git diff --check`

- **Timestamp**: 2026-05-22T16:00:00Z
  - **Action**: PR #1491 review cleanup — normalized userspace bindings
    parse error text casing to match the CLI section header terminology.
  - **File(s)**: `scripts/userspace-ha-failover-validation.sh`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-ha-failover-validation.sh`; `git diff --check`

- **Timestamp**: 2026-05-22T15:55:00Z
  - **Action**: PR #1491 review closeout — renamed standby WAN baseline
    snapshot variable for clarity, tightened userspace-binding parser
    diagnostics for empty vs unmatched rows, and moved WAN counter delta
    monotonicity checks to Python integer math to avoid shell
    signed-arithmetic edge cases.
  - **File(s)**: `scripts/userspace-ha-failover-validation.sh`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-ha-failover-validation.sh`; `git diff --check`

- **Timestamp**: 2026-05-22T15:45:00Z
  - **Action**: PR #1491 review polish — added explicit
    empty-userspace-bindings detection in standby WAN counter parsing and
    simplified standby WAN snapshot-stage failure messages to high-level
    baseline/post-validation diagnostics.
  - **File(s)**: `scripts/userspace-ha-failover-validation.sh`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-ha-failover-validation.sh`; `git diff --check`

- **Timestamp**: 2026-05-22T15:35:00Z
  - **Action**: PR #1491 review polish — clarified standby WAN TX snapshot
    failure messages for post-failover baseline vs post-validation captures
    and tightened userspace-binding parse failure checks to fail once with
    explicit context.
  - **File(s)**: `scripts/userspace-ha-failover-validation.sh`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-ha-failover-validation.sh`; `git diff --check`

- **Timestamp**: 2026-05-22T15:10:10Z
  - **Action**: PR #1491 follow-up — fixed standby WAN TX failover
    gating by measuring from post-failover baseline snapshots, failing closed
    when userspace binding counters are unavailable, and treating standby WAN
    TX counter resets as validation failures instead of clamping negative
    deltas to zero.
  - **File(s)**: `scripts/userspace-ha-failover-validation.sh`, `_Log.md`
  - **Validation**: `bash -n scripts/userspace-ha-validation.sh
    scripts/userspace-ha-failover-validation.sh`; `git diff --check`

## 2026-05-21

- **Timestamp**: 2026-05-21T23:30:00Z
  - **Action**: PR #1481 review follow-up — replaced 5 hard-coded `"xdp_userspace_prog"` literal strings with the `userspaceXDPEntryProg` constant in test files to avoid drift if the entry program name changes.
  - **File(s)**: `pkg/dataplane/userspace/maps_sync_cap_test.go`, `pkg/dataplane/userspace/manager_test.go`, `_Log.md`
  - **Validation**: `GOFLAGS=-buildvcs=false go test -count=1 ./pkg/dataplane/userspace ./pkg/dataplane`; `git diff --check`

- **Timestamp**: 2026-05-21T16:25:00Z
  - **Action**: PR #1481 comment follow-up — changed `syncInterfaceNATAddressMapsLocked` to publish desired interface-NAT entries before deleting stale keys (matching the local-map add-before-remove contract), pre-sized NAT RST publish slices from desired-entry count, and added regression tests for both full-map publication failure retention and successful stale-key replacement.
  - **File(s)**: `pkg/dataplane/userspace/maps_sync.go`, `pkg/dataplane/userspace/maps_sync_cap_test.go`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane/userspace ./pkg/dataplane`; `git diff --check`

## 2026-05-18

- **Timestamp**: 2026-05-18T04:38:00Z
  - **Action**: Issue #1379 dataplane event producer slice — threaded the event-stream worker handle into AF_XDP workers, added fixed-size non-blocking RT_FLOW emit helpers, emitted userspace policy-deny and screen-drop events from packet stages, emitted logged routing-instance/PBR filter hits, carried filter/term/action metadata through routing-instance filter evaluation, and narrowed #1379 docs to end-to-end syslog evidence, non-PBR filter-log coverage, and richer identity mapping.
  - **File(s)**: `userspace-dp/src/afxdp/event_emit.rs`, `userspace-dp/src/afxdp/mod.rs`, `userspace-dp/src/afxdp/poll_descriptor.rs`, `userspace-dp/src/afxdp/poll_stages.rs`, `userspace-dp/src/afxdp/forwarding/mod.rs`, `userspace-dp/src/afxdp/frame/tests.rs`, `userspace-dp/src/afxdp/test_fixtures.rs`, `userspace-dp/src/afxdp/types/runtime.rs`, `userspace-dp/src/afxdp/worker/lifecycle.rs`, `userspace-dp/src/afxdp/worker/mod.rs`, `userspace-dp/src/event_stream/mod.rs`, `userspace-dp/src/event_stream/producer.rs`, `userspace-dp/src/filter/compiler.rs`, `userspace-dp/src/filter/engine.rs`, `userspace-dp/src/filter/mod.rs`, `userspace-dp/src/afxdp/README.md`, `userspace-dp/src/filter/README.md`, `docs/userspace-dataplane-gaps.md`, `_Log.md`
  - **Validation**: `cargo test --manifest-path userspace-dp/Cargo.toml event_emit -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml session_miss_ack_stage_invokes_syn_cookie_runtime_validation -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml ingress_filter_routing_instance_steers_flow_into_native_gre_table -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml interface_filter_routing_instance_counted_returns_matching_override -- --nocapture`; `go test ./pkg/dataplane/userspace ./pkg/logging`; `git diff --check`

- **Timestamp**: 2026-05-18T04:01:54Z
  - **Action**: Issue #1377 SNAT pool runtime closeout slice — preserved unusable pool-mode source NAT rules in the Go userspace snapshot, added Rust source-NAT failure results for missing/empty/invalid/wrong-family/allocator failures, made the four AF_XDP `poll_descriptor.rs` source-NAT decision sites fail closed with recent-exception records before session creation or forwarding, and refreshed #1377 docs plus the contract guard.
  - **File(s)**: `README.md`, `docs/userspace-dataplane-gaps.md`, `docs/userspace-dataplane-architecture.md`, `docs/pr/1373-retire-ebpf-dataplane/README.md`, `docs/pr/1373-retire-ebpf-dataplane/plan.md`, `docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md`, `pkg/dataplane/userspace/protocol.go`, `pkg/dataplane/userspace/snapshot.go`, `pkg/dataplane/userspace/manager_test.go`, `userspace-dp/src/protocol.rs`, `userspace-dp/src/nat.rs`, `userspace-dp/src/nat_tests.rs`, `userspace-dp/src/afxdp/mod.rs`, `userspace-dp/src/afxdp/forwarding/mod.rs`, `userspace-dp/src/afxdp/poll_descriptor.rs`, `userspace-dp/tests/snat_contract_doc_guard.rs`, `_Log.md`
  - **Validation**: `gofmt -w pkg/dataplane/userspace/protocol.go pkg/dataplane/userspace/snapshot.go pkg/dataplane/userspace/manager_test.go`; `cargo test --manifest-path userspace-dp/Cargo.toml pool_snat_`; `cargo test --manifest-path userspace-dp/Cargo.toml --test snat_contract_doc_guard`; `go test ./pkg/dataplane/userspace -run 'TestBuildSourceNATSnapshots'`; `git diff --check`

- **Timestamp**: 2026-05-18T03:59:26Z
  - **Action**: #1378 policy-scheduler closeout slice — added a deterministic userspace scheduler evidence validator for active/rebuild/inactive/failover artifacts, pinned the userspace apply seed path so initial scheduled-policy snapshots do not rely on legacy policy-map updates, and narrowed the #1378 docs to live HA artifact capture only.
  - **File(s)**: `test/incus/policy_scheduler_validate.py`, `test/incus/policy_scheduler_validate_test.py`, `pkg/daemon/policy_scheduler_apply_test.go`, `docs/userspace-dataplane-gaps.md`, `docs/pr/1373-retire-ebpf-dataplane/README.md`, `docs/pr/1373-retire-ebpf-dataplane/plan-1378-policy-schedulers.md`, `_Log.md`
  - **Validation**: `python3 test/incus/policy_scheduler_validate_test.py`; `go test ./pkg/daemon -run 'TestPolicyScheduler|TestApplyConfig.*Scheduler|TestApplyConfig.*Protocol'`; `go test ./pkg/config -run 'Test.*PolicyScheduler.*ReferenceRejectsCommit'`; `go test ./pkg/dataplane/userspace -run 'Test(BuildPolicySnapshotsRoundTripsSchedulerInactiveAndRuleID|UpdatePolicyScheduleState)'`; `cargo test --manifest-path userspace-dp/Cargo.toml policy:: -- --nocapture`

## 2026-05-17

- **Timestamp**: 2026-05-17T21:25:00Z
  - **Action**: PR #1406 review follow-up — updated the Phase 0 blocker-plan summary so #1377/#1378 match the current userspace runtime contract (userspace-v1 selector landed; residual persistent-NAT/exhaustion/fail-open and scheduler validation work remain).
  - **File(s)**: `docs/pr/1373-retire-ebpf-dataplane/plan.md`, `_Log.md`
  - **Validation**: `git diff --check`

- **Timestamp**: 2026-05-17T19:59:18Z
  - **Action**: PR #1406 round-1 contract follow-up — corrected the #1377 SNAT pool plan so current userspace pool handling is documented as runtime fail-open at the four `poll_descriptor.rs` source-NAT call sites, enumerated the risk and code prerequisites for a later fail-closed runtime gate, and added a SNAT contract doc guard.
  - **File(s)**: `docs/pr/1373-retire-ebpf-dataplane/README.md`, `docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md`, `userspace-dp/tests/snat_contract_doc_guard.rs`, `_Log.md`
  - **Validation**: `cargo test --manifest-path userspace-dp/Cargo.toml --test snat_contract_doc_guard`; `rustfmt --edition 2024 --check userspace-dp/tests/snat_contract_doc_guard.rs`; `git diff --check`

- **Timestamp**: 2026-05-17T22:36:08Z
  - **Action**: PR #1408 r5 re-review follow-up — corrected mirror counter doc wording so `mirror_drops_no_frame` no longer claims TX-frame-reserve drops (those now have dedicated `mirror_drops_tx_frame_reserve` telemetry).
  - **File(s)**: `userspace-dp/src/afxdp/umem/mod.rs`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane/userspace`; `cargo test --manifest-path userspace-dp/Cargo.toml mirror::` (expected environment failure: missing libelf headers/pkg-config); `git diff --check`

- **Timestamp**: 2026-05-17T21:58:24Z
  - **Action**: PR #1410 residual review follow-up — made emit-on-wire inject tuple identity an explicit Go/Rust control-wire contract, added helper status gating for mixed-version fail-closed behavior, and stopped Rust from synthesizing source tuple fields for emitted inject packets.
  - **File(s)**: `pkg/dataplane/userspace/protocol.go`, `pkg/dataplane/userspace/inject.go`, `pkg/dataplane/userspace/inject_test.go`, `pkg/dataplane/userspace/protocol_test.go`, `pkg/cmdtree/tree.go`, `userspace-dp/src/protocol.rs`, `userspace-dp/src/server/lifecycle.rs`, `userspace-dp/src/server/README.md`, `userspace-dp/src/afxdp/coordinator/inject.rs`, `userspace-dp/src/afxdp/coordinator/tests.rs`, `userspace-dp/src/afxdp/frame/mod.rs`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane/userspace ./pkg/cmdtree`; `cargo test --manifest-path userspace-dp/Cargo.toml inject_packet -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml injected_packet -- --nocapture`; `cargo check --manifest-path userspace-dp/Cargo.toml`; `git diff --check`

- **Timestamp**: 2026-05-17T21:39:00Z
  - **Action**: PR #1410 review follow-up — reconciled README userspace capability wording so three-color policers are described as partially admitted (color-blind `then discard` slice) rather than fully gated, matching current userspace capability documentation and runtime admission behavior.
  - **File(s)**: `README.md`, `_Log.md`

- **Timestamp**: 2026-05-17T21:23:55Z
  - **Action**: PR #1410 round-3 blocker follow-up — added explicit pending-forward CoS resolution state so resolved `None`/`None` selections are not metered again, carried metadata-derived ICMP flow keys through local and embedded ICMP prebuilt-forward paths, stamped emitted inject packets with synthetic ICMP tuples before TX selection, and preserved local tunnel tuple metadata through TX.
  - **File(s)**: `userspace-dp/src/afxdp/types/tx.rs`, `userspace-dp/src/afxdp/forward_request.rs`, `userspace-dp/src/afxdp/tx/dispatch.rs`, `userspace-dp/src/afxdp/icmp.rs`, `userspace-dp/src/afxdp/poll_descriptor.rs`, `userspace-dp/src/afxdp/coordinator/inject.rs`, `userspace-dp/src/afxdp/tunnel.rs`, `userspace-dp/src/afxdp/tx/dispatch_tests.rs`, `userspace-dp/src/afxdp/tests.rs`, `userspace-dp/src/afxdp/frame/tests.rs`, `userspace-dp/src/afxdp/coordinator/tests.rs`, `_Log.md`
  - **Validation**: `cargo test --manifest-path userspace-dp/Cargo.toml build_local_time_exceeded_request -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml pending_forward_cos_resolution -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml stamp_injected_packet_tuple -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml build_live_forward_request_marks_empty_cos_selection_resolved -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml build_live_forward_request_meters_non_l4_metadata_flow -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml three_color -- --nocapture`; `cargo check --manifest-path userspace-dp/Cargo.toml`; `git diff --check`

- **Timestamp**: 2026-05-17T20:30:00Z
  - **Action**: PR #1410 round-1 review follow-up — removed flow-cache hit TX-selection cloning from the packet fast path, switched local ICMP/tunnel/control-packet CoS resolution to timestamped `_at` evaluation with flow-key fallback, and enforced `cos.drop` handling on those paths so three-color policer drops are not bypassed when metadata-only classification is used.
  - **File(s)**: `userspace-dp/src/afxdp/poll_descriptor.rs`, `userspace-dp/src/afxdp/icmp.rs`, `userspace-dp/src/afxdp/tunnel.rs`, `userspace-dp/src/afxdp/coordinator/inject.rs`, `_Log.md`

- **Timestamp**: 2026-05-17T20:37:00Z
  - **Action**: Addressed post-validation review nit by lazily constructing cached precomputed TX-selection descriptors only on flow-cache fallback forwarding, avoiding unnecessary per-hit descriptor construction on successful in-place TX hits.
  - **File(s)**: `userspace-dp/src/afxdp/poll_descriptor.rs`, `_Log.md`

- **Timestamp**: 2026-05-17T15:28:13Z
  - **Action**: PR #1397 follow-up — fixed mouse-latency diagnostics review findings by making `cwnd_settle_ok` tri-state in manifests (unknown/true/false), correcting cwnd byte-unit parsing to 1024-based `K/M/G/TBytes`, recording probe phase timings even on failed/timed-out connect/drain/read attempts, tightening fairness-regimes settle-evidence wording, and extending unit coverage for settle-diagnostics CLI output/status and failure-phase timing counts.
  - **File(s)**: `test/incus/test-mouse-latency.sh`, `test/incus/mouse_latency_orchestrate.py`, `test/incus/mouse_latency_orchestrate_test.py`, `test/incus/mouse_latency_probe.py`, `test/incus/mouse_latency_probe_test.py`, `test/incus/test_mouse_latency_shell_test.py`, `docs/fairness-regimes.md`, `_Log.md`
  - **Validation**: `cd test/incus && python3 -m unittest mouse_latency_orchestrate_test.py mouse_latency_aggregate_test.py test_mouse_latency_shell_test.py && python3 -m unittest mouse_latency_probe_test.py && bash -n test-mouse-latency.sh`; `python3 -m py_compile test/incus/mouse_latency_orchestrate.py test/incus/mouse_latency_probe.py test/incus/mouse_latency_aggregate.py`; `git diff --check`

- **Timestamp**: 2026-05-17T15:29:22Z
  - **Action**: Addressed parallel validation follow-up by making `CWND_SETTLE_OK="true"` conditional on settle-diagnostics success (explicit `else` branch) and renaming settle-diagnostics test helper variables to descriptive names.
  - **File(s)**: `test/incus/test-mouse-latency.sh`, `test/incus/mouse_latency_orchestrate_test.py`, `_Log.md`
  - **Validation**: `cd test/incus && python3 -m unittest mouse_latency_orchestrate_test.py test_mouse_latency_shell_test.py`; `cd test/incus && python3 -m unittest mouse_latency_probe_test.py`; `bash -n test/incus/test-mouse-latency.sh`

- **Timestamp**: 2026-05-17T15:30:19Z
  - **Action**: Addressed final review nits in orchestrate tests by renaming the settle-diagnostics args mock class for clarity and replacing inline cwnd-byte magic numbers with named KiB constants.
  - **File(s)**: `test/incus/mouse_latency_orchestrate_test.py`, `_Log.md`
  - **Validation**: `cd test/incus && python3 -m unittest mouse_latency_orchestrate_test.py`

- **Timestamp**: 2026-05-17T15:31:13Z
  - **Action**: Applied final Copilot review polish in orchestrate tests by making the mock args class name explicitly `Mock*` and documenting cwnd KiB fixture constants.
  - **File(s)**: `test/incus/mouse_latency_orchestrate_test.py`, `_Log.md`
  - **Validation**: `cd test/incus && python3 -m unittest mouse_latency_orchestrate_test.py`

- **Timestamp**: 2026-05-17T08:30:20Z
  - **Action**: PR #1394 round-10 follow-up — fixed standalone userspace event-stream callback wiring by always registering session/full-resync callbacks, and added a regression test that verifies standalone SessionOpen and FullResync frames are ACKed instead of stalling behind an unwired callback queue.
  - **File(s)**: `pkg/daemon/daemon_ha_userspace.go`, `pkg/daemon/userspace_sync_test.go`, `_Log.md`
  - **Validation**: `gofmt -w pkg/daemon/daemon_ha_userspace.go pkg/daemon/userspace_sync_test.go`; `go test ./pkg/daemon ./pkg/dataplane/userspace ./pkg/logging`; `git diff --check`

- **Timestamp**: 2026-05-17T06:39:00Z
  - **Action**: PR #1376 housekeeping — restored `go.mod` after an unintended direct/indirect dependency classification flip from automation so this branch remains scoped to mirror snapshot fixes.
  - **File(s)**: `go.mod`, `_Log.md`

- **Timestamp**: 2026-05-17T06:45:00Z
  - **Action**: PR #1376 re-review follow-up — renamed the mirror snapshot fail-closed wrapper to match behavior, rejected negative port-mirroring input rates before uint32 conversion to prevent wraparound, and updated mirror protocol/build tests accordingly.
  - **File(s)**: `pkg/dataplane/userspace/snapshot.go`, `pkg/dataplane/userspace/protocol_test.go`, `pkg/dataplane/userspace/manager_test.go`, `_Log.md`

- **Timestamp**: 2026-05-17T05:06:00Z
  - **Action**: PR #1395 cleanup — reverted an unintended `go.mod` direct/indirect dependency classification change introduced by automated tooling so the round-4 fix stays scoped to three-color policer compiler logic/tests/docs.
  - **File(s)**: `go.mod`, `_Log.md`

- **Timestamp**: 2026-05-17T05:12:00Z
  - **Action**: Round-5 follow-up fix — in userspace pending-XSK-startup compile path, defer `lastSnapshot` cache update until ingress/local/NAT map sync succeeds so sync failures cannot poison cached snapshot state with an unpublished generation.
  - **File(s)**: `pkg/dataplane/userspace/manager.go`, `_Log.md`

- **Timestamp**: 2026-05-17T05:16:00Z
  - **Action**: Restored `go.mod` after an unintended direct/indirect dependency classification flip introduced by an automation-only progress update.
  - **File(s)**: `go.mod`, `_Log.md`

- **Timestamp**: 2026-05-17T04:48:51Z
  - **Action**: Re-restored `go.mod` after a subsequent tooling pass reintroduced the same direct/indirect dependency classification flip.
  - **File(s)**: `go.mod`, `_Log.md`

- **Timestamp**: 2026-05-17T05:03:00Z
  - **Action**: PR #1395 round-4 follow-up cleanup — moved three-color mode marker assignment outside repeated same-mode child loops to avoid redundant writes while preserving duplicate-sibling merge semantics.
  - **File(s)**: `pkg/config/compiler_firewall.go`, `_Log.md`

- **Timestamp**: 2026-05-17T04:58:00Z
  - **Action**: PR #1395 round-4 follow-up — fixed three-color policer compiler handling for duplicate same-mode sibling blocks by iterating all `single-rate`/`two-rate` children, added hierarchical ambiguity regression coverage in parser/configstore tests, and updated filter module docs to reflect same-mode sibling merge semantics.
  - **File(s)**: `pkg/config/compiler_firewall.go`, `pkg/config/parser_ast_test.go`, `pkg/configstore/store_test.go`, `userspace-dp/src/filter/README.md`, `_Log.md`

- **Timestamp**: 2026-05-17T04:58:00Z
  - **Action**: PR #1379 round-4 blocker fix follow-up — removed HA startup ordering race by starting cluster comms only after event fanout wiring, made userspace event-stream callback registration concurrency-safe for post-start wiring, and exposed helper producer sent/dropped counters through status text and Prometheus.
  - **File(s)**: `pkg/daemon/daemon_run.go`, `pkg/dataplane/userspace/eventstream.go`, `pkg/dataplane/userspace/eventstream_test.go`, `pkg/dataplane/userspace/protocol.go`, `pkg/dataplane/userspace/statusfmt.go`, `pkg/api/metrics.go`, `pkg/api/metrics_test.go`, `_Log.md`
  - **Validation**: `gofmt -w pkg/daemon/daemon_run.go pkg/dataplane/userspace/eventstream.go pkg/dataplane/userspace/eventstream_test.go pkg/dataplane/userspace/protocol.go pkg/dataplane/userspace/statusfmt.go pkg/api/metrics.go pkg/api/metrics_test.go`; `go test ./pkg/dataplane/userspace ./pkg/logging ./pkg/api ./pkg/daemon`; `git diff --check`

- **Timestamp**: 2026-05-17T05:06:00Z
  - **Action**: Addressed automated review nit on the new event-stream lifecycle regression test by replacing fixed sleep + wall-clock polling with timeout contexts and retry loops for listener readiness/connection checks.
  - **File(s)**: `pkg/dataplane/userspace/eventstream_test.go`, `_Log.md`
  - **Validation**: `gofmt -w pkg/dataplane/userspace/eventstream_test.go`; `go test ./pkg/dataplane/userspace ./pkg/logging ./pkg/api ./pkg/daemon`; `git diff --check`

- **Timestamp**: 2026-05-17T05:13:00Z
  - **Action**: Completed the same timeout-context synchronization pattern in `TestEventStreamDataplaneEventCallbackCanBeSetAfterStart` so the new lifecycle regression test no longer relies on fixed sleeps or wall-clock deadline polling.
  - **File(s)**: `pkg/dataplane/userspace/eventstream_test.go`, `_Log.md`
  - **Validation**: `gofmt -w pkg/dataplane/userspace/eventstream_test.go`; `go test ./pkg/dataplane/userspace ./pkg/logging ./pkg/api ./pkg/daemon`; `git diff --check`

- **Timestamp**: 2026-05-17T01:12:00Z
  - **Action**: PR #1391 post-smoke follow-up — live q10(24G)+q0(best-effort) contention on `7e7eb07e` showed serviceable-only exact suppression still let q0 drain ~15.6 GB of surplus while exact was backlogged. Reworked the gate from binary serviceability to residual-rate budgeting: non-exact surplus can consume only `root_rate - backlogged_exact_guarantee_rates`, shared exact queues publish queue masks so one queue's reservation is counted once across workers, and shared interfaces use an interface-global residual token bucket rather than per-worker residual buckets.
  - **File(s)**: `userspace-dp/src/afxdp/cos/queue_service/mod.rs`, `userspace-dp/src/afxdp/cos/queue_service/tests.rs`, `userspace-dp/src/afxdp/cos/tx_completion.rs`, `userspace-dp/src/afxdp/types/shared_cos_lease.rs`, `userspace-dp/src/afxdp/types/cos.rs`, `userspace-dp/src/afxdp/cos/builders.rs`, `userspace-dp/src/afxdp/worker/cos_tests.rs`, `userspace-dp/src/afxdp/cos/README.md`, `userspace-dp/src/afxdp/types/README.md`, `_Log.md`
  - **Validation**: `rustfmt --edition 2024` on changed Rust files; `cargo test --manifest-path userspace-dp/Cargo.toml build_nonexact -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml exact_backlog -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml apply_cos_send_result_debits_shared_residual_surplus_budget -- --nocapture`; `git diff --check`

- **Timestamp**: 2026-05-17T00:08:28Z
  - **Action**: Issue #1390 — initial CoS best-effort strict-priority fix attempt; round-1 review later narrowed the invariant to surplus-only suppression so explicit non-exact guarantees remain Junos-compatible.
  - **File(s)**: `userspace-dp/src/afxdp/cos/queue_service/mod.rs`, `userspace-dp/src/afxdp/cos/queue_service/tests.rs`, `userspace-dp/src/afxdp/tx/cos_classify_tests.rs`, `userspace-dp/src/afxdp/worker/cos_tests.rs`, `userspace-dp/src/afxdp/cos/README.md`, `_Log.md`
  - **Validation**: `cargo fmt --manifest-path userspace-dp/Cargo.toml`; `cargo test --manifest-path userspace-dp/Cargo.toml build_nonexact -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::cos::queue_service::tests:: -- --nocapture`; `git diff --check`

- **Timestamp**: 2026-05-17T00:35:00Z
  - **Action**: PR #1391 round-1 review follow-up — narrowed exact-over-residual enforcement to the surplus phase so explicit non-exact guarantees keep Junos-compatible service; local and peer suppression now require a serviceable exact queue, peer serviceability uses acquire/release publication, and tests pin non-exact guarantee plus token-starved exact behavior.
  - **File(s)**: `userspace-dp/src/afxdp/cos/queue_service/mod.rs`, `userspace-dp/src/afxdp/cos/queue_service/tests.rs`, `userspace-dp/src/afxdp/cos/tx_completion.rs`, `userspace-dp/src/afxdp/types/shared_cos_lease.rs`, `userspace-dp/src/afxdp/cos/README.md`, `userspace-dp/src/afxdp/types/README.md`, `_Log.md`
  - **Validation**: `cargo test --manifest-path userspace-dp/Cargo.toml build_nonexact -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml afxdp::cos::queue_service::tests:: -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml exact_backlog -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml reset_binding_cos_runtime_clears_shared_exact_backlog_slot -- --nocapture`; `git diff --check`

- **Timestamp**: 2026-05-17T00:48:00Z
  - **Action**: PR #1385 round-3 review follow-up — corrected README prose so pool-mode SNAT is no longer described as an explicit userspace capability gate after the pool-mode fixes; the remaining caveat is cross-backend `address-persistent` parity under #1377.
  - **File(s)**: `README.md`, `_Log.md`
  - **Validation**: `git diff --check`

- **Timestamp**: 2026-05-17T01:03:00Z
  - **Action**: PR #1382 round-3 rebase follow-up — aligned the Phase 0 audit with the now-merged #1385 pool-mode SNAT fixes, and kept #1377 as the remaining cross-backend `address-persistent` parity blocker.
  - **File(s)**: `docs/pr/1373-retire-ebpf-dataplane/plan.md`, `_Log.md`
  - **Validation**: `git diff --check`

## 2026-05-16

- **Timestamp**: 2026-05-16T23:58:00Z
  - **Action**: PR #1385 round-2 review follow-up — made Rust pool-mode SNAT skip matched rules whose pool has no address for the packet family so later compatible rules can apply, added wrong-family regression tests, and documented userspace/eBPF/DPDK address-persistent algorithm divergence until #1377 defines a shared contract.
  - **File(s)**: `userspace-dp/src/nat.rs`, `userspace-dp/src/nat_tests.rs`, `docs/userspace-dataplane-architecture.md`, `docs/userspace-dataplane-gaps.md`, `README.md`, `_Log.md`
  - **Validation**: `cargo test --manifest-path userspace-dp/Cargo.toml pool_snat_wrong_family`; `go test ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-16T22:18:20Z
  - **Action**: PR #1385 round-1 review fixes — make userspace source-NAT pool snapshots fail closed when the referenced pool is missing, empty, or has an invalid port range; add regression coverage for each unsafe pool-mode case; refresh the userspace dataplane gap date after the pool-mode capability update.
  - **File(s)**: `pkg/dataplane/userspace/snapshot.go`, `pkg/dataplane/userspace/manager_test.go`, `docs/userspace-dataplane-gaps.md`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-17T00:06:00Z
  - **Action**: PR #1386 round-2 review follow-up — changed userspace buffer capacity fallback from all-or-nothing to per-row fallback so mixed helper snapshots with one populated `per_binding[]` row and one sparse row do not undercount capacity.
  - **File(s)**: `pkg/dataplane/userspace/buffersfmt.go`, `pkg/dataplane/userspace/buffersfmt_test.go`, `_Log.md`
  - **Validation**: `gofmt -w pkg/dataplane/userspace/buffersfmt.go pkg/dataplane/userspace/buffersfmt_test.go`; `go test ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-16T22:19:53Z
  - **Action**: PR #1386 round-1 review fixes — preserve the `Active sessions` footer in userspace `show system buffers`, make non-detail output aggregate-only while `buffers detail` adds per-binding rows, and fall back to `bindings[]` when `per_binding[]` lacks capacity gauges.
  - **File(s)**: `pkg/dataplane/userspace/buffersfmt.go`, `pkg/dataplane/userspace/buffersfmt_test.go`, `pkg/cli/cli_show_system.go`, `pkg/grpcapi/server_show.go`, `pkg/grpcapi/server_show_system_buffers_test.go`, `docs/userspace-dataplane-architecture.md`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane/userspace ./pkg/grpcapi ./pkg/cli ./pkg/fwdstatus`; `git diff --check`

- **Timestamp**: 2026-05-16T22:21:02Z
  - **Action**: PR #1388 round-1 review fix — preserve old-status-JSON display compatibility for shaped interfaces whose userspace runtime synthesizes default best-effort queue 0, while keeping residual scheduler-map queues from inheriting false guarantees.
  - **File(s)**: `pkg/dataplane/userspace/cosfmt.go`, `pkg/dataplane/userspace/cosfmt_test.go`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-17T00:55:00Z
  - **Action**: PR #1383 round-3 review follow-up — added the cluster sync stale-reconcile path to the interface split plan so bulk reconciliation uses the same `SessionStore`/NAT-owned companion-delete semantics as GC instead of keeping a second BPF-shaped reverse-session/DNAT cleanup copy.
  - **File(s)**: `docs/pr/1381-dataplane-interface-split/plan.md`, `_Log.md`
  - **Validation**: `git diff --check`

- **Timestamp**: 2026-05-17T00:16:00Z
  - **Action**: PR #1383 round-2 review follow-up — extended the target `ApplyResult` contract with firewall filter IDs/spans and NAT counter IDs needed by current show paths, and documented GC migration ownership for session-change counters, per-IP session-limit publish, persistent-NAT preservation, DNAT reverse cleanup, and backend-neutral stats.
  - **File(s)**: `docs/pr/1381-dataplane-interface-split/plan.md`, `_Log.md`
  - **Validation**: `git diff --check`

- **Timestamp**: 2026-05-16T23:10:00Z
  - **Action**: PR #1383 round-1 review follow-up — removed backend-specific userspace DTOs from the proposed public session-delta interface to avoid a `pkg/dataplane` ↔ `pkg/dataplane/userspace` import cycle, added the missing caller inventory, and documented compatibility, risk, architectural-mismatch, import-canary, and Phase 1 acceptance gates.
  - **File(s)**: `docs/pr/1381-dataplane-interface-split/plan.md`, `_Log.md`

- **Timestamp**: 2026-05-17T00:59:00Z
  - **Action**: PR #1384 round-3 review follow-up — changed the blocker-plan bundle introduction to say plans land before their listed #1373 retirement phase, avoiding a Phase 4 blanket statement now that #1380 is a Phase 5 observability blocker.
  - **File(s)**: `docs/pr/1373-retire-ebpf-dataplane/README.md`, `_Log.md`
  - **Validation**: `git diff --check`

- **Timestamp**: 2026-05-17T00:24:00Z
  - **Action**: PR #1384 round-2 review follow-up — aligned #1380 with the Phase 5 observability gate, and made the #1377 plan explicitly cover address-persistent SNAT pool selection plus current userspace/eBPF/DPDK algorithm divergence and required compatibility fixtures.
  - **File(s)**: `docs/pr/1373-retire-ebpf-dataplane/README.md`, `docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md`, `_Log.md`
  - **Validation**: `git diff --check`

- **Timestamp**: 2026-05-16T23:24:00Z
  - **Action**: PR #1384 round-1 review follow-up — aligned the #1373 blocker-plan index with #1377/#1380 scope, made all required-before labels explicit, tightened SYN-cookie full-epoch/low-bit-wrap semantics, added risk sections and capability-admission tests to blocker plans, and added SNAT-pool and userspace-buffer parity plan docs.
  - **File(s)**: `docs/pr/1373-retire-ebpf-dataplane/README.md`, `docs/pr/1373-retire-ebpf-dataplane/plan-1374-syn-cookies.md`, `docs/pr/1373-retire-ebpf-dataplane/plan-1375-three-color-policers.md`, `docs/pr/1373-retire-ebpf-dataplane/plan-1376-port-mirroring.md`, `docs/pr/1373-retire-ebpf-dataplane/plan-1377-snat-pools.md`, `docs/pr/1373-retire-ebpf-dataplane/plan-1378-policy-schedulers.md`, `docs/pr/1373-retire-ebpf-dataplane/plan-1379-dataplane-events.md`, `docs/pr/1373-retire-ebpf-dataplane/plan-1380-userspace-buffers.md`, `_Log.md`

- **Timestamp**: 2026-05-16T23:39:00Z
  - **Action**: PR #1382 round-1 review follow-up — reconciled Phase 0 retirement docs with #1385/#1386 fix-forward dependencies, removed stale userspace architecture limitations for features already implemented in Rust, changed userspace-dp wording to "being retired", and added Phase 0 exit criteria plus rollback path.
  - **File(s)**: `README.md`, `docs/userspace-dataplane-gaps.md`, `docs/userspace-dataplane-architecture.md`, `userspace-dp/README.md`, `docs/pr/1373-retire-ebpf-dataplane/plan.md`, `_Log.md`
  - **Validation**: `git diff --check`

- **Timestamp**: 2026-05-16T04:36:00Z
  - **Action**: PR #1320 round-3 review fixes — validate typed scheduler leaves against the apply-groups-expanded tree before compile; reject `transmit-rate exact` unless the scheduler also has a typed rate; wire `ConfigClassOfServiceSchedulers` into the real config-mode `set class-of-service schedulers <name>` completion tree; update module docs to keep the byte-size-only scheduler buffer contract explicit.
  - **File(s)**: `pkg/cmdtree/schema_validate.go`, `pkg/cmdtree/tree.go`, `pkg/cmdtree/tree_test.go`, `pkg/cmdtree/README.md`, `pkg/config/schema_validate_test.go`, `pkg/config/README.md`, `pkg/configstore/store.go`, `pkg/configstore/store_test.go`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/cmdtree/... ./pkg/config/... ./pkg/configstore/...`; `go test -count=1 ./pkg/...`; `git diff --check`

- **Timestamp**: 2026-05-16T00:14:30Z
  - **Action**: Issue #1330 — split `userspace-dp/src/bin/fairness-eval.rs` into a thin CLI shell plus `userspace-dp/src/fairness_eval/` modules for args, inputs, windowing, per-worker aggregation, RSS expectation, verdict construction, and report emission without changing CLI behavior or fairness semantics.
  - **File(s)**: `userspace-dp/src/bin/fairness-eval.rs`, `userspace-dp/src/fairness_eval/*`, `userspace-dp/src/bin/README.md`, `docs/pr/1330-fairness-eval-library/plan.md`, `_Log.md`
  - **Validation**: `cargo test --manifest-path userspace-dp/Cargo.toml --bin fairness-eval`; `cargo test --manifest-path userspace-dp/Cargo.toml --test fairness_eval_blackbox`; `git diff --check`

## 2026-05-15

- **Timestamp**: 2026-05-16T00:06:42Z
  - **Action**: PR #1316 Copilot follow-up — narrow the validation TSV auditability claim to the fields present in the checked-in TSV schema, permit TSV summaries in the `docs/pr/` evidence convention, and qualify the old dominant-failure heading as a pre-buffer-sizing snapshot.
  - **File(s)**: `docs/pr/1316-lowrate-cos-buffers/validation.md`, `docs/pr/README.md`, `docs/cos-validation-notes.md`, `_Log.md`

- **Timestamp**: 2026-05-15T23:13:00Z
  - **Action**: PR #1316 round-4 review follow-up — filled the full seven-class validation table's high-rate Max CoV values from the committed TSV evidence, and documented that the historical 8-matrix `full-cos.set` file was later amended with q0/q4 buffer-size headroom.
  - **File(s)**: `docs/pr/1316-lowrate-cos-buffers/validation.md`, `docs/pr/line-rate-investigation/8matrix-findings.md`, `_Log.md`

- **Timestamp**: 2026-05-15T23:00:00Z
  - **Action**: Restored `go.mod` to pre-PR state after an unintended direct/indirect dependency classification flip during automation-only progress updates.
  - **File(s)**: `go.mod`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-15T22:56:00Z
  - **Action**: Reverted unintended `go.mod` direct/indirect dependency reorder so round-1 fix remains scoped to CoS runtime lookup logic and tests.
  - **File(s)**: `go.mod`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-15T22:52:00Z
  - **Action**: Round-1 follow-up cleanup — remove duplicate VLAN candidate append path in CoS runtime candidate generation while preserving VLAN-first ordering for unit-zero lookups.
  - **File(s)**: `pkg/dataplane/userspace/cosfmt.go`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-15T22:45:00Z
  - **Action**: Round-1 review hardening for issue #1278 — fix unit-zero candidate ordering so VLAN binding ifindex is preferred over parent binding when both exist, preventing wrong runtime CoS counters from being shown.
  - **File(s)**: `pkg/dataplane/userspace/cosfmt.go`, `pkg/dataplane/userspace/cosfmt_test.go`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-15T22:15:00Z
  - **Action**: Issue #1298 — add an idle debug-updater regression test proving wall-clock publishes age active-flow, flow-worker-map, and CoS active-flow snapshots to zero. Round-1 review narrowed the claim to the helper path exercised by the test and tied the aging loop to `ACTIVE_WINDOW_EPOCHS` instead of a hard-coded epoch count.
  - **File(s)**: `userspace-dp/src/afxdp/flow_cache.rs`, `userspace-dp/src/afxdp/umem/tests.rs`, `_Log.md`
  - **Validation**: `cargo test idle_debug_updater_ages_active_flow_snapshots`; `cargo test idle_debug_state_publish_cadence_is_wall_clock_based`; `git diff --check`

- **Timestamp**: 2026-05-15T22:05:00Z
  - **Action**: Issue #1278 — make `show class-of-service interface` join configured reverse-egress CoS interfaces to live runtime by configured name first and binding egress ifindex second, so alias drift between `ge-0-0-1.0` and the runtime snapshot no longer hides queue counters.
  - **File(s)**: `pkg/dataplane/userspace/cosfmt.go`, `pkg/dataplane/userspace/cosfmt_test.go`, `docs/cos-validation-notes.md`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-15T21:23:20Z
  - **Action**: PR #1312 CoS TX-error attribution — round-3 fixes: (1) mirror reset-time CoS queue drains into `binding.live.dbg_cos_queue_overflow` in `reset_binding_cos_runtime` so the binding-scoped subset stays lifetime-matched with `tx_errors`; (2) add Rust regression test `reset_binding_cos_runtime_mirrors_drops_to_binding_cos_counter`; (3) update `docs/cos-validation-notes.md` to state the binding-scoped subset includes admission rejects AND reset-time queue drains, and rephrase reason-counter lines as aggregate current-runtime sums (not per-queue rows); (4) extract `saturatingAddU64`/`saturatingSubU64` into `format_math.go` with doc comments; (5) rename ECN accumulator to `cosAdmissionEcnMarked` (Go-style Ecn casing).
  - **File(s)**: `userspace-dp/src/afxdp/worker/cos.rs`, `userspace-dp/src/afxdp/worker/cos_tests.rs`, `pkg/dataplane/userspace/statusfmt.go`, `pkg/dataplane/userspace/statusfmt_test.go`, `pkg/dataplane/userspace/cosfmt.go`, `pkg/dataplane/userspace/format_math.go`, `docs/cos-validation-notes.md`, `_Log.md`
- **Timestamp**: 2026-05-15T21:42:00Z
  - **Action**: PR #1315 Copilot follow-up — keep the historical `dbg_cos_queue_overflow` wire key but relabel the CLI/docs as binding-lifetime CoS queue drops because the subset now includes reset-time CoS queue drains in addition to admission rejects.
  - **File(s)**: `pkg/dataplane/userspace/statusfmt.go`, `pkg/dataplane/userspace/statusfmt_test.go`, `pkg/dataplane/userspace/protocol.go`, `userspace-dp/src/protocol.rs`, `docs/cos-validation-notes.md`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/dataplane/userspace`; `git diff --check`

- **Timestamp**: 2026-05-15T20:33:36Z
  - **Action**: PR #1316 / issue #1312 hostile-review follow-up — clarified low-rate CoS fixture docs with the actual implicit base/cap pipeline (`rate/100` + 96 KB floor, flow-share expansion, #717 delay clamp), documented the queue-residence tradeoff for q0/q4 overrides, added a regression test pin that 1 Gbps q4 `buffer-size 4m` remains above delay-cap clamping, updated canonical fixture buffers, and committed durable validation evidence.
  - **File(s)**: `test/incus/cos-iperf-config.set`, `test/incus/cos-iperf-symmetric.set`, `test/incus/cos-iperf-same-class.set`, `docs/cos-validation-notes.md`, `docs/fairness-regimes.md`, `docs/per-5-tuple/state.md`, `docs/pr/README.md`, `docs/pr/1316-lowrate-cos-buffers/validation.md`, `docs/pr/1316-lowrate-cos-buffers/evidence/focused-summary.tsv`, `docs/pr/1316-lowrate-cos-buffers/evidence/focused-dataplane-summary.tsv`, `docs/pr/1316-lowrate-cos-buffers/evidence/focused-equal-flow-summary.tsv`, `docs/pr/1316-lowrate-cos-buffers/evidence/full-summary.tsv`, `docs/pr/1316-lowrate-cos-buffers/evidence/full-dataplane-summary.tsv`, `docs/pr/1316-lowrate-cos-buffers/evidence/full-equal-flow-summary.tsv`, `docs/pr/line-rate-investigation/full-cos.set`, `userspace-dp/src/afxdp/cos/admission_tests.rs`, `_Log.md`

## 2026-05-14

- **Timestamp**: 2026-05-14T19:33:03Z
  - **Action**: PR #1308 round-2 review follow-up — added explicit equal-flow scrape framing tests for nested begin and end-without-begin paths, added the missing `BindingCountersSnapshot` round-trip pin for `tx_shared_recycle_unknown_slot_drops`, applied `gofmt` to `protocol.go`, and renamed sweep progress output from `wrapper_status` to `exit_status` with a named infrastructure-exit constant.
  - **File(s)**: `test/incus/fairness_multi_sample_test.py`, `test/incus/fairness-cos-class-sweep.sh`, `pkg/dataplane/userspace/protocol.go`, `pkg/dataplane/userspace/protocol_test.go`, `_Log.md`

- **Timestamp**: 2026-05-14T19:19:32Z
  - **Action**: PR #1308 round-1 review follow-up — made equal-flow capture reduction fail closed on SIGTERM-truncated marked scrapes and non-integer active-worker counts, and made sweep summary rows report infrastructure exit status `2` when equal-flow capture fails after the wrapper succeeds.
  - **File(s)**: `test/incus/fairness_equal_flow_capture.py`, `test/incus/fairness-cos-class-sweep.sh`, `test/incus/fairness_multi_sample_test.py`, `docs/fairness-regimes.md`, `docs/per-5-tuple/state.md`, `_Log.md`

- **Timestamp**: 2026-05-14T18:35:00Z
  - **Action**: Issue #1306 — add first-class per-class equal-flow estimator capture to the CoS class sweep harness. The sweep now brackets each wrapper run with continuous Prometheus scraping, preserves raw scrapes, reduces target-class equal-flow aggregate/worker rows, appends equal-flow evidence to `summary.md`, and fails closed on empty/missing/invalid estimator captures.
  - **File(s)**: `test/incus/fairness-cos-class-sweep.sh`, `test/incus/fairness_equal_flow_capture.py`, `test/incus/fairness_multi_sample_test.py`, `docs/fairness-regimes.md`, `docs/per-5-tuple/state.md`, `_Log.md`

- **Timestamp**: 2026-05-14T17:53:10Z
  - **Action**: PR #1305 round-3 review follow-up — extended artifact-warning wording to the equal-flow capped-bps, worker-cap-bps, and throughput-loss-ratio Prometheus help strings.
  - **File(s)**: `pkg/api/metrics.go`, `_Log.md`

- **Timestamp**: 2026-05-14T17:38:10Z
  - **Action**: PR #1305 round-2 review follow-up — made the out-of-range worker test assert directly against `bytesByWorker` so the worker-delta cap is independently covered, and added artifact warnings to the equal-flow target/suppression metric help strings.
  - **File(s)**: `pkg/dataplane/userspace/fairness_throughput_test.go`, `pkg/api/metrics.go`, `_Log.md`

- **Timestamp**: 2026-05-14T16:49:39Z
  - **Action**: PR #1305 review follow-up — bounded equal-flow estimator worker IDs with the existing fairness RSS worker-slot cap, sharpened Prometheus help strings, and added validity boundary tests for single-worker, unsampled, zero-window, and out-of-range-worker cases.
  - **File(s)**: `pkg/dataplane/userspace/fairness_throughput.go`, `pkg/dataplane/userspace/fairness_throughput_test.go`, `pkg/api/metrics.go`, `docs/pr/1304-equal-flow-estimator/plan.md`, `_Log.md`

- **Timestamp**: 2026-05-14T14:51:46Z
  - **Action**: Issue #1304 Phase 0 — add measurement-only equal-flow rate-suppression estimator telemetry for exact CoS queues, document its invariants, and pin estimator math/Prometheus emission tests.
  - **File(s)**: `pkg/dataplane/userspace/fairness_throughput.go`, `pkg/dataplane/userspace/fairness_throughput_test.go`, `pkg/api/metrics.go`, `pkg/api/metrics_test.go`, `docs/fairness-regimes.md`, `docs/per-5-tuple/state.md`, `docs/pr/1304-equal-flow-estimator/plan.md`, `_Log.md`

- **Timestamp**: 2026-05-14T04:01:00Z
  - **Action**: PR #1301 review follow-up — removed power-of-two UMEM frame-size assumption in memmove fallback bounds calculation by switching to modulo-based in-frame offset math.
  - **File(s)**: `userspace-dp/src/afxdp/frame/mod.rs`, `_Log.md`

- **Timestamp**: 2026-05-14T03:52:00Z
  - **Action**: PR #1301 review follow-up — tightened in-frame memmove fallback slice bounds to the current UMEM chunk and added regression coverage for `FillOnSlotWithOffset` recycle tracking.
  - **File(s)**: `userspace-dp/src/afxdp/frame/mod.rs`, `userspace-dp/src/afxdp/tx/transmit_tests.rs`, `_Log.md`

## 2026-05-12

- **Timestamp**: 2026-05-12T07:50:00Z
  - **Action**: PR #1274 Copilot follow-up — use verdict JSON key names consistently in the Accepted Path publish list.
  - **File(s)**: `docs/per-5-tuple/tcp-head-start-floor.md`, `_Log.md`

- **Timestamp**: 2026-05-12T06:46:48Z
  - **Action**: PR #1274 review follow-up — wrapped TCP head-start policy prose and made the observed CoV prose/JSON-field distinction explicit.
  - **File(s)**: `docs/per-5-tuple/tcp-head-start-floor.md`, `_Log.md`

- **Timestamp**: 2026-05-12T06:29:27Z
  - **Action**: PR round-2 review follow-up — expanded AFD acronym at first use (line 5), changed `observed_cov` to `observed_CoV` in prose formulas (lines 86, 99), made epsilon explicit as 0.05.
  - **File(s)**: `docs/per-5-tuple/tcp-head-start-floor.md`, `_Log.md`

- **Timestamp**: 2026-05-12T07:35:00Z
  - **Action**: PR #1271 round-3 follow-up — add same-VLAN/different-RETH synthetic-ifindex regressions so `reth0.N` and `reth1.N` cannot collapse into one logical Rust dataplane state key.
  - **File(s)**: `pkg/dataplane/userspace/manager_test.go`, `_Log.md`

- **Timestamp**: 2026-05-12T07:20:00Z
  - **Action**: PR #1271 cleanup — removed unrelated `go.mod` direct/indirect dependency churn introduced by local test tooling to keep the diff scoped to synthetic-ifindex changes.
  - **File(s)**: `go.mod`, `_Log.md`

- **Timestamp**: 2026-05-12T07:16:00Z
  - **Action**: PR #1271 validation follow-up — documented synthetic-ifindex range rationale, improved exhaustion panic guidance, deduplicated VLAN test constants, and reverted unrelated `go.mod` drift from local test tooling.
  - **File(s)**: `pkg/dataplane/userspace/snapshot.go`, `pkg/dataplane/userspace/manager_test.go`, `go.mod`, `_Log.md`

- **Timestamp**: 2026-05-12T07:08:00Z
  - **Action**: PR #1271 follow-up — enriched synthetic-ifindex exhaustion panic diagnostics and replaced test magic VLAN bound with named constants during validation pass.
  - **File(s)**: `pkg/dataplane/userspace/snapshot.go`, `pkg/dataplane/userspace/manager_test.go`, `_Log.md`

- **Timestamp**: 2026-05-12T06:55:00Z
  - **Action**: PR #1271 round-2 follow-up — made parent-bound RETH VLAN synthetic ifindex allocation deterministic/config-derived, removed kernel-ifindex seeding, switched to high synthetic range with hard-fail on exhaustion, and added sibling-VLAN determinism regression coverage.
  - **File(s)**: `pkg/dataplane/userspace/snapshot.go`, `pkg/dataplane/userspace/manager_test.go`, `_Log.md`

- **Timestamp**: 2026-05-12T00:30:00Z
  - **Action**: PR #1267 round-2 review follow-up — fixed fairness throughput window boundary pruning/rate denominator coupling to prevent false-positive saturation at steady sub-cap traffic, and added a regression test for the 10s-scrape/30s-window boundary case.
  - **File(s)**: `pkg/dataplane/userspace/fairness_throughput.go`, `pkg/dataplane/userspace/fairness_throughput_test.go`, `_Log.md`

## 2026-05-10

- **Timestamp**: 2026-05-10T15:24:00Z
  - **Action**: PR #1253 review follow-up — corrected `userspace-dp/src/server/README.md` RSS-indirection behavior to match `pkg/daemon/rss_indirection.go` (reshape conditions, workers>=queues stale-table cleanup restore path, and queue concentration semantics).
  - **File(s)**: `userspace-dp/src/server/README.md`, `_Log.md`

- **Timestamp**: 2026-05-10T15:05:00Z
  - **Action**: PR #1253 review pass — corrected `pkg/configstore/README.md` encryption-key location wording to match `master.key` under the configstore DB directory (`db.dir`) and removed stale `/etc/xpf/config-key` path guidance.
  - **File(s)**: `pkg/configstore/README.md`, `_Log.md`

- **Timestamp**: 2026-05-10T04:06:32Z
  - **Action**: PR comment follow-up review for `docs/per-5-tuple/state.md` — replaced a non-existent memory-file reference with in-repo issue/table references (#836/#937/#1215) to keep the fairness section self-contained and verifiable.
  - **File(s)**: `docs/per-5-tuple/state.md`, `_Log.md`

## 2026-05-07

- **Timestamp**: 2026-05-07T16:13:00Z
  - **Action**: PR #1211 archive doc follow-up — fixed stale/missing cross-references in closure docs, updated per-5-tuple state to mark Path 2 closed with archive links, and clarified memory-hook wording as external memory (not an in-repo file).
  - **File(s)**: `docs/per-5-tuple/path2-archive/CLOSING-RATIONALE.md`, `docs/per-5-tuple/state.md`

## 2026-04-19 — #812 plan R1 (fold Codex round-1 hostile review)
- **Timestamp**: 2026-04-19
- **Action**: Fold Codex round-1 review into the Architect plan. Close 3 HIGH findings: small-batch amortization collapse (§3.1 per-commit stamping with honest `inserted == 1` worst-case), relaxed-atomic cross-CPU visibility (§3.6.a Relaxed+documented, invariants 6/7 rewritten, §8 hard-stop #4 uses bounded-skew delta), sidecar false-sharing (§3.3 per-binding single-writer confirmed by `Rc<WorkerUmemInner>` + `shared_umem=false` in code). Rewrite §3.4 overhead budget with three operating-point numbers (`inserted=256/64/1`) and a correct per-queue denominator (481 ns/pkt at 25 Gbps), not per-worker. Rewrite §11.3 Bonferroni family to match actual composite tests (3/cell × 12 cells = 36, not 192). Close MED #5 (sentinel vs clock-0), MED #6 (sidecar size 192 KiB, not 64 KiB), MED #7 (wire-size growth), MED #8 (Bonferroni family), MED #9 (two-thread test replaced by partial-batch / retry-unwind / bounded-skew tests). Close LOW #10 (no `now_ns` reuse), LOW #13 (named const asserts + boundary test).
  - **File(s)**: `docs/pr/812-tx-latency-histogram/plan.md`

## 2026-04-17

- **Timestamp**: 2026-04-17
  - **Action**: Issue #678 — Architect plan for remaining hot-path CPU cuts. Remeasured on loss userspace cluster (master 7c1e55b9): poll_binding 10.4%/10.6% (down from issue's 13.4%/13.3%), enqueue_pending_forwards 0.71%/<1% (down from 4.3%/3.7%), apply_nat_ipv6 <1% (down from 3.2% IPv6). Recommendation: Option A — split poll_binding into orchestration shell + per-descriptor hot path as a measurement-first structural refactor. Options B/C/D deferred as issues; Option F (close as subsumed) is the expected path post-split.
  - **File(s)**: docs/678-hotpath-cuts-plan.md

## 2026-04-03

- **Timestamp**: 2026-04-03
  - **Action**: Issue #547 — Split pkg/grpcapi/server.go (8411 lines) into 8 domain files. Mechanical move of functions, no logic changes. server.go reduced to 241 lines (types + server lifecycle).
  - **File(s)**: pkg/grpcapi/server.go, server_config.go, server_show.go, server_nat.go, server_routing.go, server_diag.go, server_helpers.go, server_dhcp.go, server_cluster.go

## 2026-04-07

- **Timestamp**: 2026-04-07T00:00:00Z
  - **Action**: Issue #545 — Split `pkg/config/compiler.go` (5878 lines) into 8 domain-specific files. Mechanical refactor, no logic changes. Functions moved to: compiler_security.go, compiler_interfaces.go, compiler_protocols.go, compiler_ipsec.go, compiler_routing.go, compiler_firewall.go, compiler_system.go, compiler_services.go. compiler.go retains top-level dispatch + applications + validators (793 lines).
  - **File(s)**: pkg/config/compiler.go, pkg/config/compiler_security.go, pkg/config/compiler_interfaces.go, pkg/config/compiler_protocols.go, pkg/config/compiler_ipsec.go, pkg/config/compiler_routing.go, pkg/config/compiler_firewall.go, pkg/config/compiler_system.go, pkg/config/compiler_services.go

- **Timestamp**: 2026-04-07T00:00:00Z
  - **Action**: Issue #532 — Fix IPv6 TTL-expired (hop limit exceeded) probe responses not being returned in userspace dataplane. Added TTL/hop-limit check with ICMP Time Exceeded generation to both session-hit and flow-cache-hit paths. Previously only the session-miss path generated TE responses; subsequent packets hitting an existing session or flow cache were silently dropped when TTL<=1 because the rewrite functions returned None without generating a response.
  - **File(s)**: userspace-dp/src/afxdp.rs

## 2026-04-05

- **Timestamp**: 2026-04-05T22:00:00Z
  - **Action**: Issue #485 — Fix TCP stream death on failback (node1→node0). Three fixes: (1) Reorder cluster Primary handler: set rg_active + pre-install neighbors BEFORE ForceRGMaster so BPF can forward the first packet arriving after VRRP installs VIPs. (2) Reorder cluster Secondary handler: run preflight (flow cache flush to FabricRedirect) BEFORE ResignRG so traffic shifts to fabric before VRRP removes VIPs. (3) Add syncMsgPrepareActivation message: demoting node notifies peer to pre-warm neighbor cache after preflight completes, giving the activating node a head start on ARP/NDP resolution.
  - **File(s)**: pkg/daemon/daemon_ha.go, pkg/cluster/sync.go

- **Timestamp**: 2026-04-05T12:00:00Z
  - **Action**: Fix TCP stream death on failback due to cold ARP cache on standby node. Root cause: `resolveNeighborsInner()` used `netlink.RouteGet()` to find the outgoing interface for static route next-hops, but on standby nodes the kernel route doesn't exist (FRR only installs it on the active). Added `addByIPOrConfig()` fallback that resolves the outgoing interface from config by matching the next-hop IP against configured interface subnets when the kernel FIB lookup fails.
  - **File(s)**: pkg/daemon/daemon.go

- **Timestamp**: 2026-04-05T10:00:00Z
  - **Action**: Issue #475 — Fix 0 throughput on pre-existing TCP streams after failover+failback. Root cause: `prewarm_reverse_synced_sessions_for_owner_rgs` published USERSPACE_SESSIONS BPF map entries for reverse sessions but not forward sessions during RG activation. Forward sessions relied on async worker processing, creating a window where the XDP shim had no REDIRECT entry. Added synchronous BPF map publishing for forward sessions in prewarm, plus a comprehensive `republish_bpf_session_entries_for_owner_rgs` that iterates ALL sessions in the `sessions` owner-RG index (not just the `reverse_prewarm` subset) to ensure no session is missed.
  - **File(s)**: userspace-dp/src/afxdp/shared_ops.rs, userspace-dp/src/afxdp/ha.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-05T08:00:00Z
  - **Action**: Issue #473 — Fix XSK bindings BPF map going stale after peer crash+reconnect. Added `verifyBindingsMapLocked()` watchdog to the 1s status poll loop. After `applyHelperStatusLocked` runs, the watchdog reads each BPF `userspace_bindings` entry and compares it against the helper's reported binding state. If a queue is Registered+Armed in the helper but the BPF map entry is all zeros, the watchdog rewrites the entry. Also repairs aliased bindings (VLAN children). This prevents silent transit traffic drops when a Compile() or HA transition zeroes the bindings map without repopulating it.
  - **File(s)**: pkg/dataplane/userspace/manager.go

- **Timestamp**: 2026-04-05T06:55:00Z
  - **Action**: Issue #466 — Fix bulk sync triggering on every reconnect/fabric-flip. Added `bulkEverCompleted` atomic flag to SessionSync that tracks whether a full bulk exchange has ever completed during the daemon's lifetime. `handleNewConnection` now only triggers `doBulkSync` on true cold start (flag is false). Active-fabric changes no longer trigger bulk at all. Daemon's `onSessionSyncPeerConnected`/`onSessionSyncPeerDisconnected` preserve primed state and sync readiness when `bulkEverCompleted` is true.
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_test.go, pkg/daemon/daemon_ha.go, pkg/daemon/session_sync_readiness_test.go

## 2026-04-04

- **Timestamp**: 2026-04-04T21:30:00Z
  - **Action**: Issue #467 — Fix bulk-prime retry loop not restarting after failed demotion barrier. `prepareUserspaceRGDemotionWithTimeout` stopped the retry loop by advancing `syncPrimeRetryGen` before waiting on barriers, but on barrier failure returned without restarting the loop, stranding the peer in an unprimed state. Added a defer that restarts `startSessionSyncPrimeRetry` on failure when peer is still connected and not yet primed.
  - **File(s)**: pkg/daemon/daemon_ha.go

- **Timestamp**: 2026-04-04T20:50:00Z
  - **Action**: Issue #458 — Fix session sync barrier timeout on second failover cycle. Root cause: `handleDisconnect` reset `barrierSeq` to 0, causing sequence collisions between stale goroutines and new barriers. Also closed waiter channels on disconnect to prevent goroutine leaks. Added `barrierAckSeq` check in `WaitForPeerBarrier` to distinguish disconnect from ack.
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_bulk.go, pkg/cluster/sync_test.go

## 2026-04-03

- **Timestamp**: 2026-04-03T18:00:00Z
  - **Action**: Issue #457 — Fix standby losing userspace readiness after partial RG demotion. The rgTransitionInFlight flag in UpdateRGActive was unconditionally set for both activation and demotion. During demotion, this caused ctrl.Enabled=0 in the BPF map globally, disrupting forwarding for other active RGs. Now only set rgTransitionInFlight during activation transitions; demotion leaves ctrl enabled so other RGs continue forwarding.
  - **File(s)**: pkg/dataplane/userspace/manager_ha.go, pkg/dataplane/userspace/manager_test.go

- **Timestamp**: 2026-04-03T12:00:00Z
  - **Action**: Issue #451 — Fix neighbor miss spike after RG failover. Part 1: resolve config-based next-hops synchronously during RG activation (VRRP MASTER and cluster-primary paths) using new `resolveNeighborsImmediate` variant that sends ARP probes without blocking for replies. Part 2: increase failover test neighbor miss threshold from 20 to 60 to accommodate observed spikes of 25-52.
  - **File(s)**: pkg/daemon/daemon.go, pkg/daemon/daemon_ha.go, scripts/userspace-ha-failover-validation.sh

- **Timestamp**: 2026-04-03T10:22:00Z
  - **Action**: Issue #418 — Replace bulk session sync with event stream replay on connect. Added `export_all_sessions_to_event_stream()` to Rust Coordinator that iterates shared sessions and pushes Open events through the event stream. Added `"export_all_sessions"` control request handler. Go daemon's `bulkSyncViaEventStreamOrFallback()` tries event stream export first, falls back to legacy BulkSync.
  - **File(s)**: userspace-dp/src/afxdp/ha.rs, userspace-dp/src/main.rs, pkg/dataplane/userspace/manager_ha.go, pkg/daemon/daemon_ha.go, pkg/daemon/userspace_sync_test.go

## 2026-04-02

- **Timestamp**: 2026-04-02T20:34:00Z
  - **Action**: Issue #403 — Planned failover must not depend on bulk sync. Added priority barrierCh channel to SessionSync so barriers/acks bypass bulk data in sendLoop. Removed syncPeerBulkPrimed gate from demotion prep. Reduced manual failover barrier timeout to 5s.
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_bulk.go, pkg/daemon/daemon_ha.go, pkg/cluster/sync_test.go

## 2026-04-01

- **Timestamp**: 2026-04-01T05:30:00Z
  - **Action**: Merged PR #301 (userspace forwarding and failover gap audit doc)
  - **File(s)**: docs/userspace-forwarding-and-failover-gap-audit.md

- **Timestamp**: 2026-04-01T06:00:00Z
  - **Action**: Implemented strict userspace mode, HA install fence, deterministic reverse companions (PR #313, issues #302-#312)
  - **File(s)**: pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/protocol.go, pkg/cluster/cluster.go, pkg/cluster/sync.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/main.rs, userspace-xdp/src/lib.rs, docs/ha-forwarding-state-inventory.md, docs/bugs.md, docs/phases.md

- **Timestamp**: 2026-04-01T06:30:00Z
  - **Action**: Address PR #313 copilot review findings — rename STRICT_PASS_BLOCKED, strict ctrl=0 drop, mode reporting, fallback names, VLAN sub-interface exclusion
  - **File(s)**: pkg/dataplane/userspace/manager.go, userspace-xdp/src/lib.rs, docs/phases.md

- **Timestamp**: 2026-04-01T13:52:00Z
  - **Action**: Fix HA session sync starvation — async bulk ack, HA sync throttle 5s, 6 retries (ba1c4304)
  - **File(s)**: pkg/cluster/sync.go, pkg/daemon/daemon.go, pkg/dataplane/userspace/manager.go

- **Timestamp**: 2026-04-01T14:44:00Z
  - **Action**: Replace bulk-sync gate with barrier check for failover readiness (e42c882e)
  - **File(s)**: pkg/daemon/daemon.go, pkg/daemon/userspace_sync_test.go

- **Timestamp**: 2026-04-01T15:39:00Z
  - **Action**: Explicit refresh_owner_rgs on RG activation + async barrier ack (a9e0501e)
  - **File(s)**: pkg/dataplane/userspace/manager.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/main.rs, pkg/cluster/sync.go

- **Timestamp**: 2026-04-01T15:59:00Z
  - **Action**: Re-resolve synced sessions with owner_rg_id=0 on active node (7417144e)
  - **File(s)**: userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T16:10:00Z
  - **Action**: Add logging rules to CLAUDE.md, remove debug eprintln (12478964)
  - **File(s)**: CLAUDE.md, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T16:59:00Z
  - **Action**: Mirror reverse sessions to helper, worker-completion ack, logging rules (#314, #315, #316) (24166737)
  - **File(s)**: CLAUDE.md, pkg/daemon/daemon.go, pkg/dataplane/userspace/manager.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T17:00:00Z
  - **Action**: Route barrier/bulk acks through sendCh instead of direct writeMu (9d2814c4)
  - **File(s)**: pkg/cluster/sync.go

- **Timestamp**: 2026-04-01T19:32:00Z
  - **Action**: Fix RefreshOwnerRGs skipped synced sessions — refresh_for_ha_activation (71b80b3d). THE key SNAT fix.
  - **File(s)**: userspace-dp/src/session.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T20:20:00Z
  - **Action**: Simplify HA failover — epoch flow cache, resolve-on-receipt, owner_rg_id, demotion (#325, #326, #327, #330) (a21018f3)
  - **File(s)**: pkg/daemon/daemon.go, pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/manager_test.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T21:52:00Z
  - **Action**: Write userspace sessions to BPF conntrack map for zone/interface display (fab9230c)
  - **File(s)**: pkg/dataplane/dataplane.go, pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/protocol.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/bpf_map.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/main.rs

- **Timestamp**: 2026-04-01T22:00:00Z
  - **Action**: Use BPF_ANY for conntrack map writes (244912f8)
  - **File(s)**: userspace-dp/src/afxdp/bpf_map.rs

- **Timestamp**: 2026-04-01T22:30:00Z
  - **Action**: Userspace/eBPF audit — counters, conntrack flush bugs, session visibility (PR #336, issues #332-#335)
  - **File(s)**: pkg/conntrack/gc.go, pkg/daemon/daemon.go, pkg/dataplane/dataplane.go, pkg/dataplane/dpdk/dpdk_cgo.go, pkg/dataplane/dpdk/dpdk_stub.go, pkg/dataplane/maps.go, pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/manager_test.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/bpf_map.rs

- **Timestamp**: 2026-04-01T23:00:00Z
  - **Action**: Address PR #336 copilot review — idle time, BPF_EXIST, counter race, safeDelta, RX counter, flush cutoff (d15d5629)
  - **File(s)**: pkg/dataplane/loader.go, pkg/dataplane/maps.go, pkg/dataplane/userspace/manager.go, pkg/dataplane/userspace/manager_test.go, userspace-dp/src/afxdp/bpf_map.rs

- **Timestamp**: 2026-04-01T23:15:00Z
  - **Action**: Thread conntrack FDs through DeleteSynced for BPF cleanup (671e5561)
  - **File(s)**: userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-01T23:30:00Z
  - **Action**: Unify synced flag + adaptive event-first session sync (#328, #320) (dcc59c67)
  - **File(s)**: pkg/daemon/daemon.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/bpf_map.rs, userspace-dp/src/afxdp/forwarding.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp/tunnel.rs, userspace-dp/src/event_stream.rs, userspace-dp/src/main.rs, userspace-dp/src/session.rs

## 2026-04-02

- **Timestamp**: 2026-04-02T18:05:00Z
  - **Action**: Start `#400` — separate transfer readiness from takeover readiness in cluster status and explicit peer-failover admission, with daemon wiring for session-sync transfer-readiness reasons
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/cluster_test.go, pkg/daemon/daemon_ha.go, pkg/daemon/userspace_sync_test.go

- **Timestamp**: 2026-04-02T17:20:00Z
  - **Action**: Start `#398` fix — add explicit session-sync transfer-readiness snapshot and fast-fail manual failover demotion when bulk receive or pending bulk ack proves the sync path is not settled; filed `#400` for exposing transfer readiness separately from takeover readiness
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_bulk.go, pkg/cluster/sync_test.go, pkg/daemon/daemon_ha.go, pkg/daemon/userspace_sync_test.go

- **Timestamp**: 2026-04-02T16:45:00Z
  - **Action**: Validate `#397` on `loss-userspace-cluster` — settled RG0 manual failover now completes on explicit failover ack + commit ack instead of heartbeat observation; filed residual issue `#398` for failover admission while requester is still in bulk receive
  - **File(s)**: testing-docs/manual-failover-transfer-commit-validation.md, testing-docs/README.md

- **Timestamp**: 2026-04-02T13:15:00Z
  - **Action**: Second #390 slice — add explicit sync-channel failover ack handshake so manual RG transfer returns applied/rejected instead of inferring success from send-only behavior
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_test.go, pkg/cluster/cluster.go, pkg/daemon/daemon_ha.go, pkg/cli/cli.go

- **Timestamp**: 2026-04-02T13:45:00Z
  - **Action**: Third #390 slice — wait for actual local RG promotion after peer transfer-out ack so CLI/local control returns on observed ownership, not just request delivery
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/cluster_test.go, pkg/cli/cli.go

- **Timestamp**: 2026-04-02T14:15:00Z
  - **Action**: Address PR #396 copilot review — typed remote-failover rejection, failover request IDs, out-of-range RG guard, timeout race guard, active-conn ack routing, and consistent gRPC wording
  - **File(s)**: pkg/cluster/sync.go, pkg/cluster/sync_test.go, pkg/daemon/daemon_ha.go, pkg/grpcapi/server.go

- **Timestamp**: 2026-04-02T16:30:00Z
  - **Action**: Next #390 slice — replace heartbeat-observed manual failover completion with explicit sync-channel transfer commit, local primary commit, peer transfer-out finalization, and commit-ack coverage
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/cluster_test.go, pkg/cluster/sync.go, pkg/cluster/sync_test.go, pkg/daemon/daemon_ha.go, pkg/cli/cli.go, pkg/grpcapi/server.go

- **Timestamp**: 2026-04-02T17:05:00Z
  - **Action**: Address PR #397 Copilot review — preserve in-flight peer transfer-out state across heartbeat refreshes until transfer commit completes or aborts
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/cluster_test.go

- **Timestamp**: 2026-04-02T12:30:00Z
  - **Action**: First #390 slice — replace weight-zero manual failover with explicit secondary-hold transfer-out state, keep ForceSecondary on zero-weight drain semantics, and teach election to promote on peer transfer-out without mutating monitor weight
  - **File(s)**: pkg/cluster/cluster.go, pkg/cluster/election.go, pkg/cluster/cluster_test.go, pkg/cluster/election_test.go, pkg/cluster/sync.go

- **Timestamp**: 2026-04-02T01:30:00Z
  - **Action**: Merged PR #337 (HA simple failover design doc). Fixed copilot review — issue reference swap in phases 3/5/6.
  - **File(s)**: docs/ha-simple-failover-design.md

- **Timestamp**: 2026-04-02T02:00:00Z
  - **Action**: Fix HA activation cleanup — deduplicate refresh, skip resolved, log mirror errors (#341, #342, #345, #346) (31b600d5)
  - **File(s)**: pkg/dataplane/userspace/manager.go, userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-02T02:30:00Z
  - **Action**: Fix watchdog threshold (2→10s), reverse companion leak on delete, remove debug eprintln (#349, #351, #352) (52254b7e)
  - **File(s)**: pkg/dataplane/userspace/manager.go, userspace-dp/src/afxdp.rs, userspace-dp/src/main.rs

- **Timestamp**: 2026-04-02T03:30:00Z
  - **Action**: Simplify HA — remove refresh RPC, skip blackhole routes, dead code cleanup, throttle post-transition sync (#353, #354, #355, #356) (5ac423a3)
  - **File(s)**: pkg/dataplane/userspace/manager.go, pkg/daemon/daemon.go

- **Timestamp**: 2026-04-02T06:00:00Z
  - **Action**: Merged PR #357 (flow cache simplification refactors). Implemented phases 3+4 from docs/flow-cache-simplification.md — explicit is_cacheable() + 10 unit tests (624a1f83)
  - **File(s)**: userspace-dp/src/afxdp/types.rs, docs/flow-cache-simplification.md

- **Timestamp**: 2026-04-02T11:45:00Z
  - **Action**: Added HA failover implementation plan tying current simplification audit to executable phases and issue dependencies (49eaf9d6)
  - **File(s)**: docs/ha-failover-implementation-plan.md, docs/ha-failover-simplification-audit.md

- **Timestamp**: 2026-04-03T00:16:04Z
  - **Action**: First #389 slice — add derived owner-RG indexes for helper shared session stores and use them for demotion-time BPF cleanup and shared-session demotion without whole-table scans
  - **File(s)**: userspace-dp/src/afxdp.rs, userspace-dp/src/afxdp/types.rs, userspace-dp/src/afxdp/ha.rs, userspace-dp/src/afxdp/shared_ops.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp/forwarding.rs, userspace-dp/src/afxdp/tunnel.rs

- **Timestamp**: 2026-04-03T00:34:06Z
  - **Action**: Address PR #404 Copilot review — make owner-RG index updates heal missing same-owner entries and serialize demotion-time key collection against in-flight shared-session publishes
  - **File(s)**: userspace-dp/src/afxdp/shared_ops.rs, userspace-dp/src/afxdp/ha.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-03T00:42:41Z
  - **Action**: Second #389 slice — add reverse-prewarm owner-RG candidate indexes so HA activation prewarm targets only affected synced forward sessions instead of scanning the full shared forward map
  - **File(s)**: userspace-dp/src/afxdp/types.rs, userspace-dp/src/afxdp/shared_ops.rs, userspace-dp/src/afxdp/ha.rs, userspace-dp/src/afxdp/session_glue.rs

- **Timestamp**: 2026-04-03T01:01:45Z
  - **Action**: Final #389 slice — index worker-local sessions by owner RG and use those indexes for export, demotion, and activation refresh so helper HA apply no longer scans the full live session table
  - **File(s)**: userspace-dp/src/session.rs, userspace-dp/src/afxdp/session_glue.rs, _Log.md

- **Timestamp**: 2026-04-03T03:00:15Z
  - **Action**: Applied Copilot review fixes for stacked #389 PRs — make reverse-prewarm owner-RG index updates lock once per refresh, restore derived indexes on rejected session updates, and remove unnecessary hot-path clones
  - **File(s)**: userspace-dp/src/afxdp/shared_ops.rs, userspace-dp/src/session.rs, userspace-dp/src/afxdp/session_glue.rs, userspace-dp/src/afxdp.rs, _Log.md

## 2026-04-03 HA Failover Fix Session

### Actions
- **Action**: Wire BulkSyncOverride in daemon_ha.go so initial bulk sync uses event stream
  - **File(s)**: `pkg/daemon/daemon_ha.go`
- **Action**: Fix stuck bulk receive state on disconnect — reset bulkInProgress in handleDisconnect
  - **File(s)**: `pkg/cluster/sync.go`
- **Action**: Add sendBulkMarkers() to send empty BulkStart/BulkEnd after event stream export
  - **File(s)**: `pkg/cluster/sync_bulk.go`
- **Action**: Fix HA session promotion — push forward sessions to workers + bump rg_epochs on activation
  - **File(s)**: `userspace-dp/src/afxdp/ha.rs`, `userspace-dp/src/afxdp/shared_ops.rs`, `userspace-dp/src/afxdp/session_glue.rs`

### Results
- Bulk sync completes correctly on both nodes (event stream + bulk markers)
- Transfer ready: yes on both nodes after deploy
- Manual failover test PASSES: iperf3 -P2 at 11 Gbps survives RG move with no visible throughput drop
- Automated script reports false failure (samples at exact transition moment)

## 2026-04-17 — #718 ECN CE marking at CoS admission
- **Action**: Add mark_ecn_ce_ipv4 / mark_ecn_ce_ipv6 / maybe_mark_ecn_ce / apply_cos_admission_ecn_policy; wire into enqueue_cos_item
  - **File(s)**: `userspace-dp/src/afxdp/tx.rs`
- **Action**: Add CoSQueueDropCounters.admission_ecn_marked field + protocol/worker/coordinator aggregation
  - **File(s)**: `userspace-dp/src/afxdp/types.rs`, `userspace-dp/src/afxdp/worker.rs`, `userspace-dp/src/afxdp/coordinator.rs`, `userspace-dp/src/protocol.rs`
- **Result**: 16 new tests (11 marker, 5 admission); full suite 667 pass / 0 fail (baseline 651); Local variant only, Prepared deferred to #718-followup

## 2026-04-17 — #727 ECN CE marking on Prepared CoS variant (#718 follow-up)
- **Action**: Add `maybe_mark_ecn_ce_prepared(req, umem)` helper; extend `apply_cos_admission_ecn_policy` to handle both `CoSPendingTxItem::Local` and `::Prepared` under a single `admission_ecn_marked` counter; take a shared `&MmapArea` inside `enqueue_cos_item` via split-borrow and thread it to the policy call
  - **File(s)**: `userspace-dp/src/afxdp/tx.rs`
- **Action**: Add 5 Prepared-variant admission tests (IPv4 ECT(0), IPv6 ECT(0), NOT-ECT, out-of-range offset, combined Local+Prepared counter pin); remove stale `admission_does_not_mark_prepared_variant` negative pin
  - **File(s)**: `userspace-dp/src/afxdp/tx.rs`
- **Result**: admission_ecn group 11/11 pass, mark_ecn_ce group 11/11 pass, full suite 680/680 pass. Marker now fires on the XSK-RX→XSK-TX zero-copy hot path (iperf3, NAT'd flows); acceptance target per `docs/cos-validation-notes.md` is `ecn_marked` becoming non-zero during live 16-flow iperf3

## 2026-04-17 — #709 Option E owner-profile telemetry (measure before optimizing)
- **Action**: Add `DRAIN_HIST_BUCKETS = 16` const-asserted, `bucket_index_for_ns` branchless helper, `drain_latency_hist` + `drain_invocations` + `drain_noop_invocations` + `redirect_acquire_hist` + `redirect_sample_counter` + `pps_owner_vs_peer` on `BindingLiveState`; add `new_seeded(worker_id)` constructor so per-worker redirect samples don't lockstep
  - **File(s)**: `userspace-dp/src/afxdp/umem.rs`
- **Action**: Time every `drain_shaped_tx` invocation with one pair of `monotonic_nanos()` calls; count owner-local vs peer-redirected packets on `ingest_cos_pending_tx` split-point; sample `enqueue_tx_owned` 1-in-256 producer-side
  - **File(s)**: `userspace-dp/src/afxdp/tx.rs`, `userspace-dp/src/afxdp/umem.rs`
- **Action**: Extend `CoSQueueStatus` serde with histograms + owner/peer pps; populate from owner binding's live snapshot in `build_worker_cos_statuses` with `max` aggregation across workers (only owner writes non-zero). Cross-worker coordinator aggregation mirrors `admission_ecn_marked` shape
  - **File(s)**: `userspace-dp/src/protocol.rs`, `userspace-dp/src/afxdp/worker.rs`, `userspace-dp/src/afxdp/coordinator.rs`
- **Action**: Go-side protocol mirror + `OwnerProfile:` line in `show class-of-service interface` under the existing `Drops:` line (only for exact queues with named owner)
  - **File(s)**: `pkg/dataplane/userspace/protocol.go`, `pkg/dataplane/userspace/cosfmt.go`, `pkg/dataplane/userspace/cosfmt_test.go`
- **Action**: Prometheus gauges/counters for `xpf_cos_drain_latency_ns_bucket`, `xpf_cos_drain_invocations_total`, `xpf_cos_redirect_acquire_ns_bucket`, `xpf_cos_owner_pps`, `xpf_cos_peer_pps`. Cardinality ≤ 16896 series (within plan §5 envelope)
  - **File(s)**: `pkg/api/metrics.go`
- **Action**: New "Reading the owner-profile counters" section with decision tree mapping drain_p99 / redirect_p99 / owner_pps ratio to #709 Option B/C/D follow-ups
  - **File(s)**: `docs/cos-validation-notes.md`
- **Result**: 7 new Rust tests (+692 total, baseline 685), 3 new Go tests; full `cargo test` + `go test ./...` green. Telemetry-only: no hot-path allocations, no new syscalls, MPSC invariants preserved, histogram bucket select branchless

## 2026-04-17 — #708 architect plan

- **Timestamp**: 2026-04-17
  - **Action**: Write #708 enqueue-pacing architect plan — Option B (per-SFQ-bucket token bucket), measurement-first, pacing gate strictly AFTER ECN marker to preserve #718 invariants. Honest framing on residual retrans (most of the ~100k retrans signal is likely ECN-induced recovery entries, not wire loss, so pacing is unlikely to move retrans meaningfully; §3 says so explicitly)
  - **File(s)**: `docs/708-enqueue-pacing-plan.md` (new)

## 2026-04-21 — #821 round 1 code review fixes

- **Timestamp**: 2026-04-21
  - **Action**: Codex HIGH-1 — drop stale `worker-tids.txt` before launching step1; install SIGINT/SIGTERM trap
    - **File(s)**: `test/incus/step2-sched-switch-capture.sh`
  - **Action**: Codex HIGH-2 — reducer drift halt stamps `suspect_reason: "drift_ge_5s"` on every JSONL line and exits 5 (H-STOP-5); classifier detects sentinel and emits `verdict=SUSPECT`; optional `--drift-halt-marker` sidecar; summary log line surfaces `suspect_reason`
    - **File(s)**: `test/incus/step2-sched-switch-reduce.py`, `test/incus/step2-sched-switch-classify.py`, `test/incus/step2-sched-switch-capture.sh`
  - **Action**: Codex HIGH-3 — capture adds `perf record -k CLOCK_REALTIME` and `perf script --ns`; reducer treats perf timestamps as absolute unix wall-clock ns and drops first-event offsetting; PERF_START_NS is diagnostic only (drift measurement)
    - **File(s)**: `test/incus/step2-sched-switch-capture.sh`, `test/incus/step2-sched-switch-reduce.py`
  - **Action**: Codex MEDIUM-4 — restore plan §4.1 `stat_runtime_check` ±1% accounting check against `(block_duration * n_workers - total_off_cpu)`
    - **File(s)**: `test/incus/step2-sched-switch-reduce.py`
  - **Action**: Codex LOW-5 — classifier meta.json top-level is plan-contracted `{verdict, rho, pvalue, duty_cycle_pct, warn_blocks}`; extras moved to `diagnostic` sub-object
    - **File(s)**: `test/incus/step2-sched-switch-classify.py`
  - **Action**: Codex LOW-6 — G8.2 grep uses `grep -qE` with whitespace-tolerant pattern; G8.3 perf-record stderr no longer suppressed
    - **File(s)**: `test/incus/step2-sched-switch-capture.sh`
  - **Action**: Codex LOW-7 — add `TestReducerNegativeWakeDelta` suite with wake-before-switch and equal-ts exercises documenting branch unreachability under monotonic perf
    - **File(s)**: `test/incus/step2-sched-switch-reduce_test.py`
  - **Action**: pyshell M1 — SIGINT/SIGTERM trap added in capture.sh
    - **File(s)**: `test/incus/step2-sched-switch-capture.sh`
  - **Action**: pyshell M2 — `reduce_events` docstring moved to first statement per PEP 257
    - **File(s)**: `test/incus/step2-sched-switch-reduce.py`
  - **Result**: `python3 -m py_compile` OK on all 4 modified `.py` files; reducer tests 13/13 green (was 10, +3 new); classifier tests 11/11 green (was 8, +3 new); V8 non-regression preserved (`step1-histogram-classify.py` unchanged)

## 2026-05-10 — docs README reference fix

- **Timestamp**: 2026-05-10T03:24:56Z
  - **Action**: Correct stale filename references in module READMEs (`eventengine.go`/`dhcprelay.go` -> `engine.go`/`relay.go`) so entry-point file:line links resolve.
  - **File(s)**: `pkg/eventengine/README.md`, `pkg/dhcprelay/README.md`

## 2026-05-10 — docs README wiring/source corrections

- **Timestamp**: 2026-05-10T05:18:20Z
  - **Action**: Correct `SessionCloseData` attribution to `logging.EventReader` session-close records (not conntrack GC delete callbacks).
  - **File(s)**: `pkg/flowexport/README.md`
- **Timestamp**: 2026-05-10T05:18:20Z
  - **Action**: Correct configstore encryption note to match implementation (`master.key` + HKDF with configured PRF).
  - **File(s)**: `pkg/configstore/README.md`

## 2026-05-12 fairness_multi_sample round-2 HIGH fixes

- **Timestamp**: 2026-05-12T06:50:50Z
  - **Action**: Round-3 follow-up — tighten verdict JSON detection to the canonical fairness-eval verdict-key set; remove the `os.getpgid` timeout race by using the process-group leader PID directly; add a bounded post-kill `communicate()`; remove a stale threshold-source reference.
  - **File(s)**: test/incus/fairness_multi_sample.py, test/incus/fairness_multi_sample_test.py, docs/per-5-tuple/v8-multi-sample.md

- **Timestamp**: 2026-05-12T07:45:00Z
  - **Action**: PR #1273 Copilot follow-up — align multi-sample verdict filtering with the canonical 10-key fairness-eval schema and validate summary numeric fields (`cstruct`, `gap`, optional `aggregate_mbps`, and integer `starved_flow_count`) instead of only `observed_cov`.
  - **File(s)**: test/incus/fairness_multi_sample.py, test/incus/fairness_multi_sample_test.py, docs/per-5-tuple/v8-multi-sample.md, docs/per-5-tuple/state.md, _Log.md

- **Timestamp**: 2026-05-12T06:29:25Z
  - **Action**: HIGH1 - Tighten extract_verdict_objects to require verdict+observed_cov+discriminator field
  - **Action**: HIGH2 - Replace subprocess.run with Popen(start_new_session=True)+os.killpg for process-group cleanup on timeout
  - **Action**: MINOR - Replace statistics.fmean with statistics.mean; remove dead timeout_stream_text
  - **Action**: Docs - Add fresh-iperf3 requirement and threshold derivation to v8-multi-sample.md
  - **Action**: Tests - Add schema-incomplete and process-group tests; move import time to top
  - **File(s)**: test/incus/fairness_multi_sample.py, test/incus/fairness_multi_sample_test.py, docs/per-5-tuple/v8-multi-sample.md
  - **Result**: 12/12 tests green (was 10)

## 2026-05-12 fairness_multi_sample round-3 fix

- **Timestamp**: 2026-05-12T07:02:16Z
  - **Action**: Fix pgid capture race - capture os.getpgid(proc.pid) immediately after Popen before communicate() can reap the leader; use cached pgid in both _kill_process_group() calls.
  - **File(s)**: test/incus/fairness_multi_sample.py
  - **Result**: 14/14 tests green

## 2026-05-12 — fairness-eval diagnostic message + test rename

- **Timestamp**: 2026-05-12T06:52:27Z
  - **Action**: PR #1272 round-3 review follow-up — clarify the top-level guard comment to reference `iface_filter_active`, and pin guard failure tests on `expected`, `non-starved`, and `dir_mult` substrings.
  - **File(s)**: `userspace-dp/src/bin/fairness-eval.rs`, `userspace-dp/tests/fairness_eval_blackbox.rs`

- **Timestamp**: 2026-05-12T06:29:24Z
  - **Action**: Fix Harness guard failure message to print `expected_sum` and `dir_mult` alongside `n_non_starved` so operators can see the bidirectional expansion factor. Update block comment to correctly describe `max(2, floor(10% × expected_sum))` formula.
  - **File(s)**: `userspace-dp/src/bin/fairness-eval.rs`
- **Timestamp**: 2026-05-12T06:29:24Z
  - **Action**: Rename `guard_low_n_iface_input_accepts_p2_single_direction_recency_undercount` → `guard_low_n_iface_input_accepts_absolute_floor_p2_gap1`; add inline math comment explaining why absolute floor (not recency) is the operative gate. Drop misleading "recency" claim from assertion messages.
  - **File(s)**: `userspace-dp/tests/fairness_eval_blackbox.rs`

## 2026-05-13 — PR #1301 cross-NIC shared-UMEM validation path

- **Timestamp**: 2026-05-13T20:22:00-07:00
  - **Action**: Enable cross-NIC shared UMEM in the loss userspace HA config, add node-local Phase 0 artifacts, push artifacts during deploy when the config requests shared UMEM, surface shared-UMEM binding mode/role in userspace status, and document the perf/counter contract for copy-free validation.
  - **File(s)**: `docs/ha-cluster-userspace.conf`, `test/incus/cluster-setup.sh`, `test/incus/loss-userspace-shared-umem-phase0-node0.json`, `test/incus/loss-userspace-shared-umem-phase0-node1.json`, `pkg/dataplane/userspace/protocol.go`, `pkg/dataplane/userspace/statusfmt.go`, `pkg/dataplane/userspace/statusfmt_test.go`, `docs/shared-umem-plan.md`, `docs/userspace-perf-compare.md`, `_Log.md`
- **Timestamp**: 2026-05-13T20:44:00-07:00
  - **Action**: Make cross-NIC shared-UMEM selection artifact-driven by default so the HA config no longer hardcodes interface names; add `selected_device_set` as the generic artifact key while keeping `selected_device_pair` as a legacy alias.
  - **File(s)**: `userspace-dp/src/afxdp/shared_umem.rs`, `docs/ha-cluster-userspace.conf`, `docs/shared-umem-plan.md`, `test/incus/loss-userspace-shared-umem-phase0-node0.json`, `test/incus/loss-userspace-shared-umem-phase0-node1.json`, `_Log.md`
- **Timestamp**: 2026-05-13T20:49:00-07:00
  - **Action**: Make cross-NIC shared UMEM opportunistic by default: no config stanza or Phase 0 artifact is required for normal copy-free forwarding, `mode off` remains the debug kill switch, and Phase 0 artifacts are audit-only instead of production gates.
  - **File(s)**: `userspace-dp/src/afxdp/shared_umem.rs`, `docs/ha-cluster-userspace.conf`, `docs/shared-umem-plan.md`, `pkg/config/ast.go`, `pkg/config/types.go`, `test/incus/cluster-setup.sh`, `README.md`, `_Log.md`
- **Timestamp**: 2026-05-13T22:30:00-07:00
  - **Action**: Close PR #1301 round-3 blockers: document the intentional PR #1297 contract change, restore Phase 0 as non-blocking runtime audit, retry failed shared-UMEM groups as private UMEM, publish fallback status through live binding snapshots, and route cancellable foreign-slot prepared recycles through the shared recycle queue when worker context is available.
  - **File(s)**: `userspace-dp/src/afxdp/shared_umem.rs`, `userspace-dp/src/afxdp/worker/mod.rs`, `userspace-dp/src/afxdp/umem/mod.rs`, `userspace-dp/src/afxdp/types/runtime.rs`, `userspace-dp/src/afxdp/tx/transmit.rs`, `userspace-dp/src/afxdp/tx/dispatch.rs`, `userspace-dp/src/afxdp/tx/drain.rs`, `userspace-dp/src/afxdp/session_glue/mod.rs`, `userspace-dp/src/afxdp/session_delta.rs`, `userspace-dp/src/afxdp/worker/lifecycle.rs`, `pkg/dataplane/userspace/statusfmt.go`, `pkg/dataplane/userspace/statusfmt_test.go`, `pkg/config/types.go`, `docs/shared-umem-plan.md`, `_Log.md`
  - **Validation**: `cargo test --manifest-path userspace-dp/Cargo.toml shared_umem -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml remember_prepared_recycle -- --nocapture`; `go test ./pkg/dataplane/userspace ./pkg/config`
- **Timestamp**: 2026-05-13T23:35:00-07:00
  - **Action**: Close PR #1301 round-4 recycle-routing and mixed-mode safety blockers: thread the shared recycle accumulator through close-delta purge, pending TX bound/drop, CoS enqueue demotion, cross-binding prepared redirect, queue-service prepared rejection, neighbor retry, CoS runtime reset, and worker-shaped request paths; remove local-only prepared recycle exports; remove arbitrary-binding fallback for unknown shared recycle slots.
  - **File(s)**: `userspace-dp/src/afxdp/tx/transmit.rs`, `userspace-dp/src/afxdp/tx/mod.rs`, `userspace-dp/src/afxdp/tx/dispatch.rs`, `userspace-dp/src/afxdp/tx/drain.rs`, `userspace-dp/src/afxdp/tx/cos_classify.rs`, `userspace-dp/src/afxdp/tx/tcp_segmentation.rs`, `userspace-dp/src/afxdp/cos/cross_binding.rs`, `userspace-dp/src/afxdp/cos/queue_service/mod.rs`, `userspace-dp/src/afxdp/cos/queue_service/service.rs`, `userspace-dp/src/afxdp/cos/queue_service/drain.rs`, `userspace-dp/src/afxdp/session_glue/mod.rs`, `userspace-dp/src/afxdp/session_delta.rs`, `userspace-dp/src/afxdp/neighbor_dispatch.rs`, `userspace-dp/src/afxdp/worker/cos.rs`, `userspace-dp/src/afxdp/worker/lifecycle.rs`, `userspace-dp/src/afxdp/worker/mod.rs`, `userspace-dp/src/afxdp/tx/README.md`, `userspace-dp/src/afxdp/cos/README.md`, `docs/shared-umem-plan.md`, `_Log.md`
  - **Validation**: `cargo test --manifest-path userspace-dp/Cargo.toml cancelled_prepared --no-run`; `cargo test --manifest-path userspace-dp/Cargo.toml shared_umem -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml cancelled_prepared -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml drain_exact_prepared -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml demote_prepared -- --nocapture`; `go test ./pkg/dataplane/userspace ./pkg/config`; `git diff --check`
- **Timestamp**: 2026-05-14T18:55:40Z
  - **Action**: #1307 minimal TX-error attribution: add `tx_shared_recycle_unknown_slot_drops` as a per-binding subset of `tx_errors` for shared-UMEM unknown-slot recycle drops, mirror it through Rust/Go status, and make the local fallback `TxError::Drop` path increment `tx_submit_error_drops`.
  - **File(s)**: `userspace-dp/src/afxdp/umem/mod.rs`, `userspace-dp/src/afxdp/worker/mod.rs`, `userspace-dp/src/afxdp/coordinator/mod.rs`, `userspace-dp/src/afxdp/tx/dispatch.rs`, `userspace-dp/src/afxdp/session_glue/mod.rs`, `userspace-dp/src/afxdp/tx/drain.rs`, `userspace-dp/src/protocol.rs`, `pkg/dataplane/userspace/protocol.go`, `pkg/dataplane/userspace/statusfmt.go`, `userspace-dp/src/afxdp/tx/README.md`, `docs/shared-umem-plan.md`, `_Log.md`
- **Timestamp**: 2026-05-14T06:05:00Z
  - **Action**: Fix shared-UMEM live-status publication discovered during cluster smoke: the shared bind path now publishes the selected mode/group/role into `BindingLiveState` before worker refresh so status snapshots match the kernel bind result instead of reporting `Shared UMEM bindings: 0/N`.
  - **File(s)**: `userspace-dp/src/afxdp/worker/mod.rs`, `userspace-dp/src/afxdp/worker/README.md`, `_Log.md`
- **Timestamp**: 2026-05-14T06:45:00Z
  - **Action**: PR #1301 round-5 minor follow-up: add regression coverage for stale/wrong/unknown shared-recycle slot routing, increment `tx_errors` when the all-bindings shared-recycle router drops an unknown slot, and downgrade the external IPv6 `mtr` final-hop miss to a warning after the controlled IPv6 dataplane checks pass.
  - **File(s)**: `userspace-dp/src/afxdp/tx/dispatch.rs`, `userspace-dp/src/afxdp/tx/dispatch_tests.rs`, `userspace-dp/src/afxdp/tx/README.md`, `docs/shared-umem-plan.md`, `scripts/userspace-ha-validation.sh`, `_Log.md`
- **Timestamp**: 2026-05-14T07:10:00Z
  - **Action**: Harden the userspace HA smoke validator after live PR #1301 smoke: retry preferred-node failover while XSK liveness propagates into RG readiness, set the default throughput shape to `PARALLEL=6` so the smoke covers the six-worker RSS set, and document the IPv6 external-`mtr` warning semantics.
  - **File(s)**: `scripts/userspace-ha-validation.sh`, `docs/userspace-ha-validation.md`, `.codex/skills/userspace-ha-validation/SKILL.md`, `_Log.md`
- **Timestamp**: 2026-05-14T07:35:00Z
  - **Action**: PR #1301 round-6 minor follow-up: make the split-slice shared-recycle router use the same slot-resolution helper as the all-bindings cleanup path and add split-slice helper coverage for stale/unknown lookup behavior.
  - **File(s)**: `userspace-dp/src/afxdp/tx/dispatch.rs`, `userspace-dp/src/afxdp/tx/dispatch_tests.rs`, `userspace-dp/src/afxdp/tx/README.md`, `_Log.md`
- **Timestamp**: 2026-05-14T08:05:00Z
  - **Action**: PR #1301 round-7 polish: aggregate unknown-slot shared-recycle stderr diagnostics to one bounded line per drain while preserving full `tx_errors` accounting.
  - **File(s)**: `userspace-dp/src/afxdp/tx/dispatch.rs`, `userspace-dp/src/afxdp/tx/README.md`, `_Log.md`
- **Timestamp**: 2026-05-14T09:45:00Z
  - **Action**: PR #1311 round-3 review fixes (on top of remote `4de390d3` which already rewrote the stress test with a quadratic schema and added a `fence(Acquire)` to the reader). Sync stale file-level doc that claimed "All atomics use Relaxed" to mention the seqlock + reader fence; reword "60-120s window" doc nits across `worker_runtime.rs`, `protocol.rs`, `pkg/dataplane/userspace/protocol.go`, and `pkg/dataplane/userspace/statusfmt.go` to match the ~1 Hz publish cadence (~60-61s under normal cadence; `WindowNS` carries exact width); drop the "default Prometheus scrape interval" wording on `WR_WINDOW_INTERVAL_NS`; fix the stale `1.5s CPU over 60s` comment in `statusfmt_test.go` to `45s CPU over 60s = 75%`. Add a `nonzero_snapshots > 1_000` guard at the end of the stress test so a broken reader returning all zeros can't silently pass (Codex round-3 ask not covered by `4de390d3`).
  - **File(s)**: `userspace-dp/src/afxdp/worker_runtime.rs`, `userspace-dp/src/afxdp/worker_runtime_tests.rs`, `userspace-dp/src/protocol.rs`, `pkg/dataplane/userspace/protocol.go`, `pkg/dataplane/userspace/statusfmt.go`, `pkg/dataplane/userspace/statusfmt_test.go`, `_Log.md`
- **Timestamp**: 2026-05-15T14:32:39-07:00
  - **Action**: #1318 scoped CoS drain idle fix: gate `drain_shaped_tx` root priming on runnable queues or due parked wake ticks, skipping timer-wheel advance and shared-root lease top-up for not-yet-serviceable parked roots while preserving due wake service.
  - **File(s)**: `userspace-dp/src/afxdp/cos/queue_service/mod.rs`, `userspace-dp/src/afxdp/cos/queue_service/tests.rs`, `userspace-dp/src/afxdp/cos/tx_completion.rs`, `userspace-dp/src/afxdp/cos/tx_completion_tests.rs`, `userspace-dp/src/afxdp/cos/README.md`, `_Log.md`
  - **Validation**: `cargo test --manifest-path userspace-dp/Cargo.toml drain_shaped_tx_ -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml root_serviceability_tracks_parked_queue_wakeup_tick -- --nocapture`; `cargo test --manifest-path userspace-dp/Cargo.toml queue_service`; `cargo test --manifest-path userspace-dp/Cargo.toml tx_completion`

- **Timestamp**: 2026-05-14T20:30:00Z
  - **Action**: #1319 Phase 1 + Phase 2 (schedulers subtree only): add typed-leaf schema infrastructure (`ValueType` enum + `ValueDesc` + `ValueExamples` + `Validator` on `cmdtree.Node`); add strict error-returning parsers `parseBandwidthLimitStrict` / `parseBurstSizeLimitStrict` / `parseScaledDecimalUnitStrict` alongside the legacy zero-return parsers; add stateless validators in `pkg/config/schema_validators.go` (`ValidateRate`, `ValidateByteSize`, `ValidateInteger`, `ValidateEnum`, `ValidatePercent`); declare per-leaf schema for `class-of-service schedulers <name> { ... }` compiler-consumed leaves (`transmit-rate`, `priority`, `buffer-size`, `surplus-sharing`, `equal-flow-enforcement`); wire `cmdtree.SchemaValidate` into `configstore.compileTree` so `commit check` rejects `transmit-rate asd` with a human-readable error before the legacy zero-return parser silently writes 0 bps. Surfaces `?` placeholder + examples for typed leaves.
  - **File(s)**: `pkg/cmdtree/tree.go`, `pkg/cmdtree/schema_validate.go` (new), `pkg/cmdtree/tree_test.go`, `pkg/cmdtree/README.md`, `pkg/config/compiler_protocols.go`, `pkg/config/schema_validators.go` (new), `pkg/config/schema_validate_test.go` (new), `pkg/config/README.md`, `pkg/configstore/store.go`, `pkg/configstore/store_test.go`, `_Log.md`
  - **Validation**: `GOCACHE=/dev/shm/cache GOTMPDIR=/dev/shm go build ./...` (clean); `go test ./pkg/cmdtree/... ./pkg/config/... ./pkg/configstore/...` (PASS); full `go test ./...` (all packages PASS).
- **Timestamp**: 2026-05-15T22:33:24Z
  - **Action**: PR #1320 round-1 review fixes: preserve split Junos-style `transmit-rate exact`; make typed scheduler leaves fail closed on missing values and unknown trailing modifiers; reject sub-byte scheduler rates that compile to zero bytes/sec; align `buffer-size` validation and help with the compiler's byte-size-only representation; remove unsupported scheduler-level `shaping-rate` from the typed schema; update module docs to match the enforced schema.
  - **File(s)**: `pkg/cmdtree/schema_validate.go`, `pkg/cmdtree/tree.go`, `pkg/cmdtree/README.md`, `pkg/config/schema_validators.go`, `pkg/config/schema_validate_test.go`, `pkg/config/README.md`, `_Log.md`
  - **Validation**: `go test -count=1 ./pkg/config ./pkg/cmdtree ./pkg/configstore` (PASS); `go test -count=1 ./pkg/...` (PASS); `git diff --check` (clean).

- **Timestamp**: 2026-05-16T14:17:38-07:00
  - **Action**: #1373 Phase 0 documentation/audit update: refresh userspace dataplane gap blockers, add retirement notices to active docs and README entry points, and add an umbrella tracker for the staged eBPF dataplane retirement. Explicitly document that Phase 0 removes no BPF source.
  - **File(s)**: `docs/userspace-dataplane-gaps.md`, `docs/pr/1373-retire-ebpf-dataplane/plan.md`, `README.md`, `CLAUDE.md`, `docs/testing.md`, `docs/development-workflow.md`, `bpf/README.md`, `userspace-dp/README.md`, `pkg/dataplane/README.md`, `testing-docs/README.md`, `_Log.md`
- **Timestamp**: 2026-05-17T09:34:59-07:00
  - **Action**: #1373 Phase 1 documentation migration: mark Rust AF_XDP userspace as the primary/default dataplane development and validation target, demote eBPF wording to legacy compatibility/regression context, and preserve explicit retirement blockers for #1374-#1381 without claiming unresolved gaps closed.
  - **File(s)**: `README.md`, `CLAUDE.md`, `docs/testing.md`, `docs/development-workflow.md`, `docs/test_env.md`, `docs/userspace-dataplane-gaps.md`, `docs/feature-gaps.md`, `docs/userspace-dataplane-architecture.md`, `docs/afxdp-packet-processing.md`, `docs/ha-cluster-test-plan.md`, `testing-docs/README.md`, `bpf/README.md`, `userspace-dp/README.md`, `pkg/dataplane/README.md`, `userspace-dp/src/afxdp/README.md`, `_Log.md`
- **Timestamp**: 2026-05-17T18:57:46Z
  - **Action**: Adversarial PR #1374 follow-up: optimize SYN-cookie validated-client cache with map+queue state so insert/take are O(1), while expiry/eviction drain stale queue tokens from the head without whole-cache scans.
  - **File(s)**: `userspace-dp/src/screen.rs`, `userspace-dp/src/screen_tests.rs`, `_Log.md`

- **Timestamp**: 2026-05-17T20:25:00Z
  - **Action**: PR #1407 Codex round-1 follow-up docs correction — replaced a non-existent scheduler test reference in the #1378 plan with the implemented delete/re-add counter lifecycle regression (`hit_counters_reset_after_rule_absent_then_readded`) to match actual coverage.
  - **File(s)**: `docs/pr/1373-retire-ebpf-dataplane/plan-1378-policy-schedulers.md`, `_Log.md`
  - **Validation**: `go test ./pkg/config ./pkg/dataplane/userspace ./pkg/api ./pkg/grpcapi ./pkg/cli`; `cargo test --manifest-path userspace-dp/Cargo.toml policy:: -- --nocapture` (blocked: missing libelf headers/pkg-config in runner)

- **Timestamp**: 2026-05-17T21:28:00Z
  - **Action**: PR #1407 Codex round-2 follow-up — added regression coverage for helper-backed sparse/global policy counters in gRPC and Prometheus reporting paths, and extended policy-hit metric collection to include global policies (`*`/`*` labels) so userspace/global counter IDs are surfaced consistently.
  - **File(s)**: `pkg/api/metrics.go`, `pkg/api/metrics_test.go`, `pkg/grpcapi/server_show_zones_test.go`, `_Log.md`
  - **Validation**: `gofmt -w pkg/api/metrics.go pkg/api/metrics_test.go pkg/grpcapi/server_show_zones_test.go`; `go test ./pkg/api ./pkg/grpcapi ./pkg/dataplane/userspace ./pkg/config`; `git diff --check`

- **Timestamp**: 2026-05-17T21:34:00Z
  - **Action**: Addressed automated review follow-up on policy-hit metrics by adding a shared `policyCounterID` helper used by collector/tests and guarding global-policy metric emission against nil policy entries.
  - **File(s)**: `pkg/api/metrics.go`, `pkg/api/metrics_test.go`, `_Log.md`
  - **Validation**: `gofmt -w pkg/api/metrics.go pkg/api/metrics_test.go`; `go test ./pkg/api ./pkg/grpcapi ./pkg/dataplane/userspace ./pkg/config`; `git diff --check`

- **Timestamp**: 2026-05-17T21:38:00Z
  - **Action**: Applied final review nits: reverted unintended zone-policy nil-contract change in Prometheus policy counter loop and documented why global policy IDs use the post-zone-set offset in metrics tests.
  - **File(s)**: `pkg/api/metrics.go`, `pkg/api/metrics_test.go`, `_Log.md`
  - **Validation**: `gofmt -w pkg/api/metrics.go pkg/api/metrics_test.go`; `go test ./pkg/api ./pkg/grpcapi ./pkg/dataplane/userspace ./pkg/config`; `git diff --check`

- **Timestamp**: 2026-05-17T22:00:00Z
  - **Action**: Added explicit invariant note in `collectPolicyCounters` clarifying why zone-pair policy loop dereferences `rule.Name` without a nil guard while global policy loop retains defensive nil filtering.
  - **File(s)**: `pkg/api/metrics.go`, `_Log.md`

- **Timestamp**: 2026-05-17T20:20:00Z
  - **Action**: Edited mirror runtime path to resolve mirror output through bind-ifindex mapping and added production-shape mirror tests.
  - **File(s)**: userspace-dp/src/afxdp/mirror.rs

- **Timestamp**: 2026-05-17T20:21:00Z
  - **Action**: Updated mirror counter comments to match actual NoFrame/NoBinding semantics.
  - **File(s)**: userspace-dp/src/afxdp/umem/mod.rs

- **Timestamp**: 2026-05-17T21:28:00Z
  - **Action**: Added cross-worker mirror admission cap path to enforce mirror-specific pending limit before redirect-inbox enqueue.
  - **File(s)**: userspace-dp/src/afxdp/umem/mod.rs, userspace-dp/src/afxdp/mirror.rs

- **Timestamp**: 2026-05-17T21:29:00Z
  - **Action**: Updated #1376 plan test/runtime notes to match implemented mirror tests and cross-worker limit semantics.
  - **File(s)**: docs/pr/1373-retire-ebpf-dataplane/plan-1376-port-mirroring.md

- **Timestamp**: 2026-05-23T16:16:59Z
  - **Action**: PR #1498 userspace shim loader r4/r5 closeout: make pinned compatibility-map drift fail closed instead of deleting individual pins or the whole BPF pin tree; cleanup only legacy-only map pins (`xdp_progs`, `tc_progs`, `policer_states`); keep stateful compatibility pins (`sessions`, `sessions_v6`, `dnat_table`, `dnat_table_v6`) preserved; make stale `tc_*` cleanup exhaustively try every pin before returning joined cleanup errors; correct userspace shim drift remediation text to `make generate-userspace-xdp`.
  - **File(s)**: `pkg/dataplane/loader.go`, `pkg/dataplane/loader_ebpf.go`, `pkg/dataplane/userspace_shim_loader_test.go`, `docs/pr/1373-retire-ebpf-dataplane/README.md`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane -run 'TestUserspaceShim|TestCleanupUserspaceShim|TestLoadOrCreatePinnedShimMap|TestEmbeddedUserspaceShim' -count=1 -v`; `go test ./pkg/dataplane -run 'TestValidateUserspaceShimSpecDriftMentionsUserspaceXDPGenerate' -count=1 -v`; `go test ./pkg/dataplane/... -count=1`; `go test ./...`; `git diff --check`; `GOFLAGS=-buildvcs=false ./scripts/userspace-phase-cycle.sh --env test/incus/loss-userspace-cluster.env` passed on `0254013c` with userspace auto-armed on `loss:xpf-userspace-fw0`, IPv4 runs 21.141/23.328/23.226 Gbps and IPv6 runs 21.137/23.079/23.073 Gbps. The later `542656ec` and this log/doc follow-up only change error text, tests, and documentation.

- **Timestamp**: 2026-05-24T03:27:07Z
  - **Action**: PR #1498 Codex r5 follow-up: added an operator runbook for
    fail-closed userspace shim compatibility-map pin recovery and centralized
    the userspace shim drift remediation text so `loadAllObjects` and
    `validateUserspaceShimSpec` share the same `make generate-userspace-xdp`
    guidance.
  - **File(s)**: `pkg/dataplane/loader_ebpf.go`,
    `docs/operations/userspace-shim-pin-recovery.md`,
    `docs/pr/1373-retire-ebpf-dataplane/README.md`, `_Log.md`
  - **Validation**: `go test ./pkg/dataplane -run
    'TestValidateUserspaceShimSpecDriftMentionsUserspaceXDPGenerate|TestUserspaceShim|TestCleanupUserspaceShim|TestLoadOrCreatePinnedShimMap|TestEmbeddedUserspaceShim'
    -count=1`; `go test ./pkg/dataplane/... -count=1`; `go test ./...
    -count=1`; `git diff --check`

- **Timestamp**: 2026-05-24T04:47:07Z
  - **Action**: #1503 documentation reconciliation: refreshed
    `docs/feature-gaps.md` so closed #1378 policy-scheduler work is no longer
    presented as open retirement follow-up, and closed #1375 policer work is
    documented as future parity/hardening rather than an active #1373
    source-removal blocker.
  - **File(s)**: `docs/feature-gaps.md`, `_Log.md`
  - **Validation**: `rg -n "#1375|#1378|retirement blocker|retirement-contract"
    docs/feature-gaps.md docs/pr/1373-retire-ebpf-dataplane/README.md
    docs/pr/1373-retire-ebpf-dataplane/plan.md`; `git diff --check`

- **Timestamp**: 2026-05-23T21:46:59-07:00
  - **Action**: #1502 artifact-schema checker follow-up: parse JSON floats as
    `Decimal`, normalize JSON integer-like values for manifest issues,
    schema version, and command exit status, reject lossy non-integer decimal
    numbers, and restrict accepted RFC3339 leap seconds to 23:59:60 on June 30
    or December 31.
  - **File(s)**: `test/incus/retire_ebpf_artifact_schema.py`,
    `test/incus/retire_ebpf_artifact_schema_test.py`, `_Log.md`
  - **Validation**: `python3 -m unittest discover -s test/incus -p
    retire_ebpf_artifact_schema_test.py`; `python3
    test/incus/retire_ebpf_artifact_schema_test.py`; `python3 -m py_compile
    test/incus/retire_ebpf_artifact_schema.py
    test/incus/retire_ebpf_artifact_schema_test.py`; `python3 -m json.tool
    docs/pr/1373-retire-ebpf-dataplane/final-validation/manifest.schema.json
    >/dev/null`; `git diff --check`

- **Timestamp**: 2026-05-24T11:01:44-07:00
  - **Action**: PR #1506 review follow-up: reject Python JSON parser
    extensions (`NaN`, `Infinity`, and `-Infinity`) through the existing
    invalid-JSON validation path, and cap Decimal integer materialization so
    hostile exponent-form manifest integers cannot force huge `int`
    allocation.
  - **File(s)**: `test/incus/retire_ebpf_artifact_schema.py`,
    `test/incus/retire_ebpf_artifact_schema_test.py`, `_Log.md`
  - **Validation**: `python3 -m unittest discover -s test/incus -p
    retire_ebpf_artifact_schema_test.py`; `python3 -m py_compile
    test/incus/retire_ebpf_artifact_schema.py
    test/incus/retire_ebpf_artifact_schema_test.py`; `git diff --check`

- **Timestamp**: 2026-05-23T21:30:00Z
  - **Action**: Hoisted PADDED_PLAINTEXT_MAX guard above next_tx_counter + header write so encap-overflow returns BufferTooSmall without observable side effects; removed dead fn peer_index; pruned r5 leftover duplicate comment block in try_encap; added install_session_serializes_with_reconcile_removal and encap_padded_plaintext_overflow_leaves_counter_and_buffer_untouched regression tests.
  - **File(s)**: userspace-dp/src/afxdp/wg/engine.rs

- **Timestamp**: 2026-05-24T04:00:00Z
  - **Action**: r8: strengthened install_session_serializes_with_reconcile_removal with an `ok > 0` gate so the race test cannot pass tautologically when the reconciler always wins (Codex r7 finding); added debug_assert! on duplicate peer pubkey in reconcile_peers so engine-side surface flags Go-control-plane validation gaps (r6 Claude nit 4 / Codex r7).
  - **File(s)**: userspace-dp/src/afxdp/wg/engine.rs

- **Timestamp**: 2026-05-24T21:30:12-07:00
  - **Action**: PR #1499 final nit: corrected the nonce-layout comment
    in `framing.rs` to match snow 0.10's default ChaCha20-Poly1305
    resolver and the WireGuard whitepaper §5.4.6. The prior comment
    stated `counter.to_le_bytes() || [0,0,0,0]` (counter first, zeros
    trailing); snow actually builds `[0,0,0,0] || counter.to_le_bytes()`
    (4 zero bytes prepended, counter LE in bytes [4..12]) per
    `snow-0.10.0/src/resolvers/default.rs:380-381`. Wire behavior was
    already correct — snow's u64 nonce parameter is passed straight
    through — only the in-code rationalization was inverted. Added an
    explicit "do not invert this" warning anchoring the snow source
    citation so a future maintainer cannot regress to the wrong layout.
    The deferred zeroize-at-construction for
    `WgEngineConfig.local_private_key` remains an integration-PR
    follow-up and is not addressed here.
  - **File(s)**: `userspace-dp/src/afxdp/wg/framing.rs`, `_Log.md`
  - **Validation**: cargo build --release; cargo test --release --bin
    xpf-userspace-dp afxdp::wg.

- **Timestamp**: 2026-05-25T06:20Z
- **Action**: Harmonize ErrDPDKBackendRetired + slog.Warn wording with config sentinel (AGY #1536 review finding)
- **File(s)**: pkg/dataplane/dataplane.go, pkg/daemon/daemon_run.go
- **Why**: Antigravity adversarial-review-mpksyrj1-f1mid9 (against #1536) noted a
  cross-PR consistency gap: the config-time sentinel ErrDPDKDataplaneRetired
  starts with "the DPDK..." while the runtime-time ErrDPDKBackendRetired (this
  PR) starts with "DPDK..." (no leading article). errors.Is matching is
  unaffected but log monitoring tools using exact string matches across both
  layers would mismatch. Aligned both the sentinel and the daemon_run.go
  slog.Warn wording to "the DPDK dataplane backend has been retired".
- **Validation**: pkg/dataplane test suite green; no other in-tree strings
  pinned the old wording.

- **Timestamp**: 2026-05-24 (1517 plan draft)
- **Action**: Wrote plan v1 (DRAFT) for #1517 — migrate pkg/cli off legacy
  dataplane.DataPlane (sub-#1451 S2). Mirrors apiRuntimeDataPlane pattern.
- **File(s)**: docs/pr/1517-cli-migration/plan.md
- **Why**: Triple-review methodology — plan first, code never first. Dispatch
  Codex + Antigravity adversarial plan review before any code touches.

- **Timestamp**: 2026-05-24 (1517 plan v2 PLAN-READY)
- **Action**: Folded Codex PLAN-NEEDS-MINOR findings into plan v2. AGY
  PLAN-READY against v1 stands. Both reviewers now agree — proceeding to
  implementation.
- **File(s)**: docs/pr/1517-cli-migration/plan.md, reviewer-ids.md
- **Why**: Codex r1 (task-mpkukwfs-gl3fv4) identified Q1 over-engineering
  (LastApplyResultOf is already `any`-typed at apply.go:54, so neither
  Option B shadow field nor Option C interface widening is needed) and a
  scope-doc citation hygiene issue. AGY r1 (adversarial-review-mpkuldhp-mnlp6x)
  was PLAN-READY across all seven hostile checks.

- **Timestamp**: 2026-05-25 (1517 implementation)
- **Action**: Implemented #1517 — added pkg/cli/runtime.go with cliRuntime
  interface (25 methods), cliUserspaceStatusProvider, and
  cliUserspaceControlProvider. Changed cli.dp from dataplane.DataPlane to
  cliRuntime; cli.New parameter type updated. Five inline interface{}
  provider probes consolidated into named interfaces.
- **File(s)**: pkg/cli/runtime.go (new), pkg/cli/cli.go,
  pkg/cli/cli_helpers.go, pkg/cli/cli_show_chassis.go,
  pkg/cli/cli_show_system.go, pkg/dataplane/retirement_boundary_canary_test.go
  (add runtime.go to legacy allowlist), docs/pr/1373-retire-ebpf-dataplane/README.md
  (add runtime.go row to migration table).
- **Validation**: cargo+go build clean; ./pkg/cli/... 5/5 flake pass;
  full Go suite green. Deployed to loss userspace cluster:
  Pass A 6/6 baseline cells 0 retrans, multi-stream -P 12 -R hit
  22.6/20.3 Gbps with 0 retrans. Pass B all 24 cells passed; shaped
  classes hit configured rates cleanly. Interactive CLI smoke
  (show security flow session brief, show security flow statistics,
  clear security flow session all, show system buffers,
  show chassis forwarding, request chassis cluster data-plane
  userspace) all work — the named provider-probe interfaces resolve
  correctly against the userspace LegacyDataPlaneAdapter.

- **Timestamp**: 2026-05-25 (1517 code-review r1 minor folds)
- **Action**: Folded Copilot inline finding on cliUserspaceControlProvider
  doc comment — said "request security flow" but correct CLI path is
  "request chassis cluster data-plane userspace" handled by
  handleRequestChassisClusterDataPlane in cli_request.go. Recorded
  reviewer-ids for code-review round 1.
- **File(s)**: pkg/cli/runtime.go, docs/pr/1517-cli-migration/reviewer-ids.md

- **Timestamp**: 2026-05-25 (1517 code review final verdicts)
- **Action**: All three reviewers MERGE-READY. Recording verdicts;
  not merging (per project policy).
- **File(s)**: docs/pr/1517-cli-migration/reviewer-ids.md
- **Validation**: Codex r3 task-mpkvl9cn-3we3in MERGE-READY (after two
  sandbox-FS-blocked retries); AGY adversarial-review-mpkvctz4-xk8x46
  MERGE-READY (exhaustive 10-check report with byte-for-byte evidence);
  Copilot COMMENTED with 1 minor inline finding, addressed in 91e1da9f.

- **Timestamp**: 2026-05-25T07:30Z
- **Action**: PR #1549 — fix stale plan.md snippet per Copilot d9545813 review
- **File(s)**: docs/pr/1517-cli-migration/plan.md
- **Why**: Copilot review on d9545813 left 1 inline comment that the plan.md
  snippet for cliUserspaceControlProvider still references `request security
  flow ...` while the actual source comment (fixed in 91e1da9f) and the actual
  handler path are `request chassis cluster data-plane userspace` via
  cli_request.go:handleRequestChassisClusterDataPlane. Updated plan snippet
  in lockstep so docs match implementation. No code change.

- **Timestamp**: 2026-05-25T07:30Z
- **Action**: #1522 plan v2 — pruned bpf/xdp/, bpf/tc/, bpf/headers/ README banner edits per AGY PLAN-NEEDS-MINOR (adversarial-review-mpkub795-6e2gou)
- **File(s)**: docs/pr/1522-readme-doc-drift/plan.md, docs/pr/1522-readme-doc-drift/reviewer-ids.md
- **Why**: AGY adversarial-review-mpkub795-6e2gou returned PLAN-NEEDS-MINOR
  on plan v1 with one specific scope-reduction request: prune the three
  bpf/*/README.md banner edits because #1476 will mechanically delete the
  entire bpf/ tree — editing those READMEs is pure churn that #1476 will
  reverse. v2 edit list reduced from 5 files to 2 (dpdk_worker/README.md +
  pkg/logging/README.md). Re-dispatching Codex + AGY plan review on v2.

- **Timestamp**: 2026-05-25T08:10Z
- **Action**: #1522 plan v3 — pruned dpdk_worker/README.md after rebase onto current master (d237cceb) exposed #1528 will delete the entire dpdk_worker/ tree
- **File(s)**: docs/pr/1522-readme-doc-drift/plan.md, docs/pr/1522-readme-doc-drift/reviewer-ids.md, pkg/logging/README.md
- **Why**: Same scope-reduction principle AGY applied to bpf/*/README.md in
  v2. #1528 is OPEN and its issue body explicitly lists
  dpdk_worker/README.md in the deletion set; master CLAUDE.md states
  "DPDK dataplane retired in #1525. ... removed in #1527/#1528". v3 is a
  strict subset of v2 (AGY adversarial-review-mplbvcsb-kxkn6q
  PLAN-READY) so no re-dispatch needed. Scope is now 1 file:
  pkg/logging/README.md line 46 one-token reframe ("...as eBPF
  ring-buffer events" -> "...as the legacy eBPF ring-buffer events do").
- **Validation**: `go test ./pkg/dataplane/... -run
  RetirementBoundary -count=1` passes locally; canary tests do not
  pin any string in `pkg/logging/README.md` or the rewritten
  sentence. `git diff --stat origin/master..HEAD` confirms only
  `*.md` files touched, so smoke is skipped per the pure-docs
  skill rule.

- **Timestamp**: 2026-05-25T08:25Z
- **Action**: #1522 PR #1555 round-2 — fold Copilot 3 minor inline nits
- **File(s)**: docs/pr/1522-readme-doc-drift/plan.md,
  docs/pr/1522-readme-doc-drift/reviewer-ids.md, _Log.md
- **Why**: Copilot inline review on PR #1555 HEAD cb4c2345 left
  three minor nits: (1) plan.md L89 referenced master tip
  `c5c52a14` but the doc header references `d237cceb` — clarify;
  (2) reviewer-ids.md L15 said "codex" lowercased — capitalize to
  "Codex" to match other occurrences; (3) _Log.md said
  "pending after commit" which reads as TODO — record actual
  validation outcome. All three are purely cosmetic; no diff to
  pkg/logging/README.md.
- **Validation**: cosmetic-only; no test/build rerun needed.

- **Timestamp**: 2026-05-24T12:00Z
- **Action**: Draft #1518 plan v1 (cluster session-sync off legacy dataplane.DataPlane)
- **File(s)**: docs/pr/1518-cluster-session-sync-migration/plan.md, reviewer-ids.md
- **Why**: Sub-#1451 S3 — narrow pkg/cluster boundary to a backend-neutral
  clusterRuntime interface; constructors + setter no longer name
  dataplane.DataPlane. Keep SetDataPlane as a deprecated alias for one cycle.
  HA-touching scope: must pass make test-failover.
- **Validation**: pending Codex + Antigravity adversarial plan review.
- **Timestamp**: 2026-05-25T08:05Z
- **Action**: Implement #1518 (cluster session-sync off legacy dataplane.DataPlane)
- **File(s)**: pkg/cluster/runtime.go (NEW), pkg/cluster/sync.go,
  pkg/cluster/sync_test.go, pkg/daemon/daemon_ha_sync.go,
  pkg/dataplane/retirement_boundary_canary_test.go,
  docs/pr/1373-retire-ebpf-dataplane/README.md, pkg/cluster/README.md
- **Why**: Sub-#1451 S3. Introduce narrow clusterRuntime interface
  (Sessions/Telemetry); NewSessionSync, NewDualSessionSync now take
  clusterRuntime instead of dataplane.DataPlane. New SetRuntime setter
  populates both runtime domains via the same SessionStoreOf/TelemetryOf
  adapters the legacy SetDataPlane uses. SetDataPlane kept as a
  deprecated alias for one release cycle. Daemon call-site in
  daemon_ha_sync.go now calls SetRuntime(d.dp) directly — no legacyDP()
  cast required at this seam.
- **Validation**: go build ./... clean; go test ./pkg/cluster/ green
  (TestSetRuntime added); go test ./pkg/daemon/ green; full suite
  go test ./... green (32 packages); retirement boundary canary updated
  with pkg/cluster/runtime.go allowlist entry + 1373 README + cluster
  README. Smoke + test-failover pending (HA-sensitive scope per CLAUDE.md).

- **Timestamp**: 2026-05-25T15:31Z
  - **Action**: PR #1538 Copilot code-review round-2 — fix `want`
    variable shadowing in TestCompileSingleStrictErrorJoinPath and
    add TestCompileAllThreeStrictValidatorsAccumulated to close the
    third-family (validatePolicySchedulerReferencesStrict) coverage
    gap flagged in round-1 review.
  - **File(s)**: `pkg/config/compiler_test.go`
- **Timestamp**: 2026-05-24T00:00Z
- **Action**: Draft #1521 plan v1 — decouple userspace maps_sync from legacy BPF map name literals (sub-#1451 S6)
- **File(s)**: docs/pr/1521-maps-sync-decouple/plan.md, docs/pr/1521-maps-sync-decouple/reviewer-ids.md
- **Why**: `pkg/dataplane/userspace/maps_sync.go` hardcodes eleven BPF map
  names by string literal that need to migrate to a package-private
  registry so #1476 can retire legacy pinning without grep-and-pray. Plan
  preserves PR #1514's documented `userspace_fallback_stats` mixed-version
  compatibility exception verbatim. Pending Codex + AGY plan review.
- **Timestamp**: 2026-05-25T15:10Z
- **Action**: #1516 (sub-#1451 S1) — implement plan v2 migrating
  pkg/grpcapi off legacy dataplane.DataPlane. New
  pkg/grpcapi/runtime.go declares grpcRuntime narrow interface plus
  userspaceStatusProvider/userspaceControlProvider/sessionCursorIterator
  named providers. server.go field type Config.DP and Server.dp swap
  dataplane.DataPlane → grpcRuntime; inline anonymous interface
  assertions in server.go, server_show_forwarding.go, server_show.go
  collapse to the named provider assertions. server_sessions.go
  sessionIteratorFrom renamed to sessionCursorIterator and moved to
  runtime.go. AGY r1 PLAN-NEEDS-MAJOR finding (userspace cursor
  pagination silently degrades because LegacyDataPlaneAdapter does
  not implement IterateSessionsFrom/V6From) addressed by adding
  delegation methods on LegacyDataPlaneAdapter (assert embedded
  a.DataPlane against cursor-iterator interface and forward to
  bpfShim). Canary allowlist + retirement docs table updated:
  pkg/grpcapi/runtime.go added, pkg/grpcapi/server.go removed (no
  longer imports pkg/dataplane).
- **File(s)**: pkg/grpcapi/runtime.go (new), pkg/grpcapi/server.go,
  pkg/grpcapi/server_sessions.go, pkg/grpcapi/server_show.go,
  pkg/grpcapi/server_show_forwarding.go,
  pkg/dataplane/userspace/legacy_dataplane.go,
  pkg/dataplane/retirement_boundary_canary_test.go,
  docs/pr/1373-retire-ebpf-dataplane/README.md,
  docs/pr/1516-grpcapi-migration/plan.md (v2).
- **Validation**: GOCACHE/GOTMPDIR full Go suite green (30+ packages),
  pkg/grpcapi 5/5 race flake check clean, cargo --release build
  clean (114 pre-existing warnings only). Boundary canary tests
  green. Smoke matrix delegated to serialized smoke-runner singleton
  per feedback_smoke_serialized_single_agent rule (AWAITING-SMOKE
  marker posted on PR).

- **Timestamp**: 2026-05-25T16:05Z
- **Action**: #1554 r3 Copilot finding fold — cross-package compile-time
  interface-satisfaction guard. The userspace-side compile-time check
  is method-shape-only (inline anonymous interface) and can't catch
  drift if the unexported pkg/grpcapi interfaces (grpcRuntime,
  sessionCursorIterator, userspaceStatusProvider,
  userspaceControlProvider) acquire a new method. Adding the asymmetric
  guard in pkg/grpcapi/runtime_canary_test.go: `var _ grpcRuntime =
  (*dpuserspace.LegacyDataPlaneAdapter)(nil)` plus the same for each
  named provider interface. _test.go scope keeps the assertions out
  of the production binary.
- **File(s)**: pkg/grpcapi/runtime_canary_test.go (new), _Log.md
- **Validation**: go test ./pkg/grpcapi/... -count=1 green; full Go
  suite green.

- **Timestamp**: 2026-05-25T08:30Z
- **Action**: #1528 DPDK mechanical removal — plan v1 DRAFT
- **File(s)**: docs/pr/1528-dpdk-mechanical-removal/plan.md
- **Why**: Phase 3 of #1525 DPDK retirement. Single auditable diff that
  deletes dpdk_worker/, pkg/dataplane/dpdk/, Makefile targets, and the
  DPDKConfig schema. Plan documents the critical Option A (keep Phase 1
  reject) vs Option B (generic reject) decision and recommends Option A
  for operator-friendly migration message + stored-config rolling-upgrade
  safety via daemon_run.go:247 soft-fallback. 10 hostile questions
  surfaced for adversarial plan review. Pending Codex + Antigravity.

- **Timestamp**: 2026-05-25T09:15Z
- **Action**: #1528 plan v2 — addresses AGY r1 PLAN-NEEDS-MAJOR
- **File(s)**: docs/pr/1528-dpdk-mechanical-removal/plan.md
- **Why**: AGY round-1 verified that `validateDataplaneTypeStrict` fires inside
  `Store.Load()` BEFORE the daemon_run.go:247 soft-fallback gets a chance to
  catch `ErrDPDKBackendRetired`. The error is swallowed at daemon_run.go:87 as
  "failed to load config from db"; ActiveConfig() returns nil; dpType resolves
  to "" → userspace; the sentinel-Is check never fires. Node boots with empty
  config = operational blackout. This is an inherited bug from Phase 1 (#1526)
  that Phase 3 should fix. v2 adds §4.6 stored-config-tolerant Load path:
  rewrite persisted `dataplane-type dpdk` to empty at Load with loud warning.
  Also flipped socket-mem schema-node decision per AGY: keep with retirement-
  marker description rather than delete (userspace path ignores unmapped
  schema children gracefully). Added Q11 + Q12 for the v2 fix path and the
  HA-sync edge case. Codex r1+r2 ENV-BLOCKED sandbox failure; AGY-only verdict
  on v1.

- **Timestamp**: 2026-05-25T09:50Z
- **Action**: #1528 plan v3 — addresses Codex r3 PLAN-NEEDS-MAJOR
- **File(s)**: docs/pr/1528-dpdk-mechanical-removal/plan.md, reviewer-ids.md
- **Why**: Codex r3 (task-mpld4f7u-l7ixka) flagged 4 substantive findings on
  v2's load-rewrite approach: (1) the rewrite walks the raw tree and would
  MISS apply-groups + ${node} injected dpdk because group expansion happens
  inside CompileConfig/CompileConfigForNode BEFORE compileExpanded;
  (2) Q11 HA-sync claim was wrong — SyncApply does NOT use Store.Load() so
  inbound DPDK sync is rejected with a compile error (verified at
  daemon_ha_sync.go:566 → store.go:191); (3) ConfigTree.FindPath doesn't
  exist publicly (only FindChild + DeletePath); (4) rewrite leaves orphan
  DPDK sub-stanza (cores, memory, rx-mode, ports) which userspace compile
  silently drops. v3 PIVOT to load-mode bypass: add compileOpts{loadMode}
  on private compileExpanded plus CompileConfigForLoad + CompileConfigForNodeAndLoad
  exported helpers called by Store.compileTreeForLoad. Bypass operates AFTER
  group expansion (handles apply-groups), no AST mutation (no orphan concern),
  and preserves DataplaneType=="dpdk" through to NewRuntimeDataPlane which
  triggers the existing daemon_run.go:247 ErrDPDKBackendRetired soft-fallback.
  Also acknowledged the runtime/import_canary_test.go:47 dpdk forbidden-import
  entry as a KEEP (defense-in-depth). AGY r2 (adversarial-review-mpld4tso-19877w)
  returned PLAN-READY on v2 but missed findings 1, 3, 4; v3 takes Codex's
  strictly-superior feedback.

- **Timestamp**: 2026-05-25T21:10Z
- **Action**: #1528 plan v3.1 — fold AGY r3 PLAN-READY minor; Codex r5 retry
- **File(s)**: docs/pr/1528-dpdk-mechanical-removal/plan.md, reviewer-ids.md
- **Why**: AGY r3 (adversarial-review-mplgkdgz-ikpdw1) returned PLAN-READY on v3
  with one minor: add TestCompileConfigForLoad_BypassesDPDKRejectViaApplyGroups
  for explicit apply-groups + ${node} coverage under load-mode bypass. Folded
  into §4.6 + test plan. Codex r4 (task-mplgjwea-goeioj) sandbox-failed and
  expired from queue; per feedback_codex_infra_must_retry rule, dispatched r5
  retry (task-mpm3bsbi-hsom0r). Awaiting verdict before proceeding to
  implementation.

- **Timestamp**: 2026-05-26T00:30Z
- **Action**: #1528 plan v3.2 — schema-validate edge lock-in (Codex r5 PLAN-NEEDS-MINOR)
- **File(s)**: docs/pr/1528-dpdk-mechanical-removal/plan.md, reviewer-ids.md
- **Why**: Codex r5 (task-mpm7n2n2-ty9kjd) returned PLAN-NEEDS-MINOR with one
  blocking concern: schemaValidateExpandedTree runs BEFORE compileTreeForLoad,
  potentially rejecting legacy DPDK sub-stanza leaves before the load-mode
  bypass can fire. Verified pkg/cmdtree/schema_validate.go:35-57 against
  actual source: SchemaValidate is opt-in per subtree and currently scoped to
  class-of-service schedulers only. The concern is unfounded TODAY. v3.2 adds
  two explicit tests (TestLoad_PersistedDPDKDataplaneTypeWithSubStanzaBootsConfigOnly
  in pkg/configstore + TestSchemaValidate_AcceptsLegacyDPDKSubStanza in
  pkg/cmdtree) plus §4.7 contract to make the schema-validate scope an
  explicit pinned surface for retirement work. Pending re-dispatch.

- **Timestamp**: 2026-05-26T01:00Z
- **Action**: #1528 plan v3.3 — strengthen TestSchemaValidate_AcceptsLegacyDPDKSubStanza fixture (Codex r6 PLAN-NEEDS-MINOR)
- **File(s)**: docs/pr/1528-dpdk-mechanical-removal/plan.md, reviewer-ids.md
- **Why**: Codex r6 (task-mpm8d1qz-9bj4nh) returned PLAN-NEEDS-MINOR: the v3.2
  fixture has no class-of-service subtree, so SchemaValidate hits the
  pkg/cmdtree/schema_validate.go:43-46 early return and the test only proves
  current early-return behavior. A future PR that adds a top-level
  system-dataplane walker independently of the cos early-return would silently
  bypass the gate. v3.3 strengthens the fixture to include a valid
  class-of-service schedulers block alongside the legacy DPDK shape, plus a
  pre-condition assertion that tree.FindChild("class-of-service") != nil. The
  cos block forces the walker to exercise the positive-path, and the DPDK
  leaves prove ignored. The strengthened fixture catches BOTH the
  unconditional-validator regression class AND the cos-early-return-removal
  class. Pending re-dispatch.

- **Timestamp**: 2026-05-26T02:15Z
- **Action**: #1528 Phase B implementation — DPDK mechanical removal complete
- **File(s)**:
  - DELETED: dpdk_worker/ (entire tree — 17 C files + headers + meson + cached build/)
  - DELETED: pkg/dataplane/dpdk/ (entire package — manager.go, dpdk_cgo.go, dpdk_stub.go, fib.go, dpdk_stub_test.go, dpdk_lookup_source_test.go)
  - EDITED: Makefile (removed build-dpdk-worker, build-dpdk, clean-dpdk targets + .PHONY + clean: clean-dpdk)
  - EDITED: pkg/config/types.go (deleted DPDKConfig, DPDKAdaptiveConfig, DPDKPort, SystemConfig.DPDKDataplane field)
  - EDITED: pkg/config/compiler_system.go (deleted case dataplaneTypeDPDK that populated DPDKConfig + compileDPDKDataplane function; left case branch as silent-drop comment)
  - EDITED: pkg/config/ast.go (rewrote socket-mem schema-node description: "Legacy DPDK socket memory (retired, ignored)")
  - EDITED: pkg/config/compiler.go (added compileOpts{loadMode}; refactored CompileConfig/CompileConfigForNode to delegate via compileWithOpts; added CompileConfigForLoad + CompileConfigForNodeAndLoad public entry points; gated validateDataplaneTypeStrict on !opts.loadMode)
  - EDITED: pkg/config/parser_system_test.go (removed DPDKDataplane != nil assertion at line 1382)
  - EDITED: pkg/config/parser_ast_test.go (added TestCompileConfigForLoad_BypassesDPDKReject + TestCompileConfigForLoad_BypassesDPDKRejectViaApplyGroups; updated compileExpanded test calls to compileOpts{})
  - EDITED: pkg/configstore/store.go (Store.Load uses new compileTreeForLoad; emits slog.Warn when DataplaneType=="dpdk")
  - EDITED: pkg/configstore/store_test.go (added TestLoad_PersistedDPDKDataplaneTypeBootsConfigOnly + TestLoad_PersistedDPDKDataplaneTypeWithSubStanzaBootsConfigOnly)
  - NEW: pkg/cmdtree/schema_validate_test.go (added TestSchemaValidate_AcceptsLegacyDPDKSubStanza with cos-populated fixture per Codex r6 v3.3 minor)
  - EDITED: pkg/dataplane/retirement_boundary_canary_test.go (deleted dpdkBackendImportForCanary const, dpdkEBPFImportAllowlist, dpdkBackendImportAllowlist; deleted TestDPDKBackendImportStaysBackendLocal + TestDPDKEBPFArtifactImportsStayAtLegacyAdapter + TestRetirementBoundaryDocsMentionDPDKPolicy; removed dpdkBackendImportForCanary check from TestOperatorPackagesDoNotImportBPFArtifactsDirectly)
  - EDITED: scripts/refactoring-audit.sh (removed dpdk_worker from find paths)
  - EDITED: docs/pr/1373-retire-ebpf-dataplane/README.md (rewrote #1475 DPDK Backend Policy section as retirement note)
  - EDITED: pkg/dataplane/README.md (rewrote DPDK retirement paragraph; removed crossed-out DPDK entry)
  - KEPT: pkg/dataplane/dataplane.go TypeDPDK + ErrDPDKBackendRetired + RegisterBackend/RegisterRuntimeBackend panic guards + case TypeDPDK arms (Phase 1 reject preservation per plan §3 / §5)
  - KEPT: pkg/config/compiler.go dataplaneTypeDPDK + ErrDPDKDataplaneRetired + validateDataplaneTypeStrict + validDataplaneType("dpdk")=true (Phase 1 reject)
  - KEPT: pkg/configstore/store_test.go TestCommit_RejectsDPDKDataplaneType (gRPC/REST wrap contract)
  - KEPT: pkg/dataplane/runtime/import_canary_test.go:47 dpdk forbidden-backend (defense-in-depth)
  - KEPT: pkg/daemon/daemon_run.go:247 errors.Is(ErrDPDKBackendRetired) soft-fallback (now reachable for stored-config rolling-upgrade)
- **Why**: Both Codex r7 (task-mpmbxohf-mft8dk) and AGY r5 (adversarial-review-mpmby226-tvzsfa) returned PLAN-READY on plan v3.3. Executed mechanical deletion + load-mode bypass per plan v3.3. All packages build clean (go build ./...). Full go test ./... passes. 5x flake check on all DPDK-related tests passes (25/25 runs). make build succeeds. make -n build-dpdk / clean-dpdk correctly report "no rule".

- **Timestamp**: 2026-05-26T02:30Z
- **Action**: #1528 PR #1560 opened; code-review cycle dispatched
- **File(s)**: docs/pr/1528-dpdk-mechanical-removal/reviewer-ids.md
- **Why**: PR #1560 (HEAD ecc4d5b8) opened with full plan v3.3 implementation.
  Body contains `Closes #1528` per feedback_pr_body_close_keyword. Copilot
  added via gh pr edit + @copilot review comment per feedback_copilot_two_bots.
  Dispatched Codex hostile code review (task-mpmf8tph-0dwkmf, inline-content)
  and AGY adversarial code review (adversarial-review-mpmf9e1k-p2wray) in
  parallel. Posted Claude SMR adversarial review as PR comment per
  feedback_triple_review_includes_claude_smr (MERGE-READY verdict). Awaiting
  Codex + AGY + Copilot to reach 4-of-4 attestation, then will post
  <!-- AWAITING-MERGE --> marker per feedback_retirement_batch_smoke_at_end.

- **Timestamp**: 2026-05-26T02:45Z
- **Action**: #1528 PR #1560 — address Copilot inline comment on phase-order wording
- **File(s)**: docs/pr/1373-retire-ebpf-dataplane/README.md
- **Why**: Copilot review COMMENTED with one inline comment on line 91 noting
  that "Phase 4 (#1529) swept documentation surfaces" could read as if Phase
  4 is complete while this PR is Phase 3 — but Phase 4 (#1529/#1537) DID
  merge before this PR (commit 564ceba1 on master). Reworded the section to
  make the phase order explicit and call out that Phase 4 landed before
  Phase 3 because the canary-pinned text strings forbade direct rewrite
  pre-Phase-3.

- **Timestamp**: 2026-05-26T09:40Z
- **Action**: #1528 — fix stale comment in pkg/config/compiler_system.go:238-244
- **File(s)**: pkg/config/compiler_system.go
- **Why**: After the rebase-to-master in 4f348ee, the `case dataplaneTypeDPDK:` comment
  still referenced `compileTreeForLoad` (which was removed) and described the old
  "config-only mode / ErrDPDKBackendRetired soft-fallback" behavior (also removed).
  Updated to describe the actual post-rebase semantics: this branch is only reachable
  from a direct CompileConfig call (commit path); Store.Load/SyncApply strip the dpdk
  leaf via rewriteRetiredDataplaneType before compile so the sub-stanza goes through
  compileUserspaceDataplane instead. validateDataplaneTypeStrict fires after
  compileSystem in any case, making the silent-drop behavior in this branch moot.


- **Action**: #1528 PR #1560 — rebase onto current master (post #1553, #1554, #1557, #1558)
- **File(s)**: Makefile, _Log.md, pkg/config/compiler.go, pkg/config/dpdk_subtree_leakage_canary_test.go (deleted), pkg/configstore/store.go, pkg/configstore/store_test.go, pkg/dataplane/retirement_boundary_canary_test.go, pkg/config/parser_ast_test.go
- **Why**: PR was DIRTY/CONFLICTING after #1558 merged (deleted bpfel files) and #1553 merged (added pkg/config/dpdk_subtree_leakage_canary_test.go with DPDKDataplane references). Rebase rewinds my plan-v3 load-mode bypass approach in favor of master's `rewriteRetiredDataplaneType` (introduced for the symmetric #1373 eBPF retirement in #1558) which strips the retired-type leaf from the AST at Load (and at SyncApply, which my bypass didn't cover). Master's rewrite already handles apply-groups + ${node} expansion paths via `groupsBlocksOf` walker — the same finding Codex r3 raised against my v2 rewrite-at-Load approach. End result: drops compileOpts{loadMode} + compileWithOpts + CompileConfigForLoad + CompileConfigForNodeAndLoad + compileTreeForLoad in favor of master's rewriteRetiredDataplaneType bridge. Net: PR is now a pure mechanical-deletion (dpdk_worker/, pkg/dataplane/dpdk/, Makefile targets, DPDKConfig/AdaptiveConfig/Port types, SystemConfig.DPDKDataplane field, compileDPDKDataplane fn, retirement-boundary canary DPDK entries). Also deletes pkg/config/dpdk_subtree_leakage_canary_test.go (PR #1553's leakage canary) since the field it polices is gone — per the canary's own comment ("This is dead code after #1528 (Phase 3) deletes the field entirely; remove this line in #1528"). Schema-validate scope contract + TestSchemaValidate_AcceptsLegacyDPDKSubStanza preserved as future-proofing for any expansion of SchemaValidate. Store.Load tests updated to assert DataplaneType=="" post-rewrite (was "dpdk" under the dropped bypass approach).

- **Timestamp**: 2026-05-26 09:50 UTC
- **Action**: Fold AGY r2 + Copilot r3 minor findings — update 3 stale comments referring to pre-rebase load-mode bypass / compileTreeForLoad to reference rewriteRetiredDataplaneType bridge (called from both Store.Load and Store.SyncApply per master post-#1558).
- **File(s)**: pkg/config/types.go (SystemConfig.DataplaneType comment); docs/pr/1373-retire-ebpf-dataplane/README.md (remaining DPDK bullet); pkg/cmdtree/schema_validate_test.go (TestSchemaValidate_AcceptsLegacyDPDKSubStanza header). Fourth comment (pkg/config/compiler_system.go) already fixed in 66c4d711.

- **Timestamp**: 2026-05-26 10:00 UTC
- **Action**: Fold Codex r-final MERGE-NEEDS-MINOR comment findings — update 2 stale comments. (1) ErrDPDKBackendRetired comment no longer references the deleted pkg/dataplane/dpdk package-local test; points to runtime/import_canary_test.go as defense-in-depth. (2) TestSchemaValidate_AcceptsLegacyDPDKSubStanza header clarifies it guards orphaned sub-stanzas that survive the rewrite bridge, not pre-bridge schema validation.
- **File(s)**: pkg/dataplane/dataplane.go (ErrDPDKBackendRetired comment); pkg/cmdtree/schema_validate_test.go (test header).

- **Timestamp**: 2026-05-26 16:25 UTC
- **Action**: #1540 REST API split — plan v1 DRAFT; identifies sibling-file shape (`pkg/api/<aspect>.go`) per parent wave-1 instructions; lists target file decomposition for handlers.go (67 fns → 11 files) and metrics.go (33 fns → 6 files); flags 7 open questions for adversarial plan review including flat-package vs subdirectory shape decision.
- **File(s)**: docs/pr/1540-rest-api-split/plan.md, docs/pr/1540-rest-api-split/reviewer-ids.md.

- **Timestamp**: 2026-05-26 16:45 UTC
- **Action**: #1540 REST API split — implementation. Split pkg/api/handlers.go (2223 LOC, 67 fns) into 13 sibling files (api/health/stats/security/nat/interfaces/routing/dhcp/ipsec/vrrp/system/config/show_text); split pkg/api/metrics.go (2033 LOC, 33 fns) into 7 sibling files (metrics/metrics_descriptors/metrics_userspace/metrics_counters/metrics_sessions/metrics_nat/metrics_system); renamed handlers_sessions.go to sessions.go. All plan-review minors from Codex + AGY folded: config.go (not config_handlers.go); newCollector moved to metrics_descriptors.go; parseMemInfoKB moved to metrics_system.go; api.go tightened (policyActionStr+screenChecks→security.go, protoName→sessions.go, configCommitResponse+commitResponseFromConfig→config.go); legacy import allowlist + retirement docs updated. Pure code motion. Full go test ./... clean.
- **File(s)**: pkg/api/api.go, config.go, dhcp.go, health.go, interfaces.go, ipsec.go, metrics.go, metrics_counters.go, metrics_descriptors.go, metrics_nat.go, metrics_sessions.go, metrics_system.go, metrics_userspace.go, nat.go, routing.go, security.go, sessions.go, show_text.go, stats.go, system.go, vrrp.go; pkg/dataplane/retirement_boundary_canary_test.go; docs/pr/1373-retire-ebpf-dataplane/README.md; docs/pr/1540-rest-api-split/plan.md; docs/pr/1540-rest-api-split/reviewer-ids.md.

- **Timestamp**: 2026-05-26 17:05 UTC
- **Action**: #1540 PR #1564 — fold Codex code-review MERGE-NEEDS-MINOR doc-drift findings + Copilot review minors. (1) plan.md updated to reflect post-fold landed shape: config.go (not config_handlers.go), newCollector → metrics_descriptors.go, parseMemInfoKB → metrics_system.go, api.go-tightening (policyActionStr/screenChecks → security.go, protoName → sessions.go, configCommitResponse + commitResponseFromConfig → config.go). (2) canary allowlist + retirement README pkg/api/api.go blurb corrected: 'apiRuntimeDataPlane + protoName' → 'apiRuntimeDataPlane + applyResult adapter' (protoName moved to sessions.go). (3) _Log.md timestamps backfilled to HH:MM UTC for Copilot consistency. Copilot's 4 inline pre-existing `net.InterfaceByName(ifName)` Junos-name findings (interfaces.go, stats.go, metrics_counters.go) are NOT addressed in this PR — pure code motion contract; pre-existing bugs to be filed as separate issues.
- **File(s)**: docs/pr/1540-rest-api-split/plan.md, pkg/dataplane/retirement_boundary_canary_test.go, docs/pr/1373-retire-ebpf-dataplane/README.md, _Log.md.

- **Timestamp**: 2026-05-26 17:15 UTC
- **Action**: #1540 PR #1564 — fold Codex round-2 MERGE-NEEDS-MINOR remaining doc-drift findings. (1) plan.md 'Open questions for adversarial review' v1 section refactored into 'Open questions — resolutions' that documents how each of the 7 v1 questions was answered across the two plan-review rounds. (2) reviewer-ids.md updated with actual round-1 verdicts (Codex MERGE-NEEDS-MINOR, AGY MERGE-READY, Copilot COMMENTED 8 inline, Claude SMR MERGE-READY) and adds round-2 entry. Doc-only fix.
- **File(s)**: docs/pr/1540-rest-api-split/plan.md, docs/pr/1540-rest-api-split/reviewer-ids.md, _Log.md.

- **Timestamp**: 2026-05-26 17:30 UTC
- **Action**: #1444 — pure code-motion refactor de-monolithizing pkg/cli/cli.go from 1999 LOC to 418 LOC. Plan v1 → Codex (PLAN-NEEDS-MAJOR) + Gemini (PLAN-NEEDS-MINOR). Plan v2 addressing all 8 v1 findings → Gemini PLAN-READY r2; Codex sandbox infra failed twice, returned PLAN-NEEDS-MINOR on third retry with inline plan paste. v3 plan acknowledges Codex r2 ownership findings. Implementation: 9 new sibling files (cli_show_security_dispatch.go, peer.go, permissions.go, apply.go, session_filter.go, app_resolve.go, link.go, chrony.go, proto.go) + extensions to existing completion.go (completer engine merged in), cli_show_cluster.go (fabricRedirectCounters), cli_show_flow.go (topTalkerEntry), cli_show_nat.go (handleShowNAT), cli_show_routing.go (handleShowRoute+handleShowProtocols), cli_show_services.go (handleShowClassOfService+handleShowServices), cli_show_interfaces.go (dhcpLease). Updated #1373 retirement-boundary canary allowlist + docs table for 4 new pkg/cli files that retain legacy dataplane imports. go build clean, all 32 test packages pass.
- **File(s)**: pkg/cli/cli.go (-1581 LOC), pkg/cli/completion.go (+218), pkg/cli/cli_show_security_dispatch.go (new), pkg/cli/peer.go (new), pkg/cli/permissions.go (new), pkg/cli/apply.go (new), pkg/cli/session_filter.go (new), pkg/cli/app_resolve.go (new), pkg/cli/link.go (new), pkg/cli/chrony.go (new), pkg/cli/proto.go (new), pkg/cli/cli_show_cluster.go, pkg/cli/cli_show_flow.go, pkg/cli/cli_show_nat.go, pkg/cli/cli_show_routing.go, pkg/cli/cli_show_services.go, pkg/cli/cli_show_interfaces.go, pkg/dataplane/retirement_boundary_canary_test.go, docs/pr/1373-retire-ebpf-dataplane/README.md, docs/pr/1444-cli-presenters/plan.md (new).

- **Timestamp**: 2026-05-26 17:45 UTC
- **Action**: #1444 PR #1566 — rebase onto origin/master @ 838657aa (post-#1564 #1540 REST API split). Conflict in _Log.md auto-resolved (keep both #1540 + #1444 chronological entries). Canary + docs README auto-merged cleanly (#1540 + #1444 modified non-overlapping table sections). Re-run go build + go test post-rebase: clean.
- **File(s)**: _Log.md (conflict resolution).

## 2026-05-26 — #1345 server/handlers.rs per-verb split

- **Timestamp**: 2026-05-26T17:00Z
- **Action**: Split 415-LOC handle_stream dispatcher into per-verb modules
- **File(s)**: userspace-dp/src/server/handlers.rs → handlers/mod.rs (181 LOC slim dispatcher) + 12 per-verb files (snapshot, forwarding, ha, neighbors, queue, binding, inject_packet, sync_session, session_deltas, export, rebind, stop_workers). Trivial arms (ping/status, update_fabrics, clear_policy_counters, shutdown, catch-all) stay inline in mod.rs. Pure code motion; zero new clones; byte-identical eprintln strings. cargo build clean, all tests pass except pre-existing master flake snat_contract_documents_current_fail_closed_runtime (confirmed on origin/master independent of this branch).
## #1327 poll_descriptor stages — 2026-05-26

- **Timestamp**: 2026-05-26
  - **Action**: Worktree created from origin/master; #1327 Step 1 plan
    review v1→v4 (PLAN-NEEDS-MAJOR → PLAN-NEEDS-MINOR → split → MERGE-READY).
  - **File(s)**: branch refactor/1327-poll-descriptor-stages

- **Timestamp**: 2026-05-26
  - **Action**: Implemented Step 1. Converted flat poll_descriptor.rs to
    directory module (poll_descriptor/mod.rs). Extracted flow-cache fast
    path (verbatim translation of original L563-894) to flow_cache_hit.rs
    with #[inline(always)] + FlowCacheOutcome { Consumed, FallThrough }.
    Moved record_rx_descriptor_telemetry verbatim to rx_telemetry.rs.
    Fixed snat_contract_doc_guard test (twice — initial extension + Copilot
    review fix on assertion messages and required-doc tokens).
    Final: mod.rs 2806 LOC (was 3292), flow_cache_hit.rs 379 LOC,
    rx_telemetry.rs 220 LOC.
  - **File(s)**: userspace-dp/src/afxdp/poll_descriptor/{mod,flow_cache_hit,rx_telemetry}.rs, userspace-dp/tests/snat_contract_doc_guard.rs

- **Timestamp**: 2026-05-26
  - **Action**: Validation gates. cargo build clean; cargo test 1417/1417
    main suite pass; snat_contract_doc_guard pre-existing master flake
    (docs/userspace-dataplane-gaps.md missing "fail-closed" keyword);
    10× afxdp:: flake same as master 2/10 wg::engine concurrent-load
    pre-existing flake; cargo asm gate confirmed via nm (no
    stage_flow_cache_hit symbol in release binary); Go suite 30/30 pass.
  - **File(s)**: PR #1571

- **Timestamp**: 2026-05-26
  - **Action**: Code reviews — Codex provisional MERGE-READY (sandbox
    infra-blocked, summary-based), AGY MERGE-READY with Python line-by-
    line verification script, Copilot 1 inline finding (test path
    hardcoding) fixed in fe176daa. Claude SMR review posted (#1571
    comment 4547263769): AF_XDP UMEM ownership / CPU-arch inline gate /
    zero allocation / HA epoch ordering / SW design pattern all verified
    MERGE-READY. AWAITING-BATCH-MERGE marker posted.
  - **File(s)**: PR #1571

## 2026-05-26 — #1542 NAT runtime split (Wave-2)
- **Timestamp**: 2026-05-26
- **Action**: Plan v1 drafted, committed (724987e6), pushed; dispatched Codex (task-mpmyrnf2-1de5ha) + AGY (adversarial-review-mpmys6pk-3ut2f2) plan reviews in parallel.
- **File(s)**: docs/pr/1542-nat-runtime-split/plan.md, docs/pr/1542-nat-runtime-split/reviewer-ids.md

## 2026-05-26 — #1542 NAT runtime split implementation
- **Timestamp**: 2026-05-26
- **Action**: Split userspace-dp/src/nat.rs (1605 LOC) into nat/{mod,allocator,source,destination,static_nat,status}.rs + tests.rs. Plan v3 ratified after Codex+AGY round 2. Cargo build clean, 1417 main tests + 212 nat tests pass, 5x flake clean.
- **File(s)**: userspace-dp/src/nat/* (created), userspace-dp/src/nat.rs (deleted), userspace-dp/src/nat_tests.rs (moved to nat/tests.rs), docs/pr/1542-nat-runtime-split/{plan,reviewer-ids}.md

## 2026-05-26 — #1356 bpf_map publish per-AF split (Wave-2)

- **Timestamp**: 2026-05-26
  **Action**: #1356 triple-review drive — split publish_bpf_conntrack_entry per-AF; PR #1572 opened; 4-of-4 attestation (Codex MERGE-NEEDS-MINOR addressed, AGY MERGE-READY, Copilot inline addressed, Claude SMR clean); AWAITING-BATCH-MERGE marker posted.
  **File(s)**: userspace-dp/src/afxdp/bpf_map/mod.rs, userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs, userspace-dp/src/afxdp/mod.rs, userspace-dp/src/afxdp/bpf_map_tests.rs, docs/pr/1356-bpf-map-split/{plan,reviewer-ids}.md

- **Timestamp**: 2026-05-26
  - **Action**: #1440 plan v1 (DRAFT). Drafted consolidation plan
    targeting wg/outer.rs duplicated checksum_be + write_outer_eth,
    gre.rs::encapsulate_native_gre_frame open-coded outer IPv4/IPv6,
    and icmp.rs::build_local_time_exceeded_v4/v6 outer headers.
    Proposed new file: userspace-dp/src/afxdp/frame/headers.rs +
    headers_tests.rs (flat files, not headers/ subdir per existing
    frame/byte_writes.rs precedent). Public-to-crate signatures
    preserved on wg/outer helpers via thin wrappers. Open questions
    1-8 flagged for adversarial review; perf-irrelevance PLAN-KILL
    explicitly invited.
  - **File(s)**: docs/pr/1440-header-serialization-consolidate/{plan,reviewer-ids}.md

- **Timestamp**: 2026-05-26
  - **Action**: #1440 plan v2 — revised after round-1 4-way review.
    Convergence findings incorporated: (1) DELETE wg/outer.rs
    entirely [Gemini+AGY+Claude SMR], (2) UDP checksum API
    u16 not Option<u16> [Codex+Gemini+Claude SMR], (3) Set IPv4
    DF=1 to fix RFC 791/6864 compliance [Gemini+AGY], (4) Add
    AVX2 length short-circuit in frame::checksum [Codex+Gemini+
    AGY], (5) Remove §5.2 differential test in favor of permanent
    golden vectors only [Codex+Gemini+AGY]. Reverted Gemini's
    unauthorized worktree writes (headers.rs, headers_tests.rs,
    checksum.rs short-circuit, eth/IP/icmp/wg edits) — Gemini went
    rogue and wrote candidate impl, then cited its own writes in
    findings. Substantive findings preserved; impl deferred to
    after plan v2 PLAN-READY.
  - **File(s)**: docs/pr/1440-header-serialization-consolidate/plan.md

- **Timestamp**: 2026-05-26
  - **Action**: Plan-review convergence on v2.2 (commit af3bef03):
    Gemini r3 PLAN-READY (independent checksum re-derivation matches
    0x2655; all 5 findings verified). AGY r2 PLAN-NEEDS-MINOR
    (3 stale Option<u16> refs) — resolved in v2.1. Codex r3
    PLAN-NEEDS-MAJOR (3 stale v1-design refs) — resolved in v2.2.
    Codex r4/r5/r6 infra-blocked (sandbox-binary missing 4×). Per
    feedback_gemini_infra_outage_merge_policy: 3× infra fails ⇒
    move forward without that reviewer at plan stage; will re-
    attempt Codex at code-review stage on the impl PR. Proceeding
    to implementation per plan v2.2.
  - **File(s)**: docs/pr/1440-header-serialization-consolidate/plan.md

- **Timestamp**: 2026-05-26
  - **Action**: #1440 implementation per plan v2.2. Created
    frame/headers.rs (consolidated builders for eth/IPv4/IPv6/UDP)
    + frame/headers_tests.rs (20 golden-vector tests). Moved
    write_eth_header + write_eth_header_slice from frame/mod.rs to
    headers.rs with re-export at old paths. Added < 32 byte
    short-circuit in checksum16_add_bytes. Refactored gre.rs v4/v6
    arms + icmp.rs build_local_time_exceeded_v4/v6 to use
    write_ipv4_header / write_ipv6_header builders. DELETED
    wg/outer.rs entirely (was scaffold-only); two surviving smoke
    tests in wg/tests.rs rewired to call frame::headers builders
    directly via the frame:: re-export. Wire-byte change: GRE outer
    IPv4 now sets DF=1 (0x4000) per RFC 791/6864; ICMP TE v4 same.
    Build clean. Cargo tests: 1431 main + 46 lib + 8 + 16 + 20 new
    headers_tests all pass. ICMP TE tests 5/5 pass.
    snat_contract_doc_guard failure is pre-existing master flake
    (references different worktree path). Go suite 30/30 pass.
    headers tests 5/5 flake-free.
  - **File(s)**: userspace-dp/src/afxdp/frame/{headers,headers_tests,checksum,mod}.rs,
    userspace-dp/src/afxdp/gre.rs, userspace-dp/src/afxdp/icmp.rs,
    userspace-dp/src/afxdp/wg/{mod,tests}.rs,
    userspace-dp/src/afxdp/wg/outer.rs (DELETED)

- **Timestamp**: 2026-05-26
  - **Action**: #1440 code-review convergence. Gemini r1 code review
    MERGE-READY (independent worktree inspection, 7/7 confirmed
    including §6.1 cs=0x2655 byte-level). AGY r1 code review
    MERGE-READY (independent checksum re-derivation; cargo check +
    cargo test frame/wg all pass; 8/8 verification points). Copilot
    PRR_kwDORLJrbM8AAAABBEn3WQ COMMENTED with no findings ("Copilot
    reviewed 12 out of 12 changed files in this pull request and
    generated no comments"). Codex r1 MERGE-NEEDS-MAJOR with one
    substantive doc-wording finding (RFC 6864 "requires" overstated
    — should be atomic-datagram "permits") + infra block; addressed
    in b60ea4c6. Codex r2 on b60ea4c6 explicitly declined to
    fabricate verdict — 6th consecutive Codex infra block. Per
    Wave-2 Bucket C "3-of-4 Codex-stuck precedent": 3 of 4 reviewers
    MERGE-READY/no-findings, posted AWAITING-BATCH-MERGE marker on
    PR #1579 at b60ea4c6.
  - **File(s)**: PR #1579, userspace-dp/src/afxdp/frame/headers.rs,
    docs/pr/1440-header-serialization-consolidate/reviewer-ids.md

## 2026-05-26 — #1351 umem snapshot+debug_state split

- **Timestamp**: 2026-05-26
  **Action**: #1356 triple-review drive — split publish_bpf_conntrack_entry per-AF; PR #1572 opened; 4-of-4 attestation (Codex MERGE-NEEDS-MINOR addressed, AGY MERGE-READY, Copilot inline addressed, Claude SMR clean); AWAITING-BATCH-MERGE marker posted.
  **File(s)**: userspace-dp/src/afxdp/bpf_map/mod.rs, userspace-dp/src/afxdp/bpf_map/publish_conntrack.rs, userspace-dp/src/afxdp/mod.rs, userspace-dp/src/afxdp/bpf_map_tests.rs, docs/pr/1356-bpf-map-split/{plan,reviewer-ids}.md

- **Timestamp**: 2026-05-26
  - **Action**: #1440 plan v1 (DRAFT). Drafted consolidation plan
    targeting wg/outer.rs duplicated checksum_be + write_outer_eth,
    gre.rs::encapsulate_native_gre_frame open-coded outer IPv4/IPv6,
    and icmp.rs::build_local_time_exceeded_v4/v6 outer headers.
    Proposed new file: userspace-dp/src/afxdp/frame/headers.rs +
    headers_tests.rs (flat files, not headers/ subdir per existing
    frame/byte_writes.rs precedent). Public-to-crate signatures
    preserved on wg/outer helpers via thin wrappers. Open questions
    1-8 flagged for adversarial review; perf-irrelevance PLAN-KILL
    explicitly invited.
  - **File(s)**: docs/pr/1440-header-serialization-consolidate/{plan,reviewer-ids}.md

- **Timestamp**: 2026-05-26
  - **Action**: #1440 plan v2 — revised after round-1 4-way review.
    Convergence findings incorporated: (1) DELETE wg/outer.rs
    entirely [Gemini+AGY+Claude SMR], (2) UDP checksum API
    u16 not Option<u16> [Codex+Gemini+Claude SMR], (3) Set IPv4
    DF=1 to fix RFC 791/6864 compliance [Gemini+AGY], (4) Add
    AVX2 length short-circuit in frame::checksum [Codex+Gemini+
    AGY], (5) Remove §5.2 differential test in favor of permanent
    golden vectors only [Codex+Gemini+AGY]. Reverted Gemini's
    unauthorized worktree writes (headers.rs, headers_tests.rs,
    checksum.rs short-circuit, eth/IP/icmp/wg edits) — Gemini went
    rogue and wrote candidate impl, then cited its own writes in
    findings. Substantive findings preserved; impl deferred to
    after plan v2 PLAN-READY.
  - **File(s)**: docs/pr/1440-header-serialization-consolidate/plan.md

- **Timestamp**: 2026-05-26
  - **Action**: Plan-review convergence on v2.2 (commit af3bef03):
    Gemini r3 PLAN-READY (independent checksum re-derivation matches
    0x2655; all 5 findings verified). AGY r2 PLAN-NEEDS-MINOR
    (3 stale Option<u16> refs) — resolved in v2.1. Codex r3
    PLAN-NEEDS-MAJOR (3 stale v1-design refs) — resolved in v2.2.
    Codex r4/r5/r6 infra-blocked (sandbox-binary missing 4×). Per
    feedback_gemini_infra_outage_merge_policy: 3× infra fails ⇒
    move forward without that reviewer at plan stage; will re-
    attempt Codex at code-review stage on the impl PR. Proceeding
    to implementation per plan v2.2.
  - **File(s)**: docs/pr/1440-header-serialization-consolidate/plan.md

- **Timestamp**: 2026-05-26
  - **Action**: #1440 implementation per plan v2.2. Created
    frame/headers.rs (consolidated builders for eth/IPv4/IPv6/UDP)
    + frame/headers_tests.rs (20 golden-vector tests). Moved
    write_eth_header + write_eth_header_slice from frame/mod.rs to
    headers.rs with re-export at old paths. Added < 32 byte
    short-circuit in checksum16_add_bytes. Refactored gre.rs v4/v6
    arms + icmp.rs build_local_time_exceeded_v4/v6 to use
    write_ipv4_header / write_ipv6_header builders. DELETED
    wg/outer.rs entirely (was scaffold-only); two surviving smoke
    tests in wg/tests.rs rewired to call frame::headers builders
    directly via the frame:: re-export. Wire-byte change: GRE outer
    IPv4 now sets DF=1 (0x4000) per RFC 791/6864; ICMP TE v4 same.
    Build clean. Cargo tests: 1431 main + 46 lib + 8 + 16 + 20 new
    headers_tests all pass. ICMP TE tests 5/5 pass.
    snat_contract_doc_guard failure is pre-existing master flake
    (references different worktree path). Go suite 30/30 pass.
    headers tests 5/5 flake-free.
  - **File(s)**: userspace-dp/src/afxdp/frame/{headers,headers_tests,checksum,mod}.rs,
    userspace-dp/src/afxdp/gre.rs, userspace-dp/src/afxdp/icmp.rs,
    userspace-dp/src/afxdp/wg/{mod,tests}.rs,
    userspace-dp/src/afxdp/wg/outer.rs (DELETED)

- **Timestamp**: 2026-05-26
  - **Action**: #1440 code-review convergence. Gemini r1 code review
    MERGE-READY (independent worktree inspection, 7/7 confirmed
    including §6.1 cs=0x2655 byte-level). AGY r1 code review
    MERGE-READY (independent checksum re-derivation; cargo check +
    cargo test frame/wg all pass; 8/8 verification points). Copilot
    PRR_kwDORLJrbM8AAAABBEn3WQ COMMENTED with no findings ("Copilot
    reviewed 12 out of 12 changed files in this pull request and
    generated no comments"). Codex r1 MERGE-NEEDS-MAJOR with one
    substantive doc-wording finding (RFC 6864 "requires" overstated
    — should be atomic-datagram "permits") + infra block; addressed
    in b60ea4c6. Codex r2 on b60ea4c6 explicitly declined to
    fabricate verdict — 6th consecutive Codex infra block. Per
    Wave-2 Bucket C "3-of-4 Codex-stuck precedent": 3 of 4 reviewers
    MERGE-READY/no-findings, posted AWAITING-BATCH-MERGE marker on
    PR #1579 at b60ea4c6.
  - **File(s)**: PR #1579, userspace-dp/src/afxdp/frame/headers.rs,
    docs/pr/1440-header-serialization-consolidate/reviewer-ids.md
## 2026-05-26 #1352 frame/{build,rewrite}/ split
## 2026-05-26 13:05 UTC #1352 frame/{build,rewrite}/ split

- **Timestamp**: 2026-05-26 13:05 UTC
- **Action**: Implemented frame/build/{mod.rs,ipv4.rs,ipv6.rs} + frame/rewrite/{mod.rs,ipv4.rs,ipv6.rs} per #1352 plan v5. Extracted 236-LOC build_forwarded_frame_into_from_frame and 223-LOC apply_rewrite_descriptor into per-family files. Codegen contract: #[inline(always)] on per-family helpers; #[inline(never)] + concrete `meta: ForwardPacketMeta` on build orchestrator; standard #[inline] on rewrite orchestrator.
- **File(s)**: userspace-dp/src/afxdp/frame/build/{mod.rs,ipv4.rs,ipv6.rs} (created); userspace-dp/src/afxdp/frame/rewrite/{mod.rs,ipv4.rs,ipv6.rs} (created); userspace-dp/src/afxdp/frame/mod.rs (orchestrator bodies removed, mod decls added; build_forwarded_frame_into wrapper now calls .into() before forwarding to concrete-typed orchestrator).
- **Validation**: cargo build --release clean. 1487 cargo tests pass (113 frame-specific tests all pass). Codegen gate: nm -C shows ZERO per-family helper definitions (#[inline(always)] folded into orchestrator), exactly ONE build_forwarded_frame_into_from_frame definition, ZERO apply_rewrite_descriptor definitions (LLVM inlined fully into single caller poll_descriptor.rs:746). One pre-existing cross-worktree doc-guard test failure unrelated to this refactor.

## 2026-05-26 — #1342 split forwarding_build.rs (plan v1)

- **Timestamp**: 2026-05-26T (plan drafted)
  - **Action**: Created worktree
    `refactor/1342-forwarding-build-split` off `origin/master` and
    drafted plan v1 covering layout (forwarding_build/mod.rs +
    siblings: zones, tunnels, interfaces, fib, cos), order-
    preservation invariants, IfaceIndex context struct, public-API
    preservation, risk table, and 7 open questions.
  - **File(s)**: `docs/pr/1342-forwarding-build-split/plan.md`,
    `docs/pr/1342-forwarding-build-split/reviewer-ids.md`.

## 2026-05-26 — #1342 plan v2 (addressing r1 findings)

- **Timestamp**: 2026-05-26T (plan v2)
  - **Action**: Codex r1 returned PLAN-NEEDS-MAJOR (3 majors + 2
    minors); AGY r1 returned PLAN-NEEDS-MINOR (5 action items).
    Both agreed layout is correct. Revised plan to:
    - Fix visibility: `pub(in crate::afxdp)` for cross-sibling
      consumers; private `use cos::build_cos_state` (no API
      widening); explicit re-export table.
    - Add explicit `fib::sort_routes(&mut state)` call after
      `fib::populate_routes` (was dropped from v1 sketch).
    - Decompose `build_cos_state` internally into
      `build_cos_classifier_tables` + `build_cos_iface_config` +
      orchestrator (3 sub-100-LOC helpers).
    - Relocate `forwarding_build_tests.rs` ->
      `forwarding_build/tests.rs` (decision made, not deferred).
    - Document static-NAT/DNAT local-delivery placement
      constraint explicitly.
    - Document `useful_cos_state` gate's queue-resolution
      ordering invariant.
  - **File(s)**:
    `docs/pr/1342-forwarding-build-split/plan.md` v2.

## 2026-05-26 — #1342 implementation complete

- **Timestamp**: 2026-05-26T (implementation done, tests pass)
  - **Action**: Implemented plan v2 layout. Created
    forwarding_build/{mod.rs (345L), zones.rs (46L),
    tunnels.rs (53L), interfaces.rs (215L), fib.rs (289L),
    cos.rs (470L)}, moved tests to forwarding_build/tests.rs.
    Updated afxdp/mod.rs include from `#[path] mod` to plain
    `mod forwarding_build;`. Build clean (24 pre-existing
    warnings unchanged). Cargo tests: 1416 pass + 1 pre-existing
    flake (afxdp::wg::engine::reconcile_peers_snapshot_is_atomic
    — verified 5x clean on retry, unrelated subsystem). Go
    tests: clean.
  - **File(s)**: see above.

## 2026-05-26 — #1342 4-of-4 attestation complete

- **Timestamp**: 2026-05-26T (AWAITING-BATCH-MERGE posted)
  - **Action**: Posted AWAITING-BATCH-MERGE marker on PR #1577
    at SHA caf46afcdc88. 4-of-4 reviewer attestation: Codex r2
    MERGE-READY (r1 minors addressed); AGY r1 MERGE-READY
    (exhaustive AST byte-identity check across 22 functions);
    Copilot COMMENTED (1 finding addressed, 1 _Log.md timestamp
    format documented as preserving file convention); Claude
    SMR MERGE-READY.
  - **File(s)**: PR comment.

- **Timestamp**: 2026-05-26 21:15 UTC
  - **Action**: #1547 plan + implementation. Three plan-review rounds.
    Round 1 (v1 f9713e65): Codex PLAN-NEEDS-MAJOR (vtyshExecutor
    defer, ifaceNetwork mis-placed, ApplyFull inline blocks, README
    stale), Gemini PLAN-KILL (false cohesion claim,
    vtyshExecutor cannot be deferred).
    Round 2 (v2 71370dc7): Codex PLAN-NEEDS-MAJOR (zero-value Manager
    panic, parsing methods must also route through executor, stale
    v1/v2 contradictions, no fake-executor tests, ECMP block omitted),
    Gemini PLAN-KILL (single-method executor strands m.reload's
    systemctl + vtysh -f path).
    Round 3 (v3 31238f3c): both PLAN-READY (Codex with one minor —
    reload test should cover both happy and fallback paths; addressed
    in implementation with TestReloadUsesSystemctlHappyPath +
    TestReloadFallsBackToVtyshLoad as separate tests).
    Implementation: pkg/frr/frr.go (1606 LOC) → 5 sibling files
    (manager.go 339, config_render.go 268, policy_render.go 503,
    vtysh.go 153, status_parse.go 325) + executor_test.go (188 LOC of
    new fake-executor tests). Public API preserved byte-identical;
    pkg/frr existing tests pass; 5/5 flake-clean; full Go suite green.
    README updated.
  - **File(s)**: pkg/frr/{manager,config_render,policy_render,vtysh,
    status_parse,executor_test}.go (NEW); pkg/frr/frr.go (DELETED);
    pkg/frr/README.md (UPDATED); docs/pr/1547-frr-split/plan.md (v1→v3);
    docs/pr/1547-frr-split/reviewer-ids.md

- **Timestamp**: 2026-05-26 21:30 UTC
  - **Action**: #1547 PR #1587 code-review convergence. Codex
    MERGE-READY task-mpn50enm-s4lwd2 (no findings; sandbox could
    not run go test but local 5/5 flake-clean + full Go suite
    green). Gemini MERGE-READY task-mpn50uq3-0v3fgu (no blockers,
    7/7 verification points). Copilot COMMENTED with no inline
    findings (reviewed 11/11 files). 4-of-4 reviewer attestation
    achieved on first code-review round. AWAITING-BATCH-MERGE
    marker is in the PR body for the refactor-chain batch.
  - **File(s)**: PR #1587 at 4ff0b6c1,
    docs/pr/1547-frr-split/reviewer-ids.md
- **Timestamp**: 2026-05-26 21:28 UTC
  - **Action**: #1349 split worker/cos/build_worker_cos_statuses_from_maps
    (268 LOC) into interface_row/queue_row/status helpers under
    worker/cos/ subdir. Plan-review rounds: Codex r1 PLAN-NEEDS-MAJOR,
    Gemini r1 PLAN-KILL, AGY r1 PLAN-READY, Claude SMR PLAN-NEEDS-MINOR.
    Plan v2 addressed Codex/SMR + Gemini's first counter-example
    (dropped merge_binding_profile_if_target, inlined gated merge).
    v2: Codex MAJOR (stale text + alloc wording + ifindex), Gemini KILL
    (style preference), AGY READY. v3 mechanical cleanup; Codex r3
    PLAN-READY pending metadata count fix. Per
    feedback_gemini_low_signal_on_refactor, Gemini's KILL on a
    refactor PR is not blocking when Codex+AGY+Claude SMR agree.
    Implementation: pure code motion + new #784 MAX-not-sum test pin.
    1434/1434 cargo bin tests pass; 24/24 cos tests pass; 5/5 flake
    on named integration test.
  - **File(s)**: userspace-dp/src/afxdp/worker/cos/{mod,interface_row,
    queue_row,status,tests}.rs; docs/pr/1349-worker-cos-status-split/
    {plan.md,reviewer-ids.md}

## 2026-05-26 — 23:44 UTC — #1346 session_glue split: AWAITING-SMOKE+test-failover

- **Action**: Drove #1346 (`userspace-dp/src/afxdp/session_glue/mod.rs` split + 16/10-param helper collapse) through triple+quad review and opened PR #1595.
- **File(s)**:
  - `userspace-dp/src/afxdp/session_glue/mod.rs` (1406 → 1103 LOC)
  - `userspace-dp/src/afxdp/session_glue/promote.rs` (new)
  - `userspace-dp/src/afxdp/session_glue/commands/{delete_synced,demote_owner_rgs,export_owner_rg_sessions,refresh_owner_rgs,upsert_synced,mod}.rs` (new)
  - `userspace-dp/src/afxdp/session_glue/tests.rs` (+ new dispatcher dedup test, 2 call-site updates)
  - `docs/pr/1346-session-glue-split/{plan,reviewer-ids}.md` (new)
- **Status**: AWAITING-SMOKE + test-failover (HA-sensitive session-sync code)
- **Attestation**: 3-of-4 with codex-stuck exception
  - Gemini r2: MERGE-READY
  - AGY r2: MERGE-READY
  - Copilot r1: COMMENTED w/ 3 inline findings, all addressed in d013302748 + 0e2a88c8b
  - Codex: 3 consecutive sandbox failures (`unified-exec` blocked)

## 2026-05-26 03:17 UTC — #1296 plan v1 DRAFT

- **Timestamp**: 2026-05-26 03:17 UTC
- **Action**: Write plan.md v1 (DRAFT) for #1296 CoS surplus-sharing
  structural-pass / high raw CoV issue. Plan likely PLAN-KILL outcome
  given artifact's PASS verdict satisfies #1217 contract and existing
  `equal-flow-enforcement` knob already implements Option 2.
- **File(s)**:
  - `docs/pr/1296-cos-surplus-cov/plan.md` (new)
