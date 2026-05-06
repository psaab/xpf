---
status: REVISED v3 — Codex r2 caught one more stale ref (worker/cos_tests.rs:312); both reviewers PLAN-NEEDS-MINOR rounds-1/2; v3 ready to ship
issue: #1210
phase: single PR — pure doc/comment edits, no behavior change
---

## Round-1 verdict resolution

Both reviewers PLAN-NEEDS-MINOR. Same-shape findings:

- **Inventory missed test files and other paths.** Both flag
  `admission_tests.rs:1178,1207,1234`, `flow_hash_tests.rs:30,107,164`,
  plus `tx.rs:NNN` line references in `tx/cos_classify.rs:571,580`,
  `umem/mod.rs:150`, `umem/tests.rs:518,519,1031,1064,1074`,
  `protocol.rs:1315`. **v2 widens the grep to all `userspace-dp/src/`
  Rust files, not just `cos/` and `types/`.**
- **types/cos.rs:81 is NOT a stale reference.** The line says "1024
  buckets gave..." — a valid historical comparison. Original v1
  listed it under "1024 → 4096" mass-replace. **v2 explicitly
  preserves it.**
- **§3.B replacement text is accurate** per both reviewers — slight
  wording tightening to clarify V_min sync only applies to
  shared_exact (not owner-local).
- **`tx.rs:NNN` references**: drop the breadcrumb (Codex) or update
  to module/function anchor (Gemini). v2 picks per-site:
  - `queue_service/mod.rs:117` — drop (decayed review breadcrumb).
  - `docs/userspace-capture-plan.md:118,452` — replace with
    `userspace-dp/src/afxdp/tx/transmit.rs:transmit_batch()`.
  - `tx/cos_classify.rs:571,580` — replace with module/function
    anchor.
  - `umem/mod.rs:150` — replace with module/function anchor.
  - `umem/tests.rs:*` — replace; tests-side, low cost.
  - `protocol.rs:1315` — replace with current path.
  - `types/cos.rs:718` — replace with `cos/queue_service/mod.rs:drain_shaped_tx`.



## 1. Issue framing

Per #1210 and Codex CoS findings retrospective: source-tree comments
and docs reference scheduler invariants that no longer match the
current code. The drift cost three plan-review cycles in this session
already (PR #1203, #936 v1, Phase 2 byte-rate). #1205 ships a CI check
to prevent future drift; this PR scrubs the existing drift.

## 2. Honest scope/value framing

**Pure documentation edits.** Zero behavior change. Zero new tests.

The value is small per-edit but compounds: each stale anchor reads as
authority on the current scheduler when reviewers / future readers
encounter it. Removing them prevents the next plan from being drafted
against fictional code state.

**If reviewers conclude the scrub is too aggressive (e.g., we're
losing intentional historical retrospective text), PLAN-NEEDS-MINOR
on the specific lines is the right verdict.**

## 3. What's being scrubbed

Verified inventory across `userspace-dp/src/afxdp/cos/`,
`userspace-dp/src/afxdp/types/`, and `docs/` excluding `_KILLED` /
`_WITHDRAWN` plan files (those preserve history by design):

### A. `COS_FLOW_FAIR_BUCKETS = 1024` references

- `userspace-dp/src/afxdp/cos/queue_ops/mod.rs:64` — comment says
  "1024, typical workloads 2-16". Update to "4096".
- `userspace-dp/src/afxdp/cos/flow_hash.rs:104` — comment says "With
  `COS_FLOW_FAIR_BUCKETS = 1024` the mask in `cos_flow_bucket_index`
  is 10 bits wide". Update to "4096" + "12 bits wide".
- `userspace-dp/src/afxdp/cos/queue_ops/pop.rs:46,135` — "1024" in
  active-set bound discussion. Update to "4096".
- `userspace-dp/src/afxdp/cos/admission.rs:110,208` — "1024 flows" /
  "1024 active buckets" in cap-derivation comments. Update to "4096".
- `userspace-dp/src/afxdp/types/cos.rs:81,99,230,564,579` — multiple
  references to "1024 buckets" in struct field docs. Update each to
  the current 4096 footprint, preserving the historical-comparison
  parenthetical (e.g., "~232 KB per queue, was ~58 KB at 1024" stays
  as-is — that's an intentional comparison, not a stale claim).

### B. `flow_fair = queue.exact && !shared_exact` references

- `userspace-dp/src/afxdp/types/cos.rs:432-434` — the high-impact one.
  Comment block currently reads:
  > Under the current promotion policy (`flow_fair = queue.exact &&
  > !shared_exact`), shared_exact queues are NOT on the flow-fair
  > path — they stay on the single-FIFO-per-worker drain with no
  > SFQ DRR ordering. The shadow exists so future cross-worker
  > fairness work (tracked in issue #786) can branch on it.

  Reality (admission.rs:478-486): `flow_fair = queue.exact` for both
  owner-local AND shared_exact since #785 Phase 3. Update to:
  > Under the current promotion policy (`flow_fair = queue.exact`),
  > shared_exact queues ARE on the flow-fair path with cross-worker
  > V_min sync via `vtime_floor: Arc<...>` (#917). The cached
  > `shared_exact` flag remains on `CoSQueueRuntime` so admission
  > paths can apply rate-aware caps differently from owner-local
  > exact queues (`cos_queue_flow_share_limit`, #914).

### C. Old `tx.rs:` line references

- `userspace-dp/src/afxdp/cos/queue_service/mod.rs:117` — references
  "tx.rs:262". The CoS code split since the reference; update to the
  current module path or drop the line reference (keep just the
  conceptual context).
- `docs/userspace-capture-plan.md:118` — "afxdp/tx.rs:transmit_batch()".
  Update to current `tx/transmit.rs` or `cos/queue_service/service.rs`
  per the actual function location.

### D. Out of scope

- Buffer-size mentions of "1024" that are NOT bucket-count related
  (e.g., `COS_ROOT_LEASE_MAX_BYTES = 512 * 1024` at
  `shared_cos_lease.rs:212` is bytes, not buckets).
- Network ring sizes, MTU, syslog buffer sizes — orthogonal.
- Doc files marked KILLED / WITHDRAWN — historical record by design.

## 4. Concrete changes (v2)

### `1024 → 4096` mass-replace

| File | Line(s) | Change |
|---|---|---|
| `userspace-dp/src/afxdp/cos/queue_ops/mod.rs` | 64 | `1024` → `4096` |
| `userspace-dp/src/afxdp/cos/flow_hash.rs` | 104-108 | `1024` / `10 bits wide` → `4096` / `12 bits wide` |
| `userspace-dp/src/afxdp/cos/queue_ops/pop.rs` | 46, 135 | `1024` → `4096` |
| `userspace-dp/src/afxdp/cos/admission.rs` | 110, 208 | `1024` → `4096` |
| `userspace-dp/src/afxdp/types/cos.rs` | 230, 564, 579 | `1024` → `4096` |
| `userspace-dp/src/afxdp/cos/admission_tests.rs` | 1178, 1207, 1234 | `1024 active buckets` → `4096 active buckets` |
| `userspace-dp/src/afxdp/cos/flow_hash_tests.rs` | 30, 107, 164 | review per-line; either update or rename adjacent test (`exact_cos_flow_bucket_distribution_at_1024`-style) |

### Preserved (intentional historical comparison)

| File | Line(s) | Reason |
|---|---|---|
| `userspace-dp/src/afxdp/types/cos.rs` | 81 | "1024 buckets gave ~17.7%" — comparison frame for current 4096 |
| `userspace-dp/src/afxdp/types/cos.rs` | 99 | "(was ~58 KB at 1024)" — structural footprint comparison |

### `flow_fair = queue.exact && !shared_exact` rewrite

| File | Line(s) | Change |
|---|---|---|
| `userspace-dp/src/afxdp/types/cos.rs` | 432-434 | rewrite per §3.B — slight wording tightening for V_min sync scope |

### `tx.rs:NNN` line reference cleanup

| File | Line(s) | Change |
|---|---|---|
| `userspace-dp/src/afxdp/cos/queue_service/mod.rs` | 117 | drop the `tx.rs:262` breadcrumb |
| `userspace-dp/src/afxdp/types/cos.rs` | 718 | replace with `cos/queue_service/mod.rs:drain_shaped_tx` |
| `userspace-dp/src/afxdp/tx/cos_classify.rs` | 571, 580 | replace with module/function anchor |
| `userspace-dp/src/afxdp/umem/mod.rs` | 150 | replace `tx.rs::stamp_submits` with current module path |
| `userspace-dp/src/afxdp/umem/tests.rs` | 518, 519, 1031, 1064, 1074 | replace with current paths |
| `userspace-dp/src/protocol.rs` | 1315 | replace `tx.rs:289/330` with current path |
| `userspace-dp/src/afxdp/worker/cos_tests.rs` | 312 | replace `tx.rs line ~250` with current path (v3 — Codex r2 catch) |
| `docs/userspace-capture-plan.md` | 118, 452 | replace with `userspace-dp/src/afxdp/tx/transmit.rs:transmit_batch()` |

Total: ~25 lines edited across ~13 files (vs original v1 estimate of
12 lines / 8 files). v2 is wider but still pure doc.

## 5. Public API preservation

None. Comments only.

## 6. Hidden invariants the change must preserve

- **No behavior change.** All tests must still pass byte-for-byte.
- **Historical retrospectives at the doc level (e.g., the multi-line
  rationale in `admission.rs:395-461` explaining why the policy
  changed in #785 Phase 3) stay as-is.** They're intentional record
  of why current code is the way it is.
- **`docs/pr/*/plan.md` files marked KILLED/WITHDRAWN** stay as-is.

## 7. Risk assessment

| Class | Level | Why |
|---|---|---|
| Behavioral regression | **NONE** | Comments only |
| Over-aggressive scrub | LOW | Each line listed individually; reviewer can flag specific lines |
| Missing references | LOW | Inventory is grep-derived; reviewer should run the same grep |

## 8. Test plan

- `cargo build --release` clean
- `cargo test --release` 977+ pass (no test changes; just verifying
  no comment edit accidentally landed inside a string/doctest)
- `go build ./...` clean
- `go test ./...` pass
- `grep -rn "COS_FLOW_FAIR_BUCKETS = 1024"
  userspace-dp/src/afxdp/cos/` returns nothing
- `grep -rn "flow_fair = queue.exact && !shared_exact"
  userspace-dp/src/afxdp/cos/` returns nothing

## 9. Out of scope

- The CI check (#1205) — separate PR
- Buffer-size unrelated `1024` references
- Adding new docs / clarifying anything beyond removing the stale text

## 10. Open questions for adversarial review

1. **Aggressiveness of the §3.B rewrite.** I'm replacing the comment
   text wholesale rather than just deleting "NOT" / "no SFQ DRR
   ordering". Is the replacement accurate per current code, or am I
   over-claiming about V_min sync semantics?

2. **Historical comparison parentheticals.** `types/cos.rs:99` says
   "(was ~58 KB at 1024)". I'm keeping it. Is that the right call,
   or should the parenthetical also be scrubbed?

3. **Whether the `tx.rs:262` style references should be dropped or
   updated.** Some references are useful as conceptual anchors even
   if the file moved. Drop, update to module-relative path, or
   case-by-case?

4. **Coverage gaps.** My grep was limited to
   `userspace-dp/src/afxdp/cos/`, `userspace-dp/src/afxdp/types/`,
   and `docs/`. Are there other paths with stale CoS references
   (e.g., `pkg/dataplane/userspace/`, `pkg/api/`, `cmd/`)?

## 11. Verdict request

PLAN-READY → execute scrub.
PLAN-NEEDS-MINOR → tweak specific lines; same scope.
PLAN-NEEDS-MAJOR → wider rewrite or different organization.
PLAN-KILL → unlikely; this is pure hygiene.
