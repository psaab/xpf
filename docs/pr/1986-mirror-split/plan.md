# Plan: de-monolith `userspace-dp/src/afxdp/mirror.rs` (#1986)

- **Status:** DRAFT — recommendation **PLAN-KILL** (work already shipped under
  PR #2027; below-threshold per the project's own modularity floor; no further
  refactor churn warranted — see §2 and §10).
- **Issue:** #1986 (refactor backlog, AGY review 012 Part II.4)
- **Branch (research only):** `research/1986-mirror-split`
- **Reviewer pass:** COMPANION-FREE (no Codex/AGY). Hostile Claude-SMR
  self-review in `claude-smr-plan-r1.md`.

---

## 1. Issue framing

#1986 asks to de-monolith `userspace-dp/src/afxdp/mirror.rs` (reported 1402 LOC)
into a `mirror/` directory with four files:

```
mirror/
  mod.rs        # mirror configuration supervisor / entry
  fast_path.rs  # inline UMEM frame copy, descriptor staging, TX enqueue (HOT)
  resolver.rs   # cold netlink/logical-ifindex + target-binding lookups
  vlan.rs       # VLAN header injection / replication helpers
```

Stated rationale: the style guide's "No monolithic files" rule, and the
hot-path I-cache argument (colocating the descriptor-copy hot path with cold
resolver scans pollutes the I-cache; "latency is sacred"). Issue disposition is
explicitly `refactor-backlog` and says *do NOT plan-converge here* (research
contract) and to *refactor-with-the-next-mirror-feature rather than as a
standalone churn PR if possible*.

## 2. Honest scope and value — **the work is already done, and it was
below-threshold**

Two findings dominate this plan and drive the PLAN-KILL recommendation.

### 2a. The split has already shipped (PR #2027, merged 2026-06-19)

`origin/master` (HEAD `9979a89a0`) already contains
`userspace-dp/src/afxdp/mirror/{mod.rs, fast_path.rs, resolver.rs}` — the issue
is OPEN only because the merge did not auto-close it. Two commits did the work:

- `6cf888e78` — verbatim `mirror.rs` → `mirror/mod.rs` rename (git 0-line rename).
- `9019bb8bd` — move whole functions into `fast_path.rs` + `resolver.rs`.

PR #2027 title: *"#1986: de-monolith afxdp/mirror.rs into
mirror/{mod,fast_path,resolver,vlan}"*. There is **no `vlan.rs`** — correctly,
because there is no VLAN code to extract (§2c).

This research therefore is not a forward plan; it is a **post-hoc verification
+ disposition recommendation**. The verification (§6) confirms the shipped
split is pure, behavior-preserving, codegen-neutral code motion. So there is
nothing left to *do* except dispose of the issue.

### 2b. The file was below BOTH modularity thresholds — the "1402 LOC"
framing conflated test LOC with production LOC

`docs/engineering-style.md` "Modularity discipline" sets the floors precisely:

> A `.rs` file that crosses **~2,000 LOC of production code (excluding
> `mod tests`)** is a smell. By the time it hits **~3,000 LOC** the next change
> should split it before adding new logic. [...] when a single `mod tests`
> block accumulates **>200 tests** across unrelated subjects, colocate [...].

Measured on the pre-split `mirror.rs` (commit `af966eea3`, 1402 LOC total):

| Segment | Lines | Threshold | Over? |
|---|---|---|---|
| Production code (lines 1–411, before `#[cfg(test)]`) | **411** | ~2,000 smell / ~3,000 split | **No — 5x under the smell floor** |
| `mod tests` block (lines 412–1402) | **991** | n/a (LOC) | — |
| Tests in that block | **21** | >200 colocation trigger | **No — 10x under** |

The issue's "at 1402 and growing" counts the 991-line/21-test block as if it
were production code. By the project's own *stated* thresholds, `mirror.rs`
crossed **neither** floor: 411 production LOC vs a 2,000 smell floor, and 21
tests vs a >200 colocation trigger. This is the central honest-scope point: the
split was a discretionary cleanup, not a threshold-mandated one.

**This is NOT "the issue should never have been filed."** The same modularity
section also says "Treat the trend as a defect" and the issue's hot/cold-mixing
rationale (a per-packet UMEM copy colocated with cold lookup scans) is a
*legitimate, LOC-independent* cohesion target. The split was discretionary-but-
defensible on those grounds, and it was executed cleanly. The PLAN-KILL is
because the work is **already done**, not because the cleanup was illegitimate.

### 2c. The suggested `vlan.rs` had no source; the `resolver.rs` ifindex move
was elsewhere

The issue's suggested decomposition named a `vlan.rs` for "VLAN header
injection / replication helpers" and a `resolver.rs` housing
`resolve_ingress_logical_ifindex`. Neither exists in `mirror.rs`:

- The only `vlan` tokens in the original are the `ingress_vlan_id: u16`
  *parameter* (threaded into `resolve_mirror_config`) and `vlan_id:` *test
  fixture* fields. There is **no VLAN header construction/replication code** —
  the shipped split honestly omitted `vlan.rs`.
- `resolve_ingress_logical_ifindex` is defined in
  `userspace-dp/src/afxdp/forwarding/mod.rs:515` (`pub(super)`), not in
  `mirror.rs`. It was never extractable from this file.

So the issue's four-file target was partly aspirational; the shipped three-file
split (`mod` + `fast_path` + `resolver`) is the *real* cohesion boundary the
file supports.

### Value verdict

The shipped refactor is correct and harmless, and it does cleanly separate the
hot enqueue path from the cold lookup/accounting helpers. But against the
project's stated thresholds the file was below-floor, and the issue's own
disposition warned against a standalone churn PR. There is no remaining work
and no benefit to re-touching it. **PLAN-KILL: close #1986 as
resolved-by-#2027.**

## 3. What's already shipped (current `origin/master`)

```
userspace-dp/src/afxdp/mirror/
  mod.rs        1076 LOC  supervisor: constants, MirrorCloneResult enum,
                          select_mirror_config / resolve_mirror_config /
                          mirror_sample_allows, submodule decls + re-exports,
                          the full 21-test `mod tests`
  fast_path.rs   272 LOC  HOT: enqueue_mirror_clone, enqueue_sampled_mirror_clone,
                          enqueue_mirror_clone_to_binding (inline UMEM copy + TX
                          staging), enqueue_mirror_clone_to_live,
                          enqueue_admitted_mirror_clone_to_live,
                          enqueue_sampled_mirror_clone_to_live
  resolver.rs     91 LOC  COLD: mirror_target_binding_index,
                          admit_mirror_clone_to_live, mirror_cos_queue_id,
                          record_mirror_clone_result
```

`afxdp/mod.rs` declares `mod mirror;` (line 84) and `use self::mirror::*;`
(line 168) — unchanged glob, so all external callers see the same symbols.

## 4. Concrete split design (as shipped) with per-file contents + visibility

This documents what landed, since there is no new design to author.

### mod.rs (supervisor)
- `const MIRROR_TX_FRAME_RESERVE: usize` — `pub(in crate::afxdp)` (unchanged).
- `const MIRROR_PENDING_LIMIT: usize` — private (unchanged).
- `enum MirrorCloneResult` — `pub(in crate::afxdp)` (unchanged).
- `select_mirror_config`, `resolve_mirror_config`, `mirror_sample_allows` — all
  `pub(in crate::afxdp)` `#[inline]` (unchanged; stayed in mod.rs as the
  config/sampling entry points).
- `mod fast_path; mod resolver;` + re-exports:
  - `pub(in crate::afxdp) use fast_path::{enqueue_admitted_mirror_clone_to_live,
    enqueue_sampled_mirror_clone};`
  - `#[cfg_attr(not(test), allow(unused_imports))] pub(in crate::afxdp) use
    fast_path::{enqueue_mirror_clone, enqueue_mirror_clone_to_live,
    enqueue_sampled_mirror_clone_to_live};` (these are dead in non-test builds;
    the lint suppression mirrors the monolith's glob visibility).
  - `pub(in crate::afxdp) use resolver::{admit_mirror_clone_to_live,
    mirror_cos_queue_id, record_mirror_clone_result};`
  - `use resolver::mirror_target_binding_index;` (sibling-only private `use` —
    keeps it out of the wider `crate::afxdp` surface while letting
    `fast_path`'s `use super::*` resolve it; a `pub(super) use` of a
    `pub(super)` item would trip E0364, same constraint as `tx/mod.rs`).
- The full `#[cfg(test)] mod tests` (21 tests) stays in mod.rs. It exercises all
  three submodules through the parent's re-exports.

### fast_path.rs (HOT)
- `use super::*;` brings in the constants, enum, `resolve_mirror_config`,
  `mirror_sample_allows`, and the resolver helpers.
- All six `enqueue_*` functions, byte-identical bodies.
- `enqueue_mirror_clone_to_binding` stays **private** — it is in the same module
  as its only caller (`enqueue_mirror_clone`), so no module boundary was
  inserted between caller and this hottest inner copy (codegen argument, §7).

### resolver.rs (COLD)
- `mirror_target_binding_index`: was module-private with **no** `#[inline]` →
  widened to `pub(super)` + `#[inline]` added (documented in-file). The widening
  is forced: the fast path moved to a sibling module and must reach it.
- `admit_mirror_clone_to_live`: visibility unchanged (`pub(in crate::afxdp)`);
  `#[inline]` **added** (documented) to preserve same-module inlining across the
  new boundary.
- `mirror_cos_queue_id`, `record_mirror_clone_result`: already `#[inline]
  pub(in crate::afxdp)` in the monolith — unchanged.

## 5. Preserved pub API

External (non-mirror-module) callers and the symbols they use, all reachable
unchanged via `use self::mirror::*;`:

| Caller | Symbol |
|---|---|
| `afxdp/neighbor_dispatch.rs:238` | `enqueue_sampled_mirror_clone` |
| `afxdp/tx/dispatch/mod.rs:230` | `enqueue_sampled_mirror_clone` |
| `afxdp/poll_descriptor/flow_cache_hit.rs:226` | `resolve_mirror_config` |
| `afxdp/poll_descriptor/flow_cache_hit.rs:295` | `enqueue_admitted_mirror_clone_to_live` |

No external signature, name, or visibility changed. The crate-level surface is
identical pre/post split (verified: function set parity, §6).

## 6. Hidden invariants + verification performed

- **Function-set parity:** extracted every `fn` from the pre-split monolith and
  from the union of the three new files. **37/37 identical**, 0 lost, 0 added
  (29 logic helpers/entry points + 8 test helpers; plus the 21 `#[test]`).
- **Body equivalence:** brace-matched and whitespace-normalized every function
  body in both. **All 37 bodies byte-identical** — the only deltas are the two
  documented `#[inline]` attribute additions (outside the body) on
  `mirror_target_binding_index` and `admit_mirror_clone_to_live`.
- **Test relocation:** the `mod tests` block (21 tests) was **not split**; it
  stayed verbatim in mod.rs. This is consistent with the >200-test colocation
  trigger (21 ≪ 200) — colocation was not required, and keeping the tests in
  the parent lets them reach all three submodules through the re-exports without
  any test-visibility churn. (Note: the issue suggested per-file `mod tests`
  "as the tx/ and cos/ layouts" do; the shipped split chose NOT to, which is
  correct under the threshold but is a deviation from the issue text — see §11
  Q4.)
- **Hot-path codegen:** §7.
- **Visibility minimality:** exactly one symbol widened
  (`mirror_target_binding_index`, private → `pub(super)`), the minimal widening
  the cross-module move forces. No symbol was widened to `pub`/`pub(crate)`.

## 7. Hot-path codegen proof (issue-mandated)

The issue requires objdump/`cargo asm` proof the fast path still inlines.
`nm` on the post-split release binary (`target/release/xpf-userspace-dp`, built
this session):

| Function | Standalone symbols | Interpretation |
|---|---|---|
| `enqueue_mirror_clone_to_binding` (hot inner UMEM copy) | **0** | fully inlined |
| `mirror_target_binding_index` (cross-module move) | **0** | fully inlined |
| `admit_mirror_clone_to_live` (cross-module move) | **0** | fully inlined |
| `enqueue_mirror_clone` (entry) | **0** | fully inlined |

Zero standalone symbols ⇒ rustc inlined all four; the cross-module split did
**not** insert a call where there was none. The `#[inline]` additions on the
two cross-module helpers are doing exactly their job. This is the
inlining-neutrality the issue demanded.

Caveat: the pre-split baseline (all four inlined when colocated in one module)
is *inferred* from "single-module bodies are trivially inlinable," not
re-measured against the pre-split binary. The absence-of-symbol result is a
sound proof that no out-of-line call site was *introduced* by the split; if
anyone re-opens to double-check, `nm` the pre-split binary too for a direct
before/after.

## 8. Risk table (4-class)

| Class | Item | Severity | Notes |
|---|---|---|---|
| Correctness | Behavior drift in moved functions | **None (verified)** | 37/37 bodies byte-identical; 33 mirror tests green; 21/21 no flake over 5x. |
| Performance | Fast path stops inlining / I-cache regression | **None (verified)** | 0 standalone symbols for all 4 hot/moved fns; `#[inline]` preserved/added. Smoke (iperf3 -P16 ≥23 Gbit/s) is the only thing NOT run here — but with byte-identical bodies + identical inlining the dataplane is unchanged (§9). |
| API/surface | External callers break / visibility leak | **None (verified)** | Glob re-export unchanged; 4 external call sites resolve identically; exactly 1 minimal `pub(super)` widening. |
| Process/disposition | Re-doing already-merged work; issue left dangling | **Medium** | The real risk now is wasted churn. Mitigation = PLAN-KILL + close #1986 as resolved-by-#2027, do not re-touch. |

## 9. Test plan

Already executed in the research worktree (off `origin/master`):

- `cargo build --release` — **clean** (140 pre-existing warnings, none new from
  the mirror module).
- `cargo test --release mirror` — **33 passed / 0 failed** (21 in
  `afxdp::mirror::tests` + mirror tests in `neighbor_dispatch`, `tx`).
- **5x flake** on the most-affected target `afxdp::mirror::tests`
  (cross-module fast_path↔resolver admission boundary): **21/21 passed all 5
  runs, 0 flake**.
- **Codegen:** `nm` symbol check — all four hot/moved fns inlined (§7).

Not run here (out of scope for COMPANION-FREE plan-drafting; would be required
*only if* new code were being written, which it is not): the loss-userspace
cluster smoke (iperf3 -P16 ≥23 Gbit/s). Because the merged code is byte-
identical-body, identical-inlining code motion, the dataplane behavior is
provably unchanged at the source and codegen level; a smoke run would re-prove
the cluster baseline, not the refactor. If the team wants belt-and-suspenders
before *closing* the issue, run one `make cluster-deploy` + iperf3 -P16 sanity —
but that validates the cluster, not this change.

## 10. Recommendation

**PLAN-KILL.** The refactor is already merged (PR #2027), verified pure /
behavior-preserving / codegen-neutral, and — per the project's own stated
thresholds — the file was below both the ~2,000-LOC production smell floor (it
was 411 production LOC) and the >200-test colocation trigger (21 tests). The
issue's "1402 LOC" framing counted the test block as production code. There is
no remaining work and the issue itself warned against standalone churn.

Action: **close #1986 as completed/resolved-by-#2027** (optionally with a one-
line note that `vlan.rs` was correctly omitted — no VLAN source existed — and
that the production-LOC was below threshold so this was a discretionary, not
mandated, cleanup). Do **not** open another PR.

## 11. Open questions (≥5)

1. **Disposition mechanics:** close #1986 directly as resolved-by-#2027, or
   leave it open with a `wontfix-residual` note covering the unbuilt `vlan.rs`?
   (Recommend: close — there is no `vlan.rs` work to leave open.)
2. **Threshold doc drift:** should the bi-weekly Rust-LOC audit that *generated*
   this issue switch to counting **production LOC excluding `mod tests`** (per
   the style guide) rather than total file LOC? mirror.rs (411 prod / 991 test)
   is a clean example of the audit over-counting. Worth a one-line audit-script
   fix so future below-floor files aren't filed.
3. **`select_mirror_config` placement:** it lives in mod.rs but is dead in
   non-test builds (only `resolve_mirror_config` + the enqueue fns are called by
   production). Is mod.rs the right home, or should the dead-in-prod config
   entry points be marked/grouped differently? (Cosmetic; out of scope.)
4. **Per-file `mod tests` deviation:** the issue asked for per-file colocated
   tests "as tx/ and cos/ do"; the shipped split kept one `mod tests` in mod.rs.
   Under the >200 trigger this is correct, but it is a literal deviation from
   the issue text. Accept as-is, or is there appetite to colocate anyway for
   consistency with tx/cos? (Recommend: accept — colocating 21 tests across 3
   files would be churn for churn's sake and force more re-exports.)
5. **`enqueue_mirror_clone_to_binding` privacy:** it is private in fast_path.rs,
   same module as its caller. If a *future* mirror feature needs to call it from
   resolver.rs or mod.rs, the boundary would force a `pub(super)` + `#[inline]`
   widening (the same pattern resolver.rs already documents). Is that future
   foreseeable, or leave it private until a real caller appears? (Recommend:
   leave private — widen on demand.)
6. **Smoke before close:** is a single iperf3 -P16 cluster sanity run wanted
   before closing #1986, given the change is already on master and serving? Or
   is the source/codegen equivalence proof sufficient? (Recommend: sufficient;
   the code already shipped and any regression would already be observable.)
7. **AGY review-012 index follow-on:** #1986 was "highest-value of the five" in
   that index. If it's below-threshold, are the other four in the same index
   also over-counted (total-LOC vs production-LOC)? Worth re-checking the index
   denominators before picking up the next one.
