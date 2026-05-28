# Codex plan-review r1 — #1623 v3.2 (task-mppkw5cs-ca6c61)

Verdict: PLAN-NEEDS-MAJOR

`codex-companion` was not available on `PATH`; I dispatched background reviewer agents instead and reviewed `55abf355f` via `git show`.

Findings:

1. **Severity: BLOCKING**  
   **Section: §6.4 / §6.7**  
   **Evidence:** §6.4 says “evaluate ONLY the (≤ 64) emitted candidates” and then returns default after `scratch[..emitted]`; it also admits “rules beyond the first 64 in merge order are silently skipped” ([plan.md:294](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:294), [plan.md:313](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:313)). §6.7 still claims first-match-wins is preserved ([plan.md:356](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:356)).  
   **Counterexample:** 65 zone-pair candidates survive Stage 2/LPM; first 64 are Stage false positives that fail `try_match_rule` due source-port/range details, candidate 65 matches. v3.2 returns default or falls through incorrectly.  
   **Fix:** overflow must be commit-rejected for `multi_stage_dag`, or the feature must be explicitly unsafe opt-in. Production mode cannot silently truncate.

2. **Severity: BLOCKING**  
   **Section: §6.4**  
   **Evidence:** loop calls `merge_iter.next()` before the claimed `64 × try_match_rule` bound ([plan.md:281](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:281)); claimed bound only counts `try_match_rule` ([plan.md:307](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:307)).  
   **Counterexample:** Stage2 has 1M rules, src citation slice has odd IDs, dst citation slice has even IDs. Zero emissions, but merge must traverse/gallop through large slices to prove no intersection.  
   **Fix:** specify and enforce a merge-step/comparison budget, or commit-reject configs whose candidate slices can exceed the bounded merge envelope. The real bound must include merge work, not only `try_match_rule`.

3. **Severity: BLOCKING**  
   **Section: §7.2**  
   **Evidence:** “if S currently has a longer-prefix entry → leave alone” conflicts with “INHERIT the parent’s coverage into every slot” ([plan.md:424](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:424), [plan.md:429](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:429)).  
   **Counterexample:** book A has `10.0.0.0/16`, book B has `10.0.1.0/24`; address `10.0.1.5` must cite A and B. “leave alone” can drop A under the /24.  
   **Fix:** build shortest-to-longest; each child slot value must be `parent_coverage ∪ child_contributions`, deduped and sorted.

4. **Severity: MAJOR**  
   **Section: §7.1 / §7.2**  
   **Evidence:** §7.1 says walk top-down before child prefixes; §7.2 loops over `entries` and says “Apply at the deepest stride first” without pinning sort order ([plan.md:384](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:384), [plan.md:410](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:410)).  
   **Fix:** make pass-2 deterministic: process `/0`, `/8`, `/16`, `/24`, then longer overflow tables; child tables are materialized from parent coverage before child additions.

5. **Severity: BLOCKING**  
   **Section: §6.2**  
   **Evidence:** v6 arena is `Vec<u8>` with `SubTrie { offset, len }`; §11 leaves `Vec<u8>` to `&[Node]` cast soundness open ([plan.md:220](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:220), [plan.md:620](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:620)).  
   **Fix:** use `Vec<Node>` or an explicitly aligned arena with offsets in `Node` units. Do not reinterpret `Vec<u8>` as `&[Node]`.

6. **Severity: MAJOR**  
   **Section: §6.1**  
   **Evidence:** API takes runtime `Side` plus shared `LpmLeafId` ([plan.md:203](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:203)); plan claims wrong-side use is “a type error” ([plan.md:213](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:213)).  
   **Fix:** distinct `SrcLpmLeafId` / `DstLpmLeafId`, and `cited_rules_src` / `cited_rules_dst`.

7. **Severity: MAJOR**  
   **Section: §6.3**  
   **Evidence:** `Multi(Arc<[u32]>)` then “8 B per slot worst case” ([plan.md:248](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:248), [plan.md:256](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:256)). `Arc<[T]>` is a fat pointer.  
   **Fix:** either update memory/cache modeling to real enum size, or use an 8-byte tagged value with `Multi(pool_id)` into an external slice pool.

8. **Severity: MAJOR**  
   **Section: §8**  
   **Evidence:** `SmallVec<[&'a [u32]; 8]>` is claimed allocation-free ([plan.md:516](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:516)). `SmallVec` allocates above inline capacity.  
   **Fix:** enforce `candidate_slices <= 8` at build time, or use a non-spilling `ArrayVec`/fixed array and hard-reject overflow.

9. **Severity: MAJOR**  
   **Section: §8 / §6.4**  
   **Evidence:** MatchAny is “unioned with the MatchAny channels” without exact ordering/dedupe semantics ([plan.md:508](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:508)).  
   **Fix:** define one sorted, unique local-rule stream per phase. MatchAny-side rules must still be intersected with the constrained opposite side and Stage2, then deduped before consuming scratch.

10. **Severity: MAJOR**  
    **Section: §10 / §3**  
    **Evidence:** §3 says Step 1 includes “bounded v6 sub-trie”; §10 says “stub for v6” and defers v6 arena to Sub-PR F ([plan.md:100](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:100), [plan.md:564](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:564), [plan.md:594](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:594)).  
    **Fix:** choose one. Either Step 1 ships bounded v6, or §3 must say Step 1 is v4-only plus v6 stub.

11. **Severity: MAJOR**  
    **Section: §9**  
    **Evidence:** knobs are under `chassis cluster cos policy`; §11 admits policy lookup is independent of CoS and `security policies global lookup` is more canonical ([plan.md:523](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:523), [plan.md:657](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:657)).  
    **Fix:** move fields under `SecurityConfig`, e.g. `set security policies lookup ...`, `stage4-buffer-size`, `lookup-v6-leaf-max`.

12. **Severity: MAJOR**  
    **Section: §6.4 / §8**  
    **Evidence:** `galloping_merge_evaluate` returns `PolicyEvaluationResult` default on miss ([plan.md:303](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:303)), while §8’s `evaluate_phase` is used as `Option` and should allow global fallback ([plan.md:481](/home/ps/git/bpfrx/.claude/worktrees/1623-multi-book-lpm-v3-2/docs/pr/1623-multi-book-lpm-v3-2/plan.md:481)).  
    **Fix:** phase evaluator returns `Option<PolicyEvaluationResult>`; only top-level returns default after zone-pair and global both fail.

Closure audit: #2, #10, #11, and most of #13 are ratifiable. #1/#9, #3, #4, #5, #6, #7/#12, and #8 are not closed as written. §5’s empirical deferral is honest for performance, but Sub-PR H must also be gated on correctness, allocation, HA, and protocol parity, not only #1612 measurement.
