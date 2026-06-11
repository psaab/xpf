PLAN-NEEDS-REVISION

Scope note: the worktree is at `3c837e1b4`, not `3541536c9`, and [plan.md](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:3) now says `Revision: r3`. I reviewed current r3 because it supersedes r2 with directly relevant folds.

**Prior 8 Findings**
1. F1 closed. Quote: “verifies the candidate at the cargo output path and only installs over the tracked ... `.o` on PASS” and “without privileges: the tracked `.o` is not updated” [plan.md:165](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:165).
2. F2 closed. Quote: “`.cargo/config.toml` becomes `linker = "bpf-linker"`” and the script checks “that resolved path” [plan.md:116](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:116).
3. F3 closed. Quote: “must NOT call `LoadUserspaceShim`/`loadUserspaceShimObjectsOnce` or anything that sets `PinByName`/`PinPath`/`MapReplacements`” [plan.md:183](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:183).
4. F4 closed for C2. Quote: “It DOES run the non-mutating spec checks production runs (`validateUserspaceShimSpec`...)” [plan.md:187](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:187).
5. F5 closed, but see new finding 4. Quote: “no `systemctl stop xpfd` and no `xpfd cleanup` may appear before the `verify-dataplane` pre-flight” [plan.md:265](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:265).
6. F6 closed. Quote: override “refuses the final install unless ... `XPF_SHIM_ALLOW_UNPINNED_INSTALL=1`” [plan.md:129](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:129), plus reproducibility gate [plan.md:277](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:277).
7. F7 closed. Quote: “the r1 ‘even if evaluated...’ side-claim is removed” [plan.md:141](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:141).
8. F8 closed. Quote: `MAX_INTERFACES=$(awk ... bpf/headers/xpf_common.h) cargo +<pin> fmt --check / clippy --release / test` [plan.md:271](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:271).

**New Findings**
1. HIGH - C1 remains weaker than C2. C1 only promises `ebpf.NewCollection` on the candidate [plan.md:160](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:160), while `validateUserspaceShimSpec` is only stated under C2 [plan.md:187](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:187). That means `make generate` can still install and commit a verifier-PASS object that production later rejects for map-shape drift. Fix: C1 and C2 should share one verify helper: load candidate or embedded spec, validate the unmodified spec, then optionally shrink for live-node anonymous load.

2. MED - `MaxEntries=1` shrink is asserted, not gate-proven. Quote: “hash-map max_entries does not feed program safety analysis, so the verifier outcome is unchanged” [plan.md:202](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:202). I believe that is true for hash lookup value-bounds today, but this plan makes C2 “authoritative” while loading a different map geometry than production. Add a root-gated equivalence test that loads PASS and preserved-REJECT objects both unmodified and shrunk on the same kernel and asserts identical verdicts.

3. MED - `taskset` mitigation lacks an implementable CPU contract. Quote: “taskset pinned away from the AF_XDP worker cores” [plan.md:208](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:208). The plan does not say how `deploy_vm()` discovers worker cores, what mask it uses, or whether an empty/invalid mask fails closed. R3 also still says the CPU hazard is “bounded by `nice -n 19`” [plan.md:304](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:304), contradicting the new taskset requirement. Specify the mask derivation and failure behavior.

4. MED - deploy ordering invariant is too narrow. It forbids early `systemctl stop xpfd` / `xpfd cleanup`, but current deploy code stops and cleans legacy `bpfrxd` before the xpfd block [cluster-setup.sh:659](/home/ps/git/bpfrx/.claude/worktrees/1864-research/test/incus/cluster-setup.sh:659). If a node is still under the legacy service name, the preflight can still happen after killing the active dataplane. Expand the invariant to “no dataplane stop, cleanup, pkill, binary replacement, or legacy-name migration before verify.”

5. LOW - TOML parsing is still under-specified. Quote: “quote/comment-tolerant extraction” plus regex validation [plan.md:104](/home/ps/git/bpfrx/.claude/worktrees/1864-research/docs/research/1864-toolchain-pin/plan.md:104). That closes empty fallback, but not wrong-table or duplicate `channel` extraction. Require exactly one `channel` key inside `[toolchain]`, reject duplicates, and validate the resolved override/install toolchain provenance.

Not a kill. The shape is good, but these are production-plan gaps, not wording nits.

Codex session ID: 019eb63d-3220-7cf0-9c10-4ae1999c193c
Resume in Codex: codex resume 019eb63d-3220-7cf0-9c10-4ae1999c193c
