# Codex hostile plan review r2 (#1981)

**Verdict:** PLAN-NEEDS-MAJOR (mechanism B ratified: "I still think B is the right direction over D"; spec needs tightening)

Verbatim Codex output:

---

PLAN-NEEDS-MAJOR

r2 did fold all six r1 findings on paper: §11 maps #1/#2 to B-mooted plus D-fallback fixes, #3 to INIT source resolution, #4 to seed/fallback publish, #5 to removing `.generation`, and #6 to flipping the recommendation to B.

I still reject r2 as ready.

1. **First deployment of B is still vulnerable.** During the upgrade that installs the first B-aware binary, the operator-visible `xpfd upgrade` is still the old binary. The current preinst explicitly says the lock probe is released before unpack and an operator can still acquire the lock during unpack: [debian/xpf.preinst](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/debian/xpf.preinst:15). The old `Run()` reads `r.cfg.StagedDir` and copies live `staged/`: [cutover.go](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/pkg/upgrade/cutover.go:116), [cutover.go](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/pkg/upgrade/cutover.go:520). B only protects cuts made by a B-aware binary after `postinst` publishes a generation. The plan’s absolute “never reads live staged” claim needs either a first-rollout exception or a real mitigation.

2. **Same-version reinstall is not solved.** r2 adds distinct genids for same-version reinstalls: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/docs/research/1981-staged-generation-immutability/plan.md:275). But destination dirs are still keyed only by `TargetVersion`, and `copyStaged` skips an existing `versions/<ver>`: [cutover.go](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/pkg/upgrade/cutover.go:512). A new generation with the same version can be published and then never copied. Worse, an existing stale or pre-fix torn `versions/<ver>` can be reused. B needs either genid-keyed destination dirs or a durable source-gen stamp in `versions/<ver>` with “skip only if same genid” semantics.

3. **Publish/GC concurrency is underspecified.** `Run()` holds the upgrade lock for the cut: [cutover.go](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/pkg/upgrade/cutover.go:61). B-P1 says postinst publishes unconditionally before the auto-cut branch, but does not say publish or staged-gen GC takes that same lock: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/docs/research/1981-staged-generation-immutability/plan.md:251). If a cut journals old gen `g0` and a concurrent publish advances `current-gen` then GCs, `g0` can disappear before or during copy unless GC protects journaled source gens or publish is serialized with cuts.

4. **INIT ordering can close #1967, but only if the journal grows.** Current `Journal` has no source generation field: [state.go](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/pkg/upgrade/state.go:115). B-P3 correctly says resolve `current-gen` at INIT and persist the genid before PREFLIGHT: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/docs/research/1981-staged-generation-immutability/plan.md:264). That is implementable and does avoid the no-source stale-snapshot regression, provided `copyStaged` never re-reads `current-gen` and never copies through the symlink path.

5. **Disk handling is not honestly closed.** B-P7 contradicts itself: it says PREFLIGHT must include publish, then admits publish happens before the cut’s PREFLIGHT: [plan.md](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/docs/research/1981-staged-generation-immutability/plan.md:287). The publish command needs its own free-space check and staged-gen GC before copying. On upgrade, ENOSPC can leave the prior generation valid. On first install, there is no prior generation, and current postinst policy falls back to direct-staged links on seed failure: [debian/xpf.postinst](/home/ps/git/bpfrx/.claude/worktrees/agent-a36484bfb0c4193ed/debian/xpf.postinst:58). That contradicts “first manual cut is never sourceless” unless publish failure fails configure or has a guaranteed fallback publish path.

For dpkg abort-unwind: B’s core claim is mostly right after B is installed. Official Debian Policy says unpack errors unwind maintainer scripts in reverse, and `postinst configure` runs after unpack with no unwind after configuration failure. Since `staged-gen/` is not a dpkg payload path, aborted unpack should not delete the prior generation; a crash before publish rename leaves `.partial`, and a crash after rename but before `current-gen` leaves prior `current-gen` usable. Source: Debian Policy Manual §6.6/§6.7: https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html

I still think B is the right direction over D. D has the same first-deploy old-binary limitation and much more maintainer-script lifecycle coupling. But r2 needs a major revision for rollout scope, same-version destination identity, publish/GC locking, and first-install ENOSPC semantics before it is PLAN-READY.
