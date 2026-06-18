# Claude SMR — hostile plan review (review-012 triage plans)

Independent (Claude) hostile pass over the five bug plans
(#1981/#1982/#1983/#1984/#1985). Severity tags follow
engineering-style.md (Medium+ = correctness/perf/contract; Low = style).

## #1982 — manifest SSOT — PLAN READY (with one MAJOR resolved inline)

- MAJOR (resolved in plan): "source the shipped xpf.bins at runtime"
  introduces a runtime file dependency for maintainer scripts (a missing
  file mid-upgrade = broken script). The plan correctly DEFERS to
  build-time inline (sed the generated BINS into the scripts at package
  build, like the existing `rules:61` ExecStartPre injection). VERDICT:
  build-time inline is the right call; the canary must then assert the
  COMMITTED scripts contain the generator's exact BINS line (so a hand-edit
  is caught), which the plan §4.4 covers. KEEP this.
- MINOR: `StagedSrc` for `xpf-day0-config` is `scripts/image/xpf-day0-config`
  (not a build output basename) — confirmed against `debian/rules:83`. The
  manifest metadata must carry the FULL source path per-binary, not assume
  `<name>` == source path. Plan's `Binary.StagedSrc` already does this.
  Good.
- TEST STRENGTH: the counter-factual (mutate a script's BINS, assert the
  canary reports divergence) meets the "recreate the failure mode" bar.
- VERDICT: PLAN READY. engineer-now. Scope is tight (no binary added).

## #1983 — rolling --unit endpoint — PLAN READY

- The plan's 4.1 (REJECT non-default unit) fully closes the correctness
  defect and is trivially testable via the existing fake-cluster seam. The
  dial-attempt recorder is a strong test (fails if code reaches the gRPC
  client). KEEP.
- SCOPE: 4.2 (clusterclient package + endpoint mapping) is a forward-looking
  enhancement, NOT required to fix the bug. Per engineering-style "narrow
  scope," ship 4.1 as the bug fix and file 4.2 separately UNLESS review
  finds the mapping trivial. The plan already frames this correctly.
- MINOR: confirm `DefaultUnit` value and that empty-string Unit (the
  zero-value path) is treated as default (it is — `cmd/xpfd/upgrade.go`
  defaults the flag to `upgrade.DefaultUnit`, but a programmatic caller
  could pass ""). The guard must accept both "" and DefaultUnit. Plan §4.1
  guards `cfg.Unit != "" && cfg.Unit != DefaultUnit` — correct.
- VERDICT: PLAN READY. engineer-now (4.1); 4.2 = tracked follow-up.

## #1984 — upgrade lock stale owner — PLAN READY

- The truncate-on-acquire fix is minimal and correct: `readOwner` already
  returns nil on empty (`lock.go:220`), so an empty file degrades to "busy,
  owner unknown" — strictly better than naming a dead PID.
- STRONG CALL (KEEP): the plan REJECTS `os.Remove` in Release on the
  split-mutex hazard (flock binds the inode, not the path — same class as
  the #1875 "never rm the cluster lock" lesson). This is the correct
  conservative posture; the tmpfs same-inode-reopen makes a lingering
  zero-length file harmless. Do NOT let review talk this into os.Remove
  without a concrete proof that no concurrent open()-then-flock straddles
  the unlink.
- TEST: the blocking-writeOwnerFn seam to reproduce the acquire→write
  window is the right reproduction; the assertion "Owner == nil, not A" is
  counter-factual-strong.
- MINOR: the added `f.Truncate(0)` must be on the SAME fd that holds the
  flock (it is — `f` post-Flock). No new fd. Good.
- VERDICT: PLAN READY. engineer-now. Severity is LOW-MEDIUM (diagnostics
  only; mutual exclusion unaffected) — correctly stated.

## #1985 — postrm exec-failure downgrade — PLAN READY (one MUST-VERIFY)

- The core fix (key downgrade detection on `dpkg --compare-versions "$2"`
  vs a static HARDENED_FLOOR, demote/drop the exec probe) is sound and
  mirrors the preinst safe pattern.
- MUST-VERIFY before engineer (flagged in plan §9): dpkg's postrm-on-upgrade
  `$2` semantics. In the dpkg call order, OLD-postrm runs as
  `postrm upgrade <new-version>` — so `$2` IS the new (incoming) version.
  Confirm against Debian Policy 6.5/ the dpkg maintainer-script flowchart
  during implementation; the test pair (upgrade>=floor survives,
  downgrade<floor tears down) pins it.
- RECOMMEND option (a): DROP the exec probe entirely once the version
  compare is authoritative. Keeping it as belt-and-suspenders (option b)
  re-admits the exec-failure foot-gun with zero benefit. The plan leans (a)
  — agree.
- TEST: non-execable staged xpfd on upgrade → layout survives; this
  recreates the exact failure mode. Strong.
- MINOR: empty/unparsable `$2` → safe branch (leave layout) + loud log.
  Plan §4.3 covers. Good.
- VERDICT: PLAN READY pending the `$2`-semantics confirmation in impl.
  engineer-now.

## #1981 — staged-generation immutability — PLAN READY-FOR-ARCH-REVIEW (mechanism OPEN)

- This is the HIGH finding and the only one NOT immediately engineer-ready:
  the mechanism (B immutable versioned staging vs C source-generation-id
  verified before+after) is deliberately left to plan review per the
  /research contract. That is correct — do not lock a mechanism without the
  architecture-review step (engineering-style workflow step 4: this crosses
  the packaging boundary).
- MAJOR on Option A (correctly rejected in plan): a `/run` sentinel
  spanning unpack→postinst reintroduces a dead-owner staleness subproblem
  (a crashed unpack wedges operator cuts until reboot). The plan rejects A
  — agree emphatically.
- MAJOR open question for Option C: is the post-copy `.generation` recheck
  window sufficient? A copy that BOTH starts and finishes within a single
  dpkg replace step could still read a stable-looking `.generation` while
  the binaries are torn. MITIGATION the plan already has: the manifest
  carries PER-BINARY checksums and the copied bytes are verified against
  them — so a torn binary is caught even if `.generation` didn't visibly
  change. This makes C robust IF the manifest is the per-binary-checksum
  kind, not just a bare genid. Review must confirm C uses per-binary
  checksums (it does, §4 Option C).
- COORDINATION: the generation manifest should be built over the #1982
  centralized binary list (don't create a third copy of the list). Plan §6
  notes this. KEEP the sequencing note: #1982 first (SSOT), then #1981
  builds the generation manifest on it.
- VERDICT: PLAN READY for the architecture review to pick B vs C (A
  rejected). needs-research until the mechanism is locked. Highest risk;
  requires step-4 arch review.

## Cross-cutting

- All five correctly observe engineering-style scope discipline (bug fix
  separate from behavior choice; #1983's 4.2 split out; #1981's mechanism
  not pre-decided).
- #1982 and #1981 SHARE the binary-list SSOT — sequence #1982 first.
- Test strength: all five plans specify counter-factual / failure-mode-
  reproducing tests, not arithmetic-consistency stubs. Good.

## Summary verdicts (Claude SMR)

| Issue | Verdict | Disposition |
|---|---|---|
| #1982 | PLAN READY | engineer-now |
| #1983 | PLAN READY | engineer-now (4.1); 4.2 follow-up |
| #1984 | PLAN READY | engineer-now |
| #1985 | PLAN READY (verify $2) | engineer-now |
| #1981 | PLAN READY for arch review (B vs C; A rejected) | needs-research |
