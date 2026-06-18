# Claude SMR — hostile plan review r2 (#1981)

**Plan:** `docs/research/1981-staged-generation-immutability/plan.md` r2
**Verdict:** **PLAN-READY with two MINOR tightenings to fold at engineer time.**

r2 flips the recommendation to Option B. I verified the flip is sound and that
every r1 finding is genuinely mooted or carried as a D-fallback fix. I then
attacked B for new failure modes the flip could have introduced. Two MINORs; no
MAJOR remains. Architecture is correct.

## Verification that r1 findings are closed (not just relabeled)

- **SMR r1-MAJOR1 / Codex r1-#1 (preinst ordering):** B writes nothing in
  preinst → the false-refusal-on-contended-abort vector does not exist. ✓
- **AGY r1-#1-CRIT / Codex r1-#2 (abort-unwind permanent wedge):** B does
  nothing on dpkg error-unwind; an aborted unpack simply does not publish a new
  generation and the prior `staged-gen/<g>` stays valid. The wedge class is
  STRUCTURALLY absent, not handled-by-careful-scripting. ✓ (this is the whole
  reason to prefer B)
- **Codex r1-#3 (#1967 stale snapshot):** B-P3 resolves the source at INIT,
  pre-PREFLIGHT, so a no-source refusal writes no journal and takes no
  `.dbsnap`. ✓ — but see MINOR-1 for the resume-keying detail.
- **Codex r1-#4 / AGY r1-#3 (seed manifest + fallback):** §4.B.4 + B-P1 publish
  on seed incl. the seed-failure fallback. ✓ — but see MINOR-2 (publish-failure
  must be loud, not silently-skipped).
- **AGY r1-#2 (first-install window):** the cut reads only published
  generations, never a partially-unpacked live `staged/`. ✓
- **Codex r1-#5 (.generation in version dirs):** mooted (no marker file). ✓
- **All-three B-not-earned:** acted on (flip). ✓

## MINOR-1 — GC must protect the genid an in-flight cut journaled; specify the publish/GC lock posture

B-P2/§6 say `staged-gen` GC protects `current-gen` and retains N=3. Consider:
an operator cut resolves `current-gen -> <g5>` at INIT and records `<g5>` in the
journal, then begins the (slow) copy `staged-gen/<g5> -> versions/<ver>.partial`.
Concurrently a SECOND package transaction's postinst publishes `<g6>`, repoints
`current-gen -> <g6>`, and runs GC, which now sees `<g5>` beyond the protected
set and removes it MID-COPY. The cut's `copyTree` from a vanishing dir errors —
which is a SAFE pre-STOP refusal, not corruption, so this is MINOR not MAJOR.

But it is avoidable and the plan should pin the contract:
1. The postinst publish + GC should run UNDER the host-wide upgrade lock
   (`/run/xpf/upgrade.lock`), exactly as the cut does, so the publish/GC and a
   cut are mutually exclusive. The existing apt-vs-operator preinst gate
   (#1965) already makes the common case exclusive (an operator cut holding the
   lock aborts a concurrent apt), but the publish itself currently runs OUTSIDE
   the lock in the postinst — taking the lock for the publish closes the
   TOCTOU residual (`postinst:123`) for the new publish/GC too.
2. Belt-and-suspenders: `staged-gen` GC should ALSO protect any genid referenced
   by an in-progress journal (mirror how `versions/` GC protects
   target/previous). The journal records the source genid (B-P3) — GC reads it
   and skips it.

State both in §6. Neither changes the recommendation.

## MINOR-2 — a publish FAILURE must be loud and must not silently let a cut read a STALE generation as "the upgrade"

B's publish is correctly best-effort-for-the-postinst (a failure must not
half-configure dpkg — mirrors the #1964 seed fallback). But there is a subtle
correctness trap the plan should name explicitly:

If the postinst publish fails (ENOSPC at install time, etc.) and is silently
skipped, `current-gen` still points at the PRIOR generation (the OLD binaries).
A subsequent operator `xpfd upgrade` then resolves the source to the OLD
generation, reads `TargetVersion == current version`, and the cut is an
idempotent no-op (`Run` short-circuits at `StateCommitted` / "already
committed"). The operator BELIEVES they upgraded; nothing changed.

This is safe (no torn set, no downgrade) but operationally confusing. The plan
should require:
- the postinst publish failure is logged LOUDLY (it already plans to fail
  loudly per B-P7 — extend that to the install-time publish, not just the cut
  PREFLIGHT), and
- `apt`/operator guidance: a "no new generation published" condition is
  surfaced (e.g. the postinst emits a clear warning + the same
  `/run/xpf/upgrade-deferred` style marker the #1965 TOCTOU branch uses), so the
  operator knows the staged binaries are present but not yet a cut source and
  must free disk + re-run.

Add this to §6 (B-P7) and §7 test 5. MINOR because the failure is fail-safe; the
fix is observability, not correctness.

## What is RIGHT

- The dpkg model (§1), the postrm purge handling (B-P6), and the
  not-a-dpkg-payload-file reasoning are all correct and corroborated by the
  postrm's own documented marker trap.
- B genuinely closes the torn-read BY CONSTRUCTION for all four managed binaries
  — the cut reads a dir dpkg is not touching. This is qualitatively stronger
  than D's "detect-and-refuse," which depends on five correct maintainer-script
  edits.
- The honest disk-cost framing (§4.B costs, B-P7) and keeping D as a fully-spec'd
  fallback (D-fix-1..5) is exactly the right shape for a research deliverable —
  the user can pick D if `/var` is too tight, with the corrected spec in hand.
- The INIT-vs-PREFLIGHT resolution (B-P3) is the right place and closes #1967 by
  construction.
- The test plan's counter-factual (point pre-fix copyStaged at torn live
  `staged/`, show the self-checksum passes) recreates the failure mode per
  engineering-style.

Fold MINOR-1 (lock the publish/GC + journal-genid GC protection) and MINOR-2
(loud publish-failure + no-silent-stale-cut) into §6/§7 and this is fully
PLAN-READY. Recommendation (Option B) ratified.
