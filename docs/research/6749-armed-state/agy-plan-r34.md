# AGY plan review — round 34 — #6749 armed-state plan v8.29 (f67996d5f)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r34-prompt.txt` (117,962 argv
bytes — r33 transport + the r33 table swapped in, the v8.29
normative edits replayed, the §6 standing Configstore/manager/debt/
control-verb inventory (v8.10-v8.17, settled r22-r28) elided to fit
MAX_ARG_STRLEN with margin). Raw output: `/tmp/agy-6749-r34.out`.
Background bash `bba8w0cvx` (direct `agy --print-timeout 9m
--print`).

**Verdict: DEMAND-REVISION** (1 BLOCKER + 1 MINOR).

---

1. **[BLOCKER] The CAS expected basis conflicts with the
   EXPOSED-currency gate for gated successors** (plan §5-C (ii)
   (b), §1 r33 row; store.go:848): the v8.26 "CAS form (expected
   store-current revision)" can key on the store's ACTIVE
   revision — which is C2 in the gated-successor window — and
   REFUSE C1's stamp even though the v8.29 gate admitted it
   (`appliedDigest` stuck at A for the whole gated window).
   (AGY's remediation: the CAS expected value is the store's
   applied/exposed revision, not the active.) SMR r34 SMR34-1
   found the same defect from the CODE side and sharpened the
   fix: the actual machinery (store.go:787-853) is DIGEST-based
   with NO revision CAS (`MarkAppliedDigest` overwrites
   unconditionally; `ActiveApplied()` is the read-side digest
   comparison) — the v8.26 revision-CAS phrasing is RETRACTED
   and replaced by the CAPTURED-DIGEST stamp
   (`MarkAppliedDigest(pair.capturedDigest)` — never
   `MarkActiveApplied()` (stamps the never-applied successor —
   the r30 f1 / #6296 class)) with the anti-stale protection
   riding the v8.29 EXPOSED-currency ADMISSION gate.
2. **[MINOR] §9 (a) omits the stamp-LANDS assertion**: a
   stamp-call-that-internally-fails would still fire the push
   and green the test while `appliedDigest` never advances.
   (= SMR r34 SMR34-2; folded v8.30: assert
   `appliedDigest == configTextDigest(C1's text)` after C1's
   drain with C2 gated, and `== digest(C2)` after C2's apply.)

Evidence wishes (informational): `setAppliedDigest`'s actual
comparison basis — answered by SMR r34's source read
(digest-based, no revision CAS).

DEMAND-REVISION
