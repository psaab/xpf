# AGY plan review — round 33 — #6749 armed-state plan v8.28 (676b176d5)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r33-prompt.txt` (131,062 argv
bytes — r32 transport + the r32 table swapped in, the v8.28
normative edits replayed, the boilerplate rewritten + trimmed
byte-by-byte to fit MAX_ARG_STRLEN). Raw output:
`/tmp/agy-6749-r33.out`. Background bash `b1fzlf70o` (direct `agy
--print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (1 BLOCKER + 1 MINOR + 1 NIT).

---

1. **[BLOCKER] The gated successor suppresses the LIVE exposed
   pair's push and stamp — silent primary↔peer divergence**
   (plan §5-C (ii), §6, §9 (a)): C1 exposed (notice queued); C2
   promoted but GATED (store-active, unexposed — its own push is
   HELD by the exposure check); C1's notice drains and the
   STORE-currency gate sees C1 no longer store-active → SKIPS
   C1's stamp and push. Net: the peer stays on A (C1 skipped,
   C2 held), `appliedRevision` stays at A, the primary runs C1
   — indefinite silent divergence while C2 remains gated
   (failover in the window runs A-policy with C1-era sessions).
   (Resolution folded v8.29: the stamp/push gate keys on
   EXPOSED currency (the notice's pair == `m.lastExposedPair`),
   NOT store currency — the SMR24-1 over-stamp case (the newer
   pair EXPOSED → skip) stays killed, and the gated-successor
   case (successor store-active but UNEXPOSED → C1 is still the
   exposed pair → stamp/push C1) now converges.) SMR r33 missed
   this (PLAN-READY-WITH-NITS this round — the SMR sweep
   re-derived the over-stamp direction but not the gated-lag
   direction; recorded honestly in the r33 ledger).
2. **[MINOR] The C2-gap union formula is wrong for re-permitted
   sessions** (plan §1 r32 row, §5-C (ii), §9 (a)): "every
   C2-permitted session survives all three" is FALSE — a session
   A-permitted, C-revoked, C2-re-permitted was deleted at C's
   exposure (correctly, at that time) and never recreated. The
   correct deleted set is (A∪C)\(C∩C2) (survivors
   (A∪C)∩C∩C2); intermediate revocations are permanent (the
   intended semantics — the final config re-permits via
   re-handshake, never resurrection). (Folded v8.29 with the
   corrected formula; the safety-critical direction — the
   stealer provably CANNOT over-delete (A\C2 ⊆ (A\C) ∪ (C\C2))
   — stands (SMR33-1 (ii)).)
3. **[NIT] The multi-gap (N > 2) generalization is unstated**
   (= SMR r33 SMR33-1 (i)) — folded v8.29.

Evidence wishes (informational): the notice drain's currency
check implementation; the held-push interaction in
daemon_ha_sync.go / sync_conn_config.go.

DEMAND-REVISION
