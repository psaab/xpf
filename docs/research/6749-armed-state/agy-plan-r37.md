# AGY plan review — round 37 — #6749 armed-state plan v8.32 (83b95df94)

**Reviewer:** AGY (hostile, zero-tool-call inline-evidence
constraint). Prompt: `/tmp/agy-6749-r37-prompt.txt` (122,812 argv
bytes — r36 transport + the r36 table swapped in, the v8.32
normative edits replayed, the boilerplate rewritten for the v8.32
deltas). Raw output: `/tmp/agy-6749-r37.out`. Background bash
`bucziz25t` (direct `agy --print-timeout 9m --print`).

**Verdict: DEMAND-REVISION** (1 MAJOR + 1 MINOR + 2 NIT).

---

1. **[MAJOR] The missing-revision stamp-skip's phase-machine state
   is undefined** (plan §5-C (ii), §9 (a)): v8.32 says the stamp
   phase "SKIPS with an edge Warn" but never marks the phase
   complete — `isTerminal()` stays false, the entry strands in
   the pending set (no terminal GC — a memory leak), and the
   sweep re-drains and re-emits the Warn on every tick
   indefinitely. (SMR r37 SMR37-2 had the outcome naming but
   not the stranding consequence — recorded honestly.) Folded
   v8.33: the skip marks the phase `complete-skipped` (a
   TERMINAL phase outcome) under `m.mu` — the entry goes
   terminal and the sweep GCs it; the edge Warn fires ONCE at
   the skip, never per-tick.
2. **[MINOR] The Compile capture-point timing is unpinned**:
   folded v8.33 — the capture runs on successful AST/tree
   compilation immediately prior to staged object creation; a
   pre-publish Compile error discards the captured value with
   the stack frame (no cursor is ever created for a failed
   compile).
3. **[NIT] The determinism citation** (= SMR r37 SMR37-1):
   folded v8.33 (the store's canonical `Format()` render is
   deterministic per tree — the property `configTextDigest`'s
   `ActiveApplied()` use already relies on — so a same-pair
   staged reshape's re-capture is byte-identical).
4. **[NIT] §9 (a) lacks the missing-revision GC assertion**:
   folded v8.33 (after the complete-skipped marking, the entry
   transitions terminal and is GC'd on the subsequent sweep
   pass — a stranded-entry or per-tick-Warn implementation
   FAILS).

Evidence wishes (informational): `manager_compile.go:177-350`'s
exact failure boundaries.

DEMAND-REVISION
