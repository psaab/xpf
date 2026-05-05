---
status: VALIDATED — strict-pin reproducibility confirmed
issue: https://github.com/psaab/xpf/issues/817
phase: #817 strict-pin scipy 1.13.1 / numpy 1.26.4 reproducibility check
---

## Summary

Per #817 acceptance: **all p-values match exactly** between the
committed Python 3.13 / scipy 1.16.3 / numpy 2.3.5 environment
and the strict-pin Python 3.11 / scipy 1.13.1 / numpy 1.26.4
environment. The classifier is fully deterministic across scipy
versions for this dataset; the gate-crossing concern flagged in
#817 (p5203-rev D2 = 0.0465 within Monte-Carlo 95 % CI of α=0.05)
is **RNG-deterministic, not scipy-version-sensitive**.

Closes #817.

## Methodology

**Pinned environment:**

```
Python 3.11.15 (uv-managed)
numpy==1.26.4
scipy==1.13.1
```

**Script version:** `test/incus/step1-histogram-classify.py` at
commit `9f789d87` (the last #816 version, before commit
`b2ffc829` / #827 added the `tx_kick_latency_hist` schema
requirement that's incompatible with the committed pre-#826
evidence). Captured to a temp path and run against a parallel
`docs/pr/816-step1-rerun/evidence-pinned/` tree (full copy of
the committed evidence).

**Run:**

```bash
# uv-managed Python 3.11 venv with pinned scipy/numpy
python /tmp/817-pinned-rerun/step1-histogram-classify-9f789d87.py \
    --evidence-root docs/pr/816-step1-rerun/evidence-pinned
```

Output verdict: `k_D1 = 4 of 11 (gate: k_v >= 2)`, `k_D2 = 3
of 11 (gate: k_v >= 2)` — same headline numbers as the
committed run.

## Results — committed vs pinned p-value diff

| cell                       | D1 orig p | D1 pin p | D1 Δ | D2 orig p | D2 pin p | D2 Δ |
|----------------------------|----------:|---------:|-----:|----------:|---------:|-----:|
| no-cos/p5201-fwd           |   0.05999 |  0.05999 |    0 |   0.29817 |  0.29817 |    0 |
| no-cos/p5202-fwd           |   0.96820 |  0.96820 |    0 |   1.00000 |  1.00000 |    0 |
| no-cos/p5203-fwd           |   0.97200 |  0.97200 |    0 |   1.00000 |  1.00000 |    0 |
| no-cos/p5204-fwd           |   0.96780 |  0.96780 |    0 |   1.00000 |  1.00000 |    0 |
| with-cos/p5201-fwd         |   0.00010 |  0.00010 |    0 |   1.00000 |  1.00000 |    0 |
| with-cos/p5201-rev         |   0.02060 |  0.02060 |    0 |   1.00000 |  1.00000 |    0 |
| with-cos/p5202-fwd         |   0.00010 |  0.00010 |    0 |   0.01200 |  0.01200 |    0 |
| with-cos/p5202-rev         |   0.92971 |  0.92971 |    0 |   0.02410 |  0.02410 |    0 |
| with-cos/p5203-fwd         |   0.62864 |  0.62864 |    0 |   1.00000 |  1.00000 |    0 |
| **with-cos/p5203-rev**     | **0.03550** | **0.03550** | **0** | **0.04650** | **0.04650** | **0** |
| with-cos/p5204-fwd         |       nan |      nan |    — |       nan |      nan |    — |
| with-cos/p5204-rev         |   0.78012 |  0.78012 |    0 |   1.00000 |  1.00000 |    0 |

**Aggregate:**
- D1: max \|Δ\| = 0.00000 across 11 finite-result cells
- D2: max \|Δ\| = 0.00000 across 11 finite-result cells
- α=0.05 gate-crossings between versions: **0**
- The p5204-fwd cell shows `nan` in both versions — evidence-quality
  artifact (suspect pool flagged independently by the classifier),
  not scipy-version-sensitive.

## Verdict against #817 acceptance criteria

- [x] `test/incus/step1-histogram-classify.py` re-run succeeds
      under `scipy 1.13.1 / numpy 1.26.4` (using the script
      version that matches the evidence's wire schema).
- [x] All p-values within Monte-Carlo 95 % CI of the committed
      values: **exact match (Δ=0) for all 11 finite-result cells.**
- [x] `perm-test-results.json` files re-derived in
      `docs/pr/816-step1-rerun/evidence-pinned/` (sister
      directory pattern).
- [x] Diff document landed at this path.

## Implications for the original concerns

1. **`p5203-rev-with-cos D2 = 0.0465` was flagged as within
   Monte-Carlo 95 % half-width of α=0.05.** Pinned re-run
   produces the **identical** value (0.04650, Δ=0). The
   Monte-Carlo seed is fully reproducible across scipy
   versions; the gate-crossing question was about RNG
   stream stability, and the answer is "the stream is
   identical, the gate-crossing is real (or its absence is
   real) — not version-noise."

2. **The committed evidence files record `scipy_version: 1.16.3`
   / `numpy_version: 2.3.5`.** The pinned files now exist
   alongside under `evidence-pinned/` for reviewers who need
   to validate against the strict-pin discipline.

## Note on script version

The committed evidence is pre-#826 (no `tx_kick_latency_hist`
key on the binding snapshot). The script at master HEAD enforces
that key as a wire-format invariant per #827 and refuses to
process the evidence. The strict-pin reproducibility check
inherently requires running the SAME script that produced the
committed `perm-test-results.json` — the script at
`9f789d87` (last #816 commit, before #827's schema requirement).
This is methodologically correct: scipy reproducibility is a
property of the analysis code + evidence + library versions
together, not of code that has since added unrelated invariants.

## References

- #816 — Step 1 classifier first-run plan + verdict.
- #826 — TX-kick wire-format wide-counter addition.
- #827 — P3 classifier extension that made
  `tx_kick_latency_hist` mandatory at the wire-format
  invariant level.
- `test/incus/requirements-step1.txt` — `scipy==1.13.1`,
  `numpy==1.26.4`.
- `docs/pr/816-step1-rerun/path-decision.md` — Path A/B
  decision context.
