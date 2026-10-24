#!/usr/bin/env python3
"""#827 P3 classifier tests — T1 gating + report shape.

Step3 reads `hist-blocks.jsonl` (written by step1); invariants K0-K3
are exercised in `step1-histogram-classify_test.py` instead. These
tests only cover step3's side of the #827 plan R2 MED-2
source-of-truth split.
"""
from __future__ import annotations

import json
from pathlib import Path

# #8136: pytest is not installed here and these run under `unittest
# discover`. unittest_shim supplies the three pytest features this file
# uses (raises/approx) plus the load_tests collector for its module-level
# test functions, which unittest would otherwise not find at all.
from unittest_shim import approx, collect_module_tests, raises

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from load_subject import load_subject  # noqa: E402


SCRIPT_DIR = Path(__file__).resolve().parent



classify_mod = load_subject("step3_tx_kick", SCRIPT_DIR / "step3-tx-kick-classify.py")


def make_block(
    b: int,
    T_D1: float,
    retry: int = 0,
    count: int = 0,
    sum_ns: int = 0,
    kick_hist: list[int] | None = None,
) -> dict:
    """Construct a synthetic hist-blocks entry. `T_D1 = shape[3..=6] sum`.

    We distribute the T_D1 mass evenly across buckets 3-6 and the
    remainder across bucket 0. All other fields default to 0.
    """
    if kick_hist is None:
        kick_hist = [0] * 16
        kick_hist[0] = count
    shape = [0.0] * 16
    share = T_D1 / 4.0
    for i in (3, 4, 5, 6):
        shape[i] = share
    shape[0] = max(0.0, 1.0 - T_D1)
    return {
        "b": b,
        "shape": shape,
        "tx_kick_retry_delta": retry,
        "tx_kick_count_delta": count,
        "tx_kick_sum_ns_delta": sum_ns,
        "tx_kick_hist_delta": kick_hist,
    }


def make_12_blocks(T_D1_list: list[float], **block_kwargs) -> list[dict]:
    """12-block fixture. `block_kwargs` can be a dict-of-lists to override
    individual blocks; otherwise every block gets the same kwargs."""
    assert len(T_D1_list) == 12
    blocks = []
    for i, td1 in enumerate(T_D1_list):
        bk = {}
        for k, v in block_kwargs.items():
            bk[k] = v[i] if isinstance(v, list) else v
        blocks.append(make_block(i, td1, **bk))
    return blocks


# ---------------------------------------------------------------- 1 ----
def test_block_delta_arithmetic_read_from_hist_blocks():
    """Step3 reports kick_latency_mean_ns = sum_ns_delta / count_delta."""
    blocks = make_12_blocks(
        [0.99] * 12,
        retry=[50] * 12,
        count=[1000] * 12,
        sum_ns=[3_000_000] * 12,  # 3 µs mean
    )
    diag = classify_mod.classify(blocks)
    for blk in diag["per_block"]:
        assert blk["kick_latency_mean_ns"] == approx(3000.0)
        assert blk["retry_count_delta"] == 50
        assert blk["kick_count_delta"] == 1000


# ---------------------------------------------------------------- 2 ----
def test_integer_gating_stable_at_2_53_scale():
    """Integer cross-multiplication stays correct at 2^53-scale values.

    This is a large-values sanity pin, NOT a float-vs-integer
    discrimination (per code-review R1 LOW-1 + R2 residual). At the
    T1 thresholds (4096 / 2048 ns) and realistic workload
    cumulatives (10^4-10^7 kicks/block, sum_ns ~10^7-10^11), f64
    never loses the precision that would swing the comparison, so
    integer and float gating would agree anyway. We pin correctness
    at 2^53-scale to verify the integer code path doesn't overflow,
    underflow, or accidentally coerce to float.
    """
    # count = 2^53, sum_ns = 3000 * count — mean 3000 ns (OUT-band
    # latency, retry=0). Verdict: NOT IN, NOT OUT (mean > 2048) →
    # INCONCLUSIVE. Float and integer math agree at this scale.
    big_count = 2 ** 53
    big_sum = big_count * 3000
    blocks = make_12_blocks(
        [0.99] * 12,
        retry=[0] * 12,
        count=[big_count] * 12,
        sum_ns=[big_sum] * 12,
    )
    diag = classify_mod.classify(blocks)
    # Integer check: 3000 * big_count vs 2048 * big_count — 3000 > 2048
    # so OUT clause's `sum_ns < 2048*count` is false → NOT OUT. With
    # retry=0 < 1000 and mean=3000 < 4096, NOT IN either → INCONCLUSIVE.
    assert diag["verdict"] == "INCONCLUSIVE"
    # Direct integer-math sanity (the production verdict path):
    assert classify_mod.t1_in_block(0, big_count, big_sum) is False
    assert classify_mod.t1_out_block(0, big_count, big_sum) is False


# ---------------------------------------------------------------- 3 ----
def test_no_kick_block_handled():
    """count_delta == 0 → no_kick=True; out clause vacuously true."""
    blocks = make_12_blocks(
        [0.99] * 12,
        retry=[0] * 12,
        count=[0] * 12,
        sum_ns=[0] * 12,
    )
    diag = classify_mod.classify(blocks)
    for blk in diag["per_block"]:
        assert blk["no_kick"] is True
        assert blk["kick_latency_mean_ns"] == 0.0
        assert blk["T1_in_sufficient_block"] is False
        assert blk["T1_out_block"] is True
    assert diag["verdict"] == "OUT"


# ---------------------------------------------------------------- 4 ----
def test_t1_in_verdict_topquartile_with_ties():
    """IN witness in elevated block; 3rd-place tie keeps all tied blocks."""
    # Block 11 has the IN signature.
    # T_D1 list: blocks 2, 7, 9 tie for 3rd place (0.95); block 11 tied.
    T_D1 = [0.10, 0.20, 0.95, 0.30, 0.40, 0.50, 0.60, 0.95, 0.70, 0.95, 0.80, 0.95]
    retry = [0] * 12
    count = [100] * 12
    sum_ns = [100 * 1000 for _ in range(12)]  # 1000 ns mean — OUT band
    retry[11] = 1500
    sum_ns[11] = 100 * 5000  # 5 µs mean — above bucket-3 lower edge
    # Block 11 is in ElevatedBlocks (T_D1 = 0.95 ties top).
    blocks = make_12_blocks(T_D1, retry=retry, count=count, sum_ns=sum_ns)
    diag = classify_mod.classify(blocks)
    assert diag["verdict"] == "IN"
    assert diag["T1_in_witness_block"] == 11
    # Tied-elevated blocks: 2, 7, 9, 11 all >= 0.95.
    assert sorted(diag["elevated_blocks"]) == [2, 7, 9, 11]


# ---------------------------------------------------------------- 5 ----
def test_t1_in_witness_outside_elevated_yields_not_in():
    """IN-shape block exists but outside top quartile → NOT IN.

    Plan §5.1 test #5 + code-review R1 MED-1: the load-bearing pin
    is `verdict != IN`. The actual verdict here is INCONCLUSIVE
    because block 5's retry=1500 also fails OUT's retry<100 clause
    (per §4.4 ∀-quantifier on OUT — every block must satisfy it).
    A block can't be IN-shape AND OUT-shape simultaneously by
    construction (the bands are disjoint), so the only way to get
    verdict OUT here would be to make block 5 NOT IN-shape, which
    would defeat the test's purpose. INCONCLUSIVE correctly
    proves the elevated-membership gate works.
    """
    # T_D1 rank: block 5 is 4th (below the top-3 threshold).
    T_D1 = [0.1, 0.2, 0.99, 0.98, 0.97, 0.50, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]
    # IN signature on block 5 (which is NOT elevated).
    retry = [0] * 12
    count = [100] * 12
    sum_ns = [100 * 1000 for _ in range(12)]  # OUT band everywhere else
    retry[5] = 1500
    sum_ns[5] = 100 * 5000  # 5 µs mean
    blocks = make_12_blocks(T_D1, retry=retry, count=count, sum_ns=sum_ns)
    diag = classify_mod.classify(blocks)
    # Elevated = top 3 = blocks 2, 3, 4 (T_D1 0.99, 0.98, 0.97)
    assert sorted(diag["elevated_blocks"]) == [2, 3, 4]
    # Block 5 has retry >= 1000 → OUT clause false → NOT OUT.
    # Block 5 is not elevated → NOT IN either.
    assert diag["verdict"] == "INCONCLUSIVE"
    # Load-bearing: regardless of which non-IN bucket the verdict
    # lands in, the IN gate must reject the rank-5 block.
    assert diag["verdict"] != "IN"


# ---------------------------------------------------------------- 6 ----
def test_t1_out_verdict_all_blocks():
    blocks = make_12_blocks(
        [0.99] * 12,
        retry=[50] * 12,
        count=[100] * 12,
        sum_ns=[100 * 1000] * 12,  # 1 µs mean
    )
    diag = classify_mod.classify(blocks)
    assert diag["verdict"] == "OUT"
    assert diag["T1_out_holds"] is True


# ---------------------------------------------------------------- 7 ----
def test_t1_inconclusive_verdict():
    """One block with retry=500 and mean=3000 ns → neither IN nor OUT."""
    retry = [50] * 12
    count = [100] * 12
    sum_ns = [100 * 1000] * 12
    retry[3] = 500
    sum_ns[3] = 100 * 3000
    blocks = make_12_blocks([0.99] * 12, retry=retry, count=count, sum_ns=sum_ns)
    diag = classify_mod.classify(blocks)
    assert diag["verdict"] == "INCONCLUSIVE"


# ---------------------------------------------------------------- 8 ----
def test_rho_reported_not_gating():
    """Very high rho but thresholds in OUT band → verdict OUT."""
    # Monotonic retry (strong correlation with T_D1) but all below 100.
    T_D1 = [0.90 + 0.005 * i for i in range(12)]
    retry = [10 + i for i in range(12)]  # 10..21, all < 100
    count = [100] * 12
    sum_ns = [100 * 1000] * 12  # 1 µs mean
    blocks = make_12_blocks(T_D1, retry=retry, count=count, sum_ns=sum_ns)
    diag = classify_mod.classify(blocks)
    assert diag["verdict"] == "OUT"
    assert diag["rho_retry"] is not None and diag["rho_retry"] > 0.9


# ---------------------------------------------------------------- 9 ----
def test_hist_blocks_wrong_length_rejected(tmp_path):
    blocks = make_12_blocks([0.99] * 12)[:11]  # 11 blocks
    path = tmp_path / "hist-blocks.jsonl"
    path.write_text("\n".join(json.dumps(b) for b in blocks) + "\n")
    with raises(ValueError, match="expected 12 blocks"):
        classify_mod.validate_hist_blocks(
            classify_mod.load_jsonl(path), path
        )


# ---------------------------------------------------------------- 10 ----
def test_shape_wrong_length_rejected(tmp_path):
    blocks = make_12_blocks([0.99] * 12)
    blocks[3]["shape"] = [0.0] * 15  # wrong length
    path = tmp_path / "hist-blocks.jsonl"
    path.write_text("\n".join(json.dumps(b) for b in blocks) + "\n")
    with raises(ValueError, match="shape length"):
        classify_mod.validate_hist_blocks(
            classify_mod.load_jsonl(path), path
        )


# ---------------------------------------------------------------- 11 ----
def test_tx_kick_delta_fields_missing_rejected(tmp_path):
    """Source-of-truth guard: step3 fails closed if step1 didn't run."""
    blocks = make_12_blocks([0.99] * 12)
    for blk in blocks:
        del blk["tx_kick_retry_delta"]
    path = tmp_path / "hist-blocks.jsonl"
    path.write_text("\n".join(json.dumps(b) for b in blocks) + "\n")
    with raises(ValueError, match="tx_kick_retry_delta"):
        classify_mod.validate_hist_blocks(
            classify_mod.load_jsonl(path), path
        )




# ------------------------------------------------------------- 7424 ----
def test_all_zero_capture_is_insufficient_not_out_7424():
    """An empty/truncated capture must not produce a definitive OUT.

    Every all-zero block satisfies `t1_out_block` — retry_delta 0 is below
    RETRY_OUT, then `count_delta == 0` returns True — so `t1_out_holds` is
    VACUOUSLY true and the report prints "the TX-kick hypothesis is ruled
    out": a definitive negative about the dataplane, from a file in which
    nothing was measured. Mirrors step2's C175-HC-070 guard.
    """
    blocks = [
        {
            "b": i,
            "shape": [0.0] * 16,
            "tx_kick_retry_delta": 0,
            "tx_kick_count_delta": 0,
            "tx_kick_sum_ns_delta": 0,
            "tx_kick_hist_delta": [0] * 16,
        }
        for i in range(12)
    ]
    diag = classify_mod.classify(blocks)
    assert diag["verdict"] == "INSUFFICIENT", (
        "an all-zero capture produced a definitive %s — nothing was measured, "
        "so there is nothing to rule out" % diag["verdict"]
    )
    assert "empty or truncated" in (diag["insufficient_reason"] or "")


def test_valid_capture_with_zero_kicks_is_still_out_7424():
    """The over-reach control, and the reason the guard needs TWO conditions.

    Zero KICKS alone is a legitimate OUT: a valid capture in which the
    dataplane simply never kicked is real evidence, and refusing it would
    discard a true negative. Only the absence of a HISTOGRAM as well means
    nothing was measured — a normalised block sums to 1.0, so a zero sum is
    the tell. Without this cell, a guard keyed on `count_delta == 0` alone
    would pass the sibling test above while breaking every real OUT.
    """
    blocks = make_12_blocks(
        [0.99] * 12,
        retry=[0] * 12,
        count=[0] * 12,
        sum_ns=[0] * 12,
    )
    diag = classify_mod.classify(blocks)
    assert diag["verdict"] == "OUT", (
        "a VALID capture whose dataplane never kicked was reported as %s; "
        "that is a real measurement and a real negative result"
        % diag["verdict"]
    )
    assert diag["insufficient_reason"] is None


def test_zero_histogram_with_kick_evidence_is_not_insufficient_7424():
    """The other half of the two-condition guard.

    A block carrying kick counts is evidence even if its histogram is empty,
    so the no-evidence shape requires BOTH to be absent. This cell fails if
    the guard is keyed on the histogram alone.
    """
    blocks = [
        {
            "b": i,
            "shape": [0.0] * 16,
            "tx_kick_retry_delta": 0,
            "tx_kick_count_delta": 5,
            "tx_kick_sum_ns_delta": 100,
            "tx_kick_hist_delta": [0] * 16,
        }
        for i in range(12)
    ]
    diag = classify_mod.classify(blocks)
    assert diag["verdict"] != "INSUFFICIENT", (
        "blocks carrying kick counts were treated as no-evidence; a capture "
        "with kicks measured something"
    )


# #8136: unittest collects classes, not bare functions.
load_tests = collect_module_tests(globals())


# #8278: the __main__ block must be LAST. unittest.main() collects at
# call time and never returns, so anything below it -- a `load_tests`
# collector, or a test function appended later -- does not exist yet
# when collection happens. step3 had three `_7424` cases defined after
# this block and ran 11 of its 14 tests under `python3 <file>` while
# `unittest discover` ran all 14; step1 ran none of its 17. Both
# reported success.
if __name__ == "__main__":
    import sys
    import unittest

    unittest.main(verbosity=2)
