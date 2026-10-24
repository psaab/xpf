#!/usr/bin/env python3
"""#827 tests for step1 kick-field parsing + K0-K3 invariants.

Exercises the extensions in `step1-histogram-classify.py` that #827
added (the sole source of truth for per-block kick deltas — see
#827 plan R2 MED-2). Existing submit-latency I13 pathway is also
regression-tested for safety.
"""
from __future__ import annotations

from pathlib import Path

# #8136: pytest is not installed here and these run under `unittest
# discover`. unittest_shim supplies the three pytest features this file
# uses (raises/approx) plus the load_tests collector for its module-level
# test functions, which unittest would otherwise not find at all.
from unittest_shim import approx, collect_module_tests, raises
import numpy as np

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from load_subject import load_subject  # noqa: E402


SCRIPT_DIR = Path(__file__).resolve().parent



step1 = load_subject("step1_histogram", SCRIPT_DIR / "step1-histogram-classify.py")


def make_binding(
    submit_count: int = 0,
    submit_sum_ns: int = 0,
    tx_packets: int = 0,
    kick_count: int = 0,
    kick_sum_ns: int = 0,
    kick_retry: int = 0,
    kick_hist: list[int] | None = None,
    submit_hist: list[int] | None = None,
    # Escape hatches for K0 (ii): allow omitting kick keys.
    include_kick_keys: bool = True,
    omit_kick_key: str | None = None,
) -> dict:
    if submit_hist is None:
        submit_hist = [0] * 16
        submit_hist[0] = submit_count
    if kick_hist is None:
        kick_hist = [0] * 16
        kick_hist[0] = kick_count
    b = {
        "tx_submit_latency_hist": submit_hist,
        "tx_submit_latency_count": submit_count,
        "tx_submit_latency_sum_ns": submit_sum_ns,
        "tx_packets": tx_packets,
    }
    if include_kick_keys:
        b["tx_kick_latency_hist"] = kick_hist
        b["tx_kick_latency_count"] = kick_count
        b["tx_kick_latency_sum_ns"] = kick_sum_ns
        b["tx_kick_retry_count"] = kick_retry
        if omit_kick_key is not None:
            del b[omit_kick_key]
    return b


def make_snap(bindings: list[dict]) -> dict:
    return {"status": {"per_binding": bindings}}


def make_13_snaps(cumulative_per_snap: list[dict]) -> list[dict]:
    """Build 13 snapshots from a list of cumulative-counter dicts.

    Each dict is `{submit_count, submit_sum_ns, tx_packets, kick_count,
    kick_sum_ns, kick_retry}` at that snapshot.
    """
    snaps = []
    for c in cumulative_per_snap:
        snaps.append(
            make_snap(
                [
                    make_binding(
                        submit_count=c.get("submit_count", 0),
                        submit_sum_ns=c.get("submit_sum_ns", 0),
                        tx_packets=c.get("tx_packets", 0),
                        kick_count=c.get("kick_count", 0),
                        kick_sum_ns=c.get("kick_sum_ns", 0),
                        kick_retry=c.get("kick_retry", 0),
                    )
                ]
            )
        )
    assert len(snaps) == 13
    return snaps


# ---------------------------------------------------------------- 12 ----
def test_kick_aggregation_sums_across_bindings():
    """Sum over 2 bindings per snapshot."""
    snap = make_snap(
        [
            make_binding(kick_count=100, kick_sum_ns=500_000, kick_retry=5),
            make_binding(kick_count=200, kick_sum_ns=1_000_000, kick_retry=15),
        ]
    )
    hist, count, sum_ns, retry = step1.sum_per_binding_kick(snap, 0)
    assert count == 300
    assert sum_ns == 1_500_000
    assert retry == 20
    assert hist[0] == 300


# ---------------------------------------------------------------- 13 ----
def test_k0_i_empty_per_binding_rejected():
    snap = make_snap([])
    with raises(ValueError, match="empty per_binding"):
        step1.sum_per_binding_kick(snap, 4)


# ---------------------------------------------------------------- 14 ----
def test_k0_ii_missing_key_rejected():
    """Binding missing tx_kick_retry_count → hard-stop with clear message."""
    snap = make_snap(
        [make_binding(kick_count=10, omit_kick_key="tx_kick_retry_count")]
    )
    with raises(ValueError, match="tx_kick_retry_count.*pre-#826"):
        step1.sum_per_binding_kick(snap, 0)


# ---------------------------------------------------------------- 15 ----
def test_k1_invariant_caught():
    """sum(kick_hist) != kick_count → K1 violation."""
    bad_hist = [0] * 16
    bad_hist[0] = 99  # but kick_count = 100
    snap = make_snap(
        [make_binding(kick_count=100, kick_hist=bad_hist)]
    )
    with raises(ValueError, match="K1 violation"):
        step1.sum_per_binding_kick(snap, 0)


# ---------------------------------------------------------------- 16 ----
def test_k2_invariant_caught():
    """K2 fires inside compute_blocks when kick_count=0 despite tx_packets."""
    cumulative = []
    for i in range(13):
        cumulative.append(
            {
                "submit_count": 100 * i,
                "submit_sum_ns": 1000 * i,
                "tx_packets": 50_000 * i,  # sustained packet flow
                "kick_count": 0,  # but zero kicks — wire regression
                "kick_sum_ns": 0,
                "kick_retry": 0,
            }
        )
    # Snap 0 is the cold — 0 packets, 0 kicks — fine. Make snap 3 bad.
    cumulative[0]["tx_packets"] = 0
    snaps = make_13_snaps(cumulative)
    with raises(ValueError, match="K2 violation"):
        step1.compute_blocks(snaps)


# ---------------------------------------------------------------- 17 ----
def test_k3_retry_backwards_caught():
    """Retry count goes backwards across two snaps → K3 violation."""
    cumulative = [
        {"submit_count": 0, "kick_count": 0, "kick_retry": 0} for _ in range(13)
    ]
    # Make snap 5 have kick_retry=10, snap 6 have kick_retry=5 (backwards).
    for i, c in enumerate(cumulative):
        c["submit_count"] = 100 * i
        c["kick_count"] = 10 * i
        c["kick_retry"] = i  # normally monotonic
    cumulative[6]["kick_retry"] = 0  # reset
    snaps = make_13_snaps(cumulative)
    with raises(ValueError, match="non-monotonic tx_kick_retry_count"):
        step1.compute_blocks(snaps)


# ---------------------------------------------------------------- 18 ----
def test_k3_sum_ns_backwards_caught():
    cumulative = [
        {
            "submit_count": 100 * i,
            "kick_count": 10 * i,
            "kick_sum_ns": 1000 * i,
            "kick_retry": i,
        }
        for i in range(13)
    ]
    cumulative[6]["kick_sum_ns"] = 100  # reset below prior
    snaps = make_13_snaps(cumulative)
    with raises(ValueError, match="non-monotonic tx_kick_latency_sum_ns"):
        step1.compute_blocks(snaps)


# ---------------------------------------------------------------- 19 ----
def test_k3_hist_bucket_backwards_caught():
    """A single kick bucket decreases across snaps → K3 flags it."""
    # Build 13 snaps cleanly first, then corrupt one bucket.
    snaps = []
    for i in range(13):
        kick_hist = [0] * 16
        kick_hist[0] = 10 * i
        kick_hist[3] = i  # steadily increasing bucket 3
        snap = make_snap(
            [
                make_binding(
                    submit_count=100 * i,
                    kick_count=10 * i + i,
                    kick_hist=kick_hist,
                )
            ]
        )
        snaps.append(snap)
    # Corrupt snap 7 bucket 3 to go backwards.
    bad_hist = [0] * 16
    bad_hist[0] = snaps[7]["status"]["per_binding"][0]["tx_kick_latency_count"]
    bad_hist[3] = 0  # backwards from snap 6's value of 6
    # Adjust count so K1 still passes on snap 7 in isolation:
    snaps[7]["status"]["per_binding"][0]["tx_kick_latency_hist"] = bad_hist
    snaps[7]["status"]["per_binding"][0]["tx_kick_latency_count"] = (
        bad_hist[0] + bad_hist[3]
    )
    # Make sure retry stays monotonic so K3 only fires on the hist.
    for i, s in enumerate(snaps):
        s["status"]["per_binding"][0]["tx_kick_retry_count"] = i
        s["status"]["per_binding"][0]["tx_kick_latency_sum_ns"] = 1000 * i
    with raises(ValueError, match="non-monotonic tx_kick_latency_hist"):
        step1.compute_blocks(snaps)


# ---------------------------------------------------------------- 20 ----
def test_twelve_snapshot_input_rejected(tmp_path):
    """load_snapshots enforces 13-snapshot contract."""
    cold = tmp_path / "flow_steer_cold.json"
    samples = tmp_path / "flow_steer_samples.jsonl"
    import json
    snap = {"status": {"per_binding": []}}
    cold.write_text(json.dumps(snap))
    # 11 samples → total 12 — should reject.
    samples.write_text("\n".join([json.dumps(snap)] * 11) + "\n")
    with raises(ValueError, match="expected 13 snapshots"):
        step1.load_snapshots(tmp_path)


# ---------------------------------------------------------------- 21 ----
def test_existing_submit_pathway_unchanged():
    """Submit-latency I13 still works with the new kick fields present."""
    snap = make_snap(
        [
            make_binding(
                submit_count=50,
                submit_sum_ns=5000,
                tx_packets=1000,
                kick_count=10,
                kick_sum_ns=1000,
                kick_retry=2,
            )
        ]
    )
    hist, count, sum_ns, tx_packets = step1.sum_per_binding_hist(snap)
    assert count == 50
    assert sum_ns == 5000
    assert tx_packets == 1000
    assert hist[0] == 50


# ---------------------------------------------------------------- 22 ----
def test_kick_delta_fields_emitted_correctly():
    """R3 MED-2 positive-path pin: step1 emits exact per-block kick deltas."""
    # 13 snapshots with linearly-growing cumulatives:
    # snap[i]: kick_count = 1000*i, kick_sum_ns = 5_000_000*i,
    #          kick_retry = 7*i, kick_hist[3] = 400*i, kick_hist[4] = 600*i.
    snaps = []
    for i in range(13):
        kick_hist = [0] * 16
        kick_hist[3] = 400 * i
        kick_hist[4] = 600 * i
        total_kick = 400 * i + 600 * i  # = 1000*i (matches kick_count)
        snap = make_snap(
            [
                make_binding(
                    submit_count=500 * i,
                    submit_sum_ns=2000 * i,
                    tx_packets=1000 * i,
                    kick_count=total_kick,
                    kick_sum_ns=5_000_000 * i,
                    kick_retry=7 * i,
                    kick_hist=kick_hist,
                )
            ]
        )
        snaps.append(snap)
    blocks = step1.compute_blocks(snaps)
    assert len(blocks) == 12
    # Each block's delta between adjacent cumulatives:
    # count_delta = 1000, sum_ns_delta = 5_000_000, retry_delta = 7,
    # hist_delta[3] = 400, hist_delta[4] = 600.
    for b, blk in enumerate(blocks):
        assert blk["b"] == b
        assert blk["tx_kick_count_delta"] == 1000
        assert blk["tx_kick_sum_ns_delta"] == 5_000_000
        assert blk["tx_kick_retry_delta"] == 7
        assert blk["tx_kick_hist_delta"][3] == 400
        assert blk["tx_kick_hist_delta"][4] == 600
        # Bucket 0 stays 0 in this fixture.
        assert blk["tx_kick_hist_delta"][0] == 0
        # Length check.
        assert len(blk["tx_kick_hist_delta"]) == 16


# ------------------------------------------------- 23 (#5077 I14) ------
def test_i14_submit_count_backwards_caught():
    """Submit cumulative count goes backwards across snaps → I14 (mirrors K3)."""
    cumulative = [
        {
            "submit_count": 100 * i,
            "submit_sum_ns": 1000 * i,
            "tx_packets": 2000 * i,
            "kick_count": 50 * i,
            "kick_sum_ns": 10 * i,
            "kick_retry": i,
        }
        for i in range(13)
    ]
    cumulative[6]["submit_count"] = 100  # reset below snap 5's 500
    snaps = make_13_snaps(cumulative)
    with raises(ValueError, match="non-monotonic tx_submit_latency_count"):
        step1.compute_blocks(snaps)


# ------------------------------------------------- 24 (#5077 I14) ------
def test_i14_submit_sum_ns_backwards_caught():
    cumulative = [
        {
            "submit_count": 100 * i,
            "submit_sum_ns": 1000 * i,
            "tx_packets": 2000 * i,
            "kick_count": 50 * i,
            "kick_sum_ns": 10 * i,
            "kick_retry": i,
        }
        for i in range(13)
    ]
    cumulative[6]["submit_sum_ns"] = 100  # reset below prior
    snaps = make_13_snaps(cumulative)
    with raises(ValueError, match="non-monotonic tx_submit_latency_sum_ns"):
        step1.compute_blocks(snaps)


# ------------------------------------------------- 25 (#5077 I14) ------
def test_i14_tx_packets_backwards_caught():
    cumulative = [
        {
            "submit_count": 100 * i,
            "submit_sum_ns": 1000 * i,
            "tx_packets": 2000 * i,
            "kick_count": 50 * i,
            "kick_sum_ns": 10 * i,
            "kick_retry": i,
        }
        for i in range(13)
    ]
    cumulative[6]["tx_packets"] = 100  # reset below prior
    snaps = make_13_snaps(cumulative)
    with raises(ValueError, match="non-monotonic tx_packets"):
        step1.compute_blocks(snaps)


# ------------------------------------------------- 26 (#5077 I14) ------
def test_i14_submit_hist_reset_and_recover_caught():
    """The #5077 core: a counter RESET drives a submit bucket negative.

    A low-frequency bucket drops 600->0 while the total submit count still
    RISES (6600->7700->8800), exactly the "count 10000->12000 while a bucket
    goes 1000->0" scenario in the issue. The pre-#5077 delta loop only
    checked `count_delta > 0`, so it normalized a NEGATIVE bucket delta into
    a non-probability shape (negative bucket fractions) and classified the
    cell as non-suspect — a false PASS. I14 must H-STOP instead.
    """
    snaps = []
    for i in range(13):
        hist = [0] * 16
        hist[0] = 1000 * i  # high-frequency bucket, cumulative
        hist[5] = 100 * i  # low-frequency bucket, cumulative
        count = hist[0] + hist[5]
        snaps.append(
            make_snap(
                [
                    make_binding(
                        submit_count=count,
                        submit_sum_ns=5000 * i,
                        tx_packets=2000 * i,
                        submit_hist=hist,
                        kick_count=500 * i,  # nonzero → no K2 false-trip
                    )
                ]
            )
        )
    # Simulate a daemon restart at snap 7: the low-frequency bucket 5 resets
    # to 0 while total count still rises (bucket 0 absorbs it, keeping count
    # monotonic and I13 intact so I14's histogram check is what fires).
    reset = snaps[7]["status"]["per_binding"][0]
    new_hist = [0] * 16
    new_hist[0] = reset["tx_submit_latency_count"]  # 7700
    new_hist[5] = 0  # backwards from snap 6's cumulative 600
    reset["tx_submit_latency_hist"] = new_hist
    reset["tx_submit_latency_count"] = sum(new_hist)  # keep I13 (== bucket 0)
    with raises(
        ValueError, match=r"non-monotonic tx_submit_latency_hist\[5\]"
    ):
        step1.compute_blocks(snaps)


# ------------------------------------------------- 27 (#5077 I14) ------
def test_i14_monotonic_submit_still_classifies():
    """Positive path: a clean monotonic submit stream is NOT flagged by I14."""
    snaps = []
    for i in range(13):
        hist = [0] * 16
        hist[0] = 1000 * i
        hist[5] = 100 * i
        count = hist[0] + hist[5]
        snaps.append(
            make_snap(
                [
                    make_binding(
                        submit_count=count,
                        submit_sum_ns=5000 * i,
                        tx_packets=2000 * i,
                        submit_hist=hist,
                        kick_count=500 * i,
                    )
                ]
            )
        )
    blocks = step1.compute_blocks(snaps)
    assert len(blocks) == 12
    # No negative bucket delta escaped into any classified block.
    for blk in blocks:
        assert all(x >= 0 for x in blk["buckets"]), blk["buckets"]
        assert all(x >= 0.0 for x in blk["shape"]), blk["shape"]


# ------------------------------------------------- 28 (C175-HC-132) ---
def test_only_cell_missing_target_returns_nonzero(tmp_path, monkeypatch):
    """--only-cell on a missing/failed cell must NOT exit 0.

    Fail-on-revert: the pre-fix main() only WARN'd on a missing target
    cell dir and still returned 0 in --only-cell mode, so step2's
    single-cell reduction ran against a cell that produced no
    hist-blocks.jsonl and the failure read as success.
    """
    import sys as _sys

    root = tmp_path / "evidence"
    root.mkdir()
    cell = "with-cos/p5201-fwd"  # a valid POOL_BY_CELL key; dir absent
    assert cell in step1.POOL_BY_CELL
    monkeypatch.setattr(
        _sys,
        "argv",
        [
            "step1-histogram-classify.py",
            "--evidence-root",
            str(root),
            "--only-cell",
            cell,
        ],
    )
    rc = step1.main()
    assert rc != 0




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
