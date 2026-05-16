#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("cos_be_contention_validate.py")
SPEC = importlib.util.spec_from_file_location("cos_be_contention_validate", MODULE_PATH)
assert SPEC is not None
cos_validate = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["cos_be_contention_validate"] = cos_validate
SPEC.loader.exec_module(cos_validate)


def _iperf_json(bps: float) -> dict:
    return {"end": {"sum_received": {"bits_per_second": bps}}}


def _status(*, q0: int = 0, q2: int = 0, q10: int = 0, q11: int = 0) -> dict:
    queues = [
        {
            "queue_id": 0,
            "forwarding_class": "best-effort",
            "drain_sent_bytes": q0,
            "drain_park_root_tokens": 1,
            "drain_park_queue_tokens": 2,
        },
        {
            "queue_id": 2,
            "forwarding_class": "iperf-1g",
            "drain_sent_bytes": q2,
            "drain_park_root_tokens": 3,
            "drain_park_queue_tokens": 4,
        },
        {
            "queue_id": 10,
            "forwarding_class": "iperf-24g",
            "drain_sent_bytes": q10,
            "drain_park_root_tokens": 5,
            "drain_park_queue_tokens": 6,
        },
        {
            "queue_id": 11,
            "forwarding_class": "iperf-uncapped",
            "drain_sent_bytes": q11,
            "drain_park_root_tokens": 7,
            "drain_park_queue_tokens": 8,
        },
    ]
    return {
        "status": {
            "cos_interfaces": [
                {
                    "ifindex": 14,
                    "interface_name": "reth0.80",
                    "queues": queues,
                }
            ]
        }
    }


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def _write_phase(
    phase_dir: Path,
    *,
    before: dict,
    during: dict,
    after: dict,
    exact_bps: float,
    contender_bps: float | None = None,
    exact_rc: int = 0,
    contender_rc: int = 0,
) -> None:
    phase_dir.mkdir(parents=True)
    _write_json(phase_dir / "status-before.json", before)
    _write_json(phase_dir / "status-during.json", during)
    _write_json(phase_dir / "status-after.json", after)
    for phase in ("before", "during", "after"):
        (phase_dir / f"status-{phase}.rc").write_text("0\n", encoding="utf-8")
    _write_json(phase_dir / "exact-iperf.json", _iperf_json(exact_bps))
    (phase_dir / "exact-iperf.rc").write_text(f"{exact_rc}\n", encoding="utf-8")
    if contender_bps is not None:
        _write_json(phase_dir / "contender-iperf.json", _iperf_json(contender_bps))
        (phase_dir / "contender-iperf.rc").write_text(f"{contender_rc}\n", encoding="utf-8")


def _write_manifest(root: Path, cell: dict | None = None) -> None:
    if cell is None:
        cell = {
            "label": "exact5202-vs-5200",
            "exact_port": 5202,
            "exact_queue": 2,
            "exact_forwarding_class": "iperf-1g",
            "contender_port": 5200,
            "contender_queue": 0,
            "contender_forwarding_class": "best-effort",
            "baseline_dir": "cell/baseline",
            "contended_dir": "cell/contended",
        }
    _write_json(
        root / "manifest.json",
        {
            "cos_interface_name": "reth0.80",
            "cells": [cell],
        },
    )


def _validate(root: Path) -> dict:
    return cos_validate.validate_artifacts(
        root,
        max_exact_drop_ratio=0.15,
        wrong_queue_sent_bytes_tolerance=0,
        min_expected_sent_bytes=1,
        min_contender_bps=100_000_000.0,
        min_exact_baseline_cap_ratio=0.70,
        min_contended_root_pressure_ratio=0.90,
    )


class CoSBEContentionValidateTests(unittest.TestCase):
    def test_passes_expected_exact_and_contender_drain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root)
            _write_phase(
                root / "cell" / "baseline",
                before=_status(q2=100),
                during=_status(q2=600),
                after=_status(q2=1100),
                exact_bps=1_000_000_000,
            )
            _write_phase(
                root / "cell" / "contended",
                before=_status(q0=200, q2=1100),
                during=_status(q0=800, q2=1600),
                after=_status(q0=1200, q2=1950),
                exact_bps=920_000_000,
                contender_bps=24_000_000_000,
            )

            summary = _validate(root)

            self.assertEqual(summary["verdict"], "PASS")
            self.assertEqual(summary["failure_reasons"], [])
            throughput = summary["cells"][0]["throughput"]
            self.assertEqual(throughput["exact_cap_mbps"], 1000.0)
            self.assertEqual(throughput["minimum_baseline_exact_mbps"], 700.0)
            self.assertEqual(throughput["minimum_contender_mbps"], 500.0)
            self.assertEqual(throughput["contended_total_mbps"], 24920.0)
            self.assertEqual(throughput["minimum_contended_total_mbps"], 22500.0)
            self.assertEqual(summary["cells"][0]["contended"]["dataplane"]["verdict"], "PASS")

    def test_default_contender_threshold_math_for_canonical_cells(self) -> None:
        root_shape = 25_000_000_000.0

        self.assertEqual(
            cos_validate._default_min_contender_bps(1_000_000_000.0, root_shape),
            500_000_000.0,
        )
        self.assertEqual(
            cos_validate._default_min_contender_bps(24_000_000_000.0, root_shape),
            1_000_000_000.0,
        )

    def test_fails_nonzero_iperf_exit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root)
            _write_phase(
                root / "cell" / "baseline",
                before=_status(q2=0),
                during=_status(q2=10),
                after=_status(q2=20),
                exact_bps=1_000_000_000,
                exact_rc=1,
            )
            _write_phase(
                root / "cell" / "contended",
                before=_status(q0=0, q2=20),
                during=_status(q0=10, q2=30),
                after=_status(q0=20, q2=40),
                exact_bps=1_000_000_000,
                contender_bps=1_000_000_000,
            )

            summary = _validate(root)

            self.assertEqual(summary["verdict"], "FAIL")
            self.assertTrue(any("iperf exited 1" in reason for reason in summary["failure_reasons"]))

    def test_fails_when_expected_queue_does_not_drain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root)
            _write_phase(
                root / "cell" / "baseline",
                before=_status(q2=100),
                during=_status(q2=100),
                after=_status(q2=100),
                exact_bps=1_000_000_000,
            )
            _write_phase(
                root / "cell" / "contended",
                before=_status(q0=0, q2=100),
                during=_status(q0=10, q2=110),
                after=_status(q0=20, q2=120),
                exact_bps=1_000_000_000,
                contender_bps=1_000_000_000,
            )

            summary = _validate(root)

            self.assertEqual(summary["verdict"], "FAIL")
            self.assertTrue(any("expected queue 2" in reason for reason in summary["failure_reasons"]))

    def test_fails_when_unexpected_queue_drains(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root)
            _write_phase(
                root / "cell" / "baseline",
                before=_status(q2=100, q10=10),
                during=_status(q2=500, q10=20),
                after=_status(q2=900, q10=30),
                exact_bps=1_000_000_000,
            )
            _write_phase(
                root / "cell" / "contended",
                before=_status(q0=0, q2=900),
                during=_status(q0=10, q2=910),
                after=_status(q0=20, q2=920),
                exact_bps=1_000_000_000,
                contender_bps=1_000_000_000,
            )

            summary = _validate(root)

            self.assertEqual(summary["verdict"], "FAIL")
            self.assertTrue(any("unexpected queue drain" in reason for reason in summary["failure_reasons"]))

    def test_fails_material_exact_throughput_drop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root)
            _write_phase(
                root / "cell" / "baseline",
                before=_status(q2=0),
                during=_status(q2=100),
                after=_status(q2=200),
                exact_bps=1_000_000_000,
            )
            _write_phase(
                root / "cell" / "contended",
                before=_status(q0=0, q2=200),
                during=_status(q0=100, q2=250),
                after=_status(q0=200, q2=300),
                exact_bps=800_000_000,
                contender_bps=1_000_000_000,
            )

            summary = _validate(root)

            self.assertEqual(summary["verdict"], "FAIL")
            self.assertTrue(any("exact throughput dropped" in reason for reason in summary["failure_reasons"]))

    def test_fails_when_contender_has_no_material_pressure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root)
            _write_phase(
                root / "cell" / "baseline",
                before=_status(q2=0),
                during=_status(q2=100),
                after=_status(q2=200),
                exact_bps=1_000_000_000,
            )
            _write_phase(
                root / "cell" / "contended",
                before=_status(q0=0, q2=200),
                during=_status(q0=1, q2=300),
                after=_status(q0=1, q2=400),
                exact_bps=1_000_000_000,
                contender_bps=1.0,
            )

            summary = _validate(root)

            self.assertEqual(summary["verdict"], "FAIL")
            self.assertTrue(any("contention pressure is too low" in reason for reason in summary["failure_reasons"]))

    def test_fails_negative_drain_shape_delta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root)
            _write_phase(
                root / "cell" / "baseline",
                before=_status(q2=200),
                during=_status(q2=150),
                after=_status(q2=100),
                exact_bps=1_000_000_000,
            )
            _write_phase(
                root / "cell" / "contended",
                before=_status(q0=0, q2=100),
                during=_status(q0=100, q2=200),
                after=_status(q0=200, q2=300),
                exact_bps=1_000_000_000,
                contender_bps=1_000_000_000,
            )

            summary = _validate(root)

            self.assertEqual(summary["verdict"], "FAIL")
            self.assertTrue(any("negative DrainShape delta" in reason for reason in summary["failure_reasons"]))

    def test_rejects_forwarding_class_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(
                root,
                {
                    "label": "exact5202-vs-5200",
                    "exact_port": 5202,
                    "exact_queue": 2,
                    "exact_forwarding_class": "not-iperf-1g",
                    "contender_port": 5200,
                    "contender_queue": 0,
                    "contender_forwarding_class": "best-effort",
                    "baseline_dir": "cell/baseline",
                    "contended_dir": "cell/contended",
                },
            )
            _write_phase(
                root / "cell" / "baseline",
                before=_status(q2=0),
                during=_status(q2=100),
                after=_status(q2=200),
                exact_bps=1_000_000_000,
            )
            _write_phase(
                root / "cell" / "contended",
                before=_status(q0=0, q2=200),
                during=_status(q0=100, q2=300),
                after=_status(q0=200, q2=400),
                exact_bps=1_000_000_000,
                contender_bps=1_000_000_000,
            )

            with self.assertRaisesRegex(cos_validate.ValidationError, "does not match canonical class"):
                _validate(root)

    def test_fails_when_baseline_does_not_prove_exact_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(root)
            _write_phase(
                root / "cell" / "baseline",
                before=_status(q2=0),
                during=_status(q2=100),
                after=_status(q2=200),
                exact_bps=500_000_000,
            )
            _write_phase(
                root / "cell" / "contended",
                before=_status(q0=0, q2=200),
                during=_status(q0=100, q2=300),
                after=_status(q0=200, q2=400),
                exact_bps=500_000_000,
                contender_bps=1_000_000_000,
            )

            summary = _validate(root)

            self.assertEqual(summary["verdict"], "FAIL")
            self.assertTrue(any("exact-alone baseline" in reason for reason in summary["failure_reasons"]))

    def test_fails_when_contended_total_does_not_prove_root_pressure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(
                root,
                {
                    "label": "exact5210-vs-5200",
                    "exact_port": 5210,
                    "exact_queue": 10,
                    "exact_forwarding_class": "iperf-24g",
                    "contender_port": 5200,
                    "contender_queue": 0,
                    "contender_forwarding_class": "best-effort",
                    "baseline_dir": "cell/baseline",
                    "contended_dir": "cell/contended",
                },
            )
            _write_phase(
                root / "cell" / "baseline",
                before=_status(q10=0),
                during=_status(q10=100),
                after=_status(q10=200),
                exact_bps=16_800_000_000,
            )
            _write_phase(
                root / "cell" / "contended",
                before=_status(q0=0, q10=200),
                during=_status(q0=100, q10=300),
                after=_status(q0=200, q10=400),
                exact_bps=14_280_000_000,
                contender_bps=1_000_000_000,
            )

            summary = _validate(root)

            self.assertEqual(summary["verdict"], "FAIL")
            self.assertTrue(any("root pressure is too low" in reason for reason in summary["failure_reasons"]))

    def test_fails_cell_specific_contender_pressure_for_24g_exact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_manifest(
                root,
                {
                    "label": "exact5210-vs-5200",
                    "exact_port": 5210,
                    "exact_queue": 10,
                    "exact_forwarding_class": "iperf-24g",
                    "exact_cap_bps": 24_000_000_000,
                    "contender_port": 5200,
                    "contender_queue": 0,
                    "contender_forwarding_class": "best-effort",
                    "min_contender_bps": 1_000_000_000,
                    "baseline_dir": "cell/baseline",
                    "contended_dir": "cell/contended",
                },
            )
            _write_phase(
                root / "cell" / "baseline",
                before=_status(q10=0),
                during=_status(q10=100),
                after=_status(q10=200),
                exact_bps=22_000_000_000,
            )
            _write_phase(
                root / "cell" / "contended",
                before=_status(q0=0, q10=200),
                during=_status(q0=100, q10=300),
                after=_status(q0=200, q10=400),
                exact_bps=21_000_000_000,
                contender_bps=500_000_000,
            )

            summary = _validate(root)

            self.assertEqual(summary["verdict"], "FAIL")
            self.assertTrue(any("below 1000.000 Mbps" in reason for reason in summary["failure_reasons"]))

    def test_iperf_parser_prefers_sum_received(self) -> None:
        artifact = {
            "end": {
                "sum_sent": {"bits_per_second": 999},
                "sum_received": {"bits_per_second": 123},
            }
        }
        self.assertEqual(cos_validate.iperf_bps(artifact), 123)


if __name__ == "__main__":
    unittest.main()
