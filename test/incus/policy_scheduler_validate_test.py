#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest


MODULE_PATH = Path(__file__).with_name("policy_scheduler_validate.py")
SPEC = importlib.util.spec_from_file_location("policy_scheduler_validate", MODULE_PATH)
assert SPEC is not None
policy_validate = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["policy_scheduler_validate"] = policy_validate
SPEC.loader.exec_module(policy_validate)


RULE_ID = "trust->untrust/scheduled-allow"


def _status(packets: int, bytes_: int | None = None) -> dict:
    if bytes_ is None:
        bytes_ = packets * 64
    return {
        "ok": True,
        "status": {
            "config_snapshot_protocol_version": 2,
            "enabled": True,
            "forwarding_armed": True,
            "dataplane_mode": "userspace_strict",
            "capabilities": {"forwarding_supported": True},
            "entry_programs": {"4": "xdp_userspace_prog"},
            "policy_rule_counters": [
                {"rule_id": RULE_ID, "packets": packets, "bytes": bytes_}
            ],
        },
    }


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def _write_artifacts(
    root: Path,
    *,
    active_packets: int = 3,
    rebuild_packets: int = 3,
    inactive_packets: int = 3,
    failover_packets: int = 4,
    missing_text: str = 'policy "scheduled-allow" references undefined scheduler "missing"',
) -> None:
    _write_json(root / "active-status.json", _status(active_packets))
    _write_json(root / "rebuild-status.json", _status(rebuild_packets))
    _write_json(root / "inactive-status.json", _status(inactive_packets))
    _write_json(root / "failover-status.json", _status(failover_packets))
    (root / "missing-scheduler-commit.txt").write_text(
        missing_text + "\n", encoding="utf-8"
    )


class PolicySchedulerValidateTests(unittest.TestCase):
    def test_passes_full_userspace_scheduler_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root)

            summary = policy_validate.validate_artifacts(root, rule_id=RULE_ID)

            self.assertEqual(summary["verdict"], "PASS")
            self.assertEqual(summary["active"]["packets"], 3)
            self.assertEqual(summary["inactive"]["packets"], 3)
            self.assertEqual(summary["failover"]["packets"], 4)

    def test_fails_when_inactive_scheduler_allows_counter_increment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root, rebuild_packets=3, inactive_packets=4)

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "counter changed while scheduler was inactive",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_fails_when_runtime_is_legacy_ebpf(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root)
            active = _status(3)
            active["status"]["dataplane_mode"] = "ebpf_only"
            _write_json(root / "active-status.json", active)

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "dataplane_mode is ebpf_only",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_fails_when_rebuild_resets_counter(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root, active_packets=3, rebuild_packets=0, inactive_packets=0)

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "policy counter went backward",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_fails_when_missing_scheduler_commit_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root, missing_text="commit complete")

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "strict rejection",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)


if __name__ == "__main__":
    unittest.main()
