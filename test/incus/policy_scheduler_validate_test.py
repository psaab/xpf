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
FALLTHROUGH_ID = "trust->untrust/allow-all"


def _status(
    packets: int,
    bytes_: int | None = None,
    fallthrough_packets: int | None = None,
) -> dict:
    if bytes_ is None:
        bytes_ = packets * 64
    counters = [{"rule_id": RULE_ID, "packets": packets, "bytes": bytes_}]
    if fallthrough_packets is not None:
        counters.append(
            {
                "rule_id": FALLTHROUGH_ID,
                "packets": fallthrough_packets,
                "bytes": fallthrough_packets * 64,
            }
        )
    return {
        "ok": True,
        "status": {
            "config_snapshot_protocol_version": 2,
            "enabled": True,
            "forwarding_armed": True,
            "dataplane_mode": "userspace_strict",
            "capabilities": {"forwarding_supported": True},
            "entry_programs": {"4": "xdp_userspace_prog"},
            "policy_rule_counters": counters,
        },
    }


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value) + "\n", encoding="utf-8")


def _ping_stats(transmitted: int, received: int, loss: str = "0%") -> str:
    return (
        "PING 172.16.80.200 (172.16.80.200) 56(84) bytes of data.\n"
        "--- 172.16.80.200 ping statistics ---\n"
        f"{transmitted} packets transmitted, {received} received, "
        f"{loss} packet loss, time 2035ms\n"
    )


def _write_artifacts(
    root: Path,
    *,
    active_packets: int = 3,
    rebuild_packets: int = 3,
    inactive_packets: int = 3,
    failover_packets: int = 4,
    rebuild_fallthrough_packets: int = 3,
    inactive_fallthrough_packets: int = 4,
    inactive_traffic: str | None = None,
    missing_text: str = 'policy "scheduled-allow" references undefined scheduler "missing"',
) -> None:
    _write_json(root / "active-status.json", _status(active_packets))
    _write_json(
        root / "rebuild-status.json",
        _status(rebuild_packets, fallthrough_packets=rebuild_fallthrough_packets),
    )
    _write_json(
        root / "inactive-status.json",
        _status(inactive_packets, fallthrough_packets=inactive_fallthrough_packets),
    )
    _write_json(root / "failover-status.json", _status(failover_packets))
    (root / "inactive-traffic.stdout").write_text(
        _ping_stats(3, 3) if inactive_traffic is None else inactive_traffic,
        encoding="utf-8",
    )
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
            self.assertEqual(summary["inactive_traffic"]["transmitted"], 3)
            self.assertEqual(summary["inactive_traffic"]["outcome"], "allowed")

    def test_fails_when_inactive_scheduler_allows_counter_increment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root, rebuild_packets=3, inactive_packets=4)

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "counter changed while scheduler was inactive",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_fails_when_allowed_inactive_traffic_has_no_counter_delta(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(
                root,
                rebuild_fallthrough_packets=3,
                inactive_fallthrough_packets=3,
            )

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "fall-through policy counters did not advance",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_fails_when_policy_counter_rule_id_is_duplicated(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root)
            duplicate = _status(3)
            duplicate["status"]["policy_rule_counters"].append(
                {"rule_id": RULE_ID, "packets": 3, "bytes": 192}
            )
            _write_json(root / "inactive-status.json", duplicate)

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "duplicate policy_rule_counters entry",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_fails_when_inactive_traffic_witness_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root)
            (root / "inactive-traffic.stdout").unlink()

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                r"missing artifact: .*inactive-traffic\.stdout",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_fails_when_inactive_window_has_zero_probe_traffic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root, inactive_traffic=_ping_stats(0, 0))

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "offered 0 packets",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_fails_when_inactive_traffic_witness_is_ambiguous(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root, inactive_traffic=_ping_stats(3, 1, loss="66%"))

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "not decisive",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_fails_when_inactive_traffic_witness_lacks_statistics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(
                root,
                inactive_traffic="PING 172.16.80.200: no summary was printed\n",
            )

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "expected exactly one ping statistics block",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_accepts_full_deny_during_inactive_window(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root, inactive_traffic=_ping_stats(3, 0, loss="100%"))

            summary = policy_validate.validate_artifacts(root, rule_id=RULE_ID)

            self.assertEqual(summary["verdict"], "PASS")
            self.assertEqual(summary["inactive_traffic"]["outcome"], "denied")

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

    def test_fails_when_entry_programs_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root)
            active = _status(3)
            del active["status"]["entry_programs"]
            _write_json(root / "active-status.json", active)

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "entry_programs must be a non-empty object",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_fails_when_entry_programs_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root)
            active = _status(3)
            active["status"]["entry_programs"] = {}
            _write_json(root / "active-status.json", active)

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "entry_programs must be a non-empty object",
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
            _write_artifacts(
                root,
                missing_text=(
                    'policy "scheduled-allow" references undefined scheduler "missing"\n'
                    "commit complete"
                ),
            )

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "looks like a successful commit",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_fails_when_packet_counter_is_boolean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root)
            _write_json(root / "active-status.json", _status(True))

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "must be a non-negative integer, got True",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_fails_when_byte_counter_is_string(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root)
            rebuild = _status(3)
            rebuild["status"]["policy_rule_counters"][0]["bytes"] = "192"
            _write_json(root / "rebuild-status.json", rebuild)

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "must be a non-negative integer, got '192'",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)

    def test_fails_when_failover_bytes_regress(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_artifacts(root)
            _write_json(root / "failover-status.json", _status(4, 100))

            with self.assertRaisesRegex(
                policy_validate.ValidationFailure,
                "failover: policy bytes went backward",
            ):
                policy_validate.validate_artifacts(root, rule_id=RULE_ID)


if __name__ == "__main__":
    unittest.main()
