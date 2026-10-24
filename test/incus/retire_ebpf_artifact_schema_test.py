#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts" / "lib"))
from load_subject import load_subject  # noqa: E402


MODULE_PATH = Path(__file__).with_name("retire_ebpf_artifact_schema.py")
schema = load_subject("retire_ebpf_artifact_schema", MODULE_PATH)


COMMIT = "a" * 40
OTHER_COMMIT = "b" * 40


def write_text(root: Path, rel: str, text: str = "artifact\n") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_json(root: Path, rel: str, value: object | None = None) -> None:
    if value is None:
        value = {"ok": True}
    write_text(root, rel, json.dumps(value) + "\n")


def command(gate: str) -> dict[str, object]:
    return {"gate": gate, "command": f"run {gate}", "exit_status": 0}


def make_manifest(commit: str = COMMIT) -> dict[str, object]:
    return {
        "schema_version": 1,
        "issues": [1373, 1477],
        "candidate_commit": commit,
        "cluster": {
            "name": "loss",
            "env_file": "test/incus/loss-userspace-cluster.env",
            "config_files": ["docs/ha-cluster-userspace.conf"],
        },
        "binaries": [
            {
                "host": "xpf-userspace-fw0",
                "path": "/usr/local/sbin/xpfd",
                "sha256": "1" * 64,
            },
            {
                "host": "xpf-userspace-fw0",
                "path": "/usr/local/bin/xpf-userspace-dp",
                "sha256": "2" * 64,
            },
        ],
        "commands": [command(gate) for gate in sorted(schema.REQUIRED_COMMAND_GATES)],
    }


def make_manifest_json() -> str:
    return json.dumps(make_manifest(), separators=(",", ":")) + "\n"


def make_summary(commit: str = COMMIT) -> str:
    lines = ["# #1477 Source-Removal Validation Summary", "", commit, ""]
    for heading in schema.SUMMARY_HEADINGS:
        lines.extend([f"## {heading}", "Recorded in fixture.", ""])
    return "\n".join(lines)


def make_syn_cookie_summary() -> str:
    lines = ["# SYN-Cookie Proof", ""]
    for heading in schema.SYN_COOKIE_HEADINGS:
        lines.extend([f"## {heading}", "Recorded in fixture.", ""])
    return "\n".join(lines)


def build_complete_artifact(root: Path, commit: str = COMMIT) -> None:
    write_json(root, "manifest.json", make_manifest(commit))
    write_text(root, "summary.md", make_summary(commit))

    write_text(root, "metadata/git-rev-parse-head.txt", commit + "\n")
    write_text(root, "metadata/git-status-short.txt", "")
    write_text(root, "metadata/cluster-env.txt")
    write_text(root, "metadata/ha-cluster-userspace.conf")
    write_text(root, "metadata/binary-sha256sums.txt")
    write_text(root, "metadata/cluster-userspace-host-ipv6-route.txt")

    for label in schema.COS_OFF_CASES:
        write_json(root, f"cos-off/{label}.json")
        write_text(root, f"cos-off/{label}.stderr", "")
        write_json(root, f"cos-off/{label}.metrics.json", {"completed": True})

    for probe in schema.SCREEN_PROBES:
        write_text(root, f"screen-flood/{probe}-before.txt")
        write_text(root, f"screen-flood/{probe}-after.txt")
        write_text(root, f"screen-flood/{probe}-configure.stdout")
        write_text(root, f"screen-flood/{probe}-configure.stderr", "")
    write_text(root, "screen-flood/restore.stdout")
    write_text(root, "screen-flood/restore.stderr", "")

    write_text(root, "syn-cookie/summary.md", make_syn_cookie_summary())
    for rel in (
        "syn-cookie/applied-config.txt",
        "syn-cookie/challenge-hping3.stdout",
        "syn-cookie/challenge-hping3.stderr",
        "syn-cookie/challenge-tcpdump.txt",
        "syn-cookie/challenge-counters-before.txt",
        "syn-cookie/challenge-counters-after.txt",
        "syn-cookie/valid-ack-rst-tcpdump.txt",
        "syn-cookie/valid-ack-rst-counters-before.txt",
        "syn-cookie/valid-ack-rst-counters-after.txt",
        "syn-cookie/random-ack-drop-tcpdump.txt",
        "syn-cookie/random-ack-drop-counters-before.txt",
        "syn-cookie/random-ack-drop-counters-after.txt",
        "syn-cookie/retransmitted-syn-admission-tcpdump.txt",
        "syn-cookie/retransmitted-syn-admission-counters-before.txt",
        "syn-cookie/retransmitted-syn-admission-counters-after.txt",
        "syn-cookie/reply-budget-counters.txt",
        "syn-cookie/failover-before-cluster-status.txt",
        "syn-cookie/failover-after-cluster-status.txt",
        "syn-cookie/failover-cookie-ack-tcpdump.txt",
        "syn-cookie/failover-counters-node1.txt",
        "syn-cookie/cleanup.stdout",
        "syn-cookie/cleanup.stderr",
        "syn-cookie/final-cluster-status.txt",
    ):
        write_text(root, rel, "" if rel.endswith(".stderr") else "artifact\n")

    for sweep in schema.COS_SWEEP_DIRS:
        write_text(root, f"{sweep}/summary.tsv")
        write_text(root, f"{sweep}/summary.md")
        write_json(root, f"{sweep}/dataplane/status-before.json")
        write_json(root, f"{sweep}/dataplane/status-after.json")
        write_json(root, f"{sweep}/dataplane/counter-delta.json")
        write_text(root, f"{sweep}/dataplane/journal-since.txt")
        write_text(root, f"{sweep}/dataplane-summary.tsv")
        write_text(root, f"{sweep}/equal-flow-summary.tsv")
        for class_name in schema.COS_CLASSES:
            base = f"{sweep}/{class_name}"
            write_text(root, f"{base}/wrapper.stdout")
            write_text(root, f"{base}/wrapper.stderr", "")
            write_json(root, f"{base}/samples/summary.json")
            write_json(root, f"{base}/equal-flow/summary.json")
            write_json(root, f"{base}/dataplane/status-before.json")
            write_json(root, f"{base}/dataplane/status-after.json")

    write_text(root, "echo-6200-6211/summary.tsv")
    write_text(root, "echo-6200-6211/latency-summary.tsv")
    for port in schema.ECHO_PORTS:
        write_text(root, f"echo-6200-6211/{port}.stdout")
        write_text(root, f"echo-6200-6211/{port}.stderr", "")

    write_text(root, "userspace-phase-cycle.log")
    write_text(root, "userspace-ha-failover.log")
    write_text(root, "ha-test-failover.log")
    write_text(root, "ha-test-ha-crash.log")
    write_text(root, "ha-test-restart-connectivity.log")
    write_text(root, "userspace-ha-failover/iperf3.log")
    write_json(root, "userspace-ha-failover/iperf3.metrics.json")
    write_text(root, "userspace-ha-failover/before-source-status.txt")
    write_text(root, "userspace-ha-failover/before-target-status.txt")
    write_text(root, "userspace-ha-failover/cycle1-failover-fw1-dp-stats.txt")
    write_text(root, "userspace-ha-failover/cycle1-failback-fw0-dp-stats.txt")
    write_text(root, "userspace-ha-failover/cycle1-failover-fw1-dp-interfaces.txt")
    write_text(root, "userspace-ha-failover/cycle1-failback-fw0-dp-interfaces.txt")

    for rel in (
        "fallback-exclusion/fw0-ip-link.txt",
        "fallback-exclusion/fw1-ip-link.txt",
        "fallback-exclusion/fw0-dp-stats.txt",
        "fallback-exclusion/fw1-dp-stats.txt",
        "fallback-exclusion/fw0-userspace-dp.json",
        "fallback-exclusion/fw1-userspace-dp.json",
        "fallback-exclusion/legacy-map-counter-audit.txt",
    ):
        if rel.endswith(".json"):
            write_json(root, rel)
        else:
            write_text(root, rel)


class RetireEbpfArtifactSchemaTests(unittest.TestCase):
    def with_fixture(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name) / f"evidence-1477-source-removal-20260522-{COMMIT[:12]}"
        build_complete_artifact(root)
        return tmp, root

    def assert_manifest_mutation_rejected(self, mutate, pattern: str) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            manifest = make_manifest()
            mutate(manifest)
            write_json(root, "manifest.json", manifest)
            with self.assertRaisesRegex(schema.ValidationFailure, pattern):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_complete_candidate_schema_passes(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            summary = schema.validate_artifact_root(root, candidate_commit=COMMIT)
            self.assertEqual(summary["verdict"], "STRUCTURE_OK")
            self.assertEqual(summary["candidate_commit"], COMMIT)

    def test_rejects_missing_reverse_ipv6_cos_off_artifact(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            (root / "cos-off/v6-reverse.metrics.json").unlink()
            with self.assertRaisesRegex(
                schema.ValidationFailure, "cos-off/v6-reverse.metrics.json"
            ):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_omitted_echo_port(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            (root / "echo-6200-6211/6211.stdout").unlink()
            with self.assertRaisesRegex(schema.ValidationFailure, "6211.stdout"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_missing_echo_latency_summary(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            (root / "echo-6200-6211/latency-summary.tsv").unlink()
            with self.assertRaisesRegex(schema.ValidationFailure, "latency-summary.tsv"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_missing_udp_screen_probe(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            (root / "screen-flood/udp-after.txt").unlink()
            with self.assertRaisesRegex(schema.ValidationFailure, "udp-after.txt"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_missing_ha_failback_leg(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            for path in (root / "userspace-ha-failover").glob(
                "cycle*-failback-*-dp-stats.txt"
            ):
                path.unlink()
            with self.assertRaisesRegex(
                schema.ValidationFailure, "HA failback dataplane stats"
            ):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_stale_commit_mismatch(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            with self.assertRaisesRegex(schema.ValidationFailure, "candidate commit mismatch"):
                schema.validate_artifact_root(root, candidate_commit=OTHER_COMMIT)

    def test_rejects_short_manifest_commit(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            manifest = make_manifest("a" * 12)
            write_json(root, "manifest.json", manifest)
            with self.assertRaisesRegex(
                schema.ValidationFailure, "full 40-character SHA"
            ):
                schema.validate_artifact_root(root)

    def test_rejects_missing_summary_section(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            text = make_summary().replace("## HA Gates\n", "")
            write_text(root, "summary.md", text)
            with self.assertRaisesRegex(schema.ValidationFailure, "## HA Gates"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_non_integer_issue_value_without_crashing(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            manifest = make_manifest()
            manifest["issues"] = [1373, {"bad": 1}, 1477]
            write_json(root, "manifest.json", manifest)
            with self.assertRaisesRegex(
                schema.ValidationFailure, "issues must be integer"
            ):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_boolean_exit_status(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            manifest = make_manifest()
            commands = manifest["commands"]
            assert isinstance(commands, list)
            commands[0]["exit_status"] = True
            write_json(root, "manifest.json", manifest)
            with self.assertRaisesRegex(schema.ValidationFailure, "exit_status"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_boolean_schema_version(self) -> None:
        self.assert_manifest_mutation_rejected(
            lambda manifest: manifest.__setitem__("schema_version", True),
            "schema_version must be 1",
        )

    def test_accepts_json_integer_float_issue_numbers(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            manifest = make_manifest()
            manifest["issues"] = [1373.0, 1477.0]
            write_json(root, "manifest.json", manifest)
            summary = schema.validate_artifact_root(root, candidate_commit=COMMIT)
            self.assertEqual(summary["verdict"], "STRUCTURE_OK")

    def test_accepts_json_integer_float_exit_status(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            manifest = make_manifest()
            commands = manifest["commands"]
            assert isinstance(commands, list)
            commands[0]["exit_status"] = 0.0
            write_json(root, "manifest.json", manifest)
            summary = schema.validate_artifact_root(root, candidate_commit=COMMIT)
            self.assertEqual(summary["verdict"], "STRUCTURE_OK")

    def test_rejects_boolean_issue_number(self) -> None:
        self.assert_manifest_mutation_rejected(
            lambda manifest: manifest.__setitem__("issues", [True, 1373, 1477]),
            "issues must be integer issue numbers",
        )

    def test_rejects_lossy_decimal_issue_number(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            text = make_manifest_json()
            needle = '"issues":[1373,1477]'
            self.assertIn(needle, text)
            write_text(
                root,
                "manifest.json",
                text.replace(needle, '"issues":[1373.0000000000000001,1477]'),
            )
            with self.assertRaisesRegex(
                schema.ValidationFailure, "issues must be integer issue numbers"
            ):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_lossy_decimal_exit_status(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            text = make_manifest_json()
            needle = '"exit_status":0'
            self.assertIn(needle, text)
            write_text(
                root,
                "manifest.json",
                text.replace(needle, '"exit_status":0.0000000000000001', 1),
            )
            with self.assertRaisesRegex(
                schema.ValidationFailure, "commands\\[0\\].exit_status"
            ):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_unknown_command_gate(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            manifest = make_manifest()
            commands = manifest["commands"]
            assert isinstance(commands, list)
            commands.append(command("unknown-gate"))
            write_json(root, "manifest.json", manifest)
            with self.assertRaisesRegex(schema.ValidationFailure, "unknown-gate"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_additional_manifest_fields(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            manifest = make_manifest()
            manifest["extra"] = "not in schema"
            write_json(root, "manifest.json", manifest)
            with self.assertRaisesRegex(schema.ValidationFailure, "unknown fields"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_schema_required_and_uniqueness_drifts(self) -> None:
        def duplicate_artifacts(manifest: dict[str, object]) -> None:
            commands = manifest["commands"]
            assert isinstance(commands, list)
            commands[0]["artifacts"] = ["summary.md", "summary.md"]

        cases = (
            (
                "missing_top_level_required",
                lambda manifest: manifest.pop("schema_version"),
                "missing required fields: schema_version",
            ),
            (
                "missing_cluster_name",
                lambda manifest: manifest["cluster"].pop("name"),
                "cluster missing required fields: name",
            ),
            (
                "duplicate_issues",
                lambda manifest: manifest.__setitem__(
                    "issues", [1373, 1373, 1477, 1477]
                ),
                "issues must not contain duplicates",
            ),
            (
                "duplicate_config_files",
                lambda manifest: manifest["cluster"].__setitem__(
                    "config_files",
                    [
                        "docs/ha-cluster-userspace.conf",
                        "docs/ha-cluster-userspace.conf",
                    ],
                ),
                "cluster.config_files must not contain duplicates",
            ),
            (
                "duplicate_command_artifacts",
                duplicate_artifacts,
                "commands\\[0\\].artifacts must not contain duplicates",
            ),
            (
                "empty_config_files",
                lambda manifest: manifest["cluster"].__setitem__(
                    "config_files", []
                ),
                "cluster.config_files must not be empty",
            ),
        )

        for name, mutate, pattern in cases:
            with self.subTest(name=name):
                self.assert_manifest_mutation_rejected(mutate, pattern)

    def test_rejects_schema_minlength_and_datetime_drifts(self) -> None:
        def empty_config_file(manifest: dict[str, object]) -> None:
            cluster = manifest["cluster"]
            assert isinstance(cluster, dict)
            cluster["config_files"] = ["docs/ha-cluster-userspace.conf", ""]

        def bad_command_timestamp(manifest: dict[str, object]) -> None:
            commands = manifest["commands"]
            assert isinstance(commands, list)
            commands[0]["started_at"] = "not-a-date"

        cases = (
            (
                "empty_cluster_name",
                lambda manifest: manifest["cluster"].__setitem__("name", ""),
                "cluster.name must be a non-empty string",
            ),
            (
                "empty_candidate_branch",
                lambda manifest: manifest.__setitem__("candidate_branch", ""),
                "candidate_branch must be a non-empty string",
            ),
            (
                "empty_config_file",
                empty_config_file,
                "cluster.config_files entries must be non-empty strings",
            ),
            (
                "bad_artifact_created_at",
                lambda manifest: manifest.__setitem__(
                    "artifact_created_at", "not-a-date"
                ),
                "artifact_created_at must be an RFC3339 date-time string",
            ),
            (
                "artifact_created_at_without_timezone",
                lambda manifest: manifest.__setitem__(
                    "artifact_created_at", "2026-05-24T03:00:00"
                ),
                "artifact_created_at must be an RFC3339 date-time string",
            ),
            (
                "bad_command_timestamp",
                bad_command_timestamp,
                "commands\\[0\\].started_at must be an RFC3339 date-time string",
            ),
        )

        for name, mutate, pattern in cases:
            with self.subTest(name=name):
                self.assert_manifest_mutation_rejected(mutate, pattern)

    def test_rejects_empty_command_artifact_path(self) -> None:
        def mutate(manifest: dict[str, object]) -> None:
            commands = manifest["commands"]
            assert isinstance(commands, list)
            commands[0]["artifacts"] = ["summary.md", ""]

        self.assert_manifest_mutation_rejected(
            mutate, "commands\\[0\\].artifacts entries must be non-empty strings"
        )

    def test_accepts_rfc3339_lowercase_tz_and_leap_second(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            manifest = make_manifest()
            manifest["artifact_created_at"] = "2026-05-24t03:00:00z"
            commands = manifest["commands"]
            assert isinstance(commands, list)
            commands[0]["started_at"] = "2026-06-30T23:59:60Z"
            commands[0]["finished_at"] = "2026-12-31T23:59:60+00:00"
            write_json(root, "manifest.json", manifest)
            summary = schema.validate_artifact_root(root, candidate_commit=COMMIT)
            self.assertEqual(summary["verdict"], "STRUCTURE_OK")

    def test_accepts_rfc3339_leap_second_with_offset(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            manifest = make_manifest()
            commands = manifest["commands"]
            assert isinstance(commands, list)
            commands[0]["started_at"] = "2026-12-31T15:59:60-08:00"
            commands[0]["finished_at"] = "2027-01-01T08:59:60+09:00"
            write_json(root, "manifest.json", manifest)
            summary = schema.validate_artifact_root(root, candidate_commit=COMMIT)
            self.assertEqual(summary["verdict"], "STRUCTURE_OK")

    def test_rejects_local_leap_shape_that_is_not_utc_leap_second(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            manifest = make_manifest()
            commands = manifest["commands"]
            assert isinstance(commands, list)
            commands[0]["started_at"] = "2026-12-31T23:59:60-08:00"
            write_json(root, "manifest.json", manifest)
            with self.assertRaisesRegex(
                schema.ValidationFailure,
                "commands\\[0\\].started_at must be an RFC3339 date-time string",
            ):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_non_leap_shaped_sixty_second_timestamps(self) -> None:
        def set_command_started_at(manifest: dict[str, object], value: str) -> None:
            commands = manifest["commands"]
            assert isinstance(commands, list)
            commands[0]["started_at"] = value

        cases = (
            (
                "top_level_wrong_month",
                lambda manifest: manifest.__setitem__(
                    "artifact_created_at", "2026-05-31T23:59:60Z"
                ),
                "artifact_created_at must be an RFC3339 date-time string",
            ),
            (
                "top_level_wrong_day",
                lambda manifest: manifest.__setitem__(
                    "artifact_created_at", "2026-06-29T23:59:60Z"
                ),
                "artifact_created_at must be an RFC3339 date-time string",
            ),
            (
                "command_wrong_hour",
                lambda manifest: set_command_started_at(
                    manifest, "2026-06-30T22:59:60Z"
                ),
                "commands\\[0\\].started_at must be an RFC3339 date-time string",
            ),
            (
                "command_wrong_minute",
                lambda manifest: set_command_started_at(
                    manifest, "2026-12-31T23:58:60Z"
                ),
                "commands\\[0\\].started_at must be an RFC3339 date-time string",
            ),
        )

        for name, mutate, pattern in cases:
            with self.subTest(name=name):
                self.assert_manifest_mutation_rejected(mutate, pattern)

    def test_rejects_additional_command_fields(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            manifest = make_manifest()
            commands = manifest["commands"]
            assert isinstance(commands, list)
            commands[0]["unexpected"] = "not in schema"
            write_json(root, "manifest.json", manifest)
            with self.assertRaisesRegex(schema.ValidationFailure, "unknown fields"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_invalid_fallback_json_artifact(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            write_text(root, "fallback-exclusion/fw0-userspace-dp.json", "{bad")
            with self.assertRaisesRegex(schema.ValidationFailure, "invalid JSON"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_non_rfc_json_constants_without_traceback(self) -> None:
        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token):
                tmp, root = self.with_fixture()
                with tmp:
                    write_text(
                        root,
                        "fallback-exclusion/fw0-userspace-dp.json",
                        f'{{"value": {token}}}\n',
                    )
                    with self.assertRaisesRegex(
                        schema.ValidationFailure,
                        "invalid JSON artifact fallback-exclusion/fw0-userspace-dp.json: "
                        f"non-RFC 8259 JSON constant: {token}",
                    ):
                        schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_non_utf8_json_artifact_without_traceback(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            path = root / "fallback-exclusion/fw1-userspace-dp.json"
            path.write_bytes(b"\xff\xfe{")
            with self.assertRaisesRegex(schema.ValidationFailure, "invalid UTF-8 JSON"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_decimal_parse_error_without_traceback(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            text = make_manifest_json()
            needle = '"schema_version":1'
            self.assertIn(needle, text)
            write_text(
                root,
                "manifest.json",
                text.replace(needle, '"schema_version":1e999999999999999999999'),
            )
            with self.assertRaisesRegex(schema.ValidationFailure, "invalid JSON"):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)

    def test_rejects_huge_decimal_integer_without_materializing(self) -> None:
        tmp, root = self.with_fixture()
        with tmp:
            text = make_manifest_json()
            needle = '"exit_status":0'
            self.assertIn(needle, text)
            write_text(
                root,
                "manifest.json",
                text.replace(needle, '"exit_status":1e999999999999999999', 1),
            )
            with self.assertRaisesRegex(
                schema.ValidationFailure, "commands\\[0\\].exit_status"
            ):
                schema.validate_artifact_root(root, candidate_commit=COMMIT)


if __name__ == "__main__":
    unittest.main()
