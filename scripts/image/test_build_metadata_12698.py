#!/usr/bin/env python3
"""#12698: build metadata environment cannot add Go linker arguments."""

import os
import tempfile
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class BuildMetadataTests(unittest.TestCase):
    def make(self, **metadata):
        env = dict(os.environ)
        env.update(metadata)
        return subprocess.run(
            ["make", "-s", "--no-print-directory", "-n", "build"],
            cwd=ROOT, env=env, text=True, capture_output=True, check=False)

    def test_valid_build_metadata_is_passed_as_one_linker_value(self):
        result = self.make(
            VERSION="v1.2.3-rc.1+build.4", COMMIT="deadbee",
            BUILD_TIME="2026-10-13T17:46:34Z")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('-X main.version=v1.2.3-rc.1+build.4', result.stdout)
        self.assertIn('-X main.commit=deadbee', result.stdout)
        self.assertIn('-X main.buildTime=2026-10-13T17:46:34Z', result.stdout)

    def test_hostile_metadata_is_refused_before_build_recipe(self):
        hostile = (
            {"VERSION": "1.2.3 -X main.injected=pwned"},
            {"VERSION": "x' ; touch /tmp/xpf-12698-pwned; echo '"},
            {"COMMIT": "deadbee -X main.injected=pwned"},
            {"BUILD_TIME": "2026-10-13T17:46:34Z -X main.injected=pwned"},
            {"VERSION": "1.2.3\n-X main.injected=pwned"},
        )
        for env in hostile:
            with self.subTest(**env):
                result = self.make(**env)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("unsafe", result.stderr)
                self.assertNotIn("go build", result.stdout)

    def test_validation_does_not_execute_metadata_as_make_or_shell_code(self):
        with tempfile.TemporaryDirectory(prefix="xpf-12698-") as tmp:
            sentinel = Path(tmp) / "executed"
            payloads = (
                f"$(shell touch {sentinel})",
                f"x' ; touch {sentinel}; echo '",
            )
            for payload in payloads:
                with self.subTest(payload=payload):
                    result = self.make(VERSION=payload)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertFalse(sentinel.exists(),
                                     f"metadata executed and created {sentinel}")

    def test_command_line_override_is_exported_and_validated(self):
        env = dict(os.environ)
        env.pop("VERSION", None)
        result = subprocess.run(
            ["make", "-s", "--no-print-directory", "-n", "build",
             "VERSION=1.2.3 -X main.version=pwned"],
            cwd=ROOT, env=env, text=True, capture_output=True, check=False)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertNotIn("go build", result.stdout)

    def test_rejects_invalid_commit_and_non_rfc3339_time(self):
        for env in (
                {"COMMIT": "DEADBEEF"},
                {"COMMIT": "bad"},
                {"BUILD_TIME": "2026-02-30T00:00:00Z"},
                {"BUILD_TIME": "2026-10-13T17:46:34+00:00"}):
            with self.subTest(**env):
                result = self.make(**env)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertNotIn("go build", result.stdout)

    def test_default_metadata_remains_accepted(self):
        env = dict(os.environ)
        for name in ("VERSION", "COMMIT", "BUILD_TIME"):
            env.pop(name, None)
        result = subprocess.run(
            ["make", "-s", "--no-print-directory", "-n", "build"],
            cwd=ROOT, env=env, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("-X main.version=", result.stdout)


if __name__ == "__main__":
    unittest.main()
