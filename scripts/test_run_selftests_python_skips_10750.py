#!/usr/bin/env python3
"""Regression coverage for all-skipped Python legs in run-selftests.sh (#10750)."""

import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "scripts" / "run-selftests.sh"

_DRIVER = r"""PASS=0; SKIP=0; FAIL=0; FAILED_LEGS=""
passl() { PASS=$((PASS + 1)); echo "PASS: $*"; }
skipl() { SKIP=$((SKIP + 1)); echo "SKIP: $*"; }
faill() { FAIL=$((FAIL + 1)); FAILED_LEGS="$FAILED_LEGS $1"; echo "FAIL: $*"; }
eval "$(sed -n '/^run_py() {/,/^}/p' "$1")"
run_py "$2"
echo "COUNTS pass=$PASS skip=$SKIP fail=$FAIL"
"""


class PythonSkipClassification10750(unittest.TestCase):
    def _run_py(self, test_source):
        with tempfile.TemporaryDirectory(prefix="selftest-py-10750-") as td:
            test_file = Path(td) / "fixture.py"
            test_file.write_text(test_source, encoding="utf-8")
            result = subprocess.run(
                ["sh", "-c", _DRIVER, "run_py-test", str(RUNNER), str(test_file)],
                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        counts = re.search(
            r"COUNTS pass=(\d+) skip=(\d+) fail=(\d+)", result.stdout)
        self.assertIsNotNone(counts, result.stdout + result.stderr)
        return tuple(map(int, counts.groups())), result.stdout

    def test_all_skipped_file_is_a_skip_not_a_pass(self):
        counts, output = self._run_py(
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    @unittest.skip('device unavailable')\n"
            "    def test_one(self): pass\n"
            "    @unittest.skip('device unavailable')\n"
            "    def test_two(self): pass\n"
            "if __name__ == '__main__': unittest.main()\n")
        self.assertEqual(counts, (0, 1, 0), output)
        self.assertIn("SKIP:", output)
        self.assertIn("all 2 tests skipped", output)

    def test_file_with_a_passing_test_and_a_skip_remains_a_pass(self):
        counts, output = self._run_py(
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_one(self): self.assertEqual(1, 1)\n"
            "    @unittest.skip('device unavailable')\n"
            "    def test_two(self): pass\n"
            "if __name__ == '__main__': unittest.main()\n")
        self.assertEqual(counts, (1, 0, 0), output)
        self.assertIn("PASS:", output)
        self.assertIn("skipped=1", output)

    def test_failed_test_remains_a_failure(self):
        counts, output = self._run_py(
            "import unittest\n"
            "class T(unittest.TestCase):\n"
            "    def test_failure(self): self.fail('fixture failure')\n"
            "if __name__ == '__main__': unittest.main()\n")
        self.assertEqual(counts, (0, 0, 1), output)
        self.assertIn("FAIL:", output)


if __name__ == "__main__":
    unittest.main()
