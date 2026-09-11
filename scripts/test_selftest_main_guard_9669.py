"""#9669: a python self-test must define every cell BEFORE its main guard.

scripts/run-selftests.sh runs each test file as `python3 <file>`. A module
executes top to bottom, and `unittest.main()` exits the process, so any
class or def below `if __name__ == "__main__":` is never defined and its cells
never run. The suite still reports OK. That is how the five #8977 cells in
scripts/deploy/test_xpf_deploy_robustness.py sat dead in `make selftest`
while `python3 -m unittest` ran them. This scans the same globs run-selftests
uses.
"""

import re
import unittest
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_GLOBS = ["scripts/image/test_*.py", "scripts/dist/test_*.py",
          "scripts/deploy/test_*.py", "scripts/test_*.py"]
_GUARD = re.compile(r'^if __name__ == ["\']__main__["\']:', re.M)
_TOPLEVEL_DEF = re.compile(r"^(class|def) ", re.M)


class CellsAreDefinedBeforeTheMainGuard9669(unittest.TestCase):
    def test_no_cell_is_defined_after_the_guard(self):
        offenders = []
        scanned = 0
        for pattern in _GLOBS:
            for path in sorted(_ROOT.glob(pattern)):
                scanned += 1
                src = path.read_text()
                guard = _GUARD.search(src)
                if guard and _TOPLEVEL_DEF.search(src, guard.end()):
                    offenders.append(str(path.relative_to(_ROOT)))
        self.assertGreater(scanned, 20, "the scan found almost no test files; it is reading the wrong tree")
        self.assertEqual(offenders, [], "these files define classes or functions after `if __name__ == \"__main__\":`, "
                                        "so `python3 <file>` never runs them")

    def test_the_scan_sees_a_late_definition(self):
        # Positive control on the matcher itself.
        src = 'import unittest\nif __name__ == "__main__":\n    unittest.main()\n\nclass Late(unittest.TestCase):\n    pass\n'
        guard = _GUARD.search(src)
        self.assertIsNotNone(guard)
        self.assertIsNotNone(_TOPLEVEL_DEF.search(src, guard.end()))


if __name__ == "__main__":
    unittest.main()
