#!/usr/bin/env python3
"""Cells for scripts/lib/load_subject.py (#16194).

The load-bearing rows are the ones that distinguish the helper from
the pre-helper boilerplate it replaces: the three script tests whose
subjects use ``dataclasses`` (close_keyword_lint, cut_stall_analyze)
registered the module in ``sys.modules`` by hand before executing it,
because ``dataclasses`` resolves string annotations through
``sys.modules[cls.__module__]``; every other file skipped registration
and would break silently if its subject grew a dataclass.  The helper
registers always, so identity (``sys.modules[name] is module``) and
the dataclass lookup hold for every migrated test, and a subject that
raises during execution must leave no half-initialised registration
behind (a later import must not find the broken module).
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

_LIB = Path(__file__).resolve().parents[1] / "lib"
sys.path.insert(0, str(_LIB))

from load_subject import load_subject  # noqa: E402


class LoadSubjectTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)
        self._names = []

    def tearDown(self):
        for name in self._names:
            sys.modules.pop(name, None)

    def _write(self, filename, body):
        path = self.dir / filename
        path.write_text(textwrap.dedent(body))
        return path

    def _load(self, name, path):
        self._names.append(name)
        return load_subject(name, path)

    def test_loads_hyphenated_file_and_registers_identity(self):
        path = self._write("my-tool.py", """\
            VALUE = 41
            """)
        mod = self._load("my_tool_16194", path)
        self.assertEqual(mod.VALUE, 41)
        self.assertIs(sys.modules["my_tool_16194"], mod)
        self.assertEqual(mod.__name__, "my_tool_16194")

    def test_dataclass_subject_resolves_via_sys_modules(self):
        # Without registration before exec, @dataclass with
        # `from __future__ import annotations` raises AttributeError
        # ("'NoneType' object has no attribute '__dict__'") because
        # dataclasses looks the class's module up in sys.modules.
        path = self._write("dc_subject.py", """\
            from __future__ import annotations

            from dataclasses import dataclass


            @dataclass(frozen=True)
            class Cell:
                ref: str
            """)
        mod = self._load("dc_subject_16194", path)
        self.assertEqual(mod.Cell(ref="x").ref, "x")
        self.assertIs(sys.modules["dc_subject_16194"], mod)

    def test_subject_can_import_itself_by_registered_name(self):
        path = self._write("selfish.py", """\
            import selfish_16194 as _self

            SAME = _self is not None
            """)
        mod = self._load("selfish_16194", path)
        self.assertTrue(mod.SAME)
        self.assertIs(sys.modules["selfish_16194"], mod)

    def test_exec_failure_propagates_and_cleans_registration(self):
        path = self._write("boom.py", """\
            raise RuntimeError("subject exploded")
            """)
        with self.assertRaises(RuntimeError) as ctx:
            self._load("boom_16194", path)
        self.assertEqual(str(ctx.exception), "subject exploded")
        self.assertNotIn("boom_16194", sys.modules)

    def test_exec_failure_restores_prior_registration(self):
        # A pre-existing entry under the same name is not the loaded
        # module, so cleanup must not delete someone else's module.
        import types

        prior = types.ModuleType("shared_16194")
        sys.modules["shared_16194"] = prior
        self._names.append("shared_16194")
        path = self._write("boom2.py", """\
            raise ValueError("nope")
            """)
        with self.assertRaises(ValueError):
            load_subject("shared_16194", path)
        self.assertIs(sys.modules["shared_16194"], prior)

    def test_missing_file_raises_import_error(self):
        with self.assertRaises(ImportError):
            self._load("missing_16194", self.dir / "does-not-exist.py")
        self.assertNotIn("missing_16194", sys.modules)

    def test_repeated_loads_replace_registration(self):
        first = self._write("one.py", "VALUE = 1\n")
        second = self._write("two.py", "VALUE = 2\n")
        mod1 = self._load("repeat_16194", first)
        mod2 = self._load("repeat_16194", second)
        self.assertIsNot(mod1, mod2)
        self.assertIs(sys.modules["repeat_16194"], mod2)
        self.assertEqual(mod2.VALUE, 2)

    def test_reimport_in_fresh_interpreter_sees_no_global_state(self):
        # Each test FILE runs as its own `python3 <file>` process in
        # run-selftests.sh, so the helper must work from a bare
        # interpreter with only scripts/lib on sys.path: no earlier
        # test's sys.modules entry may be load-bearing.  Drive the
        # real close_keyword_lint subject (a dataclass user) that way.
        lib = Path(__file__).resolve().parents[1] / "lib"
        subject = lib.parent / "close_keyword_lint.py"
        program = (
            "import sys;"
            f"sys.path.insert(0, {str(lib)!r});"
            "from load_subject import load_subject;"
            f"m = load_subject('close_keyword_lint', {str(subject)!r});"
            "print(m.close_pairs('Closes #16194')[0].ref)"
        )
        out = subprocess.run(
            [sys.executable, "-I", "-c", program],
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "#16194")

    def test_loaded_subject_cli_still_runs_by_path(self):
        # The production contract Stage A must not disturb: the file
        # keeps its hyphenated name and runs as a plain script path.
        path = self._write("my-cli.py", """\
            import sys

            print("cli:" + ",".join(sys.argv[1:]))
            """)
        out = subprocess.run(
            [sys.executable, str(path), "a", "b"],
            capture_output=True, text=True, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout.strip(), "cli:a,b")


if __name__ == "__main__":
    unittest.main()
