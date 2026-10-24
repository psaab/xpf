#!/usr/bin/env python3
"""Regression test for the #1930 kernel-hold enumeration in bake.py.

The bake pins the kernel package set with `apt-mark hold` so a background
apt cannot drift the kernel out from under the verifier-gated AF_XDP shim
(#1864/#1930). The package set is enumerated in-guest with:

    pkgs=$(dpkg-query -W -f="${Package}\\n" "linux-image-*" ... | sort -u)

That fragment is handed to the guest's `sh -c`, so the `$` in `${Package}`
must reach dpkg-query LITERALLY. Unescaped, the guest shell expands
`${Package}` itself — it is an unset shell variable, so the format string
collapses to a bare `\\n`, dpkg-query emits one blank line per installed
kernel package, `$(...)` strips the trailing newlines, and `pkgs` comes out
EMPTY. The bake then dies at its own guard:

    FATAL: no linux-* packages found to hold

which aborts every bake before the image is ever written. (Introduced
2026-06-16 by 6948ed0f8, #1930 INC-0; found by running a real bake.)

This test extracts the actual `--run-command` string bake.py emits and runs
it under a real /bin/sh against a STUB dpkg-query + apt-mark, asserting the
kernel packages are enumerated and held.

RED on revert: drop the backslash before `${Package}` in bake.py and
test_enumerates_kernel_packages fails with the FATAL guard message.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

bake = load_subject("xpf_bake_hold", Path(__file__).with_name("bake.py"))

# The kernel package set a stubbed guest reports as INSTALLED.
_INSTALLED = [
    "linux-generic",
    "linux-headers-7.0.0-30",
    "linux-headers-7.0.0-30-generic",
    "linux-image-7.0.0-30-generic",
    "linux-modules-7.0.0-30-generic",
]

# Names dpkg KNOWS OF but which are NOT installed. `dpkg-query -W` returns
# these alongside the installed set (they are left behind by a purge, or
# referenced only as some other package's dependency). `apt-mark hold` fails
# on them with "Can't select installed nor candidate version", and `set -e`
# turns that into a dead bake -- so they must be filtered out. These two
# names are the ones a real 26.04 bake actually tripped over.
_NOT_INSTALLED = [
    "linux-headers-3.0",
    "linux-image-fb-generic",
]


def _hold_command() -> str:
    """Return the single `--run-command` from bake.py that does apt-mark hold."""
    captured = {}

    def fake_run(argv, **kw):
        captured["argv"] = argv
        return None

    real_run = bake.run
    bake.run = fake_run
    try:
        bake.virt_customize("/nonexistent/work.qcow2", "/nonexistent/xpf.deb")
    finally:
        bake.run = real_run

    argv = captured["argv"]
    cmds = [argv[i + 1] for i, a in enumerate(argv[:-1])
            if a == "--run-command" and "apt-mark hold" in argv[i + 1]]
    assert len(cmds) == 1, f"expected exactly 1 apt-mark hold command, got {len(cmds)}"
    return cmds[0]


class KernelHoldEnumerationTests(unittest.TestCase):
    def setUp(self):
        self.cmd = _hold_command()

    @staticmethod
    def _stub_guest(tmp: str) -> dict:
        """Create stub dpkg-query/apt-mark on a private PATH.

        The dpkg-query stub honours `-f`/`--showformat` the way the real one
        does for the only field bake.py asks for, `${Package}`. It therefore
        emits blank lines when handed a format with no field reference —
        exactly the real behaviour the bug depended on.
        """
        binv = Path(tmp) / "bin"
        binv.mkdir()
        held = Path(tmp) / "held"
        held.write_text("")

        (binv / "dpkg-query").write_text(
            "#!/bin/sh\n"
            "fmt=''\n"
            "while [ $# -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    -W) ;;\n"
            "    -f=*) fmt=${1#-f=} ;;\n"
            "    -f|--showformat) shift; fmt=$1 ;;\n"
            "    --showformat=*) fmt=${1#--showformat=} ;;\n"
            "    *) patterns=\"$patterns $1\" ;;\n"
            "  esac\n"
            "  shift\n"
            "done\n"
            "emit() {\n"
            "  st=$1; p=$2\n"
            "  out=''\n"
            "  case \"$fmt\" in *'${db:Status-Status}'*) out=\"$st \" ;; esac\n"
            "  case \"$fmt\" in *'${Package}'*) out=\"$out$p\" ;; esac\n"
            "  printf '%s\\n' \"$out\"\n"
            "}\n"
            "for p in " + " ".join(_INSTALLED) + "; do emit installed \"$p\"; done\n"
            "for p in " + " ".join(_NOT_INSTALLED) + "; do emit not-installed \"$p\"; done\n"
        )
        # `apt-mark hold` on a name that is not installed is an ERROR, exactly
        # as the real one behaves -- so an unfiltered enumeration kills the
        # step under `set -e`.
        (binv / "apt-mark").write_text(
            "#!/bin/sh\n"
            f"HELD={held}\n"
            "case \"$1\" in\n"
            "  hold) shift; rc=0; for p in \"$@\"; do\n"
            "      case \" " + " ".join(_NOT_INSTALLED) + " \" in\n"
            "        *\" $p \"*) echo \"E: Can't select installed nor candidate\"\n"
            "                   \"version from package '$p' as it has neither\" >&2\n"
            "                 rc=100; continue ;;\n"
            "      esac\n"
            "      echo \"$p\" >> \"$HELD\"\n"
            "    done; exit $rc ;;\n"
            "  showhold) sort -u \"$HELD\" ;;\n"
            "esac\n"
        )
        for f in ("dpkg-query", "apt-mark"):
            os.chmod(binv / f, os.stat(binv / f).st_mode | stat.S_IEXEC)
        return {"PATH": f"{binv}:{os.environ['PATH']}"}

    def test_enumerates_kernel_packages(self):
        """The emitted script must enumerate + hold the installed kernel set.

        REDs on the unescaped `${Package}`: the guest shell eats the field
        reference, pkgs comes out empty, and bake.py's own guard fires.

        Also REDs on an unfiltered enumeration: the stub reports two
        not-installed names, apt-mark rejects them, and `set -e` kills the
        step -- the second half of the real bake failure.
        """
        with tempfile.TemporaryDirectory() as tmp:
            env = self._stub_guest(tmp)
            r = subprocess.run(["/bin/sh", "-c", self.cmd], env=env,
                               capture_output=True, text=True)
            self.assertEqual(
                r.returncode, 0,
                f"hold step failed rc={r.returncode}\n"
                f"stdout={r.stdout}\nstderr={r.stderr}")
            self.assertNotIn("no linux-* packages found to hold", r.stderr)
            for pkg in _INSTALLED:
                self.assertIn(pkg, r.stdout,
                              f"{pkg} missing from the held set: {r.stdout}")
            self.assertIn(f"held {len(_INSTALLED)} linux-* packages", r.stdout)
            for pkg in _NOT_INSTALLED:
                self.assertNotIn(
                    pkg, r.stdout,
                    f"not-installed {pkg} must not be handed to apt-mark hold")

    def test_field_references_are_escaped_for_the_guest_shell(self):
        """Every dpkg-query field reference must be escaped for `sh -c`.

        A textual companion to the behavioural test above: it pins the
        MECHANISM (each `$` is backslash-escaped, so the guest shell hands
        `${...}` to dpkg-query instead of expanding it) so a rewrite that
        keeps the fragment but drops an escape is caught even if the stub
        harness drifts.
        """
        fmt = _fmt_of(self.cmd)
        for field in ("${db:Status-Status}", "${Package}"):
            self.assertIn("\\" + field, fmt,
                          f"{field} must be backslash-escaped in {fmt!r}")
        # And nothing unescaped slipped through: strip the escaped forms and
        # no bare field reference may remain.
        residue = fmt.replace("\\${db:Status-Status}", "").replace("\\${Package}", "")
        self.assertNotIn("${", residue,
                         f"unescaped field reference left in {fmt!r}")

    def test_only_installed_packages_are_enumerated(self):
        """The enumeration must filter on install state.

        `dpkg-query -W` reports every package dpkg knows of. Holding a
        not-installed one is an apt-mark error and, under `set -e`, a dead
        bake. Pin that the status field is both requested and filtered on.
        """
        self.assertIn("db:Status-Status", self.cmd)
        self.assertIn('installed', self.cmd)


def _fmt_of(cmd: str) -> str:
    """Extract the dpkg-query `-f="..."` format as written in the script.

    The format contains spaces, so it cannot be recovered by splitting on
    whitespace; match the double-quoted argument instead.
    """
    m = re.search(r'-f="([^"]*)"', cmd)
    assert m, f"no -f=\"...\" argument in {cmd!r}"
    return m.group(1)


if __name__ == "__main__":
    unittest.main()
