#!/usr/bin/env python3
"""Hermetic unit tests for the #16196 command-runner seam.

Before this, `Harness.__init__` had no runner parameter, so lifecycle
logic that is pure given a command transcript — ownership refusal
(#4905-D) and the skip ledger (#7347) — could only be exercised by
patching module globals, and half the child commands (virt-*, qemu-img,
`rm`, the QEMU process lifetime) could not be faked at all without
reaching for `subprocess` itself.

These cells inject ONE fake runner at construction and drive the real
Harness methods with no incus, no qemu and no host tools present. The
fake ASSERTS on any argv shape it was not taught, so a site that escapes
the seam (straight to a real subprocess) or dispatches a shape the test
did not anticipate fails here rather than silently touching the host.

RED on revert: dropping the `runner`/`popen` parameters (or rerouting a
site back to a bare `subprocess.*` / module-global call) turns the
ownership/skip/census cells red — the fake never sees the command, the
real binary is invoked (or not found), and the census counts the escaped
site.

Reach map — every child-command site in validate.py as of #16196
(proven by SubprocessReachMapTests below, which re-derives the map by
AST rather than trusting this prose):

  REACHED — subprocess.run to completion, dispatching via
  _dispatch_run / Harness.run / Harness._run (one fake runner):
    * module `incus`        via Harness._incus        (20 call sites)
    * module `guest`        via Harness.guest         (38 call sites)
    * module `guest_sh`     via Harness.guest_sh      (30 call sites)
    * module `guest_absent` via Harness.guest_absent  ( 4 call sites)
      (the module functions keep an identical optional `runner` for
      their standalone callers — see test_validate_guest_absent_7424.py)
    * `virt-ls` / `virt-cat` in assert_image_sealed   (2 run sites)
    * `rm -rf <work>` in cleanup                      (1 run site)
    * `qemu-img info` / `qemu-img check` in scenario_qemu (2 run sites)
    * `incus list` probe in maybe_reexec_incus_admin  (via its `runner`
      parameter; main() still defaults it — no fake needed there)

  REACHED — process lifetime, dispatching via Harness._popen:
    * `subprocess.Popen` for the direct-QEMU boot leg (1 site), whose
      poll/communicate/terminate/wait/kill lifetime a run-to-completion
      runner cannot express; the seam is the constructor.

  UNREACHED — named, deliberately NOT routed:
    * `subprocess.run` / `subprocess.Popen` inside the two module-level
      defaults `_default_run` / `_default_popen`: they ARE the default
      the seam falls back to, not escapees from it.
    * `make_config_drive.build_config_drive`'s own subprocess calls
      (xpfd check-config + the ISO writer, in make_config_drive.py):
      that module owns those children; the harness calls the function,
      not the commands, and #16196's scope is validate.py.
    * `sign` (scripts/dist/sign.py) subprocess calls (minisign/gpg):
      reached only through sign.* function calls, same reason.
    * `os.execvp("sg", ...)` in maybe_reexec_incus_admin: an exec image
      replacement, not a run-to-completion child; routing it through a
      runner would fake away the process image the probe preserves.
    * `shutil.which` / `os.access` host probes: not child commands.
"""

from __future__ import annotations

import ast
import inspect
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from load_subject import load_subject  # noqa: E402

_HERE = Path(__file__).resolve().parent
validate = load_subject("validate", _HERE / "validate.py")


def _completed(rc=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


class _FakeProc:
    """The QEMU lifetime surface scenario_qemu consumes."""

    def __init__(self, argv, **kwargs):
        self.argv = list(argv)
        self.kwargs = kwargs
        self.returncode = None
        self.terminated = False
        self.killed = False
        self.waited = False

    def poll(self):
        return None

    def communicate(self):
        return b"", b""

    def terminate(self):
        self.terminated = True

    def wait(self, timeout=None):
        self.waited = True
        return 0

    def kill(self):
        self.killed = True


class FakeRunner:
    """One fake runner recording every argv; untaught shapes are errors.

    `owner` is what `incus config get <name> user.xpf-owner` reports;
    None means the get itself fails (instance absent). `guest_absent`
    probes answer `present_paths`; every other guest command succeeds.
    """

    def __init__(self, owner=None, get_rc=0, qemu_info=None,
                 present_paths=(), virt_ls="", virt_cat=""):
        self.calls = []       # list of (argv list, kwargs dict)
        self.owner = owner
        self.get_rc = get_rc
        self.qemu_info = qemu_info if qemu_info is not None else {
            "virtual-size": validate.BAKE_MIN_BYTES + (1 << 30),
            "filename": "x", "format": "qcow2"}
        self.present_paths = set(present_paths)
        self.virt_ls = virt_ls
        self.virt_cat = virt_cat

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append((argv, dict(kwargs)))
        head = argv[0]
        if head == "incus":
            return self._incus(argv)
        if head in ("virt-ls", "virt-cat"):
            if head == "virt-ls":
                # virt-ls of a missing dir mirrors the real tool so the
                # seal's "absent directory" branch stays reachable.
                return _completed(1, "", "virt-ls: No such file or directory")
            return _completed(0, self.virt_cat)
        if head == "rm":
            return _completed(0)
        if head == "qemu-img":
            if argv[1] == "info":
                return _completed(0, json.dumps(self.qemu_info))
            return _completed(0)
        raise AssertionError(f"fake runner got an untaught argv: {argv!r}")

    def _incus(self, argv):
        if argv[1:3] == ["config", "get"]:
            if self.get_rc != 0:
                return _completed(self.get_rc, "", "Error: not found")
            return _completed(0, (self.owner or "") + "\n")
        if argv[1] == "exec":
            script = argv[-1]
            if "echo XPF_ABSENT" in script:
                path = [p for p in self.present_paths if p in script]
                return _completed(0, "XPF_PRESENT\n" if path else "XPF_ABSENT\n")
            return _completed(0, "")
        return _completed(0, "")

    def argv_calling(self, *prefix):
        return [c for c in self.calls if c[0][:len(prefix)] == list(prefix)]


def _harness(runner, popen=None, keep=False):
    h = validate.Harness("img.qcow2", "meta.tar.gz", "xpf-image-net", keep,
                         verify_sig=False, runner=runner, popen=popen)
    return h


class SeamSurfaceTests(unittest.TestCase):
    def test_defaults_are_the_subprocess_path(self):
        self.assertIs(validate._default_run, validate._default_run)
        sent = object()
        with mock.patch.object(validate.subprocess, "run",
                               return_value=sent) as run:
            self.assertIs(validate._default_run(["x"], check=False), sent)
        run.assert_called_once_with(["x"], check=False)
        with mock.patch.object(validate.subprocess, "Popen",
                               return_value=sent) as popen:
            self.assertIs(validate._default_popen(["x"]), sent)
        popen.assert_called_once_with(["x"])
        # runner=None resolves to those defaults, per call:
        with mock.patch.object(validate, "_default_run",
                               return_value=sent) as default_run:
            self.assertIs(validate.incus("list", runner=None), sent)
            self.assertIs(validate._dispatch_run(None, ["x"]), sent)
        self.assertEqual(default_run.call_count, 2)

    def test_module_helpers_route_through_an_injected_runner(self):
        runner = FakeRunner(owner="unused")
        validate.incus("image", "list", runner=runner)
        validate.guest("i1", "true", runner=runner)
        self.assertTrue(validate.guest_sh("i1", "true", runner=runner))
        self.assertTrue(validate.guest_absent("i1", "/etc/xpf/xpf.conf",
                                              runner=runner))
        shapes = [c[0] for c in runner.calls]
        self.assertEqual(shapes[0], ["incus", "image", "list"])
        self.assertEqual(shapes[1], ["incus", "exec", "i1", "--", "true"])
        self.assertEqual(shapes[2],
                         ["incus", "exec", "i1", "--", "sh", "-c", "true"])
        self.assertEqual(shapes[3][:6],
                         ["incus", "exec", "i1", "--", "sh", "-c"])

    def test_constructor_stores_none_unresolved(self):
        h = _harness(None)
        self.addCleanup(shutil.rmtree, h.work, ignore_errors=True)
        self.assertIsNone(h.runner)
        self.assertIsNone(h.popen)


class OwnershipRefusalTests(unittest.TestCase):
    def test_foreign_tagged_instance_is_refused_via_fake_runner(self):
        runner = FakeRunner(owner="some-other-run")
        h = _harness(runner)
        self.addCleanup(shutil.rmtree, h.work, ignore_errors=True)
        # incus is provably absent from this test's world: the only way the
        # refusal can be observed is through the injected runner.
        with mock.patch.object(validate.subprocess, "run",
                               side_effect=AssertionError("real subprocess reached")):
            buf = io.StringIO()
            with redirect_stdout(buf):
                h._owned_delete("bystander-vm")
        self.assertIn("refusing to delete", buf.getvalue())
        self.assertEqual(runner.argv_calling("incus", "delete"), [],
                         "a foreign instance must not be force-deleted")

    def test_own_tagged_instance_is_deleted_via_fake_runner(self):
        holder = {}
        runner = FakeRunner()
        h = _harness(runner)
        self.addCleanup(shutil.rmtree, h.work, ignore_errors=True)
        runner.owner = h.run_id
        with mock.patch.object(validate.subprocess, "run",
                               side_effect=AssertionError("real subprocess reached")):
            h._owned_delete("xpf-image-x")
        self.assertEqual(len(runner.argv_calling("incus", "delete")), 1)

    def test_missing_instance_is_a_noop_via_fake_runner(self):
        runner = FakeRunner(get_rc=1)
        h = _harness(runner)
        self.addCleanup(shutil.rmtree, h.work, ignore_errors=True)
        h._owned_delete("does-not-exist")
        self.assertEqual(runner.argv_calling("incus", "delete"), [])
        self.assertEqual(len(runner.calls), 1, "only the owner probe ran")


class SkipLedgerTests(unittest.TestCase):
    def test_skip_ledger_records_through_a_fake_runner_run(self):
        """The #7347 ledger: a fatal skip fails the verdict, a tolerated
        one does not — driven through a Harness built on the fake runner
        with no incus present, lifecycle included."""
        runner = FakeRunner()
        h = _harness(runner)
        h.instances = []
        h.created_net = False
        h.imported_alias = False
        buf = io.StringIO()
        with redirect_stdout(buf):
            h.skip("X/leg", "because reasons", fatal=True)
            h.skip("Q/boot-leg", "no kvm", fatal=False)
            h.cleanup()
        code, lines = validate._skip_verdict(h.skipped, allow_skip=False)
        self.assertEqual(code, 1)
        self.assertTrue(any("REFUSING to report success" in x for x in lines))
        self.assertTrue(any("Q/thing" not in x and "X/leg" in x for x in lines))
        code_ok, _ = validate._skip_verdict(
            [x for x in h.skipped if not x[2]], allow_skip=False)
        self.assertEqual(code_ok, 0)
        # cleanup still dispatched its `rm -rf` through the same fake:
        self.assertEqual(len(runner.argv_calling("rm", "-rf")), 1)

    def test_qemu_boot_leg_skip_is_tolerated_through_fake_runner(self):
        """TCG-host shape end to end via the seam: qemu-img present (per
        PATH), qemu-system absent, so the structural probe passes through
        the fake and exactly one tolerated skip is recorded."""
        runner = FakeRunner()
        popens = []

        def fake_popen(argv, **kw):
            raise AssertionError("QEMU must not launch on a TCG host")

        h = _harness(runner, popen=fake_popen)
        self.addCleanup(shutil.rmtree, h.work, ignore_errors=True)
        with tempfile.TemporaryDirectory() as d:
            binz = Path(d) / "bin"
            binz.mkdir()
            # A real qemu-img on PATH if the host has one; otherwise a stub
            # binary that only satisfies shutil.which (the fake runner
            # answers the actual qemu-img calls, so it is never executed).
            real = shutil.which("qemu-img")
            if real:
                os.symlink(real, binz / "qemu-img")
            else:
                stub = binz / "qemu-img"
                stub.write_text("#!/bin/sh\nexit 0\n")
                stub.chmod(0o755)
            old = os.environ.get("PATH", "")
            os.environ["PATH"] = str(binz)
            try:
                self.assertIsNone(shutil.which("qemu-system-x86_64"))
                buf = io.StringIO()
                with redirect_stdout(buf):
                    h.scenario_qemu()
            finally:
                os.environ["PATH"] = old
        self.assertIn("structural probe OK", buf.getvalue())
        self.assertEqual(len(h.skipped), 1)
        what, reason, fatal = h.skipped[0]
        self.assertEqual(what, "Q/boot-leg")
        self.assertFalse(fatal)
        self.assertEqual(len(runner.argv_calling("qemu-img", "info")), 1)
        self.assertEqual(len(runner.argv_calling("qemu-img", "check")), 1)

    def test_qemu_boot_leg_lifetime_dispatches_through_fake_popen(self):
        """The Popen leg: a fake process that never boots must still be
        terminated through the injected constructor — reaching the serial
        wait with the fake proves the lifetime is the seam's, and the
        finally-block terminate/wait happened on OUR object."""
        runner = FakeRunner()
        procs = []

        def fake_popen(argv, **kw):
            proc = _FakeProc(argv, **kw)
            procs.append(proc)
            return proc

        h = _harness(runner, popen=fake_popen)
        self.addCleanup(shutil.rmtree, h.work, ignore_errors=True)
        with tempfile.TemporaryDirectory() as d:
            code = Path(d) / "CODE.fd"
            varsf = Path(d) / "VARS.fd"
            code.write_bytes(b"c")
            varsf.write_bytes(b"v")
            serial_content = {}

            def firmware():
                return str(code), str(varsf), True, "fake SB pair"

            # Pre-create the serial log scenario_qemu polls: a guest that
            # booted and applied day-0, so the leg completes its PASS path
            # instead of spinning 360s against the fake.
            orig_build = validate.make_config_drive.build_config_drive

            def build(conf, out, validate=True):
                Path(out).write_bytes(b"iso")
                serial_content["path"] = str(Path(h.work) / "qemu-serial.log")
                Path(serial_content["path"]).write_text(
                    "booting\nday-0 config installed\n")
                return out

            fake_qsys = "/fake/qemu-system-x86_64"
            with mock.patch.object(validate.shutil, "which",
                                   side_effect=lambda t: {
                                       "qemu-img": "/fake/qemu-img",
                                       "qemu-system-x86_64": fake_qsys}.get(t)), \
                    mock.patch.object(validate, "_qemu_firmware_choice",
                                      side_effect=firmware), \
                    mock.patch.object(validate.os, "access", return_value=True), \
                    mock.patch.object(validate.make_config_drive,
                                      "build_config_drive", side_effect=build), \
                    mock.patch.object(validate.time, "sleep", return_value=None):
                buf = io.StringIO()
                with redirect_stdout(buf):
                    h.scenario_qemu()
            self.assertIn("Scenario Q PASS", buf.getvalue())
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0].argv[0], fake_qsys)
        self.assertTrue(procs[0].terminated)
        self.assertTrue(procs[0].waited)
        self.assertEqual(h.skipped, [])


class SubprocessReachMapTests(unittest.TestCase):
    """Re-derive the reach map in this file's header by AST.

    The counts are the point: a new bare `subprocess.*` site, a helper
    call that bypasses the instance seam, or a lost dispatch changes a
    number here and reds until the header map is updated to match — the
    enumeration the #16196 acceptance requires cannot drift silently.
    """

    @classmethod
    def setUpClass(cls):
        cls.src = (_HERE / "validate.py").read_text()
        cls.tree = ast.parse(cls.src)

    def _harness(self):
        return next(n for n in ast.walk(self.tree)
                    if isinstance(n, ast.ClassDef) and n.name == "Harness")

    def test_only_the_two_defaults_touch_subprocess(self):
        defaults = {"_default_run", "_default_popen"}
        offenders = []
        for node in ast.walk(self.tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "subprocess"
                    and func.attr in ("run", "Popen")):
                # Attribute to the enclosing function, if any.
                offenders.append(node.lineno)
        allowed = set()
        for node in self.tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in defaults:
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        allowed.add(sub.lineno)
        escaped = [ln for ln in offenders if ln not in allowed]
        self.assertEqual(escaped, [],
                         "subprocess.run/Popen outside _default_run/"
                         "_default_popen — route it through the #16196 seam")
        self.assertEqual(len(offenders), 2,
                         "expected exactly the two default subprocess calls")

    def test_harness_dispatch_counts(self):
        harness = self._harness()
        counts = {}
        bare_helpers = []
        for node in ast.walk(harness):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if (isinstance(func, ast.Attribute)
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "self"):
                counts[func.attr] = counts.get(func.attr, 0) + 1
            if (isinstance(func, ast.Name)
                    and func.id in ("incus", "guest", "guest_sh", "guest_absent")):
                bare_helpers.append((node.lineno, func.id))
        # The thin bound helpers themselves legitimately name the module
        # functions once each; nothing else inside Harness may.
        self.assertEqual(sorted(n for _, n in bare_helpers),
                         ["guest", "guest_absent", "guest_sh", "incus"],
                         f"bare module-helper calls inside Harness: {bare_helpers}")
        expected = {"run": 1, "_run": 5, "_popen": 1, "_incus": 20,
                    "guest": 39, "guest_sh": 30, "guest_absent": 4}
        for name, want in expected.items():
            self.assertEqual(counts.get(name), want,
                             f"Harness dispatch via self.{name}: "
                             f"got {counts.get(name)}, want {want} — if a "
                             "site moved, update the reach map in this file")
        called = set(counts)
        for name in expected:
            self.assertIn(name, called)

    def test_seam_surface_exists(self):
        params = inspect.signature(validate.Harness.__init__).parameters
        self.assertIn("runner", params)
        self.assertIn("popen", params)
        self.assertIsNone(params["runner"].default)
        self.assertIsNone(params["popen"].default)
        for fn in (validate.incus, validate.guest, validate.guest_sh,
                   validate.guest_absent, validate.maybe_reexec_incus_admin):
            self.assertIn("runner", inspect.signature(fn).parameters,
                          f"{fn.__name__} lost its runner parameter")
        for name in ("run", "_run", "_popen", "_incus", "guest", "guest_sh",
                     "guest_absent"):
            self.assertTrue(hasattr(validate.Harness, name),
                            f"Harness.{name} missing")

    def test_maybe_reexec_probe_routes_through_runner(self):
        runner = FakeRunner()
        validate.maybe_reexec_incus_admin(runner=runner)
        self.assertEqual([c[0] for c in runner.calls], [["incus", "list"]])

    def test_make_config_drive_children_are_named_unreached(self):
        # Pin the UNREACHED enumeration: if make_config_drive stops owning
        # its children, this reds and the header map must be revisited.
        mcd = (_HERE / "make_config_drive.py").read_text()
        self.assertEqual(mcd.count("subprocess.run("), 2)


if __name__ == "__main__":
    unittest.main()
