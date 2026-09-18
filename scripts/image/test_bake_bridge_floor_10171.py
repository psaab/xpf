#!/usr/bin/env python3
"""Fail-on-revert for #10171: assert the bridge nf_tables kernel floor.

Follow-up from the #10164 review (Rev10164, non-blocking). The
xpf-transit-closed boot unit degrades to exit-0-with-warning when the bridge
nftables family is unsupported but inet installs (the daemon's #7191
warn-and-proceed tolerance). Appliance kernels (CONFIG_BRIDGE=m +
CONFIG_NF_TABLES_BRIDGE=m with autoload) always provide the family, so the
degraded branch fires only on foreign/trimmed kernels. #10171 asks that the
floor be asserted explicitly rather than passed silently on an unexpected
kernel; the chosen form is a bake-time check on the target kernel plus a
live-boot mirror in validate.py scenario A. The #7191 warn-and-proceed
default is unchanged — this file pins the floor assert, not the degraded
branch.

What is pinned here:

* `bake.bridge_floor_offline_snippet()` exists, names both kconfig symbols,
  reports violations as FATAL naming #10171, discovers the target kernel
  from the target root's /lib/modules (NEVER `uname -r`: virt-customize
  runs on the BUILD host kernel), and is spliced into the virt-customize
  argv AFTER the single-kernel assert (so "newest" is unambiguous).
* `validate.bridge_floor_live_snippet()` exists, names both symbols, and
  defaults to the RUNNING kernel (`uname -r`); scenario A runs it and
  fails the gate with the snippet's own FATAL line on violation.
* BEHAVIOUR, not just strings: the exact helper-returned snippets are
  executed via `sh -c` against fixture target roots (appliance-like,
  =y built-in, trimmed, missing-config, and a CONFIG_BRIDGE_NETFILTER
  distractor proving the grep anchors) and against the live host
  (appliance kernels unaffected).

Hermetic except for the live-host cells, which SKIP when the running
kernel has no /boot/config (a foreign host proves nothing either way).
On revert (drop a helper, the splice, or a symbol) these go RED.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load(name):
    spec = importlib.util.spec_from_file_location(name, HERE / f"{name}.py")
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


bake = _load("bake")
validate = _load("validate")

SYMBOLS = ("CONFIG_BRIDGE", "CONFIG_NF_TABLES_BRIDGE")
KV_FIX = "9.9.9-10171-test"


def _run_snippet(snippet, root, kver=None):
    """Execute a floor snippet against a fixture root; return CompletedProcess."""
    env = dict(os.environ)
    env["XPF_FLOOR_ROOT"] = str(root)
    if kver is not None:
        env["XPF_FLOOR_KVER"] = kver
    else:
        env.pop("XPF_FLOOR_KVER", None)
    return subprocess.run(
        ["sh", "-c", snippet], capture_output=True, text=True, env=env
    )


def _write_tree(root, config_text=None):
    """Build a fixture target root: single kernel dir + optional config."""
    mods = root / "lib" / "modules" / KV_FIX
    mods.mkdir(parents=True)
    if config_text is not None:
        boot = root / "boot"
        boot.mkdir(parents=True, exist_ok=True)
        (boot / f"config-{KV_FIX}").write_text(config_text)


APPLIANCE_CONFIG = (
    "# fixture: appliance-like deb14 kconfig\n"
    "CONFIG_BRIDGE=m\n"
    "CONFIG_BRIDGE_NETFILTER=m\n"
    "CONFIG_NF_TABLES_BRIDGE=m\n"
    "CONFIG_NFT_BRIDGE_META=m\n"
)

BUILTIN_CONFIG = (
    "CONFIG_BRIDGE=y\n"
    "CONFIG_NF_TABLES_BRIDGE=y\n"
)

TRIMMED_CONFIG = (
    "# fixture: trimmed kernel without bridge nf_tables\n"
    "CONFIG_BRIDGE=m\n"
    "# CONFIG_NF_TABLES_BRIDGE is not set\n"
)

# Proves the grep anchors: CONFIG_BRIDGE_NETFILTER=m must NOT satisfy the
# CONFIG_BRIDGE check (it has `_`, not `=`, after BRIDGE), and the bridge
# family symbol is absent entirely.
DISTRACTOR_CONFIG = (
    "CONFIG_BRIDGE_NETFILTER=m\n"
    "CONFIG_NFT_BRIDGE_META=m\n"
)


class BakeWiringTests(unittest.TestCase):
    def test_offline_helper_names_the_floor(self):
        snippet = bake.bridge_floor_offline_snippet()
        for sym in SYMBOLS:
            self.assertIn(
                sym, snippet,
                f"offline snippet must name {sym} — the #10171 floor is "
                "exactly CONFIG_BRIDGE + CONFIG_NF_TABLES_BRIDGE.",
            )
        self.assertIn("FATAL", snippet)
        self.assertIn("#10171", snippet)

    def test_offline_helper_never_uses_uname(self):
        # virt-customize runs on the BUILD host kernel; `uname -r` there is
        # the wrong kernel. The target kernel comes from the target root.
        self.assertNotIn(
            "uname -r", bake.bridge_floor_offline_snippet(),
            "offline snippet must discover the TARGET kernel from "
            "the target root's /lib/modules, never `uname -r` (build host).",
        )
        # Fixture overrides are opt-in only; the production bake path must
        # not become bypassable through its environment.
        snippet = bake.bridge_floor_offline_snippet()
        self.assertNotIn("XPF_FLOOR_ROOT", snippet)
        self.assertNotIn("XPF_FLOOR_KVER", snippet)

    def test_bake_splices_check_after_single_kernel_assert(self):
        src = (HERE / "bake.py").read_text()
        splice = src.find("bridge_floor_offline_snippet()")
        self.assertNotEqual(
            splice, -1, "bake.py must splice bridge_floor_offline_snippet() "
            "into the virt-customize argv.")
        # The single-kernel hard assert makes "newest in /lib/modules"
        # unambiguous; the floor check must run after it.
        anchor = src.find("kernels in /lib/modules after purge")
        self.assertNotEqual(anchor, -1, "single-kernel assert anchor moved?")
        self.assertGreater(
            splice, anchor,
            "bridge floor check must run AFTER the single-kernel assert so "
            "it examines the surviving kernel.",
        )


class ValidateWiringTests(unittest.TestCase):
    def test_live_helper_names_the_floor(self):
        snippet = validate.bridge_floor_live_snippet()
        for sym in SYMBOLS:
            self.assertIn(sym, snippet)
        self.assertIn("FATAL", snippet)
        self.assertIn("#10171", snippet)

    def test_live_helper_defaults_to_running_kernel(self):
        # The live mirror asserts the RUNNING kernel (the offline check
        # asserted the SHIPPED one); fixture overrides are opt-in only.
        snippet = validate.bridge_floor_live_snippet()
        self.assertIn("uname -r", snippet)
        self.assertNotIn("XPF_FLOOR_KVER", snippet)
        self.assertNotIn("XPF_FLOOR_ROOT", snippet)

    def test_scenario_a_runs_live_check_and_fails_loud(self):
        src = (HERE / "validate.py").read_text()
        self.assertIn(
            "bridge_floor_live_snippet()", src,
            "validate.py scenario A must run bridge_floor_live_snippet().")


class SnippetBehaviorTests(unittest.TestCase):
    def setUp(self):
        if shutil.which("sh") is None:
            self.skipTest("no sh interpreter")
        tmp = os.environ.get("TMPDIR", "/tmp")
        self.work = Path(tmp) / f"xpf-10171-{os.getpid()}"
        self.work.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)

    def _snippets(self):
        return {
            "offline": bake.bridge_floor_offline_snippet(test_seams=True),
            "live": validate.bridge_floor_live_snippet(test_seams=True),
        }

    def test_appliance_config_passes_both_snippets(self):
        root = self.work / "appliance"
        _write_tree(root, APPLIANCE_CONFIG)
        for name, snippet in self._snippets().items():
            with self.subTest(snippet=name):
                proc = _run_snippet(snippet, root, KV_FIX)
                self.assertEqual(
                    proc.returncode, 0,
                    f"{name}: appliance-like config must pass "
                    f"(stderr={proc.stderr!r})",
                )

    def test_builtin_y_config_passes(self):
        root = self.work / "builtin"
        _write_tree(root, BUILTIN_CONFIG)
        for name, snippet in self._snippets().items():
            with self.subTest(snippet=name):
                proc = _run_snippet(snippet, root, KV_FIX)
                self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_trimmed_config_fails_naming_symbol(self):
        root = self.work / "trimmed"
        _write_tree(root, TRIMMED_CONFIG)
        for name, snippet in self._snippets().items():
            with self.subTest(snippet=name):
                proc = _run_snippet(snippet, root, KV_FIX)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("FATAL", proc.stderr)
                self.assertIn("CONFIG_NF_TABLES_BRIDGE", proc.stderr)

    def test_missing_config_fails_fatal(self):
        root = self.work / "noconfig"
        _write_tree(root, None)
        for name, snippet in self._snippets().items():
            with self.subTest(snippet=name):
                proc = _run_snippet(snippet, root, KV_FIX)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn("FATAL", proc.stderr)

    def test_netfilter_distractor_does_not_satisfy_bridge(self):
        root = self.work / "distractor"
        _write_tree(root, DISTRACTOR_CONFIG)
        for name, snippet in self._snippets().items():
            with self.subTest(snippet=name):
                proc = _run_snippet(snippet, root, KV_FIX)
                self.assertNotEqual(
                    proc.returncode, 0,
                    f"{name}: CONFIG_BRIDGE_NETFILTER must not satisfy the "
                    "CONFIG_BRIDGE check.",
                )
                self.assertIn("FATAL", proc.stderr)

    def test_offline_discovers_kver_from_target_root(self):
        # No XPF_FLOOR_KVER override: the offline snippet must find the
        # single kernel in the TARGET root's /lib/modules on its own.
        root = self.work / "discover"
        _write_tree(root, APPLIANCE_CONFIG)
        proc = _run_snippet(
            bake.bridge_floor_offline_snippet(test_seams=True), root
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_live_host_kernel_meets_floor(self):
        # Appliance-unaffected proof on a real deb14 kernel: the live
        # snippet with no overrides must pass where the config exists.
        kver = os.uname().release
        if not Path(f"/boot/config-{kver}").is_file():
            self.skipTest(f"no /boot/config-{kver} on this host")
        proc = subprocess.run(
            ["sh", "-c", validate.bridge_floor_live_snippet()],
            capture_output=True, text=True,
        )
        self.assertEqual(
            proc.returncode, 0,
            f"live host kernel {kver} must meet the floor: {proc.stderr!r}",
        )


if __name__ == "__main__":
    unittest.main()
