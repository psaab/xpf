#!/usr/bin/env python3
"""Unit tests for #9920 (cohort: dist re-sign laundering + loop status + helper pin).

F-063: `make dist-sign` derived its file list from the LIVE manifest and
re-signed whatever it found, laundering a reduced set into a validly-signed
state with no validated/base_image_pinned/guest_kernel assertion. The
sign-manifest CLI is now fail-CLOSED for xpf-*.SHA256SUMS manifests
(sign.assert_bake_set, before any write); the library functions stay
permissive (bake.py and the publish-negative fixtures call them directly).
And publish.gate_images enforces the four-file set at the trust boundary, so
direct-sign, library, and rename bypasses of the basename-scoped CLI gate all
refuse downstream (parent review: publish previously verified listed-only).

F-064: the recipe's status was the LAST iteration's (a failed rotation
reported success, half-signed tree), and sign.py let OSError escape as an
unhandled traceback. The recipe now accumulates failures and names each
(covered behaviorally by selftest.sh section 8l); _main maps OSError to
`ERROR:` + exit 1 (covered here).

F-148: userspace-dp built with whatever cargo resolved to while debian/rules
claimed "pinned cargo". The pin is userspace-dp/rust-toolchain.toml,
enforced explicitly by the Makefile (`$(CARGO) +<pin>` via
build_support/dp-toolchain.sh).

Red-green: every cell below FAILS on base a17a9c67f (same APIs — strictness
absent, traceback escaping, pin files missing) and PASSES post-fix. minisign
gates ONLY the cells that sign/verify (refusals raise before minisign runs,
so they execute on a minimal host too). Each behavioral cell carries its
killing mutation as a `# kill:` comment.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
import sign  # noqa: E402

_ROOT = _HERE.parent.parent
_SPEC = importlib.util.spec_from_file_location(
    "xpf_bake", _ROOT / "scripts" / "image" / "bake.py")
bake = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(bake)
_PSPEC = importlib.util.spec_from_file_location(
    "xpf_publish_9920", _HERE / "publish.py")
publish = importlib.util.module_from_spec(_PSPEC)
assert _PSPEC.loader is not None
_PSPEC.loader.exec_module(publish)

_HAVE_MINISIGN = shutil.which("minisign") is not None
VER = "9.9.20"
KVER = "7.0.0-15-generic"


def _write_set(d, ver=VER, validated=True, base_pinned=True,
               guest_kernel=KVER, omit=(), extra=()):
    """Write an (almost) honest 4-file bake set in `d`; return (files, sums).

    Every default is valid, so each refusal cell varies ONE input (a negative
    satisfiable by the wrong cause stops testing what it names). `omit` drops
    members by basename suffix; `extra` adds bare files by basename.
    """
    paths = {
        ".qcow2": os.path.join(d, f"xpf-{ver}.qcow2"),
        ".meta": os.path.join(d, f"xpf-{ver}.incus-metadata.tar.gz"),
        ".manifest": os.path.join(d, f"xpf-{ver}.manifest"),
        ".pkgs": os.path.join(d, f"xpf-{ver}.pkgs"),
    }
    Path(paths[".qcow2"]).write_text(f"qcow-{ver}\n")
    Path(paths[".meta"]).write_text(f"meta-{ver}\n")
    sidecar = (f"version: {ver}\n"
               f"base_image_pinned: {'true' if base_pinned else 'false'}\n"
               f"validated: {'true' if validated else 'false'}\n")
    if guest_kernel is not None:
        sidecar += f"guest_kernel: {guest_kernel}\n"
    Path(paths[".manifest"]).write_text(sidecar)
    pkgs = ["# xpf appliance image inventory",
            f"guest_kernel: {guest_kernel or KVER}", "packages:"]
    pkgs += [f"pkg{i}=1.0-{i}" for i in range(60)]
    Path(paths[".pkgs"]).write_text("\n".join(pkgs) + "\n")
    files = [p for k, p in paths.items()
             if not any(p.endswith(s) for s in omit)]
    for name in extra:
        p = os.path.join(d, name)
        Path(p).write_text("extra\n")
        files.append(p)
    return files, os.path.join(d, f"xpf-{ver}.SHA256SUMS")


def _run_main(argv):
    """Run sign._main capturing stderr; return (rc, stderr)."""
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        rc = sign._main(argv)
    return rc, buf.getvalue()


def _freeze(path, content=b"old-bytes\n"):
    """Write `content` + pin mtime; return (content, mtime) for later compare."""
    Path(path).write_bytes(content)
    os.utime(path, (1000000000, 1000000000))
    return content, 1000000000


class StrictSignManifestTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-9920-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    @unittest.skipUnless(_HAVE_MINISIGN, "minisign not installed")
    def test_honest_set_signs_and_verifies(self):
        # kill: any refusal leg that fires on a conforming set.
        sec = os.path.join(self.dir, "img.sec")
        pub = os.path.join(self.dir, "img.pub")
        subprocess.run(["minisign", "-G", "-W", "-p", pub, "-s", sec],
                       check=True, capture_output=True)
        files, sums = _write_set(self.dir)
        rc, err = _run_main(["sign-manifest", "--manifest", sums,
                             "--seckey", sec] + files)
        self.assertEqual(rc, 0, err)
        r = subprocess.run(["minisign", "-V", "-p", pub, "-m", sums,
                            "-x", sums + ".minisig"], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr.decode())

    def test_ssot_members_are_the_bake_four(self):
        # kill: rename/add/drop a template without updating bake.
        self.assertEqual(sign.BAKE_SET_TEMPLATES, (
            "xpf-{ver}.qcow2",
            "xpf-{ver}.incus-metadata.tar.gz",
            "xpf-{ver}.manifest",
            "xpf-{ver}.pkgs",
        ))
        self.assertEqual(sign.bake_set_basenames("1.2.3"), [
            "xpf-1.2.3.qcow2", "xpf-1.2.3.incus-metadata.tar.gz",
            "xpf-1.2.3.manifest", "xpf-1.2.3.pkgs"])

    def test_reduced_set_refused_library_leaves_bytes_identical(self):
        # kill: drop the set-equality check in assert_bake_set.
        files, sums = _write_set(self.dir, omit=(".pkgs",))
        old_sums, sums_mtime = _freeze(sums, b"live-manifest-bytes\n")
        old_sig, sig_mtime = _freeze(sums + ".minisig", b"old-sig-bytes\n")
        with self.assertRaises(sign.SignError) as ctx:
            sign.assert_bake_set(sums, files)
        self.assertIn("four-file set", str(ctx.exception))
        self.assertEqual(Path(sums).read_bytes(), old_sums)
        self.assertEqual(os.stat(sums).st_mtime, sums_mtime)
        self.assertEqual(Path(sums + ".minisig").read_bytes(), old_sig)
        self.assertEqual(os.stat(sums + ".minisig").st_mtime, sig_mtime)

    def test_reduced_set_refused_cli(self):
        # kill: drop the is_bake_manifest gate call in _main.
        files, sums = _write_set(self.dir, omit=(".pkgs",))
        old_sums, _ = _freeze(sums, b"live-manifest-bytes\n")
        rc, err = _run_main(["sign-manifest", "--manifest", sums,
                             "--seckey", "/nonexistent.sec"] + files)
        self.assertEqual(rc, 1)
        self.assertTrue(err.startswith("ERROR:"), err)
        self.assertIn("four-file set", err)
        self.assertNotIn("Traceback", err)
        self.assertEqual(Path(sums).read_bytes(), old_sums)
        self.assertFalse(os.path.exists(sums + ".minisig"))

    def test_sign_failure_leaves_live_files_identical(self):
        # kill: write-then-sign in place instead of temp+rename (#10119).
        # The gate PASSES (honest set); minisign then fails on the bogus key —
        # and neither the live manifest nor the live .minisig may change.
        files, sums = _write_set(self.dir)
        old_sums, sums_mtime = _freeze(sums, b"stale-live-manifest-bytes\n")
        old_sig, sig_mtime = _freeze(sums + ".minisig", b"stale-sig-bytes\n")
        rc, err = _run_main(["sign-manifest", "--manifest", sums,
                             "--seckey", "/nonexistent.sec"] + files)
        self.assertEqual(rc, 1)
        self.assertTrue(err.startswith("ERROR:"), err)
        self.assertNotIn("Traceback", err)
        self.assertEqual(Path(sums).read_bytes(), old_sums)
        self.assertEqual(os.stat(sums).st_mtime, sums_mtime)
        self.assertEqual(Path(sums + ".minisig").read_bytes(), old_sig)
        self.assertEqual(os.stat(sums + ".minisig").st_mtime, sig_mtime)

    def test_extra_file_refused(self):
        # kill: compare with subset instead of equality.
        files, sums = _write_set(self.dir, extra=("xpf-9.9.20.extra",))
        with self.assertRaises(sign.SignError) as ctx:
            sign.assert_bake_set(sums, files)
        self.assertIn("four-file set", str(ctx.exception))

    def test_validated_false_refused(self):
        # kill: drop the validated leg.
        files, sums = _write_set(self.dir, validated=False)
        with self.assertRaises(sign.SignError) as ctx:
            sign.assert_bake_set(sums, files)
        self.assertIn("validated=", str(ctx.exception))

    def test_base_pinned_false_refused(self):
        # kill: drop the base_image_pinned leg.
        files, sums = _write_set(self.dir, base_pinned=False)
        with self.assertRaises(sign.SignError) as ctx:
            sign.assert_bake_set(sums, files)
        self.assertIn("base_image_pinned=", str(ctx.exception))

    def test_missing_guest_kernel_refused(self):
        # kill: drop the guest_kernel leg.
        files, sums = _write_set(self.dir, guest_kernel=None)
        with self.assertRaises(sign.SignError) as ctx:
            sign.assert_bake_set(sums, files)
        self.assertIn("guest_kernel", str(ctx.exception))

    def test_scattered_set_refused(self):
        # kill: drop the sibling-directory check.
        files, sums = _write_set(self.dir, omit=(".pkgs",))
        other = os.path.join(self.dir, "elsewhere")
        os.mkdir(other)
        stray = os.path.join(other, f"xpf-{VER}.pkgs")
        shutil.copy(os.path.join(self.dir, f"xpf-{VER}.pkgs"), stray)
        files.append(stray)
        with self.assertRaises(sign.SignError) as ctx:
            sign.assert_bake_set(sums, files)
        self.assertIn("not beside the manifest", str(ctx.exception))

    def test_dotdot_version_refused(self):
        # kill: skip validate_version on the derived ver.
        sums = os.path.join(self.dir, "xpf-...SHA256SUMS")
        with self.assertRaises(sign.SignError) as ctx:
            sign.assert_bake_set(sums, [])
        self.assertIn("safe version", str(ctx.exception))

    def test_leading_dash_version_refused(self):
        # kill: skip validate_version on the derived ver.
        sums = os.path.join(self.dir, "xpf--1.2.3.SHA256SUMS")
        with self.assertRaises(sign.SignError) as ctx:
            sign.assert_bake_set(sums, [])
        self.assertIn("must not start with", str(ctx.exception))

    def test_is_bake_manifest_scoping(self):
        # kill: broaden/narrow the gate predicate.
        self.assertTrue(sign.is_bake_manifest("dist/xpf-1.2.3.SHA256SUMS"))
        self.assertTrue(sign.is_bake_manifest("xpf-0.0.0-selftest.SHA256SUMS"))
        for other in ("scratch.SHA256SUMS", "xpf-1.2.3.qcow2", "SHA256SUMS",
                      "xpf-1.2.3.SHA256SUMS.minisig", "xpf-.txt"):
            self.assertFalse(sign.is_bake_manifest(other), other)

    @unittest.skipUnless(_HAVE_MINISIGN, "minisign not installed")
    def test_non_bake_basename_stays_permissive(self):
        # kill: apply the gate to every manifest name. Pins the adjudicated
        # scoping: only publish-discovered names are gated.
        sec = os.path.join(self.dir, "img.sec")
        pub = os.path.join(self.dir, "img.pub")
        subprocess.run(["minisign", "-G", "-W", "-p", pub, "-s", sec],
                       check=True, capture_output=True)
        lone = os.path.join(self.dir, "lone.bin")
        Path(lone).write_text("lone\n")
        sums = os.path.join(self.dir, "scratch.SHA256SUMS")
        rc, err = _run_main(["sign-manifest", "--manifest", sums,
                             "--seckey", sec, lone])
        self.assertEqual(rc, 0, err)

    def test_version_parity_with_bake(self):
        # kill: widen/narrow sign's charset vs bake's (#5992 mirror idiom).
        bad = ["../../../../etc/cron.d/x", "1.0/../x", "..", ".", "a/b",
               "a\\b", "/abs/1.2.3", "-rf", ".hidden", "1.0%n", "1.0 2.0",
               "a;rm -rf /", "a$(whoami)", "1:2.3.4", ""]
        good = ["1.2.3", "1.2.3-5-gabcdef", "1.2.3-dirty", "1.0.0+build.7",
                "1.0.0~rc1", "v1.2.3", "dev", "0.9.0+deb1", "9.9.20",
                "8l-broken"]
        for v in bad + good:
            try:
                bake.validate_version(v, "--version")
                bake_ok = True
            except SystemExit:
                bake_ok = False
            try:
                sign.validate_version(v, "--version")
                sign_ok = True
            except sign.SignError:
                sign_ok = False
            self.assertEqual(sign_ok, bake_ok,
                             f"sign vs bake disagree on {v!r}")


class OSErrorHandlingTests(unittest.TestCase):
    """F-064: missing/unreadable inputs fail as ERROR, not traceback."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-9920-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def _assert_error_not_traceback(self, argv):
        # FAIL-form: on base _main RAISES (traceback to the caller), so a bare
        # _run_main call would ERROR instead of FAIL. try/except + fail keeps
        # the cell FAIL-on-base.
        buf = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf):
                rc = sign._main(argv)
        except Exception as e:  # noqa: BLE001 — the assertion IS no-raise
            self.fail(f"_main raised {type(e).__name__}: {e}")
        err = buf.getvalue()
        self.assertEqual(rc, 1)
        self.assertTrue(err.startswith("ERROR:"), err)
        self.assertNotIn("Traceback", err)
        return err

    def test_missing_file_is_error_not_traceback(self):
        # kill: drop the OSError handler in _main.
        sums = os.path.join(self.dir, "scratch.SHA256SUMS")
        err = self._assert_error_not_traceback(
            ["sign-manifest", "--manifest", sums,
             "--seckey", "/nonexistent.sec", "/nonexistent-file-xyz"])
        self.assertIn("nonexistent-file-xyz", err)

    def test_missing_artifact_in_bake_set_is_error(self):
        # kill: drop the OSError handler in _main. Strict checks pass (the set
        # is NAMED right); the hash read then fails on the deleted file.
        files, sums = _write_set(self.dir)
        os.remove(os.path.join(self.dir, f"xpf-{VER}.qcow2"))
        err = self._assert_error_not_traceback(
            ["sign-manifest", "--manifest", sums,
             "--seckey", "/nonexistent.sec"] + files)
        self.assertIn(f"xpf-{VER}.qcow2", err)


@unittest.skipUnless(_HAVE_MINISIGN, "minisign not installed")
class PublishCompletenessTests(unittest.TestCase):
    """Parent review: gate_images enforces the four-file set, closing the
    direct-sign, library, and rename bypasses of the basename-scoped CLI gate
    (publish previously verified listed files only, and the orphan sweep only
    fires for files PRESENT but uncovered — a manifest that OMITS qcow2 or the
    metadata tarball published a partial set)."""

    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="xpf-9920-pub-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        # Keys live OUTSIDE dist: the default-deny sweep refuses stray files.
        self.keys = tempfile.mkdtemp(prefix="xpf-9920-keys-")
        self.addCleanup(shutil.rmtree, self.keys, ignore_errors=True)
        self.pub = os.path.join(self.keys, "img.pub")
        self.sec = os.path.join(self.keys, "img.sec")
        subprocess.run(["minisign", "-G", "-W", "-p", self.pub,
                        "-s", self.sec],
                       check=True, capture_output=True)
        self._old_env = os.environ.get("XPF_IMAGE_PUBKEY")
        os.environ["XPF_IMAGE_PUBKEY"] = self.pub
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        if self._old_env is None:
            os.environ.pop("XPF_IMAGE_PUBKEY", None)
        else:
            os.environ["XPF_IMAGE_PUBKEY"] = self._old_env

    def _signed_dist(self, omit=()):
        """Genuinely-signed dist: 4-file set minus `omit` (disk AND manifest).

        Signed via the LOW-LEVEL library — the bypass spelling the CLI gate
        cannot see — proving the publish boundary holds regardless of how the
        signature was produced."""
        files, sums = _write_set(self.dir, omit=omit)
        sign.write_manifest(sums, files)
        sign.sign_manifest(sums, self.sec, comment="9920-pubtest")
        return sums

    def _refused(self, needle, needle2=None):
        with self.assertRaises(SystemExit) as ctx:
            publish.gate_images(self.dir, require_installer=False)
        self.assertNotEqual(ctx.exception.code, 0)
        self.assertIn(needle, str(ctx.exception.code))
        if needle2:
            self.assertIn(needle2, str(ctx.exception.code))

    def test_missing_qcow2_refused(self):
        # kill: drop the set(checks)==SSOT check in gate_images.
        self._signed_dist(omit=(".qcow2",))
        self._refused("four-file set", f"xpf-{VER}.qcow2")

    def test_missing_metadata_refused(self):
        # kill: drop the set(checks)==SSOT check in gate_images.
        self._signed_dist(omit=("incus-metadata.tar.gz",))
        self._refused("four-file set", "incus-metadata")

    def test_complete_set_passes_images_gate(self):
        # kill: any over-strict membership comparison (e.g. order-sensitive).
        self._signed_dist()
        versions, _pub = publish.gate_images(self.dir,
                                             require_installer=False)
        self.assertIn(VER, versions)


class HelperPinTests(unittest.TestCase):
    """F-148: the helper toolchain pin exists, parses strictly, and is enforced."""

    def test_toolchain_toml_pins_exact_version(self):
        # kill: delete the pin file or float the channel.
        toml_path = _ROOT / "userspace-dp" / "rust-toolchain.toml"
        self.assertTrue(toml_path.is_file(),
                        "userspace-dp/rust-toolchain.toml is missing")
        with open(toml_path, "rb") as f:
            data = tomllib.load(f)
        channel = data["toolchain"]["channel"]
        self.assertRegex(channel, r"\A\d+\.\d+\.\d+\Z")

    def _script(self, toml_text=None, cargo=None):
        script = (_ROOT / "userspace-dp" / "build_support"
                  / "dp-toolchain.sh")
        if toml_text is None:
            toml = str(_ROOT / "userspace-dp" / "rust-toolchain.toml")
        else:
            d = tempfile.mkdtemp(prefix="xpf-9920-toml-")
            self.addCleanup(shutil.rmtree, d, ignore_errors=True)
            toml = os.path.join(d, "rust-toolchain.toml")
            Path(toml).write_text(toml_text)
        argv = ["sh", str(script), toml] + ([cargo] if cargo else [])
        return subprocess.run(argv, capture_output=True, text=True)

    def test_pin_script_prints_pin_for_good_toml(self):
        # kill: break the happy path (wrong table scope, bad print).
        r = self._script()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertRegex(r.stdout.strip(), r"\A\d+\.\d+\.\d+\Z")

    def test_pin_script_tolerates_trailing_comments(self):
        # kill: anchor the section match at line end (valid TOML refused).
        r = self._script('[toolchain] # trailing comment\n'
                         'channel = "1.2.3" # pinned\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "1.2.3")

    def test_pin_script_rejects_interior_whitespace(self):
        # kill: strip-all-whitespace normalization ("1.98 .1" -> 1.98.1).
        r = self._script('[toolchain]\nchannel = "1.98 .1"\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("X.Y.Z", r.stderr)

    def test_pin_script_rejects_unquoted_channel(self):
        # kill: accept bare values (invalid TOML — strings must be quoted).
        r = self._script('[toolchain]\nchannel = 1.2.3\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("X.Y.Z", r.stderr)

    def test_pin_script_rejects_unpinned_channel(self):
        # kill: accept any channel string (e.g. "stable" floats).
        r = self._script('[toolchain]\nchannel = "stable"\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("X.Y.Z", r.stderr)

    def test_pin_script_rejects_wrong_table_channel(self):
        # kill: match channel outside [toolchain].
        r = self._script('[other]\nchannel = "1.2.3"\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("exactly one", r.stderr)

    def test_pin_script_rejects_duplicate_channel(self):
        # kill: silently take the first of two channels.
        r = self._script('[toolchain]\nchannel = "1.2.3"\n'
                         'channel = "1.2.4"\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("exactly one", r.stderr)

    def test_pin_script_rejects_missing_file(self):
        # kill: default to unpinned when the SSOT is absent.
        script = (_ROOT / "userspace-dp" / "build_support"
                  / "dp-toolchain.sh")
        r = subprocess.run(["sh", str(script), "/nonexistent.toml"],
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("missing", r.stderr)

    def test_pin_script_verifies_cargo_toolchain(self):
        # kill: skip the cargo usability check (non-rustup cargo then fails
        # cryptically mid-build instead of loudly here).
        d = tempfile.mkdtemp(prefix="xpf-9920-cargo-")
        self.addCleanup(shutil.rmtree, d, ignore_errors=True)
        good = os.path.join(d, "cargo-good")
        Path(good).write_text("#!/bin/sh\nexit 0\n")
        os.chmod(good, 0o755)
        r = self._script(cargo=good)
        self.assertEqual(r.returncode, 0, r.stderr)
        bad = os.path.join(d, "cargo-bad")
        Path(bad).write_text("#!/bin/sh\nexit 1\n")
        os.chmod(bad, 0o755)
        r = self._script(cargo=bad)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not usable", r.stderr)

    def test_all_cargo_recipes_use_pinned_toolchain(self):
        # kill: drop +$$pinned from any of the five cargo lines (or add a
        # sixth unpinned cargo run to these recipes).
        text = (_ROOT / "Makefile").read_text()
        in_recipe = False
        cargo_lines = []
        for line in text.splitlines():
            if re.match(r"^(build-userspace-dp|build-userspace-dp-debug-log"
                        r"|test-rust):", line):
                in_recipe = True
                continue
            if in_recipe and line and not line[0].isspace() \
                    and not line.startswith("#"):
                in_recipe = False
            if in_recipe and line.startswith("\t") and "$(CARGO)" in line:
                cargo_lines.append(line)
        self.assertEqual(len(cargo_lines), 5,
                         f"expected 5 cargo lines, found {len(cargo_lines)}: "
                         f"{cargo_lines}")
        for line in cargo_lines:
            self.assertIn("+$$pinned", line)

    def test_debian_rules_names_pin_file(self):
        # Tripwire only (comment text, weakest cell by design): the claim must
        # name its mechanism so a reader can verify it.
        text = (_ROOT / "debian" / "rules").read_text()
        self.assertIn("userspace-dp/rust-toolchain.toml", text)


if __name__ == "__main__":
    unittest.main()
