#!/usr/bin/env python3
"""Regression tests for #12144: bind the flat apt pool to the selected set.

The default dist-deb glob is pinned to Makefile's DEB_VERSION, explicit input
sets are checked against dpkg control identity, and each flat rebuild withdraws
packages omitted from that set. The publish gate cross-checks the signed
Packages index, pool contents, and verified image release versions.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

_DIST = Path(__file__).resolve().parent
_BUILDER = _DIST / "build-apt-repo.sh"
_SPEC = importlib.util.spec_from_file_location("publish_12144", _DIST / "publish.py")
publish = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(publish)

_HAVE_BUILD_TOOLS = bool(shutil.which("apt-ftparchive") and
                         shutil.which("dpkg-deb"))


def _make_deb(path, package, version, keyring=None):
    pkgdir = Path(str(path) + ".pkg")
    debian = pkgdir / "DEBIAN"
    debian.mkdir(parents=True)
    (debian / "control").write_text(
        f"Package: {package}\nVersion: {version}\nArchitecture: amd64\n"
        "Maintainer: t <t@x.invalid>\nDescription: 12144 fixture\n")
    if keyring is not None:
        keydir = pkgdir / "usr/share/keyrings"
        keydir.mkdir(parents=True)
        (keydir / "xpf-archive-keyring.asc").write_text(keyring)
    subprocess.run(["dpkg-deb", "--build", str(pkgdir), str(path)],
                   check=True, capture_output=True, timeout=60)
    return Path(path)


def _run(script, outdir, debs=(), env_extra=None):
    env = dict(os.environ)
    for var in ("XPF_APT_COMPONENT", "XPF_APT_ARCH", "XPF_APT_ORIGIN",
                "XPF_APT_SUITE", "XPF_APT_TOOL", "XPF_GPG_KEY",
                "XPF_APT_VALID_DAYS", "XPF_DEB_VERSION"):
        env.pop(var, None)
    env.update(env_extra or {})
    args = ["sh", str(script), "--out", str(outdir), "--suite", "stable"]
    if debs:
        args.extend(["--debs", *(str(deb) for deb in debs)])
    p = subprocess.run(args, capture_output=True, text=True, env=env,
                       timeout=120)
    return p.returncode, (p.stdout or "") + (p.stderr or "")


@unittest.skipUnless(_HAVE_BUILD_TOOLS,
                     "needs apt-ftparchive + dpkg-deb for real package fixtures")
class AptBindingTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="xpf-apt12144-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.out = self.root / "out"

    def _deb(self, filename, package, version, keyring=None):
        return _make_deb(self.root / filename, package, version, keyring)

    def _packages(self, outdir=None):
        outdir = outdir or self.out
        return (Path(outdir) / "apt/dists/stable/main/binary-amd64/Packages").read_text()

    def test_flat_rebuild_withdraws_omitted_package(self):
        xpf = self._deb("xpf_0.0.1+g1111111_amd64.deb", "xpf", "0.0.1+g1111111")
        appliance = self._deb("xpf-appliance_0.0.1+g1111111_amd64.deb",
                              "xpf-appliance", "0.0.1+g1111111")
        rc, out = _run(_BUILDER, self.out, (xpf, appliance))
        self.assertEqual(rc, 0, out[-800:])
        self.assertIn("Package: xpf-appliance", self._packages())

        rc, out = _run(_BUILDER, self.out, (xpf,))
        self.assertEqual(rc, 0, out[-800:])
        self.assertNotIn("Package: xpf-appliance", self._packages())
        pool = Path(self.out) / "apt/pool/stable/main/x/xpf"
        self.assertEqual({p.name for p in pool.glob("*.deb")}, {xpf.name})

    def test_default_glob_uses_authoritative_version_not_higher_extra(self):
        repo = self.root / "fake-repo"
        script = repo / "scripts/dist/build-apt-repo.sh"
        script.parent.mkdir(parents=True)
        shutil.copyfile(_BUILDER, script)
        debdir = repo / "dist-deb"
        debdir.mkdir(parents=True)
        selected_version = "0.0.1+g1111111"
        for package, prefix in (("xpf", "xpf"), ("xpf-appliance", "xpf-appliance")):
            _make_deb(debdir / f"{prefix}_{selected_version}_amd64.deb",
                      package, selected_version)
        extra = _make_deb(debdir / "xpf_9.9.9+g9999999_amd64.deb",
                          "xpf", "9.9.9+g9999999")

        rc, out = _run(script, self.out, env_extra={
            "XPF_DEB_VERSION": selected_version,
        })
        self.assertEqual(rc, 0, out[-800:])
        packages = self._packages()
        self.assertIn(f"Version: {selected_version}", packages)
        self.assertNotIn("Version: 9.9.9+g9999999", packages)
        pool = Path(self.out) / "apt/pool/stable/main/x/xpf"
        self.assertNotIn(extra.name, {p.name for p in pool.glob("*.deb")})

    def test_default_glob_fails_closed_without_authoritative_version(self):
        repo = self.root / "fake-no-version"
        script = repo / "scripts/dist/build-apt-repo.sh"
        script.parent.mkdir(parents=True)
        shutil.copyfile(_BUILDER, script)
        debdir = repo / "dist-deb"
        debdir.mkdir(parents=True)
        _make_deb(debdir / "xpf_0.0.1+g1111111_amd64.deb",
                  "xpf", "0.0.1+g1111111")
        rc, out = _run(script, self.out)
        self.assertNotEqual(rc, 0)
        self.assertIn("XPF_DEB_VERSION is required", out)
        self.assertFalse((self.out / "apt").exists())

    def test_filename_and_control_version_must_match(self):
        mismatched = self._deb("xpf_0.0.1+g1111111_amd64.deb",
                               "xpf", "0.0.2+g2222222")
        rc, out = _run(_BUILDER, self.out, (mismatched,))
        self.assertNotEqual(rc, 0)
        self.assertIn("package identity mismatch", out)
        pool = self.out / "apt/pool/stable/main/x/xpf"
        self.assertEqual(list(pool.glob("*.deb")), [])

    def test_explicit_debs_ignore_default_version_pin(self):
        version = "0.0.1+g1111111"
        xpf = self._deb(f"xpf_{version}_amd64.deb", "xpf", version)
        rc, out = _run(_BUILDER, self.out, (xpf,), env_extra={
            "XPF_DEB_VERSION": "9.9.9+g9999999",
        })
        self.assertEqual(rc, 0, out[-800:])
        self.assertIn(f"Version: {version}", self._packages())

    def test_explicit_set_rejects_higher_duplicate_package(self):
        version = "0.0.1+g1111111"
        xpf = self._deb(f"xpf_{version}_amd64.deb", "xpf", version)
        extra = self._deb("xpf_9.9.9+g9999999_amd64.deb",
                          "xpf", "9.9.9+g9999999")
        rc, out = _run(_BUILDER, self.out, (xpf, extra))
        self.assertNotEqual(rc, 0)
        self.assertIn("duplicate package identity", out)

    def test_publish_gate_binds_versions_and_rejects_duplicate_identity(self):
        version = "0.0.1+g1111111"
        xpf = self._deb(f"xpf_{version}_amd64.deb", "xpf", version)
        appliance = self._deb(f"xpf-appliance_{version}_amd64.deb",
                              "xpf-appliance", version)
        rc, out = _run(_BUILDER, self.out, (xpf, appliance))
        self.assertEqual(rc, 0, out[-800:])
        release = (self.out / "apt/dists/stable/Release").read_text()
        publish._gate_apt_package_set(self.out, "stable", release, {version})
        with self.assertRaisesRegex(SystemExit, "outside the verified target image version"):
            publish._gate_apt_package_set(self.out, "stable", release,
                                          {"9.9.9+g9999999"})

        pool = self.out / "apt/pool/stable/main/x/xpf"
        altered = _make_deb(self.root / "altered.deb", "xpf", version,
                            keyring="substituted payload")
        shutil.copyfile(altered, pool / f"xpf_{version}_amd64.deb")
        with self.assertRaisesRegex(SystemExit, "Size/SHA256"):
            publish._gate_apt_package_set(self.out, "stable", release, {version})
        shutil.copyfile(xpf, pool / xpf.name)

        extra = self._deb("xpf_9.9.9+g9999999_amd64.deb",
                          "xpf", "9.9.9+g9999999")
        pool = self.out / "apt/pool/stable/main/x/xpf"
        shutil.copyfile(extra, pool / extra.name)
        with self.assertRaisesRegex(SystemExit, "multiple apt versions"):
            publish._gate_apt_package_set(self.out, "stable", release,
                                          {version, "9.9.9+g9999999"})


if __name__ == "__main__":
    unittest.main()
