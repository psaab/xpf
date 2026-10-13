#!/usr/bin/env python3
"""#12158: the packaged xpfd's dirty marker agrees with its package version.

`make deb` rewrites debian/changelog and only then lets dpkg-buildpackage rerun
the Makefile through debian/rules, so the inner `git describe --dirty` default
marked EVERY packaged xpfd `-dirty`. bake.py therefore stripped `-dirty` before
comparing versions, which also discarded a real marker on a clean-labelled
package. The deb recipe now hands the inner build a VERSION whose marker
follows DEB_VERSION (the #12141 shared probe), and bind_deb_identity requires
`-dirty` on xpfd exactly when the package version carries `.dirty`.

The recipe cells run the REAL Makefile `deb` target in a throwaway checkout.
A stand-in dpkg-buildpackage on PATH drives the REAL debian/rules build step
under `make -n` (so the `$(MAKE) build` hop is real), then records xpfd's link
flags and `git describe --dirty` as seen at that moment. Pre-fix, the clean
cell embeds `-dirty` and the bind cells accept mismatched markers.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_HERE = Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent
_SPEC = importlib.util.spec_from_file_location("xpf_bake_12158", _HERE / "bake.py")
bake = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(bake)

# Stand-in for dpkg-buildpackage: it runs where the real one does (the source
# root, after the recipe's changelog rewrite), dry-runs debian/rules' build
# step, and leaves the two packages the recipe copies into dist-deb/.
_FAKE_DPKG_BUILDPACKAGE = r"""#!/bin/sh
set -e
version=$(sed -n '1s/^xpf (\([^)]*\)).*/\1/p' debian/changelog)
{
    echo "changelog_version=$version"
    echo "describe_dirty_now=$(git describe --tags --always --dirty)"
    make -n -f debian/rules override_dh_auto_build
} >"$XPF_12158_CAPTURE" 2>&1
: >"../xpf_${version}_amd64.deb"
: >"../xpf-appliance_${version}_amd64.deb"
"""


def _git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True,
        capture_output=True, text=True).stdout.strip()


def _commit_fixture(root):
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "xpf 12158 test")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "commit.gpgsign", "false")
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "fixture base")


class DebRecipeMarkerTests(unittest.TestCase):
    """The deb recipe hands the inner xpfd build the package's dirty marker."""

    @classmethod
    def setUpClass(cls):
        cache = tempfile.TemporaryDirectory(prefix="xpf-12158-gocache-")
        cls.addClassCleanup(cache.cleanup)
        cls.gocache = cache.name

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="xpf-deb-marker-12158-")
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        # dpkg-buildpackage writes packages to the source PARENT; keep that
        # parent private to the test.
        self.root = base / "src"
        for rel in ("cmd/xpfd", "cmd/cli", "pkg", "debian", "scripts/image"):
            (self.root / rel).mkdir(parents=True)
        (self.root / "go.mod").write_text("module fixture.local/xpf\n\ngo 1.24\n")
        (self.root / "pkg/app.go").write_text("package pkg\nvar Value = 1\n")
        for name in ("xpfd", "cli"):
            (self.root / "cmd" / name / "main.go").write_text(
                'package main\nimport "fixture.local/xpf/pkg"\n'
                "func main() { _ = pkg.Value }\n")
        for rel in (".gitignore", "Makefile", "debian/.gitignore",
                    "debian/rules", "scripts/image/build_provenance.py",
                    "scripts/image/validate-build-metadata.py"):
            shutil.copy2(_ROOT / rel, self.root / rel)
        (self.root / "debian/changelog").write_text(
            "xpf (0.0.0) unstable; urgency=medium\n\n"
            "  * fixture entry\n\n"
            " -- xpf test <test@example.invalid>  "
            "Mon, 12 Oct 2026 00:00:00 +0000\n")
        _commit_fixture(self.root)

        bin_dir = base / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "dpkg-buildpackage"
        fake.write_text(_FAKE_DPKG_BUILDPACKAGE)
        fake.chmod(0o755)
        self.capture = base / "capture.txt"
        self.env = {
            key: value for key, value in os.environ.items()
            if key not in ("VERSION", "MAKEFLAGS", "MFLAGS", "MAKELEVEL")
            and not key.startswith("DEB_")
        }
        self.env.update({
            "PATH": f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "GOENV": "off",
            "GOFLAGS": "",
            "GOWORK": "off",
            "GOCACHE": self.gocache,
            "XPF_12158_CAPTURE": str(self.capture),
        })

    def head_describe(self):
        return _git(self.root, "describe", "--tags", "--always", "HEAD")

    def package_version(self, *, dirty):
        sha = _git(self.root, "rev-parse", "--short=12", "HEAD")
        return f"0.0.1+g{sha}" + (".dirty" if dirty else "")

    def run_deb(self, *make_args, env=None):
        """Run `make deb`; return (changelog version, embedded, describe)."""
        self.capture.unlink(missing_ok=True)
        result = subprocess.run(
            ["make", "--no-print-directory", "-C", str(self.root), "deb",
             *make_args],
            env=self.env if env is None else env,
            capture_output=True, text=True, check=False)
        capture = self.capture.read_text() if self.capture.exists() else ""
        self.assertEqual(
            result.returncode, 0,
            f"make deb failed:\n{result.stdout}\n{result.stderr}\n{capture}")
        fields = dict(
            line.split("=", 1) for line in capture.splitlines()
            if line.startswith(("changelog_version=", "describe_dirty_now=")))
        links = [line for line in capture.splitlines()
                 if "go build -ldflags" in line and "-o xpfd " in line]
        self.assertEqual(len(links), 1, capture)
        embedded = re.search(r"-X main\.version=(\S+) ", links[0])
        self.assertIsNotNone(embedded, links[0])
        package = fields["changelog_version"]
        self.assertTrue(
            (self.root / "dist-deb" / f"xpf_{package}_amd64.deb").is_file())
        return package, embedded.group(1), fields["describe_dirty_now"]

    def test_clean_package_embeds_clean_xpfd_version(self):
        package, embedded, describe_now = self.run_deb()
        self.assertEqual(package, self.package_version(dirty=False))
        # The inner build runs after the changelog rewrite, when Git itself
        # calls the tree dirty, so the old inner default embedded -dirty.
        self.assertEqual(describe_now, self.head_describe() + "-dirty")
        self.assertEqual(embedded, self.head_describe())

    def test_staged_source_edit_marks_package_and_xpfd(self):
        with (self.root / "pkg/app.go").open("a") as source:
            source.write("var Staged = 2\n")
        _git(self.root, "add", "pkg/app.go")
        package, embedded, _ = self.run_deb()
        self.assertEqual(package, self.package_version(dirty=True))
        self.assertEqual(embedded, self.head_describe() + "-dirty")

    def test_untracked_compiled_source_marks_package_and_xpfd(self):
        # `git describe --dirty` ignores untracked files; the shared probe
        # does not, and the embedded marker must follow the probe.
        (self.root / "pkg/new.go").write_text("package pkg\nvar New = 3\n")
        self.assertEqual(
            _git(self.root, "describe", "--tags", "--always", "--dirty"),
            self.head_describe())
        package, embedded, _ = self.run_deb()
        self.assertEqual(package, self.package_version(dirty=True))
        self.assertEqual(embedded, self.head_describe() + "-dirty")

    def test_changelog_edit_marks_package_and_xpfd(self):
        # DEB_VERSION is sampled before the recipe's own version rewrite, so
        # no changelog exclusion exists: a real edit (shipped as
        # /usr/share/doc/xpf/changelog.gz) is dirty source in both markers.
        changelog = self.root / "debian/changelog"
        changelog.write_text(
            changelog.read_text().replace("fixture entry", "local edit"))
        package, embedded, _ = self.run_deb()
        self.assertEqual(package, self.package_version(dirty=True))
        self.assertEqual(embedded, self.head_describe() + "-dirty")

    def test_explicit_version_keeps_make_precedence(self):
        with self.subTest(channel="command line"):
            _, embedded, _ = self.run_deb("VERSION=operator-pin")
            self.assertEqual(embedded, "operator-pin")
        with self.subTest(channel="environment"):
            _, embedded, _ = self.run_deb(env={**self.env, "VERSION": "env-pin"})
            self.assertEqual(embedded, "env-pin")


class BindDirtyMarkerTests(unittest.TestCase):
    """bind_deb_identity requires xpfd -dirty exactly when the package is."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="xpf-bind-marker-12158-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        (self.root / "src.txt").write_text("v1\n")
        _commit_fixture(self.root)
        # bind_deb_identity reads the module-global ROOT at call time.
        patcher = mock.patch.object(bake, "ROOT", str(self.root))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.head = _git(self.root, "rev-parse", "HEAD")
        self.describe = _git(self.root, "describe", "--tags", "--always", "HEAD")
        self.clean_package = "0.0.1+g" + self.head[:12]
        self.dirty_package = self.clean_package + ".dirty"

    def bind(self, package, xpfd_version, *, skip_build):
        output = f"xpfd {xpfd_version} (commit {self.head[:9]}, built test)\n"
        return bake.bind_deb_identity(
            package, output, skip_build=skip_build, head_commit=self.head)

    def test_matching_clean_markers_bind(self):
        for skip_build in (False, True):
            with self.subTest(skip_build=skip_build):
                self.assertEqual(
                    self.bind(self.clean_package, self.describe,
                              skip_build=skip_build),
                    (self.describe, self.head))

    def test_matching_dirty_markers_bind(self):
        # Dirty packages stay bakeable; their .dirty version names the set.
        dirty_describe = self.describe + "-dirty"
        for skip_build in (False, True):
            with self.subTest(skip_build=skip_build):
                self.assertEqual(
                    self.bind(self.dirty_package, dirty_describe,
                              skip_build=skip_build),
                    (dirty_describe, self.head))

    def test_dirty_xpfd_in_clean_package_is_refused(self):
        for skip_build in (False, True):
            with self.subTest(skip_build=skip_build):
                with self.assertRaises(SystemExit) as caught:
                    self.bind(self.clean_package, self.describe + "-dirty",
                              skip_build=skip_build)
                self.assertIn("marks dirty build bytes",
                              str(caught.exception.code))

    def test_dirty_xpfd_refused_when_package_commit_is_not_local(self):
        # --skip-build of a package whose commit is absent locally skips the
        # describe comparison; the marker check must not depend on it.
        with self.assertRaises(SystemExit) as caught:
            bake.bind_deb_identity(
                "0.0.1+gdeadbeefcafe",
                "xpfd release-dirty (commit deadbeefcafe, built test)\n",
                skip_build=True, head_commit="")
        self.assertIn("marks dirty build bytes", str(caught.exception.code))

    def test_clean_xpfd_in_dirty_package_is_refused(self):
        for skip_build in (False, True):
            with self.subTest(skip_build=skip_build):
                with self.assertRaises(SystemExit) as caught:
                    self.bind(self.dirty_package, self.describe,
                              skip_build=skip_build)
                self.assertIn("has no -dirty marker",
                              str(caught.exception.code))


class DebianRulesStagingTests(unittest.TestCase):
    def test_every_xpf_file_staged_by_debian_rules_is_git_ignored(self):
        # An unignored staged copy under debian/ is an untracked package input
        # to the shared probe, so the next build would be marked dirty.
        rules = (_ROOT / "debian" / "rules").read_text().replace("\\\n", " ")
        staged = set(re.findall(
            r"(?:\bcp\s+\S+\s+|>\s*)(debian/xpf\.[\w.-]+)(?=\s|$)", rules))
        self.assertTrue(staged, "no generated debian/xpf.* files in debian/rules")
        for path in sorted(staged):
            result = subprocess.run(
                ["git", "check-ignore", "-q", path],
                cwd=_ROOT, capture_output=True, text=True)
            self.assertEqual(
                result.returncode, 0,
                f"{path} staged by debian/rules is not git-ignored")


if __name__ == "__main__":
    unittest.main()
