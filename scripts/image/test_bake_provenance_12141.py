#!/usr/bin/env python3
"""#12141/#12158: package and bake identities cover the complete build input."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent
_SPEC = importlib.util.spec_from_file_location("xpf_bake_provenance", _HERE / "bake.py")
bake = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(bake)


class BuildProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="xpf-provenance-12141-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "cmd/xpfd").mkdir(parents=True)
        (self.root / "cmd/cli").mkdir(parents=True)
        (self.root / "pkg/dataplane").mkdir(parents=True)
        (self.root / "scripts/image").mkdir(parents=True)
        (self.root / "docs").mkdir()
        (self.root / "debian").mkdir()
        (self.root / "go.mod").write_text("module fixture.local/xpf\n\ngo 1.24\n")
        (self.root / ".gitignore").write_bytes(
            (_REPO / ".gitignore").read_bytes() + b"\n/pkg/generated/\n")
        (self.root / "debian/.gitignore").write_bytes(
            (_REPO / "debian/.gitignore").read_bytes())
        (self.root / "pkg/app.go").write_text(
            'package pkg\nimport _ "fixture.local/xpf/pkg/dataplane"\nvar Value = 1\n')
        (self.root / "pkg/dataplane/base.go").write_text(
            "package dataplane\nvar Base = 1\n")
        (self.root / "cmd/xpfd/main.go").write_text(
            'package main\nimport "fixture.local/xpf/pkg"\nfunc main() { _ = pkg.Value }\n')
        (self.root / "cmd/cli/main.go").write_text(
            'package main\nimport "fixture.local/xpf/pkg"\nfunc main() { _ = pkg.Value }\n')
        (self.root / "scripts/image/build_provenance.py").write_bytes(
            (_HERE / "build_provenance.py").read_bytes())
        makefile = (_REPO / "Makefile").read_text(encoding="utf-8")
        makefile += (
            "\n.PHONY: provenance-test-dirty\n"
            "provenance-test-dirty:\n"
            "\t@printf '%s' '$(DEB_GIT_DIRTY)'\n"
        )
        (self.root / "Makefile").write_text(makefile)
        self.git("init", "-q")
        self.git("config", "user.name", "Provenance Test")
        self.git("config", "user.email", "provenance@example.invalid")
        self.git("add", ".")
        self.git("commit", "-qm", "fixture base")

    def git(self, *args, check=True):
        return subprocess.run(
            ["git", "-C", str(self.root), *args], check=check,
            capture_output=True, text=True)

    def probe_env(self):
        return {
            **os.environ,
            "GOFLAGS": "",
            "GOWORK": "off",
            "GOCACHE": str(self.root / ".gocache"),
        }

    def make_suffix(self):
        return subprocess.check_output(
            ["make", "-s", "--no-print-directory", "-C", str(self.root),
             "provenance-test-dirty"], text=True, env=self.probe_env())

    def make_test_deb(self, version):
        package_tmp = tempfile.TemporaryDirectory(prefix="xpf-deb-fixture-")
        self.addCleanup(package_tmp.cleanup)
        package = Path(package_tmp.name)
        control = package / "DEBIAN"
        control.mkdir()
        control.chmod(0o755)
        commit = self.git("rev-parse", "HEAD").stdout.strip()
        describe = self.git("describe", "--tags", "--always", "HEAD").stdout.strip()
        staged = package / "usr/local/share/xpf/staged"
        staged.mkdir(parents=True)
        xpfd = staged / "xpfd"
        xpfd.write_text(
            f"#!/bin/sh\necho 'xpfd {describe} (commit {commit[:7]}, built fixture)'\n")
        xpfd.chmod(0o755)
        (control / "control").write_text(
            f"Package: xpf\nVersion: {version}\nArchitecture: amd64\n"
            "Maintainer: fixture\nDescription: fixture package\n")
        deb_dir = self.root / "dist-deb"
        deb_dir.mkdir(exist_ok=True)
        deb = deb_dir / f"xpf_{version}_amd64.deb"
        subprocess.run(["dpkg-deb", "-b", str(package), str(deb)],
                       check=True, capture_output=True)
        return deb

    def run_bake_main(self, argv, *, mutate_on_build=False):
        root = self.root
        here = root / "scripts/image"
        copied = []

        def fake_run(command, **kwargs):
            if command[0] == "dpkg-deb":
                return subprocess.run(command, check=True, **kwargs)
            if command[0] == "make":
                if mutate_on_build:
                    with (root / "pkg/app.go").open("a") as source:
                        source.write("\nvar BuildMutation = 12141\n")
                return subprocess.CompletedProcess(command, 0)
            if command[0] == "qemu-img":
                Path(command[-2]).write_bytes(b"work disk")
            elif command[0] == "virt-resize":
                Path(command[-1]).write_bytes(b"resized disk")
            elif command[0] == "virt-customize":
                copied.extend(command)
            elif command[0] == "virt-sparsify":
                Path(command[-1]).write_bytes(b"qcow data")
            elif command[0] == "tar":
                return subprocess.run(command, check=True, **kwargs)
            elif command[0] != "virt-sysprep":
                raise AssertionError(f"unexpected bake command: {command}")
            return subprocess.CompletedProcess(command, 0)

        def fake_out_text(command):
            if command[0] == "virt-filesystems":
                return "/dev/sda1 1 ext4\n"
            if command[0] == "virt-cat":
                return ("# xpf appliance image inventory\n"
                        "guest_kernel: 6.18.0-fixture\npackages:\n"
                        + "".join(f"p{i}=1\n" for i in range(60)))
            return subprocess.run(
                command, check=True, capture_output=True, text=True).stdout

        cache = root / "cache"
        environment = self.probe_env()
        environment.update({
            "XDG_CACHE_HOME": str(cache),
            "XPF_SIGN_SECKEY": "",
        })
        with (
            mock.patch.object(bake, "ROOT", str(root)),
            mock.patch.object(bake, "HERE", str(here)),
            mock.patch.object(bake, "fetch_base", return_value=(
                "26.04", "https://example.invalid", "ubuntu.img",
                str(root / "base.img"), "0" * 64, True)),
            mock.patch.object(bake, "out_text", side_effect=fake_out_text),
            mock.patch.object(bake, "run", side_effect=fake_run),
            mock.patch.object(bake, "require", return_value=None),
            mock.patch.object(bake, "ensure_memlock", return_value=None),
            mock.patch.object(bake, "validation_gate_step", return_value=True),
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(bake.sys, "argv", argv),
        ):
            result = bake.main()
        return result, copied

    def assert_dirty_parity(self, dirty):
        commit = self.git(
            "rev-parse", "--short=12", "HEAD").stdout.strip()
        expected = f"0.0.1+g{commit}"
        if dirty:
            expected += ".dirty"
        with mock.patch.dict(os.environ, self.probe_env(), clear=True):
            self.assertEqual(bake.deb_version_for_head(str(self.root)), expected)
            self.assertEqual(self.make_suffix(), ".dirty" if dirty else "")

    def test_clean_source_is_clean_in_bake_and_make(self):
        self.assert_dirty_parity(False)

    def test_deb_generated_unit_copies_do_not_dirty_clean_source(self):
        for name in (
                "xpf.xpf-uefi-slots.service",
                "xpf.xpf-kernel-promote.service",
                "xpf.xpf-kernel-promote-failed.service"):
            (self.root / "debian" / name).write_text("# generated by debhelper\n")
        self.assert_dirty_parity(False)

    def test_staged_tracked_edit_is_dirty_in_bake_and_make(self):
        with (self.root / "pkg/app.go").open("a") as source:
            source.write("var Staged = 2\n")
        self.git("add", "pkg/app.go")
        self.assertEqual(self.git("diff", "--quiet", check=False).returncode, 0)
        self.assert_dirty_parity(True)

    def test_consumed_untracked_go_source_is_dirty_in_bake_and_make(self):
        (self.root / "pkg/new.go").write_text("package pkg\nvar New = 3\n")
        self.assertEqual(self.git("diff", "--quiet", check=False).returncode, 0)
        self.assert_dirty_parity(True)

    def test_ignored_but_compiled_bpf_go_source_is_dirty(self):
        dataplane = self.root / "pkg/dataplane"
        dataplane.mkdir(exist_ok=True)
        source = dataplane / "zz_bpfel.go"
        source.write_text("package dataplane\nvar ignoredBuildInput = 1\n")
        self.git("check-ignore", "pkg/dataplane/zz_bpfel.go")
        self.assert_dirty_parity(True)

    def test_unstaged_tracked_edit_is_dirty_in_bake_and_make(self):
        with (self.root / "pkg/app.go").open("a") as source:
            source.write("var Unstaged = 4\n")
        self.assert_dirty_parity(True)

    def test_unrelated_or_ignored_untracked_files_do_not_dirty_build(self):
        (self.root / "docs/unconsumed.txt").write_text("notes\n")
        (self.root / "pkg/generated").mkdir()
        (self.root / "pkg/generated/ignored.go").write_text("package pkg\n")
        deploy_tools = self.root / "scripts/deploy"
        deploy_tools.mkdir()
        (deploy_tools / "unconsumed.py").write_text("# not used by package/bake\n")
        self.assert_dirty_parity(False)

    def test_make_rejects_dirty_source_when_suffix_override_hides_it(self):
        with (self.root / "pkg/app.go").open("a") as source:
            source.write("var Dirty = 5\n")
        clean_version = (
            "0.0.1+g" + self.git("rev-parse", "--short=12", "HEAD").stdout.strip())
        result = subprocess.run(
            ["make", "-s", "--no-print-directory", "-C", str(self.root),
             "deb", "DEB_GIT_DIRTY=", f"DEB_VERSION={clean_version}"],
            capture_output=True, text=True, check=False, env=self.probe_env())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "FATAL: DEB_VERSION dirty suffix disagrees with source inputs",
            result.stderr)

    def test_explicit_clean_version_cannot_name_dirty_source(self):
        with mock.patch.dict(os.environ, self.probe_env(), clear=True):
            clean_version = bake.deb_version_for_head(str(self.root))
            (self.root / "pkg/new.go").write_text(
                "package pkg\nvar New = 3\n")
            dirty_version = bake.deb_version_for_head(str(self.root))
        with self.assertRaises(SystemExit) as caught:
            bake.require_current_build_version(clean_version, dirty_version)
        self.assertIn("does not match current build provenance", str(caught.exception))

    def test_main_rejects_explicit_clean_version_before_building_dirty_source(self):
        args = SimpleNamespace(
            version="0.0.1+gabcdef012345", skip_build=False)
        with (
            mock.patch.object(
                bake.argparse.ArgumentParser, "parse_args", return_value=args),
            mock.patch.object(
                bake, "deb_version_for_head",
                return_value="0.0.1+gabcdef012345.dirty"),
            mock.patch.dict(os.environ, {}, clear=True),
        ):
            with self.assertRaises(SystemExit) as caught:
                bake.main()
        self.assertIn("does not match current build provenance",
                      str(caught.exception))

    def test_info_exclude_ignored_compiled_go_input_is_dirty(self):
        source = self.root / "pkg/local_override.go"
        source.write_text("package pkg\nvar CompiledIgnored = 12141\n")
        exclude = self.root / ".git/info/exclude"
        with exclude.open("a") as rules:
            rules.write("/pkg/local_override.go\n")
        self.assertIn("local_override.go",
                      self.git("check-ignore", "-v",
                               "pkg/local_override.go").stdout)
        archive = self.root.parent / f"{self.root.name}-ignored.a"
        result = subprocess.run(
            ["go", "build", "-o", str(archive), "./pkg"],
            cwd=self.root, env=self.probe_env(), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        symbols = subprocess.run(
            ["go", "tool", "nm", str(archive)], env=self.probe_env(),
            capture_output=True, text=True, check=True).stdout
        self.assertIn("pkg.CompiledIgnored", symbols)
        self.assert_dirty_parity(True)
        archive.unlink(missing_ok=True)

    def test_global_ignore_rule_for_compiled_go_input_is_dirty(self):
        source = self.root / "pkg/global_override.go"
        source.write_text("package pkg\nvar CompiledGlobalIgnored = 12141\n")
        global_ignore = self.root.parent / f"{self.root.name}-global-ignore"
        global_ignore.write_text("/pkg/global_override.go\n")
        self.addCleanup(global_ignore.unlink, missing_ok=True)
        self.git("config", "core.excludesFile", str(global_ignore))
        self.assertIn("global_override.go",
                      self.git("check-ignore", "-v",
                               "pkg/global_override.go").stdout)
        archive = self.root.parent / f"{self.root.name}-global-ignored.a"
        result = subprocess.run(
            ["go", "build", "-o", str(archive), "./pkg"],
            cwd=self.root, env=self.probe_env(), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        symbols = subprocess.run(
            ["go", "tool", "nm", str(archive)], env=self.probe_env(),
            capture_output=True, text=True, check=True).stdout
        self.assertIn("pkg.CompiledGlobalIgnored", symbols)
        self.assert_dirty_parity(True)
        archive.unlink(missing_ok=True)

    def test_go_overlay_is_refused_with_clear_provenance_error(self):
        replacement = self.root.parent / f"{self.root.name}-replacement.go"
        replacement.write_text("package pkg\nvar OverlayOnly = 12141\n")
        self.addCleanup(replacement.unlink, missing_ok=True)
        overlay = self.root.parent / f"{self.root.name}-overlay.json"
        overlay.write_text(json.dumps({
            "Replace": {str(self.root / "pkg/app.go"): str(replacement)}}))
        self.addCleanup(overlay.unlink, missing_ok=True)
        env = self.probe_env()
        env["GOFLAGS"] = f"-overlay={overlay}"
        result = subprocess.run(
            [sys.executable, str(_HERE / "build_provenance.py"),
             "--dirty-suffix", "--root", str(self.root)],
            env=env, capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GOFLAGS -overlay redirects build inputs", result.stderr)

        clean_version = (
            "0.0.1+g" + self.git("rev-parse", "--short=12", "HEAD").stdout.strip())
        refused_build = subprocess.run(
            ["make", "-s", "--no-print-directory", "-C", str(self.root),
             "deb", f"DEB_VERSION={clean_version}"],
            env=env, capture_output=True, text=True, check=False)
        self.assertNotEqual(refused_build.returncode, 0)
        self.assertIn("GOFLAGS -overlay redirects build inputs",
                      refused_build.stderr)
        self.assertIn("FATAL: provenance probe refused the build",
                      refused_build.stderr)

    def test_go_overlay_double_dash_spelling_is_refused(self):
        # Go accepts --flag identically to -flag: the refusal must match
        # both spellings (GLM F1-F5 confirmation defect).
        overlay = self.root.parent / f"{self.root.name}-overlay-dd.json"
        overlay.write_text(json.dumps({"Replace": {}}))
        self.addCleanup(overlay.unlink, missing_ok=True)
        env = self.probe_env()
        env["GOFLAGS"] = f"--overlay={overlay}"
        result = subprocess.run(
            [sys.executable, str(_HERE / "build_provenance.py"),
             "--dirty-suffix", "--root", str(self.root)],
            env=env, capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GOFLAGS -overlay redirects build inputs", result.stderr)

    def test_go_env_file_goflags_are_refused(self):
        # `go env -w` persisted GOFLAGS are honored by every go subprocess
        # but invisible to os.environ: read the effective flags (GLM defect).
        overlay = self.root.parent / f"{self.root.name}-overlay-env.json"
        overlay.write_text(json.dumps({"Replace": {}}))
        self.addCleanup(overlay.unlink, missing_ok=True)
        goenv = self.root.parent / f"{self.root.name}-goenv"
        env = self.probe_env()
        env["GOENV"] = str(goenv)
        env.pop("GOFLAGS", None)
        self.addCleanup(goenv.unlink, missing_ok=True)
        persist = subprocess.run(
            ["go", "env", "-w", f"GOFLAGS=-overlay={overlay}"],
            env=env, capture_output=True, text=True, check=False)
        self.assertEqual(persist.returncode, 0, persist.stderr)
        result = subprocess.run(
            [sys.executable, str(_HERE / "build_provenance.py"),
             "--dirty-suffix", "--root", str(self.root)],
            env=env, capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GOFLAGS -overlay redirects build inputs", result.stderr)

    def test_go_env_failure_refuses_rather_than_certifying_clean(self):
        # Astra F1: a failing `go env` discovery must refuse, never fall
        # back to os.environ. A fake go that always fails breaks BOTH
        # queries, so on pre-fold code this shape exits 0 with .dirty
        # (false-dirty, not false-clean); the test still catches any
        # return of a fallback arm. The env-only false-clean shape (go
        # env fails while go list succeeds) is reviewer-proven (F1b).
        overlay = self.root.parent / f"{self.root.name}-overlay-f1.json"
        overlay.write_text(json.dumps({"Replace": {}}))
        self.addCleanup(overlay.unlink, missing_ok=True)
        fakego = self.root.parent / f"{self.root.name}-fakego"
        fakego.mkdir(exist_ok=True)
        self.addCleanup(shutil.rmtree, fakego, ignore_errors=True)
        (fakego / "go").write_text("#!/bin/sh\necho 'go: fake toolchain failure' >&2\nexit 1\n")
        os.chmod(fakego / "go", 0o755)
        goenv = self.root.parent / f"{self.root.name}-goenv-f1"
        env = self.probe_env()
        env["GOENV"] = str(goenv)
        env.pop("GOFLAGS", None)
        self.addCleanup(goenv.unlink, missing_ok=True)
        persist = subprocess.run(
            ["go", "env", "-w", f"GOFLAGS=-overlay={overlay}"],
            env=env, capture_output=True, text=True, check=False)
        self.assertEqual(persist.returncode, 0, persist.stderr)
        env["PATH"] = f"{fakego}{os.pathsep}{env.get('PATH', '')}"
        result = subprocess.run(
            [sys.executable, str(_HERE / "build_provenance.py"),
             "--dirty-suffix", "--root", str(self.root)],
            env=env, capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot discover effective GOFLAGS", result.stderr)

    def test_relative_goenv_is_resolved_from_probed_root(self):
        # Astra F2: relative GOENV must resolve from --root, not the caller
        # CWD — else a successful query inspects the wrong env file.
        overlay = self.root.parent / f"{self.root.name}-overlay-rel.json"
        overlay.write_text(json.dumps({"Replace": {}}))
        self.addCleanup(overlay.unlink, missing_ok=True)
        rel_goenv = ".git/review-goenv-f2"
        env = self.probe_env()
        env["GOENV"] = rel_goenv
        env.pop("GOFLAGS", None)
        persist = subprocess.run(
            ["go", "env", "-w", f"GOFLAGS=-overlay={overlay}"],
            cwd=self.root, env=env, capture_output=True, text=True, check=False)
        self.assertEqual(persist.returncode, 0, persist.stderr)
        self.addCleanup(os.unlink, str(self.root / rel_goenv))
        # Sanity: from elsewhere the same env sees no flags (wrong file).
        elsewhere = subprocess.run(
            ["go", "env", "GOFLAGS"], cwd="/tmp",
            env=env, capture_output=True, text=True, check=False)
        self.assertEqual(elsewhere.stdout.strip(), "")
        result = subprocess.run(
            [sys.executable, str(_HERE / "build_provenance.py"),
             "--dirty-suffix", "--root", str(self.root)],
            cwd="/tmp", env=env, capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GOFLAGS -overlay redirects build inputs", result.stderr)

    def test_adjacent_quoted_goflags_cannot_hide_overlay(self):
        # Astra F3: Go splits adjacent quoted fields separately (shlex
        # concatenates) — `"-tags=x""--overlay=A"` must still refuse.
        overlay = self.root.parent / f"{self.root.name}-overlay-adj.json"
        overlay.write_text(json.dumps({"Replace": {}}))
        self.addCleanup(overlay.unlink, missing_ok=True)
        env = self.probe_env()
        env["GOENV"] = "off"
        env["GOFLAGS"] = f'"-tags=review""--overlay={overlay}"'
        result = subprocess.run(
            [sys.executable, str(_HERE / "build_provenance.py"),
             "--dirty-suffix", "--root", str(self.root)],
            env=env, capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("GOFLAGS -overlay redirects build inputs", result.stderr)
    def test_go_flags_splitter_matches_go_quoted_split(self):
        # Opus F3 confirmation: the splitter must match Go quoted.Split on
        # every B-class (post-close content, backslash-space, mid-field
        # quote, in-quote backslash, single-quote backslash, VT). Ground
        # truth verified against /usr/lib/go-1.26 quoted.go via a go-run
        # driver (parent check, 15/15 + 2 empty-input shapes).
        _PROV_SPEC = importlib.util.spec_from_file_location(
            "xpf_build_provenance_head", _HERE / "build_provenance.py")
        assert _PROV_SPEC.loader is not None
        _prov = importlib.util.module_from_spec(_PROV_SPEC)
        _PROV_SPEC.loader.exec_module(_prov)
        _split_go_flags = _prov._split_go_flags
        DQ, SQ, BS, VT, NB = chr(34), chr(39), chr(92), chr(11), chr(160)
        A = "/tmp/x.json"
        cases = [
            ('"-tags=review""--overlay=' + A + '"',
             ["-tags=review", "--overlay=" + A]),
            ('"-mod=mod"-overlay=' + A,
             ["-mod=mod", "-overlay=" + A]),
            ("-tags=x" + BS + " -overlay=" + A,
             ["-tags=x" + BS, "-overlay=" + A]),
            ("-tags=a" + SQ + " -overlay=" + A + " -tags=b" + SQ,
             ["-tags=a" + SQ, "-overlay=" + A, "-tags=b" + SQ]),
            ("-tags=v" + VT + "y -overlay=" + A + " -tags=z",
             ["-tags=v" + VT + "y", "-overlay=" + A, "-tags=z"]),
            ("plain -overlay=" + A + " tail",
             ["plain", "-overlay=" + A, "tail"]),
            ("-flag=x" + NB + "-overlay=" + A,
             ["-flag=x" + NB + "-overlay=" + A]),
            ('"a"b"c"d', ["a", 'b"c"d']),
            ("x" + DQ + "y", ["x" + DQ + "y"]),
        ]
        for raw, want in cases:
            with self.subTest(raw=raw):
                self.assertEqual(_split_go_flags(raw), want)
        with self.subTest(raw="unterminated-quote"):
            with self.assertRaises(Exception):
                _split_go_flags(DQ + "unterminated")
        self.assertEqual(_split_go_flags(""), [])
        self.assertEqual(_split_go_flags("   "), [])

    def test_non_ascii_ignored_bpf_source_is_dirty_and_compiled(self):
        source = self.root / "pkg/dataplane/é_bpfel.go"
        source.write_text("package dataplane\nvar QuotedBPFInput = 12141\n")
        self.git("check-ignore", "pkg/dataplane/é_bpfel.go")
        archive = self.root.parent / f"{self.root.name}-quoted.a"
        result = subprocess.run(
            ["go", "build", "-o", str(archive), "./pkg/dataplane"],
            cwd=self.root, env=self.probe_env(), capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        symbols = subprocess.run(
            ["go", "tool", "nm", str(archive)], env=self.probe_env(),
            capture_output=True, text=True, check=True).stdout
        self.assertIn("pkg/dataplane.QuotedBPFInput", symbols)
        self.assert_dirty_parity(True)
        archive.unlink(missing_ok=True)

    def test_ls_files_warning_on_unreadable_build_dir_is_dirty(self):
        blocked = self.root / "pkg/unreadable"
        blocked.mkdir()
        (blocked / "live.go").write_text(
            "package ignored\nvar Unenumerated = 12141\n")
        blocked.chmod(0)
        try:
            scan = self.git(
                "ls-files", "--others", "--exclude-standard", "--", "pkg",
                check=False)
            self.assertEqual(scan.returncode, 0)
            self.assertEqual(scan.stdout, "")
            self.assertIn("warning: could not open directory", scan.stderr)
            with mock.patch.dict(os.environ, self.probe_env(), clear=True):
                self.assertTrue(
                    bake.build_provenance.source_tree_dirty(str(self.root)))
            self.assert_dirty_parity(True)
        finally:
            blocked.chmod(0o755)

    def test_skip_build_sidecar_attests_dirty_current_image_inputs(self):
        with mock.patch.dict(os.environ, self.probe_env(), clear=True):
            package_version = bake.deb_version_for_head(str(self.root))
        self.make_test_deb(package_version)
        image_input = self.root / "scripts/image/xpf-input-closed.service"
        image_input.write_text(
            "[Service]\nExecStart=/bin/echo local-image-input\n")
        out = self.root / "bake-out"
        result, copied = self.run_bake_main([
            "bake.py", "--skip-build", "--skip-validate",
            "--version", package_version, "--out", str(out)])
        self.assertEqual(result, 0)
        self.assertIn(
            f"{image_input}:/usr/lib/systemd/system", copied)
        manifest = out / f"xpf-{package_version}.manifest"
        self.assertIn(f"version: {package_version}\n", manifest.read_text())
        self.assertIn("source_dirty: true\n", manifest.read_text())

    def test_exported_deb_version_cannot_hide_post_build_source_drift(self):
        with mock.patch.dict(os.environ, self.probe_env(), clear=True):
            clean_version = bake.deb_version_for_head(str(self.root))
        self.make_test_deb(clean_version)
        args = [
            "bake.py", "--skip-validate", "--out", str(self.root / "f2-clean"),
        ]

        class ReachedPackageSelection(Exception):
            pass

        with mock.patch.dict(os.environ, {"DEB_VERSION": clean_version}, clear=False):
            with mock.patch.object(
                    bake, "select_xpf_deb",
                    side_effect=ReachedPackageSelection):
                with self.assertRaises(ReachedPackageSelection):
                    self.run_bake_main(args)

            args[-1] = str(self.root / "f2-dirty")
            with mock.patch.object(
                    bake, "select_xpf_deb",
                    side_effect=ReachedPackageSelection):
                with self.assertRaises(SystemExit) as caught:
                    self.run_bake_main(args, mutate_on_build=True)
        self.assertIn("does not match current build provenance",
                      str(caught.exception))
        self.assertIn(".dirty", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
