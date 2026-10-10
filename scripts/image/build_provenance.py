#!/usr/bin/env python3
"""Shared build-input provenance probe for Makefile and appliance bake."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys


class ProvenanceError(RuntimeError):
    """Build inputs cannot be safely attested under the current Go flags."""


# Make's Go build inputs. Keep these package paths in lockstep with `build` and
# `build-ctl`; `source_tree_dirty` asks Go for their actual transitive sources.
GO_BUILD_TARGETS = ("./cmd/xpfd", "./cmd/cli")

# These GOFLAGS can redirect the source/module/compiler input away from files
# the repository probe can attest. Refuse them rather than sign a false-clean
# identity. Ordinary flags such as -tags remain supported and are honored by
# `go list` below.
UNATTESTABLE_GOFLAGS = ("-overlay", "-modfile", "-toolexec", "-pkgdir")

# Untracked files in these build-input roots can be consumed by package/bake.
# Tracked changes are checked across the whole tree to preserve the existing
# dirty-tree convention; unrelated untracked notes and test artifacts stay clean.
UNTRACKED_BUILD_INPUTS = (
    ".cargo",
    "Makefile",
    "cmd",
    "debian",
    "go.mod",
    "go.sum",
    "go.work",
    "go.work.sum",
    "internal",
    "pkg",
    "proto",
    "scripts/dist",
    "scripts/image",
    "test/incus/xpfd.service",
    "userspace-dp",
    "vendor",
)


def _split_go_flags(raw):
    # Go-compatible field splitting for GOFLAGS: unlike Python shlex (which
    # concatenates adjacent quoted strings), Go's quoted.Split emits each
    # quoted field separately, including adjacent fields without whitespace.
    # `"-tags=x""--overlay=A"` is ONE shlex token but TWO Go flags — and the
    # second one redirects source. Split on quote boundaries the way Go does
    # so no flag hides inside a benign token (Astra GOFLAGS-confirmation F3).
    fields, buf, quote, had = [], [], None, False
    i = 0
    while i < len(raw):
        ch = raw[i]
        if quote is not None:
            if ch == quote:
                quote = None
                had = True
            elif ch == "\\" and i + 1 < len(raw):
                i += 1
                buf.append(raw[i])
            else:
                buf.append(ch)
        elif ch in ("'", '"'):
            # A quote starting a new field right after token content (no
            # whitespace) begins a SEPARATE field, per Go quoted.Split.
            if had:
                fields.append("".join(buf))
                buf, had = [], False
            quote = ch
        elif ch.isspace():
            if had:
                fields.append("".join(buf))
                buf, had = [], False
        elif ch == "\\" and i + 1 < len(raw):
            i += 1
            buf.append(raw[i])
            had = True
        else:
            buf.append(ch)
            had = True
        i += 1
    if quote is not None:
        raise ProvenanceError("cannot parse GOFLAGS for provenance: unterminated quote")
    if had:
        fields.append("".join(buf))
    return fields


def _check_go_flags(root):
    # Read the EFFECTIVE flags: `go env GOFLAGS` merges `go env -w`
    # persisted flags that os.environ cannot see. Run it with cwd=root:
    # relative GOENV paths resolve from the caller directory, so a query
    # anywhere else can inspect a different env file than the build
    # consumes (Astra F2). On ANY discovery failure refuse: falling back
    # to possibly-empty os.environ would certify persisted redirections
    # as clean (Astra F1).
    try:
        env_result = subprocess.run(
            ["go", "env", "GOFLAGS"],
            cwd=root,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, check=False)
    except OSError as e:
        raise ProvenanceError(f"cannot discover effective GOFLAGS for provenance: {e}") from e
    if env_result.returncode != 0:
        raise ProvenanceError(
            "cannot discover effective GOFLAGS for provenance: "
            f"go env exited {env_result.returncode}: {env_result.stderr.strip()}")
    raw = env_result.stdout.strip()
    if not raw:
        # go env succeeded but reports no flags: authoritative ONLY if
        # os.environ agrees (belt-and-braces; go env merges both, so a
        # divergence here means the query missed live configuration).
        raw = os.environ.get("GOFLAGS", "")
    flags = _split_go_flags(raw)
    for token in flags:
        # Go accepts -flag and --flag identically: strip ALL leading
        # dashes before matching so neither spelling evades the check.
        normalized = "-" + token.lstrip("-").split("=", 1)[0]
        for flag in UNATTESTABLE_GOFLAGS:
            if normalized == flag:
                raise ProvenanceError(
                    f"GOFLAGS {flag} redirects build inputs that source "
                    "provenance cannot attest; unset that flag before "
                    "building")


def _warn_scan_failure(command, result):
    detail = os.fsdecode(result.stderr).strip()
    if detail:
        print(f"WARNING: {command} could not completely enumerate build "
              f"inputs: {detail}", file=sys.stderr)
    else:
        print(f"WARNING: {command} exited {result.returncode} while probing "
              "build inputs", file=sys.stderr)


def _compiled_sources(root):
    """Return repo-relative files consumed by the two Makefile Go builds."""
    try:
        result = subprocess.run(
            ["go", "list", "-deps", "-compiled", "-json", *GO_BUILD_TARGETS],
            cwd=root, env={**os.environ, "CGO_ENABLED": "0"},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except OSError as e:
        print(f"WARNING: cannot enumerate compiled Go inputs: {e}",
              file=sys.stderr)
        return None
    if result.returncode != 0 or result.stderr:
        _warn_scan_failure("go list", result)
        return None

    try:
        text = result.stdout.decode("utf-8", "strict")
    except UnicodeDecodeError as e:
        print(f"WARNING: cannot decode compiled Go input list: {e}",
              file=sys.stderr)
        return None
    decoder = json.JSONDecoder()
    offset = 0
    sources = set()
    try:
        while offset < len(text):
            while offset < len(text) and text[offset].isspace():
                offset += 1
            if offset == len(text):
                break
            package, offset = decoder.raw_decode(text, offset)
            if package.get("Error") or package.get("DepsErrors"):
                print("WARNING: go list reported an incomplete package graph",
                      file=sys.stderr)
                return None
            directory = package.get("Dir")
            if not directory:
                continue
            for field in (
                    "CompiledGoFiles", "GoFiles", "CgoFiles",
                    "EmbedFiles", "CFiles", "CXXFiles", "MFiles",
                    "HFiles", "FFiles", "SFiles", "SwigFiles",
                    "SwigCXXFiles", "SysoFiles"):
                for name in package.get(field, ()):
                    path = name if os.path.isabs(name) else os.path.join(
                        directory, name)
                    path = os.path.abspath(path)
                    try:
                        if os.path.commonpath((root, path)) == root:
                            sources.add(os.path.relpath(path, root))
                    except ValueError:
                        continue
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError) as e:
        print(f"WARNING: cannot parse compiled Go input list: {e}",
              file=sys.stderr)
        return None
    return sources


def _ignored_compiled_sources(root):
    sources = _compiled_sources(root)
    if sources is None:
        return None
    if not sources:
        return False
    input_paths = b"".join(os.fsencode(path) + b"\0"
                           for path in sorted(sources))
    try:
        result = subprocess.run(
            ["git", "-C", root, "check-ignore", "-q", "-z", "--stdin"],
            input=input_paths, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, check=False)
    except OSError as e:
        print(f"WARNING: cannot check ignored compiled inputs: {e}",
              file=sys.stderr)
        return None
    if result.stderr or result.returncode not in (0, 1):
        _warn_scan_failure("git check-ignore", result)
        return None
    return result.returncode == 0


def _ls_files(root, *args):
    command = ["git", "-C", root, "ls-files", "-z", *args]
    try:
        result = subprocess.run(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False)
    except OSError as e:
        print(f"WARNING: cannot enumerate build inputs with git ls-files: {e}",
              file=sys.stderr)
        return None
    # Git can warn (for example, on an unreadable directory) and still exit
    # zero. Any stderr means enumeration is incomplete or uncertain.
    if result.returncode != 0 or result.stderr:
        _warn_scan_failure("git ls-files", result)
        return None
    return result.stdout


def source_tree_dirty(root):
    """Return whether tracked or consumed build inputs differ from HEAD.

    Tracked changes are compared with HEAD so staged-only edits are included.
    Untracked files are considered only in build-input roots. Go's package
    graph enumerates the exact compiled inputs of Make's two Go build targets;
    ignored files in that set are checked directly, covering info-exclude and
    global-ignore rules without marking ignored files in unused packages.
    Git/Go enumeration warnings fail closed as dirty. No subprocess timeout is
    configured, so a hung Git or Go process can block the probe.
    """
    root = os.path.abspath(os.fspath(root))
    _check_go_flags(root)
    try:
        tracked = subprocess.run(
            ["git", "-C", root, "diff", "HEAD", "--quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            check=False)
    except OSError:
        return True
    if tracked.returncode != 0 or tracked.stderr:
        return True
    untracked = _ls_files(
        root, "--others", "--exclude-standard", "--",
        *UNTRACKED_BUILD_INPUTS)
    if untracked is None:
        return True
    ignored_compiled = _ignored_compiled_sources(root)
    if ignored_compiled is None:
        return True
    return tracked.returncode != 0 or bool(untracked) or ignored_compiled


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    parser.add_argument("--dirty-suffix", action="store_true")
    args = parser.parse_args()
    if not args.dirty_suffix:
        parser.error("--dirty-suffix is required")
    try:
        dirty = source_tree_dirty(args.root)
    except ProvenanceError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2
    print(".dirty" if dirty else "")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
