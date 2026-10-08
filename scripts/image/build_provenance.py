#!/usr/bin/env python3
"""Shared build-input provenance probe for Makefile and appliance bake."""

from __future__ import annotations

import argparse
import os
import subprocess

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
)


def source_tree_dirty(root):
    """Return whether tracked or consumed untracked build input differs from HEAD.

    `git diff --quiet` compares the worktree with the index and misses staged
    changes. Compare tracked files against HEAD, then find untracked build
    inputs. Go compiles ignored generated BPF `.go` files too, so inspect
    ignored files in its package roots and count those sources. Git errors fail
    closed as dirty so unverifiable state cannot attest clean.
    """
    root = os.fspath(root)
    try:
        tracked = subprocess.run(
            ["git", "-C", root, "diff", "HEAD", "--quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False).returncode
        untracked = subprocess.run(
            ["git", "-C", root, "ls-files", "--others", "--exclude-standard",
             "--", *UNTRACKED_BUILD_INPUTS],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, check=True).stdout
        ignored_go = subprocess.run(
            ["git", "-C", root, "ls-files", "--others", "--ignored",
             "--exclude-standard", "--", "cmd", "internal", "pkg"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError):
        return True
    ignored_bpf_source = any(
        path.endswith(("_bpfel.go", "_bpfeb.go"))
        for path in ignored_go.splitlines())
    return tracked != 0 or bool(untracked.strip()) or ignored_bpf_source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))
    parser.add_argument("--dirty-suffix", action="store_true")
    args = parser.parse_args()
    if not args.dirty_suffix:
        parser.error("--dirty-suffix is required")
    print(".dirty" if source_tree_dirty(args.root) else "")


if __name__ == "__main__":
    main()
