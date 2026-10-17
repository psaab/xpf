#!/bin/sh
# Test changed Go packages and their in-repository reverse dependencies.
# BASE and HEAD are commit IDs available in the checked-out repository.
set -eu

LIST_ONLY=0
if [ "${1:-}" = "--list" ]; then
  LIST_ONLY=1
  shift
fi
if [ "$#" -ne 2 ]; then
  echo "usage: $0 [--list] BASE_SHA HEAD_SHA" >&2
  exit 2
fi
BASE=$1
HEAD=$2

if ! CHANGED=$(git diff --name-only "$BASE" "$HEAD"); then
  echo "unable to diff repository paths between $BASE and $HEAD" >&2
  exit 1
fi
if [ -z "$CHANGED" ]; then
  echo "No files changed; skipping affected Go tests."
  exit 0
fi

# Tree-census packages (#14647): their tests scan the whole repository
# (git grep / AST walks over non-Go files too) yet no scanned package
# imports them, so reverse-import closure can never reach them and a
# content-only change would otherwise select nothing. They are always
# selected. Keep this list in sync with the census self-test
# (scripts/ci_affected_go_tests_selftest.sh), which fails if a listed
# package disappears or a new import-less tree-scanning package appears
# without being listed.
# The Python selector uses go list's package owners and all regular/test import
# edges. Package-local fixtures map to their nearest Go package; shared fixtures,
# module changes, or vendored changes seed every in-repository package.
# A changed path owned by no Go package and not on the never-read
# allowlist below also seeds every package: Go tests read Rust sources,
# docs, manifests, fixtures and workflow files by path, and the import
# graph has no edge for those reads (#14647). The allowlist is only for
# paths no Go test reads; when in doubt, do not allowlist -- seeding all
# is the safe fallback, never seeding nothing.
PKGS=$(printf '%s\n' "$CHANGED" | python3 -c '
import json
import os
import pathlib
import subprocess
import sys

changed = [line.rstrip("\n") for line in sys.stdin if line.rstrip("\n")]
module_changed = any(path in ("go.mod", "go.sum") for path in changed)
vendored_changed = any(path.startswith("vendor/") for path in changed)
fixture_dirs = {"testdata", "fixtures", "test-fixtures", "test_fixtures"}

# Packages whose tests scan the tree but that nothing scanned imports
# (#14647). Synced with scripts/ci_affected_go_tests_selftest.sh.
census_packages = {
    "github.com/psaab/xpf/pkg/docsref",
    "github.com/psaab/xpf/pkg/durationaudit",
    "github.com/psaab/xpf/pkg/memlockcensus",
    "github.com/psaab/xpf/pkg/refactoraudit",
    "github.com/psaab/xpf/pkg/showaudit",
}

# Changed paths no Go test reads (#14647). Anything not listed here and
# not owned by a Go package seeds every package instead of nothing.
# docs/log/ and docs/issues/*-history*.md are append-only records that
# docsref deliberately excludes (isHistoricalArchive); the two non-test
# workflows examine no Go source.
def never_read(path):
    if path == "_Log.md":
        return True
    if path.startswith("docs/log/"):
        return True
    if path.startswith("docs/issues/") and (
        path.endswith("-history.md") or path.endswith("-history-archive.md")
    ):
        return True
    if path == ".github/workflows/close-keyword-lint.yml":
        return True
    if path == ".github/workflows/retain-shim-gate-verdict.yml":
        return True
    return False

listed = subprocess.run(
    ["go", "list", "-json", "./..."],
    check=True,
    capture_output=True,
    text=True,
).stdout
decoder = json.JSONDecoder()
index = 0
packages = {}
owners = {}
directories = {}
while index < len(listed):
    while index < len(listed) and listed[index].isspace():
        index += 1
    if index == len(listed):
        break
    package, index = decoder.raw_decode(listed, index)
    import_path = package["ImportPath"]
    directory = os.path.realpath(package["Dir"])
    packages[import_path] = package
    directories[directory] = import_path
    for field in ("GoFiles", "CgoFiles", "TestGoFiles", "XTestGoFiles", "IgnoredGoFiles"):
        for filename in package.get(field, []):
            owners[os.path.normpath(os.path.join(directory, filename))] = import_path

seeds = set()
if module_changed or vendored_changed:
    seeds.update(packages)
else:
    unresolved = []
    root = os.path.realpath(".")
    for filename in changed:
        path = os.path.normpath(os.path.join(root, filename))
        owner = owners.get(path)
        directory = os.path.realpath(os.path.dirname(path))
        while owner is None:
            owner = directories.get(directory)
            if owner is not None or directory == root:
                break
            parent = os.path.dirname(directory)
            if parent == directory:
                break
            directory = parent
        if owner is not None:
            seeds.add(owner)
        elif fixture_dirs.intersection(pathlib.PurePosixPath(filename).parts):
            seeds.update(packages)
        elif filename.endswith(".go"):
            unresolved.append(filename)
        elif not never_read(filename):
            # Non-Go path owned by no package: Go tests read such files
            # by path (Rust sources, docs, manifests), so fall back to
            # every package rather than selecting nothing (#14647).
            seeds.update(packages)
    if unresolved:
        print(
            "cannot map changed Go file(s) to a package; refusing to skip tests: "
            + ", ".join(unresolved),
            file=sys.stderr,
        )
        sys.exit(1)

# Census packages scan the tree yet are imported by nothing scanned, so
# reverse-import closure cannot reach them; always run them (#14647).
# Fail closed if a listed census package no longer exists, so the list
# cannot silently rot into a no-op.
missing_census = sorted(census_packages - set(packages))
if missing_census:
    print(
        "census package(s) no longer exist; update census_packages in "
        "scripts/ci_affected_go_tests.sh: " + ", ".join(missing_census),
        file=sys.stderr,
    )
    sys.exit(1)
seeds.update(census_packages)

if not seeds:
    print("No changed Go source package; skipping affected Go tests.", file=sys.stderr)
    sys.exit(0)

reverse_imports = {}
for import_path, package in packages.items():
    dependencies = set()
    for field in ("Imports", "TestImports", "XTestImports"):
        dependencies.update(package.get(field, []))
    for dependency in dependencies:
        reverse_imports.setdefault(dependency, set()).add(import_path)

selected = set(seeds)
queue = list(seeds)
while queue:
    dependency = queue.pop()
    for importer in reverse_imports.get(dependency, ()):
        if importer not in selected:
            selected.add(importer)
            queue.append(importer)

print(" ".join(sorted(selected)))
')

if [ -z "$PKGS" ]; then
  exit 0
fi
printf 'Affected Go packages: %s\n' "$PKGS"
if [ "$LIST_ONLY" -eq 1 ]; then
  exit 0
fi
# Package import paths cannot contain shell whitespace.
# shellcheck disable=SC2086
set -- $PKGS
exec go test -count=1 "$@"
