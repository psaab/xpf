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

# The Python selector uses go list's package owners and all regular/test import
# edges. Package-local fixtures map to their nearest Go package; shared fixtures,
# module changes, or vendored changes seed every in-repository package.
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
    if unresolved:
        print(
            "cannot map changed Go file(s) to a package; refusing to skip tests: "
            + ", ".join(unresolved),
            file=sys.stderr,
        )
        sys.exit(1)

if not seeds:
    print("No changed Go source package; skipping affected Go tests.")
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
