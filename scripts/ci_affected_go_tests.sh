#!/bin/sh
# Test changed Go packages and their in-repository reverse dependencies.
# BASE and HEAD are commit IDs available in the checked-out repository.
set -eu

LIST_ONLY=0
PACKAGE_FILE=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --list)
      LIST_ONLY=1
      shift
      ;;
    --packages-file)
      if [ "$#" -lt 2 ]; then
        echo "usage: $0 [--list] [--packages-file FILE] BASE_SHA HEAD_SHA" >&2
        exit 2
      fi
      PACKAGE_FILE=$2
      shift 2
      ;;
    *)
      break
      ;;
  esac
done
if [ "$#" -ne 2 ]; then
  echo "usage: $0 [--list] [--packages-file FILE] BASE_SHA HEAD_SHA" >&2
  exit 2
fi
BASE=$1
HEAD=$2

if ! CHANGED=$(git diff --name-only --no-renames "$BASE" "$HEAD"); then
  echo "unable to diff repository paths between $BASE and $HEAD" >&2
  exit 1
fi
if [ -z "$CHANGED" ] && [ -z "$PACKAGE_FILE" ]; then
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
# Explicit package lists run directly; path-to-package selection is not needed
# for a bounded cohort or a differential-runner self-test.
if [ -n "$PACKAGE_FILE" ]; then
  PKGS=
else
  PKGS=$(printf '%s\n' "$CHANGED" | python3 -c '
import json
import os
import re
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
# The historical-archive set (append-only records that docsref excludes
# via isHistoricalArchive) lives in scripts/historical-paths.txt, shared
# with pkg/docsref (#17115); the two non-test workflows examine no Go
# source and stay local to this selector.
def _load_historical_patterns17115():
    pats = []
    with open("scripts/historical-paths.txt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                pats.append(line)
    if not pats:
        print("scripts/historical-paths.txt parsed to ZERO patterns", file=sys.stderr)
        sys.exit(1)
    return pats

_historical_patterns17115 = _load_historical_patterns17115()

def _historical_match17115(path):
    for pat in _historical_patterns17115:
        if "*" not in pat:
            if pat == path:
                return True
        else:
            pre, suf = pat.split("*", 1)
            if len(path) >= len(pre) + len(suf) and path.startswith(pre) and path.endswith(suf):
                return True
    return False

def never_read(path):
    if _historical_match17115(path):
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
# Reads-source-of edges (#15241 A58-01, #16461): a test that opens another
# package Go source by relative path (pkg/denyaudit reading
# ../grpcapi/authz.go) has no import edge to that package -- denyaudit is
# imported BY grpcapi, not the reverse -- so the reverse-import closure
# below can never select it for a change to the file it reads. Derive
# the missing edges from the test sources themselves: every relative
# path literal in a *_test.go that resolves to a file inside another Go
# package makes the test package a reader of that package. Relative
# literals of ANY depth count (../../cmd/cli/clear.go from pkg/grpcapi);
# only a resolved path outside the repo is rejected (#16461).
# Repo-root-anchored reads (#16461): a test that derives the repo root
# (filepath.Dir(filepath.Dir(wd)) or filepath.Abs("../..")) and then
# reads root-anchored literals ("pkg/api", "pkg/grpcapi",
# filepath.Join(root, "pkg/api/api.go")) has no ".." literal naming the
# scanned package at all -- the pkg/diagcmd session-walk canary (#7294)
# scans exactly those two packages, so a change to either must select
# pkg/diagcmd. Root-anchored literals are therefore honoured ONLY in a
# test file that itself declares such a root derivation, and only when
# the anchored path exists in the tree, so prose mentioning pkg/... in
# an ordinary test cannot manufacture an edge.
reads_source_of = {}
_join_call = re.compile(r"filepath\.Join\(([^)]*)\)")
_quoted = re.compile(r"\"((?:[^\"\\]|\\.)*)\"")
_declares_root = re.compile(
    r"filepath\.Dir\s*\(\s*filepath\.Dir\s*\(|filepath\.Abs\s*\(\s*\"\.\./\.\.\""
)
repo_root = os.path.realpath(".")
for import_path, package in packages.items():
    import_dir = os.path.realpath(package["Dir"])
    for field in ("TestGoFiles", "XTestGoFiles"):
        for filename in package.get(field, []):
            test_path = os.path.join(import_dir, filename)
            try:
                with open(test_path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            targets = set()
            for qm in _quoted.finditer(text):
                raw = qm.group(1)
                if raw == ".." or raw.startswith("../"):
                    targets.add(os.path.normpath(os.path.join(import_dir, raw)))
            for m in _join_call.finditer(text):
                parts = _quoted.findall(m.group(1))
                if not parts:
                    continue
                first = parts[0]
                if first in ("..", ".") or first.startswith("../"):
                    targets.add(os.path.normpath(os.path.join(import_dir, *parts)))
                elif first in ("pkg", "cmd") or first.startswith(("pkg/", "cmd/")):
                    targets.add(os.path.normpath(os.path.join(repo_root, *parts)))
            if _declares_root.search(text):
                anchored = set()
                for qm in _quoted.finditer(text):
                    raw = qm.group(1)
                    if raw.startswith(("pkg/", "cmd/")):
                        anchored.add(raw)
                for m in _join_call.finditer(text):
                    parts = _quoted.findall(m.group(1))
                    if parts and (
                        parts[0] in ("pkg", "cmd")
                        or parts[0].startswith(("pkg/", "cmd/"))
                    ):
                        anchored.add("/".join(parts))
                for raw in anchored:
                    resolved = os.path.normpath(os.path.join(repo_root, raw))
                    if os.path.exists(resolved):
                        targets.add(resolved)
            for resolved in targets:
                # Keep a resolved-path-inside-repo check: a literal that
                # climbs out of the tree names no in-repo package.
                if resolved == repo_root:
                    continue
                try:
                    if os.path.commonpath([repo_root, resolved]) != repo_root:
                        continue
                except ValueError:
                    continue
                # The owning package is the nearest mapped ancestor
                # directory, exactly as for changed paths (the target
                # may be a package directory itself).
                probe = resolved if os.path.isdir(resolved) else os.path.dirname(resolved)
                owner = None
                while True:
                    owner = directories.get(os.path.realpath(probe))
                    if owner is not None or probe == repo_root or os.path.dirname(probe) == probe:
                        break
                    probe = os.path.dirname(probe)
                if owner is not None and owner != import_path:
                    reads_source_of.setdefault(owner, set()).add(import_path)

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
# Merge the reads-source-of edges (#15241 A58-01) into the same closure.
for dependency, readers in reads_source_of.items():
    reverse_imports.setdefault(dependency, set()).update(readers)

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
fi

if [ -n "$PACKAGE_FILE" ]; then
  if [ ! -f "$PACKAGE_FILE" ]; then
    printf 'package list does not exist: %s\n' "$PACKAGE_FILE" >&2
    exit 2
  fi
  PKGS=$(python3 - "$PACKAGE_FILE" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
packages = [
    line.strip()
    for line in path.read_text(encoding="utf-8").splitlines()
    if line.strip() and not line.lstrip().startswith("#")
]
if not packages:
    raise SystemExit(f"{path}: package list is empty")
if len(packages) != len(set(packages)):
    raise SystemExit(f"{path}: duplicate package path")
if any(not package.startswith("github.com/psaab/xpf/") or
       any(char.isspace() for char in package) for package in packages):
    raise SystemExit(f"{path}: expected one in-repository import path per line")
print(" ".join(packages))
PY
)
fi

if [ -z "$PKGS" ]; then
  exit 0
fi
printf 'Affected Go packages: %s\n' "$PKGS"
if [ "$LIST_ONLY" -eq 1 ]; then
  exit 0
fi

# Default two-SHA mode keeps the strict pre-#16723 gate: any HEAD failure
# fails the build, with no base comparison. The base differential below
# must not weaken it (a base-red package must not mask a head red, or a
# true-positive detector like pkg/cli would go report-only), so it runs
# only for an explicit --packages-file cohort.
# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
if [ -z "$PACKAGE_FILE" ]; then
  # Package import paths cannot contain shell whitespace.
  # shellcheck disable=SC2086
  set -- $PKGS
  # Master (#18038) wraps this exec in testguard-run.sh for host-state
  # isolation. Keep that wrap whenever the wrapper exists so a landing
  # rebase cannot revert it; the plain form runs only where the wrapper
  # is absent (this branch's base predates #18038).
  if [ -x "$script_dir/testguard-run.sh" ]; then
    exec "$script_dir/testguard-run.sh" go test -count=1 "$@"
  fi
  exec go test -count=1 "$@"
fi
if [ -z "${TMPDIR:-}" ]; then
  TMPDIR=/var/worktrees/.cache/tmpdir
fi
mkdir -p "$TMPDIR"
repo_root=$(git rev-parse --show-toplevel)
test_runner="$script_dir/go-test-json.sh"
head_log=$(mktemp "$TMPDIR/affected-go-head.XXXXXX")
base_log=
base_tree=
cleanup_base_tree() {
  if [ -n "$head_log" ]; then
    rm -f "$head_log"
  fi
  if [ -n "$base_log" ]; then
    rm -f "$base_log"
  fi
  if [ -n "$base_tree" ]; then
    if ! git -C "$repo_root" worktree remove "$base_tree" >/dev/null 2>&1; then
      printf 'warning: unable to remove base test worktree %s\n' "$base_tree" >&2
    fi
  fi
}
trap cleanup_base_tree EXIT

failed_packages() {
  python3 - "$1" <<'PY'
import re
import sys

failed = set()
with open(sys.argv[1], encoding="utf-8", errors="replace") as stream:
    for line in stream:
        match = re.match(r"^FAIL[ \t]+(\S+)(?:[ \t]|$)", line)
        if match and match.group(1).startswith("github.com/psaab/xpf/"):
            failed.add(match.group(1))
print(" ".join(sorted(failed)))
PY
}
run_logged_tests() {
  runner=$1
  log=$2
  shift 2
  bash -o pipefail -c '
    runner=$1
    log=$2
    shift 2
    bash "$runner" "" "$@" 2>&1 | tee "$log"
  ' affected-go-tests "$runner" "$log" "$@"
}

set -- $PKGS
# Run HEAD once across the selected set. The shared runner preserves text
# output and returns 3 on a timeout, which is VOID rather than a red package.
if run_logged_tests "$test_runner" "$head_log" go -count=1 "$@"; then
  head_rc=0
else
  head_rc=$?
fi
if [ "$head_rc" -eq 0 ]; then
  exit 0
fi
if [ "$head_rc" -eq 3 ]; then
  printf 'VOID: selected Go package tests timed out at head %s\n' "$HEAD" >&2
  exit 3
fi
if [ "$head_rc" -ne 1 ]; then
  printf 'VOID: unable to run selected Go packages at head %s (runner rc=%s)\n' \
    "$HEAD" "$head_rc" >&2
  exit 2
fi
head_failed=$(failed_packages "$head_log")
if [ -z "$head_failed" ]; then
  printf 'VOID: head %s failed without package-level test results\n' "$HEAD" >&2
  exit 2
fi

base_tree=$(mktemp -d "$TMPDIR/affected-go-base.XXXXXX")
rmdir "$base_tree"
if ! git -C "$repo_root" worktree add --detach "$base_tree" "$BASE"; then
  rmdir "$base_tree" 2>/dev/null || :
  base_tree=
  printf 'unable to create base test worktree for %s\n' "$BASE" >&2
  exit 2
fi

# A base package must exist and compile before a test failure there can be
# called a known-red baseline. Missing/build-broken packages are VOID.
set -- $head_failed
for package in "$@"; do
  if ! (cd "$base_tree" && go list "$package" >/dev/null 2>&1); then
    printf 'VOID: %s did not exist or was not listable at base %s\n' \
      "$package" "$BASE" >&2
    exit 2
  fi
  base_binary=$(mktemp "$TMPDIR/affected-go-base-test.XXXXXX")
  if ! (cd "$base_tree" && go test -c -o "$base_binary" "$package"); then
    rm -f "$base_binary"
    printf 'VOID: %s did not compile at base %s; cannot compare test verdicts\n' \
      "$package" "$BASE" >&2
    exit 2
  fi
  rm -f "$base_binary"
done

base_log=$(mktemp "$TMPDIR/affected-go-base.XXXXXX")
if (cd "$base_tree" && run_logged_tests "$test_runner" "$base_log" \
  go -count=1 "$@"); then
  base_rc=0
else
  base_rc=$?
fi
if [ "$base_rc" -eq 3 ]; then
  printf 'VOID: base Go package tests timed out at %s\n' "$BASE" >&2
  exit 3
fi
if [ "$base_rc" -gt 1 ]; then
  printf 'VOID: unable to run base Go packages at %s (runner rc=%s)\n' \
    "$BASE" "$base_rc" >&2
  exit 2
fi
base_failed=$(failed_packages "$base_log")
if [ "$base_rc" -eq 1 ] && [ -z "$base_failed" ]; then
  printf 'VOID: base %s failed without package-level test results\n' "$BASE" >&2
  exit 2
fi

regression=0
for package in $head_failed; do
  case " $base_failed " in
    *" $package "*)
      printf 'BASELINE-RED: %s fails at both base %s and head %s\n' \
        "$package" "$BASE" "$HEAD" >&2
      ;;
    *)
      printf 'REGRESSION: %s passed at base %s but fails at head %s\n' \
        "$package" "$BASE" "$HEAD" >&2
      regression=1
      ;;
  esac
done
exit "$regression"
