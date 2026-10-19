#!/usr/bin/env bash
# Self-test for the #14647 affected-Go-test selector contract.
#
# The defect: scripts/ci_affected_go_tests.sh seeded only from the owning
# or nearest Go package, closed over reverse imports only, and silently
# exited 0 ("No changed Go source package") for every other path. Go
# tests that read the tree by path -- Rust sources, docs, manifests --
# and the import-less census packages (docsref, memlockcensus,
# refactoraudit, showaudit) therefore never ran on the change shapes
# that break them; pkg/memlockcensus stayed red on master from
# aaf85dbda6 because the introducing PR never selected it.
#
# This self-test pins, against real commits and a synthetic repo:
#   1. --list 7ade1a12a3^ 7ade1a12a3 (Rust-only) selects
#      pkg/dataplane/userspace (fallback seeds all, never nothing).
#   2. --list aaf85dbda6^ aaf85dbda6 selects pkg/memlockcensus
#      (always-appended census packages).
#   3. A Go-only change in a temp clone still selects the census
#      packages (always-append is not the all-seed fallback).
#   4. A docs/log-only change selects exactly the census packages
#      (explicit never-read allowlist, not the all-seed fallback).
#   5. census_packages in the selector matches the live set of
#      import-less tree-scanning packages, so a new census package
#      cannot appear unlisted (and a renamed one fails closed here
#      before it fails closed in CI).
#
# Hermetic except for `go list` over this repo and the two real-commit
# legs, which need the commits present (they are on master). No cluster,
# no network.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
selector="$here/ci_affected_go_tests.sh"

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  ok   %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  FAIL %s\n' "$1"; }
contains() { # <haystack> <needle> <name>
  case " $1 " in
    *" $2 "*) ok "$3" ;;
    *) bad "$3: [$2] not in selection" ;;
  esac
}

cd "$root" || { echo "FATAL: cannot cd to repo root" >&2; exit 1; }

for c in 7ade1a12a3 aaf85dbda6; do
  if ! git rev-parse --verify --quiet "$c^{commit}" >/dev/null; then
    echo "FATAL: required commit $c not present in this clone" >&2
    exit 1
  fi
done

# ── 1. Rust-only change: fallback seeds all, never nothing ──
out=$(bash "$selector" --list 7ade1a12a3^ 7ade1a12a3 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "rust-only: selector exits 0" || bad "rust-only: rc=$rc out=$out"
sel=${out#Affected Go packages: }
contains "$sel" "github.com/psaab/xpf/pkg/dataplane/userspace" \
  "rust-only: pkg/dataplane/userspace selected"
contains "$sel" "github.com/psaab/xpf/pkg/memlockcensus" \
  "rust-only: census package selected"

# ── 2. The commit that broke memlockcensus selects it ──
out=$(bash "$selector" --list aaf85dbda6^ aaf85dbda6 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "aaf85: selector exits 0" || bad "aaf85: rc=$rc out=$out"
sel=${out#Affected Go packages: }
contains "$sel" "github.com/psaab/xpf/pkg/memlockcensus" \
  "aaf85: pkg/memlockcensus selected"

# ── 3+4. Synthetic repo: always-append vs never-read allowlist ──
# A throwaway clone at HEAD with two synthetic commits, so the legs do
# not depend on finding suitable real commits for these shapes.
tmp=$(mkdir -p /var/worktrees/.cache/tmpdir && TMPDIR=/var/worktrees/.cache/tmpdir mktemp -d)
trap 'rm -rf "$tmp"' EXIT
git clone --quiet --no-hardlinks "$root" "$tmp/clone" 2>/dev/null
git -C "$tmp/clone" checkout --quiet -B selftest HEAD
git -C "$tmp/clone" config user.email selftest@example.invalid
git -C "$tmp/clone" config user.name selftest

# 3. Go-only change: one owning package plus exactly the census set
#    beyond its reverse-dependency closure is hard to predict, so assert
#    the census packages are present (the always-append), not the set.
printf '\n// selftest touch\n' >> "$tmp/clone/pkg/memlockcensus/registry.go"
git -C "$tmp/clone" add pkg/memlockcensus/registry.go
git -C "$tmp/clone" commit --quiet -m "selftest: go-only change"
out=$(cd "$tmp/clone" && bash "$selector" --list HEAD^ HEAD 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "go-only: selector exits 0" || bad "go-only: rc=$rc out=$out"
sel=${out#Affected Go packages: }
for p in docsref durationaudit memlockcensus refactoraudit showaudit; do
  contains "$sel" "github.com/psaab/xpf/pkg/$p" "go-only: census pkg/$p appended"
done

# 4. docs/log-only change: the census packages plus their reverse
#    dependents (structaudit imports refactoraudit), and nothing else.
#    This distinguishes the never-read allowlist from the all-seed
#    fallback: a selector that simply seeds all for non-Go paths fails
#    this leg, and one that seeds nothing fails it too.
printf '# selftest\n' > "$tmp/clone/docs/log/14647-selftest.md"
git -C "$tmp/clone" add docs/log/14647-selftest.md
git -C "$tmp/clone" commit --quiet -m "selftest: docs/log-only change"
out=$(cd "$tmp/clone" && bash "$selector" --list HEAD^ HEAD 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "docs/log-only: selector exits 0" || bad "docs/log-only: rc=$rc out=$out"
sel=${out#Affected Go packages: }
want="github.com/psaab/xpf/pkg/docsref github.com/psaab/xpf/pkg/durationaudit github.com/psaab/xpf/pkg/memlockcensus github.com/psaab/xpf/pkg/refactoraudit github.com/psaab/xpf/pkg/refactoraudit/structaudit github.com/psaab/xpf/pkg/showaudit"
if [ "$sel" = "$want" ]; then
  ok "docs/log-only: exactly census packages + reverse dependents"
else
  bad "docs/log-only: want [$want] got [$sel]"
fi

# 4b. (#15241 A58-01) A change to a Go file another package's test reads
#     by relative path selects the reading package. denyaudit's
#     sites_9042_test.go opens ../grpcapi/authz.go and asserts denyRPC
#     routes through denyaudit.Note; grpcapi imports denyaudit, so the
#     reverse-import closure from grpcapi can never reach denyaudit.
#     Appending a denyRPC mutant comment must still select denyaudit
#     via the reads-source-of edge derived from the path literal. The
#     mutant keeps the tree compiling, because the selector runs
#     `go list` over the whole module; the test itself is never run
#     here — selection is the property under test.
printf '\n// selftest source-read mutant (#15241)\n' >> "$tmp/clone/pkg/grpcapi/authz.go"
git -C "$tmp/clone" add pkg/grpcapi/authz.go
git -C "$tmp/clone" commit --quiet -m "selftest: denyRPC source-read mutant"
out=$(cd "$tmp/clone" && bash "$selector" --list HEAD^ HEAD 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "source-read: selector exits 0" || bad "source-read: rc=$rc out=$out"
sel=${out#Affected Go packages: }
contains "$sel" "github.com/psaab/xpf/pkg/grpcapi" \
  "source-read: owning pkg/grpcapi selected"
contains "$sel" "github.com/psaab/xpf/pkg/denyaudit" \
  "source-read: pkg/denyaudit selected via reads-source-of edge (A58-01)"
git -C "$tmp/clone" reset --quiet --hard HEAD^

# 4c. (#15241 A58-03) A cross-package rename selects BOTH packages. git
#     diff --name-only reports only the destination of a rename, so the
#     source package — whose tests may no longer compile — was never
#     selected. --no-renames reports the delete and the add separately.
#     git mv keeps the file content byte-identical so git detects the
#     rename; the selector must still select the source package.
git -C "$tmp/clone" mv cmd/shimverify/main.go cmd/shim-manifest/zz_main_15241.go
git -C "$tmp/clone" commit --quiet -m "selftest: cross-package move"
out=$(cd "$tmp/clone" && bash "$selector" --list HEAD^ HEAD 2>&1); rc=$?
[ "$rc" -eq 0 ] && ok "rename: selector exits 0" || bad "rename: rc=$rc out=$out"
sel=${out#Affected Go packages: }
contains "$sel" "github.com/psaab/xpf/cmd/shimverify" \
  "rename: source cmd/shimverify selected (A58-03)"
contains "$sel" "github.com/psaab/xpf/cmd/shim-manifest" \
  "rename: destination cmd/shim-manifest selected"
git -C "$tmp/clone" reset --quiet --hard HEAD^

# ── 5. census_packages matches the live census packages ──
# The selector's census list must equal the pkg/ packages that declare
# a repo-wide census (doc.go or census test header) and that no package
# imports through a regular import, ignoring a subpackage importing
# its parent (structaudit -> refactoraudit). That set today is
# docsref, durationaudit, memlockcensus, refactoraudit and showaudit.
# A new package meeting both halves, or a listed package that stops
# meeting them, fails here instead of silently never running (or
# silently always running).
expected=$(python3 - <<'PY'
import json, os, re, subprocess

listed = subprocess.run(
    ["go", "list", "-json", "./..."], check=True, capture_output=True, text=True
).stdout
dec = json.JSONDecoder()
pkgs = {}
i = 0
while i < len(listed):
    while i < len(listed) and listed[i].isspace():
        i += 1
    if i >= len(listed):
        break
    p, i = dec.raw_decode(listed, i)
    pkgs[p["ImportPath"]] = p

imported = set()
for importer, p in pkgs.items():
    for imp in p.get("Imports", []):
        # A subpackage importing its parent (structaudit ->
        # refactoraudit) makes the parent reachable only from inside
        # its own tree, not from any scanned package; that does not
        # count as an import edge for census purposes.
        if importer.startswith(imp + "/"):
            continue
        imported.add(imp)

# Declared repo-wide censuses: doc.go (or the census test header, for
# durationaudit which has no doc.go) claiming a repo-wide / tree /
# cross-package census. Bounded scans (denyaudit's sibling-file check)
# do not claim this and are excluded.
claim = re.compile(r"repo-wide|repository-wide|cross-cutting|cross-package|in the tree|every .* in the tree", re.I)
scan = re.compile(
    r"filepath\.Walk|WalkDir|exec\.Command|go/parser"
)
census = []
for path, p in sorted(pkgs.items()):
    if not path.startswith("github.com/psaab/xpf/pkg/"):
        continue
    if path in imported:
        continue
    files = p.get("GoFiles", []) + p.get("TestGoFiles", []) + p.get("XTestGoFiles", [])
    texts = []
    for f in files:
        try:
            texts.append(open(os.path.join(p["Dir"], f), encoding="utf-8", errors="ignore").read())
        except OSError:
            pass
    if any(claim.search(t) for t in texts) and any(scan.search(t) for t in texts):
        census.append(path)
print(" ".join(census))
PY
)
listed_census=$(python3 - <<'PY'
import re
text = open("scripts/ci_affected_go_tests.sh", encoding="utf-8").read()
m = re.search(r"census_packages = \{([^}]*)\}", text)
if not m:
    print("MISSING")
else:
    print(" ".join(sorted(re.findall(r'"([^"]+)"', m.group(1)))))
PY
)
if [ "$listed_census" = "MISSING" ]; then
  bad "census-sync: census_packages block not found in selector"
elif [ "$listed_census" = "$expected" ]; then
  ok "census-sync: selector census_packages matches live tree-scanners"
else
  bad "census-sync: selector lists [$listed_census] but tree has [$expected]"
fi

printf '\nci_affected_go_tests_selftest: passed=%d failed=%d\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
