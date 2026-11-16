#!/usr/bin/env bash
# Self-test for scripts/go-fortest-liveness-census.sh (#17342). Hermetic:
# fixture Go trees and baselines under a temp dir, plus one run over the real
# tree. Needs python3 (the census engine); SKIPs (77) without it.
#
# Every claim is paired with a fixture the census must REJECT, because a census
# that cannot be made to fail is indistinguishable from one that checks
# nothing. Cells:
#   - live: a hook called from a _test.go file passes;
#   - comment only (the #17342 trap): a hook whose only mentions are its godoc
#     and a comment elsewhere FAILS, naming it;
#   - method hook: an uncalled `func (x *T) ...ForTesting(` FAILS, the shape
#     deadcode cannot see;
#   - baselined dead hook passes; a baseline row whose hook gained a caller,
#     or was deleted, FAILS as stale;
#   - a malformed baseline row FAILS; a tree with no hooks is exit 2;
#   - the real tree passes.
# Mutants: counting comment lines as callers makes the comment-only cell
# pass, and dropping the stale-row check makes the gained-a-caller cell pass.
set -uo pipefail

here=$(cd "$(dirname "$0")" && pwd)
census="$here/go-fortest-liveness-census.sh"
if ! command -v python3 >/dev/null 2>&1; then
	echo "SKIP: python3 not installed"
	exit 77
fi
if [[ ! -f "$census" ]]; then
	echo "FAIL: $census is missing; every cell below would pass for the wrong reason"
	exit 1
fi
tmp=$(mktemp -d "${TMPDIR:-/tmp}/fortest-liveness-selftest.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS: $*"; }
bad() { fail=$((fail + 1)); echo "FAIL: $*"; }

# tree <name>: a fixture module with one live hook (called from a test).
tree() {
	mkdir -p "$tmp/$1/pkg/a"
	cat >"$tmp/$1/pkg/a/a.go" <<'GO'
package a

// FooForTest is called by a_test.go.
func FooForTest() int { return 1 }
GO
	cat >"$tmp/$1/pkg/a/a_test.go" <<'GO'
package a

import "testing"

func TestFoo(t *testing.T) { _ = FooForTest() }
GO
	: >"$tmp/$1.allow"
}
# run <script> <tree> [allow]: prints rc; output in $tmp/<tree>.out
run() {
	local rc=0
	FORTEST_ROOT="$tmp/$2" FORTEST_ALLOW="${3:-$tmp/$2.allow}" sh "$1" >"$tmp/$2.out" 2>&1 || rc=$?
	echo "$rc"
}
show() { tr '\n' '|' <"$tmp/$1.out"; }

tree live
rc=$(run "$census" live)
if [[ "$rc" == 0 ]]; then ok "live: a hook called from a _test.go file passes"; else bad "live: rc=$rc $(show live)"; fi

tree comment
cat >"$tmp/comment/pkg/a/b.go" <<'GO'
package a

// BarForTest replaces the clock. Test-only.
func BarForTest() {}
GO
cat >"$tmp/comment/pkg/a/c.go" <<'GO'
package a

// Tests call BarForTest to freeze time.
var _ = 0
GO
rc=$(run "$census" comment)
if [[ "$rc" == 1 ]] && grep -q 'BarForTest has no caller' "$tmp/comment.out"; then
	ok "comment only: a hook mentioned only in comments FAILS, named"
else
	bad "comment only: rc=$rc $(show comment)"
fi

tree method
cat >"$tmp/method/pkg/a/m.go" <<'GO'
package a

type T struct{ v int }

func (x *T) SetVForTesting(v int) { x.v = v }
GO
rc=$(run "$census" method)
if [[ "$rc" == 1 ]] && grep -q 'SetVForTesting has no caller' "$tmp/method.out"; then
	ok "method hook: an uncalled exported method FAILS, named"
else
	bad "method hook: rc=$rc $(show method)"
fi

tree based
cp "$tmp/comment/pkg/a/b.go" "$tmp/based/pkg/a/b.go"
printf 'BarForTest\tpkg/a/b.go\tkept for a pending test\n' >"$tmp/based.allow"
rc=$(run "$census" based)
if [[ "$rc" == 0 ]]; then ok "baselined: a dead hook with a baseline row passes"; else bad "baselined: rc=$rc $(show based)"; fi

tree gained
cp "$tmp/comment/pkg/a/b.go" "$tmp/gained/pkg/a/b.go"
printf 'package a\n\nfunc useBar() { BarForTest() }\n' >"$tmp/gained/pkg/a/use.go"
printf 'BarForTest\tpkg/a/b.go\tkept for a pending test\n' >"$tmp/gained.allow"
rc=$(run "$census" gained)
if [[ "$rc" == 1 ]] && grep -q 'BarForTest .* is stale: the hook now has a caller' "$tmp/gained.out"; then
	ok "stale row: a baselined hook that gained a caller FAILS"
else
	bad "stale row (caller): rc=$rc $(show gained)"
fi

tree gone
printf 'GoneForTest\tpkg/a/gone.go\twas here\n' >"$tmp/gone.allow"
rc=$(run "$census" gone)
if [[ "$rc" == 1 ]] && grep -q 'GoneForTest .* is stale: the hook is gone' "$tmp/gone.out"; then
	ok "stale row: a baselined hook that was deleted FAILS"
else
	bad "stale row (gone): rc=$rc $(show gone)"
fi

tree malformed
printf 'JustAName\n' >"$tmp/malformed.allow"
rc=$(run "$census" malformed)
if [[ "$rc" == 1 ]] && grep -q 'want <name>' "$tmp/malformed.out"; then
	ok "malformed baseline row FAILS"
else
	bad "malformed row: rc=$rc $(show malformed)"
fi

mkdir -p "$tmp/empty/pkg/a"
printf 'package a\n\nfunc F() {}\n' >"$tmp/empty/pkg/a/a.go"
: >"$tmp/empty.allow"
rc=$(run "$census" empty)
if [[ "$rc" == 2 ]]; then ok "no hooks: a tree with nothing to vouch for is exit 2, not a pass"; else bad "no hooks: rc=$rc $(show empty)"; fi

rc=0
sh "$census" >"$tmp/real.out" 2>&1 || rc=$?
if [[ "$rc" == 0 ]]; then ok "real tree: $(head -1 "$tmp/real.out")"; else bad "real tree: rc=$rc $(show real)"; fi

# mutate <name> <sed expr> <fixture> <expect>: the mutant must flip the cell.
mutate() {
	sed "$2" "$census" >"$tmp/$1.sh"
	if cmp -s "$census" "$tmp/$1.sh"; then
		bad "mutation $1: the anchor was not found"
		return
	fi
	local rc
	rc=$(run "$tmp/$1.sh" "$3")
	if [[ "$rc" == "$4" ]]; then
		ok "mutation $1: the $3 cell flips (rc=$rc)"
	else
		bad "mutation $1: the $3 cell did not flip (rc=$rc); it cannot see the defect"
	fi
}
mutate comments-count 's/code = line.split("\/\/", 1)\[0\]  # a comment is not a caller/code = line/' comment 0
mutate no-stale-check 's/^    if name not in dead:$/    if False:/' gained 0

echo "go-fortest-liveness-census selftest: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
