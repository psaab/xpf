#!/usr/bin/env bash
# Self-test for scripts/go-buildtag-census.sh (#9922 F-159).
#
# Hermetic: fixture trees under a mktemp -d, plus a STUB go that emulates
# `go vet` (fails when the package carries a STUB_VET_FAIL marker) so every
# fixture cell runs without a toolchain. Two cells use the REAL go when it
# is present — the positive control on the real `functional1944` file and a
# real uncompilable-tagged negative — and SKIP with a note when it is not.
#
# THE CELLS THAT MATTER ARE THE ONES THAT MUST FAIL. A census is a gate, and
# a gate that cannot be made to FAIL is indistinguishable from one that
# examines nothing — which is the defect this whole cohort is about. So the
# FAIL branches (uncompilable tag, fail-closed blindness) are asserted by
# fixtures the census MUST reject, each paired with a near-twin it MUST
# accept, because a census that reddened on everything would satisfy every
# failure cell while being useless.
set -u

PASS=0; FAIL=0; SKIPPED=0
ok()   { PASS=$((PASS+1)); echo "PASS: $*"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL: $*"; }
skip() { SKIPPED=$((SKIPPED+1)); echo "SKIP: $*"; }

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CENSUS="$ROOT/scripts/go-buildtag-census.sh"
SH_BIN=$(command -v sh)

# The census script must EXIST before any cell runs. Without this, a missing
# path makes every `rc != 0` positive control below pass for the wrong reason
# — a control that fires on the harness rather than on the subject is not a
# control.
[ -f "$CENSUS" ] || {
	echo "FAIL: $CENSUS not found — every positive control below would"
	echo "      pass on the missing file instead of on the census."
	exit 1
}

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# ── stub go: emulates `go vet -tags <tag> ./<pkgdir>` ──
# Exits 1 when any file under the package dir carries STUB_VET_FAIL, else 0,
# and appends every invocation to $STUB_GO_LOG so cells can assert the leg
# actually ran (with the right -tags), not merely that the verdict flipped.
STUB_GO="$WORK/stubbin/go"
mkdir -p "$WORK/stubbin"
cat >"$STUB_GO" <<'EOF'
#!/bin/sh
echo "$@" >>"$STUB_GO_LOG"
dir=""
for a in "$@"; do
	case "$a" in
		./*) dir="$a" ;;
	esac
done
if [ -n "$dir" ] && grep -rq "STUB_VET_FAIL" "$dir" 2>/dev/null; then
	echo "stub-go: $dir does not compile (STUB_VET_FAIL marker)" >&2
	exit 1
fi
exit 0
EOF
chmod +x "$STUB_GO"

new_fixture() { # new_fixture <name> -> echoes the fixture root
	local fx="$WORK/fx-$1"
	mkdir -p "$fx/pkg"
	echo "$fx"
}

# run_census <fx> <known> <log> -> prints merged output, returns census rc.
# KNOWN is per-fixture: point it at the tagged file when the cell wants the
# fail-closed control to pass, at an absent path when the cell wants it out
# of the way, at a present-but-untagged file when the cell wants it to trip.
run_census() {
	GO_BUILDTAG_ROOT="$1" GO_BUILDTAG_DIRS="pkg" GO_BUILDTAG_KNOWN="$2" \
	GO="$STUB_GO" STUB_GO_LOG="$3" "$SH_BIN" "$CENSUS" 2>&1
}

# ── 1. clean tagged tree: PASS, and the row is VISIBLE ──
# Visibility is the missing census row: the file AND its constraint must be
# named, or an auditor cannot tell "one tag, vetted" from "nothing scanned".
FX1=$(new_fixture clean)
mkdir -p "$FX1/pkg/alpha"
cat >"$FX1/pkg/alpha/alpha.go" <<'GO'
package alpha
func Alpha() int { return 1; }
GO
cat >"$FX1/pkg/alpha/alpha_tagged_test.go" <<'GO'
//go:build fixtag

package alpha

import "testing"

func TestAlpha(t *testing.T) {
	if Alpha() != 1 {
		t.Fatal("nope")
	}
}
GO
LOG1="$WORK/log1"; : >"$LOG1"
out=$(run_census "$FX1" "pkg/alpha/alpha_tagged_test.go" "$LOG1"); rc=$?
[ "$rc" = "0" ] && ok "clean tagged tree passes" || bad "clean tagged tree failed (rc=$rc): $out"
echo "$out" | grep -q "pkg/alpha/alpha_tagged_test.go: //go:build fixtag" \
	&& ok "the census row names the file AND its constraint" \
	|| bad "census row missing file/constraint: $out"
grep -q -- "-tags fixtag" "$LOG1" \
	&& ok "the compile leg ran with -tags fixtag" \
	|| bad "vet leg never invoked (stub log empty): $(cat "$LOG1")"

# ── 2. POSITIVE CONTROL: tagged but uncompilable MUST fail ──
# The defect this census exists to catch: a tagged file rotting outside the
# default gate. The marker is the stub's emulation of a compile error; cell 7
# repeats this shape with the real toolchain.
FX2=$(new_fixture broken)
mkdir -p "$FX2/pkg/beta"
cat >"$FX2/pkg/beta/beta.go" <<'GO'
package beta
func Beta() int { return 2; }
GO
cat >"$FX2/pkg/beta/beta_tagged_test.go" <<'GO'
//go:build fixtag

package beta

import "testing"

// STUB_VET_FAIL: emulates a file that no longer compiles under its tag.
var _ = undefinedSymbolBuildtag

func TestBeta(t *testing.T) {
	if Beta() != 2 {
		t.Fatal("nope")
	}
}
GO
LOG2="$WORK/log2"; : >"$LOG2"
out=$(run_census "$FX2" "pkg/beta/beta_tagged_test.go" "$LOG2"); rc=$?
[ "$rc" != "0" ] \
	&& ok "positive control: uncompilable tagged file fails the census" \
	|| bad "uncompilable tagged file did NOT fail the census — the compile leg has no teeth"
echo "$out" | grep -q "pkg/beta/beta_tagged_test.go" \
	&& ok "the failure names the rotting file" \
	|| bad "failure does not name the file: $out"
grep -q -- "-tags fixtag" "$LOG2" \
	&& ok "the failing verdict came from a -tags fixtag leg" \
	|| bad "FAIL arrived without the vet leg running: $(cat "$LOG2")"

# ── 3. misplaced constraint (AFTER ^package) is IGNORED ──
# Go ignores it too — a post-package //go:build line is a comment, a fixture
# literal, or prose (the retirement-boundary and osident canaries all carry
# such mentions). KNOWN points at an absent path: nothing tagged, nothing
# known, so the board is genuinely empty and must pass.
FX3=$(new_fixture misplaced)
mkdir -p "$FX3/pkg/gamma"
cat >"$FX3/pkg/gamma/gamma_test.go" <<'GO'
package gamma

import "testing"

//go:build fixtag

func TestGamma(t *testing.T) {}
GO
LOG3="$WORK/log3"; : >"$LOG3"
out=$(run_census "$FX3" "pkg/gamma/does-not-exist_test.go" "$LOG3"); rc=$?
[ "$rc" = "0" ] && ok "post-package constraint is ignored (empty board passes)" \
	|| bad "misplaced constraint tripped the census (rc=$rc): $out"
echo "$out" | grep -q "gamma_test.go: //go:build" \
	&& bad "misplaced constraint was listed as a census row: $out" \
	|| ok "misplaced constraint produces no census row"
[ -s "$LOG3" ] \
	&& bad "a vet leg ran for a misplaced constraint: $(cat "$LOG3")" \
	|| ok "no vet leg runs for a misplaced constraint"

# ── 4. complex expression: NEEDS-REVIEW, loud but non-failing ──
# The census has no compile leg for `!cgo` / `foo && bar`; it must SAY so on
# every run, not silently drop the file. None exist today — the first one
# must be impossible to miss, not impossible to land.
FX4=$(new_fixture complex)
mkdir -p "$FX4/pkg/delta"
cat >"$FX4/pkg/delta/delta.go" <<'GO'
package delta
func Delta() int { return 4; }
GO
cat >"$FX4/pkg/delta/delta_tagged_test.go" <<'GO'
//go:build linux && amd64

package delta

import "testing"

func TestDelta(t *testing.T) {}
GO
LOG4="$WORK/log4"; : >"$LOG4"
out=$(run_census "$FX4" "pkg/delta/delta_tagged_test.go" "$LOG4"); rc=$?
[ "$rc" = "0" ] && ok "complex constraint does not fail the census" \
	|| bad "complex constraint failed the census (rc=$rc): $out"
echo "$out" | grep -q "NEEDS-REVIEW: pkg/delta/delta_tagged_test.go" \
	&& ok "complex constraint is a loud NEEDS-REVIEW line" \
	|| bad "no NEEDS-REVIEW line for the complex constraint: $out"
[ -s "$LOG4" ] \
	&& bad "a vet leg ran for a complex constraint it cannot express: $(cat "$LOG4")" \
	|| ok "no vet leg runs for a complex constraint"

# ── 5. FAIL-CLOSED pair: blindness to the known file MUST fail ──
# (a) the trip: KNOWN exists on disk but discovery finds nothing (here the
# known-path file is untagged — the parse is blind to exactly what it must
# see). (b) the twin: same empty discovery with KNOWN absent passes, proving
# the trip is the blindness and not a blanket red on empty boards.
FX5=$(new_fixture blind)
mkdir -p "$FX5/pkg/eps"
cat >"$FX5/pkg/eps/eps_test.go" <<'GO'
package eps

import "testing"

func TestEps(t *testing.T) {}
GO
LOG5="$WORK/log5"; : >"$LOG5"
out=$(run_census "$FX5" "pkg/eps/eps_test.go" "$LOG5"); rc=$?
[ "$rc" != "0" ] \
	&& ok "fail-closed: known-present-but-undiscovered fails" \
	|| bad "fail-closed did NOT trip — a blind parse reports a clean board"
echo "$out" | grep -q "fail-closed" \
	&& ok "the fail-closed failure says so by name" \
	|| bad "fail-closed trip has no fail-closed text: $out"

LOG5b="$WORK/log5b"; : >"$LOG5b"
out=$(run_census "$FX5" "pkg/eps/does-not-exist_test.go" "$LOG5b"); rc=$?
[ "$rc" = "0" ] \
	&& ok "twin: empty discovery with the known file genuinely absent passes" \
	|| bad "twin failed (rc=$rc): $out"

# ── 6. no-go: SKIP 77 via an empty-PATH stub ──
# The hermetic-runner convention: "the measurement did not happen" is a skip,
# never green, never red. Absolute $SH_BIN because PATH cannot resolve `sh`
# once the stub is in place.
EMPTYBIN="$WORK/emptybin"; mkdir -p "$EMPTYBIN"
out=$(PATH="$EMPTYBIN" "$SH_BIN" "$CENSUS" 2>&1); rc=$?
[ "$rc" = "77" ] && ok "no-go exits 77 (SKIP)" || bad "no-go exited $rc, want 77: $out"
echo "$out" | grep -q "SKIP" && ok "no-go SKIP says so" || bad "no-go has no SKIP text: $out"

# ── 7. real-toolchain cells (gated on go) ──
if command -v go >/dev/null 2>&1; then
	# (a) positive control on the REAL tree: the functional1944 file must be
	# discovered, named, and vetted green. This is what `make test-go` runs.
	out=$("$SH_BIN" "$CENSUS" 2>&1); rc=$?
	[ "$rc" = "0" ] && ok "real tree passes" || bad "real tree failed (rc=$rc): $out"
	echo "$out" | grep -q "pkg/daemon/login_password_functional_test.go: //go:build functional1944" \
		&& ok "real tree names the functional1944 row" \
		|| bad "functional1944 row missing on the real tree: $out"

	# (b) real negative: a genuinely uncompilable tagged fixture must fail
	# under the real `go vet -tags`. go.mod pins an OLD go directive so no
	# toolchain fetch can fire; no external imports, so no network.
	FX7=$(new_fixture realbroken)
	mkdir -p "$FX7/pkg/broken"
	printf 'module buildtagfixt\n\ngo 1.21\n' >"$FX7/go.mod"
	cat >"$FX7/pkg/broken/broken.go" <<'GO'
package broken
func Broken() int { return 7; }
GO
	cat >"$FX7/pkg/broken/broken_test.go" <<'GO'
//go:build fixbroken

package broken

import "testing"

var _ = undefinedSymbolBuildtag1944

func TestBroken(t *testing.T) {}
GO
	out=$(GO_BUILDTAG_ROOT="$FX7" GO_BUILDTAG_DIRS="pkg" \
		GO_BUILDTAG_KNOWN="pkg/broken/broken_test.go" \
		"$SH_BIN" "$CENSUS" 2>&1); rc=$?
	[ "$rc" != "0" ] \
		&& ok "real-toolchain negative: uncompilable tagged fixture fails" \
		|| bad "real go vet passed an uncompilable tagged fixture — the leg is hollow"
	echo "$out" | grep -q "undefined" \
		&& ok "the real failure carries the vet diagnostic" \
		|| bad "no vet diagnostic in the real failure: $out"
else
	skip "real-toolchain cells (go not installed)"
fi

# ── summary ──
echo ""
echo "go-buildtag-census-selftest: passed=$PASS failed=$FAIL skipped=$SKIPPED"
[ "$FAIL" -eq 0 ] || exit 1
exit 0
