#!/usr/bin/env bash
# Self-test for scripts/go-skip-census.sh (#9052 item 4). Hermetic: a synthetic
# tree of _test.go fixtures, no repo scan, no network.
#
# THE CELLS THAT MATTER ARE THE POSITIVE CONTROLS. A census is a gate, and a
# gate that cannot be made to FAIL is indistinguishable from one that examines
# nothing — which is the defect this whole issue is about. So every claim below
# is paired with a fixture the census MUST reject.
set -u
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PASS: $*"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $*"; }

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
# The census script must EXIST before any cell runs. Without this, a missing
# path makes every `rc != 0` positive control below pass for the wrong reason
# — a control that fires on the harness rather than on the subject is not a
# control. Measured: it scored 3 false PASSes before this guard was added.
[ -f "$ROOT/scripts/go-skip-census.sh" ] || {
	echo "FAIL: $ROOT/scripts/go-skip-census.sh not found — every positive"
	echo "      control below would pass on the missing file instead of on the census."
	exit 1
}
# python3 is the census engine; without it the script under test exits 77, and
# every cell below would fail on the harness rather than on the subject.
if ! command -v python3 >/dev/null 2>&1; then
	echo "SKIP: python3 not installed — cannot run the census self-test"
	exit 77
fi
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/pkg/alpha" "$WORK/pkg/beta"

cat > "$WORK/pkg/alpha/a_test.go" <<'GO'
package alpha
func TestOne(t *testing.T)   { t.Skip("needs root to write /etc/shadow") }
func TestTwo(t *testing.T)   { t.Skip("running as root: the 0000 dir is readable") }
func TestThree(t *testing.T) { t.Skip("no incus binary in this environment") }
GO
cat > "$WORK/pkg/beta/b_test.go" <<'GO'
package beta
func TestFour(t *testing.T) { t.SkipNow() }
func TestFive(t *testing.T) { t.Skip(someReason) }
GO

FLOORS="$WORK/floors"
run_census() { ( GO_SKIP_ROOT="$WORK" GO_SKIP_DIRS=pkg GO_SKIP_FLOORS="$FLOORS" \
	sh "$ROOT/scripts/go-skip-census.sh" 2>&1 ); }

# ── 1. Classification, including BOTH directions of privilege dependence ──
cat > "$FLOORS" <<'F'
total = 5
priv-absent = 1
priv-present = 1
other = 1
unparsed = 2
F
out=$(run_census); rc=$?
[ "$rc" = "0" ] && ok "a tree matching its floors is OK" || { bad "clean tree failed: $out"; }
echo "$out" | grep -qE "^ +priv-absent +1( |$)" && ok "a 'needs root' skip lands in priv-absent" ||
	bad "priv-absent misclassified"
echo "$out" | grep -qE "^ +priv-present +1( |$)" && ok "a 'running as root' skip lands in priv-present — the INVERSE direction, which a single 'root-gated' bucket would hide" ||
	bad "priv-present misclassified"
echo "$out" | grep -q "NO SINGLE RUN EXAMINES" &&
	ok "the census states that no single run examines both privilege groups" ||
	bad "the census does not report the two-direction finding"

# ── 2. THE LOAD-BEARING ONE: what it cannot parse is COUNTED, not dropped ──
# t.SkipNow() has no message by construction; t.Skip(someReason) has a
# non-literal one. A census that silently dropped these would shrink its own
# population exactly where somebody wrote something unusual.
echo "$out" | grep -qE "^ +unparsed +2( |$)" &&
	ok "SkipNow() and a non-literal message are COUNTED in a named 'unparsed' bucket, not dropped" ||
	bad "unparsed bucket is wrong — a dropped site is a silently shrinking population"
echo "$out" | grep -q "t.SkipNow() carries no message" &&
	ok "the unparsed sites are listed BY NAME, so an auditor can see what was not classified" ||
	bad "unparsed sites are not named"

# ── 3. POSITIVE CONTROL: a NEW skip must red. This is the subject mutation ──
cat >> "$WORK/pkg/beta/b_test.go" <<'GO'
func TestSix(t *testing.T) { t.Skip("a brand new unexplained skip") }
GO
out=$(run_census); rc=$?
[ "$rc" != "0" ] && ok "positive control: a NEW skip reds the census" ||
	bad "a new skip did NOT red the census — it reports a clean board for a subject the suite stopped examining"
echo "$out" | grep -q "total grew 5 -> 6" && ok "the failure names the delta" || bad "no delta in the failure"

# ── 4. POSITIVE CONTROL: good news must red too, or a fix is never banked ──
sed -i 's/func TestSix.*$//' "$WORK/pkg/beta/b_test.go"
sed -i 's/^total = 5/total = 9/' "$FLOORS"
out=$(run_census); rc=$?
[ "$rc" != "0" ] && ok "positive control: a floor left LOOSE reds as GOOD NEWS" ||
	bad "a loose floor passed — that is exactly the room the next regression hides in"
echo "$out" | grep -q "GOOD NEWS" && ok "the good-news branch is labelled as such" || bad "good news not labelled"

# ── 5. POSITIVE CONTROL: an UNDECLARED bucket must red, not default to zero ──
sed -i 's/^total = 9/total = 5/' "$FLOORS"
sed -i '/^unparsed/d' "$FLOORS"
out=$(run_census); rc=$?
[ "$rc" != "0" ] && ok "positive control: a bucket with no declared floor reds" ||
	bad "an undeclared bucket passed — it would ratchet against nothing"
echo "$out" | grep -q "no floor declared for 'unparsed'" &&
	ok "the failure names the undeclared bucket" || bad "undeclared bucket not named"

# ── 6. An EMPTY sweep is not a pass ──
mkdir -p "$WORK/empty"
out=$( GO_SKIP_ROOT="$WORK" GO_SKIP_DIRS=empty GO_SKIP_FLOORS="$FLOORS" \
	sh "$ROOT/scripts/go-skip-census.sh" 2>&1 )
echo "$out" | grep -q "0 skip call sites" &&
	ok "an empty scan reports 0 rather than silently succeeding on a population it never found" ||
	bad "empty scan output is not explicit: $out"

echo
echo "  go-skip census selftest: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
# An empty sweep is not a pass: if the cells stopped executing, PASS is 0 and
# this is the only thing that says so.
[ "$PASS" -gt 0 ] || { echo "FAIL: the selftest ran ZERO cells" >&2; exit 1; }
exit 0
