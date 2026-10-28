#!/usr/bin/env bash
# Self-test for scripts/go-deadcode-gate.sh (#17154, R4-Q49-01). Hermetic:
# fixture deadcode output fed via DEADCODE_OUTPUT, fixture allowlists, no
# toolchain, no network, no repo scan.
#
# THE CELLS THAT MATTER ARE THE POSITIVE CONTROLS. A gate that cannot be
# made to FAIL is indistinguishable from one that examines nothing — the
# defect this whole issue is about. So every claim is paired: an exact
# fixture the gate must ACCEPT, and near-twins it must REJECT (a new dead
# function, a stale row, malformed rows), because a gate that reddened on
# everything would satisfy every failure cell while being useless.
#
# The ACCEPTANCE mutation of #17154 — re-adding one of bd3dee05c0's
# deleted wrappers without a caller — is cell 2: the wrapper's deadcode
# row appears with no allowlist row and the gate reds naming it.
set -u
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PASS: $*"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $*"; }

ROOT=$(cd "$(dirname "$0")/.." && pwd)
# The gate script must EXIST before any cell runs. Without this, a missing
# path makes every `rc != 0` positive control pass for the wrong reason —
# a control that fires on the harness rather than on the subject.
[ -f "$ROOT/scripts/go-deadcode-gate.sh" ] || {
	echo "FAIL: $ROOT/scripts/go-deadcode-gate.sh not found — every positive"
	echo "      control below would pass on the missing file instead of on the gate."
	exit 1
}
if ! command -v python3 >/dev/null 2>&1; then
	echo "SKIP: python3 not installed — cannot run the deadcode gate self-test"
	exit 77
fi
# #16477: fail loudly if mktemp cannot create the work dir.
WORK=$(mktemp -d) || { echo "FATAL: mktemp -d failed (TMPDIR=${TMPDIR:-unset})" >&2; exit 2; }
[ -n "$WORK" ] && [ -d "$WORK" ] || { echo "FATAL: work dir not created: '$WORK'" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT

GATE="$ROOT/scripts/go-deadcode-gate.sh"

# Fixture analyser output: two production rows (one a method), one test
# helper. Line numbers are deliberately arbitrary — the gate must compare
# (path, symbol), never the line.
BASE_OUT="$WORK/base.out"
cat > "$BASE_OUT" <<'EOF'
pkg/alpha/a.go:10:6: unreachable func: DeadAlpha
pkg/alpha/b.go:20:15: unreachable func: Widget.DeadMethod
pkg/alpha/a_test.go:5:6: unreachable func: deadTestHelper
EOF

BASE_ALLOW="$WORK/base.allow"
cat > "$BASE_ALLOW" <<'EOF'
# fixture allowlist
pkg/alpha/a.go	DeadAlpha	LEGACY-DEBT	pre-existing dead code at gate landing; delete per-package	#17154
pkg/alpha/b.go	Widget.DeadMethod	LEGITIMATE	compile-time guard assert; never called by design	#17154
pkg/alpha/a_test.go	deadTestHelper	LEGACY-DEBT	pre-existing dead test helper at gate landing	#17154
EOF

run_gate() { # run_gate <out> <allow> -> merged output; rc in $?
	DEADCODE_OUTPUT="$1" DEADCODE_ALLOWLIST="$2" GO_DEADCODE_ROOT="$WORK" sh "$GATE" 2>&1
}

# ── 1. Exact match is green, and the census states its reach ────────
out=$(run_gate "$BASE_OUT" "$BASE_ALLOW"); rc=$?
[ "$rc" = "0" ] && ok "an exact (path, symbol) match is green" || bad "exact match red: $out"
echo "$out" | grep -q "3 unreachable function(s) (1 LEGITIMATE + 2 LEGACY-DEBT" &&
	ok "the gate publishes its denominator (3 rows, split by class)" ||
	bad "denominator not published: $out"

# ── 2. POSITIVE CONTROL (the #17154 acceptance mutation): a NEW dead
# function — the re-added orphaned wrapper shape — reds, named. ──────
cp "$BASE_OUT" "$WORK/mut.out"
echo 'pkg/alpha/wrapper.go:42:6: unreachable func: readdedOrphanWrapper17154' >> "$WORK/mut.out"
out=$(run_gate "$WORK/mut.out" "$BASE_ALLOW"); rc=$?
[ "$rc" != "0" ] && ok "positive control: a new unreachable function reds the gate" ||
	bad "a new dead function did NOT red — the gate examines nothing"
echo "$out" | grep -q "readdedOrphanWrapper17154" &&
	ok "the failure names the new dead function" || bad "new dead function not named: $out"

# ── 3. POSITIVE CONTROL: a STALE row reds — the allowlist only shrinks.
# Removing DeadAlpha's analyser row (deleted, or called again) must not
# leave a silent carve-out behind. ────────────────────────────────────
grep -v DeadAlpha "$BASE_OUT" > "$WORK/shrunk.out"
out=$(run_gate "$WORK/shrunk.out" "$BASE_ALLOW"); rc=$?
[ "$rc" != "0" ] && ok "positive control: a stale allowlist row reds the gate" ||
	bad "a stale row passed — a deleted function's carve-out would survive silently"
echo "$out" | grep -q "stale allowlist" && echo "$out" | grep -q "DeadAlpha" &&
	ok "the failure names the stale row" || bad "stale row not named: $out"

# ── 4. Line numbers moving must NOT red: comparison is (path, symbol).
sed 's/:10:6:/:999:1:/; s/:20:15:/:7:3:/' "$BASE_OUT" > "$WORK/moved.out"
out=$(run_gate "$WORK/moved.out" "$BASE_ALLOW"); rc=$?
[ "$rc" = "0" ] && ok "shifted line numbers stay green (pair comparison, not line text)" ||
	bad "a line-number move reddened the gate: $out"

# ── 5. POSITIVE CONTROLS: malformed rows red, each named by line ────
# 5a: too few columns (space-joined instead of TAB).
printf 'pkg/alpha/a.go DeadAlpha LEGACY-DEBT reason #17154\n' > "$WORK/bad-cols.allow"
out=$(run_gate "$BASE_OUT" "$WORK/bad-cols.allow"); rc=$?
[ "$rc" != "0" ] && echo "$out" | grep -q "want 5 TAB-separated columns" &&
	ok "positive control: a non-TAB row reds as malformed" ||
	bad "a space-joined row was not rejected as malformed: $out"
# 5b: unknown class.
sed 's/LEGACY-DEBT/WHATEVER/' "$BASE_ALLOW" > "$WORK/bad-class.allow"
out=$(run_gate "$BASE_OUT" "$WORK/bad-class.allow"); rc=$?
[ "$rc" != "0" ] && echo "$out" | grep -q "class must be LEGITIMATE or LEGACY-DEBT" &&
	ok "positive control: an unknown row class reds" ||
	bad "an unknown class was accepted: $out"
# 5c: empty reason.
sed 's/pre-existing dead code at gate landing; delete per-package//' "$BASE_ALLOW" > "$WORK/bad-reason.allow"
out=$(run_gate "$BASE_OUT" "$WORK/bad-reason.allow"); rc=$?
[ "$rc" != "0" ] && echo "$out" | grep -q "empty reason" &&
	ok "positive control: a reasonless carve-out reds (#9590)" ||
	bad "a reasonless row was accepted: $out"
# 5d: empty expiry-or-issue.
sed 's/#17154$//' "$BASE_ALLOW" > "$WORK/bad-expiry.allow"
out=$(run_gate "$BASE_OUT" "$WORK/bad-expiry.allow"); rc=$?
[ "$rc" != "0" ] && echo "$out" | grep -q "empty expiry-or-issue" &&
	ok "positive control: a row with no issue/expiry reds" ||
	bad "a row with no issue/expiry was accepted: $out"
# 5e: duplicate row.
cat "$BASE_ALLOW" "$BASE_ALLOW" | grep -v '^#' > "$WORK/dup.allow"
out=$(run_gate "$BASE_OUT" "$WORK/dup.allow"); rc=$?
[ "$rc" != "0" ] && echo "$out" | grep -q "duplicate row" &&
	ok "positive control: a duplicate row reds" ||
	bad "a duplicate row was accepted: $out"

# ── 6. POSITIVE CONTROL: unparseable analyser output reds, never a
# clean board over output the gate could not read. ───────────────────
printf 'pkg/alpha/a.go:10:6: unreachable func: DeadAlpha\ngarbage line\n' > "$WORK/garbage.out"
out=$(run_gate "$WORK/garbage.out" "$BASE_ALLOW"); rc=$?
[ "$rc" != "0" ] && echo "$out" | grep -q "unparseable deadcode output line" &&
	ok "positive control: unparseable analyser output reds" ||
	bad "garbage analyser output was treated as a census: $out"

# ── 7. An EMPTY analyser output against a non-empty allowlist reds via
# the stale branch (it examined a tree and found nothing the rows claim).
: > "$WORK/empty.out"
out=$(run_gate "$WORK/empty.out" "$BASE_ALLOW"); rc=$?
[ "$rc" != "0" ] && echo "$out" | grep -q "stale allowlist" &&
	ok "empty output reds as stale rows, not as a clean sweep" ||
	bad "empty output passed over a non-empty allowlist: $out"

echo "  go-deadcode gate selftest: $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ] || exit 1
# An empty sweep is not a pass: if the cells stopped executing, PASS is 0
# and this is the only thing that says so.
[ "$PASS" -gt 0 ] || { echo "FAIL: the selftest ran ZERO cells" >&2; exit 1; }
exit 0
