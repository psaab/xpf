#!/usr/bin/env bash
# Self-test for scripts/ignored-cell-census.sh (#8352). Hermetic: fixture trees
# under a mktemp -d and a MOCKED issue-state command. No cluster, no network.
#
# Usage: ./test/incus/ignored-cell-census-selftest.sh   (rc 0 = all pass)
#
# It is a gate ABOUT a gate, so every defence is asserted from BOTH sides: a
# fixture that must FAIL, and the nearly-identical fixture that must PASS. A
# census that reddened on everything would satisfy every failure cell here
# while being useless, and one that reddened on nothing would satisfy every
# pass cell; only having both aimed at the same distinction shows the census
# can tell them apart.
#
# Falsifiability of this file: if the census stops distinguishing a declared
# reason from an undeclared one, the paired cells disagree and the mismatch is
# named. If a fixture stops reaching the census at all, the arrange-side
# assertions (the census's own summary line) fail rather than a cell passing
# vacuously. On an empty fixture the census must FAIL, and that is its own cell.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CENSUS="${IGN_CENSUS_SCRIPT:-$ROOT/scripts/ignored-cell-census.sh}"

PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1"; FAIL=$((FAIL + 1)); }

WORK=$(mktemp -d "${TMPDIR:-/var/worktrees/.cache/tmpdir}/xpf-ignored-census.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# fixture <name> <rust-source-body> — a tree with one crate dir and one .rs file
fixture() {
	local name="$1" body="$2"
	local d="$WORK/$name/crate/src"
	mkdir -p "$d"
	printf '%s\n' "$body" >"$d/tests.rs"
	printf '%s\n' "$WORK/$name"
}

# run_census <root> [args...] — sets $CENSUS_RC and $CENSUS_OUT.
#
# It does NOT echo, and the callers do not wrap it in $( ). A command
# substitution runs the function in a SUBSHELL, so an rc assigned inside is
# discarded on return and every cell reads rc=0 -- which reads as "the census
# passed" and made four failure cells pass while the census was working
# correctly. Writing through a file survives.
CENSUS_RC=0
CENSUS_OUT=""
run_census() {
	local root="$1"
	shift
	IGN_CENSUS_ROOT="$root" IGN_CENSUS_DIRS="crate" sh "$CENSUS" "$@" >"$WORK/census.out" 2>&1
	CENSUS_RC=$?
	CENSUS_OUT=$(cat "$WORK/census.out")
}

# A mocked issue-state command: prints OPEN for every number except those in
# $CLOSED_IDS. Mocking is what keeps this hermetic AND lets the CLOSED branch
# be exercised, which is the branch that carries the whole point of the census.
# shellcheck disable=SC2034  # read by $WORK/gh-state through the environment
CLOSED_IDS=""
export CLOSED_IDS
cat >"$WORK/gh-state" <<'MOCK'
#!/bin/sh
for c in $CLOSED_IDS; do
	[ "$1" = "$c" ] && { echo CLOSED; exit 0; }
done
echo OPEN
MOCK
chmod +x "$WORK/gh-state"

# ── 1. A bare #[ignore] is a FAIL, and its declared twin is not ──────
bare=$(fixture bare '#[test]
#[ignore]
fn t() {}')
run_census "$bare"
if [[ $CENSUS_RC -ne 0 && "$CENSUS_OUT" == *"declares no kind"* && "$CENSUS_OUT" == *"tests.rs:2"* ]]; then
	ok "a bare #[ignore] fails and is named by file:line"
else
	bad "a bare #[ignore] was not reported (rc=$CENSUS_RC)"
fi

declared=$(fixture declared '#[test]
#[ignore = "MEASUREMENT: prints a rate; run with --ignored"]
fn t() {}')
run_census "$declared"
if [[ $CENSUS_RC -eq 0 && "$CENSUS_OUT" == *"1 measurement(s)"* ]]; then
	ok "the same cell WITH a MEASUREMENT marker passes"
else
	bad "a declared measurement was rejected (rc=$CENSUS_RC): $CENSUS_OUT"
fi

# ── 2. Prose is not a declaration ────────────────────────────────────
#
# The pre-#8352 spelling. Exempting it by matching the phrase would mean a
# reworded comment silently changes the cell's kind, so the marker is required
# and prose is UNDECLARED.
prose=$(fixture prose '#[test]
#[ignore = "measurement, not an assertion; run with --ignored --nocapture"]
fn t() {}')
run_census "$prose"
if [[ $CENSUS_RC -ne 0 && "$CENSUS_OUT" == *"declares no kind"* ]]; then
	ok "prose that only DESCRIBES a measurement is undeclared, not exempt"
else
	bad "prose was accepted as a declaration — a phrase test dies to paraphrase (rc=$CENSUS_RC)"
fi

# A reason that merely MENTIONS an issue is likewise not a declaration.
mention=$(fixture mention '#[test]
#[ignore = "flaky under load, see #7209 for context"]
fn t() {}')
run_census "$mention"
if [[ $CENSUS_RC -ne 0 && "$CENSUS_OUT" == *"declares no kind"* ]]; then
	ok "a reason that MENTIONS an issue is not thereby issue-linked"
else
	bad "a passing mention of #N was read as a declaration (rc=$CENSUS_RC)"
fi

# ── 3. The wake-up: an issue-linked cell reds when its issue CLOSES ──
linked=$(fixture linked '#[test]
#[ignore = "#7209: reds until sync_session is off the snapshot-wide mutex"]
fn t() {}')

# Both sides go through the MOCK: the OPEN side too, or it would reach the
# network and the cell would be measuring GitHub rather than the census.
CLOSED_IDS="" IGN_CENSUS_GH_STATE="$WORK/gh-state" run_census "$linked" --check-issues
rc_open=$CENSUS_RC
out_open=$CENSUS_OUT
CLOSED_IDS="7209" IGN_CENSUS_GH_STATE="$WORK/gh-state" run_census "$linked" --check-issues
rc_closed=$CENSUS_RC
out_closed=$CENSUS_OUT

if [[ $rc_open -eq 0 && "$out_open" == *"1 issue-linked"* ]]; then
	ok "an issue-linked cell passes while its issue is OPEN"
else
	bad "an issue-linked cell failed with the issue OPEN (rc=$rc_open): $out_open"
fi
if [[ $rc_closed -ne 0 && "$out_closed" == *"#7209 is CLOSED"* && "$out_closed" == *"tests.rs:2"* ]]; then
	ok "closing the issue REDS the census and names the cell to reactivate"
else
	bad "a CLOSED issue did not red the census (rc=$rc_closed): $out_closed"
fi

# ── 4. "Could not ask" is never "they are open" ──────────────────────
cat >"$WORK/gh-silent" <<'MOCK'
#!/bin/sh
exit 1
MOCK
chmod +x "$WORK/gh-silent"
IGN_CENSUS_GH_STATE="$WORK/gh-silent" run_census "$linked" --check-issues
if [[ $CENSUS_RC -ne 0 && "$CENSUS_OUT" == *"could not read the state"* ]]; then
	ok "an unreadable issue state FAILS rather than being read as open"
else
	bad "an unreadable issue state did not fail (rc=$CENSUS_RC): $CENSUS_OUT"
fi

# With no gh at all, the ISSUE half must SKIP (77), not silently pass. Built by
# running the census under a PATH that has the tools it needs and no gh.
mkdir -p "$WORK/nogh"
for t in sh grep sed cut sort awk wc; do
	p=$(command -v "$t" 2>/dev/null) && ln -sf "$p" "$WORK/nogh/$t"
done
if command -v gh >/dev/null 2>&1; then
	out=$(PATH="$WORK/nogh" IGN_CENSUS_ROOT="$linked" IGN_CENSUS_DIRS="crate" \
		sh "$CENSUS" --check-issues 2>&1)
	rc=$?
	if [[ $rc -eq 77 && "$out" == *"gh not installed"* ]]; then
		ok "with no gh the issue check SKIPs (77) rather than reporting the issues open"
	else
		bad "no-gh did not SKIP (rc=$rc): $out"
	fi
	# ...and the hermetic half still runs under the same conditions: an
	# undeclared cell must FAIL even when the issue check cannot run, or a
	# machine without gh would lose the census entirely.
	out=$(PATH="$WORK/nogh" IGN_CENSUS_ROOT="$bare" IGN_CENSUS_DIRS="crate" \
		sh "$CENSUS" --check-issues 2>&1)
	rc=$?
	if [[ $rc -eq 1 && "$out" == *"declares no kind"* ]]; then
		ok "with no gh the HERMETIC half still fails an undeclared cell (not a blanket SKIP)"
	else
		bad "no-gh turned the whole census into a skip (rc=$rc): $out"
	fi
else
	echo "  (skipped no-gh cells: gh is not installed, so the branch is the default)"
fi

# ── 5. An empty sweep is not a clean board ───────────────────────────
empty=$(fixture empty '#[test]
fn t() {}')
run_census "$empty"
if [[ $CENSUS_RC -ne 0 && "$CENSUS_OUT" == *"ZERO #[ignore] cells"* ]]; then
	ok "a tree with no #[ignore] cells FAILS rather than sweeping clean"
else
	bad "an empty sweep reported a clean board (rc=$CENSUS_RC)"
fi

# ── 6. MUTATION: break the classifier, the positive control must trip ─
#
# If the classifier stops recognising the issue form, every cell looks exempt
# and the board reads clean over an inverted world. Nothing but this control
# can tell that apart from a genuinely clean tree.
mutant="$WORK/mutant-census.sh"
python3 - "$CENSUS" "$mutant" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src, encoding="utf-8").read()
old = "\tn=$(printf '%s' \"$reason\" | sed -n 's/^#\\([0-9][0-9]*\\):.*/\\1/p')"
assert s.count(old) == 1, f"mutation anchor not found ({s.count(old)})"
open(dst, "w", encoding="utf-8").write(s.replace(old, '\tn=""'))
PY
out=$(IGN_CENSUS_SCRIPT="$mutant" IGN_CENSUS_ROOT="$linked" IGN_CENSUS_DIRS="crate" \
	sh "$mutant" 2>&1)
rc=$?
if [[ $rc -ne 0 && "$out" == *"positive control"* && "$out" == *"classifier is broken"* ]]; then
	ok "MUTATION: a classifier that never recognises an issue trips the positive control"
else
	bad "MUTATION ESCAPED: a broken classifier did not trip the control (rc=$rc): $out"
fi

# -- 7. MUTATION: widen/over-narrow the scan pattern; the control must trip --
#
# #8980: the scan matched `#[ignore` anywhere, so PROSE mentioning the
# attribute inside a doc comment counted as a cell. The census already had a
# control for the scan -- the ZERO-hits check in cell 5 -- and it could not
# see this: a non-zero-hits check bounds a pattern that is too TIGHT and is
# blind BY CONSTRUCTION to one that is too LOOSE. These mutants cover the
# other half of that space, one in each direction.
scan_mutant="$WORK/scan-mutant-census.sh"

# 7a. LOOSE: remove the comment filter from the composition entirely.
python3 - "$CENSUS" "$scan_mutant" <<'PYMUT'
import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src, encoding="utf-8").read()
old = "\tfi | drop_comment_lines\n"
assert s.count(old) == 1, f"loose-mutation anchor not found ({s.count(old)})"
open(dst, "w", encoding="utf-8").write(s.replace(old, "\tfi\n"))
PYMUT
out=$(IGN_CENSUS_SCRIPT="$scan_mutant" IGN_CENSUS_ROOT="$linked" IGN_CENSUS_DIRS="crate" \
	sh "$scan_mutant" 2>&1)
rc=$?
if [[ $rc -ne 0 && "$out" == *"scan-pattern control"* && "$out" == *"too-loose"* ]]; then
	ok "MUTATION: a scan that counts doc-comment prose trips the scan control"
else
	bad "MUTATION ESCAPED: a too-loose scan was not caught (rc=$rc): $out"
fi

# 7b. TIGHT: a filter that drops any line CONTAINING "//" instead of one in
# comment POSITION. It looks equivalent and silently discards every cell whose
# reason cites a URL -- also invisible to a zero-hits control, since plenty of
# cells would remain.
python3 - "$CENSUS" "$scan_mutant" <<'PYMUT'
import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src, encoding="utf-8").read()
old = "grep -vE '^[^:]*:[0-9]+:[[:space:]]*//'"
assert s.count(old) == 1, f"tight-mutation anchor not found ({s.count(old)})"
open(dst, "w", encoding="utf-8").write(s.replace(old, "grep -vE '//'"))
PYMUT
out=$(IGN_CENSUS_SCRIPT="$scan_mutant" IGN_CENSUS_ROOT="$linked" IGN_CENSUS_DIRS="crate" \
	sh "$scan_mutant" 2>&1)
rc=$?
if [[ $rc -ne 0 && "$out" == *"scan-pattern control"* && "$out" == *"too-tight"* ]]; then
	ok "MUTATION: a comment filter keyed on // anywhere trips the scan control"
else
	bad "MUTATION ESCAPED: an over-aggressive comment filter was not caught (rc=$rc): $out"
fi

echo
echo "  ignored-cell census selftest: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]] || exit 1
[[ "$PASS" -gt 0 ]] || {
	echo "FAIL: the selftest ran ZERO cells" >&2
	exit 1
}
exit 0
