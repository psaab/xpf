#!/usr/bin/env bash
# Self-test for scripts/mirror-census.py (#18645).
#
# Hermetic: fixture trees under a mktemp -d. No network, no git. Runs in about
# a second.
#
# WHY THIS EXISTS
#
# A mirror census whose comparison is broken reports every set of copies as
# identical, which is exactly what a correct census says about a tree whose
# copies agree. Only a mutation tells them apart. So each verdict is asserted
# twice: a fixture that must produce it, and a MUTATION of the line tagged
# `census-guard: <name>` that must make the same fixture stop producing it. A
# mutation that does not flip its cell is an ESCAPE and fails this self-test.
#
# The positive control runs the other way: copies that differ only in
# wrapping and indentation must PASS, and a census that compares raw text
# (normalisation removed) must fail them. Without it, a census that reds on
# every pair would satisfy every FAIL cell below.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CENSUS="${REPO_ROOT}/scripts/mirror-census.py"
PY="$(command -v python3 || true)"

PASS=0
FAIL=0
ok()  { echo "  ok   — $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL — $*" >&2; FAIL=$((FAIL + 1)); }

[[ -f "$CENSUS" ]] || { echo "FATAL: census not found at $CENSUS" >&2; exit 1; }
[[ -n "$PY" ]] || { echo "SKIP: python3 not installed" >&2; exit 77; }

if [[ -z "${TMPDIR:-}" ]]; then mkdir -p /var/worktrees/.cache/tmpdir; fi
WORK="$(mktemp -d "${TMPDIR:-/var/worktrees/.cache/tmpdir}/mirror-census-selftest.XXXXXX")" \
	|| { echo "FATAL: cannot create work dir" >&2; exit 2; }
[[ -n "$WORK" && -d "$WORK" ]] || { echo "FATAL: work dir not created: '$WORK'" >&2; exit 2; }
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

new_fixture() {
	local fx="$WORK/$1"
	mkdir -p "$fx/docs" "$fx/pkg/x"
	echo "$fx"
}

run_census() { # run_census <fx> <script>
	OUT=$(MIRROR_CENSUS_ROOT="$1" MIRROR_CENSUS_SCOPE="CLAUDE.md docs pkg" "$PY" "$2" 2>&1)
	RC=$?
}

mutant() {
	local name=$1
	shift
	local out="$WORK/mutant-$name.py" e
	cp "$CENSUS" "$out"
	for e in "$@"; do
		sed -i "$e" "$out"
	done
	if cmp -s "$CENSUS" "$out"; then
		bad "mutation '$name' changed NOTHING (a census-guard tag moved)"
	fi
	echo "$out"
}

guard_off() {
	printf '%s' "/census-guard: $1\$/s/if [^#]*:  # census-guard/if False:  # census-guard/"
}

assert_fails() { # <fx> <TAG> <label>
	run_census "$1" "$CENSUS"
	if [[ $RC -eq 1 && "$OUT" == *"FAIL: $2:"* ]]; then
		ok "$3"
	else
		bad "$3 (rc=$RC; expected a FAIL tagged $2)"
		printf '%s\n' "$OUT" | sed 's/^/         /' >&2
	fi
}

assert_flips() { # <fx> <TAG> <label> <mutant>
	run_census "$1" "$4"
	if [[ "$OUT" == *"FAIL: $2:"* ]]; then
		bad "$3 — mutation ESCAPED: the mutated census still reports $2"
		printf '%s\n' "$OUT" | sed 's/^/         /' >&2
	else
		ok "$3"
	fi
}

assert_clean() { # <fx> <blocks> <label>
	run_census "$1" "$CENSUS"
	if [[ $RC -eq 0 && "$OUT" == *"mirror census: $2 block(s)"* && "$OUT" == *"mirror census: OK"* ]]; then
		ok "$3"
	else
		bad "$3 (rc=$RC; expected a clean pass over $2 blocks)"
		printf '%s\n' "$OUT" | sed 's/^/         /' >&2
	fi
}

assert_not_clean() { # <fx> <blocks> <label> <mutant>
	run_census "$1" "$4"
	if [[ $RC -eq 0 && "$OUT" == *"mirror census: $2 block(s)"* ]]; then
		bad "$3 — mutation ESCAPED: the mutated census still passes over $2 blocks"
		printf '%s\n' "$OUT" | sed 's/^/         /' >&2
	else
		ok "$3"
	fi
}

# A valid pair used as ballast in the FAIL fixtures, so a mutant that stops
# seeing the defect yields a clean pass rather than an EMPTY failure.
add_pair() { # add_pair <fx> <id>
	printf '%s\n' "x <!-- mirror:$2 -->same words<!-- /mirror:$2 --> y" >"$1/docs/pair-$2-a.md"
	printf '%s\n' "<!-- mirror:$2 -->" "same" "words" "<!-- /mirror:$2 -->" >"$1/docs/pair-$2-b.md"
}

# ── positive control P: copies that differ only in wrapping and indentation ─
FX_P="$(new_fixture positive)"
cat >"$FX_P/docs/a.md" <<'MD'
- **Timing**: the threshold is interval × threshold. <!-- mirror:detect -->The receiver
  checks staleness every quarter interval, so a peer is declared within that
  check period.<!-- /mirror:detect --> Legacy VRRP is separate.
MD
cat >"$FX_P/pkg/x/README.md" <<'MD'
Heartbeat: 100ms × 5. <!-- mirror:detect -->The receiver checks staleness every
quarter interval, so a peer is declared within that check
period.<!-- /mirror:detect -->
MD
assert_clean "$FX_P" 2 "positive control: two copies that differ only in wrapping and list indentation pass"
M_RAW="$(mutant raw-compare '/census-guard: normalise$/s/return " ".join(text.split())/return text/')"
assert_not_clean "$FX_P" 2 "positive control mutation: a census comparing raw text fails the re-wrapped copies" "$M_RAW"

# ── cell D: one word different ────────────────────────────────────────────
FX_D="$(new_fixture differ)"
printf '%s\n' '<!-- mirror:m -->a peer is declared at 0.5 s<!-- /mirror:m -->' >"$FX_D/docs/a.md"
printf '%s\n' '<!-- mirror:m -->a peer is declared at 0.6 s<!-- /mirror:m -->' >"$FX_D/docs/b.md"
assert_fails "$FX_D" DIFFER "differ: two same-id blocks one word apart red"
run_census "$FX_D" "$CENSUS"
if [[ "$OUT" == *"'0.5' vs '0.6'"* ]]; then
	ok "differ: the report names the first differing word"
else
	bad "differ: expected the first differing word in the report"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi
M_DIFF="$(mutant differ "$(guard_off differ)")"
assert_flips "$FX_D" DIFFER "differ mutation: with the comparison off the cell flips" "$M_DIFF"

# ── cell O: a block with no partner ───────────────────────────────────────
FX_O="$(new_fixture orphan)"
add_pair "$FX_O" ballast
printf '%s\n' '<!-- mirror:lonely -->only copy<!-- /mirror:lonely -->' >"$FX_O/docs/a.md"
assert_fails "$FX_O" ORPHAN "orphan: a block whose id appears nowhere else reds"
M_ORPH="$(mutant orphan "$(guard_off orphan)")"
assert_flips "$FX_O" ORPHAN "orphan mutation: with the partner check off the cell flips" "$M_ORPH"

# ── cells U1..U3: unbalanced markers ──────────────────────────────────────
FX_U1="$(new_fixture unclosed)"
add_pair "$FX_U1" ballast
printf '%s\n' '<!-- mirror:open -->never closed' >"$FX_U1/docs/a.md"
assert_fails "$FX_U1" UNCLOSED "unclosed: an opening marker with no close reds"
M_UNC="$(mutant unclosed "$(guard_off unclosed)")"
assert_flips "$FX_U1" UNCLOSED "unclosed mutation: with the check off the cell flips" "$M_UNC"

FX_U2="$(new_fixture stray-close)"
add_pair "$FX_U2" ballast
printf '%s\n' 'text<!-- /mirror:stray -->' >"$FX_U2/docs/a.md"
assert_fails "$FX_U2" STRAY-CLOSE "stray close: a closing marker with no opening reds"
M_STRAY="$(mutant stray-close "$(guard_off unbalanced-close)")"
assert_flips "$FX_U2" STRAY-CLOSE "stray close mutation: with the check off the cell flips" "$M_STRAY"

FX_U3="$(new_fixture nested)"
add_pair "$FX_U3" inner
printf '%s\n' '<!-- mirror:outer -->a <!-- mirror:inner -->same words<!-- /mirror:inner --> b<!-- /mirror:outer -->' >"$FX_U3/docs/a.md"
printf '%s\n' '<!-- mirror:outer -->a b<!-- /mirror:outer -->' >"$FX_U3/docs/b.md"
assert_fails "$FX_U3" NESTED "nested: a block opened inside another block reds"
M_NEST="$(mutant nesting "$(guard_off nesting)")"
assert_flips "$FX_U3" NESTED "nested mutation: with the check off the cell flips" "$M_NEST"

# ── cell M: near-miss markers ─────────────────────────────────────────────
FX_M="$(new_fixture near-miss)"
add_pair "$FX_M" ballast
printf '%s\n' 'a <!-- Mirror:x --> b' 'c <!-- mirror:Bad_Id --> d' 'e <!--mirror x--> f' >"$FX_M/docs/a.md"
assert_fails "$FX_M" MALFORMED "near-miss: a wrong-case key, a bad id and a missing colon red instead of being ignored"
run_census "$FX_M" "$CENSUS"
n=$(printf '%s\n' "$OUT" | grep -c 'FAIL: MALFORMED:' || true)
if [[ "$n" -eq 3 ]]; then
	ok "near-miss: all three spellings are reported ($n)"
else
	bad "near-miss: expected 3 MALFORMED reports, got $n"
fi
M_NEAR="$(mutant near-miss "$(guard_off near-miss)")"
assert_flips "$FX_M" MALFORMED "near-miss mutation: with the check off the cell flips" "$M_NEAR"

# ── cell E: empty blocks would "agree" ────────────────────────────────────
FX_E="$(new_fixture empty-block)"
printf '%s\n' 'a <!-- mirror:e --><!-- /mirror:e --> b' >"$FX_E/docs/a.md"
printf '%s\n' '<!-- mirror:e -->' '' '<!-- /mirror:e -->' >"$FX_E/docs/b.md"
assert_fails "$FX_E" EMPTY-BLOCK "empty block: two empty blocks red instead of agreeing"
M_EMPB="$(mutant empty-block "$(guard_off empty-block)")"
assert_flips "$FX_E" EMPTY-BLOCK "empty block mutation: with the check off the cell flips" "$M_EMPB"

# ── cell Z: the empty sweep ───────────────────────────────────────────────
FX_Z="$(new_fixture no-blocks)"
printf '%s\n' 'No mirrors here.' >"$FX_Z/docs/a.md"
assert_fails "$FX_Z" EMPTY "empty sweep: zero blocks is a FAIL, not a clean board"
M_EMPTY="$(mutant empty-sweep "$(guard_off empty-sweep)")"
assert_flips "$FX_Z" EMPTY "empty sweep mutation: with the check off the cell flips" "$M_EMPTY"

# ── cell N: documentation of the convention is not a block ────────────────
FX_N="$(new_fixture not-blocks)"
add_pair "$FX_N" real
cat >"$FX_N/docs/convention.md" <<'MD'
Wrap a copy in `<!-- mirror:<id> -->` and `<!-- /mirror:<id> -->`, for
example `<!-- mirror:doc -->`.

~~~
<!-- mirror:doc -->
text
~~~
MD
# A ~~~ fence on purpose: a ``` fence is ALSO a code span to the inline-code
# blanking, so the fence-skip mutation below could not be attributed.
assert_clean "$FX_N" 2 "not blocks: inline code and fenced examples are skipped; the real pair is read"
M_FENCE="$(mutant fence '/census-guard: fence$/s/if s.startswith("```") or s.startswith("~~~"):/if False:/')"
assert_not_clean "$FX_N" 2 "not blocks mutation: without the fence skip the fenced example is read" "$M_FENCE"
M_INLINE="$(mutant inline-code '/census-guard: inline-code$/s/return INLINE_CODE_RE.sub(.*)  #/return blanked  #/')"
assert_not_clean "$FX_N" 2 "not blocks mutation: without the inline-code blanking the code span is read" "$M_INLINE"

# ── cell R: the census never writes (CLAUDE.md is the owner's) ────────────
FX_R="$(new_fixture read-only)"
add_pair "$FX_R" ballast
printf '%s\n' '# Rules' 'x <!-- mirror:ballast -->other words<!-- /mirror:ballast -->' >"$FX_R/CLAUDE.md"
before=$(cd "$FX_R" && find . -type f -exec sha256sum {} + | sort)
run_census "$FX_R" "$CENSUS"
after=$(cd "$FX_R" && find . -type f -exec sha256sum {} + | sort)
if [[ $RC -eq 1 && "$OUT" == *"FAIL: DIFFER:"*"CLAUDE.md"* && "$OUT" == *"owner action"* && "$before" == "$after" ]]; then
	ok "read-only: a drifted CLAUDE.md copy reds as an owner action, and no file changed"
else
	bad "read-only: expected a DIFFER owner action and an unchanged tree (rc=$RC)"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi

echo ""
echo "mirror-census-selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
