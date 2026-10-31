#!/usr/bin/env bash
# Self-test for scripts/instructions-census.py (#18645).
#
# Hermetic: fixture trees under a mktemp -d, a fixed "today", and a stub in
# place of `gh`. No network, no cluster, no git. Runs in a few seconds.
#
# WHY THIS EXISTS
#
# The census is a gate about instructions, and its failure mode is the one a
# review cannot see: a census whose matcher or date check is broken reports a
# CLEAN BOARD, which looks exactly like a healthy tree. So each verdict is
# asserted twice: a fixture that must produce it, and a MUTATION of the census
# (an edit to the line tagged `census-guard: <name>`) that must make that
# fixture stop producing it. A mutation that does not flip its cell is an
# ESCAPE and fails this self-test: the cell was passing for another reason.
#
# The positive controls run the other way. A fixture of valid markers must
# PASS with an exact marker count, and a mutation that over-reports (an
# inverted comparison) or under-reads (a dropped marker position) must make
# it fail. Without them, a census that reds on everything would satisfy every
# FAIL cell below.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CENSUS="${REPO_ROOT}/scripts/instructions-census.py"
PY="$(command -v python3 || true)"

PASS=0
FAIL=0
ok()  { echo "  ok   — $*"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL — $*" >&2; FAIL=$((FAIL + 1)); }

[[ -f "$CENSUS" ]] || { echo "FATAL: census not found at $CENSUS" >&2; exit 1; }
[[ -n "$PY" ]] || { echo "SKIP: python3 not installed" >&2; exit 77; }

if [[ -z "${TMPDIR:-}" ]]; then mkdir -p /var/worktrees/.cache/tmpdir; fi
WORK="$(mktemp -d "${TMPDIR:-/var/worktrees/.cache/tmpdir}/instructions-census-selftest.XXXXXX")" \
	|| { echo "FATAL: cannot create work dir" >&2; exit 2; }
[[ -n "$WORK" && -d "$WORK" ]] || { echo "FATAL: work dir not created: '$WORK'" >&2; exit 2; }
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

TODAY=2026-10-31

# The gh stand-in: 101 OPEN, 102 CLOSED, 104 closed (lower case, as the REST
# API spells it), 103 unreadable (exit 1, no output).
cat >"$WORK/gh-state.sh" <<'SH'
case "$1" in
101) echo OPEN ;;
102) echo CLOSED ;;
104) echo closed ;;
*) exit 1 ;;
esac
SH

# A fixture is a miniature repo: docs/, scripts/ and a CLAUDE.md.
new_fixture() {
	local fx="$WORK/$1"
	mkdir -p "$fx/docs" "$fx/scripts"
	: >"$fx/CLAUDE.md"
	echo "$fx"
}

# run_census <fx> <script> [census args...] -> output; rc in $RC
run_census() {
	local fx=$1 script=$2
	shift 2
	OUT=$(INSTR_CENSUS_ROOT="$fx" \
		INSTR_CENSUS_SCOPE="docs scripts CLAUDE.md" \
		INSTR_CENSUS_EXCLUDE="${FX_EXCLUDE:-}" \
		INSTR_CENSUS_TODAY="$TODAY" \
		INSTR_CENSUS_GH_STATE="sh $WORK/gh-state.sh" \
		"$PY" "$script" "$@" 2>&1)
	RC=$?
}

# mutant <name> <sed-expr>... -> path to a MUTATED copy of the census
mutant() {
	local name=$1
	shift
	local out="$WORK/mutant-$name.py" e
	cp "$CENSUS" "$out"
	for e in "$@"; do
		sed -i "$e" "$out"
	done
	if cmp -s "$CENSUS" "$out"; then
		bad "mutation '$name' changed NOTHING (its sed no longer matches the census -- a census-guard tag moved)"
	fi
	echo "$out"
}

# guard_off <name> -> a sed expression turning that guard's `if` into `if False`
guard_off() {
	printf '%s' "/census-guard: $1\$/s/if [^#]*:  # census-guard/if False:  # census-guard/"
}

# assert_fails <fx> <TAG> <label> [args...]
assert_fails() {
	local fx=$1 tag=$2 label=$3
	shift 3
	run_census "$fx" "$CENSUS" "$@"
	if [[ $RC -eq 1 && "$OUT" == *"FAIL: $tag:"* ]]; then
		ok "$label"
	else
		bad "$label (rc=$RC; expected a FAIL tagged $tag)"
		printf '%s\n' "$OUT" | sed 's/^/         /' >&2
	fi
}

# assert_flips <fx> <TAG> <label> <mutant> [args...]: the mutant must NOT
# produce the tag. If it still does, the cell has no power over that line.
assert_flips() {
	local fx=$1 tag=$2 label=$3 mut=$4
	shift 4
	run_census "$fx" "$mut" "$@"
	if [[ "$OUT" == *"FAIL: $tag:"* ]]; then
		bad "$label — mutation ESCAPED: the mutated census still reports $tag"
		printf '%s\n' "$OUT" | sed 's/^/         /' >&2
	else
		ok "$label"
	fi
}

# assert_clean <fx> <count> <label> [args...]
assert_clean() {
	local fx=$1 n=$2 label=$3
	shift 3
	run_census "$fx" "$CENSUS" "$@"
	if [[ $RC -eq 0 && "$OUT" == *"instructions census: $n marker(s)"* && "$OUT" == *"instructions census: OK"* ]]; then
		ok "$label"
	else
		bad "$label (rc=$RC; expected a clean pass over exactly $n markers)"
		printf '%s\n' "$OUT" | sed 's/^/         /' >&2
	fi
}

# assert_not_clean <fx> <count> <label> <mutant> [args...]: the mutant must
# break the clean pass (rc != 0, or a different marker count).
assert_not_clean() {
	local fx=$1 n=$2 label=$3 mut=$4
	shift 4
	run_census "$fx" "$mut" "$@"
	if [[ $RC -eq 0 && "$OUT" == *"instructions census: $n marker(s)"* ]]; then
		bad "$label — mutation ESCAPED: the mutated census still passes cleanly over $n markers"
		printf '%s\n' "$OUT" | sed 's/^/         /' >&2
	else
		ok "$label"
	fi
}

# ── positive control P: every valid form, in every position ───────────────
# Six markers: Markdown HTML comment on its own line, the bare trailing-line
# form, an HTML comment inside a table row, a shell comment, an env comment
# with a future Review-by, and a Review-by that is TODAY (the boundary: a
# date is past only when it is before today).
FX_P="$(new_fixture positive)"
cat >"$FX_P/docs/a.md" <<'MD'
# Doc

- A temporary rule.
  <!-- Expires-when: #101 closed -->
- Another temporary rule.
  Expires-when: #101 closed

| ID | Rule |
|---|---|
| X1 | holds until #101 closes <!-- Expires-when: #101 closed --> |
MD
cat >"$FX_P/scripts/x.sh" <<'SH'
#!/bin/sh
# Expires-when: #101 closed
echo temporary
SH
cat >"$FX_P/scripts/lab.env" <<'ENV'
# Expires-when: the lab box is renumbered; Review-by: 2026-12-01
# Expires-when: the target moves; Review-by: 2026-10-31
TARGET=1
ENV
assert_clean "$FX_P" 6 "positive control: six valid markers (HTML comment, trailing line, table row, shell, env, Review-by == today) pass hermetic"
assert_clean "$FX_P" 6 "positive control: the same tree passes ONLINE when every named issue is open" --online

M_PASTEQ="$(mutant past-inclusive '/census-guard: past-date$/s/m.review < today/m.review <= today/')"
assert_not_clean "$FX_P" 6 "positive control mutation: a census that treats TODAY as past reds the boundary marker" "$M_PASTEQ"
M_OPENCLOSED="$(mutant open-is-closed '/census-guard: closed-check$/s/state != "open"/state == "open"/')"
assert_not_clean "$FX_P" 6 "positive control mutation: a census that reads OPEN as closed reds online" "$M_OPENCLOSED" --online
M_NOHTML="$(mutant no-html '/census-guard: html-comment$/s/HTML_RE.finditer(text)/[]/')"
assert_not_clean "$FX_P" 6 "positive control mutation: dropping the HTML-comment position loses markers (count changes)" "$M_NOHTML"
M_NOLINE="$(mutant no-line-start '/census-guard: line-start$/s/LINE_START_RE.match(text)/None/')"
assert_not_clean "$FX_P" 6 "positive control mutation: dropping the line-start position loses markers (count changes)" "$M_NOLINE"

# ── cell C: a CLOSED issue reds online, and only online ───────────────────
FX_C="$(new_fixture closed)"
printf '%s\n' '- rule' '  <!-- Expires-when: #102 closed -->' >"$FX_C/docs/a.md"
printf '%s\n' '# Expires-when: #104 closed' 'X=1' >"$FX_C/scripts/b.env"
assert_fails "$FX_C" CLOSED "closed issue: a marker naming a CLOSED issue reds the online census" --online
run_census "$FX_C" "$CENSUS" --online
if [[ "$OUT" == *"#102 is CLOSED"* && "$OUT" == *"#104 is CLOSED"* ]]; then
	ok "closed issue: both spellings of the state (CLOSED, closed) are read as closed"
else
	bad "closed issue: expected #102 and #104 both reported CLOSED"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi
assert_clean "$FX_C" 2 "closed issue: the hermetic census does not ask GitHub, so the same tree passes it"
M_CLOSED="$(mutant closed-check "$(guard_off closed-check)")"
assert_flips "$FX_C" CLOSED "closed issue mutation: with the closed check off the cell flips" "$M_CLOSED" --online

# ── cell U: an UNREADABLE state is a FAIL, never "open" ───────────────────
FX_U="$(new_fixture unreadable)"
printf '%s\n' '# Expires-when: #103 closed' >"$FX_U/scripts/c.sh"
assert_fails "$FX_U" UNREADABLE "unreadable: an issue whose state cannot be read reds online" --online
M_UNREAD="$(mutant unreadable-as-open "$(guard_off unreadable)" \
	'/census-guard: closed-check$/s/state != "open"/state not in ("open", "")/')"
run_census "$FX_U" "$M_UNREAD" --online
if [[ $RC -eq 0 ]]; then
	ok "unreadable mutation: a census that reads a failed lookup as open passes, so the cell has power"
else
	bad "unreadable mutation ESCAPED: the mutated census still fails (rc=$RC)"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi

# ── cell S: --online with no gh is a SKIP (77), never a pass ──────────────
mkdir -p "$WORK/nogh"
OUT=$(cd "$FX_P" && PATH="$WORK/nogh" INSTR_CENSUS_ROOT="$FX_P" INSTR_CENSUS_SCOPE="docs scripts CLAUDE.md" \
	INSTR_CENSUS_EXCLUDE="" INSTR_CENSUS_TODAY="$TODAY" "$PY" "$CENSUS" --online 2>&1)
RC=$?
if [[ $RC -eq 77 && "$OUT" == *"SKIP:"* ]]; then
	ok "no gh: the online check exits 77 (SKIP) instead of reporting the issues open"
else
	bad "no gh: expected exit 77, got $RC"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi
M_SKIP="$(mutant skip-as-pass '/census-guard: skip$/s/return 77/return 0/')"
OUT=$(PATH="$WORK/nogh" INSTR_CENSUS_ROOT="$FX_P" INSTR_CENSUS_SCOPE="docs scripts CLAUDE.md" \
	INSTR_CENSUS_EXCLUDE="" INSTR_CENSUS_TODAY="$TODAY" "$PY" "$M_SKIP" --online 2>&1)
RC=$?
if [[ $RC -ne 77 ]]; then
	ok "no gh mutation: a census that passes without asking is caught (rc=$RC)"
else
	bad "no gh mutation ESCAPED: still exit 77"
fi

# ── cell E: a past Review-by reds HERMETIC mode ───────────────────────────
FX_E="$(new_fixture expired)"
printf '%s\n' '# Expires-when: the lab box is renumbered; Review-by: 2026-10-30' 'X=1' >"$FX_E/scripts/lab.env"
assert_fails "$FX_E" EXPIRED "past Review-by: a date before today reds the hermetic census"
M_PAST="$(mutant past-date "$(guard_off past-date)")"
assert_flips "$FX_E" EXPIRED "past Review-by mutation: with the date check off the cell flips" "$M_PAST"

# ── cell R: free text with no Review-by ───────────────────────────────────
FX_R="$(new_fixture no-review)"
printf '%s\n' '<!-- Expires-when: the lab box is renumbered -->' >"$FX_R/docs/a.md"
assert_fails "$FX_R" NO-REVIEW-BY "no Review-by: a free-text condition without a date reds"
M_NOREV="$(mutant free-needs-review "$(guard_off free-needs-review)")"
assert_flips "$FX_R" NO-REVIEW-BY "no Review-by mutation: with the check off the cell flips" "$M_NOREV"

# ── cells M1..M6: malformed markers ───────────────────────────────────────
M_MALF="$(mutant malformed "$(guard_off malformed)")"
malformed_cell() { # malformed_cell <name> <file> <line> <label>
	local fx
	fx="$(new_fixture "malformed-$1")"
	printf '%s\n' "$3" >"$fx/$2"
	# A valid companion, so a mutant that stops SEEING the bad line yields a
	# clean pass (attributable) rather than an EMPTY failure.
	printf '%s\n' '# Expires-when: #101 closed' >"$fx/scripts/ok.sh"
	assert_fails "$fx" MALFORMED "malformed ($1): $4"
	assert_flips "$fx" MALFORMED "malformed ($1) mutation: with the malformed check off the cell flips" "$M_MALF"
	LAST_FX=$fx
}
malformed_cell empty scripts/a.sh '# Expires-when:' "an empty condition reds"
malformed_cell no-closed scripts/a.sh '# Expires-when: #18576' "'#NNNN' without 'closed' reds"
FX_NOCLOSED=$LAST_FX
malformed_cell near-miss scripts/a.sh '# Expires When: #101 closed' "a near-miss key spelling reds instead of being ignored"
FX_NEAR=$LAST_FX
malformed_cell bad-date docs/a.md '<!-- Expires-when: lab renumbered; Review-by: 2026-13-01 -->' "an impossible Review-by date reds"
malformed_cell no-semicolon docs/a.md '<!-- Expires-when: lab renumbered Review-by: 2026-12-01 -->' "a Review-by not separated by ';' reds"
malformed_cell orphan-review scripts/a.sh '# Review-by: 2026-12-01' "a Review-by with no Expires-when reds"
malformed_cell placeholder docs/a.md '<!-- Expires-when: #NNNN closed -->' "a placeholder issue number reds"

M_STRICT="$(mutant strict-key '/census-guard: near-miss$/s/= r".*"  #/= r"Expires-when:"  #/')"
assert_flips "$FX_NEAR" MALFORMED "near-miss mutation: an exact-match key no longer SEES the typo, so the cell flips" "$M_STRICT"
M_ISSUE="$(mutant issue-form '/census-guard: issue-form$/s/ISSUE_RE.match(cond)/re.match(r"^#(\\d+)", cond)/')"
assert_flips "$FX_NOCLOSED" MALFORMED "issue-form mutation: a loose issue pattern accepts '#NNNN' alone, so the cell flips" "$M_ISSUE"

# ── cell N: things that are NOT markers (the loose bound) ─────────────────
# Each of these would be MALFORMED if it were read as a marker (a placeholder
# issue number), so a census that reads any of them fails this cell.
FX_N="$(new_fixture not-markers)"
cat >"$FX_N/docs/a.md" <<'MD'
# Convention

Write an Expires-when: #NNNN closed marker next to the rule.
Use `<!-- Expires-when: #NNNN closed -->` in Markdown.

```
# Expires-when: #NNNN closed
<!-- Expires-when: #NNNN closed -->
```

- The one real marker.
  <!-- Expires-when: #101 closed -->
MD
assert_clean "$FX_N" 1 "not markers: mid-line prose, an inline code span and a fenced block are not read; the one real marker is"
M_FENCE="$(mutant fence '/census-guard: fence$/s/= fence_lines(raw, starts, lines) if is_md else \[\]/= []/')"
assert_not_clean "$FX_N" 1 "not markers mutation: without the fence skip the fenced examples are read" "$M_FENCE"
M_INLINE="$(mutant inline-code '/census-guard: inline-code$/s/text = INLINE_CODE_RE.sub("", text)/pass/')"
assert_not_clean "$FX_N" 1 "not markers mutation: without the inline-code strip the code span is read" "$M_INLINE"
M_ANYWHERE="$(mutant anywhere \
	'/census-guard: position$/s/r"\^\\s\*"/r"\\s*"/' \
	'/census-guard: line-start$/s/LINE_START_RE.match(text)/LINE_START_RE.search(text)/')"
assert_not_clean "$FX_N" 1 "not markers mutation: matching the key ANYWHERE on a line reads the prose mention" "$M_ANYWHERE"

# ── cell Z: the empty sweeps ──────────────────────────────────────────────
FX_Z="$(new_fixture no-markers)"
printf '%s\n' '# Nothing temporary here.' >"$FX_Z/docs/a.md"
assert_fails "$FX_Z" EMPTY "empty sweep: zero markers is a FAIL, not a clean board"
M_EMPTY="$(mutant empty-markers "$(guard_off empty-markers)")"
assert_flips "$FX_Z" EMPTY "empty sweep mutation: with the zero-marker check off the cell flips" "$M_EMPTY"

FX_ZS="$WORK/no-files"
mkdir -p "$FX_ZS/docs" "$FX_ZS/scripts"
: >"$FX_ZS/CLAUDE.notmd"
OUT=$(INSTR_CENSUS_ROOT="$FX_ZS" INSTR_CENSUS_SCOPE="docs scripts" INSTR_CENSUS_EXCLUDE="" \
	INSTR_CENSUS_TODAY="$TODAY" "$PY" "$CENSUS" 2>&1)
RC=$?
if [[ $RC -eq 1 && "$OUT" == *"FAIL: EMPTY-SCAN:"* ]]; then
	ok "empty scan: a scope that yields zero files is a FAIL"
else
	bad "empty scan: expected EMPTY-SCAN (rc=$RC)"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi
M_EMPTYF="$(mutant empty-files "$(guard_off empty-files)")"
OUT=$(INSTR_CENSUS_ROOT="$FX_ZS" INSTR_CENSUS_SCOPE="docs scripts" INSTR_CENSUS_EXCLUDE="" \
	INSTR_CENSUS_TODAY="$TODAY" "$PY" "$M_EMPTYF" 2>&1)
if [[ "$OUT" == *"FAIL: EMPTY-SCAN:"* ]]; then
	bad "empty scan mutation ESCAPED: still reports EMPTY-SCAN"
else
	ok "empty scan mutation: with the zero-file check off the cell flips"
fi

# ── cell X: the named self-exclusion cannot rot ───────────────────────────
FX_X="$(new_fixture stale-exclude)"
printf '%s\n' '# Expires-when: #101 closed' >"$FX_X/scripts/a.sh"
FX_EXCLUDE="scripts/gone.py" assert_fails "$FX_X" SCOPE "stale exclusion: excluding a path that does not exist reds"
M_EXCL="$(mutant stale-exclude "$(guard_off stale-exclude)")"
FX_EXCLUDE="scripts/gone.py" assert_flips "$FX_X" SCOPE "stale exclusion mutation: with the check off the cell flips" "$M_EXCL"
printf '%s\n' '# Expires-when:' >"$FX_X/scripts/excluded.py"
FX_EXCLUDE="scripts/excluded.py" assert_clean "$FX_X" 1 "exclusion: an excluded file's quoted markers are not read"

# ── cell O: CLAUDE.md is read, reported as an owner action, never written ─
FX_O="$(new_fixture claude-md)"
printf '%s\n' '# Expires-when: #101 closed' >"$FX_O/scripts/a.sh"
printf '%s\n' '# Rules' '' '- old rule' '  <!-- Expires-when: #102 closed -->' >"$FX_O/CLAUDE.md"
before=$(sha256sum "$FX_O/CLAUDE.md")
run_census "$FX_O" "$CENSUS" --online
after=$(sha256sum "$FX_O/CLAUDE.md")
if [[ $RC -eq 1 && "$OUT" == *"CLAUDE.md:4 (CLAUDE.md is read-only for agents: owner action)"* && "$before" == "$after" ]]; then
	ok "CLAUDE.md: a closed marker there reds as an OWNER action, and the file is byte-identical afterwards"
else
	bad "CLAUDE.md: expected an owner-action CLOSED report and an unchanged file (rc=$RC)"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi

echo ""
echo "instructions-census-selftest: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
