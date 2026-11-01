#!/usr/bin/env bash
# Self-test for scripts/instructions-census.py (#18645).
#
# Hermetic: fixture trees under a mktemp -d, a fixed "today", a stub in place
# of `gh`, and (one cell) a throwaway local git repo. No network, no cluster.
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
# The positive controls run the other way. A fixture of valid markers in every
# accepted position must PASS with an exact marker count, and a mutation that
# over-reports or under-reads must make it fail. Without them, a census that
# reds on everything would satisfy every FAIL cell below.
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

# run_census <fx> <script> [census args...] -> output in OUT, rc in RC.
# FX_TOUCHED (default: nothing) is the PR's touched-file list.
run_census() {
	local fx=$1 script=$2
	shift 2
	OUT=$(INSTR_CENSUS_ROOT="$fx" \
		INSTR_CENSUS_SCOPE="${FX_SCOPE:-docs scripts CLAUDE.md}" \
		INSTR_CENSUS_EXCLUDE="${FX_EXCLUDE:-}" \
		INSTR_CENSUS_TODAY="$TODAY" \
		INSTR_CENSUS_TOUCHED="${FX_TOUCHED:-}" \
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

assert_fails() { # <fx> <TAG> <label> [args...]
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

assert_flips() { # <fx> <TAG> <label> <mutant> [args...]
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

assert_clean() { # <fx> <count> <label> [args...]
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

assert_not_clean() { # <fx> <count> <label> <mutant> [args...]
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

# ── positive control P: every valid form, in every accepted position ──────
# Markdown: an HTML comment on its own line, a bare trailing line, an HTML
# comment in a table row, and a bare CRLF line. Code files: `#`, `*`, `;`,
# `/* ... */` leaders, a CRLF shell line, a future Review-by and one that is
# TODAY (the boundary: a date is past only when it is before today).
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
printf '%s\r\n' 'Rule text.' 'Expires-when: #101 closed' >"$FX_P/docs/crlf.md"
cat >"$FX_P/scripts/x.sh" <<'SH'
#!/bin/sh
# Expires-when: #101 closed
echo temporary
SH
printf '%s\r\n' '#!/bin/sh' '# Expires-when: #101 closed' 'echo crlf' >"$FX_P/scripts/crlf.sh"
cat >"$FX_P/scripts/box.conf" <<'CONF'
/*
 * Expires-when: #101 closed
 */
; Expires-when: #101 closed
/* Expires-when: #101 closed */
CONF
cat >"$FX_P/scripts/lab.env" <<'ENV'
# Expires-when: the lab box is renumbered; Review-by: 2026-12-01
# Expires-when: the target moves; Review-by: 2026-10-31
TARGET=1
ENV
P_N=11
assert_clean "$FX_P" $P_N "positive control: $P_N valid markers (4 Markdown positions incl. CRLF; #, *, ;, /* */ leaders; a CRLF shell line; Review-by future and == today) pass"
assert_clean "$FX_P" $P_N "positive control: the same tree passes the ONLINE sweep when every named issue is open" --online --all

M_PASTEQ="$(mutant past-inclusive '/census-guard: past-date$/s/m.review < today/m.review <= today/')"
assert_not_clean "$FX_P" $P_N "positive control mutation: treating TODAY as past reds the boundary marker" "$M_PASTEQ" --all
M_OPENCLOSED="$(mutant open-is-closed '/census-guard: closed-check$/s/state != "open"/state == "open"/')"
assert_not_clean "$FX_P" $P_N "positive control mutation: reading OPEN as closed reds online" "$M_OPENCLOSED" --online --all
M_NOHTML="$(mutant no-html '/census-guard: html-comment$/s/HTML_RE.finditer(text)/[]/')"
assert_not_clean "$FX_P" $P_N "positive control mutation: dropping the HTML-comment position loses markers" "$M_NOHTML"
M_NOLINE="$(mutant no-line-start '/census-guard: line-start$/s/(MD_START_RE if is_md else LINE_START_RE).match(text)/None/')"
assert_not_clean "$FX_P" $P_N "positive control mutation: dropping the line-start position loses markers" "$M_NOLINE"
M_NOSTAR="$(mutant leader-no-star '/census-guard: leader$/s/|\\\*)"/)"/')"
assert_not_clean "$FX_P" $P_N "positive control mutation: a leader set without \`*\` misreads the block-comment line" "$M_NOSTAR"
M_NOSEMI="$(mutant leader-no-semicolon '/census-guard: leader$/s/|;+|/|/')"
assert_not_clean "$FX_P" $P_N "positive control mutation: a leader set without \`;\` misreads the ; line" "$M_NOSEMI"
M_NOCRLF="$(mutant no-crlf-strip '/census-guard: crlf$/s/payload.strip()/payload.strip(" ")/')"
assert_not_clean "$FX_P" $P_N "positive control mutation: a strip that keeps the CR makes the CRLF lines malformed" "$M_NOCRLF"
M_NOTAIL="$(mutant strip-tail-noop '/census-guard: strip-tail$/s/("-->", "\*\/")/()/')"
assert_not_clean "$FX_P" $P_N "positive control mutation: without strip_tail the /* ... */ marker is malformed" "$M_NOTAIL"

# ── cell C: a CLOSED issue reds the online sweep ──────────────────────────
FX_C="$(new_fixture closed)"
printf '%s\n' '- rule' '  <!-- Expires-when: #102 closed -->' >"$FX_C/docs/a.md"
printf '%s\n' '# Expires-when: #104 closed' 'X=1' >"$FX_C/scripts/b.env"
assert_fails "$FX_C" CLOSED "closed issue: a marker naming a CLOSED issue reds the online sweep" --online --all
run_census "$FX_C" "$CENSUS" --online --all
if [[ "$OUT" == *"#102 is CLOSED"* && "$OUT" == *"#104 is CLOSED"* ]]; then
	ok "closed issue: both spellings of the state (CLOSED, closed) are read as closed"
else
	bad "closed issue: expected #102 and #104 both reported CLOSED"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi
assert_clean "$FX_C" 2 "closed issue: the hermetic census does not ask GitHub, so the same tree passes it" --all
M_CLOSED="$(mutant closed-check "$(guard_off closed-check)")"
assert_flips "$FX_C" CLOSED "closed issue mutation: with the closed check off the cell flips" "$M_CLOSED" --online --all

# ── cell U: an UNREADABLE state is a FAIL, never "open" ───────────────────
FX_U="$(new_fixture unreadable)"
printf '%s\n' '# Expires-when: #103 closed' >"$FX_U/scripts/c.sh"
assert_fails "$FX_U" UNREADABLE "unreadable: an issue whose state cannot be read reds online" --online --all
M_UNREAD="$(mutant unreadable-as-open "$(guard_off unreadable)" \
	'/census-guard: closed-check$/s/state != "open"/state not in ("open", "")/')"
run_census "$FX_U" "$M_UNREAD" --online --all
if [[ $RC -eq 0 ]]; then
	ok "unreadable mutation: a census that reads a failed lookup as open passes, so the cell has power"
else
	bad "unreadable mutation ESCAPED: the mutated census still fails (rc=$RC)"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi

# ── cell S: --online with no gh is a SKIP (77), never a pass ──────────────
mkdir -p "$WORK/nogh"
nogh_run() { # nogh_run <script>
	OUT=$(PATH="$WORK/nogh" INSTR_CENSUS_ROOT="$FX_P" INSTR_CENSUS_SCOPE="docs scripts CLAUDE.md" \
		INSTR_CENSUS_EXCLUDE="" INSTR_CENSUS_TODAY="$TODAY" INSTR_CENSUS_TOUCHED="" \
		"$PY" "$1" --online --all 2>&1)
	RC=$?
}
nogh_run "$CENSUS"
if [[ $RC -eq 77 && "$OUT" == *"SKIP:"* ]]; then
	ok "no gh: the online check exits 77 (SKIP) instead of reporting the issues open"
else
	bad "no gh: expected exit 77, got $RC"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi
M_SKIP="$(mutant skip-as-pass '/census-guard: skip$/s/return 77/return 0/')"
nogh_run "$M_SKIP"
if [[ $RC -ne 77 ]]; then
	ok "no gh mutation: a census that passes without asking is caught (rc=$RC)"
else
	bad "no gh mutation ESCAPED: still exit 77"
fi

# ── cell E: a past Review-by reds the sweep ───────────────────────────────
FX_E="$(new_fixture expired)"
printf '%s\n' '# Expires-when: the lab box is renumbered; Review-by: 2026-10-30' 'X=1' >"$FX_E/scripts/lab.env"
assert_fails "$FX_E" EXPIRED "past Review-by: a date before today reds the --all sweep" --all
M_PAST="$(mutant past-date "$(guard_off past-date)")"
assert_flips "$FX_E" EXPIRED "past Review-by mutation: with the date check off the cell flips" "$M_PAST" --all

# ── cells D1..D5: PR mode limits the EXPIRY checks to touched files ───────
# A date that passes on a calendar day must red the PRs that touch that
# instruction, not every open PR on the same day.
run_census "$FX_E" "$CENSUS"
if [[ $RC -eq 0 && "$OUT" == *"NOTE: 1 marker(s) outside this change are past their Review-by date"* ]]; then
	ok "PR mode: an expired marker in an UNTOUCHED file passes with a NOTE (no same-day red on every PR)"
else
	bad "PR mode: expected a pass with a NOTE for the untouched expired marker (rc=$RC)"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi
FX_TOUCHED="scripts/lab.env" assert_fails "$FX_E" EXPIRED "PR mode: the same expired marker in a TOUCHED file reds"
M_TOUCH_NONE="$(mutant touched-none '/census-guard: touched$/s/m.path in touched/False/')"
FX_TOUCHED="scripts/lab.env" assert_flips "$FX_E" EXPIRED "PR mode mutation: a census that never sees touched files flips the touched cell" "$M_TOUCH_NONE"
M_TOUCH_ALL="$(mutant touched-all '/census-guard: touched$/s/m.path in touched/True/')"
run_census "$FX_E" "$M_TOUCH_ALL"
if [[ $RC -ne 0 ]]; then
	ok "PR mode mutation: a census that treats every file as touched reds the untouched cell (the live-lock shape)"
else
	bad "PR mode mutation ESCAPED: untouched still passes when every file counts as touched"
fi
FX_TOUCHED="docs/other.md" assert_clean "$FX_C" 2 "PR mode: a CLOSED issue in an untouched file is not checked online (the keeper's sweep reports it)" --online
FX_TOUCHED="docs/a.md" assert_fails "$FX_C" CLOSED "PR mode: a CLOSED issue in a touched file reds online" --online

# D4: when the diff cannot be computed, fail CLOSED (every file in scope).
OUT=$(INSTR_CENSUS_ROOT="$FX_E" INSTR_CENSUS_SCOPE="docs scripts CLAUDE.md" INSTR_CENSUS_EXCLUDE="" \
	INSTR_CENSUS_TODAY="$TODAY" GIT_CEILING_DIRECTORIES="$WORK" "$PY" "$CENSUS" --base no-such-ref 2>&1)
RC=$?
if [[ $RC -eq 1 && "$OUT" == *"FAIL: EXPIRED:"* && "$OUT" == *"could not compute the diff"* ]]; then
	ok "PR mode: an uncomputable diff (no repo, bad base) fails closed: the expired marker reds"
else
	bad "PR mode: expected a fail-closed EXPIRED (rc=$RC)"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi
M_OPEN="$(mutant diff-fail-open '/census-guard: diff-fail-closed$/s/if touched is None:/if touched is None and False:/' \
	'/census-guard: touched$/s/m.path in touched/m.path in (touched or ())/')"
OUT=$(INSTR_CENSUS_ROOT="$FX_E" INSTR_CENSUS_SCOPE="docs scripts CLAUDE.md" INSTR_CENSUS_EXCLUDE="" \
	INSTR_CENSUS_TODAY="$TODAY" GIT_CEILING_DIRECTORIES="$WORK" "$PY" "$M_OPEN" --base no-such-ref 2>&1)
if [[ "$OUT" != *"FAIL: EXPIRED:"* ]]; then
	ok "PR mode mutation: failing OPEN on an uncomputable diff hides the expired marker, so the cell has power"
else
	bad "PR mode mutation ESCAPED"
fi

# D5: the real git path: merge-base diff + uncommitted + untracked files.
if command -v git >/dev/null 2>&1; then
	G="$WORK/gitfx"
	mkdir -p "$G/docs" "$G/scripts"
	: >"$G/CLAUDE.md"
	printf '%s\n' '# Expires-when: old rule; Review-by: 2026-10-01' >"$G/scripts/old.env"
	printf '%s\n' '# Expires-when: other rule; Review-by: 2026-10-02' >"$G/scripts/edited.env"
	git -C "$G" init -q && git -C "$G" add -A && git -C "$G" -c user.name=t -c user.email=t@t commit -q -m base
	git -C "$G" branch -q base
	printf '%s\n' '# Expires-when: other rule; Review-by: 2026-10-03' >"$G/scripts/edited.env"
	OUT=$(INSTR_CENSUS_ROOT="$G" INSTR_CENSUS_SCOPE="docs scripts CLAUDE.md" INSTR_CENSUS_EXCLUDE="" \
		INSTR_CENSUS_TODAY="$TODAY" "$PY" "$CENSUS" --base base 2>&1)
	RC=$?
	if [[ $RC -eq 1 && "$OUT" == *"FAIL: EXPIRED: scripts/edited.env:1"* && "$OUT" != *"FAIL: EXPIRED: scripts/old.env"* && "$OUT" == *"(1 touched file(s))"* ]]; then
		ok "PR mode (git): only the file the change edited is in the expiry scope (edited.env reds, old.env is a NOTE)"
	else
		bad "PR mode (git): expected only edited.env EXPIRED (rc=$RC)"
		printf '%s\n' "$OUT" | sed 's/^/         /' >&2
	fi
else
	echo "  skip — PR mode (git): git not installed"
fi

# ── cell W: a Review-by within SOON days warns (lead time), never fails ───
FX_W="$(new_fixture soon)"
printf '%s\n' '# Expires-when: the lab box is renumbered; Review-by: 2026-11-10' >"$FX_W/scripts/lab.env"
run_census "$FX_W" "$CENSUS" --all
if [[ $RC -eq 0 && "$OUT" == *"WARN: SOON: scripts/lab.env:1: Review-by 2026-11-10 is 10 day(s) away"* ]]; then
	ok "lead time: a Review-by 10 days out prints a SOON warning and still passes"
else
	bad "lead time: expected a SOON warning and rc 0 (rc=$RC)"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi
M_SOON="$(mutant no-soon '/census-guard: soon$/s/<= SOON_DAYS/< 0/')"
run_census "$FX_W" "$M_SOON" --all
if [[ "$OUT" != *"WARN: SOON:"* ]]; then
	ok "lead time mutation: without the lead-time check the warning is gone, so the cell has power"
else
	bad "lead time mutation ESCAPED"
fi

# ── cell H: a Review-by beyond the HORIZON reds (no permanent pass) ───────
FX_H="$(new_fixture horizon)"
printf '%s\n' '# Expires-when: someday; Review-by: 2099-01-01' >"$FX_H/scripts/a.sh"
assert_fails "$FX_H" HORIZON "horizon: Review-by 2099-01-01 reds in PR mode, untouched (a syntax-class check)"
printf '%s\n' '# Expires-when: someday; Review-by: 2027-04-29' >"$FX_H/scripts/a.sh"
assert_clean "$FX_H" 1 "horizon: today + 180 days (2027-04-29) is still allowed"
printf '%s\n' '# Expires-when: someday; Review-by: 2027-04-30' >"$FX_H/scripts/a.sh"
assert_fails "$FX_H" HORIZON "horizon: today + 181 days reds"
M_HOR="$(mutant horizon "$(guard_off horizon)")"
assert_flips "$FX_H" HORIZON "horizon mutation: with the horizon off the cell flips" "$M_HOR"

# ── cell R: free text with no Review-by ───────────────────────────────────
FX_R="$(new_fixture no-review)"
printf '%s\n' '<!-- Expires-when: the lab box is renumbered -->' >"$FX_R/docs/a.md"
assert_fails "$FX_R" NO-REVIEW-BY "no Review-by: a free-text condition without a date reds"
M_NOREV="$(mutant free-needs-review "$(guard_off free-needs-review)")"
assert_flips "$FX_R" NO-REVIEW-BY "no Review-by mutation: with the check off the cell flips" "$M_NOREV"

# ── cells M*: malformed and MISPLACED markers ─────────────────────────────
M_MALF="$(mutant malformed "$(guard_off malformed)")"
M_MISP="$(mutant misplaced "$(guard_off misplaced)")"
malformed_cell() { # malformed_cell <name> <file> <line> <label> [mutant]
	local fx mut=${5:-$M_MALF}
	fx="$(new_fixture "malformed-$1")"
	printf '%s\n' "$3" >"$fx/$2"
	# A valid companion, so a mutant that stops SEEING the bad line yields a
	# clean pass (attributable) rather than an EMPTY failure.
	printf '%s\n' '# Expires-when: #101 closed' >"$fx/scripts/ok.sh"
	assert_fails "$fx" MALFORMED "malformed ($1): $4"
	assert_flips "$fx" MALFORMED "malformed ($1) mutation: with its check off the cell flips" "$mut"
	LAST_FX=$fx
}
malformed_cell empty scripts/a.sh '# Expires-when:' "an empty condition reds"
malformed_cell no-closed scripts/a.sh '# Expires-when: #18576' "'#NNNN' without 'closed' reds"
FX_NOCLOSED=$LAST_FX
malformed_cell near-miss scripts/a.sh '# Expires When: #101 closed' "a near-miss key spelling reds instead of being ignored"
FX_NEAR=$LAST_FX
malformed_cell nb-hyphen docs/a.md $'Expires\u2011when: #101 closed' "a NON-BREAKING hyphen in the key reds"
malformed_cell expires-colon-when docs/a.md 'Expires: when #8 closes' "the 'Expires: when' shape reds"
malformed_cell bad-date docs/a.md '<!-- Expires-when: lab renumbered; Review-by: 2026-13-01 -->' "an impossible Review-by date reds"
malformed_cell no-semicolon docs/a.md '<!-- Expires-when: lab renumbered Review-by: 2026-12-01 -->' "a Review-by not separated by ';' reds"
malformed_cell orphan-review scripts/a.sh '# Review-by: 2026-12-01' "a Review-by with no Expires-when reds"
malformed_cell placeholder docs/a.md '<!-- Expires-when: #NNNN closed -->' "a placeholder issue number reds"
# MISPLACED: a key outside a marker position (AC's probe shapes).
malformed_cell md-dash-bullet docs/a.md '- Expires-when: #2 closed' "a Markdown '- ' bullet is misplaced, not silently skipped" "$M_MISP"
malformed_cell md-star-bullet docs/a.md '* Expires-when: #3 closed' "a Markdown '* ' bullet is misplaced (no leaders in Markdown)" "$M_MISP"
malformed_cell blockquote docs/a.md '> Expires-when: #4 closed' "a blockquote is misplaced" "$M_MISP"
malformed_cell ordered docs/a.md '1. Expires-when: #5 closed' "an ordered-list item is misplaced" "$M_MISP"
malformed_cell bold docs/a.md '**Expires-when:** #6 closed' "a bold key is misplaced" "$M_MISP"
malformed_cell table-cell docs/a.md '| a | Expires-when: #7 closed |' "a table cell outside an HTML comment is misplaced" "$M_MISP"
malformed_cell mid-prose docs/a.md $'Note \u2014 Expires-when: #10 closed' "a key mid-sentence is misplaced" "$M_MISP"
malformed_cell mid-comment scripts/a.sh '# NOTE: Expires-when: #16 closed' "a mid-comment '# NOTE: Expires-when:' is misplaced" "$M_MISP"
malformed_cell md-heading docs/a.md '# Expires-when: #101 closed' "a Markdown heading is misplaced" "$M_MISP"

M_STRICT="$(mutant strict-key '/census-guard: near-miss$/s/r"(?:.*)")  #/r"-when:")  #/')"
assert_flips "$FX_NEAR" MALFORMED "near-miss mutation: a strict key no longer SEES the typo, so the cell flips" "$M_STRICT"
M_ISSUE="$(mutant issue-form '/census-guard: issue-form$/s/ISSUE_RE.match(cond)/re.match(r"^#(\\d+)", cond)/')"
assert_flips "$FX_NOCLOSED" MALFORMED "issue-form mutation: a loose issue pattern accepts '#NNNN' alone, so the cell flips" "$M_ISSUE"

# ── cell N: things that are NOT markers (the loose bound) ─────────────────
# Each example would be MALFORMED if it were read as a marker (a placeholder
# issue number), so a census that reads any of them fails this cell. Prose
# that talks about the convention puts the key in backticks.
FX_N="$(new_fixture not-markers)"
cat >"$FX_N/docs/a.md" <<'MD'
# Convention

Use `<!-- Expires-when: #NNNN closed -->` in Markdown; `Expires-when:` is the key.

```
# Expires-when: #NNNN closed
<!-- Expires-when: #NNNN closed -->
```

~~~
Expires-when: #NNNN closed
~~~

- The one real marker.
  <!-- Expires-when: #101 closed -->
MD
printf '%s\n' '# the key is `Expires-when:` -- see the skill' >"$FX_N/scripts/doc.sh"
assert_clean "$FX_N" 1 "not markers: inline code spans (Markdown and shell), a backtick fence and a tilde fence are skipped; the one real marker is read"
M_FENCE="$(mutant fence '/census-guard: fence$/s/spans, unclosed = fence_spans(raw, starts, lines)/spans, unclosed = [], None/')"
assert_not_clean "$FX_N" 1 "not markers mutation: without fences the fenced examples are read" "$M_FENCE"
M_TILDE="$(mutant tilde-ignored '/census-guard: tilde$/s/(b"```", b"~~~")/(b"```",)/')"
assert_not_clean "$FX_N" 1 "not markers mutation: ignoring ~~~ fences reads the tilde-fenced example" "$M_TILDE"
M_INLINE="$(mutant inline-code '/census-guard: inline-code$/s/text = INLINE_CODE_RE.sub(lambda m: " " \* len(m.group(0)), text)/pass/')"
assert_not_clean "$FX_N" 1 "not markers mutation: without the code-span strip the backticked key is read" "$M_INLINE"

# ── cell F: fences follow CommonMark (type and length), and an unclosed ───
# fence that would swallow a marker-shaped line is reported.
FX_F="$(new_fixture fences)"
printf '%s\n' '~~~' '```' '~~~' 'Expires-when: #101 closed' >"$FX_F/docs/parity.md"
assert_clean "$FX_F" 1 "fence parity: a \`\`\` inside a ~~~ block does not close it, so the marker after the block is read"
M_TOGGLE="$(mutant fence-any-closes '/census-guard: fence-match$/s/elif run\[:1\] == open_\[1\] and len(run) >= open_\[2\] and not rest.strip():/elif True:/')"
assert_not_clean "$FX_F" 1 "fence parity mutation: closing on ANY fence line (the old toggle) swallows the marker" "$M_TOGGLE"
FX_F2="$(new_fixture unclosed)"
printf '%s\n' '```' 'example' 'Expires-when: #101 closed' >"$FX_F2/docs/a.md"
printf '%s\n' '# Expires-when: #101 closed' >"$FX_F2/scripts/ok.sh"
assert_fails "$FX_F2" MALFORMED "unclosed fence: a fence that never closes, with a marker-shaped line after it, reds instead of hiding it"
M_UNCL="$(mutant unclosed-fence "$(guard_off unclosed-fence)")"
assert_flips "$FX_F2" MALFORMED "unclosed fence mutation: with the report off the swallowed marker goes unseen" "$M_UNCL"
FX_F3="$(new_fixture unclosed-quiet)"
printf '%s\n' '```' 'code that a review mentions' 'more review text' >"$FX_F3/docs/a.md"
printf '%s\n' '# Expires-when: #101 closed' >"$FX_F3/scripts/ok.sh"
assert_clean "$FX_F3" 1 "unclosed fence, nothing marker-shaped after it: no report (low noise on old docs)"

# ── cell Z: the empty sweeps ──────────────────────────────────────────────
FX_Z="$(new_fixture no-markers)"
printf '%s\n' '# Nothing temporary here.' >"$FX_Z/docs/a.md"
assert_fails "$FX_Z" EMPTY "empty sweep: zero markers is a FAIL, not a clean board"
M_EMPTY="$(mutant empty-markers "$(guard_off empty-markers)")"
assert_flips "$FX_Z" EMPTY "empty sweep mutation: with the zero-marker check off the cell flips" "$M_EMPTY"

FX_ZS="$WORK/no-files"
mkdir -p "$FX_ZS/docs" "$FX_ZS/scripts"
FX_SCOPE="docs scripts" assert_fails "$FX_ZS" EMPTY-SCAN "empty scan: a scope that yields zero files is a FAIL"
M_EMPTYF="$(mutant empty-files "$(guard_off empty-files)")"
FX_SCOPE="docs scripts" assert_flips "$FX_ZS" EMPTY-SCAN "empty scan mutation: with the zero-file check off the cell flips" "$M_EMPTYF"

# ── cell X: the named self-exclusion cannot rot ───────────────────────────
FX_X="$(new_fixture stale-exclude)"
printf '%s\n' '# Expires-when: #101 closed' >"$FX_X/scripts/a.sh"
FX_EXCLUDE="scripts/gone.py" assert_fails "$FX_X" SCOPE "stale exclusion: excluding a path that does not exist reds"
M_EXCL="$(mutant stale-exclude "$(guard_off stale-exclude)")"
FX_EXCLUDE="scripts/gone.py" assert_flips "$FX_X" SCOPE "stale exclusion mutation: with the check off the cell flips" "$M_EXCL"
printf '%s\n' '# Expires-when:' >"$FX_X/scripts/excluded.py"
FX_EXCLUDE="scripts/excluded.py" assert_clean "$FX_X" 1 "exclusion: an excluded file's quoted markers are not read"

# ── cell K: the DEFAULT scope and exclusions ──────────────────────────────
# README.md, AGENTS.md, pkg/**/README.md and .service files are read; a
# non-README Markdown under pkg/ and the generated docs/issues/ are not.
FX_K="$WORK/default-scope"
mkdir -p "$FX_K/docs/issues" "$FX_K/.claude/skills" "$FX_K/test/incus" "$FX_K/scripts" "$FX_K/pkg/a/b"
: >"$FX_K/Makefile"
: >"$FX_K/CLAUDE.md"
: >"$FX_K/scripts/instructions-census.py"
: >"$FX_K/test/incus/instructions-census-selftest.sh"
printf '%s\n' '<!-- Expires-when: #101 closed -->' >"$FX_K/README.md"
printf '%s\n' '<!-- Expires-when: #101 closed -->' >"$FX_K/AGENTS.md"
printf '%s\n' '<!-- Expires-when: #101 closed -->' >"$FX_K/pkg/a/b/README.md"
printf '%s\n' '<!-- Expires-when: #NNNN closed -->' >"$FX_K/pkg/a/b/notes.md"
printf '%s\n' '# Expires-when: #101 closed' '[Unit]' >"$FX_K/test/incus/x.service"
printf '%s\n' 'Quoted from GitHub: - Expires-when: #NNNN closed' >"$FX_K/docs/issues/issue-history.md"
OUT=$(INSTR_CENSUS_ROOT="$FX_K" INSTR_CENSUS_TODAY="$TODAY" INSTR_CENSUS_TOUCHED="" "$PY" "$CENSUS" 2>&1)
RC=$?
if [[ $RC -eq 0 && "$OUT" == *"instructions census: 4 marker(s)"* ]]; then
	ok "default scope: README.md, AGENTS.md, pkg/**/README.md and a .service file are read; pkg/**/notes.md and docs/issues/ are not"
else
	bad "default scope: expected 4 markers and a clean pass (rc=$RC)"
	printf '%s\n' "$OUT" | sed 's/^/         /' >&2
fi

# ── cell O: CLAUDE.md is read, reported as an owner action, never written ─
FX_O="$(new_fixture claude-md)"
printf '%s\n' '# Expires-when: #101 closed' >"$FX_O/scripts/a.sh"
printf '%s\n' '# Rules' '' '- old rule' '  <!-- Expires-when: #102 closed -->' >"$FX_O/CLAUDE.md"
before=$(sha256sum "$FX_O/CLAUDE.md")
run_census "$FX_O" "$CENSUS" --online --all
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
