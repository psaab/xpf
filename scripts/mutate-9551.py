#!/usr/bin/env python3
"""Mutation matrix for the #9551 close-keyword lint and its wiring.

Discipline:
  * every mutant is proven APPLIED by count; a removal is counted 1 -> 0;
  * every file is restored from `git show HEAD:`, never from a private backup,
    and each restore is verified with `git diff --quiet`;
  * each run is bounded, and a hang is VOID;
  * a run with fewer than 50 executed tests, or a module that failed to load,
    is VOID, never a kill;
  * kills are scored by the failing test's QUALIFIED NAME, and a kill that
    misses the mutant's expected cell is flagged. A mutation caught by the
    wrong cell reads as a working guard.
The tree must be committed and clean before it runs.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEST = "scripts/test_close_keyword_lint.py"
L = "scripts/close_keyword_lint.py"
CI = "scripts/close_keyword_lint_ci.sh"
HOOK = "scripts/git-hooks/commit-msg"
INST = "scripts/git-hooks/install.sh"

CUE_CELLS = {
    "not": "NegationCueTest.test_not", "n't": "NegationCueTest.test_contraction",
    "cannot": "NegationCueTest.test_cannot", "never": "NegationCueTest.test_never",
    "no longer": "NegationCueTest.test_no_longer", "rather than": "NegationCueTest.test_rather_than",
    "instead of": "NegationCueTest.test_instead_of", "without": "NegationCueTest.test_without",
    "unlike": "NegationCueTest.test_unlike", "neither/nor": "NegationCueTest.test_neither_nor",
    "partial": "NegationCueTest.test_partial", "partly": "NegationCueTest.test_partly",
    "scope": "ScopingHeadingTest.test_scope", "non-goal": "ScopingHeadingTest.test_non_goal",
    "deferred": "ScopingHeadingTest.test_deferred", "follow-up": "ScopingHeadingTest.test_follow_up",
}


def cue_line(name: str) -> str:
    src = (ROOT / L).read_text()
    lines = [ln + "\n" for ln in src.splitlines() if ln.lstrip().startswith(f'("{name}", ')]
    assert len(lines) == 1, f"cue line for {name!r}: {lines}"
    return lines[0]


MUTANTS = [(f"cue:{c}", L, cue_line(c), "", cell) for c, cell in CUE_CELLS.items()] + [
    ("boundary: line break removed", L, r'CLAUSE_BOUNDARY_RE = re.compile(r"\n|\||[.!?;](?=\s)")',
     r'CLAUSE_BOUNDARY_RE = re.compile(r"\||[.!?;](?=\s)")',
     "AcceptedRowsTest.test_a_negation_on_the_line_above_does_not_leak"),
    ("boundary: terminator without trailing whitespace", L, r'[.!?;](?=\s)")', r'[.!?;]")',
     "ClauseBoundaryTest.test_a_filename_dot_is_not_a_terminator"),
    ("boundary: sentence terminators removed", L, r'"\n|\||[.!?;](?=\s)"', r'"\n|\|"',
     "AcceptedRowsTest.test_a_sentence_terminator_ends_the_clause"),
    ("boundary: table pipe removed", L, r'"\n|\||[.!?;](?=\s)"', r'"\n|[.!?;](?=\s)"',
     "AcceptedRowsTest.test_a_table_cell_is_its_own_clause"),
    ("boundary: comma added (the plausible wrong fix)", L, r'"\n|\||[.!?;](?=\s)"', r'"\n|\||,|[.!?;](?=\s)"',
     "ClauseBoundaryTest.test_a_parenthetical_comma_does_not_hide_the_negation"),
    ("predicate: emphasis not stripped", L, '    return EMPHASIS_RE.sub("", text)\n', "    return text\n",
     "IncidentShapesTest.test_emphasis_between_the_keyword_and_the_number"),
    ("predicate: no line-break span", L, r'KEYWORD + r"\s*:?\s*" + REF', r'KEYWORD + r"[ \t]*:?[ \t]*" + REF',
     "PredicateTest.test_heading_then_paragraph_closes_across_the_blank_line"),
    ("predicate: colon form dropped", L, r'KEYWORD + r"\s*:?\s*" + REF', r'KEYWORD + r"\s+" + REF',
     "PredicateTest.test_documented_forms"),
    ("predicate: URL form dropped", L, r'|https?://github\.com/(?P<uslug>', r'|NEVERMATCH(?P<uslug>',
     "PredicateTest.test_url_form_is_matched"),
    ("predicate: owner/repo form dropped", L, r'(?P<slug>[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+)?#', r'(?P<slug>\b\B)?#',
     "PredicateTest.test_documented_forms"),
    ("predicate: no leading word boundary", L, r'KEYWORD = r"\b(?P<kw>', r'KEYWORD = r"(?P<kw>',
     "PredicateTest.test_words_that_are_not_keywords"),
    ("verdict: whole-body instead of per-pair", L, "    return pairs, refused\n",
     "    return pairs, ([Refusal(p, refused[0].cue, refused[0].why) for p in pairs] if refused else refused)\n",
     "AcceptedRowsTest.test_a_mixed_body_refuses_only_the_negated_pair"),
    ("verdict: negation read after the keyword too", L,
     "cue = _first_cue(NEGATION_CUES, _clause_before(norm, p.start))",
     "cue = _first_cue(NEGATION_CUES, _clause_before(norm, p.start) + norm[p.start:p.start + 200])",
     "AcceptedRowsTest.test_a_negation_after_the_pair"),
    ("verdict: heading rule applied to every line", L, "        if HEADING_RE.match(prefix):\n", "        if True:\n",
     "ScopingHeadingTest.test_a_scoping_word_outside_a_heading_is_accepted"),
    ("verdict: heading cue read to end of line", L, "        prefix = _line_prefix(norm, p.start)\n",
     "        prefix = _line_prefix(norm, p.start) + norm[p.start:].split('\\n', 1)[0]\n",
     "ScopingHeadingTest.test_a_scoping_word_after_the_keyword_on_a_heading_is_accepted"),
    ("cli: refusal exits 0", L, "    return 1 if refused else 0\n", "    return 0\n",
     "CliTest.test_exit_status_for_files_stdin_and_usage"),
    ("cli: unreadable input fails open", L,
     '        print(f"close-keyword lint: cannot read input: {e}", file=sys.stderr)\n        return 2\n',
     '        print(f"close-keyword lint: cannot read input: {e}", file=sys.stderr)\n        return 0\n',
     "CliTest.test_an_unreadable_range_fails_closed"),
    ("ci: body leg dropped", CI,
     'printf \'%s\' "${PR_BODY-}" | python3 "$lint" --source "PR ${PR_NUMBER:-?} body" -\nbody_rc=$?\n',
     "body_rc=0\n", "CiLegsTest.test_the_body_leg_refuses_a_negated_body"),
    ("ci: commit leg dropped", CI, 'python3 "$lint" --commits "${BASE_SHA}..${HEAD_SHA}"\ncommits_rc=$?\n',
     "commits_rc=0\n", "CiLegsTest.test_the_commit_leg_refuses_a_negated_commit_message"),
    ("ci: verdict is the better leg", CI, 'if [ "$body_rc" -ne 0 ] || [ "$commits_rc" -ne 0 ]; then',
     'if [ "$body_rc" -ne 0 ] && [ "$commits_rc" -ne 0 ]; then',
     "CiLegsTest.test_the_body_leg_refuses_a_negated_body"),
    ("ci: missing range fails open", CI, "required\" >&2\n\texit 2\n", "required\" >&2\n\texit 0\n",
     "CiLegsTest.test_a_missing_range_fails_closed"),
    ("ci: body shell-evaluated", CI, 'printf \'%s\' "${PR_BODY-}" |', 'eval "printf \'%s\' \\"${PR_BODY-}\\"" |',
     "CiLegsTest.test_the_body_is_never_shell_evaluated"),
    ("hook: lint not run", HOOK, 'exec python3 "$lint" --source "commit message" "$1"\n', "exit 0\n",
     "CommitHookTest.test_refuses_a_negated_message_and_admits_a_real_close"),
    ("hook: fails closed without the lint", HOOK, '[ -f "$lint" ] || exit 0\n', '[ -f "$lint" ] || exit 1\n',
     "CommitHookTest.test_fails_open_where_the_worktree_predates_the_linter"),
    ("install: overwrites an existing hook", INST, 'if [ -e "$target" ]; then\n', "if false; then\n",
     "CommitHookTest.test_the_installer_refuses_to_replace_a_different_hook"),
    ("install: ignores core.hooksPath", INST, "hooks=$(git rev-parse --git-path hooks)\n",
     "hooks=$(git rev-parse --git-dir)/hooks\n",
     "CommitHookTest.test_refuses_a_negated_message_and_admits_a_real_close"),
]


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)


def restore(path):
    head = git("show", f"HEAD:{path}").stdout
    (ROOT / path).write_text(head)
    if git("diff", "--quiet", "--", path).returncode != 0:
        raise SystemExit(f"RESTORE FAILED for {path}")


def run_cells(timeout=240):
    try:
        p = subprocess.run([sys.executable, "-m", "unittest", "-v", TEST], cwd=ROOT,
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "VOID(hang)", [], 0
    out = p.stdout + p.stderr
    m = re.search(r"^Ran (\d+) tests?", out, re.M)
    ran = int(m.group(1)) if m else 0
    # Normalise to Class.test. unittest qualifies names by how the file was
    # loaded (`scripts.test_close_keyword_lint.X.y` under `-m unittest <path>`).
    # v1 stripped only the module name, left a `scripts.` prefix, and so scored
    # all 45 real kills as KILLED-BY-OTHER-CELL.
    failed = sorted({".".join(q.split(".")[-2:])
                     for q in re.findall(r"^(?:FAIL|ERROR): \w+ \(([\w.]+)\)", out, re.M)})
    if "_FailedTest" in out or ran < 50:
        return f"VOID(ran={ran} or load failure)", failed, ran
    return ("KILLED" if failed else "SURVIVED"), failed, ran


def main():
    if git("status", "--porcelain").stdout.strip():
        raise SystemExit("ABORT: commit before running the matrix (tree is dirty)")
    v, failed, ran = run_cells()
    print(f"BASELINE: {v} ran={ran} failed={failed}")
    if v != "SURVIVED":
        raise SystemExit("ABORT: baseline is not clean")
    rows = []
    for name, path, old, new, expect in MUTANTS:
        src = (ROOT / path).read_text()
        before = src.count(old)
        mutated = src.replace(old, new, 1)
        after = mutated.count(old)
        applied = before == 1 and (after == 0 or (old in new and mutated != src))
        if not applied:
            rows.append((name, f"VOID(not applied: {before}->{after})", [], expect))
            print(f"{name}: VOID not applied {before}->{after}")
            continue
        (ROOT / path).write_text(mutated)
        try:
            v, failed, ran = run_cells()
        finally:
            restore(path)
        verdict = v
        if v == "KILLED" and expect not in failed:
            verdict = "KILLED-BY-OTHER-CELL"
        rows.append((name, verdict, failed, expect))
        print(f"{name}: applied {before}->{after}; {verdict} ran={ran}; expected={expect}; failed={failed}")
    if git("status", "--porcelain").stdout.strip():
        raise SystemExit("POSTCONDITION FAILED: tree not clean after matrix")
    print("\n=== MATRIX ===")
    for name, verdict, failed, expect in rows:
        print(f"{verdict:22} {name}")
    bad = [r for r in rows if r[1] != "KILLED"]
    print(f"\n{len(rows) - len(bad)}/{len(rows)} KILLED by their expected cell; not clean: {[r[0] for r in bad]}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
