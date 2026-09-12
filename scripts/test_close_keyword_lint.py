#!/usr/bin/env python3
"""Cells for scripts/close_keyword_lint.py (#9551).

The load-bearing rows are the ACCEPTED ones. A lint that refuses every `#N`
passes every refusal cell in this file, and it would be worse than the defect,
because it blocks the `Closes #N` a real fix is required to carry. So each
accept row is the control for one specific clause boundary.

Mutation shape: every negation cue and every scoping-heading cue has a cell in
which it is the ONLY cue. Deleting one cue from its table therefore reds a
distinct, named cell. A single mutant that deletes the whole table would show
only that the table matters as a unit, not which cue is load-bearing.
"""

from __future__ import annotations

import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINT = ROOT / "scripts" / "close_keyword_lint.py"
_spec = importlib.util.spec_from_file_location("close_keyword_lint", LINT)
ckl = importlib.util.module_from_spec(_spec)
# dataclasses resolves string annotations through sys.modules, so the module
# must be registered before it executes.
sys.modules[_spec.name] = ckl
_spec.loader.exec_module(ckl)


def pair_refs(text):
    return [p.ref for p in ckl.close_pairs(text)]


def refused_refs(text):
    return [r.pair.ref for r in ckl.refusals(text)[1]]


def only_cue(test, text):
    refused = ckl.refusals(text)[1]
    test.assertEqual(len(refused), 1, f"expected exactly one refusal for {text!r}, got {refused}")
    return refused[0].cue


class PredicateTest(unittest.TestCase):
    """What GitHub acts on: the documented forms plus the measured shapes."""

    def test_documented_forms(self):
        self.assertEqual(pair_refs("Closes #10"), ["#10"])
        self.assertEqual(pair_refs("Fixes octo-org/octo-repo#100"), ["octo-org/octo-repo#100"])
        for text in ("Closes: #10", "CLOSES #10", "CLOSES: #10"):
            self.assertEqual(pair_refs(text), ["#10"], text)

    def test_every_documented_keyword(self):
        for kw in ("close", "closes", "closed", "fix", "fixes", "fixed",
                   "resolve", "resolves", "resolved"):
            self.assertEqual(pair_refs(f"{kw} #7"), ["#7"], kw)
            self.assertEqual(pair_refs(f"{kw.capitalize()} #7"), ["#7"], kw)

    def test_a_keyword_acts_on_the_first_reference_only(self):
        self.assertEqual(pair_refs("Resolves #10, #11"), ["#10"])
        self.assertEqual(pair_refs("Resolves #10, resolves #123"), ["#10", "#123"])

    def test_emphasis_and_code_spans_do_not_break_the_token(self):
        self.assertEqual(pair_refs("It does not **fix #9412**"), ["#9412"])
        self.assertEqual(pair_refs("it would fix `#9412`"), ["#9412"])
        self.assertEqual(pair_refs("_closes_ #3"), ["#3"])

    def test_heading_then_paragraph_closes_across_the_blank_line(self):
        self.assertEqual(pair_refs("## What this does NOT close\n\n`#7406` is out of scope."), ["#7406"])

    def test_url_form_is_matched(self):
        self.assertEqual(pair_refs("fixes https://github.com/psaab/xpf/issues/12"), ["psaab/xpf#12"])

    def test_words_that_are_not_keywords(self):
        for text in ("enclosed #5", "prefix #5", "fixing #5", "closer #5", "Refs #5",
                     "#5 remains open", "a fix for #5", "snake_fix #5"):
            self.assertEqual(pair_refs(text), [], text)

    def test_line_numbers_survive_normalization(self):
        (p,) = ckl.close_pairs("a\n**b**\ncloses #3")
        self.assertEqual(p.line, 3)


class IncidentShapesTest(unittest.TestCase):
    """The recorded wrong closes, in the shape each one actually took."""

    def test_scope_heading_in_a_pr_body(self):
        self.assertEqual(refused_refs("## Scope — this does not close #9016"), ["#9016"])

    def test_negated_sentence_in_a_commit_message(self):
        self.assertEqual(refused_refs("It does not fix #9412, which stays OPEN."), ["#9412"])

    def test_bold_around_the_phrase(self):
        # The markers sit OUTSIDE the pair, so this passes with or without
        # stripping. It pins the incident's real shape, not the stripping.
        self.assertEqual(refused_refs("It does not **fix #9412**."), ["#9412"])

    def test_emphasis_between_the_keyword_and_the_number(self):
        # Only stripping can join these: `**` sits between keyword and number.
        self.assertEqual(refused_refs("It does not **fix** #9412."), ["#9412"])

    def test_heading_ending_in_the_keyword_across_a_blank_line(self):
        self.assertEqual(refused_refs("## What this does NOT close\n\n`#7406` is out of scope."), ["#7406"])


class NegationCueTest(unittest.TestCase):
    """One cell per NEGATION_CUES entry; each text carries that cue alone."""

    def test_not(self):
        self.assertEqual(only_cue(self, "This change does not close #1"), "not")

    def test_contraction(self):
        self.assertEqual(only_cue(self, "This change doesn't close #1"), "n't")

    def test_contraction_with_a_typographic_apostrophe(self):
        self.assertEqual(only_cue(self, "This change doesn’t close #1"), "n't")

    def test_cannot(self):
        self.assertEqual(only_cue(self, "The sweep cannot fix #1"), "cannot")

    def test_never(self):
        self.assertEqual(only_cue(self, "This never fixed #1"), "never")

    def test_no_longer(self):
        self.assertEqual(only_cue(self, "The guard no longer closes #1"), "no longer")

    def test_rather_than(self):
        self.assertEqual(only_cue(self, "Pin the value rather than fix #1"), "rather than")

    def test_instead_of(self):
        self.assertEqual(only_cue(self, "Add a guard instead of fix #1"), "instead of")

    def test_without(self):
        self.assertEqual(only_cue(self, "Lands the comment without fix #1"), "without")

    def test_unlike(self):
        self.assertEqual(only_cue(self, "Unlike the fix #1 there is no wire change"), "unlike")

    def test_neither_nor(self):
        self.assertEqual(only_cue(self, "It neither closes #1"), "neither/nor")

    def test_partial(self):
        self.assertEqual(only_cue(self, "A partial fix #1"), "partial")

    def test_partly(self):
        self.assertEqual(only_cue(self, "This partly resolves #1"), "partly")


class ScopingHeadingTest(unittest.TestCase):
    """One cell per SCOPING_HEADING_CUES entry, plus the two controls."""

    def test_scope(self):
        self.assertEqual(only_cue(self, "## Scope: closes #7 for the v4 half"), "scope")

    def test_non_goal(self):
        self.assertEqual(only_cue(self, "## Non-goals — fixes #7"), "non-goal")

    def test_deferred(self):
        self.assertEqual(only_cue(self, "## Deferred: resolves #7"), "deferred")

    def test_follow_up(self):
        self.assertEqual(only_cue(self, "## Follow-ups: closes #7"), "follow-up")

    def test_a_scoping_word_outside_a_heading_is_accepted(self):
        self.assertEqual(refused_refs("Scope: closes #7 for the v4 half"), [])

    def test_a_heading_without_a_scoping_cue_is_accepted(self):
        self.assertEqual(refused_refs("## Fixes #12: carry the domain"), [])

    def test_a_scoping_word_after_the_keyword_on_a_heading_is_accepted(self):
        self.assertEqual(refused_refs("## Fixes #12: follow-ups listed below"), [])


class AcceptedRowsTest(unittest.TestCase):
    """The load-bearing rows. A refuse-everything lint reds every one."""

    def test_closes_alone_on_a_line(self):
        self.assertEqual(pair_refs("Closes #9546"), ["#9546"])
        self.assertEqual(refused_refs("Closes #9546"), [])

    def test_refs_is_not_a_close(self):
        self.assertEqual(pair_refs("Refs #9016"), [])

    def test_prose_reference_without_a_close_verb(self):
        self.assertEqual(pair_refs("#9016 remains open; this change is narrower."), [])

    def test_a_negation_on_the_line_above_does_not_leak(self):
        self.assertEqual(refused_refs("This does not touch the helper\nCloses #12"), [])

    def test_a_sentence_terminator_ends_the_clause(self):
        self.assertEqual(refused_refs("It does not regress anything. Fixes #12."), [])

    def test_a_negation_after_the_pair(self):
        self.assertEqual(refused_refs("Fixes #12, not a refactor."), [])

    def test_a_table_cell_is_its_own_clause(self):
        self.assertEqual(refused_refs("| not planned | Closes #12 |"), [])

    def test_a_mixed_body_refuses_only_the_negated_pair(self):
        body = "Fixes #1\n\nThis does not close #2."
        self.assertEqual(pair_refs(body), ["#1", "#2"])
        self.assertEqual(refused_refs(body), ["#2"])
        out, notes = io.StringIO(), io.StringIO()
        self.assertEqual(ckl.lint_text("body", body, out, notes), 1)
        self.assertIn("CLOSES #2", out.getvalue())
        self.assertNotIn("#1", out.getvalue())
        self.assertIn("will close #1", notes.getvalue())


class ClauseBoundaryTest(unittest.TestCase):
    """Where the clause deliberately does NOT end."""

    def test_a_filename_dot_is_not_a_terminator(self):
        self.assertEqual(refused_refs("This does not touch pkg/x.go or fix #3"), ["#3"])

    def test_a_parenthetical_comma_does_not_hide_the_negation(self):
        self.assertEqual(refused_refs("It does not, as the review assumed, fix #5"), ["#5"])

    def test_the_documented_price_of_comma_blindness(self):
        # Refused on purpose. See the module doc: a comma boundary would lose
        # the parenthetical case above, and this author has a spelling that passes.
        self.assertEqual(refused_refs("This is not cosmetic, it fixes #4"), ["#4"])


class FailureTextTest(unittest.TestCase):
    def test_names_the_issue_and_the_safe_spellings(self):
        out, notes = io.StringIO(), io.StringIO()
        ckl.lint_text("src", "This does not close #42", out, notes)
        text = out.getvalue()
        for want in ("REFUSED src:1", "CLOSES #42", "Refs #42", "#42 remains open", "URL"):
            self.assertIn(want, text)


def run_lint(*args, stdin=None, cwd=None):
    return subprocess.run([sys.executable, str(LINT), *args], input=stdin,
                          capture_output=True, text=True, cwd=cwd)


def git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid",
                    "-c", "core.hooksPath=/dev/null", *args],
                   cwd=repo, check=True, capture_output=True, text=True)


class CliTest(unittest.TestCase):
    def test_exit_status_for_files_stdin_and_usage(self):
        with tempfile.TemporaryDirectory() as d:
            clean, bad = Path(d, "clean.md"), Path(d, "bad.md")
            clean.write_text("Closes #1\nRefs #2\n")
            bad.write_text("This does not close #2\n")
            self.assertEqual(run_lint(str(clean)).returncode, 0)
            self.assertEqual(run_lint(str(bad)).returncode, 1)
            self.assertEqual(run_lint("-", stdin="It does not fix #3").returncode, 1)
            self.assertEqual(run_lint(str(Path(d, "missing.md"))).returncode, 2)
            self.assertEqual(run_lint().returncode, 2)

    def test_commits_lints_every_commit_message_in_the_range(self):
        with tempfile.TemporaryDirectory() as repo:
            git(repo, "init", "-q")
            git(repo, "commit", "-q", "--allow-empty", "-m", "base")
            git(repo, "tag", "base")
            git(repo, "commit", "-q", "--allow-empty", "-m", "subject\n\nCloses #1")
            git(repo, "commit", "-q", "--allow-empty", "-m", "subject\n\nIt does not fix #2.")
            res = run_lint("--commits", "base..HEAD", cwd=repo)
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            self.assertIn("CLOSES #2", res.stdout)
            self.assertNotIn("CLOSES #1", res.stdout)
            self.assertIn("will close #1", res.stderr)
            self.assertIn("2 source(s) checked", res.stderr)

    def test_an_unreadable_range_fails_closed(self):
        with tempfile.TemporaryDirectory() as repo:
            git(repo, "init", "-q")
            git(repo, "commit", "-q", "--allow-empty", "-m", "base")
            self.assertEqual(run_lint("--commits", "no-such-ref..HEAD", cwd=repo).returncode, 2)


CI = ROOT / "scripts" / "close_keyword_lint_ci.sh"
HOOK = ROOT / "scripts" / "git-hooks" / "commit-msg"
INSTALL = ROOT / "scripts" / "git-hooks" / "install.sh"


def clean_env(**extra):
    """The environment for a temp repo, with every GIT_* variable removed.

    A GIT_DIR inherited from an enclosing git process would point these
    commands at the REAL repository.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(extra)
    return env


def git_in(repo, *args, check=True):
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=repo, env=clean_env(), capture_output=True, text=True, check=check)


def new_repo(d):
    git_in(d, "init", "-q")
    git_in(d, "config", "core.hooksPath", str(Path(d, ".testhooks")))
    git_in(d, "commit", "-q", "--allow-empty", "-m", "base")
    return git_in(d, "rev-parse", "HEAD").stdout.strip()


def run_ci(repo, body, base, head):
    env = clean_env(PR_BODY=body, PR_NUMBER="7", BASE_SHA=base, HEAD_SHA=head)
    return subprocess.run(["bash", str(CI)], cwd=repo, env=env, capture_output=True, text=True)


class CiLegsTest(unittest.TestCase):
    """Both legs of the pull-request check, each able to refuse on its own."""

    def _repo(self, d, *messages):
        base = new_repo(d)
        for m in messages:
            git_in(d, "commit", "-q", "--allow-empty", "-m", m)
        return base, git_in(d, "rev-parse", "HEAD").stdout.strip()

    def test_the_body_leg_refuses_a_negated_body(self):
        with tempfile.TemporaryDirectory() as d:
            base, head = self._repo(d, "subject\n\nCloses #1")
            res = run_ci(d, "## Scope — this does not close #2", base, head)
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            self.assertIn("REFUSED PR 7 body:1", res.stdout)
            self.assertIn("CLOSES #2", res.stdout)

    def test_the_commit_leg_refuses_a_negated_commit_message(self):
        with tempfile.TemporaryDirectory() as d:
            base, head = self._repo(d, "subject\n\nIt does not fix #3.")
            res = run_ci(d, "Closes #1", base, head)
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            self.assertIn("REFUSED commit ", res.stdout)
            self.assertIn("CLOSES #3", res.stdout)

    def test_a_clean_pull_request_passes(self):
        with tempfile.TemporaryDirectory() as d:
            base, head = self._repo(d, "subject\n\nCloses #1")
            res = run_ci(d, "Closes #1\nRefs #2", base, head)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_a_missing_range_fails_closed(self):
        with tempfile.TemporaryDirectory() as d:
            base, head = self._repo(d)
            self.assertEqual(run_ci(d, "Closes #1", "", head).returncode, 2)

    def test_the_body_is_never_shell_evaluated(self):
        with tempfile.TemporaryDirectory() as d:
            base, head = self._repo(d, "subject")
            body = "$(touch pwned-a) `touch pwned-b` ${PATH:+x}"
            res = run_ci(d, body, base, head)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertFalse(Path(d, "pwned-a").exists())
            self.assertFalse(Path(d, "pwned-b").exists())


class CommitHookTest(unittest.TestCase):
    """The commit path: the installed hook refuses at `git commit` time."""

    def _checkout(self, d, with_hook=True, with_lint=True):
        new_repo(d)
        if with_hook:
            Path(d, "scripts", "git-hooks").mkdir(parents=True)
            Path(d, "scripts", "git-hooks", "commit-msg").write_text(HOOK.read_text())
        if with_lint:
            Path(d, "scripts").mkdir(exist_ok=True)
            Path(d, "scripts", "close_keyword_lint.py").write_text(LINT.read_text())
        res = subprocess.run(["bash", str(INSTALL)], cwd=d, env=clean_env(),
                             capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertTrue(Path(d, ".testhooks", "commit-msg").exists())

    def test_refuses_a_negated_message_and_admits_a_real_close(self):
        with tempfile.TemporaryDirectory() as d:
            self._checkout(d)
            before = git_in(d, "rev-parse", "HEAD").stdout
            res = git_in(d, "commit", "--allow-empty", "-m", "subject\n\nIt does not fix #9.",
                         check=False)
            self.assertNotEqual(res.returncode, 0, "the hook admitted a negated close")
            self.assertIn("CLOSES #9", res.stdout + res.stderr)
            self.assertEqual(git_in(d, "rev-parse", "HEAD").stdout, before)
            res = git_in(d, "commit", "--allow-empty", "-m", "subject\n\nCloses #9", check=False)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_fails_open_where_the_worktree_predates_the_linter(self):
        with tempfile.TemporaryDirectory() as d:
            self._checkout(d, with_hook=True, with_lint=False)
            res = git_in(d, "commit", "--allow-empty", "-m", "It does not fix #9.", check=False)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        with tempfile.TemporaryDirectory() as d:
            self._checkout(d, with_hook=False, with_lint=False)
            res = git_in(d, "commit", "--allow-empty", "-m", "It does not fix #9.", check=False)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_the_installer_refuses_to_replace_a_different_hook(self):
        with tempfile.TemporaryDirectory() as d:
            new_repo(d)
            hooks = Path(d, ".testhooks")
            hooks.mkdir()
            theirs = "#!/bin/sh\nexit 0\n"
            Path(hooks, "commit-msg").write_text(theirs)
            res = subprocess.run(["bash", str(INSTALL)], cwd=d, env=clean_env(),
                                 capture_output=True, text=True)
            self.assertEqual(res.returncode, 1, res.stdout + res.stderr)
            self.assertIn("REFUSING", res.stderr)
            self.assertEqual(Path(hooks, "commit-msg").read_text(), theirs)

    def test_the_installer_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            new_repo(d)
            for want in ("installed", "already installed"):
                res = subprocess.run(["bash", str(INSTALL)], cwd=d, env=clean_env(),
                                     capture_output=True, text=True)
                self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
                self.assertIn(want, res.stdout)


if __name__ == "__main__":
    unittest.main()
