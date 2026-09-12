#!/usr/bin/env python3
"""Refuse a NEGATED GitHub close keyword before it closes an issue (#9551).

GitHub's close-keyword parser does not read negation. A sentence that says an
issue stays open, but puts a close verb in front of the issue number, closes
that issue when it reaches the default branch, exactly like `Closes #N`. It
happened to two issues on one day: once through a PR-body scope heading
(#9016), once through a commit-message sentence saying the change did not fix
the issue (#9412). The rule was already written down and handed to every lane.
Prose did not prevent it, so this is a mechanical refusal.

The predicate: what GitHub acts on (`close_pairs`)
--------------------------------------------------
Documented in docs.github.com/en/issues/tracking-your-work-with-issues/
using-issues/linking-a-pull-request-to-an-issue ("Linking a pull request to an
issue using a keyword"):

  * the keywords are close, closes, closed, fix, fixes, fixed, resolve,
    resolves and resolved;
  * the forms are "KEYWORD #ISSUE-NUMBER" and
    "KEYWORD OWNER/REPOSITORY#ISSUE-NUMBER";
  * "The keywords can be followed by colons or in uppercase", as in
    `Closes: #10`, `CLOSES #10` and `CLOSES: #10`;
  * several issues need "the full syntax for each issue", so a keyword acts
    on the FIRST reference after it and no other;
  * a keyword is honoured in the description of a PR that targets the default
    branch, and in a commit message "when you merge the commit into the
    default branch".

Measured in this repo, from recovered wrong closes (docs/engineering-style.md,
"A closing keyword cannot be negated"):

  * markdown emphasis and code spans do not break the token, so
    `**fix #N**` still closes;
  * a heading that ENDS in the keyword, followed by a paragraph that STARTS
    with the reference, closes across the blank line between them.

The predicate is a deliberate SUPERSET of the documented forms. Whitespace is
optional around the colon, and the issue and pull URL form is matched. An
over-match can only cost a rewording inside a sentence that is already
negated. A miss costs a closed issue.

The refusal (`refusals`)
------------------------
A pair is refused in two cases:
  * its keyword is preceded, within its own clause, by a negation cue
    (NEGATION_CUES);
  * its keyword sits on a markdown heading line carrying a scoping cue
    (SCOPING_HEADING_CUES) before it.
An author who wants the close does not negate it.

The clause runs back from the keyword to the nearest line break, table-cell
pipe, or sentence terminator. A terminator is `.`, `!`, `?` or `;`, and only
counts when whitespace follows it.
  * The line break is load-bearing for the REQUIRED form: `Closes #N` alone on
    a line must not inherit a "not" from the line above.
  * A terminator needs trailing whitespace so a filename, as in
    `pkg/x.go or fix #N`, cannot cut a negation off from its keyword.
  * Commas, dashes and parentheses are deliberately NOT boundaries, so
    "it does not, as the review assumed, fix #N" is caught. The price is that
    "this is not cosmetic, it fixes #N" is refused as well. The failure text
    names the spelling that passes.

Verdicts are PER PAIR, never per body. In "Fixes #1 ... does not close #2",
only #2 is refused and named, so a legitimate close in the same body goes
through.

Where it runs: scripts/close_keyword_lint_ci.sh holds both pull-request legs (the
body and every commit message in a range), and `make close-keyword-lint` plus the
selftest call it. The GitHub Actions job that would run it on every pull request
is NOT in the tree: pushing a workflow file needs an OAuth token with `workflow`
scope, which the token in use does not have (#9551). The commit-msg hook is installed by
`make install-git-hooks`.

Exit status: 0 nothing refused; 1 at least one refusal; 2 usage, read, git or
gh failure. A lint that cannot read its input must not pass.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass

KEYWORD = r"\b(?P<kw>close[sd]?|fix(?:e[sd])?|resolve[sd]?)\b"
REF = (
    r"(?:(?P<slug>[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+)?#(?P<num>[0-9]+)"
    r"|https?://github\.com/(?P<uslug>[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+)"
    r"/(?:issues|pull)/(?P<unum>[0-9]+))"
)
# `\s` spans line breaks: the heading-then-paragraph shape closes across them.
PAIR_RE = re.compile(KEYWORD + r"\s*:?\s*" + REF, re.IGNORECASE)

# Emphasis and code-span markers are removed before matching. An underscore
# counts only at a word edge (`_fix_`), so snake_case survives. None of these
# markers is a line break, so line numbers are preserved.
EMPHASIS_RE = re.compile(r"[*`]|(?<![A-Za-z0-9])_|_(?![A-Za-z0-9])")

# One cue per line, and no cue matches inside another. A mutation that deletes
# exactly one cue is therefore killed by a cell that uses that cue alone.
NEGATION_CUES = (
    ("not", r"\bnot\b"),
    ("n't", r"n['’]t\b"),
    ("cannot", r"\bcannot\b"),
    ("never", r"\bnever\b"),
    ("no longer", r"\bno\s+longer\b"),
    ("rather than", r"\brather\s+than\b"),
    ("instead of", r"\binstead\s+of\b"),
    ("without", r"\bwithout\b"),
    ("unlike", r"\bunlike\b"),
    ("neither/nor", r"\b(?:neither|nor)\b"),
    ("partial", r"\bpartial(?:ly)?\b"),
    ("partly", r"\bpartly\b"),
)

SCOPING_HEADING_CUES = (
    ("scope", r"\bscope\b"),
    ("non-goal", r"\bnon-?goals?\b"),
    ("deferred", r"\bdeferred\b"),
    ("follow-up", r"\bfollow[- ]?ups?\b"),
)

HEADING_RE = re.compile(r"^[ ]{0,3}#{1,6}[ \t]")
CLAUSE_BOUNDARY_RE = re.compile(r"\n|\||[.!?;](?=\s)")


@dataclass(frozen=True)
class Pair:
    """One (keyword, reference) that GitHub will act on."""

    keyword: str
    ref: str
    number: int
    start: int
    line: int
    phrase: str


@dataclass(frozen=True)
class Refusal:
    pair: Pair
    cue: str
    why: str  # "negated" or "scoping heading"


def normalize(text: str) -> str:
    return EMPHASIS_RE.sub("", text)


def close_pairs(text: str) -> list[Pair]:
    """Every (keyword, reference) pair GitHub would act on, in order."""
    norm = normalize(text)
    pairs = []
    for m in PAIR_RE.finditer(norm):
        num = m.group("num") or m.group("unum")
        slug = m.group("slug") or m.group("uslug")
        start = m.start("kw")
        pairs.append(
            Pair(
                keyword=m.group("kw"),
                ref=f"{slug}#{num}" if slug else f"#{num}",
                number=int(num),
                start=start,
                line=norm.count("\n", 0, start) + 1,
                phrase=" ".join(m.group(0).split()),
            )
        )
    return pairs


def _compiled(cues):
    return [(name, re.compile(rx, re.IGNORECASE)) for name, rx in cues]


def _first_cue(cues, text: str) -> str | None:
    for name, rx in _compiled(cues):
        if rx.search(text):
            return name
    return None


def _clause_before(norm: str, start: int) -> str:
    cut = 0
    for b in CLAUSE_BOUNDARY_RE.finditer(norm, 0, start):
        cut = b.end()
    return norm[cut:start]


def _line_prefix(norm: str, start: int) -> str:
    return norm[norm.rfind("\n", 0, start) + 1 : start]


def refusals(text: str) -> tuple[list[Pair], list[Refusal]]:
    """All pairs, and the subset refused. Decided per pair."""
    norm = normalize(text)
    pairs = close_pairs(text)
    refused = []
    for p in pairs:
        cue = _first_cue(NEGATION_CUES, _clause_before(norm, p.start))
        if cue:
            refused.append(Refusal(p, cue, "negated"))
            continue
        prefix = _line_prefix(norm, p.start)
        if HEADING_RE.match(prefix):
            cue = _first_cue(SCOPING_HEADING_CUES, prefix)
            if cue:
                refused.append(Refusal(p, cue, "scoping heading"))
    return pairs, refused


def format_refusal(source: str, r: Refusal) -> str:
    p = r.pair
    what = "a negation" if r.why == "negated" else "a scoping heading"
    return (
        f'REFUSED {source}:{p.line}: "{p.phrase}" CLOSES {p.ref} when this '
        f"reaches the default branch.\n"
        f"  GitHub's close-keyword parser does not read negation, and this "
        f'keyword follows {what} ("{r.cue}").\n'
        f"  Name the issue with no close verb in front of the number, e.g.:\n"
        f"    Refs {p.ref}\n"
        f"    {p.ref} remains open; this change is narrower\n"
        f"    or link the issue by its URL, with no close verb before it\n"
    )


def lint_text(source: str, text: str, out, notes) -> int:
    pairs, refused = refusals(text)
    refused_starts = {r.pair.start for r in refused}
    for r in refused:
        out.write(format_refusal(source, r))
    for p in pairs:
        if p.start not in refused_starts:
            notes.write(f"will close {p.ref}: {source}:{p.line}: \"{p.phrase}\"\n")
    return len(refused)


def commit_messages(rev_range: str, cwd: str | None = None) -> list[tuple[str, str]]:
    """(sha, full message) for every commit in `rev_range`, oldest last."""
    res = subprocess.run(
        ["git", "log", "--format=%H%x00%B%x1e", rev_range],
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(f"git log {rev_range} failed: {res.stderr.strip()}")
    out = []
    for rec in res.stdout.split("\x1e"):
        rec = rec.lstrip("\n")
        if not rec:
            continue
        sha, _, body = rec.partition("\x00")
        out.append((sha, body))
    return out


def pr_sources(number: str) -> list[tuple[str, str]]:
    res = subprocess.run(
        ["gh", "pr", "view", number, "--json", "body,commits"],
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(f"gh pr view {number} failed: {res.stderr.strip()}")
    data = json.loads(res.stdout)
    sources = [(f"PR {number} body", data.get("body") or "")]
    for c in data.get("commits") or []:
        msg = (c.get("messageHeadline") or "") + "\n\n" + (c.get("messageBody") or "")
        sources.append((f"commit {c.get('oid', '?')[:12]}", msg))
    return sources


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Refuse a negated GitHub close keyword (#9551)."
    )
    ap.add_argument("files", nargs="*", help="text files to lint; '-' reads stdin")
    ap.add_argument("--source", help="label for a single file or stdin")
    ap.add_argument("--commits", metavar="RANGE", help="lint every commit message in RANGE")
    ap.add_argument("--pr", metavar="N", help="lint PR N's body and commit messages (gh)")
    args = ap.parse_args(argv)
    if not (args.files or args.commits or args.pr):
        ap.print_usage(sys.stderr)
        return 2

    sources: list[tuple[str, str]] = []
    try:
        for f in args.files:
            label = args.source or ("stdin" if f == "-" else f)
            text = sys.stdin.read() if f == "-" else open(f, encoding="utf-8").read()
            sources.append((label, text))
        if args.commits:
            for sha, body in commit_messages(args.commits):
                sources.append((f"commit {sha[:12]}", body))
        if args.pr:
            sources.extend(pr_sources(args.pr))
    except (OSError, RuntimeError, ValueError, UnicodeDecodeError) as e:
        print(f"close-keyword lint: cannot read input: {e}", file=sys.stderr)
        return 2

    refused = sum(lint_text(label, text, sys.stdout, sys.stderr) for label, text in sources)
    print(
        f"close-keyword lint: {len(sources)} source(s) checked, {refused} refused",
        file=sys.stderr,
    )
    return 1 if refused else 0


if __name__ == "__main__":
    sys.exit(main())
