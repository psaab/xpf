#!/usr/bin/env python3
"""scripts/instructions-census.py -- census over EXPIRY MARKERS (#18645).

WHAT IT ASSERTS

  Every temporary instruction that carries an expiry marker states its expiry
  in a form a tool can check, and the expiry has not passed.

  The marker convention (documented for operators in
  .claude/skills/campaign/SKILL.md, "Expiry markers"):

    Expires-when: #NNNN closed
        The instruction stops being true when issue (or PR) NNNN closes.
    Expires-when: <free-text condition>; Review-by: YYYY-MM-DD
        Any other condition. A free-text condition cannot be checked by a
        tool, so it MUST carry a Review-by date, and the date is the trigger.
        The date may be at most HORIZON days (180) ahead, so a far-future
        date cannot become a permanent pass.

  A marker sits on ONE line, in one of these positions:

    * code files (shell, Python, env, Makefile, conf, ...): at the start of
      a line, after optional whitespace and a comment leader (`#`, `//`,
      `;`, `--`, `*`, `/*`);
    * Markdown: a bare line (no leader: `- `, `> `, `1. `, `**` and `#` all
      mean something else there);
    * any file: the first word of an HTML comment, anywhere on the line,
      `<!-- Expires-when: #NNNN closed -->` (also inside a table row).

  Anything else that LOOKS like a key is reported, not ignored: a loose
  spelling of either key anywhere else on a line (a list bullet, a
  blockquote, bold, a table cell outside a comment, mid-sentence prose, a
  mid-comment `# NOTE: Expires-when:`) is MALFORMED ("misplaced"). Prose that
  means to talk about the convention puts the key in a code span
  (backticks), which is removed before the scan, or in a Markdown fenced
  code block.

MODES -- the failure scope

  The syntax checks (malformed, misplaced, no Review-by, beyond the horizon,
  an unclosed Markdown fence) apply to EVERY marker in the scope, always.

  The expiry checks (a Review-by date before today; with --online, a CLOSED
  issue) depend on the mode:

    default (PR mode)  only markers in files the change TOUCHES: the diff
                       against the merge-base with --base REV (default
                       origin/master), plus uncommitted and untracked files.
                       A date that passes on a calendar day therefore reds
                       the PRs that touch that instruction, not every open
                       PR at once (a landing guard that fails every lane on
                       the same day live-locks the queue and invites
                       date-bumping). Expired markers elsewhere are counted
                       in a NOTE. If the diff cannot be computed, every
                       file is treated as touched (fail closed).
    --all              every marker. The campaign keeper's hourly sweep:
                       `make instructions-census-online` runs --online --all
                       and reports expired dates and closed issues for the
                       whole tree.

  In the failure scope, a Review-by within SOON days (14) prints a WARN
  line (lead time), which is not a failure.

  CI runs the default mode against the PR's base. `make instructions-census`
  runs it against origin/master.

WHY IT EXISTS

  Temporary instructions outlived their premise. failover-clock-lib.sh said
  "the loss lab has no NTP" long after the lab had NTP (fixed in #18618);
  CLAUDE.md still names the old loss iperf target; an always-on watcher ran a
  four-day-stale checkout. The ones that DID get retired carried an explicit
  expiry. This census makes the expiry a red test instead of a memory.

FALSIFIABILITY -- what this reports when the property is FALSE

  MALFORMED (a bad key, a misplaced key, a bad or missing condition, a bad
  date, a Markdown fence that never closes with a marker-shaped line after
  it), NO-REVIEW-BY, HORIZON, EXPIRED, CLOSED,
  UNREADABLE (a state that cannot be read; with no `gh` the online check
  exits 77, SKIP, because "we could not ask" is not "it is open"), and the
  empty sweeps EMPTY-SCAN (zero files) and EMPTY (zero markers). Each is a
  fixture AND a mutation cell in test/incus/instructions-census-selftest.sh;
  the mutation edits the line tagged `census-guard: <name>` below and the
  cell must flip.

SCOPE

  docs/, .claude/skills/, test/incus/, scripts/, the Makefile, CLAUDE.md,
  README.md, AGENTS.md and every pkg/**/README.md, by file type (see
  TEXT_SUFFIXES). docs/issues/ is excluded: it is generated from GitHub
  (issue and PR bodies), not instructions. CLAUDE.md is owned by the user:
  the census READS it and never writes it (no file is written by this
  script); a failure there is reported as an owner action. The census's own
  source and self-test are excluded by NAME because they quote markers as
  fixtures; each excluded path must exist, so the exclusion cannot rot.

USAGE
  python3 scripts/instructions-census.py [--base REV]   # PR mode
  python3 scripts/instructions-census.py --all          # sweep
  python3 scripts/instructions-census.py --online --all # the keeper
  Env overrides (used by the self-test): INSTR_CENSUS_ROOT,
  INSTR_CENSUS_SCOPE and INSTR_CENSUS_EXCLUDE (space-separated),
  INSTR_CENSUS_TODAY (YYYY-MM-DD), INSTR_CENSUS_BASE, INSTR_CENSUS_TOUCHED
  (the touched files, space-separated, instead of asking git),
  INSTR_CENSUS_GH_STATE (a command, run with the issue number as its last
  argument, that prints the state), INSTR_CENSUS_VERBOSE=1.
  Exit: 0 clean, 1 FAIL, 77 SKIP (--online without gh), 2 usage.
"""

import bisect
import datetime
import fnmatch
import itertools
import os
import re
import shlex
import shutil
import subprocess
import sys

DEFAULT_SCOPE = ("docs .claude/skills test/incus scripts Makefile CLAUDE.md "
                 "README.md AGENTS.md pkg/**/README.md")
DEFAULT_EXCLUDE = ("scripts/instructions-census.py "
                   "test/incus/instructions-census-selftest.sh docs/issues")
# Read-only files: reported, never written. (Nothing here writes any file;
# this list only changes the remedy text.)
READ_ONLY = {"CLAUDE.md"}
HORIZON_DAYS = 180
SOON_DAYS = 14

TEXT_SUFFIXES = (
    ".md", ".sh", ".bash", ".py", ".env", ".mk", ".conf", ".set",
    ".toml", ".yml", ".yaml", ".unreached", ".floors", ".service",
)
TEXT_NAMES = {"Makefile", "CLAUDE.md"}

CANON_EXPIRES = "Expires-when:"
CANON_REVIEW = "Review-by:"

# Loose spellings, so a typo is reported instead of silently not matching:
# any case, any dash (including U+2010..U+2015 and a no-break space) or
# none, and the "Expires: when" shape.
SEP = "[-_  ‐-―]?"
EXPIRES_LOOSE = (r"[Ee][Xx][Pp][Ii][Rr][Ee][Ss]"
                 r"(?:" + SEP + r"[Ww][Hh][Ee][Nn]\s*:|\s*:\s*[Ww][Hh][Ee][Nn]\b)")  # census-guard: near-miss
REVIEW_LOOSE = r"[Rr][Ee][Vv][Ii][Ee][Ww]" + SEP + r"[Bb][Yy]\s*:"
KEY = "(" + EXPIRES_LOOSE + "|" + REVIEW_LOOSE + ")"
KEY_RE = re.compile(KEY)
LEADER = r"(?:#+|//|;+|--|/\*|\*)"  # census-guard: leader

# Position 1 (code files): line start, after whitespace and a comment leader.
LINE_START_RE = re.compile(r"^\s*" + LEADER + r"?\s*" + KEY + r"(.*)$")  # census-guard: position
# Position 1 (Markdown): a bare line.
MD_START_RE = re.compile(r"^\s*" + KEY + r"(.*)$")
# Position 2 (any file): the first word of an HTML comment.
HTML_RE = re.compile(r"<!--\s*" + KEY + r"(.*?)(?:-->|$)")
# A cheap literal prefilter (a superset of both loose keys): the regex scan is
# ~30x slower and would cost seconds over docs/.
PREFILTER = (b"expires", b"review")
INLINE_CODE_RE = re.compile(r"(`+).*?\1")
FENCE_OPEN_RE = re.compile(rb"^[ \t]*(`{3,}|~{3,})(.*)$")
ISSUE_RE = re.compile(r"^#(\d+) closed$")
DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})$")
REVIEW_TAIL_RE = re.compile(r";\s*(" + REVIEW_LOOSE + r")\s*(.*)$")


class Marker:
    def __init__(self, path, lineno, kind, detail, issue=None, review=None):
        self.path = path
        self.lineno = lineno
        self.kind = kind  # ISSUE | FREE | MALFORMED
        self.detail = detail
        self.issue = issue
        self.review = review  # datetime.date or None

    def where(self):
        return "%s:%d" % (self.path, self.lineno)


def strip_tail(payload):
    # .strip() also removes a CRLF file's trailing CR, which is how CRLF
    # markers parse (the self-test pins it with two CRLF fixtures).
    payload = payload.strip()  # census-guard: crlf
    for tail in ("-->", "*/"):  # census-guard: strip-tail
        if payload.endswith(tail):
            payload = payload[: -len(tail)].rstrip()
    return payload


def parse_date(text):
    m = DATE_RE.match(text)
    if not m:
        return None
    try:
        return datetime.date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def classify(key, payload, path, lineno):
    """Turn one matched key + payload into a Marker."""
    k = re.sub(r"\s+", "", key)
    if re.fullmatch(REVIEW_LOOSE, key):
        return Marker(path, lineno, "MALFORMED",
                      "a Review-by with no Expires-when before it on the same "
                      "line (write `Expires-when: <condition>; Review-by: "
                      "YYYY-MM-DD`)")
    if k != CANON_EXPIRES:
        return Marker(path, lineno, "MALFORMED",
                      "near-miss key %r; the key is exactly %r" % (key.strip(), CANON_EXPIRES))
    payload = strip_tail(payload)
    review = None
    tail = REVIEW_TAIL_RE.search(payload)
    if tail:
        cond = payload[: tail.start()].strip()
        rkey, rval = tail.group(1), strip_tail(tail.group(2))
        if re.sub(r"\s+", "", rkey) != CANON_REVIEW:
            return Marker(path, lineno, "MALFORMED",
                          "near-miss key %r; the key is exactly %r" % (rkey.strip(), CANON_REVIEW))
        review = parse_date(rval)
        if review is None:
            return Marker(path, lineno, "MALFORMED",
                          "Review-by %r is not a real YYYY-MM-DD date" % rval)
    else:
        cond = payload
    if re.search(REVIEW_LOOSE, cond):
        return Marker(path, lineno, "MALFORMED",
                      "Review-by must follow the condition after a `;`")
    if not cond:
        return Marker(path, lineno, "MALFORMED",
                      "empty condition: name an issue (`#NNNN closed`) or a condition")
    if cond.startswith("#"):
        m = ISSUE_RE.match(cond)  # census-guard: issue-form
        if not m:
            return Marker(path, lineno, "MALFORMED",
                          "%r: a condition that starts with `#` must be exactly "
                          "`#NNNN closed`" % cond)
        return Marker(path, lineno, "ISSUE", cond, issue=int(m.group(1)), review=review)
    return Marker(path, lineno, "FREE", cond, review=review)


def scan_line(text, is_md, path, lineno):
    """Markers (and misplaced keys) on one line."""
    text = INLINE_CODE_RE.sub(lambda m: " " * len(m.group(0)), text)  # census-guard: inline-code
    out = []
    spans = []
    m = (MD_START_RE if is_md else LINE_START_RE).match(text)  # census-guard: line-start
    if m:
        out.append(classify(m.group(1), m.group(2), path, lineno))
        spans.append((m.start(1), len(text)))
    else:
        for h in HTML_RE.finditer(text):  # census-guard: html-comment
            out.append(classify(h.group(1), h.group(2), path, lineno))
            spans.append((h.start(1), h.end()))
    for k in KEY_RE.finditer(text):
        inside = any(a <= k.start() < b for a, b in spans)
        if not inside:  # census-guard: misplaced
            out.append(Marker(path, lineno, "MALFORMED",
                              "misplaced key %r: a marker is a bare line in Markdown, a "
                              "comment-leader line in code, or the first word of an HTML "
                              "comment; prose about the convention puts the key in "
                              "backticks" % k.group(0).strip()))
    return out


def fence_spans(raw, starts, lines):
    """Markdown fenced blocks as (open, close) line indices, CommonMark-style.

    A fence closes only on a line of the SAME character, at least as long as
    the opening run, with nothing else on it. A backtick opener whose info
    string holds a backtick is not a fence. Returns (spans, unclosed_open_idx).
    """
    cand = set()
    for lit in (b"```", b"~~~"):  # census-guard: tilde
        i = raw.find(lit)
        while i != -1:
            n = bisect.bisect_right(starts, i) - 1
            if lines[n].lstrip(b" \t").startswith(lit):
                cand.add(n)
            i = raw.find(lit, starts[n] + len(lines[n]) + 1)
    spans = []
    open_ = None
    for i in sorted(cand):
        m = FENCE_OPEN_RE.match(lines[i].rstrip(b"\r"))
        if not m:
            continue
        run, rest = m.group(1), m.group(2)
        if open_ is None:
            if run[:1] == b"`" and b"`" in rest:
                continue
            open_ = (i, run[:1], len(run))
        elif run[:1] == open_[1] and len(run) >= open_[2] and not rest.strip():  # census-guard: fence-match
            spans.append((open_[0], i))
            open_ = None
    unclosed = None
    if open_ is not None:
        unclosed = open_[0]
        spans.append((open_[0], len(lines) - 1))
    return spans, unclosed


def scan_file(path, rel):
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return None, "cannot read: %s" % e
    if b"\0" in raw[:8192]:
        return [], None
    low = raw.lower()
    if not any(p in low for p in PREFILTER):
        return [], None
    is_md = rel.endswith(".md")
    # Work in bytes until a line is a candidate: decoding and lower-casing
    # the whole of docs/ as str costs seconds.
    lines = raw.split(b"\n")
    starts = list(itertools.accumulate((len(ln) + 1 for ln in lines[:-1]), initial=0))
    cand = set()
    for lit in PREFILTER:
        i = low.find(lit)
        while i != -1:
            cand.add(bisect.bisect_right(starts, i) - 1)
            i = low.find(lit, i + 1)
    markers = []
    spans = []
    unclosed = None
    if is_md:
        spans, unclosed = fence_spans(raw, starts, lines)  # census-guard: fence
    opens = [a for a, _ in spans]
    dropped = None
    for idx in sorted(cand):
        line = lines[idx].decode("utf-8", errors="replace")
        j = bisect.bisect_right(opens, idx) - 1
        if j >= 0 and spans[j][0] <= idx <= spans[j][1]:
            # Inside a fence: an example. Unless the fence never closes and
            # the line is marker-shaped, in which case the census would be
            # silently dropping it.
            if (unclosed is not None and spans[j][0] == unclosed and dropped is None
                    and KEY_RE.search(INLINE_CODE_RE.sub(" ", line))):
                dropped = idx
            continue
        markers.extend(scan_line(line, is_md, rel, idx + 1))
    if dropped is not None:  # census-guard: unclosed-fence
        markers.append(Marker(rel, unclosed + 1, "MALFORMED",
                              "code fence opened here is never closed, so the marker-shaped "
                              "line %d after it is invisible to this census; close the fence"
                              % (dropped + 1)))
    return markers, None


def wanted(name):
    return name in TEXT_NAMES or name.endswith(TEXT_SUFFIXES)


def has_shebang(path):
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"#!"
    except OSError:
        return False


def excluded(rel, exclude):
    return any(rel == x or rel.startswith(x.rstrip("/") + "/") for x in exclude)


def walk(root, scope, exclude):
    files = []
    problems = []
    for entry in scope:
        if "**" in entry:
            base, _, pat = entry.partition("/**/")
            if not os.path.isdir(os.path.join(root, base)):
                problems.append("scope entry does not exist: %s" % entry)
                continue
            for d, dirs, names in os.walk(os.path.join(root, base)):
                dirs[:] = sorted(x for x in dirs if x not in (".git", "target", "node_modules"))
                for n in sorted(names):
                    if fnmatch.fnmatch(n, pat):
                        files.append(os.path.relpath(os.path.join(d, n), root))
            continue
        p = os.path.join(root, entry)
        if os.path.isfile(p):
            files.append(entry)
        elif os.path.isdir(p):
            for d, dirs, names in os.walk(p):
                dirs[:] = sorted(x for x in dirs if x not in (".git", "target", "node_modules"))
                for n in sorted(names):
                    full = os.path.join(d, n)
                    if wanted(n) or ("." not in n and has_shebang(full)):
                        files.append(os.path.relpath(full, root))
        else:
            problems.append("scope entry does not exist: %s (stale entry in the census scope)" % entry)
    for x in exclude:
        if not os.path.exists(os.path.join(root, x)):  # census-guard: stale-exclude
            problems.append("excluded path does not exist: %s (stale exclusion -- delete it)" % x)
    files = sorted({f for f in files if not excluded(f, exclude)})
    return files, problems


def git_touched(root, base):
    """Files the change touches: the diff against merge-base(base, HEAD),
    uncommitted changes, and untracked files. None if git cannot say."""
    def git(*args):
        r = subprocess.run(["git", "-C", root] + list(args), capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip() or "git %s failed" % args[0])
        return r.stdout
    try:
        mb = git("merge-base", base, "HEAD").strip()
        out = git("diff", "--name-only", "--no-renames", mb)
        out += git("ls-files", "--others", "--exclude-standard")
    except (OSError, RuntimeError) as e:
        return None, str(e)
    return {x for x in out.split("\n") if x}, None


def default_state(issue):
    out = subprocess.run(
        ["gh", "api", "repos/{owner}/{repo}/issues/%d" % issue, "--jq", ".state"],
        capture_output=True, text=True, timeout=60,
    )
    return out.stdout.strip() if out.returncode == 0 else ""


def main(argv):
    online = False
    sweep = False
    base = os.environ.get("INSTR_CENSUS_BASE", "origin/master")
    args = list(argv)
    while args:
        a = args.pop(0)
        if a == "--online":
            online = True
        elif a == "--all":
            sweep = True
        elif a == "--base" and args:
            base = args.pop(0)
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            print("usage: instructions-census.py [--online] [--all | --base REV]", file=sys.stderr)
            return 2

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.environ.get("INSTR_CENSUS_ROOT") or os.path.dirname(here)
    scope = os.environ.get("INSTR_CENSUS_SCOPE", DEFAULT_SCOPE).split()
    exclude = os.environ.get("INSTR_CENSUS_EXCLUDE", DEFAULT_EXCLUDE).split()
    today_s = os.environ.get("INSTR_CENSUS_TODAY", "")
    if today_s:
        today = parse_date(today_s)
        if today is None:
            print("FATAL: INSTR_CENSUS_TODAY=%r is not YYYY-MM-DD" % today_s, file=sys.stderr)
            return 2
    else:
        today = datetime.datetime.now(datetime.timezone.utc).date()

    fails = []
    notes = []

    def fail(tag, msg):
        fails.append("%s: %s" % (tag, msg))

    files, problems = walk(root, scope, exclude)
    for p in problems:
        fail("SCOPE", p)

    markers = []
    for rel in files:
        got, err = scan_file(os.path.join(root, rel), rel)
        if err:
            fail("SCOPE", "%s: %s" % (rel, err))
            continue
        markers.extend(got)

    if not files:  # census-guard: empty-files
        fail("EMPTY-SCAN", "the scan read ZERO files under: %s (the scope or the walk is wrong)" % " ".join(scope))
    elif not markers:  # census-guard: empty-markers
        fail("EMPTY", "the scan found ZERO expiry markers in %d file(s); a broken matcher "
             "reads exactly like this. If the tree truly has none, retire this census "
             "deliberately." % len(files))

    # The failure scope for the EXPIRY checks.
    if sweep:
        mode = "--all (every marker)"
        in_scope = lambda m: True  # noqa: E731
    else:
        if "INSTR_CENSUS_TOUCHED" in os.environ:
            touched, why = set(os.environ["INSTR_CENSUS_TOUCHED"].split()), None
        else:
            touched, why = git_touched(root, base)
        if touched is None:  # census-guard: diff-fail-closed
            notes.append("could not compute the diff against %s (%s): every marker is in "
                         "the expiry scope" % (base, why))
            mode = "diff vs %s UNAVAILABLE, so every marker" % base
            in_scope = lambda m: True  # noqa: E731
        else:
            mode = "diff vs %s (%d touched file(s))" % (base, len(touched))
            in_scope = lambda m: m.path in touched  # noqa: E731  # census-guard: touched

    def owner(m):
        return " (CLAUDE.md is read-only for agents: owner action)" if m.path in READ_ONLY else ""

    out_expired = 0
    for m in markers:
        if m.kind == "MALFORMED":  # census-guard: malformed
            fail("MALFORMED", "%s: %s%s" % (m.where(), m.detail, owner(m)))
            continue
        if m.kind == "FREE" and m.review is None:  # census-guard: free-needs-review
            fail("NO-REVIEW-BY", "%s: free-text condition %r carries no Review-by date; a tool "
                 "cannot check the condition, so the date is the trigger%s" % (m.where(), m.detail, owner(m)))
        if m.review is None:
            continue
        if (m.review - today).days > HORIZON_DAYS:  # census-guard: horizon
            fail("HORIZON", "%s: Review-by %s is more than %d days ahead (today %s UTC); a "
                 "far-future date is a permanent pass. Pick a date you will re-check by%s"
                 % (m.where(), m.review.isoformat(), HORIZON_DAYS, today.isoformat(), owner(m)))
        if m.review < today:  # census-guard: past-date
            if in_scope(m):
                fail("EXPIRED", "%s: Review-by %s is before today (%s UTC): re-check %r, then "
                     "delete the instruction or move the date with a reason%s"
                     % (m.where(), m.review.isoformat(), today.isoformat(), m.detail, owner(m)))
            else:
                out_expired += 1
        elif in_scope(m) and (m.review - today).days <= SOON_DAYS:  # census-guard: soon
            print("  WARN: SOON: %s: Review-by %s is %d day(s) away: %r"
                  % (m.where(), m.review.isoformat(), (m.review - today).days, m.detail))
    if out_expired:
        notes.append("%d marker(s) outside this change are past their Review-by date; the "
                     "keeper's --all sweep reports and files them" % out_expired)

    skipped = False
    n_checked = 0
    if online:
        cmd = os.environ.get("INSTR_CENSUS_GH_STATE", "")
        if not cmd and shutil.which("gh") is None:
            skipped = True
        else:
            issues = sorted({m.issue for m in markers if m.kind == "ISSUE" and in_scope(m)})
            n_checked = len(issues)
            for n in issues:
                if cmd:
                    r = subprocess.run(shlex.split(cmd) + [str(n)], capture_output=True, text=True)
                    state = r.stdout.strip() if r.returncode == 0 else ""
                else:
                    state = default_state(n)
                state = state.lower()
                where = ", ".join(m.where() + owner(m) for m in markers if m.issue == n and in_scope(m))
                if not state:  # census-guard: unreadable
                    fail("UNREADABLE", "could not read the state of #%d (named at %s)" % (n, where))
                    continue
                if state != "open":  # census-guard: closed-check
                    fail("CLOSED", "#%d is %s, but its expiry marker is still present at %s: "
                         "retire the instruction (delete it, or restate it as permanent "
                         "without the marker)" % (n, state.upper(), where))

    n_issue = sum(1 for m in markers if m.kind == "ISSUE")
    n_free = sum(1 for m in markers if m.kind == "FREE")
    if os.environ.get("INSTR_CENSUS_VERBOSE") == "1":
        for m in markers:
            print("  %-9s %s %s%s" % (m.kind, m.where(), m.detail,
                                      " review-by=" + m.review.isoformat() if m.review else ""))
    for n in notes:
        print("  NOTE: " + n)
    for f in fails:
        print("  FAIL: " + f, file=sys.stderr)
    print("instructions census: %d marker(s) in %d file(s) -- %d issue-linked, %d free-text; "
          "expiry scope: %s%s"
          % (len(markers), len(files), n_issue, n_free, mode,
             "; online: checked %d issue(s)" % n_checked if online and not skipped else ""))
    if fails:
        print("instructions census: FAILED (%d problem(s))" % len(fails), file=sys.stderr)
        return 1
    if skipped:
        print("SKIP: gh not installed -- cannot check whether the named issues are still open",
              file=sys.stderr)
        return 77  # census-guard: skip
    print("instructions census: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
