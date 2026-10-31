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

  A marker sits on ONE line, in one of two positions:

    * at the start of a line, after optional whitespace and an optional
      comment leader (`#`, `//`, `;`, `--`, `*`, `/*`), e.g. a shell, Python,
      env or Makefile comment, or a bare trailing line in Markdown;
    * as the first word of an HTML comment, anywhere on the line:
      `<!-- Expires-when: #NNNN closed -->`. This is the Markdown form that
      also works inside a table row.

  A mention anywhere else (mid-sentence prose, a Markdown inline code span,
  a Markdown fenced code block) is NOT a marker. That is how a document can
  describe the convention without being read as a marker itself.

  Two modes:

    hermetic (default)  validate every marker's syntax; a free-text marker
                        must carry Review-by; a Review-by date BEFORE today
                        (UTC) FAILs. This is the expiry trigger that needs no
                        network, and it is what CI and `make selftest` run.
    --online            also ask GitHub for the state of every #NNNN; a
                        CLOSED issue whose marker is still present FAILs.
                        `make instructions-census-online`; the campaign keeper
                        runs this mode.

WHY IT EXISTS

  Temporary instructions outlived their premise. failover-clock-lib.sh said
  "the loss lab has no NTP" long after the lab had NTP (fixed in #18618);
  CLAUDE.md still names the old loss iperf target; an always-on watcher ran a
  four-day-stale checkout. The ones that DID get retired carried an explicit
  expiry. This census makes the expiry a red test instead of a memory.

FALSIFIABILITY -- what this reports when the property is FALSE

  * A marker that names no issue and no condition, a condition starting with
    `#` that is not exactly `#NNNN closed`, an unparseable or impossible
    Review-by date, a `Review-by:` not separated from the condition by `;`,
    or a near-miss spelling of either key (`Expires When:`, `expires-when:`,
    `Review-By:`) is printed under MALFORMED by file:line. A near-miss is a
    FAIL, not an ignored line: a typo would otherwise hide the marker.
  * A free-text marker without Review-by is printed under NO-REVIEW-BY.
  * A Review-by date before today (UTC) is printed under EXPIRED.
  * (--online) An issue that is not OPEN is printed under CLOSED with every
    marker that names it; an issue whose state cannot be read is UNREADABLE.
    With no `gh` and no override the online check exits 77 (SKIP): "we could
    not ask" is not "it is open".
  * If the scan reads ZERO files, or finds ZERO markers, the census FAILs
    (EMPTY-SCAN, EMPTY). A census over an empty set is the shape a broken walk or a
    broken matcher produces. If the tree genuinely has no live markers, this
    census has nothing to protect and should be retired deliberately.
  * Each defence above is a fixture AND a mutation cell in
    test/incus/instructions-census-selftest.sh; the mutation edits the line
    tagged `census-guard: <name>` below and the cell must flip.

SCOPE

  docs/, .claude/skills/, test/incus/, scripts/, Makefile and CLAUDE.md, by
  file type (see TEXT_SUFFIXES). CLAUDE.md is owned by the user: the census
  READS it like any other file and never writes it (no file is written by
  this script); a failure there is reported as an owner action. The census's
  own source and self-test are excluded by NAME because they quote markers
  as fixtures; each excluded path must exist, so the exclusion cannot rot.

USAGE
  python3 scripts/instructions-census.py            # hermetic
  python3 scripts/instructions-census.py --online   # also ask GitHub
  Env overrides (used by the self-test): INSTR_CENSUS_ROOT,
  INSTR_CENSUS_SCOPE (space-separated), INSTR_CENSUS_EXCLUDE
  (space-separated), INSTR_CENSUS_TODAY (YYYY-MM-DD),
  INSTR_CENSUS_GH_STATE (a command; it is run with the issue number as its
  last argument and must print the state, e.g. OPEN or CLOSED).
  Exit: 0 clean, 1 FAIL, 77 SKIP (--online without gh), 2 usage.
"""

import bisect
import datetime
import itertools
import os
import re
import shlex
import shutil
import subprocess
import sys

DEFAULT_SCOPE = "docs .claude/skills test/incus scripts Makefile CLAUDE.md"
DEFAULT_EXCLUDE = (
    "scripts/instructions-census.py test/incus/instructions-census-selftest.sh"
)
# Read-only files: reported, never written. (Nothing here writes any file;
# this list only changes the remedy text.)
READ_ONLY = {"CLAUDE.md"}

TEXT_SUFFIXES = (
    ".md", ".sh", ".bash", ".py", ".env", ".mk", ".conf", ".set",
    ".toml", ".yml", ".yaml", ".unreached", ".floors",
)
TEXT_NAMES = {"Makefile", "CLAUDE.md"}

CANON_EXPIRES = "Expires-when:"
CANON_REVIEW = "Review-by:"

# Loose spellings, so a typo is reported instead of silently not matching.
EXPIRES_LOOSE = r"[Ee][Xx][Pp][Ii][Rr][Ee][Ss][-_ ]?[Ww][Hh][Ee][Nn]\s*:"  # census-guard: near-miss
REVIEW_LOOSE = r"[Rr][Ee][Vv][Ii][Ee][Ww][-_ ]?[Bb][Yy]\s*:"
LEADER = r"(?:#+|//|;+|--|/\*|\*)?"

# Position 1: line start (after whitespace and an optional comment leader).
LINE_START_RE = re.compile(
    r"^\s*" + LEADER + r"\s*(" + EXPIRES_LOOSE + r"|" + REVIEW_LOOSE + r")(.*)$"  # census-guard: position
)
# Position 2: the first word of an HTML comment, anywhere on the line.
HTML_RE = re.compile(
    r"<!--\s*(" + EXPIRES_LOOSE + r"|" + REVIEW_LOOSE + r")(.*?)(?:-->|$)"
)
# A cheap literal prefilter (a superset of both loose keys): the regex scan is
# ~30x slower and would cost seconds over docs/.
PREFILTER = (b"expires", b"review-by", b"review_by", b"reviewby", b"review by")
INLINE_CODE_RE = re.compile(r"(`+).*?\1")
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
    payload = payload.strip()
    for tail in ("-->", "*/"):
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


def scan_line(text, is_md):
    """Yield (key, payload) for every marker position on one line."""
    if is_md:
        text = INLINE_CODE_RE.sub("", text)  # census-guard: inline-code
    found = []
    m = LINE_START_RE.match(text)  # census-guard: line-start
    if m:
        found.append((m.group(1), m.group(2)))
    else:
        for h in HTML_RE.finditer(text):  # census-guard: html-comment
            found.append((h.group(1), h.group(2)))
    return found


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
    # Candidate lines: those holding a prefilter literal. Only these pay for
    # the regexes.
    cand = set()
    for lit in PREFILTER:
        i = low.find(lit)
        while i != -1:
            cand.add(bisect.bisect_right(starts, i) - 1)
            i = low.find(lit, i + 1)
    # Markdown fenced code blocks hold EXAMPLES, not markers. A line is inside
    # a fence when an odd number of fence lines precede it.
    fence_idx = fence_lines(raw, starts, lines) if is_md else []  # census-guard: fence
    fence_set = set(fence_idx)
    markers = []
    for idx in sorted(cand):
        if idx in fence_set or bisect.bisect_left(fence_idx, idx) % 2 == 1:
            continue
        line = lines[idx].decode("utf-8", errors="replace").rstrip("\r")
        for key, payload in scan_line(line, is_md):
            markers.append(classify(key, payload, rel, idx + 1))
    return markers, None


def fence_lines(raw, starts, lines):
    """Indices of Markdown fence lines (``` or ~~~ after optional blanks)."""
    idx = set()
    for lit in (b"```", b"~~~"):
        i = raw.find(lit)
        while i != -1:
            n = bisect.bisect_right(starts, i) - 1
            if lines[n].lstrip(b" \t").startswith(lit):
                idx.add(n)
            i = raw.find(lit, starts[n] + len(lines[n]) + 1)
    return sorted(idx)


def wanted(name):
    return name in TEXT_NAMES or name.endswith(TEXT_SUFFIXES)


def has_shebang(path):
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"#!"
    except OSError:
        return False


def walk(root, scope, exclude):
    files = []
    problems = []
    for entry in scope:
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
    files = [f for f in files if f not in exclude]
    return files, problems


def default_state(issue):
    out = subprocess.run(
        ["gh", "api", "repos/{owner}/{repo}/issues/%d" % issue, "--jq", ".state"],
        capture_output=True, text=True, timeout=60,
    )
    return out.stdout.strip() if out.returncode == 0 else ""


def main(argv):
    online = False
    for a in argv:
        if a == "--online":
            online = True
        elif a in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            print("usage: instructions-census.py [--online]", file=sys.stderr)
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

    def owner(m):
        return " (CLAUDE.md is read-only for agents: owner action)" if m.path in READ_ONLY else ""

    for m in markers:
        if m.kind == "MALFORMED":  # census-guard: malformed
            fail("MALFORMED", "%s: %s%s" % (m.where(), m.detail, owner(m)))
            continue
        if m.kind == "FREE" and m.review is None:  # census-guard: free-needs-review
            fail("NO-REVIEW-BY", "%s: free-text condition %r carries no Review-by date; a tool "
                 "cannot check the condition, so the date is the trigger%s" % (m.where(), m.detail, owner(m)))
        if m.review is not None and m.review < today:  # census-guard: past-date
            fail("EXPIRED", "%s: Review-by %s is before today (%s UTC): re-check %r, then delete "
                 "the instruction or move the date with a reason%s"
                 % (m.where(), m.review.isoformat(), today.isoformat(), m.detail, owner(m)))

    skipped = False
    if online:
        cmd = os.environ.get("INSTR_CENSUS_GH_STATE", "")
        if not cmd and shutil.which("gh") is None:
            skipped = True
        else:
            issues = sorted({m.issue for m in markers if m.kind == "ISSUE"})
            for n in issues:
                if cmd:
                    r = subprocess.run(shlex.split(cmd) + [str(n)], capture_output=True, text=True)
                    state = r.stdout.strip() if r.returncode == 0 else ""
                else:
                    state = default_state(n)
                state = state.lower()
                where = ", ".join(m.where() + owner(m) for m in markers if m.issue == n)
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
    for f in fails:
        print("  FAIL: " + f, file=sys.stderr)
    print("instructions census: %d marker(s) in %d file(s) -- %d issue-linked, %d free-text%s"
          % (len(markers), len(files), n_issue, n_free,
             "; online: checked %d issue(s)" % len({m.issue for m in markers if m.issue})
             if online and not skipped else ""))
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
