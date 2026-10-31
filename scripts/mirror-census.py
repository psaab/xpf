#!/usr/bin/env python3
"""scripts/mirror-census.py -- census over MIRRORED DOC BLOCKS (#18645).

WHAT IT ASSERTS

  Text that is deliberately copied into several documents stays identical.
  A copy is wrapped in a pair of HTML comments, which Markdown renders as
  nothing:

    <!-- mirror:<id> -->  ...the mirrored text...  <!-- /mirror:<id> -->

  <id> is lower-case letters, digits and `-`. Every block with the same id,
  in any scanned file, must have the same text after whitespace
  normalisation (every run of whitespace, including line breaks and list
  indentation, becomes one space; leading and trailing space is dropped).
  So a mirror may be re-wrapped or re-indented freely, and nothing else.

  The markers may sit mid-line, which is how a mirror can start or end
  inside a paragraph without splitting it. Do not start a Markdown line with
  the opening marker inside a paragraph: a line that begins with `<!--`
  ends the paragraph there.

WHY IT EXISTS

  CLAUDE.md's private-RG peer-loss detection paragraph is mirrored in about
  eight documents. #18643 had to re-synchronise them all, and a reviewer had
  to confirm character identity by hand. Mirrors drift because nothing
  compares them; this census compares them on every run.

FALSIFIABILITY -- what this reports when the property is FALSE

  * Two blocks with one id whose normalised text differs: DIFFER, naming
    both files and the first differing word.
  * A block whose id appears in no other block: ORPHAN. A mirror without a
    partner checks nothing, and is usually a typo in an id.
  * An opening marker with no close (UNCLOSED), a close with no opening
    (STRAY-CLOSE), or a block opened inside another block (NESTED).
  * A near-miss marker (`<!-- Mirror:x -->`, `<!-- mirror:Bad_Id -->`,
    `<!--mirror x-->`): MALFORMED, never an ignored line.
  * A block with no text: EMPTY-BLOCK (two empty blocks would "agree").
  * ZERO blocks in the scanned tree: EMPTY. A broken walk or a broken
    matcher produces exactly that board.
  * Each verdict is a fixture AND a mutation cell in
    test/incus/mirror-census-selftest.sh; the mutation edits the line tagged
    `census-guard: <name>` and the cell must flip.

  Markers inside a Markdown fenced code block or an inline code span are
  documentation of the convention, not markers, and are skipped.

SCOPE

  Every *.md file under the repo root's CLAUDE.md, AGENTS.md, README.md,
  docs/, pkg/, .claude/, test/ and scripts/. CLAUDE.md is owned by the
  user: it is READ, never written (this script writes nothing). Until the
  owner wraps CLAUDE.md's copy, CLAUDE.md is simply not a member of the set.

USAGE
  python3 scripts/mirror-census.py
  Env overrides (used by the self-test): MIRROR_CENSUS_ROOT,
  MIRROR_CENSUS_SCOPE (space-separated), MIRROR_CENSUS_VERBOSE=1.
  Exit: 0 clean, 1 FAIL.
"""

import os
import re
import sys

DEFAULT_SCOPE = "CLAUDE.md AGENTS.md README.md docs pkg .claude test scripts"
READ_ONLY = {"CLAUDE.md"}

MARK_RE = re.compile(r"<!--\s*(/?)mirror:([a-z0-9][a-z0-9-]*)\s*-->")
NEAR_RE = re.compile(r"<!--\s*/?\s*mirror\b", re.IGNORECASE)
# A code span may wrap lines but never crosses a blank line (a paragraph end),
# so a stray backtick cannot blank the rest of the file.
INLINE_CODE_RE = re.compile(r"(`+)(?:(?!\n[ \t]*\n).)*?\1", re.DOTALL)


def normalise(text):
    return " ".join(text.split())  # census-guard: normalise


def blank_code(text):
    """Blank fenced code blocks and inline code spans, keeping offsets."""
    out = []
    in_fence = False
    for line in text.split("\n"):
        s = line.lstrip(" \t")
        if s.startswith("```") or s.startswith("~~~"):  # census-guard: fence
            in_fence = not in_fence
            out.append(" " * len(line))
            continue
        out.append(" " * len(line) if in_fence else line)
    blanked = "\n".join(out)
    return INLINE_CODE_RE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), blanked)  # census-guard: inline-code


def lineno_of(text, offset):
    return text.count("\n", 0, offset) + 1


def first_diff(a, b):
    wa, wb = a.split(" "), b.split(" ")
    for i in range(max(len(wa), len(wb))):
        x = wa[i] if i < len(wa) else "<end>"
        y = wb[i] if i < len(wb) else "<end>"
        if x != y:
            ctx = " ".join(wa[max(0, i - 4):i])
            return "word %d after %r: %r vs %r" % (i + 1, ctx, x, y)
    return "identical"


def scan(root, rel, fails):
    """Return [(id, normalised_text, 'path:line')] for one file."""
    try:
        with open(os.path.join(root, rel), encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError as e:
        fails.append(("SCOPE", "%s: cannot read: %s" % (rel, e)))
        return []
    if "<!--" not in text or not NEAR_RE.search(text):
        return []  # no marker of any spelling: skip the expensive pass
    code = blank_code(text)
    blocks = []
    open_id, open_at, open_end = None, 0, 0
    marks = list(MARK_RE.finditer(code))
    canon = {m.start() for m in marks}
    for n in NEAR_RE.finditer(code):
        if n.start() not in canon:  # census-guard: near-miss
            end = code.find("-->", n.start())
            frag = text[n.start():end + 3 if end != -1 else n.start() + 40]
            fails.append(("MALFORMED", "%s:%d: %r is not `<!-- mirror:<id> -->` or "
                          "`<!-- /mirror:<id> -->` (id: a-z, 0-9, -)"
                          % (rel, lineno_of(text, n.start()), frag.strip())))
    for m in marks:
        closing, mid = m.group(1) == "/", m.group(2)
        where = "%s:%d" % (rel, lineno_of(text, m.start()))
        if not closing:
            if open_id is not None:  # census-guard: nesting
                fails.append(("NESTED", "%s: mirror:%s opens inside mirror:%s (opened at line %d); "
                              "blocks do not nest" % (where, mid, open_id, lineno_of(text, open_at))))
            open_id, open_at, open_end = mid, m.start(), m.end()
            continue
        if open_id != mid:  # census-guard: unbalanced-close
            fails.append(("STRAY-CLOSE", "%s: /mirror:%s closes a block that is not open%s"
                          % (where, mid, " (mirror:%s is)" % open_id if open_id else "")))
            continue
        body = normalise(text[open_end:m.start()])
        blocks.append((mid, body, "%s:%d" % (rel, lineno_of(text, open_at))))
        open_id = None
    if open_id is not None:  # census-guard: unclosed
        fails.append(("UNCLOSED", "%s:%d: mirror:%s is never closed"
                      % (rel, lineno_of(text, open_at), open_id)))
    return blocks


def walk(root, scope, fails):
    files = []
    for entry in scope:
        p = os.path.join(root, entry)
        if os.path.isfile(p):
            if entry.endswith(".md"):
                files.append(entry)
        elif os.path.isdir(p):
            for d, dirs, names in os.walk(p):
                dirs[:] = sorted(x for x in dirs if x not in (".git", "target", "node_modules")
                                 and not x.startswith("xdp-tools"))
                for n in sorted(names):
                    if n.endswith(".md"):
                        files.append(os.path.relpath(os.path.join(d, n), root))
        elif entry in ("CLAUDE.md", "AGENTS.md", "README.md"):
            continue  # optional root files (absent in a fixture tree)
        else:
            fails.append(("SCOPE", "scope entry does not exist: %s" % entry))
    return files


def main(argv):
    if argv:
        if argv[0] in ("-h", "--help"):
            print(__doc__)
            return 0
        print("usage: mirror-census.py", file=sys.stderr)
        return 2
    here = os.path.dirname(os.path.abspath(__file__))
    root = os.environ.get("MIRROR_CENSUS_ROOT") or os.path.dirname(here)
    scope = os.environ.get("MIRROR_CENSUS_SCOPE", DEFAULT_SCOPE).split()
    fails = []
    files = walk(root, scope, fails)
    blocks = []
    for rel in files:
        blocks.extend(scan(root, rel, fails))

    by_id = {}
    for mid, body, where in blocks:
        by_id.setdefault(mid, []).append((body, where))

    for mid in sorted(by_id):
        members = by_id[mid]
        for body, where in members:
            if not body:  # census-guard: empty-block
                fails.append(("EMPTY-BLOCK", "%s: mirror:%s has no text" % (where, mid)))
        if len(members) < 2:  # census-guard: orphan
            fails.append(("ORPHAN", "%s: mirror:%s has no partner block in any scanned file "
                          "(a typo in the id, or its partner was deleted)" % (members[0][1], mid)))
            continue
        ref_body, ref_where = members[0]
        for body, where in members[1:]:
            if body != ref_body:  # census-guard: differ
                fails.append(("DIFFER", "mirror:%s differs between %s and %s: %s"
                              % (mid, ref_where, where, first_diff(ref_body, body))))

    if not blocks:  # census-guard: empty-sweep
        fails.append(("EMPTY", "ZERO mirror blocks in %d Markdown file(s) under: %s (a broken walk "
                      "or matcher reads exactly like this)" % (len(files), " ".join(scope))))

    if os.environ.get("MIRROR_CENSUS_VERBOSE") == "1":
        for mid in sorted(by_id):
            for body, where in by_id[mid]:
                print("  mirror:%s %s (%d chars)" % (mid, where, len(body)))
    for tag, msg in fails:
        owner = " (CLAUDE.md is read-only for agents: owner action)" if any(
            msg.startswith(r + ":") or (" " + r + ":") in msg for r in READ_ONLY) else ""
        print("  FAIL: %s: %s%s" % (tag, msg, owner), file=sys.stderr)
    print("mirror census: %d block(s), %d id(s), in %d Markdown file(s)"
          % (len(blocks), len(by_id), len(files)))
    if fails:
        print("mirror census: FAILED (%d problem(s))" % len(fails), file=sys.stderr)
        return 1
    print("mirror census: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
