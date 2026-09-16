#!/usr/bin/env bash
# scripts/go-skip-census.sh — census over Go test SKIPS (#9052 item 4).
#
# WHAT IT ASSERTS
#
#   1. The number of skipped Go cells does not grow unnoticed. The floors in
#      GO_SKIP_FLOORS are the measured truth; an increase REDS, a decrease reds
#      as GOOD NEWS with an instruction to tighten.
#   2. The PRIVILEGE-DEPENDENT set is reported separately, BY NAME, and SPLIT
#      BY DIRECTION, because its absence is SYSTEMATIC rather than incidental.
#      The split is the finding: 40 cells skip because privilege is ABSENT and
#      10 skip because it is PRESENT, so NO SINGLE RUN EXAMINES ALL 50.
#      Running the suite as root does not close the gap — it trades one set of
#      unexamined subjects for a different one. Folded into a single total that
#      is invisible, and the obvious remedy ("just run it as root") looks like
#      a fix when it is a swap.
#   3. Every skip call site lands in a NAMED bucket, including the ones this
#      script cannot parse.
#
# WHY (3) IS THE LOAD-BEARING ONE
#
#   A census that silently drops what it cannot read is blind exactly where
#   somebody wrote something unusual — and "unusual" correlates with "worth
#   looking at". The failure mode is not a wrong number, it is a number that
#   looks complete. So `unparsed` is a REPORTED bucket with its own floor: a
#   skip whose message is a variable, a constant, or a call, and `t.SkipNow()`,
#   which carries no message at all. If that bucket grows, the census says so
#   instead of quietly shrinking its own population.
#
#   This is the #9088 lesson applied ahead of time. That census lost a live
#   operator-reachable defect because the row left the population as
#   `unmeasured` when a strict validator rejected its placeholder — the
#   instrument was blind precisely at the containers someone had cared enough
#   to gate. `unmeasured` is not neutral, and neither is `unparsed`.
#
# WHY A CENSUS AND NOT A TEST
#
#   `go test ./...` prints `ok` for a package whose cells all skipped. The
#   summary line for "everything passed" and "nothing ran" is byte-identical,
#   and no leg passes -v. 365 call sites across the tree were invisible to every
#   gate in the repo until #9812 folded this census into `make selftest` —
#   while censuses already exist for Rust `#[ignore]` (ignored-cell-census.sh),
#   shell harnesses (harness-census.sh) and python (run-selftests.sh).
#
# WHAT IT DELIBERATELY DOES NOT DO
#
#   It does not judge whether a skip is JUSTIFIED. There is no marker
#   convention on Go skips today, so any such verdict would be a guess off
#   message prose, and a census whose verdict is a guess trains people to
#   argue with it. It counts, classifies, names, and ratchets.
#
# Usage:
#   sh scripts/go-skip-census.sh            # census + ratchet check
#   sh scripts/go-skip-census.sh --list     # also list every skip by file:line
#   GO_SKIP_DIRS="pkg cmd" sh scripts/...   # override the scan roots
set -eu

# python3 is the census engine (the classifier below is a heredoc). Without it
# there is nothing to run, so SKIP rather than die under `set -eu` with
# "python3: command not found". POSIX: the Makefile leaf and the census
# self-test invoke this script via `sh` despite the bash shebang, so this
# guard — like the rest of the script — must stay sh-compatible.
if ! command -v python3 >/dev/null 2>&1; then
	echo "SKIP: python3 not installed — cannot run the skip census"
	exit 77
fi

# GO_SKIP_ROOT exists so the census can be pointed at a FIXTURE tree. Without
# it the script hard-cd'd to its own repo, so `GO_SKIP_DIRS=pkg` invoked from
# anywhere else silently scanned the REAL tree and reported its numbers — a
# gate that reads a tree other than the one you aimed it at is not a gate, and
# its self-test could not have been hermetic. Measured: the first selftest run
# reported 315 sites from the repo while asserting against a 5-site fixture.
ROOT=${GO_SKIP_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}
cd "$ROOT"
SCAN_DIRS=${GO_SKIP_DIRS:-"pkg cmd test"}
FLOORS_FILE=${GO_SKIP_FLOORS:-"scripts/go-skip-census.floors"}
LIST=0
[ "${1:-}" = "--list" ] && LIST=1

python3 - "$FLOORS_FILE" "$LIST" $SCAN_DIRS <<'PY'
import os, re, sys

floors_file, do_list = sys.argv[1], sys.argv[2] == "1"
scan_dirs = sys.argv[3:]

# t.Skip( / t.Skipf( / t.SkipNow( on any receiver spelled t, tb, b, or f —
# the four names this tree uses for a *testing.T/B/F or a testing.TB.
CALL = re.compile(r'\b(?:t|tb|b|f)\.(Skipf|SkipNow|Skip)\s*\(')
# A literal first argument, single or back-quoted, possibly concatenated.
LITERAL = re.compile(r'^\s*(?:"((?:[^"\\]|\\.)*)"|`([^`]*)`)')

# Comments are not call sites. A `t.Skip(` mentioned in `//` or `/* */` prose
# (or commented out) must not count: without this the census is coupled to
# prose — rewording a comment flips the total. Strings match FIRST so a `//`
# inside a literal (a URL before a real call on the same line) cannot hide the
# call. Comments blank to same-length spaces with newlines kept, so reported
# line numbers are unchanged. Rune literals match exactly one char/escape so a
# stray apostrophe cannot swallow code.
STRIP = re.compile(r'"(?:[^"\\\n]|\\.)*"|`[^`]*`|\'(?:[^\'\\\n]|\\.)\'|//[^\n]*|/\*.*?\*/', re.S)


def _blank(m):
    s = m.group(0)
    if s.startswith('//') or s.startswith('/*'):
        return ''.join('\n' if ch == '\n' else ' ' for ch in s)
    return s

ROOT_WORDS = re.compile(
    r'\broot\b|privileg|CAP_[A-Z_]+|euid|geteuid|\bsudo\b|unshare|netns|'
    r'network namespace', re.I)

# Both directions of privilege dependence are counted, and kept apart.
HAVE_PRIV = re.compile(
    r'running as root|running with privileg|root bypass|as root:', re.I)

buckets = {"priv-absent": [], "priv-present": [], "other": [], "unparsed": []}
per_pkg = {}

for d in scan_dirs:
    for dirpath, _dirs, files in os.walk(d):
        for fn in files:
            if not fn.endswith("_test.go"):
                continue
            path = os.path.join(dirpath, fn)
            try:
                src = open(path, encoding="utf-8").read()
            except OSError:
                continue
            src = STRIP.sub(_blank, src)
            for m in CALL.finditer(src):
                line = src.count("\n", 0, m.start()) + 1
                site = f"{path}:{line}"
                pkg = dirpath
                per_pkg[pkg] = per_pkg.get(pkg, 0) + 1
                kind = m.group(1)
                if kind == "SkipNow":
                    # No message by construction: it cannot be classified, and
                    # saying so is the point.
                    buckets["unparsed"].append((site, "t.SkipNow() carries no message"))
                    continue
                lit = LITERAL.match(src[m.end():])
                if not lit:
                    buckets["unparsed"].append((site, "non-literal skip message"))
                    continue
                msg = (lit.group(1) or lit.group(2) or "").replace("\\n", " ")
                if ROOT_WORDS.search(msg):
                    target = "priv-present" if HAVE_PRIV.search(msg) else "priv-absent"
                else:
                    target = "other"
                buckets[target].append((site, msg[:110]))

total = sum(len(v) for v in buckets.values())

floors = {}
if os.path.exists(floors_file):
    for raw in open(floors_file, encoding="utf-8"):
        raw = raw.split("#", 1)[0].strip()
        if not raw:
            continue
        k, _, v = raw.partition("=")
        floors[k.strip()] = int(v.strip())

print(f"go-skip census: {total} skip call sites in {len(per_pkg)} packages")
for name in ("priv-absent", "priv-present", "other", "unparsed"):
    n = len(buckets[name])
    fl = floors.get(name)
    suffix = "" if fl is None else f"  (floor {fl})"
    print(f"  {name:<12} {n:>4}{suffix}")

# The root-gated set BY NAME, always — it is the group shed on every run, and a
# count alone cannot tell an operator which subjects went unexamined.
if buckets["priv-absent"] or buckets["priv-present"]:
    print(f"\n  NO SINGLE RUN EXAMINES THESE {len(buckets['priv-absent']) + len(buckets['priv-present'])} CELLS:")
    print(f"    {len(buckets['priv-absent'])} shed on an UNPRIVILEGED run, "
          f"{len(buckets['priv-present'])} shed on a PRIVILEGED one. Running as "
          f"root swaps the unexamined set, it does not shrink it.")
for label, key in (("shed when privilege is ABSENT", "priv-absent"),
                   ("shed when privilege is PRESENT", "priv-present")):
    if buckets[key]:
        print(f"\n  {label}:")
        for site, msg in sorted(buckets[key]):
            print(f"    {site}  {msg}")
if buckets["unparsed"]:
    print("\n  unparsed skip sites (counted, NOT classified — see the header):")
    for site, why in sorted(buckets["unparsed"]):
        print(f"    {site}  {why}")
if do_list:
    print("\n  every other skip:")
    for site, msg in sorted(buckets["other"]):
        print(f"    {site}  {msg}")

rc = 0
checks = [("total", total)] + [(k, len(v)) for k, v in buckets.items()]
for name, got in checks:
    fl = floors.get(name)
    if fl is None:
        print(f"\nFAIL: no floor declared for {name!r}. Add it to {floors_file} "
              f"at the measured value ({got}); an undeclared bucket ratchets "
              f"against nothing.")
        rc = 1
        continue
    if got > fl:
        print(f"\nFAIL: {name} grew {fl} -> {got}. A new skip is a subject the "
              f"suite stopped examining while still printing 'ok'. Either "
              f"un-skip it, or raise the floor in {floors_file} in the SAME "
              f"change, with the reason in the commit message.")
        rc = 1
    elif got < fl:
        print(f"\nFAIL (GOOD NEWS): {name} shrank {fl} -> {got}. Tighten the "
              f"floor to {got} in {floors_file}. Leaving it loose gives the "
              f"next regression that much room to hide.")
        rc = 1

if rc == 0:
    print("\ngo-skip census: OK")
sys.exit(rc)
PY
