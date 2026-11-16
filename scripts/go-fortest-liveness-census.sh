#!/bin/sh
# scripts/go-fortest-liveness-census.sh -- every `*ForTest*` hook in non-test
# Go code has a caller (#17342).
#
# A `func ...ForTest...` in production code is a test seam. One that nothing
# calls is dead code whose doc comment still claims a test exercises it, which
# is how three of them went unnoticed: a count-based liveness check read the
# godoc line as a reference, and deadcode (scripts/go-deadcode-gate.sh) keeps an
# exported method of a live type reachable, so it cannot see such a method.
#
# The census counts a hook as LIVE when its name appears in Go code outside its
# own definition line, comments stripped. A dead hook must be listed in the
# baseline scripts/go-fortest-liveness.allow (name, file, reason), and every
# baseline row must still name a dead hook. Both directions FAIL: a new dead
# hook, and a stale row (the hook gained a caller or was deleted).
#
# Usage: sh scripts/go-fortest-liveness-census.sh
#   FORTEST_ROOT=<dir>   scan this tree instead of the repository (selftests)
#   FORTEST_ALLOW=<file> use this baseline instead of the repository's
# Exit: 0 = matches the baseline, 1 = drift, 2 = cannot run.
set -eu
# shellcheck disable=SC1007 # `CDPATH= cd` empties CDPATH for this cd only
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=${FORTEST_ROOT:-$(dirname -- "$here")}
allow=${FORTEST_ALLOW:-$here/go-fortest-liveness.allow}
if ! command -v python3 >/dev/null 2>&1; then
	echo "go-fortest-liveness-census: python3 not found" >&2
	exit 2
fi
exec python3 -I - "$root" "$allow" <<'PY'
import os
import re
import sys

root, allow_path = sys.argv[1], sys.argv[2]
DEF = re.compile(r"^func (?:\([^)]*\) )?([A-Za-z0-9_]*ForTest[A-Za-z0-9_]*)\s*[\[(]")
SKIP_DIRS = {".git", "vendor", "node_modules", "target"}

sources = {}
for top, dirs, names in os.walk(root):
    dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
    for name in names:
        if name.endswith(".go"):
            path = os.path.join(top, name)
            with open(path, encoding="utf-8", errors="replace") as handle:
                text = handle.read()
            if "ForTest" in text:
                sources[os.path.relpath(path, root)] = text.splitlines()

definitions = {}  # name -> {(file, line)}
for rel, lines in sources.items():
    if rel.endswith("_test.go"):
        continue
    for number, line in enumerate(lines, 1):
        match = DEF.match(line)
        if match:
            definitions.setdefault(match.group(1), set()).add((rel, number))
if not definitions:
    print(f"go-fortest-liveness-census: no *ForTest* definitions under {root}; nothing to vouch for", file=sys.stderr)
    sys.exit(2)

pattern = re.compile(r"\b(" + "|".join(sorted(map(re.escape, definitions), key=len, reverse=True)) + r")\b")
references = {name: 0 for name in definitions}
for rel, lines in sources.items():
    for number, line in enumerate(lines, 1):
        code = line.split("//", 1)[0]  # a comment is not a caller
        for match in pattern.finditer(code):
            if (rel, number) not in definitions[match.group(1)]:
                references[match.group(1)] += 1
dead = {name: sorted(definitions[name])[0][0] for name, count in references.items() if count == 0}

allowed = {}
problems = []
try:
    with open(allow_path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, 1):
            if not line.strip() or line.startswith("#"):
                continue
            fields = line.rstrip("\n").split("\t")
            if len(fields) != 3 or not all(f.strip() for f in fields):
                problems.append(f"{allow_path}:{number}: want <name>\\t<file>\\t<reason>, got {line.rstrip()!r}")
                continue
            allowed[fields[0]] = fields[1]
except FileNotFoundError:
    pass

for name in sorted(dead):
    if name not in allowed:
        problems.append(f"{dead[name]}: {name} has no caller (comments do not count). "
                        "Delete it, call it, or list it in the baseline with a reason")
for name in sorted(allowed):
    if name not in dead:
        state = "is gone" if name not in definitions else "now has a caller"
        problems.append(f"baseline row {name} ({allowed[name]}) is stale: the hook {state}; delete the row")

print(f"go-fortest-liveness-census: {len(definitions)} *ForTest* hooks, {len(dead)} with no caller, "
      f"{len(allowed)} baseline row(s)")
for problem in problems:
    print(f"FAIL: {problem}")
sys.exit(1 if problems else 0)
PY
