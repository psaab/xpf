#!/bin/sh
# scripts/go-deadcode-gate.sh — module-wide Go reachability gate (#17154, R4-Q49-01).
#
# WHAT IT ASSERTS
#
#   The set of functions unreachable from any binary or test in the module
#   (`deadcode -test ./...`, golang.org/x/tools/cmd/deadcode) is EXACTLY the
#   set declared in docs/deadcode-allowlist.txt — no more, no less:
#
#     * a NEW unreachable function (a live function lost its last caller, or
#       a helper was added without one) fails, naming path and symbol;
#     * a STALE allowlist row (its function was deleted, or regained a
#       caller) fails, naming the row: the allowlist only shrinks, in the
#       same change that deletes or revives the function;
#     * a MALFORMED allowlist row (not five TAB-separated columns, class
#       other than LEGITIMATE/LEGACY-DEBT, empty reason or empty
#       expiry-or-issue) fails, naming the line: every row carries a
#       reason and an issue/expiry, per the #9590 vet-gate contract ("an
#       exception must be a named, reasoned carve-out, never a quiet
#       re-narrowing of this scope").
#
#   Comparison is on the (path, symbol) pair only. deadcode's FuncName for
#   a method includes its receiver (CLI.showInterfacesExtensive); line
#   numbers are ignored so a row survives unrelated edits to its file.
#
# WHY IT EXISTS
#
#   Nothing checked reachability before this gate. At the issue's census
#   (0ce804221f, deadcode@v0.38.0 -test ./...) 154 production functions
#   were dead even from tests and 529 more were reachable only from tests;
#   the orphans clustered on deliberate refactor commits (#16173, #16065,
#   #15158, #10512) that moved callers and left the old definition behind.
#   Dead code then received fixes (#9523, #10862) and shipped one bug via
#   a surviving weaker twin (#2898). The Go linker strips unreachable
#   functions, so the cost is reviewer/fixer time and misleading docs,
#   not binary size — but it recurs at every review until a gate reds it.
#
# PHASES
#
#   Phase 1 (this gate): the base `-test` census diffed against the
#   allowlist. The allowlist is seeded with the measured baseline: 5
#   LEGITIMATE rows (three `var _` compile-guard asserts in
#   pkg/dataplane/*_published_*.go, pkg/api's setClockForTest and
#   pkg/authz's SetLookupListenerOwnerForTest) and the pre-existing dead
#   functions as LEGACY-DEBT rows, to be deleted per-package together
#   with their rows (fix direction (3) of #17154). Adding a LEGACY-DEBT
#   row for code written after landing is forbidden: delete the dead
#   function instead.
#
#   Phase 2 (follow-up, NOT this gate): production-root reachability
#   (`deadcode ./...` without -test) reporting functions reachable only
#   from tests that carry neither a ForTest/ForTesting name nor an
#   allowlist row, so a weaker twin cannot survive by being test-called.
#
# TOOLCHAIN PIN — why the version is checked, and why go1.27 fails here
#
#   deadcode v0.38.0 is the version #17154 measured and this gate pins,
#   invoked as `go run golang.org/x/tools/cmd/deadcode@v0.38.0` (never
#   `go tool deadcode`: go.mod's tool directive selects x/tools v0.40.0,
#   a different analyser — a gate must not drift with go.mod's indirect
#   bumps). The SSA builder in both v0.38.0 and v0.40.0 panics with
#   "unexpected expr: *ast.KeyValueExpr" on this tree under go1.27.2
#   (reproduced at 2dce74b744 on ./pkg/config, ./pkg/cli, ./pkg/api,
#   ./pkg/cluster and ./cmd/...; the pinned CI check-nft-deadcode leg is
#   exposed to the same crash when CI's toolchain moves to 1.27).
#   go1.26.9 runs the pinned analyser cleanly (this gate's baseline:
#   196 rows). #18753 extracts the go1.26.* resolver into
#   `scripts/resolve-deadcode-go.sh`, shared with the scoped
#   `make check-nft-deadcode` target. The resolver checks $DEADCODE_GO,
#   $GO, PATH `go`, then the conventional install locations. With none,
#   it exits 77 (NOT-EXAMINED) rather than red or green; `make test-go`
#   treats 77 as a skip-with-message. XPF_DEADCODE_REQUIRE=1 turns that
#   into a hard failure; CI provisions go1.26.9 only for the scoped
#   deadcode step and sets REQUIRE there, while the main toolchain stays
#   go1.24.9 from go-version-file.
#
# OVERRIDES (hermetic self-test and fixtures)
#
#   DEADCODE_OUTPUT=<file>  read deadcode's stdout from <file> instead of
#                           running the analyser (no toolchain needed).
#   DEADCODE_ALLOWLIST=<f>  allowlist path (default docs/deadcode-allowlist.txt).
#   DEADCODE_GO=<go>        go binary used for `go run` (default: resolved).
#   GO_DEADCODE_ROOT=<dir>  tree to cd into (default: this script's repo).
#   XPF_DEADCODE_REQUIRE=1  a missing go1.26 toolchain is exit 1, not 77 (set by CI for check-nft-deadcode; see TOOLCHAIN PIN above).
#
# Exit: 0 = exact match, 1 = mismatch/malformed, 2 = analyser/toolchain
# error, 77 = SKIP (no usable toolchain and not required).
set -u

# shellcheck disable=SC1007  # `CDPATH= cd` clears CDPATH for this command only
ROOT=${GO_DEADCODE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}
cd "$ROOT" || { echo "go-deadcode-gate: FATAL: cannot cd to $ROOT" >&2; exit 2; }

ALLOWLIST=${DEADCODE_ALLOWLIST:-docs/deadcode-allowlist.txt}
DEADCODE_VERSION=v0.38.0

[ -f "$ALLOWLIST" ] || {
	echo "go-deadcode-gate: FAIL: allowlist $ALLOWLIST not found" >&2
	exit 1
}

SCRATCH_BASE=${TMPDIR:-/var/worktrees/.cache/tmpdir}
mkdir -p "$SCRATCH_BASE" 2>/dev/null || SCRATCH_BASE=/tmp
SCRATCH=$(mktemp -d "$SCRATCH_BASE/xpf-deadcode-gate.XXXXXX") || {
	echo "go-deadcode-gate: FATAL: mktemp failed (TMPDIR=${TMPDIR:-unset})" >&2
	exit 2
}
trap 'rm -rf "$SCRATCH"' EXIT INT TERM

# ── obtain deadcode output ──────────────────────────────────────────
if [ -n "${DEADCODE_OUTPUT:-}" ]; then
	[ -f "$DEADCODE_OUTPUT" ] || {
		echo "go-deadcode-gate: FAIL: DEADCODE_OUTPUT=$DEADCODE_OUTPUT not found" >&2
		exit 2
	}
	cp "$DEADCODE_OUTPUT" "$SCRATCH/deadcode.raw"
	echo "go-deadcode-gate: using recorded analyser output $DEADCODE_OUTPUT (DEADCODE_OUTPUT override)"
else
	# Resolve go1.26.* with the shared resolver; stdout is its binary path.
	# The pinned analyser's SSA builder panics under go1.27 (see header).
	if GO_BIN=$(sh "$ROOT/scripts/resolve-deadcode-go.sh"); then
		GO_VER=$("$GO_BIN" version 2>/dev/null | sed -n 's/.*\(go1\.26\.[0-9]*\).*/\1/p')
		echo "go-deadcode-gate: running golang.org/x/tools/cmd/deadcode@$DEADCODE_VERSION -test ./... with $GO_BIN ($GO_VER)"
		if ! "$GO_BIN" run "golang.org/x/tools/cmd/deadcode@$DEADCODE_VERSION" -test ./... >"$SCRATCH/deadcode.raw" 2>"$SCRATCH/deadcode.err"; then
			echo "go-deadcode-gate: FAIL: deadcode $DEADCODE_VERSION exited nonzero:" >&2
			cat "$SCRATCH/deadcode.err" >&2
			exit 2
		fi
	else
		rc=$?
		exit "$rc"
	fi
fi

# ── parse + compare (python3 is the diff/validation engine) ─────────
if ! command -v python3 >/dev/null 2>&1; then
	echo "SKIP: python3 not installed — cannot run the deadcode gate comparison"
	exit 77
fi

python3 - "$SCRATCH/deadcode.raw" "$ALLOWLIST" <<'PY'
import re, sys

raw_path, allow_path = sys.argv[1], sys.argv[2]

ROW = re.compile(r'^(.+?):\d+:\d+: unreachable func: (.+?)\s*$')

actual = {}  # (path, symbol) -> raw line, first occurrence wins
for line in open(raw_path, encoding="utf-8"):
    line = line.rstrip("\n")
    if not line.strip():
        continue
    m = ROW.match(line)
    if not m:
        print(f"go-deadcode-gate: FAIL: unparseable deadcode output line: {line!r}", file=sys.stderr)
        sys.exit(1)
    actual.setdefault((m.group(1), m.group(2)), line)

allowed = {}  # (path, symbol) -> (class, reason, expiry, lineno)
errors = []
for lineno, raw in enumerate(open(allow_path, encoding="utf-8"), 1):
    line = raw.rstrip("\n")
    if not line.strip() or line.lstrip().startswith("#"):
        continue
    cols = line.split("\t")
    if len(cols) != 5:
        errors.append(f"line {lineno}: want 5 TAB-separated columns "
                      f"(path, symbol, class, reason, expiry-or-issue), got {len(cols)}: {line!r}")
        continue
    path, symbol, cls, reason, expiry = (c.strip() for c in cols)
    if not path or not symbol:
        errors.append(f"line {lineno}: empty path or symbol: {line!r}")
        continue
    if cls not in ("LEGITIMATE", "LEGACY-DEBT"):
        errors.append(f"line {lineno}: class must be LEGITIMATE or LEGACY-DEBT, got {cls!r}: {line!r}")
        continue
    if not reason:
        errors.append(f"line {lineno}: empty reason — every carve-out is named and reasoned (#9590): {line!r}")
        continue
    if not expiry:
        errors.append(f"line {lineno}: empty expiry-or-issue — every row names an issue or expiry: {line!r}")
        continue
    key = (path, symbol)
    if key in allowed:
        errors.append(f"line {lineno}: duplicate row for {path} {symbol} (first at line {allowed[key][3]})")
        continue
    allowed[key] = (cls, reason, expiry, lineno)

rc = 0
if errors:
    rc = 1
    print("go-deadcode-gate: FAIL: malformed allowlist rows:", file=sys.stderr)
    for e in errors:
        print(f"  docs/deadcode-allowlist.txt:{e}", file=sys.stderr)

new_dead = sorted(set(actual) - set(allowed))
stale = sorted(set(allowed) - set(actual))
if new_dead:
    rc = 1
    print("go-deadcode-gate: FAIL: unreachable function(s) with no allowlist row "
          "(a live function lost its last caller, or a helper was added without one). "
          "Delete the dead function; only a compile-guard or ForTest seam earns a "
          "LEGITIMATE row, with a reason:", file=sys.stderr)
    for path, symbol in new_dead:
        print(f"  {actual[(path, symbol)]}", file=sys.stderr)
if stale:
    rc = 1
    print("go-deadcode-gate: FAIL: stale allowlist row(s) — the function is gone "
          "or reachable again. Remove the row in this same change; the allowlist "
          "only shrinks:", file=sys.stderr)
    for path, symbol in stale:
        print(f"  {path}\t{symbol}\t(allowlist line {allowed[(path, symbol)][3]})", file=sys.stderr)

n_legit = sum(1 for v in allowed.values() if v[0] == "LEGITIMATE")
n_debt = sum(1 for v in allowed.values() if v[0] == "LEGACY-DEBT")
print(f"go-deadcode-gate: {len(actual)} unreachable function(s) "
      f"({n_legit} LEGITIMATE + {n_debt} LEGACY-DEBT allowlisted, {len(allowed)} rows)")
if rc == 0:
    print("go-deadcode-gate: OK — unreachable set == allowlist")
sys.exit(rc)
PY
