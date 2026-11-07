#!/bin/sh
# scripts/resolve-deadcode-go.sh — resolve a go1.26.* toolchain for the
# pinned deadcode analyser (#18753, shared by #17008 and #17154).
#
# WHY GO1.26 ONLY
#
#   The pinned analyser (golang.org/x/tools/cmd/deadcode@v0.38.0, and
#   go.mod's tool-directive x/tools v0.40.0 alike) panics in its SSA
#   builder with "unexpected expr: *ast.KeyValueExpr" on this tree
#   under go1.27 (verified #17154/#18753). go1.26.* runs it cleanly.
#   Until a measured analyser release runs on the tree's ambient
#   toolchain, every deadcode gate must drive the pinned analyser with
#   a go1.26.* toolchain — resolved here, once, so the scoped
#   (Makefile check-nft-deadcode) and module-wide
#   (scripts/go-deadcode-gate.sh) gates can never drift apart in what
#   they accept.
#
# CONTRACT
#
#   Prints the resolved go binary's path as given (exactly one line)
#   on stdout and exits 0. stdout carries NOTHING else, so callers can
#   capture it with $(...). With no usable go1.26.* toolchain it
#   prints nothing on stdout and exits 77 (SKIP — the measurement did
#   not happen); under XPF_DEADCODE_REQUIRE=1 it exits 1 instead.
#   DEADCODE_GO_CANDIDATES may replace the entire list for hermetic
#   resolver tests; normal callers should use DEADCODE_GO / GO instead.
#   List entries are shell words (binary paths may not contain spaces).
#   Diagnostics go to stderr only, so the NOT-EXAMINED / hard-fail
#   wording lives in one place.
#
# RESOLUTION (first go1.26.* wins)
#
#   $DEADCODE_GO, then $GO, then PATH `go`, then the conventional
#   install locations /usr/lib/go-1.26/bin/go, /usr/lib/go-1.26.*/bin/go,
#   /usr/local/go/bin/go and $HOME/sdk/go1.26*/bin/go.
set -u

if [ "${DEADCODE_GO_CANDIDATES+x}" = x ]; then
	GO_CANDIDATES=$DEADCODE_GO_CANDIDATES
else
	GO_CANDIDATES="${DEADCODE_GO:-} ${GO:-} go /usr/lib/go-1.26/bin/go /usr/lib/go-1.26.*/bin/go /usr/local/go/bin/go ${HOME:-}/sdk/go1.26*/bin/go"
fi
for cand in $GO_CANDIDATES; do
	[ -n "$cand" ] || continue
	command -v "$cand" >/dev/null 2>&1 || [ -x "$cand" ] || continue
	ver=$("$cand" version 2>/dev/null | sed -n 's/.*\(go1\.26\.[0-9]*\).*/\1/p')
	if [ -n "$ver" ]; then
		printf '%s\n' "$cand"
		exit 0
	fi
done

if [ "${XPF_DEADCODE_REQUIRE:-}" = "1" ]; then
	echo "resolve-deadcode-go: FAIL: no go1.26.* toolchain found (XPF_DEADCODE_REQUIRE=1); deadcode v0.38.0 panics under go1.27 — install go1.26 or set DEADCODE_GO" >&2
	exit 1
fi
echo "resolve-deadcode-go: NOT-EXAMINED: no go1.26.* toolchain found (deadcode v0.38.0's SSA builder panics under go1.27); set DEADCODE_GO or install go1.26" >&2
exit 77
