#!/bin/sh
# Hermetic regression tests for the #18745 nftables kernel leg's Go selection.
# Fake unshare supplies only the capability probe. The Go wrapper runs the
# REAL Go test command against a generated fixture package, without
# package code or network-namespace privileges.
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LEG=${1:-$SCRIPT_DIR/selftest-nftables-kernel_18745.sh}
# #19136: GO_REAL must be the Go toolchain, never test/support/host-bin-shims/go.
# scripts/run-selftests.sh puts that shim first in PATH, and testguard-run.sh
# puts it first again inside the leg. The shim resolves "the real go" as the
# next `go` on PATH, which there is this fixture's own wrapper below. So a
# GO_REAL taken from run-selftests.sh's PATH sent wrapper -> shim -> wrapper
# through a new testguard-run.sh on every turn, an unbounded recursion that
# hung `make selftest` for 60 min and masked every later leg. Resolve it with
# the shim directory removed. An explicit GO_REAL is still honoured.
# shellcheck disable=SC1007 # `CDPATH= cd` clears CDPATH for this command only
SHIM_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/../support/host-bin-shims" 2>/dev/null && pwd || true)
PATH_WITHOUT_SHIMS=$(printf '%s\n' "$PATH" | tr ':' '\n' | grep -vxF -- "${SHIM_DIR:-/nonexistent}" | paste -sd: -)
GO_REAL=${GO_REAL:-$(PATH=$PATH_WITHOUT_SHIMS command -v go || true)}
if [ -z "$GO_REAL" ] || ! command -v "$GO_REAL" >/dev/null 2>&1; then
	echo "SKIP: go not installed — cannot exercise #18745 GOFLAGS handling"
	exit 77
fi
if [ ! -f "$LEG" ]; then
	echo "FAIL: kernel leg not found: $LEG"
	exit 1
fi

WORK=$(mktemp -d) || { echo "FATAL: mktemp -d failed" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
FIXTURE_ROOT="$WORK/tree"
mkdir -p "$WORK/bin" "$FIXTURE_ROOT/pkg/nftables" || {
	echo "FATAL: cannot create fixture directories" >&2
	exit 2
}
cat >"$FIXTURE_ROOT/go.mod" <<'MODULE'
module example.invalid/nftables-kernel-probe

go 1.20
MODULE

# Generate the same kernel-test names the runner pins, plus a known non-kernel
# test for the inherited one-test -run regression and fillers. The total is
# deliberately NOT the 216 the leg used to pin (#19141): the leg must read
# which tests to expect from the tree it runs.
kernel_names=$(sed -n "/^expected_kernel_cells='/,/^'$/p" \
	"$SCRIPT_DIR/selftest-nftables-kernel_18745.sh" | sed '1d;$d')
kernel_count=$(printf '%s\n' "$kernel_names" | grep -cE '^Test[^[:space:]]+$' || true)
if [ "$kernel_count" -ne 36 ]; then
	echo "FAIL: runner declares $kernel_count kernel cells, want 36"
	exit 1
fi
fillers=190
fixture_total=$((kernel_count + 1 + fillers))
{
	printf 'package nftables\n\nimport "testing"\n\n'
	while IFS= read -r name; do
		[ -n "$name" ] || continue
		printf 'func %s(t *testing.T) {}\n' "$name"
	done <<NAMES
$kernel_names
NAMES
	printf 'func TestAdjudicatedTransitMarkMatchesRust(t *testing.T) {}\n'
	i=1
	while [ "$i" -le "$fillers" ]; do
		printf 'func TestProbeNonKernel%03d(t *testing.T) {}\n' "$i"
		i=$((i + 1))
	done
} >"$FIXTURE_ROOT/pkg/nftables/kernel_probe_test.go"

cat >"$WORK/bin/unshare" <<'UNSHARE'
#!/bin/sh
if [ "$#" -eq 3 ] && [ "$1" = "-rn" ] && [ "$2" = "true" ]; then
	exit 0
fi
# Accept the legacy -rn probe pair and the guarded runner's real
# invocation (-Urp ... / nested -nm): drop every flag token, then exec
# the first non-flag command exactly as the runner would.
while [ "$#" -gt 0 ]; do
	case "$1" in
	-*) shift ;;
	*) break ;;
	esac
done
if [ "$#" -lt 1 ]; then
	echo "stub unshare: no command after flags: $*" >&2
	exit 97
fi
exec "$@"
UNSHARE

cat >"$WORK/bin/go" <<'GO'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" != test ]]; then
	echo "go wrapper: unexpected command: $*" >&2
	exit 97
fi
shift
# PROBE_EXTRA_SKIP narrows the run AFTER the leg's own -skip '' (the last
# -skip wins), the way a caller-side filter would.
if [[ -n "${PROBE_EXTRA_SKIP:-}" ]]; then
	exec "$GO_REAL" test "$@" -skip="$PROBE_EXTRA_SKIP"
fi
exec "$GO_REAL" test "$@"
GO
chmod +x "$WORK/bin/unshare" "$WORK/bin/go" || {
	echo "FATAL: cannot make stubs executable" >&2
	exit 2
}

check_full_leg() {
	label=$1
	go_flags=$2
	if out=$(cd "$FIXTURE_ROOT" && PATH="$WORK/bin:$PATH" GO="$WORK/bin/go" GO_REAL="$GO_REAL" GOFLAGS="$go_flags" sh "$LEG" 2>&1); then
		case "$out" in
		*"PASS: all $fixture_total pkg/nftables tests ran; all 36 pinned kernel cells passed"*)
			echo "PASS: $label — inherited GOFLAGS did not narrow the leg" ;;
		*)
			echo "FAIL: $label — the leg returned success without proving the complete pinned run"
			printf '%s\n' "$out" | sed 's/^/      /'
			return 1 ;;
		esac
	else
		echo "FAIL: $label — the leg failed under the hermetic fixture"
		printf '%s\n' "$out" | sed 's/^/      /'
		return 1
	fi
}

# check_leg_fails <label> <text the failure must contain> [VAR=value ...]:
# the leg must exit nonzero and name what it caught.
check_leg_fails() {
	label=$1
	want=$2
	shift 2
	if out=$(cd "$FIXTURE_ROOT" && env PATH="$WORK/bin:$PATH" GO="$WORK/bin/go" GO_REAL="$GO_REAL" GOFLAGS= "$@" sh "$LEG" 2>&1); then
		echo "FAIL: $label — the leg passed"
		printf '%s\n' "$out" | sed 's/^/      /'
		return 1
	fi
	case "$out" in
	*"$want"*)
		echo "PASS: $label — the leg failed and named it" ;;
	*)
		echo "FAIL: $label — the leg failed without naming \"$want\""
		printf '%s\n' "$out" | sed 's/^/      /'
		return 1 ;;
	esac
}

failures=0
check_full_leg 'GOFLAGS -run subset' '-run=TestAdjudicatedTransitMarkMatchesRust' || failures=$((failures + 1))
check_full_leg 'GOFLAGS -skip all tests' '-skip=^Test' || failures=$((failures + 1))
# A declared test that did not run is a narrowed package.
check_leg_fails 'narrowed run' 'TestProbeNonKernel007' PROBE_EXTRA_SKIP='^TestProbeNonKernel007$' || failures=$((failures + 1))
# A test the compiler runs but the source scan cannot see (a signature split
# over lines) means the scan cannot vouch for the run.
cat >"$FIXTURE_ROOT/pkg/nftables/unscanned_probe_test.go" <<'UNSCANNED'
package nftables

import "testing"

func TestProbeUnscanned(
	t *testing.T,
) {
}
UNSCANNED
check_leg_fails 'unscanned test' 'TestProbeUnscanned' || failures=$((failures + 1))
rm -f "$FIXTURE_ROOT/pkg/nftables/unscanned_probe_test.go"
if [ "$failures" -ne 0 ]; then
	echo "nftables-kernel-probes: FAIL ($failures case(s))"
	exit 1
fi
echo "nftables-kernel-probes: PASS (4 cases)"
