#!/bin/sh
# Hermetic regression tests for the #18745 nftables kernel leg's Go selection.
# Fake unshare supplies only the capability probe. The Go wrapper runs the
# REAL Go test command against a generated 216-test fixture package, without
# package code or network-namespace privileges.
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
LEG=${1:-$SCRIPT_DIR/selftest-nftables-kernel_18745.sh}
GO_REAL=${GO_REAL:-$(command -v go || true)}
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
# test for the inherited one-test -run regression and enough fillers to pin
# the expected total at 216.
kernel_names=$(sed -n "/^expected_kernel_cells='/,/^'$/p" \
	"$SCRIPT_DIR/selftest-nftables-kernel_18745.sh" | sed '1d;$d')
kernel_count=$(printf '%s\n' "$kernel_names" | grep -cE '^Test[^[:space:]]+$' || true)
if [ "$kernel_count" -ne 36 ]; then
	echo "FAIL: runner declares $kernel_count kernel cells, want 36"
	exit 1
fi
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
	while [ "$i" -le 179 ]; do
		printf 'func TestProbeNonKernel%03d(t *testing.T) {}\n' "$i"
		i=$((i + 1))
	done
} >"$FIXTURE_ROOT/pkg/nftables/kernel_probe_test.go"

cat >"$WORK/bin/unshare" <<'UNSHARE'
#!/bin/sh
if [ "$#" -eq 3 ] && [ "$1" = "-rn" ] && [ "$2" = "true" ]; then
	exit 0
fi
if [ "$#" -lt 2 ] || [ "$1" != "-rn" ]; then
	echo "stub unshare: unexpected arguments: $*" >&2
	exit 97
fi
shift
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
		*"PASS: all 216 pkg/nftables tests ran; all 36 pinned kernel cells passed"*)
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

failures=0
check_full_leg 'GOFLAGS -run subset' '-run=TestAdjudicatedTransitMarkMatchesRust' || failures=$((failures + 1))
check_full_leg 'GOFLAGS -skip all tests' '-skip=^Test' || failures=$((failures + 1))
if [ "$failures" -ne 0 ]; then
	echo "nftables-kernel-probes: FAIL ($failures case(s))"
	exit 1
fi
echo "nftables-kernel-probes: PASS (2 GOFLAGS cases)"
