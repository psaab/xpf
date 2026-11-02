#!/bin/sh
# Hermetic regression tests for the #18745 nftables kernel leg's Go selection.
# The fake unshare supplies the capability probe; fake go uses the real Go
# test-list command but reports each selected test as a PASS without executing
# package code or requiring a network namespace.
set -u

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)
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
mkdir -p "$WORK/bin" || { echo "FATAL: cannot create stub directory" >&2; exit 2; }

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
#!/bin/sh
if [ "$#" -lt 2 ] || [ "$1" != test ]; then
	echo "stub go: unexpected command: $*" >&2
	exit 97
fi
shift
# Reuse the real Go test list but emulate the test selection flags: `go test
# -list` reports names independently of `-run`/`-skip`, whereas execution
# applies them. Parse GOFLAGS first and command-line flags second, matching the
# precedence that the leg must rely on, then report only selected names.
effective_run=
effective_skip=
parse_selection_flags() {
	while [ "$#" -gt 0 ]; do
		flag=$1
		shift
		case "$flag" in
		-run) effective_run=${1-}; [ "$#" -eq 0 ] || shift ;;
		-run=*) effective_run=${flag#-run=} ;;
		-skip) effective_skip=${1-}; [ "$#" -eq 0 ] || shift ;;
		-skip=*) effective_skip=${flag#-skip=} ;;
		esac
	done
}
set -f
[ -z "${GOFLAGS:-}" ] || parse_selection_flags $GOFLAGS
parse_selection_flags "$@"
if ! names=$(GOFLAGS= "$GO_REAL" test -list '^Test' ./pkg/nftables/ 2>&1); then
	printf '%s\n' "$names" >&2
	exit 1
fi
printf '%s\n' "$names" | while IFS= read -r name; do
	case "$name" in
	Test*)
		if [ -n "$effective_run" ] && ! printf '%s\n' "$name" | grep -qE "$effective_run"; then
			continue
		fi
		if [ -n "$effective_skip" ] && printf '%s\n' "$name" | grep -qE "$effective_skip"; then
			continue
		fi
		printf '%s\n' "--- PASS: $name (0.00s)"
		;;
	esac
done
set +f
GO
chmod +x "$WORK/bin/unshare" "$WORK/bin/go" || { echo "FATAL: cannot make stubs executable" >&2; exit 2; }

check_full_leg() {
	label=$1
	go_flags=$2
	if out=$(cd "$ROOT" && PATH="$WORK/bin:$PATH" GO="$WORK/bin/go" GO_REAL="$GO_REAL" GOFLAGS="$go_flags" sh "$LEG" 2>&1); then
		case "$out" in
		*"PASS: all 216 pkg/nftables tests ran; all 36 pinned kernel cells passed"*)
			echo "PASS: $label — inherited GOFLAGS did not narrow the leg" ;;
		*)
			echo "FAIL: $label — the leg returned success without proving the complete pinned run"
			printf '%s\n' "$out" | sed 's/^/      /'
			return 1 ;;
		esac
	else
		echo "FAIL: $label — the leg failed under the hermetic fake tools"
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
