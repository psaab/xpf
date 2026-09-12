#!/bin/bash
# scripts/miri-leg.sh -- run Miri over the REGISTERED subset of userspace-dp
# and score the result TOTALLY (#9499 member 2).
#
# WHY THE SCORING IS THE POINT
#
#   Miri's exit status is not a sufficient oracle here. `cargo miri test --
#   <filter>` that matches NOTHING prints `0 passed; ... N filtered out` and
#   exits 0, which is indistinguishable from a clean run unless something reads
#   the counts. That is the exact shape #9499 is about -- a gate that cannot
#   fail is not a gate -- so every registered module must produce a result line
#   whose passed count meets the floor recorded in the registry:
#
#     * NO `test result:` line for a registered module  -> FAIL (not a skip).
#       This is what a renamed or deleted module looks like.
#     * `0 passed`                                      -> FAIL.
#     * passed < the registry floor                     -> FAIL, naming both
#       numbers. Tests may be added (the floor is a floor), but coverage may
#       not quietly drop.
#     * any `failed` count > 0                          -> FAIL.
#     * an `unsupported operation` line                 -> FAIL, not a pass.
#       Miri refusing to execute something is a VOID measurement, and a VOID
#       that scores as clean is worse than a red: it is a claim of coverage
#       nobody made.
#
#   Isolation stays ON. A module that needs `-Zmiri-disable-isolation` is
#   reading files in its tests, which makes it a poor UB oracle and a slow one;
#   such a module belongs in userspace-dp/MIRI.unregistered with that reason,
#   not in the registry behind a weakened flag.
#
# HOST NOTE
#
#   Miri is interpreted and single-threaded; the registered subset is sized to
#   stay in minutes, and the crate build under Miri dominates a cold run. This
#   is a heavy job on a shared box -- run it as the only one.
set -u

REPO_ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO_ROOT" || exit 1

REGISTRY=userspace-dp/MIRI.registry
MANIFEST=userspace-dp/Cargo.toml
TOOLCHAIN=${MIRI_TOOLCHAIN:-+nightly}
LOGDIR=${MIRI_LOG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/miri-leg.XXXXXXXX")}
mkdir -p "$LOGDIR"

[ -f "$REGISTRY" ] || { echo "miri leg: missing $REGISTRY" >&2; exit 1; }

if ! command -v cargo >/dev/null 2>&1; then
	echo "miri leg: cargo not found" >&2
	exit 1
fi
if ! cargo "$TOOLCHAIN" miri --version >/dev/null 2>&1; then
	# A missing Miri is a real blocker, not a skip: the whole point of the leg
	# is that it executes. Say how to install it and fail.
	echo "miri leg: \`cargo $TOOLCHAIN miri\` is not available." >&2
	echo "          rustup toolchain install nightly --component miri" >&2
	exit 1
fi

FAIL=0
n=0
fail() { FAIL=$((FAIL + 1)); echo "  FAIL: $*" >&2; }

while IFS= read -r line; do
	case "$line" in \#* | '') continue ;; esac
	mod=$(awk '{print $1}' <<<"$line")
	floor=$(awk '{print $2}' <<<"$line")
	[ -n "$mod" ] || continue
	n=$((n + 1))
	log="$LOGDIR/$(tr -c 'A-Za-z0-9_.-' '_' <<<"$mod").log"

	echo "miri leg: $mod (floor $floor)"
	# `--test-threads=1`: Miri interprets, and a parallel harness multiplies
	# both the memory and the interleavings for no added signal here.
	cargo "$TOOLCHAIN" miri test --manifest-path "$MANIFEST" --bins -- \
		"$mod" --test-threads=1 >"$log" 2>&1
	rc=$?

	if grep -q 'unsupported operation' "$log"; then
		fail "$mod: Miri hit an UNSUPPORTED OPERATION -- the run is VOID, not clean"
		grep -m2 'unsupported operation' "$log" | sed 's/^/        /' >&2
		echo "        Remedy: narrow the module, or move it to userspace-dp/MIRI.unregistered" >&2
		echo "        with that reason. Do NOT add -Zmiri-disable-isolation to buy a green." >&2
		continue
	fi

	# EVERY `test result:` line, summed -- not the first one.
	#
	# `--bins` runs each binary target in turn, so this log carries one result
	# line per binary. Reading only the FIRST is wrong in both directions and
	# both were live here: `src/bin/fairness-eval.rs` runs before `src/main.rs`
	# and reports `0 passed; 63 filtered out` for a filter aimed at main, which
	# scored a clean 12-test run as "the filter matched nothing"; and a failure
	# in a LATER binary would have been hidden behind an earlier clean line.
	# Found by running the leg for real, not by review -- the self-test's
	# fixtures were all single-binary and could not see it.
	n_res=$(grep -c '^test result:' "$log")
	if [ "$n_res" -eq 0 ]; then
		fail "$mod: NO \`test result:\` line (rc=$rc) -- a filter that matches nothing exits 0"
		tail -5 "$log" | sed 's/^/        /' >&2
		echo "        Remedy: the module path in $REGISTRY no longer names anything." >&2
		continue
	fi

	passed=$(grep '^test result:' "$log" |
		sed -n 's/.*[.:] \([0-9]*\) passed.*/\1/p' | awk '{t+=$1} END{print t+0}')
	failed=$(grep '^test result:' "$log" |
		sed -n 's/.*[;,] \([0-9]*\) failed.*/\1/p' | awk '{t+=$1} END{print t+0}')
	passed=${passed:-0}
	failed=${failed:-0}

	if [ "$failed" -gt 0 ] || [ "$rc" -ne 0 ]; then
		fail "$mod: $failed failed (rc=$rc)"
		grep -m10 -E '^(test .* FAILED|error|  = note)' "$log" | sed 's/^/        /' >&2
		continue
	fi
	if [ "$passed" -eq 0 ]; then
		fail "$mod: 0 passed across $n_res binary/binaries -- the filter matched nothing and Miri exited 0"
		continue
	fi
	if [ "$passed" -lt "$floor" ]; then
		fail "$mod: $passed passed, below the registered floor of $floor"
		echo "        Coverage dropped. Either restore the tests, or lower the floor in" >&2
		echo "        $REGISTRY and say why in its reason -- deliberately, in writing." >&2
		continue
	fi
	echo "  ok: $mod -- $passed passed across $n_res binary/binaries (floor $floor)"
done <"$REGISTRY"

if [ "$n" -eq 0 ]; then
	echo "miri leg: the registry names NO modules -- a leg that runs nothing must not pass" >&2
	exit 1
fi

echo ""
echo "miri leg: $n registered module(s), $FAIL failure(s); logs in $LOGDIR"
[ "$FAIL" -eq 0 ] || exit 1
echo "miri leg: OK"
