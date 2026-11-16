#!/usr/bin/env bash
# scripts/nftables-probes-shim-path-selftest.sh -- #19136: the #18745
# nftables kernel-probes selftest finishes, in bounded time, under the PATH
# scripts/run-selftests.sh gives every leg (test/support/host-bin-shims first).
#
# Under that PATH the leg once took host-bin-shims/go as its "real" go. Its
# fixture wrapper then re-invoked the shim, the shim resolved the wrapper as
# the next `go` on PATH, and every turn started another testguard-run.sh. The
# recursion was unbounded: `make selftest` hung for 60 min, and every leg after
# this one never ran. Cells:
#   - bounded: the leg, under run-selftests.sh's exact PATH and a time bound,
#     passes (rc 124 is the hang);
#   - shim guard: with GO_REAL forced to the shim (the pre-fix resolution), the
#     leg fails fast with the shim's nesting message instead of hanging. This
#     proves the recursion is real and is now bounded.
# Needs go (the leg SKIPs without it, and so does this).
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
leg="$root/test/nftables/nftables-kernel-probes_18745-selftest.sh"
shims="$root/test/support/host-bin-shims"
bound=${XPF_PROBES_BOUND_S:-600}
guard_bound=${XPF_PROBES_GUARD_BOUND_S:-240}

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS: $*"; }
bad() { fail=$((fail + 1)); echo "FAIL: $*"; }

tmp=$(mktemp -d "${TMPDIR:-/tmp}/nftables-probes-shim-path.XXXXXX")
trap 'rm -rf "$tmp"' EXIT

# bounded: exactly the PATH run-selftests.sh sets up (shims first).
rc=0
(cd "$root" && PATH="$shims:$PATH" timeout "$bound" sh "$leg") >"$tmp/bounded.out" 2>&1 || rc=$?
if [[ $rc -eq 77 ]]; then
	echo "SKIP: $(grep -m1 -i skip "$tmp/bounded.out" || echo 'the leg skipped')"
	exit 77
fi
if [[ $rc -eq 0 ]] && grep -q '^nftables-kernel-probes: PASS' "$tmp/bounded.out"; then
	ok "bounded: under run-selftests.sh's PATH the leg passes within ${bound}s"
elif [[ $rc -eq 124 ]]; then
	bad "bounded: the leg did not finish within ${bound}s under run-selftests.sh's PATH (the #19136 hang)"
else
	bad "bounded: the leg failed (rc $rc): $(tail -n 8 "$tmp/bounded.out" | tr '\n' '|')"
fi

# shim guard: the pre-fix GO_REAL (the shim itself) must fail fast, not hang.
rc=0
(cd "$root" && PATH="$shims:$PATH" GO_REAL="$shims/go" timeout "$guard_bound" sh "$leg") >"$tmp/guard.out" 2>&1 || rc=$?
if [[ $rc -ne 0 && $rc -ne 124 ]] && grep -q 'nested shim invocations' "$tmp/guard.out"; then
	ok "shim guard: GO_REAL=the shim fails within ${guard_bound}s on the shim's nesting limit (rc $rc), not a hang"
elif [[ $rc -eq 124 ]]; then
	bad "shim guard: GO_REAL=the shim still recursed until the ${guard_bound}s bound"
else
	bad "shim guard: GO_REAL=the shim did not fail on the nesting limit (rc $rc): $(tail -n 8 "$tmp/guard.out" | tr '\n' '|')"
fi

echo "nftables probes shim-path selftest: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
