#!/bin/sh
# #14833: repo build/test scratch must not default to /tmp, /dev/shm, /var/tmp.
# Pins: Makefile/run-selftests export TMPDIR/GOCACHE/GOTMPDIR/CARGO_TARGET_DIR
# defaults under /var/worktrees/.cache; every other audited file either
# inherits TMPDIR (shell mktemp / python tempfile) or pins explicitly.
# Non-goals: remote-VM temp paths (run_vm/run_host/incus exec strings),
# guest paths in bake.py, fixture literals in *_test files, legacy
# mutate-*.py one-offs (their wt-* worktrees are historical).
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
fail=0
bad='TMPDIR=/tmp|TMPDIR:-/tmp|TMPDIR:-/var/tmp|MUTATE_WORKDIR:-/var/tmp|ARTIFACT_DIR:-/tmp|"/tmp"|/dev/shm|get\("TMPDIR", "/tmp"\)|TMPDIR", "/tmp"|environ\.get\("TMPDIR", "/tmp"\)'
check_file() { # check_file <file>
  f=$1
  # Literal forbidden defaults (comments excluded: prose may name them).
  if grep -vE '^[[:space:]]*#' "$root/$f" | grep -nE "$bad" | grep -q .; then
    echo "FAIL: forbidden scratch default in $f"
    grep -vE '^[[:space:]]*#' "$root/$f" | grep -nE "$bad" | head -5
    fail=1
  fi
  # Bare mktemp (no explicit template dir): falls back to $TMPDIR, so it
  # needs an inline/earlier TMPDIR pin in the same file. Templated forms
  # (mktemp "$VAR/...", mktemp -t) follow their template/TMPDIR, audited
  # above via the forbidden-default check. Comments are prose.
  awk '
    /^[[:space:]]*#/ { next }
    /TMPDIR=\/var\/worktrees\/\.cache\/tmpdir|TMPDIR:-\/var\/worktrees|TMPDIR="\$\{TMPDIR:-\/var\/worktrees/ { pinned=1 }
    /(^|[^_A-Za-z])mktemp( |$|;|\))/ && $0 !~ /TMPDIR=|TMPDIR:-|mktemp -d -t|mktemp -t|mktemp -d "\$|mktemp "\$|mktemp -d \$\{|mktemp "\$\{|mktemp -d\)|mktemp\)/ && !pinned { print FILENAME": bare mktemp line " NR": "$0; bad=1 }
    END { exit bad }
  ' "$root/$f" || fail=1
}
FILES="Makefile
scripts/mutate-selftest.sh
scripts/mutate.sh
scripts/miri-leg.sh
scripts/debug-leg-census-selftest.sh
scripts/dist/selftest.sh
scripts/dist/install.sh
scripts/image/test-grow-root.sh
scripts/image/bake.py
scripts/run-selftests.sh
scripts/ci_affected_go_tests_selftest.sh
scripts/go-test-json-selftest.sh
scripts/refactoring-audit-refresh.sh
scripts/docs/check-no-ci-claims-selftest.sh
scripts/docs/check-upgrade-docs-selftest.sh
scripts/userspace-perf-compare.sh
scripts/cut_stall_sampler.sh
scripts/image/test_bake_bridge_floor_10171.py
scripts/userspace-ha-validation.sh
scripts/userspace-ha-failover-validation.sh
scripts/userspace-native-gre-validation.sh
test/incus/harness-census-selftest.sh
test/incus/harness-ledger-mutation-selftest.sh
test/incus/harness-result-selftest.sh
test/incus/harness-result.sh
test/incus/ignored-cell-census-selftest.sh
test/incus/selftest-census-selftest.sh
test/incus/ha-smoke-iperf-lib.sh
test/incus/ipsec-content-change-10878.sh
test/incus/miri-census-selftest.sh
test/incus/private-rg-fullcycle-selftest.sh
test/incus/private-rg-selftest.sh
test/incus/with-cluster.sh
test/incus/wire-appmatch-twins.sh
test/incus/wire-conntrack-lifecycle.sh
test/incus/wire-gate-hermetic-selftest.sh
test/incus/wire-gate-lib.sh
test/incus/wire-hostinbound-deny.sh
test/incus/wire-policy-deny.sh
test/incus/wire-routing-separation.sh
test/incus/wire-zone-matrix.sh
test/incus/test-private-rg.sh
test/incus/test-failover.sh
test/incus/test-rolling-upgrade.sh
test/incus/t12-g2-9506.sh
test/incus/cluster-lock.sh
test/incus/test-mouse-latency-matrix.sh
test/incus/fairness-harness.sh
test/incus/wg-interop.env
test/mutation/shim-ext-parity-acceptance.sh"
for f in $FILES; do check_file "$f"; done
echo "ok: audited $(printf '%s\n' "$FILES" | wc -l) files for forbidden defaults + bare mktemp"

# Positive pins.
grep -q 'TMPDIR ?= /var/worktrees/.cache/tmpdir' "$root/Makefile" || { echo "FAIL: Makefile TMPDIR default missing"; fail=1; }
grep -q 'GOTMPDIR ?= /var/worktrees/.cache/go-tmp' "$root/Makefile" || { echo "FAIL: Makefile GOTMPDIR default missing"; fail=1; }
grep -q 'CARGO_TARGET_DIR ?= /var/worktrees/.cache/cargo' "$root/Makefile" || { echo "FAIL: Makefile CARGO_TARGET_DIR default missing"; fail=1; }
grep -q 'TMPDIR=/var/worktrees/.cache/go-tmp' "$root/Makefile" || { echo "FAIL: memlock TMPDIR not pinned"; fail=1; }
grep -q 'TMPDIR:-/var/worktrees/.cache/tmpdir' "$root/scripts/run-selftests.sh" || { echo "FAIL: run-selftests TMPDIR default missing"; fail=1; }
grep -q 'mkdir -p "$WORK"' "$root/scripts/mutate.sh" || { echo "FAIL: mutate.sh lost mkdir -p \$WORK"; fail=1; }
grep -q 'MUTATE_WORKDIR:-/var/worktrees/.cache/tmpdir' "$root/scripts/mutate.sh" || { echo "FAIL: mutate WORK not pinned"; fail=1; }

# AF_UNIX sun_path budget: worst memlock guard socket is
# <GOTMPDIR>/Test<Name><random>/<sock>. Allow root(28)+testdir(60)+sock(20).
sock=/var/worktrees/.cache/go-tmp/TestMemlockGuard1234567890/0123456789.sock
n=$(printf %s "$sock" | wc -c)
[ "$n" -lt 108 ] || { echo "FAIL: modelled guard socket path $n >= 108 bytes"; fail=1; }
mkdir -p /var/worktrees/.cache/tmpdir /var/worktrees/.cache/go-tmp /var/worktrees/.cache/go-build /var/worktrees/.cache/cargo || { echo "FAIL: cannot create scratch dirs"; fail=1; }
echo "scratch-pinning-selftest: fail=$fail (modelled socket=$n bytes)"
exit $fail
