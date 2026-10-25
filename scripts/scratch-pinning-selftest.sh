#!/bin/sh
# #14833: repo build/test scratch must not default to /tmp, /dev/shm, /var/tmp.
# Pins: Makefile/run-selftests export TMPDIR/GOCACHE/GOTMPDIR/CARGO_TARGET_DIR
# defaults under /var/worktrees/.cache; every other audited file either
# inherits TMPDIR (shell mktemp / python tempfile) or pins explicitly.
# Non-goals: remote-VM temp paths (run_vm/run_host/incus exec strings),
# guest paths in bake.py, fixture literals in *_test files, legacy
# mutate-*.py one-offs (their wt-* worktrees are historical), and the
# shipped installer scripts/dist/install.sh (#16539: it runs on customer
# hosts, so it uses mktemp -t honouring TMPDIR / falling back to /tmp).
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
grep -q 'GOTMPDIR ?= /wtgt' "$root/Makefile" || { echo "FAIL: Makefile GOTMPDIR default missing or not the short /wtgt root (#16494)"; fail=1; }
grep -q 'CARGO_TARGET_DIR ?= /var/worktrees/.cache/cargo' "$root/Makefile" || { echo "FAIL: Makefile CARGO_TARGET_DIR default missing"; fail=1; }
grep -q 'TMPDIR=/wtgt' "$root/Makefile" || { echo "FAIL: memlock TMPDIR not pinned to the short root"; fail=1; }
grep -q 'GOTMPDIR:-/wtgt' "$root/scripts/run-selftests.sh" || { echo "FAIL: run-selftests GOTMPDIR default missing or not the short /wtgt root (#16494)"; fail=1; }
grep -q 'TMPDIR:-/var/worktrees/.cache/tmpdir' "$root/scripts/run-selftests.sh" || { echo "FAIL: run-selftests TMPDIR default missing"; fail=1; }
grep -q 'mkdir -p "$WORK"' "$root/scripts/mutate.sh" || { echo "FAIL: mutate.sh lost mkdir -p \$WORK"; fail=1; }
grep -q 'MUTATE_WORKDIR:-/var/worktrees/.cache/tmpdir' "$root/scripts/mutate.sh" || { echo "FAIL: mutate WORK not pinned"; fail=1; }
# #16477: a templated mktemp whose parent may not exist (clean CI runner:
# no /var/worktrees, TMPDIR unset) must create the pinned parent first or
# check mktemp's status — an unchecked one leaves WORK empty and every
# fixture lands at "/<name>", turning the run into bogus failures.
for f in test/incus/harness-census-selftest.sh \
  test/incus/harness-ledger-mutation-selftest.sh \
  test/incus/harness-result-selftest.sh \
  test/incus/ignored-cell-census-selftest.sh \
  test/incus/selftest-census-selftest.sh \
  test/incus/miri-census-selftest.sh \
  test/incus/private-rg-selftest.sh \
  test/incus/private-rg-fullcycle-selftest.sh; do
  grep -q 'mkdir -p /var/worktrees/.cache/tmpdir' "$root/$f" || { echo "FAIL: $f does not create the pinned tmpdir parent (#16477)"; fail=1; }
  grep -q 'FATAL: cannot create work dir\|FATAL: work dir not created\|cannot create sandbox dir\|cannot create leg cell dir' "$root/$f" || { echo "FAIL: $f does not fail loudly on mktemp failure (#16477)"; fail=1; }
done

# AF_UNIX sun_path budget (#16494): executed canary, not a modelled
# path. The pre-#16494 check modelled a 71-byte socket Go never
# produces (26-char test dir, no /001 sequence dir); Go's real
# testing.TempDir shape is <GOTMPDIR>/<name[:64]><random>/001/<sock>,
# which under the old 28-char root is 120 octets for control.sock.
# scripts/sunpath-canary reproduces that shape and binds it. It must
# PASS under the pinned short root and FAIL under a long root, so a
# canary that stops binding reds here too. If /wtgt cannot be created
# (unprivileged host without the dir), the positive leg SKIPs loudly
# rather than falling back to a long root; the negative leg still runs.
mkdir -p /var/worktrees/.cache/tmpdir /var/worktrees/.cache/go-build /var/worktrees/.cache/cargo || { echo "FAIL: cannot create scratch dirs"; fail=1; }
GO=${GO:-go}
canary_out=""
if mkdir -p /wtgt 2>/dev/null; then
  if canary_out=$(GOTMPDIR=/wtgt TMPDIR=/wtgt GOCACHE="${GOCACHE:-/var/worktrees/.cache/go-build}" "$GO" run ./scripts/sunpath-canary 2>&1); then
    echo "ok: sunpath canary binds under pinned /wtgt root: $canary_out"
  else
    echo "FAIL: sunpath canary does not bind under pinned /wtgt root: $canary_out"; fail=1
  fi
else
  echo "SKIP: cannot create /wtgt; sunpath canary positive leg not run (create /wtgt writable to enable it)"
fi
longroot=/var/worktrees/.cache/go-tmp-canary-longroot-16494
mkdir -p "$longroot" || { echo "FAIL: cannot create long canary root"; fail=1; }
if canary_out=$(GOTMPDIR="$longroot" TMPDIR="$longroot" GOCACHE="${GOCACHE:-/var/worktrees/.cache/go-build}" "$GO" run ./scripts/sunpath-canary 2>&1); then
  echo "FAIL: sunpath canary unexpectedly binds under long root $longroot: $canary_out"; fail=1
else
  echo "ok: sunpath canary reds under long root ($longroot): $canary_out"
fi
rmdir "$longroot" 2>/dev/null || true
echo "scratch-pinning-selftest: fail=$fail"
exit $fail
