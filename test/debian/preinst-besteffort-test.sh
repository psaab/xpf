#!/bin/sh
# #1964 / AGY review-011 — prove debian/xpf.preinst's legacy migration is
# best-effort: a failure inside migrate_legacy_layout must NEVER fail the
# preinst (apt) transaction. This drives the REAL preinst `upgrade` case
# end-to-end (not just the extracted function), with the lock + migration
# path redirected under a temp root, and injects a migration failure.
#
#   sh   test/debian/preinst-besteffort-test.sh
#   dash test/debian/preinst-besteffort-test.sh
set -e

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREINST="${1:-$HERE/../../debian/xpf.preinst}"
[ -f "$PREINST" ] || { echo "preinst not found: $PREINST" >&2; exit 1; }

run_scenario() {
    name="$1"
    ROOT=$(mktemp -d)
    # Patch the absolute layout vars + the lock path to the temp root so the
    # real preinst runs hermetically. Keep the lock under $ROOT/run so flock
    # succeeds (free lock) and the gate passes; we are testing the migration
    # best-effort, not the gate.
    sed \
      -e "s#^LOCK=.*#LOCK=$ROOT/run/xpf/upgrade.lock#" \
      -e "s#^STAGED=.*#STAGED=$ROOT/usr/local/share/xpf/staged#" \
      -e "s#^SBIN=.*#SBIN=$ROOT/usr/local/sbin#" \
      -e "s#^VERSIONS=.*#VERSIONS=$ROOT/var/lib/xpf/versions#" \
      -e "s#mkdir -p /run/xpf#mkdir -p $ROOT/run/xpf#g" \
      -e "s#chmod 0750 /run/xpf#chmod 0750 $ROOT/run/xpf#g" \
      -e 's#chmod 0600 "$LOCK"#chmod 0600 "$LOCK"#' \
      "$PREINST" > "$ROOT/preinst"
    chmod +x "$ROOT/preinst"
    STAGED="$ROOT/usr/local/share/xpf/staged"
    SBIN="$ROOT/usr/local/sbin"
    VERSIONS="$ROOT/var/lib/xpf/versions"
    "scenario_$name"
    rm -rf "$ROOT" 2>/dev/null || { chmod -R u+w "$ROOT" 2>/dev/null; rm -rf "$ROOT"; }
    echo "PASS $name"
}

build_legacy() {
    ver="$1"
    mkdir -p "$STAGED" "$SBIN"
    cat > "$STAGED/xpfd" <<EOF
#!/bin/sh
[ "\$1" = version ] && echo "xpfd $ver (commit x, built y)"
EOF
    chmod +x "$STAGED/xpfd"
    for b in cli xpf-userspace-dp xpf-day0-config; do
        echo "bin-$b-$ver" > "$STAGED/$b"; chmod +x "$STAGED/$b"
    done
    for b in xpfd cli xpf-userspace-dp xpf-day0-config; do
        ln -sf "$STAGED/$b" "$SBIN/$b"
    done
}

# A normal legacy upgrade succeeds and exits 0 (sanity).
scenario_normal_succeeds() {
    build_legacy "1.0.0"
    if ! "$ROOT/preinst" upgrade "0.9.0"; then
        echo "FAIL: normal preinst upgrade exited non-zero"; exit 1
    fi
    [ -L "$VERSIONS/current" ] || { echo "FAIL: current not created in normal path"; exit 1; }
}

# Migration failure (versions parent is read-only -> mkdir/cp fails) must
# NOT fail the preinst transaction: exit 0, legacy layout left intact.
scenario_failure_does_not_abort() {
    build_legacy "1.0.0"
    # Make /var/lib/xpf read-only so `mkdir -p "$VERSIONS"` / cp fails.
    mkdir -p "$ROOT/var/lib/xpf"
    chmod 0555 "$ROOT/var/lib/xpf"
    rc=0
    "$ROOT/preinst" upgrade "0.9.0" || rc=$?
    chmod 0755 "$ROOT/var/lib/xpf" 2>/dev/null || true
    if [ "$rc" -ne 0 ]; then
        echo "FAIL: preinst aborted (rc=$rc) on a migration failure — violates best-effort"; exit 1
    fi
    # Legacy sbin links must be left intact (untouched).
    [ "$(readlink "$SBIN/xpfd")" = "$STAGED/xpfd" ] || { echo "FAIL: sbin mutated despite migration failure"; exit 1; }
    # current must not exist (migration aborted before creating it).
    [ ! -e "$VERSIONS/current" ] || { echo "FAIL: current created despite migration failure"; exit 1; }
}

run_scenario normal_succeeds
run_scenario failure_does_not_abort
echo "ALL PREINST BEST-EFFORT SCENARIOS PASSED"
