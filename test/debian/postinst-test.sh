#!/bin/sh
# #2000 — debian/xpf.postinst UPGRADE absent-link recovery test. The postinst
# is shell, so it is tested in shell. Run:
#
#   sh   test/debian/postinst-test.sh
#   dash test/debian/postinst-test.sh
#
# It runs the REAL postinst with the layout path vars rewritten to a temp ROOT,
# builds a hardened layout (versions/current present, sbin links resolving
# THROUGH it), deletes ONE sbin link, runs the `configure <old-version>`
# (upgrade) branch, and asserts the REPAIRED link resolves through
# versions/current/<bin>, NOT staged/<bin> (#2000). It also covers the
# newly-introduced-managed-binary edge (target absent from versions/current ->
# the link stays absent until the verified cut) and proves NON-TAUTOLOGY by
# synthesizing the pre-#2000 direct-to-staged postinst and asserting it repairs
# to staged (so the assertion discriminates the fix).
set -e

HERE=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
POSTINST="${1:-$HERE/../../debian/xpf.postinst}"
[ -f "$POSTINST" ] || { echo "postinst not found: $POSTINST" >&2; exit 1; }

BINS="xpfd cli xpf-userspace-dp xpf-day0-config"

# Run the REAL postinst with overridden absolute path vars by editing the
# script's var assignments + CURRENT_DIR to point under a temp ROOT, and
# neutralizing the side-effecting #DEBHELPER# / systemctl bits that a unit
# test must not trigger. We generate a patched copy per scenario.
patched_postinst() {
    sed \
      -e "s#^STAGED=.*#STAGED=$ROOT/usr/local/share/xpf/staged#" \
      -e "s#^SBIN=.*#SBIN=$ROOT/usr/local/sbin#" \
      -e "s#^SYSCTL_D=.*#SYSCTL_D=$ROOT/etc/sysctl.d#" \
      -e "s#^\([[:space:]]*\)CURRENT_DIR=.*#\1CURRENT_DIR=$ROOT/var/lib/xpf/versions/current#" \
      -e "s#/etc/xpf/node-id#$ROOT/etc/xpf/node-id#g" \
      -e "s#\\[ -d /run/systemd/system \\]#false#g" \
      "$POSTINST" > "$ROOT/postinst"
    chmod +x "$ROOT/postinst"
    [ "$(grep -E '^STAGED=' "$ROOT/postinst" || true)" = "STAGED=$ROOT/usr/local/share/xpf/staged" ] || {
        echo "FAIL: patched postinst missing rewritten STAGED assignment"; exit 1; }
    # #9725: the scrub EDITS files, so an un-rewritten SYSCTL_D would have this
    # unit test rewrite the host's own /etc/sysctl.d.
    [ "$(grep -E '^SYSCTL_D=' "$ROOT/postinst" || true)" = "SYSCTL_D=$ROOT/etc/sysctl.d" ] || {
        echo "FAIL: patched postinst missing rewritten SYSCTL_D assignment"; exit 1; }
    [ "$(grep -E '^SBIN=' "$ROOT/postinst" || true)" = "SBIN=$ROOT/usr/local/sbin" ] || {
        echo "FAIL: patched postinst missing rewritten SBIN assignment"; exit 1; }
    current_line=$(grep -E '^[[:space:]]*CURRENT_DIR=' "$ROOT/postinst" || true)
    case "$current_line" in
        *"CURRENT_DIR=$ROOT/var/lib/xpf/versions/current") ;;
        *) echo "FAIL: patched postinst missing rewritten CURRENT_DIR assignment"; exit 1 ;;
    esac
    grep -Fqx "            elif [ -f $ROOT/etc/xpf/node-id ]; then" "$ROOT/postinst" || {
        echo "FAIL: patched postinst missing rewritten node-id gate"; exit 1; }
    grep -Fqx "                    if false && ! systemctl is-active --quiet xpfd; then" "$ROOT/postinst" || {
        echo "FAIL: patched postinst missing neutralized systemd gate"; exit 1; }
}

run_scenario() {
    name="$1"
    ROOT=$(mktemp -d)
    STAGED="$ROOT/usr/local/share/xpf/staged"
    SBIN="$ROOT/usr/local/sbin"
    VERSIONS="$ROOT/var/lib/xpf/versions"
    CURRENT="$VERSIONS/current"
    patched_postinst
    "scenario_$name"
    rm -rf "$ROOT"
    echo "PASS $name"
}

# Build a hardened layout: versions/<ver>/<bin>, current -> <ver>, sbin ->
# versions/current/<bin>. The staged xpfd is a stub that answers the two
# subcommands the upgrade branch invokes (`publish-generation`, `upgrade`).
# publish-generation exits 0 here; the postinst still SKIPS the cut because the
# test drops a node-id file so the node is treated as CLUSTERED (stage-only).
# That keeps the scenarios focused on the absent-link recovery loop, not the
# cut machine.
build_hardened() {
    ver="$1"
    mkdir -p "$STAGED" "$SBIN" "$VERSIONS/$ver" "$ROOT/etc/xpf"
    : > "$ROOT/etc/xpf/node-id"
    cat > "$STAGED/xpfd" <<'EOF'
#!/bin/sh
case "$1" in
    publish-generation) exit 0 ;;  # published; node-id makes it stage-only
    upgrade)            exit 0 ;;
    version)            echo "xpfd VER (commit x, built y)"; exit 0 ;;
    *)                  echo "unknown command \"$1\"" >&2; exit 1 ;;
esac
EOF
    sed -i "s/VER/$ver/" "$STAGED/xpfd"
    chmod +x "$STAGED/xpfd"
    echo "bin-xpfd" > "$VERSIONS/$ver/xpfd"; chmod +x "$VERSIONS/$ver/xpfd"
    for b in cli xpf-userspace-dp xpf-day0-config; do
        echo "bin-$b" > "$STAGED/$b"; chmod +x "$STAGED/$b"
        echo "bin-$b" > "$VERSIONS/$ver/$b"; chmod +x "$VERSIONS/$ver/$b"
    done
    ln -sf "$ver" "$CURRENT"
    for b in $BINS; do
        ln -sf "$CURRENT/$b" "$SBIN/$b"
    done
}

# === #2000 CORE: an absent sbin link is recovered THROUGH versions/current ===
# Delete ONE sbin link, run the upgrade-configure branch, assert the repaired
# link resolves to versions/current/<bin>, NOT staged/<bin>. Done for `cli`
# (operator tool — direct-to-staged would run the new CLI against the old
# daemon) and `xpf-userspace-dp` (the helper — direct-to-staged would expose
# the unverified staged helper before the cut verified it).
assert_recovers_through_current() {
    missing="$1"
    build_hardened "1.0.0"
    rm -f "$SBIN/$missing"
    if [ -L "$SBIN/$missing" ]; then
        echo "FAIL: precondition: $missing link should be gone"
        exit 1
    fi
    "$ROOT/postinst" configure "0.9.0"
    [ -L "$SBIN/$missing" ] || { echo "FAIL: $missing link not recreated"; exit 1; }
    tgt=$(readlink "$SBIN/$missing")
    [ "$tgt" = "$CURRENT/$missing" ] || {
        echo "FAIL: $missing recovered to '$tgt', want '$CURRENT/$missing' (through versions/current, not staged)"; exit 1; }
    # The other links are UNTOUCHED (still through current).
    for b in $BINS; do
        [ "$b" = "$missing" ] && continue
        [ "$(readlink "$SBIN/$b")" = "$CURRENT/$b" ] || {
            echo "FAIL: $b disturbed (now '$(readlink "$SBIN/$b")')"; exit 1; }
    done
}

scenario_recovers_cli_through_current() {
    assert_recovers_through_current "cli"
}

scenario_recovers_helper_through_current() {
    assert_recovers_through_current "xpf-userspace-dp"
}

# === Existing-link protection is preserved (only ABSENT links are touched) ===
# An operator-repointed sbin link is NOT repointed; a dangling link (e.g. one
# increment-B repointed to a transiently-missing versions/<v>/ target) is NOT
# stolen. -e alone follows a symlink, so the postinst guards with -L too.
scenario_leaves_existing_and_dangling_links() {
    build_hardened "1.0.0"
    # Operator repointed cli elsewhere (existing, resolvable).
    ln -sf "/opt/custom/cli" "$SBIN/cli"
    # A dangling link (broken: target does not exist).
    ln -sf "$CURRENT/nonexistent-target" "$SBIN/xpf-userspace-dp"
    "$ROOT/postinst" configure "0.9.0"
    [ "$(readlink "$SBIN/cli")" = "/opt/custom/cli" ] || {
        echo "FAIL: operator-repointed cli was disturbed"; exit 1; }
    [ "$(readlink "$SBIN/xpf-userspace-dp")" = "$CURRENT/nonexistent-target" ] || {
        echo "FAIL: dangling link was stolen/repointed"; exit 1; }
}

# === NEW-MANAGED-BINARY EDGE: absent from versions/current -> stays absent ===
# A newly-introduced managed binary on its FIRST upgrade has no entry under
# versions/current yet. Its absent sbin link must be LEFT ABSENT (never pointed
# direct to the unverified staged binary); the verified cut populates
# versions/<v>/ and flips it.
scenario_new_managed_binary_stays_absent() {
    build_hardened "1.0.0"
    # Simulate `cli` being newly introduced: present in staged, ABSENT from
    # versions/current, and its sbin link absent.
    rm -f "$SBIN/cli" "$CURRENT/cli"
    if [ -e "$CURRENT/cli" ]; then
        echo "FAIL: precondition: current/cli should be absent"
        exit 1
    fi
    "$ROOT/postinst" configure "0.9.0"
    if [ -e "$SBIN/cli" ]; then
        echo "FAIL: new-managed-binary cli link created (exposes unverified staged)"
        exit 1
    fi
    if [ -L "$SBIN/cli" ]; then
        echo "FAIL: new-managed-binary cli link created as symlink"
        exit 1
    fi
    # The others are unchanged.
    for b in xpfd xpf-userspace-dp xpf-day0-config; do
        [ "$(readlink "$SBIN/$b")" = "$CURRENT/$b" ] || {
            echo "FAIL: $b disturbed by the new-managed-binary path"; exit 1; }
    done
}

# === Legacy/never-seeded host (no versions/current): absent link left for the
# preinst migration + cut, NEVER pointed direct to staged here. ===
scenario_legacy_no_current_leaves_absent() {
    mkdir -p "$STAGED" "$SBIN" "$ROOT/etc/xpf"
    : > "$ROOT/etc/xpf/node-id"
    cat > "$STAGED/xpfd" <<'EOF'
#!/bin/sh
case "$1" in
    publish-generation) exit 0 ;;
    upgrade) exit 0 ;;
    *) echo "unknown \"$1\"" >&2; exit 1 ;;
esac
EOF
    chmod +x "$STAGED/xpfd"
    for b in cli xpf-userspace-dp xpf-day0-config; do
        echo "bin-$b" > "$STAGED/$b"; chmod +x "$STAGED/$b"
    done
    # Legacy direct-to-staged links for the present ones; xpfd link ABSENT.
    for b in cli xpf-userspace-dp xpf-day0-config; do
        ln -sf "$STAGED/$b" "$SBIN/$b"
    done
    if [ -e "$CURRENT" ]; then
        echo "FAIL: precondition: no versions/current expected"
        exit 1
    fi
    "$ROOT/postinst" configure "0.9.0"
    # The absent xpfd link must NOT be recreated direct to staged.
    if [ -e "$SBIN/xpfd" ]; then
        echo "FAIL: legacy host absent xpfd link recreated direct to staged"
        exit 1
    fi
    if [ -L "$SBIN/xpfd" ]; then
        echo "FAIL: legacy host absent xpfd link recreated"
        exit 1
    fi
    # The existing legacy links are NOT disturbed (only absent links acted on).
    for b in cli xpf-userspace-dp xpf-day0-config; do
        [ "$(readlink "$SBIN/$b")" = "$STAGED/$b" ] || {
            echo "FAIL: legacy link $b disturbed"; exit 1; }
    done
}

# === NON-TAUTOLOGY PROOF ===
# Synthesize the PRE-#2000 (buggy) postinst by patching the fixed temp copy
# back to the old behavior: recreate an absent link DIRECT to $STAGED with no
# versions/current indirection. Run the SAME core scenario and assert it
# repairs to STAGED. This proves scenario_recovers_*_through_current actually
# discriminates the fix: the old script repairs to staged (would FAIL the
# core assertion), the fixed script repairs through current (PASSES). A
# sentinel records that the rewrite matched something so a pattern-drift
# regression fails loud instead of vacuously synthesizing the fixed script.
patched_postinst_oldbug() {
    # Replace the whole absent-link recovery for-loop body (from the
    # `CURRENT_DIR=` line through the loop's closing `done`) with the historical
    # direct-to-staged recreation. awk so the rewrite is robust to comment
    # churn. The block to replace begins at the (temp-rewritten) CURRENT_DIR
    # assignment and ends at the FIRST `done` after it.
    awk -v sbin="$SBIN" -v staged="$STAGED" '
      BEGIN { in_block = 0; synth = 0 }
      $0 ~ /^[[:space:]]*CURRENT_DIR=.*\/versions\/current[[:space:]]*$/ {
        print "            for b in $BINS; do"
        print "                if [ ! -e \"$SBIN/$b\" ] && [ ! -L \"$SBIN/$b\" ]; then"
        print "                    mkdir -p \"$SBIN\""
        print "                    ln -sfnT \"$STAGED/$b\" \"$SBIN/$b\""
        print "                fi"
        print "            done"
        in_block = 1
        synth = 1
        next
      }
      in_block == 1 {
        if ($0 ~ /^[[:space:]]*done[[:space:]]*$/) { in_block = 0 }
        next
      }
      { print }
      END { print "# __OLDBUG_SYNTH__=" synth > "/dev/stderr" }
    ' "$ROOT/postinst" > "$ROOT/postinst.oldbug" 2> "$ROOT/postinst.oldbug.synth"
    chmod +x "$ROOT/postinst.oldbug"
}

scenario_oldbug_repairs_to_staged_proves_nontautology() {
    build_hardened "1.0.0"
    patched_postinst_oldbug
    grep -q '__OLDBUG_SYNTH__=1' "$ROOT/postinst.oldbug.synth" || {
        echo "FAIL(non-tautology): awk did not match the recovery loop — no old-bug script synthesized (proof vacuous)"; exit 1; }
    if cmp -s "$ROOT/postinst" "$ROOT/postinst.oldbug"; then
        echo "FAIL(non-tautology): synthesized old-bug postinst is identical to the fixed one"
        exit 1
    fi
    sh -n "$ROOT/postinst.oldbug" || { echo "FAIL: synthesized old-bug postinst has a syntax error"; exit 1; }
    rm -f "$SBIN/cli"
    "$ROOT/postinst.oldbug" configure "0.9.0"
    # OLD behavior: the absent cli link is recreated DIRECT to staged.
    tgt=$(readlink "$SBIN/cli")
    [ "$tgt" = "$STAGED/cli" ] || {
        echo "FAIL(non-tautology): old-bug postinst recovered cli to '$tgt', expected '$STAGED/cli' — the core test would not discriminate the fix"; exit 1; }
}

run_scenario recovers_cli_through_current
run_scenario recovers_helper_through_current
run_scenario leaves_existing_and_dangling_links
run_scenario new_managed_binary_stays_absent
run_scenario legacy_no_current_leaves_absent
run_scenario oldbug_repairs_to_staged_proves_nontautology
echo "ALL POSTINST SCENARIOS PASSED"
