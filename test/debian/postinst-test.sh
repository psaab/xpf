#!/bin/sh
# First-install seed safety (#10771) and upgrade absent-link recovery (#2000).
# The postinst is shell, so it is tested in shell. Run:
#
#   sh   test/debian/postinst-test.sh
#   dash test/debian/postinst-test.sh
#
# It runs the REAL postinst with layout paths rewritten to a temp ROOT. The
# first-install cells exercise `configure ""` on success and seed failure,
# then kill the postinst shell while seed-runtime is blocked and assert all
# staged launch links already exist. The upgrade cells prove absent links
# recover through versions/current rather than staged, cover a newly managed
# binary, and retain the #2000 old-bug non-tautology control.
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
      -e "s#^XPF_RUN_DIR=.*#XPF_RUN_DIR=$ROOT/run/xpf#" \
      -e "s#^\([[:space:]]*\)CURRENT_DIR=.*#\1CURRENT_DIR=$ROOT/var/lib/xpf/versions/current#" \
      -e "s#/etc/xpf/node-id#$ROOT/etc/xpf/node-id#g" \
      -e "s#\\[ -d /run/systemd/system \\]#false#g" \
      "$POSTINST" > "$ROOT/postinst"
    chmod +x "$ROOT/postinst"
    [ "$(grep -E '^STAGED=' "$ROOT/postinst" || true)" = "STAGED=$ROOT/usr/local/share/xpf/staged" ] || {
        echo "FAIL: patched postinst missing rewritten STAGED assignment"; exit 1; }
    [ "$(grep -E '^SBIN=' "$ROOT/postinst" || true)" = "SBIN=$ROOT/usr/local/sbin" ] || {
        echo "FAIL: patched postinst missing rewritten SBIN assignment"; exit 1; }
    [ "$(grep -E '^XPF_RUN_DIR=' "$ROOT/postinst" || true)" = "XPF_RUN_DIR=$ROOT/run/xpf" ] || {
        echo "FAIL: patched postinst missing rewritten XPF_RUN_DIR assignment"; exit 1; }
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

# First-install success: the fake seed-runtime adopts the pre-created staged
# launch links into the versioned chain, exercising the configure "" branch.
build_first_install_success() {
    mkdir -p "$STAGED"
    for b in $BINS; do
        printf 'staged-%s\n' "$b" > "$STAGED/$b"
        chmod 0755 "$STAGED/$b"
    done
    cat > "$STAGED/xpfd" <<EOF
#!/bin/sh
case "\$1" in
    seed-runtime)
        mkdir -p "$VERSIONS/1.0.0"
        for b in $BINS; do cp "$STAGED/\$b" "$VERSIONS/1.0.0/\$b"; done
        ln -sfn 1.0.0 "$CURRENT"
        for b in $BINS; do ln -sfn "$CURRENT/\$b" "$SBIN/\$b"; done
        exit 0 ;;
    *) exit 1 ;;
esac
EOF
    chmod 0755 "$STAGED/xpfd"
}

scenario_first_install_configure_empty_seeds_layout() {
    build_first_install_success
    "$ROOT/postinst" configure ""
    for b in $BINS; do
        [ -L "$SBIN/$b" ] || { echo "FAIL: first install omitted sbin/$b"; exit 1; }
        [ "$(readlink "$SBIN/$b")" = "$CURRENT/$b" ] || {
            echo "FAIL: first install $b link is not through versions/current"; exit 1; }
        cmp -s "$STAGED/$b" "$SBIN/$b" || {
            echo "FAIL: first install $b link does not resolve to the versioned staged bytes"; exit 1; }
    done
}

scenario_first_install_seed_failure_falls_back_to_staged() {
    mkdir -p "$STAGED"
    for b in $BINS; do
        printf 'staged-%s\n' "$b" > "$STAGED/$b"
        chmod 0755 "$STAGED/$b"
    done
    cat > "$STAGED/xpfd" <<'EOF'
#!/bin/sh
case "$1" in
    seed-runtime) exit 1 ;;
    *) exit 1 ;;
esac
EOF
    chmod 0755 "$STAGED/xpfd"
    "$ROOT/postinst" configure ""
    for b in $BINS; do
        [ -L "$SBIN/$b" ] || { echo "FAIL: seed failure left sbin/$b absent"; exit 1; }
        [ "$(readlink "$SBIN/$b")" = "$STAGED/$b" ] || {
            echo "FAIL: seed failure $b fallback is not direct-staged"; exit 1; }
        [ -x "$SBIN/$b" ] || { echo "FAIL: seed failure sbin/$b is not launchable"; exit 1; }
    done
}


# Kill the postinst shell while seed-runtime is still running. All sbin names
# must already resolve to staged binaries even though neither the seed's step 4
# nor #DEBHELPER# can run.
scenario_first_install_killed_during_seed_keeps_launch_links() {
    mkdir -p "$STAGED"
    for b in $BINS; do
        printf 'staged-%s\n' "$b" > "$STAGED/$b"
        chmod 0755 "$STAGED/$b"
    done
    cat > "$STAGED/xpfd" <<EOF
#!/bin/sh
case "\$1" in
    seed-runtime)
        echo \$\$ > "$ROOT/seed-child.pid"
        : > "$ROOT/seed-started"
        while [ ! -e "$ROOT/release-seed" ]; do sleep 0.05; done
        : > "$ROOT/seed-finished"
        exit 0 ;;
    *) exit 1 ;;
esac
EOF
    chmod 0755 "$STAGED/xpfd"
    "$ROOT/postinst" configure "" &
    postinst_pid=$!
    tries=0
    while [ ! -f "$ROOT/seed-started" ]; do
        tries=$((tries + 1))
        if [ "$tries" -ge 100 ]; then
            kill -KILL "$postinst_pid" 2>/dev/null || true
            echo "FAIL: first-install postinst never entered seed-runtime"; exit 1
        fi
        sleep 0.05
    done
    kill -KILL "$postinst_pid" 2>/dev/null || true
    if wait "$postinst_pid" 2>/dev/null; then
        echo "FAIL: first-install postinst unexpectedly survived SIGKILL"; exit 1
    fi
    : > "$ROOT/release-seed"
    tries=0
    while [ ! -f "$ROOT/seed-finished" ]; do
        tries=$((tries + 1))
        if [ "$tries" -ge 100 ]; then
            echo "FAIL: seed-runtime child did not exit after release"; exit 1
        fi
        sleep 0.05
    done
    for b in $BINS; do
        [ -L "$SBIN/$b" ] || { echo "FAIL: killed postinst left sbin/$b absent"; exit 1; }
        [ "$(readlink "$SBIN/$b")" = "$STAGED/$b" ] || {
            echo "FAIL: killed postinst sbin/$b does not fall back to staged"; exit 1; }
        [ -x "$SBIN/$b" ] || { echo "FAIL: killed postinst sbin/$b is not launchable"; exit 1; }
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

# #10751 fresh-install barrier: with no live daemon and booted systemd, the
# first-install branch must start the barrier live (dh_installsystemd
# --no-start only stages it for next boot).
patched_postinst_barrier_live() {
    # Standard rewrites neutralize every systemd gate; re-arm ONLY the
    # barrier gate (unique: it tests $SBIN/xpfd executability).
    sed -i 's|if false && \[ -x "\$SBIN/xpfd" \]; then # 10751-BARRIER-GATE|if true; then # 10751-BARRIER-GATE|' "$ROOT/postinst"
    grep -Fq 'if true; then # 10751-BARRIER-GATE' "$ROOT/postinst" || {
        echo "FAIL: barrier gate re-arm did not match (postinst drift?)"; exit 1; }
    NFT_TABLE_PRESENT=no
    export NFT_TABLE_PRESENT
    stub_nft
}

stub_systemctl() {
    # $1: is-active exit status (0 = live daemon, 1 = none).
    mkdir -p "$ROOT/bin"
    SYSTEMCTL_LOG="$ROOT/systemctl.log"
    export SYSTEMCTL_LOG
    cat > "$ROOT/bin/systemctl" <<EOF
#!/bin/sh
echo "systemctl \$*" >> "$SYSTEMCTL_LOG"
if [ "\$1" = is-active ]; then exit $1; fi
exit 0
EOF
    chmod +x "$ROOT/bin/systemctl"
}

scenario_first_install_starts_barrier_without_daemon() {
    build_first_install_success
    patched_postinst_barrier_live
    stub_systemctl 1
    PATH="$ROOT/bin:$PATH" "$ROOT/postinst" configure ""
    grep -Fq 'nft list table inet xpf_input_barrier' "$NFT_LOG" || {
        echo "FAIL: postinst did not probe kernel barrier state"; exit 1; }
    grep -Fq 'systemctl is-active --quiet xpfd' "$SYSTEMCTL_LOG" || {
        echo "FAIL: postinst did not probe for a live daemon"; exit 1; }
    grep -Fq 'systemctl enable --now xpf-input-closed.service' "$SYSTEMCTL_LOG" || {
        echo "FAIL: fresh install without a daemon did not start the input barrier live"; exit 1; }
}

scenario_first_install_injects_barrier_with_active_unhanded_daemon() {
    build_first_install_success
    patched_postinst_barrier_live
    stub_systemctl 0
    PATH="$ROOT/bin:$PATH" "$ROOT/postinst" configure ""
    grep -Fq 'nft list table inet xpf_input_barrier' "$NFT_LOG" || {
        echo "FAIL: postinst did not consult kernel truth before the daemon probe"; exit 1; }
    grep -Fq 'systemctl is-active --quiet xpfd' "$SYSTEMCTL_LOG" || {
        echo "FAIL: postinst did not probe for a live daemon"; exit 1; }
    grep -Fq 'systemctl enable --now xpf-input-closed.service' "$SYSTEMCTL_LOG" || {
        echo "FAIL: active-but-unhanded daemon did not get a barrier injection"; exit 1; }
}

stub_nft() {
    # NFT_TABLE_PRESENT=yes simulates a live barrier table (exit 0 plus a
    # DROP-bearing dump); NFT_TABLE_SHELL=yes simulates a present-but-open
    # shell (exit 0, table header with no DROP verdict).
    mkdir -p "$ROOT/bin"
    NFT_LOG="$ROOT/nft.log"
    export NFT_LOG NFT_TABLE_PRESENT NFT_TABLE_SHELL
    cat > "$ROOT/bin/nft" <<EOF
#!/bin/sh
echo "nft \$*" >> "$NFT_LOG"
if [ "\$1 \$2 \$3 \$4" = "list table inet xpf_input_barrier" ]; then
    if [ "\$NFT_TABLE_SHELL" = yes ]; then
        echo 'table inet xpf_input_barrier {'
        echo '  chain input {'
        echo '    type filter hook input priority 12; policy accept;'
        echo '  }'
        echo '}'
        exit 0
    elif [ "\$NFT_TABLE_PRESENT" = yes ]; then
        echo 'table inet xpf_input_barrier {'
        echo '  chain input {'
        echo '    type filter hook input priority 12; policy accept;'
        echo '    ct state established,related accept'
        echo '    iifname != { "fxp0" } drop'
        echo '  }'
        echo '}'
        exit 0
    else
        exit 1
    fi
fi
exit 1
EOF
    chmod +x "$ROOT/bin/nft"
}
stub_flock() {
    # FLOCK_HELD=yes simulates a live owner holding the marker (flock
    # fails, exit 1); FLOCK_ERROR=yes simulates an operational/internal
    # flock error (exit 2 — a distinct code the shell gate maps to live
    # like any nonzero); unset simulates stale/orphaned (flock succeeds).
    # Every invocation is logged so scenarios prove which mode fired.
    mkdir -p "$ROOT/bin"
    FLOCK_LOG="$ROOT/flock.log"
    export FLOCK_HELD FLOCK_ERROR FLOCK_LOG
    cat > "$ROOT/bin/flock" <<EOF
#!/bin/sh
if [ "\$FLOCK_ERROR" = yes ]; then echo "flock exit=2" >> "$FLOCK_LOG"; exit 2; fi
if [ "\$FLOCK_HELD" = yes ]; then echo "flock exit=1" >> "$FLOCK_LOG"; exit 1; fi
echo "flock exit=0" >> "$FLOCK_LOG"
exit 0
EOF
    chmod +x "$ROOT/bin/flock"
}

scenario_first_install_skips_barrier_when_table_live() {
    build_first_install_success
    patched_postinst_barrier_live
    stub_systemctl 0
    NFT_TABLE_PRESENT=yes
    export NFT_TABLE_PRESENT
    PATH="$ROOT/bin:$PATH" "$ROOT/postinst" configure ""
    grep -Fq 'nft list table inet xpf_input_barrier' "$NFT_LOG" || {
        echo "FAIL: postinst did not probe kernel barrier state"; exit 1; }
    if grep -Fq 'systemctl enable --now xpf-input-closed.service' "$SYSTEMCTL_LOG"; then
        echo "FAIL: postinst injected the barrier despite a live table"; exit 1
    fi
    if [ -e "$SYSTEMCTL_LOG" ] && grep -Fq 'systemctl is-active --quiet xpfd' "$SYSTEMCTL_LOG"; then
        echo "FAIL: postinst probed the daemon despite a live table (table must win first)"; exit 1
    fi
}

scenario_first_install_injects_barrier_when_table_shell() {
    build_first_install_success
    patched_postinst_barrier_live
    stub_systemctl 0
    NFT_TABLE_PRESENT=yes
    NFT_TABLE_SHELL=yes
    export NFT_TABLE_PRESENT NFT_TABLE_SHELL
    PATH="$ROOT/bin:$PATH" "$ROOT/postinst" configure ""
    grep -Fq 'nft list table inet xpf_input_barrier' "$NFT_LOG" || {
        echo "FAIL: postinst did not probe kernel barrier state"; exit 1; }
    grep -Fq 'systemctl enable --now xpf-input-closed.service' "$SYSTEMCTL_LOG" || {
        echo "FAIL: present-but-open shell table did not trigger a barrier injection"; exit 1; }
}

scenario_first_install_skips_barrier_with_live_handoff_marker() {
    build_first_install_success
    patched_postinst_barrier_live
    stub_systemctl 0
    stub_flock
    FLOCK_HELD=yes
    export FLOCK_HELD
    mkdir -p "$ROOT/run/xpf"
    : > "$ROOT/run/xpf/early-input-handoff.done"
    PATH="$ROOT/bin:$PATH" "$ROOT/postinst" configure ""
    if grep -Fq 'systemctl enable --now xpf-input-closed.service' "$SYSTEMCTL_LOG"; then
        echo "FAIL: postinst injected the barrier despite a handoff marker (raw-binary daemon?)"; exit 1
    fi
    if [ -e "$NFT_LOG" ] && grep -Fq 'nft list table' "$NFT_LOG"; then
        echo "FAIL: postinst probed kernel despite a handoff marker (marker must win first)"; exit 1
    fi
    if [ -e "$SYSTEMCTL_LOG" ] && grep -Fq 'systemctl is-active --quiet xpfd' "$SYSTEMCTL_LOG"; then
        echo "FAIL: postinst probed the daemon despite a handoff marker"; exit 1
    fi
}

scenario_first_install_injects_barrier_with_stale_handoff_marker() {
    build_first_install_success
    patched_postinst_barrier_live
    stub_systemctl 1
    stub_flock
    unset FLOCK_HELD
    export FLOCK_HELD
    mkdir -p "$ROOT/run/xpf"
    : > "$ROOT/run/xpf/early-input-handoff.done"
    PATH="$ROOT/bin:$PATH" "$ROOT/postinst" configure ""
    grep -Fq 'nft list table inet xpf_input_barrier' "$NFT_LOG" || {
        echo "FAIL: postinst skipped kernel truth on a stale unlocked marker"; exit 1; }
    grep -Fq 'systemctl enable --now xpf-input-closed.service' "$SYSTEMCTL_LOG" || {
        echo "FAIL: stale unlocked marker plus absent table did not trigger a barrier injection"; exit 1; }
}

scenario_first_install_proceeds_without_flock_binary() {
    build_first_install_success
    patched_postinst_barrier_live
    stub_systemctl 1
    # NOTE: no stub_flock — and the system PATH is withheld so flock(1)
    # is genuinely unresolvable; every OTHER external the fresh-install
    # path needs is symlinked in (only flock stays absent).
    for u in grep mkdir cp ln id cat chmod rm sed; do
        command -v "$u" >/dev/null 2>&1 || { echo "FAIL: test host lacks $u for the no-flock sandbox"; exit 1; }
        ln -s "$(command -v "$u")" "$ROOT/bin/$u"
    done
    mkdir -p "$ROOT/run/xpf"
    : > "$ROOT/run/xpf/early-input-handoff.done"
    # Preconditions (non-vacuity): flock unresolvable, grep usable — a
    # missing grep would inject via pipeline-false for the wrong reason.
    if PATH="$ROOT/bin" command -v flock >/dev/null 2>&1; then
        echo "FAIL: flock resolvable in the no-flock sandbox"; exit 1
    fi
    PATH="$ROOT/bin" command -v grep >/dev/null 2>&1 || {
        echo "FAIL: grep unresolvable in the no-flock sandbox (inject would be vacuous)"; exit 1; }
    PATH="$ROOT/bin" "$ROOT/postinst" configure ""
    grep -Fq 'nft list table inet xpf_input_barrier' "$NFT_LOG" || {
        echo "FAIL: postinst skipped kernel truth with flock missing (must fail closed via kernel truth)"; exit 1; }
    grep -Fq 'systemctl enable --now xpf-input-closed.service' "$SYSTEMCTL_LOG" || {
        echo "FAIL: missing flock plus absent table did not trigger a barrier injection"; exit 1; }
}

scenario_first_install_skips_barrier_on_flock_error() {
    build_first_install_success
    patched_postinst_barrier_live
    stub_systemctl 0
    stub_flock
    FLOCK_ERROR=yes
    export FLOCK_ERROR
    mkdir -p "$ROOT/run/xpf"
    : > "$ROOT/run/xpf/early-input-handoff.done"
    PATH="$ROOT/bin:$PATH" "$ROOT/postinst" configure ""
    # The stub's distinct exit proves the error path fired (not held/stale).
    grep -Fq 'flock exit=2' "$FLOCK_LOG" || {
        echo "FAIL: flock stub did not take the error path (fixture vacuous)"; exit 1; }
    # Residual contract: every nonzero flock result reads live here (see
    # the bounded-modes comment at the gate) — so an error skips.
    if grep -Fq 'systemctl enable --now xpf-input-closed.service' "$SYSTEMCTL_LOG"; then
        echo "FAIL: postinst injected despite a flock error (residual contract: errors read live)"; exit 1
    fi
    if [ -e "$NFT_LOG" ] && grep -Fq 'nft list table' "$NFT_LOG"; then
        echo "FAIL: postinst probed kernel despite a flock error (marker must win first)"; exit 1
    fi
}

scenario_upgrade_never_starts_barrier() {
    build_hardened "1.0.0"
    patched_postinst_barrier_live
    stub_systemctl 1
    grep -Fq '10751-BARRIER-GATE' "$ROOT/postinst" || {
        echo "FAIL: barrier block missing from patched postinst; absence pin would be vacuous"; exit 1; }
    PATH="$ROOT/bin:$PATH" "$ROOT/postinst" configure "0.9.0"
    if [ -e "$SYSTEMCTL_LOG" ] && grep -Fq 'systemctl enable --now xpf-input-closed.service' "$SYSTEMCTL_LOG"; then
        echo "FAIL: upgrade injected the barrier into a possibly armed daemon"; exit 1
    fi
}

run_scenario first_install_configure_empty_seeds_layout
run_scenario first_install_seed_failure_falls_back_to_staged
run_scenario first_install_killed_during_seed_keeps_launch_links
run_scenario first_install_starts_barrier_without_daemon
run_scenario first_install_injects_barrier_with_active_unhanded_daemon
run_scenario first_install_skips_barrier_when_table_live
run_scenario first_install_injects_barrier_when_table_shell
run_scenario first_install_skips_barrier_with_live_handoff_marker
run_scenario first_install_injects_barrier_with_stale_handoff_marker
run_scenario first_install_proceeds_without_flock_binary
run_scenario first_install_skips_barrier_on_flock_error
run_scenario upgrade_never_starts_barrier
run_scenario recovers_cli_through_current
run_scenario recovers_helper_through_current
run_scenario leaves_existing_and_dangling_links
run_scenario new_managed_binary_stays_absent
run_scenario legacy_no_current_leaves_absent
run_scenario oldbug_repairs_to_staged_proves_nontautology
echo "ALL POSTINST SCENARIOS PASSED"
