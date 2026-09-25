#!/bin/sh
# #1964 — debian/xpf.postrm lifecycle test (remove/purge sbin cleanup,
# purge versions/ removal, downgrade cleanup). The postrm is shell, so it is
# tested in shell. Run:
#
#   sh   test/debian/postrm-test.sh
#   dash test/debian/postrm-test.sh
#
# It extracts the helper functions from debian/xpf.postrm, overrides the
# layout path vars to a temp root, and drives the case-branch bodies via a
# small re-implementation of the dispatch (the real case branches use the
# overridden vars through the sourced functions).
set -e

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
POSTRM="${1:-$HERE/../../debian/xpf.postrm}"
[ -f "$POSTRM" ] || { echo "postrm not found: $POSTRM" >&2; exit 1; }

# Run the REAL postrm with overridden absolute path vars by editing the
# script's var assignments to point under a temp ROOT. We do this by
# generating a patched copy per scenario.
patched_postrm() {
    sed \
      -e "s#^STAGED=.*#STAGED=$ROOT/usr/local/share/xpf/staged#" \
      -e "s#^SBIN=.*#SBIN=$ROOT/usr/local/sbin#" \
      -e "s#^VERSIONS=.*#VERSIONS=$ROOT/var/lib/xpf/versions#" \
      -e "s#^CURRENT=.*#CURRENT=\"\$VERSIONS/current\"#" \
      -e "s#^STAGED_GEN=.*#STAGED_GEN=$ROOT/var/lib/xpf/staged-gen#" \
      -e "s#^DROPIN=.*#DROPIN=$ROOT/etc/systemd/system/xpfd.service.d/10-xpf-version.conf#" \
      -e "s#^TRANSIT_IPV4_SYSCTL=.*#TRANSIT_IPV4_SYSCTL=$ROOT/proc/sys/net/ipv4/ip_forward#" \
      -e "s#^TRANSIT_IPV6_SYSCTL=.*#TRANSIT_IPV6_SYSCTL=$ROOT/proc/sys/net/ipv6/conf/all/forwarding#" \
      -e "s#\\[ -d /run/systemd/system \\]#false#" \
      "$POSTRM" > "$ROOT/postrm"
    chmod +x "$ROOT/postrm"
}

run_scenario() {
    name="$1"
    ROOT=$(mktemp -d)
    STAGED="$ROOT/usr/local/share/xpf/staged"
    SBIN="$ROOT/usr/local/sbin"
    VERSIONS="$ROOT/var/lib/xpf/versions"
    CURRENT="$VERSIONS/current"
    STAGED_GEN="$ROOT/var/lib/xpf/staged-gen"
    DROPIN="$ROOT/etc/systemd/system/xpfd.service.d/10-xpf-version.conf"
    TRANSIT_IPV4_SYSCTL="$ROOT/proc/sys/net/ipv4/ip_forward"
    TRANSIT_IPV6_SYSCTL="$ROOT/proc/sys/net/ipv6/conf/all/forwarding"
    mkdir -p "$(dirname "$TRANSIT_IPV4_SYSCTL")" "$(dirname "$TRANSIT_IPV6_SYSCTL")"
    printf '0\n' > "$TRANSIT_IPV4_SYSCTL"
    printf '0\n' > "$TRANSIT_IPV6_SYSCTL"
    BINS="xpfd cli xpf-userspace-dp xpf-day0-config"
    patched_postrm
    "scenario_$name"
    rm -rf "$ROOT"
    echo "PASS $name"
}

# Build a hardened layout: versions/<ver>/<bin>, current -> <ver>, sbin ->
# versions/current/<bin>, drop-in present. xpfd in the version dir + staged
# both respond to seed-runtime --capability-check.
build_hardened() {
    ver="$1"
    mkdir -p "$STAGED" "$SBIN" "$VERSIONS/$ver" "$(dirname "$DROPIN")"
    make_xpfd() {
        cat > "$1" <<'EOF'
#!/bin/sh
if [ "$1" = seed-runtime ] && [ "$2" = --capability-check ]; then
    echo "seed-runtime supported"; exit 0
fi
if [ "$1" = transit-barrier ] && [ "$2" = remove ]; then
    echo "transit barrier removed"; exit 0
fi
[ "$1" = version ] && { echo "xpfd VER (commit x, built y)"; exit 0; }
echo "unknown command" >&2; exit 1
EOF
        sed -i "s/VER/$ver/" "$1"
        chmod +x "$1"
    }
    make_xpfd "$VERSIONS/$ver/xpfd"
    make_xpfd "$STAGED/xpfd"
    for b in cli xpf-userspace-dp xpf-day0-config; do
        echo "bin-$b" > "$VERSIONS/$ver/$b"; chmod +x "$VERSIONS/$ver/$b"
        echo "bin-$b" > "$STAGED/$b"; chmod +x "$STAGED/$b"
    done
    ln -sf "$ver" "$CURRENT"
    for b in $BINS; do
        ln -sf "$CURRENT/$b" "$SBIN/$b"
    done
    echo "[Service]" > "$DROPIN"
    # #1981 staged-generation tree (a published generation + current-gen).
    mkdir -p "$STAGED_GEN/00000000000000000001-aabbccddeeff0011"
    echo "bin" > "$STAGED_GEN/00000000000000000001-aabbccddeeff0011/xpfd"
    ln -sf "00000000000000000001-aabbccddeeff0011" "$STAGED_GEN/current-gen"
}

# Replace staged/xpfd with a PRE-#1964 binary (no seed-runtime support).
make_staged_prehardened() {
    cat > "$STAGED/xpfd" <<'EOF'
#!/bin/sh
[ "$1" = version ] && { echo "xpfd 0.9.0 (commit x)"; exit 0; }
echo "xpfd: unknown command \"$1\"" >&2; exit 1
EOF
    chmod +x "$STAGED/xpfd"
}

# remove leaves versions/ but removes the through-current sbin links AND the
# runtime unit drop-in (#1967).
scenario_remove_keeps_versions() {
    build_hardened "1.0.0"
    "$ROOT/postrm" remove
    for b in $BINS; do
        [ -L "$SBIN/$b" ] && { echo "FAIL: sbin $b not removed"; exit 1; } || true
    done
    [ -d "$VERSIONS/1.0.0" ] || { echo "FAIL: versions/ removed on remove"; exit 1; }
    [ -L "$CURRENT" ] || { echo "FAIL: current removed on remove"; exit 1; }
    # #1967: the versioned-runtime unit drop-in must be removed on remove.
    [ -e "$DROPIN" ] && { echo "FAIL: drop-in not removed on remove"; exit 1; } || true
    # The empty .service.d dir should be rmdir'd too.
    [ -d "$(dirname "$DROPIN")" ] && { echo "FAIL: empty .service.d not rmdir'd on remove"; exit 1; } || true
    [ "$(cat "$TRANSIT_IPV4_SYSCTL")" = 1 ] || { echo "FAIL: IPv4 forwarding sysctl not restored on remove"; exit 1; }
    [ "$(cat "$TRANSIT_IPV6_SYSCTL")" = 1 ] || { echo "FAIL: IPv6 forwarding sysctl not restored on remove"; exit 1; }
}

scenario_remove_barrier_failure_keeps_sysctls_closed() {
    build_hardened "1.0.0"
    cat > "$VERSIONS/1.0.0/xpfd" <<'EOF'
#!/bin/sh
exit 1
EOF
    chmod +x "$VERSIONS/1.0.0/xpfd"
    "$ROOT/postrm" remove
    [ "$(cat "$TRANSIT_IPV4_SYSCTL")" = 0 ] || { echo "FAIL: IPv4 forwarding opened after failed barrier removal"; exit 1; }
    [ "$(cat "$TRANSIT_IPV6_SYSCTL")" = 0 ] || { echo "FAIL: IPv6 forwarding opened after failed barrier removal"; exit 1; }
}

# purge removes the through-current sbin links, the runtime drop-in (#1967),
# the versions/ tree, AND the #1981 staged-gen/ tree.
scenario_purge_removes_versions() {
    build_hardened "1.0.0"
    "$ROOT/postrm" purge
    for b in $BINS; do
        [ -L "$SBIN/$b" ] && { echo "FAIL: sbin $b not removed"; exit 1; } || true
    done
    [ -e "$VERSIONS" ] && { echo "FAIL: versions/ not removed on purge"; exit 1; } || true
    [ -e "$STAGED_GEN" ] && { echo "FAIL: staged-gen/ not removed on purge"; exit 1; } || true
    [ -e "$DROPIN" ] && { echo "FAIL: drop-in not removed on purge"; exit 1; } || true
}

# #1981 B-P6: a downgrade to a package BELOW the staged-gen floor (0.0.4200) —
# including a post-#1964 (>= 0.0.4104) but pre-#1981 package, which keeps the
# #1964 versioned-runtime layout intact — must remove staged-gen/.
scenario_downgrade_removes_staged_gen_below_floor() {
    build_hardened "1.0.0"
    # Post-#1964 but pre-#1981 ($2 in [4104, 4200)): the #1964 layout survives,
    # but staged-gen/ must be removed.
    "$ROOT/postrm" upgrade "0.0.4150"
    [ -e "$STAGED_GEN" ] && { echo "FAIL: staged-gen/ not removed on a pre-#1981 downgrade"; exit 1; } || true
    # The #1964 layout is untouched (above the 0.0.4104 floor).
    [ -L "$CURRENT" ] || { echo "FAIL: #1964 current wrongly deleted on a post-#1964 downgrade"; exit 1; }
    [ -e "$DROPIN" ] || { echo "FAIL: #1964 drop-in wrongly removed on a post-#1964 downgrade"; exit 1; }
}

# A hardened->hardened downgrade at or above the staged-gen floor keeps
# staged-gen/ (the incoming package manages it).
scenario_downgrade_keeps_staged_gen_at_floor() {
    build_hardened "1.0.0"
    "$ROOT/postrm" upgrade "0.0.4200"
    [ -d "$STAGED_GEN" ] || { echo "FAIL: staged-gen/ removed on an at-floor (>=#1981) downgrade"; exit 1; }
}

# An empty/unparsable $2 leaves staged-gen/ intact (safe-on-ambiguity).
scenario_downgrade_empty_version_keeps_staged_gen() {
    build_hardened "1.0.0"
    "$ROOT/postrm" upgrade ""
    [ -d "$STAGED_GEN" ] || { echo "FAIL: staged-gen/ removed on empty incoming version"; exit 1; }
}

# remove with a NON-empty .service.d (a foreign drop-in) removes only OUR
# drop-in and leaves the dir + foreign file intact (#1967 rmdir is best-effort).
scenario_remove_keeps_foreign_dropin() {
    build_hardened "1.0.0"
    foreign="$(dirname "$DROPIN")/99-operator.conf"
    echo "[Service]" > "$foreign"
    "$ROOT/postrm" remove
    [ -e "$DROPIN" ] && { echo "FAIL: our drop-in not removed"; exit 1; } || true
    [ -e "$foreign" ] || { echo "FAIL: foreign drop-in removed"; exit 1; }
    [ -d "$(dirname "$DROPIN")" ] || { echo "FAIL: non-empty .service.d rmdir'd"; exit 1; }
}

# remove on a legacy/never-seeded host (no drop-in present) is a clean no-op
# for the drop-in step (#1967 — must be safe if absent).
scenario_remove_no_dropin_ok() {
    mkdir -p "$STAGED" "$SBIN"
    for b in $BINS; do echo x > "$STAGED/$b"; ln -sf "$STAGED/$b" "$SBIN/$b"; done
    # No DROPIN, no versions/.
    "$ROOT/postrm" remove
    for b in $BINS; do
        [ -L "$SBIN/$b" ] && { echo "FAIL: legacy sbin $b not removed"; exit 1; } || true
    done
}

# downgrade to a pre-hardened package: drop-in removed, sbin repointed to
# staged, current deleted.
scenario_downgrade_to_prehardened() {
    build_hardened "0.0.5000+gaaaa"
    make_staged_prehardened
    # $2 is a pre-#1964 version (< the 0.0.4104 floor) -> genuine downgrade.
    "$ROOT/postrm" upgrade "0.0.4000+gbbbb"
    [ -e "$DROPIN" ] && { echo "FAIL: drop-in not removed"; exit 1; } || true
    # The .d dir must be rmdir'd when empty (exercises dirname "$DROPIN").
    [ -e "$(dirname "$DROPIN")" ] && { echo "FAIL: empty drop-in .d dir not removed"; exit 1; } || true
    for b in $BINS; do
        tgt=$(readlink "$SBIN/$b")
        [ "$tgt" = "$STAGED/$b" ] || { echo "FAIL: sbin $b -> $tgt, want staged"; exit 1; }
    done
    [ -e "$CURRENT" ] && { echo "FAIL: current not deleted"; exit 1; } || true
}

# upgrade to a newer hardened package ($2 >= floor): layout untouched.
scenario_upgrade_to_hardened_noop() {
    build_hardened "0.0.5000+gaaaa"
    # $2 is a post-#1964 version (>= the 0.0.4104 floor) -> NOT a downgrade.
    "$ROOT/postrm" upgrade "0.0.5500+gbbbb"
    [ -e "$DROPIN" ] || { echo "FAIL: drop-in removed on hardened->hardened"; exit 1; }
    for b in $BINS; do
        tgt=$(readlink "$SBIN/$b")
        [ "$tgt" = "$CURRENT/$b" ] || { echo "FAIL: sbin $b repointed on hardened->hardened ($tgt)"; exit 1; }
    done
    [ -L "$CURRENT" ] || { echo "FAIL: current deleted on hardened->hardened"; exit 1; }
}

# operator-repointed sbin link is NOT removed (not owned).
scenario_remove_skips_foreign_link() {
    build_hardened "1.0.0"
    cat > "$ROOT/foreign-xpfd" <<EOF
#!/bin/sh
echo called > "$ROOT/foreign-called"
EOF
    chmod +x "$ROOT/foreign-xpfd"
    ln -sf "$ROOT/foreign-xpfd" "$SBIN/xpfd"
    "$ROOT/postrm" remove
    [ "$(readlink "$SBIN/xpfd")" = "$ROOT/foreign-xpfd" ] || { echo "FAIL: removed a foreign sbin link"; exit 1; }
    [ ! -e "$ROOT/foreign-called" ] || { echo "FAIL: invoked an operator-repointed xpfd"; exit 1; }
}

# legacy direct-to-staged sbin links are still removed (back-compat).
scenario_remove_legacy_links() {
    mkdir -p "$STAGED" "$SBIN"
    for b in $BINS; do echo x > "$STAGED/$b"; ln -sf "$STAGED/$b" "$SBIN/$b"; done
    "$ROOT/postrm" remove
    for b in $BINS; do
        [ -L "$SBIN/$b" ] && { echo "FAIL: legacy sbin $b not removed"; exit 1; } || true
    done
}

# downgrade must NOT clobber a foreign/operator-repointed sbin link (Codex).
scenario_downgrade_skips_foreign_link() {
    build_hardened "0.0.5000+gaaaa"
    make_staged_prehardened
    # Operator repointed xpfd elsewhere; the others stay package-owned.
    ln -sf "/opt/custom/xpfd" "$SBIN/xpfd"
    # $2 < floor -> genuine pre-#1964 downgrade.
    "$ROOT/postrm" upgrade "0.0.4000+gbbbb"
    [ "$(readlink "$SBIN/xpfd")" = "/opt/custom/xpfd" ] || { echo "FAIL: downgrade clobbered a foreign sbin link"; exit 1; }
    # The owned ones are repointed to staged.
    for b in cli xpf-userspace-dp xpf-day0-config; do
        [ "$(readlink "$SBIN/$b")" = "$STAGED/$b" ] || { echo "FAIL: owned sbin $b not repointed to staged"; exit 1; }
    done
}

# === #1985 regression scenarios: downgrade decision is EXEC-FREE + version-keyed ===

# CORE #1985 BUG CASE: a real UPGRADE ($2 >= the 0.0.4104 floor) whose staged
# xpfd cannot EXEC (dynamic-link error / corruption / arch mismatch) must NOT
# be misclassified as a pre-#1964 downgrade. The version arg says "upgrade",
# so the layout MUST survive regardless of the staged binary's health. The old
# exec-probe gate tore the runtime down here.
scenario_upgrade_nonexecable_staged_survives() {
    build_hardened "0.0.5000+gaaaa"
    # Staged xpfd present and STILL marked executable, but unrunnable: a file
    # with a bogus ELF magic + the exec bit set exec()s to ENOEXEC ("Exec
    # format error") (Copilot). This is the true #1985 failure mode -- a
    # binary the OLD code probed with `[ -x ] && "$STAGED/xpfd" ...` that
    # PASSES the -x test but fails to actually run (dynamic-link error /
    # corruption / arch mismatch). The version-floor gate never execs it;
    # only $2 matters.
    printf '\177ELF\001bogus-unrunnable' > "$STAGED/xpfd"
    chmod +x "$STAGED/xpfd"
    [ -x "$STAGED/xpfd" ] || { echo "FAIL: precondition: staged xpfd should be -x (executable bit set)"; exit 1; }
    "$ROOT/postrm" upgrade "0.0.5500+gbbbb"
    [ -e "$DROPIN" ] || { echo "FAIL: drop-in removed on upgrade w/ non-execable staged xpfd"; exit 1; }
    [ -e "$(dirname "$DROPIN")" ] || { echo "FAIL: .service.d removed on upgrade w/ non-execable staged xpfd"; exit 1; }
    [ -L "$CURRENT" ] || { echo "FAIL: current deleted on upgrade w/ non-execable staged xpfd"; exit 1; }
    for b in $BINS; do
        tgt=$(readlink "$SBIN/$b")
        [ "$tgt" = "$CURRENT/$b" ] || { echo "FAIL: sbin $b repointed on upgrade ($tgt) w/ non-execable staged xpfd"; exit 1; }
    done
}

# A hardened->hardened DOWNGRADE ($2 lower but still >= floor) where the staged
# xpfd cannot exec also keeps the layout: $2 is above the floor, so it is not a
# pre-#1964 downgrade.
scenario_downgrade_hardened_nonexecable_survives() {
    build_hardened "0.0.5500+gaaaa"
    # Executable bit set but unrunnable (bogus ELF magic -> ENOEXEC), same as
    # the upgrade scenario (Copilot): exercises the real "executable but
    # cannot exec" case, not the [ -x ] short-circuit.
    printf '\177ELF\001bogus-unrunnable' > "$STAGED/xpfd"
    chmod +x "$STAGED/xpfd"
    "$ROOT/postrm" upgrade "0.0.5000+gbbbb"
    [ -e "$DROPIN" ] || { echo "FAIL: drop-in removed on hardened->hardened downgrade w/ non-execable staged xpfd"; exit 1; }
    [ -L "$CURRENT" ] || { echo "FAIL: current deleted on hardened->hardened downgrade w/ non-execable staged xpfd"; exit 1; }
}

# A genuine pre-#1964 downgrade is detected by $2 < floor even when the staged
# binary EXECs fine -- the gate no longer trusts (or runs) exec at all. The
# staged xpfd here is a perfectly runnable pre-hardened binary; the layout must
# still be torn down because $2 is below the floor.
scenario_downgrade_below_floor_execable_tears_down() {
    build_hardened "0.0.5000+gaaaa"
    make_staged_prehardened   # runnable pre-hardened binary
    [ -x "$STAGED/xpfd" ] || { echo "FAIL: precondition: staged xpfd should be execable"; exit 1; }
    "$ROOT/postrm" upgrade "0.0.4000+gbbbb"
    [ -e "$DROPIN" ] && { echo "FAIL: drop-in not removed on below-floor downgrade"; exit 1; } || true
    [ -e "$(dirname "$DROPIN")" ] && { echo "FAIL: empty .service.d not removed on below-floor downgrade"; exit 1; } || true
    for b in $BINS; do
        tgt=$(readlink "$SBIN/$b")
        [ "$tgt" = "$STAGED/$b" ] || { echo "FAIL: sbin $b -> $tgt, want staged on below-floor downgrade"; exit 1; }
    done
    [ -e "$CURRENT" ] && { echo "FAIL: current not deleted on below-floor downgrade"; exit 1; } || true
}

# Boundary: $2 exactly AT the floor is the first hardened version -> NOT a
# pre-#1964 downgrade -> layout survives (the comparison is strictly less-than).
scenario_upgrade_at_floor_survives() {
    build_hardened "0.0.5000+gaaaa"
    "$ROOT/postrm" upgrade "0.0.4104"
    [ -e "$DROPIN" ] || { echo "FAIL: drop-in removed at exactly the floor version"; exit 1; }
    [ -L "$CURRENT" ] || { echo "FAIL: current deleted at exactly the floor version"; exit 1; }
}

# Empty $2 (should not happen on a normal upgrade, but be defensive): SAFE
# default is to leave the layout intact, never tear down.
scenario_upgrade_empty_version_survives() {
    build_hardened "0.0.5000+gaaaa"
    "$ROOT/postrm" upgrade ""
    [ -e "$DROPIN" ] || { echo "FAIL: drop-in removed on empty \$2"; exit 1; }
    [ -L "$CURRENT" ] || { echo "FAIL: current deleted on empty \$2"; exit 1; }
}

# Unparsable $2: dpkg --compare-versions errors (status 2); SAFE default is to
# leave the layout intact (only a confirmed lt comparison tears down).
scenario_upgrade_unparsable_version_survives() {
    build_hardened "0.0.5000+gaaaa"
    "$ROOT/postrm" upgrade "not a version!!"
    [ -e "$DROPIN" ] || { echo "FAIL: drop-in removed on unparsable \$2"; exit 1; }
    [ -L "$CURRENT" ] || { echo "FAIL: current deleted on unparsable \$2"; exit 1; }
}

# Below-floor $2 but NO hardened layout present (legacy/never-seeded host, no
# versions/current): the AND guard short-circuits -> clean no-op under set -e.
scenario_downgrade_below_floor_no_layout_noop() {
    mkdir -p "$STAGED" "$SBIN"
    for b in $BINS; do echo x > "$STAGED/$b"; ln -sf "$STAGED/$b" "$SBIN/$b"; done
    "$ROOT/postrm" upgrade "0.0.4000+gbbbb"
    for b in $BINS; do
        [ "$(readlink "$SBIN/$b")" = "$STAGED/$b" ] || { echo "FAIL: legacy sbin $b disturbed on below-floor no-layout upgrade"; exit 1; }
    done
}

# === #1997 regression: crash mid-teardown -> postrm RERUN completes drop-in cleanup ===

# Reconstruct the EXACT on-disk state left by a kill mid-downgrade-teardown,
# AFTER `rm versions/current` but BEFORE the drop-in was removed: current is
# gone, the drop-in still exists, and sbin is already repointed to staged (the
# repoint ran first). This is the orphan window the bug left behind. A postrm
# RERUN of the same pre-#1964 downgrade MUST finish the job: remove the
# orphaned 10-xpf-version.conf (and rmdir the empty .service.d), without
# tripping over the now-absent current. Before #1997 the rerun saw current
# gone, took the false branch on the versions/current-only guard, and left the
# orphan drop-in pinning a stale ExecStart.
build_crashed_midteardown() {
    # Start from a full pre-#1964 downgrade source state, then simulate the
    # crash: sbin already repointed to staged, current already removed, drop-in
    # still present.
    build_hardened "0.0.5000+gaaaa"
    make_staged_prehardened
    # Step 1 of the teardown already ran: sbin points at staged.
    for b in $BINS; do ln -sf "$STAGED/$b" "$SBIN/$b"; done
    # Step "rm current" already ran: current is gone.
    rm -f "$CURRENT"
    # The drop-in removal had NOT run yet: orphan still on disk.
    [ -e "$DROPIN" ] || { echo "FAIL: precondition: drop-in should still exist before rerun"; exit 1; }
    [ -e "$CURRENT" ] && { echo "FAIL: precondition: current should already be gone"; exit 1; } || true
}

scenario_rerun_after_crash_removes_orphan_dropin() {
    build_crashed_midteardown
    # Rerun the SAME pre-#1964 downgrade postrm.
    "$ROOT/postrm" upgrade "0.0.4000+gbbbb"
    [ -e "$DROPIN" ] && { echo "FAIL: rerun did not remove the orphan drop-in"; exit 1; } || true
    [ -e "$(dirname "$DROPIN")" ] && { echo "FAIL: rerun did not rmdir the empty .service.d"; exit 1; } || true
    # sbin stays repointed to staged (idempotent).
    for b in $BINS; do
        [ "$(readlink "$SBIN/$b")" = "$STAGED/$b" ] || { echo "FAIL: sbin $b not at staged after rerun"; exit 1; }
    done
    # current stays gone.
    [ -e "$CURRENT" ] && { echo "FAIL: current resurrected on rerun"; exit 1; } || true
}

# NON-TAUTOLOGY PROOF: synthesize the PRE-#1997 (buggy) postrm by patching the
# fixed script back to the old behavior — guard on versions/current ALONE and
# delete current BEFORE the drop-in removal — then run the SAME rerun scenario
# and assert it LEAVES the orphan. This proves scenario_rerun_after_crash_*
# discriminates the fix: it FAILS on the old order/guard and PASSES on the new
# one. If a future edit makes the new guard accidentally equivalent to the old
# one, this scenario starts failing (the old script would no longer leave an
# orphan), flagging the regression.
patched_postrm_oldbug() {
    # Reproduce the pre-#1997 two defects on top of the patched temp postrm:
    #   1. drop the `|| [ -e "$DROPIN" ]` arm from the presence guard, AND
    #   2. restore the old step order (rm current, THEN remove_runtime_dropin),
    # by replacing the whole teardown if-body with the historical sequence.
    # We do it with awk so the rewrite is robust to comment churn: between the
    # guard `if incoming_predates_hardened_layout` line and its closing `fi`,
    # emit the legacy body. SYNTH count is exported via a sentinel line so the
    # caller can FAIL LOUD if the pattern matched nothing (else the meta-test
    # would be tautological — synthesizing the SAME fixed script and "proving"
    # nothing). The guard-line match tolerates trailing whitespace after the
    # line-continuation backslash (Copilot): `&&[[:space:]]*\\[[:space:]]*$`
    # rather than anchoring `\\$` hard at EOL, so a stray trailing space does
    # not silently skip the rewrite.
    awk '
      BEGIN { in_block = 0; synth = 0 }
      /^[[:space:]]*if incoming_predates_hardened_layout "\$2" &&[[:space:]]*\\[[:space:]]*$/ {
        print "        if incoming_predates_hardened_layout \"$2\" && \\"
        print "           { [ -L \"$CURRENT\" ] || [ -e \"$CURRENT\" ]; }; then"
        print "            repoint_owned_sbin_to_staged"
        print "            rm -f \"$CURRENT\""
        print "            remove_runtime_dropin"
        print "        fi"
        in_block = 1
        synth = 1
        next
      }
      in_block == 1 {
        # Skip original body lines until the closing `fi` of the if-block.
        if ($0 ~ /^[[:space:]]*fi[[:space:]]*$/) { in_block = 0 }
        next
      }
      { print }
      END { print "# __OLDBUG_SYNTH__=" synth > "/dev/stderr" }
    ' "$ROOT/postrm" > "$ROOT/postrm.oldbug" 2> "$ROOT/postrm.oldbug.synth"
    chmod +x "$ROOT/postrm.oldbug"
}

scenario_oldbug_leaves_orphan_proves_nontautology() {
    build_crashed_midteardown
    patched_postrm_oldbug
    # The awk MUST have matched the guard line and rewritten the block. If it
    # synthesized nothing (pattern drift / trailing-ws regression), the
    # "old-bug" script would be identical to the fixed one and the proof would
    # be vacuous — fail loud.
    grep -q '__OLDBUG_SYNTH__=1' "$ROOT/postrm.oldbug.synth" || {
        echo "FAIL(non-tautology): awk did not match the guard line — no old-bug script was synthesized (the proof would be vacuous)"; exit 1; }
    # And the synthesized script must actually DIFFER from the fixed one.
    cmp -s "$ROOT/postrm" "$ROOT/postrm.oldbug" && {
        echo "FAIL(non-tautology): synthesized old-bug postrm is identical to the fixed postrm"; exit 1; } || true
    # Sanity: the synthesized old script must be valid shell.
    sh -n "$ROOT/postrm.oldbug" || { echo "FAIL: synthesized old-bug postrm has a syntax error"; exit 1; }
    "$ROOT/postrm.oldbug" upgrade "0.0.4000+gbbbb"
    # The OLD behavior: rerun sees current gone, guard is false, drop-in stays.
    [ -e "$DROPIN" ] || { echo "FAIL(non-tautology): old-bug postrm UNEXPECTEDLY removed the orphan drop-in — the rerun test would not discriminate the fix"; exit 1; }
}

run_scenario remove_keeps_versions
run_scenario remove_barrier_failure_keeps_sysctls_closed
run_scenario purge_removes_versions
run_scenario remove_keeps_foreign_dropin
run_scenario remove_no_dropin_ok
run_scenario downgrade_to_prehardened
run_scenario downgrade_skips_foreign_link
run_scenario upgrade_to_hardened_noop
run_scenario upgrade_nonexecable_staged_survives
run_scenario downgrade_hardened_nonexecable_survives
run_scenario downgrade_below_floor_execable_tears_down
run_scenario upgrade_at_floor_survives
run_scenario upgrade_empty_version_survives
run_scenario upgrade_unparsable_version_survives
run_scenario downgrade_below_floor_no_layout_noop
run_scenario remove_skips_foreign_link
run_scenario remove_legacy_links
run_scenario downgrade_removes_staged_gen_below_floor
run_scenario downgrade_keeps_staged_gen_at_floor
run_scenario downgrade_empty_version_keeps_staged_gen
run_scenario rerun_after_crash_removes_orphan_dropin
run_scenario oldbug_leaves_orphan_proves_nontautology
echo "ALL POSTRM SCENARIOS PASSED"
