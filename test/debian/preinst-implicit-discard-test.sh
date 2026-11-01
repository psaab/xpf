#!/bin/sh
# #18728 — prove debian/xpf.preinst refuses an `upgrade` (before unpack) when
# the RUNNING build would start discarding traffic: its `show system alarms`
# carries the pre-#18728 "has no terminal catch-all term; xpf accepts traffic
# matching no term" warning. Drives the REAL preinst `upgrade` case with the
# layout + lock redirected under a temp root and a fake old `cli`.
#
#   sh   test/debian/preinst-implicit-discard-test.sh
#   dash test/debian/preinst-implicit-discard-test.sh
set -e

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PREINST="${1:-$HERE/../../debian/xpf.preinst}"
[ -f "$PREINST" ] || { echo "preinst not found: $PREINST" >&2; exit 1; }

OLD_WARN='  WARNING: interface reth0 unit 80: filter output "bandwidth-output" has no terminal catch-all term; xpf accepts traffic matching no term (Junos stateless filters imply a final discard) — append an explicit final `term <name> { then discard; }` for Junos-style deny-by-default, or `then accept` to make permit-by-default explicit'
NEW_WARN='  WARNING: interface reth0 unit 80: filter output "bandwidth-output" has no terminal catch-all term; unmatched traffic is discarded (Junos default) and counted as implicit-discard; add a final `term <name> { then accept; }` if you intended permit-by-default (#18728)'
FAILED=0

# run <name> <want-rc> <cli-mode> [env assignment]
#   cli-mode: old | new | clean | down | absent
run() {
    name="$1"; want="$2"; mode="$3"; envset="${4:-}"
    ROOT=$(mktemp -d)
    sed \
      -e "s#^LOCK=.*#LOCK=$ROOT/run/xpf/upgrade.lock#" \
      -e "s#^STAGED=.*#STAGED=$ROOT/usr/local/share/xpf/staged#" \
      -e "s#^SBIN=.*#SBIN=$ROOT/usr/local/sbin#" \
      -e "s#^VERSIONS=.*#VERSIONS=$ROOT/var/lib/xpf/versions#" \
      -e "s#mkdir -p /run/xpf#mkdir -p $ROOT/run/xpf#g" \
      -e "s#chmod 0750 /run/xpf#chmod 0750 $ROOT/run/xpf#g" \
      "$PREINST" > "$ROOT/preinst"
    chmod +x "$ROOT/preinst"
    mkdir -p "$ROOT/usr/local/sbin" "$ROOT/usr/local/share/xpf/staged"
    case "$mode" in
        absent) ;;
        down)
            printf '#!/bin/sh\necho "error: cannot connect to xpfd" >&2\nexit 1\n' > "$ROOT/usr/local/sbin/cli"
            chmod +x "$ROOT/usr/local/sbin/cli" ;;
        *)
            case "$mode" in
                old) body="1 active alarm(s):
$OLD_WARN" ;;
                new) body="1 active alarm(s):
$NEW_WARN" ;;
                clean) body="No alarms currently active" ;;
            esac
            {
                echo '#!/bin/sh'
                echo '[ "$1" = "-c" ] && [ "$2" = "show system alarms" ] || exit 9'
                echo "cat <<'ALARMS'"
                echo "$body"
                echo "ALARMS"
            } > "$ROOT/usr/local/sbin/cli"
            chmod +x "$ROOT/usr/local/sbin/cli" ;;
    esac
    set +e
    if [ -n "$envset" ]; then
        env "$envset" "$ROOT/preinst" upgrade 0.9.0 > "$ROOT/out" 2>&1
    else
        "$ROOT/preinst" upgrade 0.9.0 > "$ROOT/out" 2>&1
    fi
    rc=$?
    set -e
    ok=1
    if [ "$want" = 0 ] && [ "$rc" -ne 0 ]; then ok=0; fi
    if [ "$want" != 0 ] && [ "$rc" -eq 0 ]; then ok=0; fi
    if [ "$want" != 0 ]; then
        grep -q 'refusing to upgrade (#18728)' "$ROOT/out" || ok=0
        grep -q 'bandwidth-output' "$ROOT/out" || ok=0
        grep -q 'XPF_UPGRADE_ACCEPT_IMPLICIT_DISCARD=1' "$ROOT/out" || ok=0
        # Refused BEFORE the #1964 snapshot: nothing created under versions/.
        [ ! -e "$ROOT/var/lib/xpf/versions" ] || ok=0
    fi
    if [ "$ok" = 1 ]; then
        echo "PASS $name"
    else
        echo "FAIL $name (rc=$rc want=$want)"; sed 's/^/    /' "$ROOT/out"
        FAILED=$((FAILED + 1))
    fi
    rm -rf "$ROOT"
}

run refuses_old_build_with_catchall_less_filter 1 old
run override_allows_upgrade 0 old XPF_UPGRADE_ACCEPT_IMPLICIT_DISCARD=1
run running_build_already_discards_allows 0 new
run clean_alarms_allow 0 clean
run unreachable_daemon_proceeds 0 down
run no_cli_proceeds 0 absent

# install (fresh) never runs the gate.
ROOT=$(mktemp -d)
sed -e "s#^SBIN=.*#SBIN=$ROOT/sbin#" "$PREINST" > "$ROOT/preinst"
mkdir -p "$ROOT/sbin"
printf '#!/bin/sh\necho "  WARNING: x has no terminal catch-all term; xpf accepts traffic matching no term"\n' > "$ROOT/sbin/cli"
chmod +x "$ROOT/preinst" "$ROOT/sbin/cli"
if sh "$ROOT/preinst" install >/dev/null 2>&1; then echo "PASS install_skips_gate"; else echo "FAIL install_skips_gate"; FAILED=$((FAILED + 1)); fi
rm -rf "$ROOT"

if [ "$FAILED" -ne 0 ]; then
    echo "preinst-implicit-discard-test: $FAILED failed"
    exit 1
fi
echo "preinst-implicit-discard-test: all passed"
