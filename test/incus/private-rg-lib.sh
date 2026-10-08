#!/usr/bin/env bash
# shellcheck shell=bash
#
# Shared helpers for test-private-rg.sh (#12211). Sourced, never executed.
#
# The three defects this file exists for:
#  1. The full cycle ran `sed -i` on the TRACKED canonical conf and left it
#     dirty (legacy `no-private-rg-election;` appended) on success AND abort,
#     with no restore trap or byte-identical assert.
#  2. The VRRP presence/absence cells read an UNSCOPED `journalctl -n 100`
#     window: the absence cell passed when the start line scrolled out, and
#     the presence twin redded on the same scroll-out.
#  3. The no-multicast capture watched hardcoded `ge-0-0-1`/`ge-0-0-0`, but
#     neither canonical conf has a data-plane `ge-0/0/0` (it is the fab0
#     fabric member); the WAN RETH member differs per cluster env.
#
# All live-node access goes through `incus`, which the hermetic selftest
# (test/incus/private-rg-selftest.sh) replaces with a fixture. No direct
# network, cluster, or journal access here beyond that one seam.

# privrg_snapshot_conf <conf> <snapshot>
#   Copy <conf> byte-for-byte to <snapshot>. Refuses a missing source rather
#   than snapshotting emptiness.
privrg_snapshot_conf() {
	local conf="$1" snapshot="$2"
	if [[ ! -f "$conf" ]]; then
		echo "privrg: refusing to snapshot missing conf: $conf" >&2
		return 1
	fi
	cp -p "$conf" "$snapshot"
}

# privrg_restore_conf <conf> <snapshot>
#   Restore <conf> from a snapshot taken by privrg_snapshot_conf. Refuses an
#   empty snapshot path rather than truncating the conf.
privrg_restore_conf() {
	local conf="$1" snapshot="$2"
	if [[ -z "$snapshot" || ! -f "$snapshot" ]]; then
		echo "privrg: refusing to restore $conf from missing snapshot" >&2
		return 1
	fi
	cp -p "$snapshot" "$conf"
}

# privrg_conf_byte_identical <conf> <snapshot>
#   rc 0 iff <conf> is byte-identical to <snapshot> (cmp, silent).
privrg_conf_byte_identical() {
	cmp -s "$1" "$2"
}

# privrg_conf_git_clean <conf>
#   rc 0 iff <conf> has no modification vs HEAD. SKIPS (rc 2) when git is
#   unavailable, the file is outside a worktree, or the file is untracked —
#   callers must still enforce privrg_conf_byte_identical against the
#   snapshot in that case; a skip is never a pass.
privrg_conf_git_clean() {
	local conf="$1"
	command -v git >/dev/null 2>&1 || return 2
	git rev-parse --show-toplevel >/dev/null 2>&1 || return 2
	git ls-files --error-unmatch "$conf" >/dev/null 2>&1 || return 2
	git diff --quiet -- "$conf"
}

# privrg_reth_member <conf> <reth>
#   Echo the node0 physical member interface of reth0 (WAN) or reth1 (LAN),
#   as the kernel dash-name tcpdump needs (e.g. ge-0-0-2). The conf carries
#   slash-names (`ge-0/0/2`); both canonical confs spell node0 members that
#   way. rc 1 when the conf has no such member (never echo a guess).
privrg_reth_member() {
	local conf="$1" reth="$2" member
	member=$(awk -v reth="$reth" '
		$1 == "node1" { in_node1 = 1 }
		in_node1 { next }
		/^[[:space:]]*ge-[0-9/]+[[:space:]]*\{/ { iface = $1; next }
		$0 ~ "redundant-parent[[:space:]]+" reth "[;[:space:]]" {
			if (iface != "") { print iface; exit }
		}
	' "$conf")
	[[ -n "$member" ]] || return 1
	printf '%s\n' "${member//\//-}"
}

# privrg_xpfd_journal <node>
#   Echo the CURRENT xpfd systemd invocation's journal on <node>. The
#   _SYSTEMD_INVOCATION_ID selector excludes retained records from earlier
#   daemon invocations, while the unbounded journal query ensures an old
#   VRRP start line cannot scroll out. Refuses an empty/unreadable invocation
#   ID rather than falling back to a PID or unscoped read.
privrg_xpfd_journal() {
	local node="$1" invocation_id
	invocation_id=$(incus exec "$node" -- systemctl show -p InvocationID --value xpfd 2>/dev/null) || return 1
	[[ -n "$invocation_id" ]] || return 1
	incus exec "$node" -- journalctl -u xpfd "_SYSTEMD_INVOCATION_ID=$invocation_id" --no-pager 2>/dev/null
}

# privrg_log_has_vrrp_start <journal-text>
#   rc 0 if one captured current-invocation log contains an instance start.
privrg_log_has_vrrp_start() {
	grep -q "vrrp: instance starting" <<<"$1"
}

# privrg_log_has_vrrp_master <journal-text>
#   rc 0 if one captured current-invocation log contains a MASTER transition.
privrg_log_has_vrrp_master() {
	grep -q "vrrp: state change.*MASTER" <<<"$1"
}
# privrg_assert_running_mode <node> <private|legacy>
#   Attest the config currently loaded by the node's active store. The
#   desired mode is explicit so neither phase can pass by observing the
#   previous phase's configuration.
privrg_assert_running_mode() {
	local node="$1" expected="$2" cfg
	cfg=$(incus exec "$node" -- cli -c "show configuration chassis cluster | display set" 2>/dev/null) || {
		echo "privrg: cannot read running chassis cluster config on $node" >&2
		return 1
	}
	[[ -n "$cfg" ]] || {
		echo "privrg: running chassis cluster config is empty on $node" >&2
		return 1
	}
	case "$expected" in
	private)
		if printf '%s\n' "$cfg" | grep -q "no-private-rg-election"; then
			echo "privrg: $node running config still disables private RG election" >&2
			return 1
		fi
		;;
	legacy)
		if ! printf '%s\n' "$cfg" | grep -q "no-private-rg-election"; then
			echo "privrg: $node running config does not disable private RG election" >&2
			return 1
		fi
		;;
	*)
		echo "privrg: invalid expected running mode: $expected" >&2
		return 2
		;;
	esac
}

# privrg_assert_both_running_modes <node0> <node1> <private|legacy>
privrg_assert_both_running_modes() {
	local node0="$1" node1="$2" expected="$3"
	privrg_assert_running_mode "$node0" "$expected" &&
		privrg_assert_running_mode "$node1" "$expected"
}
