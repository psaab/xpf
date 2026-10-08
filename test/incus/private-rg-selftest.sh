#!/usr/bin/env bash
# Hermetic regression tests for test-private-rg.sh (#12211).
# No Incus, cluster, systemd journal, or network.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
# shellcheck source=test/incus/private-rg-lib.sh
source "${SCRIPT_DIR}/private-rg-lib.sh"

PASS=0
FAIL=0
ok() { echo "PASS: $1"; PASS=$((PASS + 1)); }
bad() { echo "FAIL: $1" >&2; FAIL=$((FAIL + 1)); }

WORK=$(mktemp -d "${TMPDIR:-/tmp}/private-rg-selftest.XXXXXX")
trap 'rm -rf "$WORK"' EXIT
FAKE_JOURNAL="$WORK/journal.tsv"
FAKE_CLI_CALLS="$WORK/cli-calls"
: > "$FAKE_JOURNAL"
: > "$FAKE_CLI_CALLS"
FAKE_INVOCATION_ID=run-current
FAKE_FW0_CONFIG="$WORK/fw0.conf"
FAKE_FW1_CONFIG="$WORK/fw1.conf"

# Fake only the live boundary used by private-rg-lib.sh. It requires the
# systemd invocation selector and filters retained records exactly as the
# live query should: current xpfd invocation only, never the previous one.
incus() {
	local node command invocation_id text seq
	[[ "$1" == exec ]] || return 90
	shift
	node="$1"
	shift
	[[ "$1" == -- ]] || return 91
	shift
	command="$1"
	shift
	case "$command" in
	systemctl)
		[[ " $* " == *" InvocationID "* ]] || return 92
		printf '%s\n' "$FAKE_INVOCATION_ID"
		;;
	journalctl)
		[[ " $* " == *" -u xpfd "* ]] || return 93
		[[ " $* " == *" _SYSTEMD_INVOCATION_ID=$FAKE_INVOCATION_ID "* ]] || return 94
		[[ " $* " != *" -n "* ]] || return 95
		while IFS=$'\t' read -r seq invocation_id text; do
			[[ -n "$seq" ]] || continue
			[[ "$invocation_id" == "$FAKE_INVOCATION_ID" ]] && printf '%s\n' "$text"
		done < "$FAKE_JOURNAL"
		;;
	cli)
		printf '%s\n' "$node" >> "$FAKE_CLI_CALLS"
		case "$node" in
		fw0) cat "$FAKE_FW0_CONFIG" ;;
		fw1) cat "$FAKE_FW1_CONFIG" ;;
		*) return 96 ;;
		esac
		;;
	*)
		echo "unexpected fake incus command: $command $*" >&2
		return 97
		;;
	esac
}

# In-window positive controls prove one captured invocation log can drive both
# the start and MASTER predicates without racing a second invocation lookup.
printf '1\t%s\tvrrp: instance starting\n2\t%s\tvrrp: state change to MASTER\n' \
	"$FAKE_INVOCATION_ID" "$FAKE_INVOCATION_ID" > "$FAKE_JOURNAL"
if current_log=$(privrg_xpfd_journal fw0) &&
   privrg_log_has_vrrp_start "$current_log" &&
   privrg_log_has_vrrp_master "$current_log"; then
	ok "in-window current-invocation VRRP start and MASTER are detected"
else
	bad "in-window current-invocation VRRP start and MASTER are detected"
fi

# A 151-entry invocation fixture puts the start event outside the old -n 100
# tail. The legacy query misses it; the invocation-scoped unbounded query
# detects it without depending on a small retained-log window.
: > "$FAKE_JOURNAL"
printf '1\t%s\tvrrp: instance starting\n' "$FAKE_INVOCATION_ID" >> "$FAKE_JOURNAL"
for seq in $(seq 2 151); do
	printf '%s\t%s\tcurrent invocation retained filler %s\n' \
		"$seq" "$FAKE_INVOCATION_ID" "$seq" >> "$FAKE_JOURNAL"
done
legacy_tail=$(tail -n 100 "$FAKE_JOURNAL")
if ! printf '%s\n' "$legacy_tail" | grep -q 'vrrp: instance starting' &&
   current_log=$(privrg_xpfd_journal fw0) &&
   privrg_log_has_vrrp_start "$current_log"; then
	ok "scrolled-out VRRP start is invisible to old tail but detected in current invocation"
else
	bad "scrolled-out VRRP start is invisible to old tail but detected in current invocation"
fi

# A prior xpfd systemd invocation can have VRRP start entries while the
# current invocation has none; old entries must not fail the absence cell.
printf '1\trun-previous\tvrrp: instance starting\n2\t%s\txpfd started without VRRP\n' \
	"$FAKE_INVOCATION_ID" > "$FAKE_JOURNAL"
if current_log=$(privrg_xpfd_journal fw0) &&
   ! privrg_log_has_vrrp_start "$current_log" &&
   ! privrg_log_has_vrrp_master "$current_log"; then
	ok "previous-invocation-only VRRP records do not affect current-invocation cells"
else
	bad "previous-invocation-only VRRP records do not affect current-invocation cells"
fi

# Capture interfaces come from the node0 RETH parent declarations, not the
# unrelated fab0 member or hardcoded interfaces.
userspace_conf="$ROOT/docs/ha-cluster-userspace.conf"
legacy_conf="$ROOT/docs/ha-cluster.conf"
if [[ "$(privrg_reth_member "$userspace_conf" reth0)" == ge-0-0-2 &&
      "$(privrg_reth_member "$userspace_conf" reth1)" == ge-0-0-1 ]]; then
	ok "userspace WAN/LAN capture interfaces are the node0 RETH members"
else
	bad "userspace WAN/LAN capture interfaces are the node0 RETH members"
fi
if [[ "$(privrg_reth_member "$legacy_conf" reth0)" == ge-0-0-3 &&
      "$(privrg_reth_member "$legacy_conf" reth1)" == ge-0-0-1 ]]; then
	ok "legacy WAN/LAN capture interfaces are the node0 RETH members"
else
	bad "legacy WAN/LAN capture interfaces are the node0 RETH members"
fi

# Snapshot and restore a tracked conf in an isolated git repo. Both the
# byte-identical comparison and git's tracked-file dirty check must flip RED
# for the temporary edit and return GREEN after restoring the saved bytes.
mkdir -p "$WORK/git"
cp "$userspace_conf" "$WORK/git/ha-cluster.conf"
git -C "$WORK/git" init -q
git -C "$WORK/git" config user.name selftest
git -C "$WORK/git" config user.email selftest@example.invalid
git -C "$WORK/git" add ha-cluster.conf
git -C "$WORK/git" commit -qm baseline
conf="$WORK/git/ha-cluster.conf"
snapshot="$WORK/config.snapshot"
if privrg_snapshot_conf "$conf" "$snapshot"; then
	printf '\n# transient private-RG selftest mutation\n' >> "$conf"
	if ! privrg_conf_byte_identical "$conf" "$snapshot" &&
	   ! (cd "$WORK/git" && privrg_conf_git_clean ha-cluster.conf); then
		privrg_restore_conf "$conf" "$snapshot"
		if privrg_conf_byte_identical "$conf" "$snapshot" &&
		   (cd "$WORK/git" && privrg_conf_git_clean ha-cluster.conf) &&
	   git -C "$WORK/git" diff --quiet -- ha-cluster.conf; then
			ok "snapshot restore returns tracked conf to byte-identical git-clean state"
		else
			bad "snapshot restore returns tracked conf to byte-identical git-clean state"
		fi
	else
		bad "snapshot detects a tracked conf mutation"
	fi
else
	bad "snapshot refuses missing config and saves present bytes"
fi

# Attestation reads each node's running configuration separately and rejects
# a split mode where only one node has the requested setting.
printf 'set chassis cluster node 0\nset chassis cluster node 1\n' > "$FAKE_FW0_CONFIG"
cp "$FAKE_FW0_CONFIG" "$FAKE_FW1_CONFIG"
: > "$FAKE_CLI_CALLS"
if privrg_assert_both_running_modes fw0 fw1 private &&
   [[ "$(wc -l < "$FAKE_CLI_CALLS")" -eq 2 ]]; then
	ok "running private-RG mode is attested on both nodes"
else
	bad "running private-RG mode is attested on both nodes"
fi
printf 'set chassis cluster no-private-rg-election\n' > "$FAKE_FW0_CONFIG"
cp "$FAKE_FW0_CONFIG" "$FAKE_FW1_CONFIG"
if privrg_assert_both_running_modes fw0 fw1 legacy; then
	ok "running legacy VRRP mode is attested on both nodes"
else
	bad "running legacy VRRP mode is attested on both nodes"
fi
: > "$FAKE_FW1_CONFIG"
if ! privrg_assert_both_running_modes fw0 fw1 legacy 2>"$WORK/split.err" &&
   grep -q "fw1" "$WORK/split.err"; then
	ok "split running modes fail the two-node attestation"
else
	bad "split running modes fail the two-node attestation"
fi

echo "----------------------------------------"
echo "private-rg selftest: $PASS passed, $FAIL failed"
[[ "$FAIL" -eq 0 ]]
