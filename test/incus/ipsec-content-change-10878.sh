#!/usr/bin/env bash
# #10878 live regression: a same-name PSK + traffic-selector change must
# replace the established IKE/CHILD SAs and remove the old XFRM selectors.
# Run only under the isolated-cluster lock:
#   ./test/incus/with-cluster.sh '10878 IPsec content change' -- \
#       ./test/incus/ipsec-content-change-10878.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=test/incus/ipsec-9506-fixture.sh
source "${SCRIPT_DIR}/ipsec-9506-fixture.sh"

fix9506_require_lock || exit 2
fix9506_cluster_env

shape=v4_native
count=2
old_selector=10.0.61.0/24
new_selector=10.0.61.0/25
workdir="$(mktemp -d "${TMPDIR:-/tmp}/xpf-ipsec-10878.XXXXXX")"
chmod 0700 "$workdir"
fixture_active=0

cleanup() {
    local rc=$? cleanup_rc=0
    trap - EXIT
	if ((fixture_active)); then
		if fix9506_teardown "$count" "$workdir"; then
			:
		else
			cleanup_rc=$?
		fi
	fi
    rm -rf "$workdir"
    if ((cleanup_rc != 0)); then
        echo "10878: fixture teardown failed" >&2
        exit 1
    fi
    exit "$rc"
}
trap cleanup EXIT

append_selectors() {
    local set_file="$1" selector="$2" i vpn peer_ts
    for ((i = 0; i < count; i++)); do
        vpn="$(fix9506_vpn "$i")"
        peer_ts="$(fix9506_inner4 "$i")"
        printf 'set security ipsec vpn %s traffic-selector ts10878 local-ip %s\n' \
            "$vpn" "$selector"
        printf 'set security ipsec vpn %s traffic-selector ts10878 remote-ip %s\n' \
            "$vpn" "$peer_ts"
    done >>"$set_file"
}

wait_for_selectors() {
    local tag="$1" selector="$2" deadline node
    deadline=$(($(date +%s) + FIX9506_CONVERGE_TIMEOUT))
    while (( $(date +%s) < deadline )); do
        fix9506_probe_node "$FIX9506_NODE0" "$workdir" "${tag}-fw0"
        fix9506_probe_node "$FIX9506_NODE1" "$workdir" "${tag}-fw1"
        local ready=1
        for node in fw0 fw1; do
            if ! grep -Fq 'ESTABLISHED' "$workdir/${tag}-${node}-sas.txt" ||
                ! grep -Fq "$selector" "$workdir/${tag}-${node}-sas.txt" ||
                ! grep -Fq "$selector" "$workdir/${tag}-${node}-xfrm-policy.txt"; then
                ready=0
            fi
        done
        if ((ready)); then
            return 0
        fi
        sleep "$FIX9506_SA_POLL_INTERVAL"
    done
    echo "10878: timed out waiting for selector ${selector} on both firewalls" >&2
    for node in fw0 fw1; do
        for surface in sas xfrm-policy; do
            file="$workdir/${tag}-${node}-${surface}.txt"
            printf '\n--- %s ---\n' "$file" >&2
            cat "$file" >&2
        done
    done
    return 1
}

assert_old_spis_removed() {
    python3 - "$workdir/before-fw0-xfrm-state.txt" \
        "$workdir/after-fw0-xfrm-state.txt" "$FIX9506_FW_WAN4" \
        "$FIX9506_PEER_WAN4" "$workdir/before-fw1-xfrm-state.txt" \
        "$workdir/after-fw1-xfrm-state.txt" "$FIX9506_FW_LAN4" \
        "$FIX9506_PEER_LAN4" <<'PY'
import re
import sys


def tunnel_spis(path, endpoint_a, endpoint_b):
    text = open(path, encoding="utf-8").read()
    in_tunnel = False
    found = set()
    for line in text.splitlines():
        endpoints = re.search(r"\bsrc\s+(\S+)\s+dst\s+(\S+)", line)
        if endpoints:
            in_tunnel = set(endpoints.groups()) == {endpoint_a, endpoint_b}
        if in_tunnel:
            spi = re.search(r"\bspi\s+(0x[0-9a-fA-F]+)", line)
            if spi:
                found.add(spi.group(1).lower())
    return found


pairs = [
    ("fw0", sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]),
    ("fw1", sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8]),
]
for node, before_path, after_path, endpoint_a, endpoint_b in pairs:
    old = tunnel_spis(before_path, endpoint_a, endpoint_b)
    new = tunnel_spis(after_path, endpoint_a, endpoint_b)
    if len(old) < 2:
        raise SystemExit(f"10878: {node} baseline has fewer than two fixture ESP SPIs: {old}")
    if len(new) < 2:
        raise SystemExit(f"10878: {node} replacement has fewer than two fixture ESP SPIs: {new}")
    stale = old & new
    if stale:
        raise SystemExit(f"10878: {node} retained old fixture ESP SPI(s): {sorted(stale)}")
    print(f"10878: {node} old fixture ESP SPIs absent; replacement SPIs present")
PY
}

# Establish the old connection under its initial key, then load an explicit
# /24 proxy-ID through the normal CLI commit path so both the baseline and the
# change are same-name manager applies.
if fix9506_fixture_config_present || fix9506_peer_exists; then
    echo "10878: refusing to overwrite an existing #9506 fixture" >&2
    exit 2
fi
fix9506_require_nft
fix9506_record_parent_baseline "$workdir"
fix9506_rg_record "$workdir" >&2
fixture_active=1
rg2="$(fix9506_rg_primary "$FIX9506_NODE0" 2)"
if [[ "$rg2" != node1 ]]; then
    fix9506_rg_failover 2 1 >&2
fi
fix9506_wait_outer_paths "$shape"
fix9506_peer_up "$shape" "$count" "$workdir"
read -r set_file _ < <(fix9506_gen_config "$shape" "$count" "$workdir")
fix9506_commit_file "$FIX9506_NODE0" "$set_file" "setup-${shape}x${count}"
fix9506_install_inner_routes "$shape" "$count"
for ((i = 0; i < count; i++)); do
    half="$(fix9506_half "$i")"
    node="$FIX9506_NODE0"
    [[ "$half" == wan ]] || node="$FIX9506_NODE1"
    vpn="$(fix9506_vpn "$i")"
    if ! fix9506_remote "$node" "swanctl --list-sas | grep -Fq '$vpn:'"; then
        # The regression needs a known active old SA as its baseline. Start
        # the owner-side connection explicitly, then let converge verify it.
        fix9506_remote "$node" "timeout 30 swanctl --initiate --child '$vpn'" || \
            echo "10878: explicit baseline initiation for $vpn returned non-zero; checking convergence" >&2
    fi
done
fix9506_converge "$shape" "$count" "$workdir"
read -r set_file _ < <(fix9506_gen_config "$shape" "$count" "$workdir")
append_selectors "$set_file" "$old_selector"
fix9506_commit_file "$FIX9506_NODE0" "$set_file" baseline-10878
wait_for_selectors baseline "$old_selector"

# Record the established baseline on both nodes. The scoped SPI assertion
# below matches only the fixture's WAN/LAN outer endpoint pair.
fix9506_probe_node "$FIX9506_NODE0" "$workdir" before-fw0
fix9506_probe_node "$FIX9506_NODE1" "$workdir" before-fw1

# Update the remote peer first, then commit a same-name firewall config with
# both a rotated PSK and narrowed local selector.
FIX9506_PSK=xpf-9506-lab-psk-ROTATED-10878
FIX9506_LAN_TS="${new_selector},2001:559:8585:ef00::/64"
peer_conf="$(fix9506_peer_write_swanctl "$shape" "$count" "$workdir")"
sg incus-admin -c "incus file push $(printf '%q' "$peer_conf") $(printf '%q' "$FIX9506_PEER_REF")/etc/swanctl/conf.d/xpf-9506.conf"
fix9506_remote "$FIX9506_PEER_REF" 'swanctl --load-all' >/dev/null

read -r set_file _ < <(fix9506_gen_config "$shape" "$count" "$workdir")
append_selectors "$set_file" "$new_selector"
fix9506_commit_file "$FIX9506_NODE0" "$set_file" rotate-10878
wait_for_selectors after "$new_selector"

# The old /24 proxy-ID must be absent from both live strongSwan selectors and
# kernel policies after the replacement, not merely hidden by a new SA.
for node in fw0 fw1; do
    if grep -Fq "$old_selector" "$workdir/after-${node}-sas.txt" ||
        grep -Fq "$old_selector" "$workdir/after-${node}-xfrm-policy.txt"; then
        echo "10878: ${node} still exposes old selector ${old_selector}" >&2
        exit 1
    fi
done
assert_old_spis_removed

echo "10878: PASS — rotated PSK and narrowed selector replaced the live SAs; old SPIs and /24 selector are absent"
