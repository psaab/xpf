#!/usr/bin/env bash
# #9506 fixture: strongSwan peer + route-based xfrmi/stN + live SAs.
#
# Builds the lab scope docs/log/9506-s5.md names as missing: a dedicated
# strongSwan peer endpoint/network, matching PSK/proposals/traffic selectors,
# route-based xfrmi/stN on both firewalls, and live SA/divert verification.
#
# Topology (all on the isolated loss userspace cluster):
#   peer loss:xpf-ipsec-peer-9506, dual-homed:
#     eth0 SR-IOV mlx0 vlan 50  172.16.50.202 / 2001:559:8585:50::202 (WAN half)
#     eth1 SR-IOV mlx1 vlan 3667 10.0.61.201 / 2001:559:8585:ef00::201 (LAN half)
#     dummy9506 inner subnets per tunnel i:
#       192.168.(100+i).1/24 + 2001:db8:9506:<i>::1/64
#   fw side: N tunnels (N even), even i WAN-anchored (RG1/node0),
#   odd i LAN-anchored (RG2/node1 after fixture pins RG2 to node1).
#   bind-interface st9506.<i> (if_id 9506<<16|(i+1)), zone vpn9506,
#   static inner routes via stN, lan<->vpn9506 policies.
#   Peer is policy-based (no xfrmi); fw side is route-based. TS narrow on
#   the peer (unique peer-inner per tunnel, shared LAN remote), 0/0 both
#   families on the fw default render; IKEv2 narrows to the peer offer.
#
# Usage (all mutating commands require the with-cluster lock):
#   ./test/incus/with-cluster.sh '9506 fixture' -- \
#       ./test/incus/ipsec-9506-fixture.sh up <shape> <count>
#   ./test/incus/with-cluster.sh '9506 fixture' -- \
#       ./test/incus/ipsec-9506-fixture.sh down
#   ./test/incus/ipsec-9506-fixture.sh gen-config <shape> <count> <dir>
#   shapes: v4_native v4_nat_t v6_native v6_nat_t; count: even, 2..32.
#
# Sourced as a library by test/incus/t12-g2-9506.sh; executed directly it
# runs the CLI below. Sourcing has no side effects.
set -uo pipefail

FIX9506_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIX9506_ROOT="$(cd "${FIX9506_SCRIPT_DIR}/../.." && pwd)"

# --- Tunables (environment overrides; never commit a real PSK) ---
FIX9506_PEER_NAME="${FIX9506_PEER_NAME:-xpf-ipsec-peer-9506}"
FIX9506_PEER_IMAGE="${FIX9506_PEER_IMAGE:-images:debian/trixie}"
FIX9506_WAN_PF="${FIX9506_WAN_PF:-mlx0}"
FIX9506_WAN_VLAN="${FIX9506_WAN_VLAN:-50}"
FIX9506_LAN_PF="${FIX9506_LAN_PF:-mlx1}"
FIX9506_LAN_VLAN="${FIX9506_LAN_VLAN:-3667}"
FIX9506_PEER_WAN4="${FIX9506_PEER_WAN4:-172.16.50.202}"
FIX9506_PEER_WAN6="${FIX9506_PEER_WAN6:-2001:559:8585:50::202}"
FIX9506_PEER_LAN4="${FIX9506_PEER_LAN4:-10.0.61.201}"
FIX9506_PEER_LAN6="${FIX9506_PEER_LAN6:-2001:559:8585:ef00::201}"
FIX9506_FW_WAN4="${FIX9506_FW_WAN4:-172.16.50.8}"
FIX9506_FW_WAN6="${FIX9506_FW_WAN6:-2001:559:8585:50::8}"
FIX9506_FW_LAN4="${FIX9506_FW_LAN4:-10.0.61.1}"
FIX9506_FW_LAN6="${FIX9506_FW_LAN6:-2001:559:8585:ef00::1}"
FIX9506_INNER4_BASE="${FIX9506_INNER4_BASE:-192.168.100.0}"
FIX9506_INNER4_OCTET="${FIX9506_INNER4_OCTET:-100}"
FIX9506_INNER6_PREFIX="${FIX9506_INNER6_PREFIX:-2001:db8:9506}"
FIX9506_LAN_TS="${FIX9506_LAN_TS:-10.0.61.0/24,2001:559:8585:ef00::/64}"
FIX9506_DENY_TARGET4="${FIX9506_DENY_TARGET4:-10.0.61.250/32}"
FIX9506_DENY4_NAME="${FIX9506_DENY4_NAME:-addr9506-deny4}"
FIX9506_DENY6_NAME="${FIX9506_DENY6_NAME:-addr9506-deny6}"
FIX9506_DENY_TARGET6="${FIX9506_DENY_TARGET6:-2001:559:8585:ef00::250/128}"
# LAB-ONLY PSK for the isolated fixture; override via env, never logged.
FIX9506_PSK="${XPF_9506_IPSEC_PSK:-xpf-9506-lab-psk-CHANGE-ME}"
FIX9506_IKE_PROP="${FIX9506_IKE_PROP:-aes128-sha256-modp2048}"
FIX9506_ESP_PROP="${FIX9506_ESP_PROP:-aes128-sha256-modp2048}"
FIX9506_ZONE="${FIX9506_ZONE:-vpn9506}"
FIX9506_ST_BASE="${FIX9506_ST_BASE:-st9506}"
FIX9506_IKE_PROPOSAL="${FIX9506_IKE_PROPOSAL:-ike9506}"
FIX9506_IKE_POLICY="${FIX9506_IKE_POLICY:-pol9506}"
FIX9506_ESP_PROPOSAL="${FIX9506_ESP_PROPOSAL:-esp9506}"
FIX9506_CONVERGE_TIMEOUT="${FIX9506_CONVERGE_TIMEOUT:-300}"
FIX9506_SA_POLL_INTERVAL="${FIX9506_SA_POLL_INTERVAL:-5}"

fix9506_cluster_env() {
    # shellcheck source=test/incus/loss-userspace-cluster.env
    source "${FIX9506_SCRIPT_DIR}/loss-userspace-cluster.env"
    FIX9506_NODE0="${FW0:-${INCUS_REMOTE:-loss}:xpf-userspace-fw0}"
    FIX9506_NODE1="${FW1:-${INCUS_REMOTE:-loss}:xpf-userspace-fw1}"
    FIX9506_PEER_REF="${INCUS_REMOTE:-loss}:${FIX9506_PEER_NAME}"
    FIX9506_LAN_REF="${INCUS_REMOTE:-loss}:${LAN_HOST:-cluster-userspace-host}"
}

# remote <node> <command>: same transport as t12-g2-9506.sh (group-gated
# incus, stdin-independent so a two-node read cannot silently sample one).
fix9506_remote() {
    local node="$1" command="$2"
    sg incus-admin -c "incus exec -n $(printf '%q' "$node") -- bash -lc $(printf '%q' "$command")"
}

fix9506_incus() {
    sg incus-admin -c "incus $*"
}

fix9506_require_lock() {
    if [[ -z "${XPF_CLUSTER_LOCK_HELD:-}" ]]; then
        echo "fix9506: refusing cluster mutation without the with-cluster lock" >&2
        return 2
    fi
}

fix9506_valid_shape() {
    case "$1" in
    v4_native|v4_nat_t|v6_native|v6_nat_t) return 0 ;;
    *) return 1 ;;
    esac
}

fix9506_valid_count() {
    [[ "$1" =~ ^[0-9]+$ ]] || return 1
    (( $1 >= 2 && $1 <= 32 && $1 % 2 == 0 )) || return 1
    return 0
}

# Half of tunnel i: even -> wan (RG1/node0), odd -> lan (RG2/node1).
fix9506_half() { (( $1 % 2 == 0 )) && printf 'wan' || printf 'lan'; }

fix9506_outer_addrs() {
    # fix9506_outer_addrs <shape> <half>: prints "fw_outer peer_outer".
    local shape="$1" half="$2" fw peer
    case "${shape}_${half}" in
    v4_*_wan) fw="$FIX9506_FW_WAN4"; peer="$FIX9506_PEER_WAN4" ;;
    v4_*_lan) fw="$FIX9506_FW_LAN4"; peer="$FIX9506_PEER_LAN4" ;;
    v6_*_wan) fw="$FIX9506_FW_WAN6"; peer="$FIX9506_PEER_WAN6" ;;
    v6_*_lan) fw="$FIX9506_FW_LAN6"; peer="$FIX9506_PEER_LAN6" ;;
    *) echo "fix9506: bad shape/half ${shape}/${half}" >&2; return 1 ;;
    esac
    printf '%s %s\n' "$fw" "$peer"
}

fix9506_shape_encap() { [[ "$1" == *nat_t ]] && printf 'force' || printf 'auto'; }

fix9506_inner4() { printf '192.168.%d.0/24' "$((FIX9506_INNER4_OCTET + $1))"; }
fix9506_inner4_ip() { printf '192.168.%d.1' "$((FIX9506_INNER4_OCTET + $1))"; }
fix9506_inner6() { printf '%s:%x::/64' "$FIX9506_INNER6_PREFIX" "$1"; }
fix9506_inner6_ip() { printf '%s:%x::1' "$FIX9506_INNER6_PREFIX" "$1"; }
fix9506_stn() { printf '%s.%d' "$FIX9506_ST_BASE" "$1"; }
fix9506_vpn() { printf 'vpn9506t%d' "$1"; }
fix9506_gw() { printf 'gw9506t%d' "$1"; }

# --- Peer lifecycle ---

fix9506_peer_exists() {
    fix9506_cluster_env
    sg incus-admin -c "incus info $(printf '%q' "$FIX9506_PEER_REF")" >/dev/null 2>&1
}

fix9506_require_nft() {
    local node
    for node in "$FIX9506_NODE0" "$FIX9506_NODE1"; do
        if ! fix9506_remote "$node" 'command -v nft >/dev/null 2>&1'; then
            echo "fix9506: missing nft on $node; repair with apt-get install -y nftables or recreate the VM" >&2
            return 1
        fi
    done
}
fix9506_shape_family() {
    case "$1" in
    v4_native|v4_nat_t) printf 'v4' ;;
    v6_native|v6_nat_t) printf 'v6' ;;
    *) return 1 ;;
    esac
}

fix9506_shape_inner_ts() {
    # fix9506_shape_inner_ts <shape> <index> <side>: side=local|remote.
    local shape="$1" index="$2" side="$3"
    if [[ "$(fix9506_shape_family "$shape")" == v4 ]]; then
        if [[ "$side" == local ]]; then
            fix9506_inner4 "$index"
        else
            printf '%s\n' "${FIX9506_LAN_TS%%,*}"
        fi
    else
        if [[ "$side" == local ]]; then
            fix9506_inner6 "$index"
        else
            printf '%s\n' "${FIX9506_LAN_TS#*,}"
        fi
    fi
}


fix9506_peer_write_swanctl() {
    # fix9506_peer_write_swanctl <shape> <count>: render the peer
    # swanctl file locally; caller pushes it. Prints path. PSK is
    # interpolated here only; callers must never log the file.
    local shape="$1" count="$2" dir="$3"
    local out="$dir/peer-9506-swanctl.conf"
    {
        printf 'connections {\n'
        local i half peer local_ts remote_ts
        for ((i = 0; i < count; i++)); do
            half="$(fix9506_half "$i")"
            read -r _fw peer <<<"$(fix9506_outer_addrs "$shape" "$half")"
            local_ts="$(fix9506_shape_inner_ts "$shape" "$i" local)"
            remote_ts="$(fix9506_shape_inner_ts "$shape" "$i" remote)"
            printf '  peer9506t%d {\n' "$i"
            printf '    version = 2\n'
            printf '    local_addrs = %s\n' "$peer"
            printf '    remote_addrs = %%any\n'
            if [[ "$(fix9506_shape_encap "$shape")" == force ]]; then
                printf '    encap = yes\n'
            fi
            printf '    proposals = %s\n' "$FIX9506_IKE_PROP"
            printf '    local {\n      auth = psk\n      id = "@peer9506t%d"\n    }\n' "$i"
            printf '    remote {\n      auth = psk\n      id = "@xpf9506t%d"\n    }\n' "$i"
            printf '    children {\n      ts%d {\n' "$i"
            printf '        local_ts = %s\n' "$local_ts"
            printf '        remote_ts = %s\n' "$remote_ts"
            printf '        esp_proposals = %s\n' "$FIX9506_ESP_PROP"
            printf '      }\n    }\n'
            printf '  }\n'
        done
        printf '}\n\nsecrets {\n  ike-9506-global {\n    secret = "%s"\n  }\n}\n' "$FIX9506_PSK"
    } >"$out"
    printf '%s\n' "$out"
}

fix9506_peer_up() {
    # fix9506_peer_up <shape> <count> <workdir>
    local shape="$1" count="$2" workdir="$3"
    fix9506_require_lock || return 2
    fix9506_cluster_env
    if ! sg incus-admin -c "incus info $(printf '%q' "$FIX9506_PEER_REF")" >/dev/null 2>&1; then
        sg incus-admin -c "incus init $(printf '%q' "$FIX9506_PEER_IMAGE") $(printf '%q' "$FIX9506_PEER_REF")" || return 1
    fi
    if ! sg incus-admin -c "incus config device get $(printf '%q' "$FIX9506_PEER_REF") eth0 nictype" >/dev/null 2>&1; then
        sg incus-admin -c "incus config device add $(printf '%q' "$FIX9506_PEER_REF") eth0 nic nictype=sriov parent=$(printf '%q' "$FIX9506_WAN_PF") vlan=$(printf '%q' "$FIX9506_WAN_VLAN")" || return 1
    fi
    if ! sg incus-admin -c "incus config device get $(printf '%q' "$FIX9506_PEER_REF") eth1 nictype" >/dev/null 2>&1; then
        sg incus-admin -c "incus config device add $(printf '%q' "$FIX9506_PEER_REF") eth1 nic nictype=sriov parent=$(printf '%q' "$FIX9506_LAN_PF") vlan=$(printf '%q' "$FIX9506_LAN_VLAN")" || return 1
    fi
    sg incus-admin -c "incus start $(printf '%q' "$FIX9506_PEER_REF")" >/dev/null 2>&1 || true
    local n
    for n in $(seq 1 30); do
        fix9506_remote "$FIX9506_PEER_REF" 'ip link show eth0 && ip link show eth1' >/dev/null 2>&1 && break
        sleep 2
    done
    fix9506_remote "$FIX9506_PEER_REF" 'ip link show eth0 && ip link show eth1' >/dev/null 2>&1 || {
        echo "fix9506: peer NICs never appeared" >&2
        return 1
    }
    fix9506_remote "$FIX9506_PEER_REF" 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq strongswan strongswan-swanctl iproute2 iperf3 iputils-ping python3 tcpdump' || return 1
    # Static outer addresses (pinned units, same pattern as mouse-target).
    fix9506_remote "$FIX9506_PEER_REF" "cat > /etc/systemd/system/peer9506-addr.service <<'UNIT'
[Unit]
Description=#9506 fixture peer outer addresses
After=network.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ip addr replace ${FIX9506_PEER_WAN4}/24 dev eth0
ExecStart=/sbin/ip -6 addr replace ${FIX9506_PEER_WAN6}/64 dev eth0
ExecStart=/sbin/ip addr replace ${FIX9506_PEER_LAN4}/24 dev eth1
ExecStart=/sbin/ip -6 addr replace ${FIX9506_PEER_LAN6}/64 dev eth1
ExecStart=/sbin/ip link set eth0 up
ExecStart=/sbin/ip link set eth1 up
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload && systemctl enable --now peer9506-addr.service" || return 1
    # A recreated SR-IOV peer gets a new MAC; remove stale entries left by a
    # prior fixture instance before charon initiates either half.
    local node
    for node in "$FIX9506_NODE0" "$FIX9506_NODE1"; do
        fix9506_remote "$node" \
            "ip neigh flush to $FIX9506_PEER_WAN4 >/dev/null 2>&1 || true; ip -6 neigh flush to $FIX9506_PEER_WAN6 >/dev/null 2>&1 || true; ip neigh flush to $FIX9506_PEER_LAN4 >/dev/null 2>&1 || true; ip -6 neigh flush to $FIX9506_PEER_LAN6 >/dev/null 2>&1 || true" ||
            return 1
    done
    fix9506_remote "$FIX9506_PEER_REF" \
        "ip neigh flush to $FIX9506_FW_WAN4 >/dev/null 2>&1 || true; ip -6 neigh flush to $FIX9506_FW_WAN6 >/dev/null 2>&1 || true; ip neigh flush to $FIX9506_FW_LAN4 >/dev/null 2>&1 || true; ip -6 neigh flush to $FIX9506_FW_LAN6 >/dev/null 2>&1 || true" ||
        return 1
    # Inner subnets on a dummy; forwarding on.
    {
        printf 'ip link add dummy9506 type dummy 2>/dev/null || true\n'
        local i
        for ((i = 0; i < count; i++)); do
            printf 'ip addr replace %s/24 dev dummy9506\n' "$(fix9506_inner4_ip "$i")"
            printf 'ip -6 addr replace %s/64 dev dummy9506\n' "$(fix9506_inner6_ip "$i")"
        done
        printf 'ip link set dummy9506 up\n'
        printf 'sysctl -w net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1 >/dev/null\n'
        printf 'ip rule add pref 50 from %s/32 lookup main 2>/dev/null || true\n' "$FIX9506_PEER_WAN4"
        printf 'ip rule add pref 50 from %s/32 lookup main 2>/dev/null || true\n' "$FIX9506_PEER_LAN4"
        printf 'ip -6 rule add pref 50 from %s/128 lookup main 2>/dev/null || true\n' "$FIX9506_PEER_WAN6"
        printf 'ip -6 rule add pref 50 from %s/128 lookup main 2>/dev/null || true\n' "$FIX9506_PEER_LAN6"
    } >"$workdir/peer-net.sh"
    sg incus-admin -c "incus file push $(printf '%q' "$workdir/peer-net.sh") $(printf '%q' "$FIX9506_PEER_REF")/root/peer-net.sh" || return 1
    fix9506_remote "$FIX9506_PEER_REF" 'bash /root/peer-net.sh' || return 1
    local swanctl
    swanctl="$(fix9506_peer_write_swanctl "$shape" "$count" "$workdir")"
    sg incus-admin -c "incus file push $(printf '%q' "$swanctl") $(printf '%q' "$FIX9506_PEER_REF")/etc/swanctl/conf.d/xpf-9506.conf" || return 1
    fix9506_remote "$FIX9506_PEER_REF" 'systemctl enable --now strongswan && swanctl --load-all 2>&1 | tail -5' || return 1
    printf 'fix9506: peer %s up (%s x%d)\n' "$FIX9506_PEER_REF" "$shape" "$count" >&2
}

fix9506_peer_down() {
    fix9506_require_lock || return 2
    fix9506_cluster_env
    if sg incus-admin -c "incus info $(printf '%q' "$FIX9506_PEER_REF")" >/dev/null 2>&1; then
        sg incus-admin -c "incus delete --force $(printf '%q' "$FIX9506_PEER_REF")" || return 1
    fi
    printf 'fix9506: peer %s deleted\n' "$FIX9506_PEER_REF" >&2
}

# --- xpf config generation ---

fix9506_gen_config() {
    # fix9506_gen_config <shape> <count> <dir>: writes fixture.set (+
    # fixture-del.set). Pure local; no lock needed.
    local shape="$1" count="$2" dir="$3"
    fix9506_valid_shape "$shape" || { echo "fix9506: bad shape $shape" >&2; return 1; }
    fix9506_valid_count "$count" || { echo "fix9506: bad count $count" >&2; return 1; }
    mkdir -p "$dir"
    local set="$dir/fixture-9506.set" del="$dir/fixture-9506-del.set"
    {
        printf 'set security ike proposal %s authentication-method pre-shared-keys\n' "$FIX9506_IKE_PROPOSAL"
        printf 'set security ike proposal %s encryption-algorithm aes-128-cbc\n' "$FIX9506_IKE_PROPOSAL"
        printf 'set security ike proposal %s authentication-algorithm sha-256\n' "$FIX9506_IKE_PROPOSAL"
        printf 'set security ike proposal %s dh-group group14\n' "$FIX9506_IKE_PROPOSAL"
        printf 'set security ike policy %s mode main\n' "$FIX9506_IKE_POLICY"
        printf 'set security ike policy %s proposals %s\n' "$FIX9506_IKE_POLICY" "$FIX9506_IKE_PROPOSAL"
        printf 'set security ipsec proposal %s protocol esp\n' "$FIX9506_ESP_PROPOSAL"
        printf 'set security ipsec proposal %s encryption-algorithm aes-128-cbc\n' "$FIX9506_ESP_PROPOSAL"
        printf 'set security ipsec proposal %s authentication-algorithm hmac-sha-256-128\n' "$FIX9506_ESP_PROPOSAL"
        printf 'set security ipsec proposal %s dh-group group14\n' "$FIX9506_ESP_PROPOSAL"
        local i half fw peer extif gw vpn stn
        for ((i = 0; i < count; i++)); do
            half="$(fix9506_half "$i")"
            read -r fw peer <<<"$(fix9506_outer_addrs "$shape" "$half")"
            if [[ "$half" == wan ]]; then extif="reth0.50"; else extif="reth1"; fi
            gw="$(fix9506_gw "$i")"; vpn="$(fix9506_vpn "$i")"; stn="$(fix9506_stn "$i")"
            printf 'set security ipsec gateway %s address %s\n' "$gw" "$peer"
            printf 'set security ipsec gateway %s ike-policy %s\n' "$gw" "$FIX9506_IKE_POLICY"
            printf 'set security ipsec gateway %s external-interface %s\n' "$gw" "$extif"
            printf 'set security ipsec gateway %s version v2-only\n' "$gw"
            if [[ "$(fix9506_shape_encap "$shape")" == force ]]; then
                printf 'set security ipsec gateway %s nat-traversal force\n' "$gw"
            fi
            printf 'set security ipsec gateway %s local-identity hostname xpf9506t%d\n' "$gw" "$i"
            printf 'set security ipsec gateway %s remote-identity hostname peer9506t%d\n' "$gw" "$i"
            printf 'set security ipsec vpn %s gateway %s\n' "$vpn" "$gw"
            printf 'set security ipsec vpn %s bind-interface %s\n' "$vpn" "$stn"
            printf 'set security ipsec vpn %s ipsec-policy %s\n' "$vpn" "$FIX9506_ESP_PROPOSAL"
            printf 'set security ipsec vpn %s establish-tunnels immediately\n' "$vpn"
            printf 'set security zones security-zone %s interfaces %s\n' "$FIX9506_ZONE" "$stn"
            if [[ "$(fix9506_shape_family "$shape")" == v4 ]]; then
                printf 'set routing-options static route %s next-hop %s\n' "$(fix9506_inner4 "$i")" "$stn"
            else
                printf 'set routing-options static route %s next-hop %s\n' "$(fix9506_inner6 "$i")" "$stn"
            fi
        done
        # Fresh PSK line on every gen (value never logged by callers).
        # Zone policies: permit both directions + a leading deny probe for
        # denied-ingress evidence (dst TEST-NET-2, never routed back).
        printf 'set security address-book global address %s %s\n' "$FIX9506_DENY4_NAME" "$FIX9506_DENY_TARGET4"
        printf 'set security address-book global address %s %s\n' "$FIX9506_DENY6_NAME" "$FIX9506_DENY_TARGET6"
        local z="$FIX9506_ZONE"
        printf 'set security policies from-zone lan to-zone %s policy p9506-out match source-address any\n' "$z"
        printf 'set security policies from-zone lan to-zone %s policy p9506-out match destination-address any\n' "$z"
        printf 'set security policies from-zone lan to-zone %s policy p9506-out match application any\n' "$z"
        printf 'set security policies from-zone lan to-zone %s policy p9506-out then permit\n' "$z"
        printf 'set security policies from-zone lan to-zone %s policy p9506-out then count\n' "$z"
        printf 'set security policies from-zone lan to-zone %s policy p9506-out then log session-init\n' "$z"
        printf 'set security policies from-zone %s to-zone lan policy p9506-deny-probe match source-address any\n' "$z"
        printf 'set security policies from-zone %s to-zone lan policy p9506-deny-probe match destination-address %s\n' "$z" "$FIX9506_DENY4_NAME"
        printf 'set security policies from-zone %s to-zone lan policy p9506-deny-probe match destination-address %s\n' "$z" "$FIX9506_DENY6_NAME"
        printf 'set security policies from-zone %s to-zone lan policy p9506-deny-probe match application any\n' "$z"
        printf 'set security policies from-zone %s to-zone lan policy p9506-deny-probe then deny count\n' "$z"
        printf 'set security policies from-zone %s to-zone lan policy p9506-deny-probe then deny log session-init\n' "$z"
        printf 'set security policies from-zone %s to-zone lan policy p9506-deny-probe then deny\n' "$z"
        printf 'set security policies from-zone %s to-zone lan policy p9506-in match source-address any\n' "$z"
        printf 'set security policies from-zone %s to-zone lan policy p9506-in match destination-address any\n' "$z"
        printf 'set security policies from-zone %s to-zone lan policy p9506-in match application any\n' "$z"
        printf 'set security policies from-zone %s to-zone lan policy p9506-in then permit\n' "$z"
        printf 'set security policies from-zone %s to-zone lan policy p9506-in then count\n' "$z"
        printf 'set security policies from-zone %s to-zone lan policy p9506-in then log session-init\n' "$z"
        # IKE to charon must pass host-inbound on both outer zones. reth1
        # carries a per-interface stanza that REPLACES the zone stanza, so
        # the token goes there (not zone level) for LAN; WAN is zone level.
        printf 'set security zones security-zone wan host-inbound-traffic system-services ike\n'
        printf 'set security zones security-zone lan interfaces reth1 host-inbound-traffic system-services ike\n'
    } >"$set"
    # The PSK line is appended separately so gen callers can audit line
    # counts without the secret adjacent to them in diffs.
    printf 'set security ike policy %s pre-shared-key ascii-text "%s"\n' \
        "$FIX9506_IKE_POLICY" "$FIX9506_PSK" >>"$set"
    {
        # Deletes in dependency-reverse: policies, zone members, routes,
        # vpns, gateways, proposals, host-inbound tokens.
        local i
        printf 'delete security policies from-zone lan to-zone %s\n' "$FIX9506_ZONE"
        printf 'delete security policies from-zone %s to-zone lan\n' "$FIX9506_ZONE"
        printf 'delete security address-book global address %s\n' "$FIX9506_DENY4_NAME"
        printf 'delete security address-book global address %s\n' "$FIX9506_DENY6_NAME"
        printf 'delete security zones security-zone %s\n' "$FIX9506_ZONE"
        for ((i = 0; i < count; i++)); do
            if [[ "$(fix9506_shape_family "$shape")" == v4 ]]; then
                printf 'delete routing-options static route %s\n' "$(fix9506_inner4 "$i")"
            else
                printf 'delete routing-options static route %s\n' "$(fix9506_inner6 "$i")"
            fi
            printf 'delete security ipsec vpn %s\n' "$(fix9506_vpn "$i")"
            printf 'delete security ipsec gateway %s\n' "$(fix9506_gw "$i")"
        done
        printf 'delete security ike policy %s\n' "$FIX9506_IKE_POLICY"
        printf 'delete security ike proposal %s\n' "$FIX9506_IKE_PROPOSAL"
        printf 'delete security ipsec proposal %s\n' "$FIX9506_ESP_PROPOSAL"
        printf 'delete security zones security-zone wan host-inbound-traffic system-services ike\n'
        printf 'delete security zones security-zone lan interfaces reth1 host-inbound-traffic system-services ike\n'
    } >"$del"
    printf '%s %s\n' "$set" "$del"
}

# --- Config apply / rollback (fw0 commits; config-sync replicates) ---

fix9506_cli_session() {
    # fix9506_cli_session <node> <stdin-file>: run a CLI REPL script,
    # print transcript to stdout.
    local node="$1" script="$2"
    fix9506_remote "$node" "cat > /tmp/fix9506-cli-in.txt <<'CLIEOF'
$(cat "$script")
CLIEOF
/usr/local/sbin/cli < /tmp/fix9506-cli-in.txt 2>&1; echo \"CLI_EXIT=\$?\""
}

fix9506_commit_file() {
    # fix9506_commit_file <node> <local.set> <label>: push + load merge +
    # commit check + commit with marker verification.
    local node="$1" local_set="$2" label="$3"
    local remote_set="/tmp/fix9506-${label}-${BASHPID}-${RANDOM}.set"
    sg incus-admin -c "incus file push $(printf '%q' "$local_set") $(printf '%q' "$node")$(printf '%q' "$remote_set")" || return 1
    local script out
    script="$(mktemp)"; out="$(mktemp)"
    {
        printf 'configure\n'
        printf 'load merge %s\n' "$remote_set"
        printf 'commit check\n'
        printf 'commit\n'
        printf 'exit\nquit\n'
    } >"$script"
    fix9506_cli_session "$node" "$script" >"$out" 2>&1 || true
    rm -f "$script"
    # This CLI emits no standalone configuration-check-success line; commit
    # complete is the positive check+commit marker after `commit check`.
    if ! grep -Eq '^load( merge)? complete' "$out" ||
        ! grep -q '^commit complete' "$out"; then
        echo "fix9506: commit FAILED for $label on $node:" >&2
        grep -iE 'error|invalid|failed|warning: |load|commit check|commit complete' "$out" | head -n 20 >&2
        rm -f "$out"
        fix9506_remote "$node" "rm -f $(printf '%q' "$remote_set")" >/dev/null 2>&1 || true
        return 1
    fi
    grep -iE '^warning: ' "$out" | head -n 10 >&2 || true
    rm -f "$out"
    fix9506_remote "$node" "rm -f $(printf '%q' "$remote_set")" >/dev/null 2>&1 || true
    return 0
}

fix9506_rollback() {
    local node="$1" script out
    script="$(mktemp)"; out="$(mktemp)"
    printf 'configure\nrollback 1\ncommit\nexit\nquit\n' >"$script"
    fix9506_cli_session "$node" "$script" >"$out" 2>&1 || true
    rm -f "$script"
    if grep -q '^commit complete' "$out" && grep -q 'configuration rolled back' "$out"; then
        rm -f "$out"; return 0
    fi
    echo "fix9506: rollback FAILED on $node" >&2
    head -n 20 "$out" >&2
    rm -f "$out"
    return 1
}

# --- Redundancy-group pinning (both-nodes SAs need RG1->node0, RG2->node1) ---

fix9506_rg_primary() {
    # fix9506_rg_primary <node> <rg>: prints primary node name (node0/node1).
    local node="$1" rg="$2" out
    out="$(fix9506_remote "$node" "/usr/local/sbin/cli -c 'show chassis cluster status'" 2>/dev/null)" || return 1
    awk -v rg="$rg" '
        $0 ~ "Redundancy group: "rg" " {inrg=1; next}
        $0 ~ "Redundancy group: " {inrg=0}
        inrg && $1 ~ /^node[01]$/ && $3 == "primary" {print $1; exit}
    ' <<<"$out"
}

fix9506_rg_manual() {
    # Prints "nodeN manual-state" for one RG; manual is usually yes/no.
    local node="$1" rg="$2" out
    out="$(fix9506_remote "$node" "/usr/local/sbin/cli -c 'show chassis cluster status'")" || return 1
    awk -v rg="$rg" '
        $0 ~ "Redundancy group: "rg" " {inrg=1; next}
        $0 ~ "Redundancy group: " {inrg=0}
        inrg && $1 ~ /^node[01]$/ && $3 == "primary" {print $1, $5; exit}
    ' <<<"$out"
}

fix9506_rg_record() {
    # fix9506_rg_record <dir>: record pre-run owner and forced/manual state.
    local dir="$1" state owner manual
    fix9506_cluster_env
    state="$(fix9506_rg_manual "$FIX9506_NODE0" 2)" || return 1
    read -r owner manual <<<"$state"
    {
        printf 'rg0=%s\n' "$(fix9506_rg_primary "$FIX9506_NODE0" 0)"
        printf 'rg1=%s\n' "$(fix9506_rg_primary "$FIX9506_NODE0" 1)"
        printf 'rg2=%s\n' "$owner"
        printf 'rg2_manual=%s\n' "$manual"
    } >"$dir/rg-primaries.txt"
    cat "$dir/rg-primaries.txt"
}
fix9506_rg_restore() {
    # Restore one RG's pre-run owner and manual/forced state. Automatic RGs
    # need a targeted move before reset; reset alone can leave the current
    # node as automatic primary.
    local rg="$1" want="$2" manual="$3" state got_owner got_manual n
    fix9506_cluster_env
    if [[ "$manual" == no ]]; then
        got_owner="$(fix9506_rg_primary "$FIX9506_NODE0" "$rg" 2>/dev/null || true)"
        if [[ "$got_owner" != "$want" ]]; then
            fix9506_remote "$FIX9506_NODE0" "/usr/local/sbin/cli -c 'request chassis cluster failover redundancy-group $rg node ${want#node}'" >/dev/null 2>&1 || return 1
            for ((n = 0; n < 60; n++)); do
                got_owner="$(fix9506_rg_primary "$FIX9506_NODE0" "$rg" 2>/dev/null || true)"
                [[ "$got_owner" == "$want" ]] && break
                sleep 5
            done
            [[ "$got_owner" == "$want" ]] || return 1
        fi
        fix9506_remote "$FIX9506_NODE0" "/usr/local/sbin/cli -c 'request chassis cluster failover reset redundancy-group $rg'" >/dev/null 2>&1 || return 1
    else
        fix9506_remote "$FIX9506_NODE0" "/usr/local/sbin/cli -c 'request chassis cluster failover redundancy-group $rg node ${want#node}'" >/dev/null 2>&1 || return 1
    fi
    for ((n = 0; n < 60; n++)); do
        state="$(fix9506_rg_manual "$FIX9506_NODE0" "$rg" 2>/dev/null)" || true
        read -r got_owner got_manual <<<"$state"
        if [[ "$got_owner" == "$want" && "$got_manual" == "$manual" ]]; then
            return 0
        fi
        sleep 5
    done
    echo "fix9506: RG$rg restore mismatch want=${want}/${manual} got=${got_owner:-?}/${got_manual:-?}" >&2
    return 1
}

fix9506_rg_failover() {
    # fix9506_rg_failover <rg> <node>: targeted failover + wait for primary.
    local rg="$1" node="$2" got="" n
    local want="node${node}"
    fix9506_cluster_env
    fix9506_remote "$FIX9506_NODE0" "/usr/local/sbin/cli -c 'request chassis cluster failover redundancy-group $rg node $node'" || return 1
    for ((n = 0; n < 60; n++)); do
        got="$(fix9506_rg_primary "$FIX9506_NODE0" "$rg" 2>/dev/null)" || true
        [[ "$got" == "$want" ]] && { printf '%s\n' "$got"; return 0; }
        sleep 5
    done
    echo "fix9506: RG$rg never reached $want (last=$got)" >&2
    return 1
}

# --- Live verification probes (read-only; raw output retained by callers) ---

fix9506_probe_node() {
    # fix9506_probe_node <node> <dir> <tag>: snapshot stN/xfrm/ruleset/sas.
    local node="$1" dir="$2" tag="$3"
    fix9506_remote "$node" 'ip -d -o link show type xfrm | sed -n "/: st[0-9][0-9]*\(\.[0-9][0-9]*\)\?\(@[^:]*\)\?:/p"' >"$dir/${tag}-st-links.txt" 2>&1 || :
    fix9506_remote "$node" 'ip -s xfrm state' >"$dir/${tag}-xfrm-state.txt" 2>&1 || :
    fix9506_remote "$node" 'ip -s xfrm policy' >"$dir/${tag}-xfrm-policy.txt" 2>&1 || :
    fix9506_remote "$node" 'nft -j list ruleset' >"$dir/${tag}-ruleset.json" 2>&1 || :
    fix9506_remote "$node" 'swanctl --list-sas 2>&1' >"$dir/${tag}-sas.txt" 2>&1 || :
    fix9506_remote "$node" 'cat /proc/net/netfilter/nfnetlink_queue 2>&1' >"$dir/${tag}-nfqueue.txt" 2>&1 || :
}
fix9506_count_stn() { grep -cE 'st9506' "$1" 2>/dev/null || true; }
fix9506_count_xfrm() { grep -cE '^src ' "$1" 2>/dev/null || true; }
fix9506_count_sa_established() { grep -cE 'ESTABLISHED' "$1" 2>/dev/null || true; }
fix9506_count_xfrm_packets() {
    awk '
        /lifetime current:/ {want=1; next}
        want && match($0, /[0-9]+\(bytes\),[[:space:]]*[0-9]+\(packets\)/) {
            text = substr($0, RSTART, RLENGTH)
            sub(/.*,[[:space:]]*/, "", text)
            sub(/\(packets\).*/, "", text)
            total += text
            want=0
        }
        END {print total + 0}
    ' "$1" 2>/dev/null || printf '0\n'
}

fix9506_count_xfrm_packets_ifid() {
    # fix9506_count_xfrm_packets_ifid <ip-xfrm-state> <hex-if_id>
    # Counts only the lifetime packet counters belonging to the selected
    # fixture tunnel, rather than conflating unrelated live XFRM state.
    local file="$1" target="$2"
    awk -v target="$target" '
        /^src / {selected=0; want=0; next}
        $1 == "if_id" && $2 == target {selected=1; next}
        /lifetime current:/ {want=1; next}
        want && selected && match($0, /[0-9]+\(bytes\),[[:space:]]*[0-9]+\(packets\)/) {
            text = substr($0, RSTART, RLENGTH)
            sub(/.*,[[:space:]]*/, "", text)
            sub(/\(packets\).*/, "", text)
            total += text
            want=0
        }
        END {print total + 0}
    ' "$file" 2>/dev/null || printf '0\n'
}
fix9506_fixture_residue() {
    # Scoped residue probe: unrelated baseline XFRM/NFQUEUE state is allowed,
    # but this fixture's stN, if_id range, divert table, and queue bindings
    # must all be absent after teardown.
    local dir="$1" tag="$2" residue=0
    grep -q 'st9506' "$dir/${tag}-st-links.txt" 2>/dev/null && residue=1 || :
    grep -Eq 'if_id (0x2522[0-9a-fA-F]{4}|622985[0-9]+)' \
        "$dir/${tag}-xfrm-state.txt" "$dir/${tag}-xfrm-policy.txt" 2>/dev/null && residue=1 || :
    grep -q 'xpf_ipsec_divert' "$dir/${tag}-ruleset.json" 2>/dev/null && residue=1 || :
    if [[ -s "$dir/fixture-queues.txt" ]]; then
        while IFS= read -r queue; do
            [[ "$queue" =~ ^[0-9]+$ ]] || continue
            grep -Eq "(^|[^0-9])${queue}([^0-9]|$)" "$dir/${tag}-nfqueue.txt" 2>/dev/null && residue=1 || :
        done <"$dir/fixture-queues.txt"
    fi
    printf '%s\n' "$residue"
}

fix9506_divert_queues() {
    # fix9506_divert_queues <ruleset.json>: prints per-class queue counts
    # and distinct total: "inet_fw inet_in br_fw br_in distinct".
    python3 - "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)
    items = doc.get("nftables")
    if not isinstance(items, list):
        raise ValueError("no list")
except Exception:
    print("0 0 0 0 0")
    raise SystemExit(0)
counts = {("inet", "forward"): set(), ("inet", "input"): set(),
          ("bridge", "forward"): set(), ("bridge", "input"): set()}
fam = tbl = chn = None
def walk(o):
    global fam, tbl, chn
    if isinstance(o, dict):
        if set(o.keys()) == {"queue"} or ("queue" in o and isinstance(o.get("queue"), (dict, int))):
            q = o["queue"]
            num = q.get("num") if isinstance(q, dict) else q
            try:
                counts[(fam, chn)].add(int(num))
            except Exception:
                pass
        for v in o.values():
            walk(v)
    elif isinstance(o, list):
        for v in o:
            walk(v)
for x in items:
    if isinstance(x, dict) and isinstance(x.get("table"), dict):
        t = x["table"]
        fam = str(t.get("family"))
        tbl = str(t.get("name"))
    elif isinstance(x, dict) and isinstance(x.get("chain"), dict):
        c = x["chain"]
        fam = str(c.get("family"))
        tbl = str(c.get("table"))
        chn = str(c.get("name"))
    elif isinstance(x, dict) and isinstance(x.get("rule"), dict):
        r = x["rule"]
        fam = str(r.get("family", fam))
        tbl = str(r.get("table", tbl))
        chn = str(r.get("chain", chn))
        if tbl == "xpf_ipsec_divert":
            walk(r.get("expr", []))
allq = set().union(*counts.values())
print("%d %d %d %d %d" % (len(counts[("inet", "forward")]),
      len(counts[("inet", "input")]), len(counts[("bridge", "forward")]),
      len(counts[("bridge", "input")]), len(allq)))
PY
}
fix9506_divert_queue_ids() {
    # Print the actual queue numbers in xpf_ipsec_divert, one per line.
    python3 - "$1" <<'PY'
import json, sys
try:
    with open(sys.argv[1], encoding="utf-8") as fh:
        doc = json.load(fh)
except Exception:
    raise SystemExit(0)
out = set()
def walk(value):
    if isinstance(value, dict):
        q = value.get("queue")
        n = q.get("num") if isinstance(q, dict) else q
        if n is not None:
            try:
                out.add(int(n))
            except (TypeError, ValueError):
                pass
        for child in value.values():
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)
for item in doc.get("nftables", []):
    if isinstance(item, dict) and isinstance(item.get("rule"), dict):
        rule = item["rule"]
        if rule.get("table") == "xpf_ipsec_divert":
            walk(rule.get("expr", []))
for n in sorted(out):
    print(n)
PY
}

fix9506_converge() {
    # fix9506_converge <shape> <count> <dir>: poll until both nodes show
    # N stN, N/2 established SAs each (own half), 4N distinct divert
    # queues, readable nft — or timeout with the precise missing piece.
    local shape="$1" count="$2" dir="$3"
    fix9506_cluster_env
    local half=$((count / 2)) deadline
    deadline=$(($(date +%s) + FIX9506_CONVERGE_TIMEOUT))
    local st0 st1 sa0 sa1 q0d q1d r0 r1
    while (($(date +%s) < deadline)); do
        fix9506_probe_node "$FIX9506_NODE0" "$dir" fw0
        fix9506_probe_node "$FIX9506_NODE1" "$dir" fw1
        st0=$(fix9506_count_stn "$dir/fw0-st-links.txt")
        st1=$(fix9506_count_stn "$dir/fw1-st-links.txt")
        sa0=$(fix9506_count_sa_established "$dir/fw0-sas.txt")
        sa1=$(fix9506_count_sa_established "$dir/fw1-sas.txt")
        read -r _ _ _ _ q0d < <(fix9506_divert_queues "$dir/fw0-ruleset.json")
        read -r _ _ _ _ q1d < <(fix9506_divert_queues "$dir/fw1-ruleset.json")
        r0=0; r1=0
        python3 -c 'import json,sys; json.load(open(sys.argv[1])); print(1)' "$dir/fw0-ruleset.json" 2>/dev/null | grep -q 1 && r0=1 || true
        python3 -c 'import json,sys; json.load(open(sys.argv[1])); print(1)' "$dir/fw1-ruleset.json" 2>/dev/null | grep -q 1 && r1=1 || true
        printf 'fix9506: converge stn=%s/%s sa=%s/%s (want %d) queues=%s/%s (want %d) nft=%s/%s\n' \
            "$st0" "$st1" "$sa0" "$sa1" "$half" "$q0d" "$q1d" "$((count * 4))" "$r0" "$r1" >&2
        if ((st0 == count && st1 == count && sa0 >= half && sa1 >= half &&
             q0d == count * 4 && q1d == count * 4 && r0 == 1 && r1 == 1)); then
            return 0
        fi
        sleep "$FIX9506_SA_POLL_INTERVAL"
    done
    echo "fix9506: CONVERGE TIMEOUT ${shape}x${count}: fw0(stn=$st0 sa=$sa0 q=$q0d nft=$r0) fw1(stn=$st1 sa=$sa1 q=$q1d nft=$r1)" >&2
    return 1
}
fix9506_wait_outer_paths() {
    local shape="$1" half fw peer node n ok
    for half in wan lan; do
        read -r fw peer <<<"$(fix9506_outer_addrs "$shape" "$half")"
        if [[ "$half" == wan ]]; then node="$FIX9506_NODE0"; else node="$FIX9506_NODE1"; fi
        ok=0
        for ((n = 0; n < 60; n++)); do
            if [[ "$(fix9506_shape_family "$shape")" == v4 ]]; then
                if fix9506_remote "$node" "ip -o -4 addr show | grep -Eq '[[:space:]]${fw}/' && ip route get $peer" >/dev/null 2>&1; then
                    ok=1
                    break
                fi
            elif fix9506_remote "$node" "ip -o -6 addr show | grep -Eq '[[:space:]]${fw}/' && ip -6 route get $peer" >/dev/null 2>&1; then
                ok=1
                break
            fi
            sleep 1
        done
        if ((ok == 0)); then
            echo "fix9506: outer path/address unavailable ${half} node=${node} fw=${fw} peer=${peer}" >&2
            return 1
        fi
    done
}

fix9506_install_inner_routes() {
    local shape="$1" count="$2" node i route stn
    local deadline=$(($(date +%s) + FIX9506_CONVERGE_TIMEOUT))
    for node in "$FIX9506_NODE0" "$FIX9506_NODE1"; do
        for ((i = 0; i < count; i++)); do
            stn="$(fix9506_stn "$i")"
            # Config commit returns before the async XFRM reconcile creates
            # the kernel link. Wait for that applied state before installing
            # routes, rather than turning the normal convergence window into
            # an immediate "Cannot find device" setup failure.
            while ! fix9506_remote "$node" "ip link show dev $stn" >/dev/null 2>&1; do
                if (( $(date +%s) >= deadline )); then
                    echo "fix9506: timed out waiting for $stn on $node before route install" >&2
                    return 1
                fi
                sleep 1
            done
            if [[ "$(fix9506_shape_family "$shape")" == v4 ]]; then
                route="$(fix9506_inner4 "$i")"
                fix9506_remote "$node" "ip route replace $route dev $stn" || return 1
            else
                route="$(fix9506_inner6 "$i")"
                fix9506_remote "$node" "ip -6 route replace $route dev $stn" || return 1
            fi
        done
    done
}
fix9506_record_parent_baseline() {
    local dir="$1" out
    out="$(fix9506_remote "$FIX9506_NODE0" 'cli -c "show configuration | display set"' 2>/dev/null)" || return 1
    {
        if grep -Fqx 'set security ike' <<<"$out"; then
            printf 'ike=present\n'
        else
            printf 'ike=absent\n'
        fi
        if grep -Fqx 'set security ipsec' <<<"$out"; then
            printf 'ipsec=present\n'
        else
            printf 'ipsec=absent\n'
        fi
        if grep -Fqx 'set security address-book global' <<<"$out"; then
            printf 'address-book-global=present\n'
        else
            printf 'address-book-global=absent\n'
        fi
    } >"$dir/fixture-security-parents.txt"
}

fix9506_prune_empty_parents() {
    local dir="$1" baseline prune
    baseline="$dir/fixture-security-parents.txt"
    prune="$dir/fixture-9506-prune.set"
    [[ -s "$baseline" ]] || return 0
    : >"$prune"
    local out parent status
    out="$(fix9506_remote "$FIX9506_NODE0" 'cli -c "show configuration | display set"' 2>/dev/null || true)"
    while IFS='=' read -r parent status; do
        [[ "$status" == absent ]] || continue
        case "$parent" in
        ike)
            if grep -Fqx 'set security ike' <<<"$out" &&
               ! grep -qE '^set security ike .+' <<<"$out"; then
                printf 'delete security ike\n' >>"$prune"
            fi
            ;;
        ipsec)
            if grep -Fqx 'set security ipsec' <<<"$out" &&
               ! grep -qE '^set security ipsec .+' <<<"$out"; then
                printf 'delete security ipsec\n' >>"$prune"
            fi
            ;;
        address-book-global)
            if grep -Fqx 'set security address-book global' <<<"$out" &&
               ! grep -qE '^set security address-book global .+' <<<"$out"; then
                printf 'delete security address-book global\n' >>"$prune"
            fi
            ;;
        esac
    done <"$baseline"
    if [[ -s "$prune" ]]; then
        fix9506_commit_file "$FIX9506_NODE0" "$prune" teardown-prune || return 1
    fi
}


fix9506_remove_inner_routes() {
    local count="$1" node i
    for node in "$FIX9506_NODE0" "$FIX9506_NODE1"; do
        for ((i = 0; i < count; i++)); do
            fix9506_remote "$node" \
                "ip route del $(fix9506_inner4 "$i") dev $(fix9506_stn "$i") 2>/dev/null || true; ip -6 route del $(fix9506_inner6 "$i") dev $(fix9506_stn "$i") 2>/dev/null || true" ||
                return 1
        done
    done
}

fix9506_setup() {
    # fix9506_setup <shape> <count> <dir>
    local shape="$1" count="$2" dir="$3"
    fix9506_require_lock || return 2
    fix9506_valid_shape "$shape" || return 1
    fix9506_valid_count "$count" || return 1
    fix9506_cluster_env
    fix9506_require_nft || return 1
    mkdir -p "$dir"
    fix9506_record_parent_baseline "$dir" || return 1
    local mutated=0
    # Every mutation after this point is paired with teardown. Call the
    # cleanup helper explicitly on each failure; a RETURN trap is unsafe
    # here because Bash can invoke it after the function-local scope ends.
    fix9506_setup_cleanup() {
        local cleanup_rc=0
        if ((mutated)); then
            echo "fix9506: setup failed; restoring fixture state" >&2
            fix9506_teardown "$count" "$dir" || cleanup_rc=$?
            mutated=0
        fi
        if ((cleanup_rc != 0)); then
            echo "fix9506: setup cleanup FAILED rc=$cleanup_rc" >&2
        fi
        return "$cleanup_rc"
    }
    fix9506_rg_record "$dir" >&2 || return 1
    local rg2
    rg2="$(fix9506_rg_primary "$FIX9506_NODE0" 2)" || return 1
    if [[ "$rg2" != node1 ]]; then
        mutated=1
        fix9506_rg_failover 2 1 >&2 || {
            fix9506_setup_cleanup || :
            return 1
        }
    fi
    fix9506_wait_outer_paths "$shape" || {
        fix9506_setup_cleanup || :
        return 1
    }
    mutated=1
    fix9506_peer_up "$shape" "$count" "$dir" || {
        fix9506_setup_cleanup || :
        return 1
    }
    local set del
    if ! read -r set del < <(fix9506_gen_config "$shape" "$count" "$dir"); then
        fix9506_setup_cleanup || :
        return 1
    fi
    fix9506_commit_file "$FIX9506_NODE0" "$set" "setup-${shape}x${count}" || {
        fix9506_setup_cleanup || :
        return 1
    }
    fix9506_install_inner_routes "$shape" "$count" || {
        fix9506_setup_cleanup || :
        return 1
    }
    fix9506_converge "$shape" "$count" "$dir" || {
        fix9506_setup_cleanup || :
        return 1
    }
    {
        fix9506_divert_queue_ids "$dir/fw0-ruleset.json"
        fix9506_divert_queue_ids "$dir/fw1-ruleset.json"
    } | sort -nu >"$dir/fixture-queues.txt"
    if [[ ! -s "$dir/fixture-queues.txt" ]]; then
        echo "fix9506: converged fixture has no queue witness" >&2
        fix9506_setup_cleanup || :
        return 1
    fi
    printf 'fix9506: setup complete %s x%d\n' "$shape" "$count" >&2

}
fix9506_fixture_config_present() {
    local out
    out="$(fix9506_remote "$FIX9506_NODE0" 'cli -c "show configuration | display set"' 2>/dev/null || true)"
    grep -qE 'vpn9506|gw9506|st9506|192\.168\.10[01]\.' <<<"$out"
}

fix9506_terminate_owned_sas() {
    local count="$1" node
    for node in "$FIX9506_NODE0" "$FIX9506_NODE1"; do
        fix9506_remote "$node" \
            "for ((i = 0; i < $count; i++)); do vpn=vpn9506t\$i; timeout 20 swanctl --terminate --ike \"\$vpn\" --force >/dev/null 2>&1 || true; done" ||
            return 1
    done
}

fix9506_teardown() {
    # fix9506_teardown <count> <dir>: remove xpf config, restore RGs,
    # delete peer, verify residue. Idempotent.
    local count="$1" dir="$2"
    fix9506_require_lock || return 2
    fix9506_cluster_env
    mkdir -p "$dir"
    local rc=0
    fix9506_terminate_owned_sas "$count" || rc=1
    fix9506_remove_inner_routes "$count" || rc=1
    if fix9506_fixture_config_present; then
        if [[ -f "$dir/fixture-9506-del.set" ]]; then
            fix9506_commit_file "$FIX9506_NODE0" "$dir/fixture-9506-del.set" "teardown" || rc=1
        else
            local set del
            read -r set del < <(fix9506_gen_config v4_native "$count" "$dir")
            fix9506_commit_file "$FIX9506_NODE0" "$del" "teardown" || rc=1
        fi
    fi
    # Poll for fixture disappearance on both nodes, including asynchronous
    # XFRM/policy/divert teardown rather than only the netdev deletion.
    local n st0 st1 residue0 residue1
    st0=1
    st1=1
    residue0=1
    residue1=1
    for ((n = 0; n < 36; n++)); do
        fix9506_probe_node "$FIX9506_NODE0" "$dir" fw0-post
        fix9506_probe_node "$FIX9506_NODE1" "$dir" fw1-post
        st0=$(fix9506_count_stn "$dir/fw0-post-st-links.txt")
        st1=$(fix9506_count_stn "$dir/fw1-post-st-links.txt")
        residue0="$(fix9506_fixture_residue "$dir" fw0-post)"
        residue1="$(fix9506_fixture_residue "$dir" fw1-post)"
        ((st0 == 0 && st1 == 0 && residue0 == 0 && residue1 == 0)) && break
        sleep 5
    done
    if ((st0 != 0 || st1 != 0)); then
        echo "fix9506: teardown residue: stn fw0=$st0 fw1=$st1" >&2
        rc=1
    fi
    residue0="$(fix9506_fixture_residue "$dir" fw0-post)"
    residue1="$(fix9506_fixture_residue "$dir" fw1-post)"
    if [[ "$residue0" != 0 || "$residue1" != 0 ]]; then
        echo "fix9506: XFRM/divert/NFQUEUE residue fw0=$residue0 fw1=$residue1" >&2
        rc=1
    fi
    # Restore RG2's recorded owner and manual/forced state. A normal
    # baseline must use reset, not a second forced failover.
    if [[ -f "$dir/rg-primaries.txt" ]]; then
        local want want_manual
        want="$(sed -n 's/^rg2=//p' "$dir/rg-primaries.txt")"
        want_manual="$(sed -n 's/^rg2_manual=//p' "$dir/rg-primaries.txt")"
        if [[ -n "$want" && -n "$want_manual" ]]; then
            fix9506_rg_restore 2 "$want" "$want_manual" >&2 || rc=1
        else
            echo "fix9506: missing RG2 restore witness" >&2
            rc=1
        fi
    fi
    fix9506_prune_empty_parents "$dir" || rc=1
    fix9506_peer_down || rc=1
    if fix9506_peer_exists; then
        echo "fix9506: peer instance still exists after teardown" >&2
        rc=1
    fi
    return $rc
}

# --- Standalone CLI (no-op when sourced) ---
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    cmd="${1:-help}"
    case "$cmd" in
    up)
        [[ $# -eq 3 ]] || { echo "usage: $0 up <shape> <count>" >&2; exit 2; }
        fix9506_cluster_env
        fix9506_setup "$2" "$3" "${XPF_9506_FIXTURE_DIR:-/var/tmp/xpf-9506-fixture}"
        ;;
    down)
        fix9506_cluster_env
        fix9506_teardown "${2:-2}" "${XPF_9506_FIXTURE_DIR:-/var/tmp/xpf-9506-fixture}"
        ;;
    status)
        fix9506_cluster_env
        d="${XPF_9506_FIXTURE_DIR:-/var/tmp/xpf-9506-fixture}"
        mkdir -p "$d"
        fix9506_probe_node "$FIX9506_NODE0" "$d" fw0
        fix9506_probe_node "$FIX9506_NODE1" "$d" fw1
        printf 'fw0 stn=%s xfrm=%s sa_est=%s queues=[%s] nft=%s\n' \
            "$(fix9506_count_stn "$d/fw0-st-links.txt")" \
            "$(fix9506_count_xfrm "$d/fw0-xfrm-state.txt")" \
            "$(fix9506_count_sa_established "$d/fw0-sas.txt")" \
            "$(fix9506_divert_queues "$d/fw0-ruleset.json")" \
            "$(python3 -c 'import json,sys; json.load(open(sys.argv[1])); print(1)' "$d/fw0-ruleset.json" 2>/dev/null || echo 0)"
        printf 'fw1 stn=%s xfrm=%s sa_est=%s queues=[%s] nft=%s\n' \
            "$(fix9506_count_stn "$d/fw1-st-links.txt")" \
            "$(fix9506_count_xfrm "$d/fw1-xfrm-state.txt")" \
            "$(fix9506_count_sa_established "$d/fw1-sas.txt")" \
            "$(fix9506_divert_queues "$d/fw1-ruleset.json")" \
            "$(python3 -c 'import json,sys; json.load(open(sys.argv[1])); print(1)' "$d/fw1-ruleset.json" 2>/dev/null || echo 0)"
        ;;
    gen-config)
        [[ $# -eq 4 ]] || { echo "usage: $0 gen-config <shape> <count> <dir>" >&2; exit 2; }
        fix9506_gen_config "$2" "$3" "$4"
        ;;
    *)
        sed -n '1,30p' "$0"
        exit 2
        ;;
    esac
fi
