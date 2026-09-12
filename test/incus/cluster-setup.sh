#!/usr/bin/env bash
# xpf Chassis Cluster (HA) test environment management
#
# Creates a two-VM HA cluster with heartbeat, fabric, and shared LAN
# networks, plus a test container on the cluster LAN.
#
# Single-config model: both nodes share a unified config with
# apply-groups "${node}" expansion. Node ID comes from /etc/xpf/node-id.
# Interface names follow vSRX conventions: fxp0, em0, ge-X/Y/Z.
#
# Parameterized via env file — set BPFRX_CLUSTER_ENV to source custom
# settings (remote host, SR-IOV parents, VF indices, network names, etc.).
# Without an env file, defaults match the original local cluster.
# The Makefile cluster-* aliases pass loss-userspace-cluster.env by default.
#
# Usage:
#   ./test/incus/cluster-setup.sh init              # Create networks + profile
#   ./test/incus/cluster-setup.sh create             # Launch both VMs + test container
#   ./test/incus/cluster-setup.sh destroy            # Tear down VMs + container
#   ./test/incus/cluster-setup.sh deploy [0|1|all]   # Build and push to VM(s)
#   ./test/incus/cluster-setup.sh ssh 0|1            # Shell into VM
#   ./test/incus/cluster-setup.sh status             # Show all VM status
#   ./test/incus/cluster-setup.sh logs 0|1           # Show xpfd logs
#   ./test/incus/cluster-setup.sh start [0|1|all]    # Start xpfd service
#   ./test/incus/cluster-setup.sh stop [0|1|all]     # Stop xpfd service
#   ./test/incus/cluster-setup.sh restart [0|1|all]  # Restart xpfd service

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# #1875: shared-cluster lock protocol (marker validation + owner
# reporting). Mutating verbs serialize through with-cluster.sh — see
# require_cluster_cell below and the protocol header in cluster-lock.sh.
# shellcheck source=cluster-lock.sh
source "${SCRIPT_DIR}/cluster-lock.sh"
# shellcheck source=cluster-build-identity.sh
source "${SCRIPT_DIR}/cluster-build-identity.sh"

# Source env file for custom deployments (remote, SR-IOV config, etc.)
if [[ -n "${BPFRX_CLUSTER_ENV:-}" && -f "$BPFRX_CLUSTER_ENV" ]]; then
	# shellcheck disable=SC1090
	source "$BPFRX_CLUSTER_ENV"
fi

# Re-exec under incus-admin group if needed. Forward ALL BPFRX_*/XPF_*
# scalar vars, not just BPFRX_CLUSTER_ENV: sg's env preservation is
# not guaranteed on every platform, and losing XPF_CLUSTER_LOCK_HELD
# here would deadlock a deploy running inside a with-cluster.sh cell
# (#1875 plan A3 / SMR r2 S1).
if ! incus list &>/dev/null 2>&1; then
	if getent group incus-admin &>/dev/null && id -nG | grep -qw incus-admin; then
		local_env=""
		for _v in "${!BPFRX_@}" "${!XPF_@}"; do
			local_env+="${_v}=$(printf '%q' "${!_v}") "
		done
		exec sg incus-admin -c "${local_env}$(printf '%q ' "$0" "$@")"
	fi
fi

# #1875: serialize a mutating verb against other agents. Either we are
# already inside a valid lock cell (marker from a live ancestor holder
# — return immediately and run lock-free), or we re-exec this whole
# invocation through with-cluster.sh, which blocks with a named-holder
# report until the cluster is ours and re-runs us with the marker set.
# The re-exec'd child runs with the lock fd closed, so killing the
# verb's process tree releases the lock instantly. ORIG_ARGS preserves
# the exact argv for the re-exec ("$SCRIPT_DIR/cluster-setup.sh", not
# "$0", to dodge PATH/symlink oddities — Codex r2).
ORIG_ARGS=("$@")
require_cluster_cell() { # require_cluster_cell <purpose words...>
	if xpf_cluster_lock_held; then
		return 0
	fi
	exec "${SCRIPT_DIR}/with-cluster.sh" "cluster-setup $*" \
		-- "${SCRIPT_DIR}/cluster-setup.sh" "${ORIG_ARGS[@]}"
}

# ── Defaults (local cluster values if no env file) ───────────────────

INCUS_REMOTE="${INCUS_REMOTE:-}"
VM0="${VM0:-xpf-fw0}"
VM1="${VM1:-xpf-fw1}"
LAN_HOST="${LAN_HOST:-cluster-lan-host}"
PROFILE="${PROFILE:-xpf-cluster}"
# Ubuntu 26.04 to match the production appliance base (scripts/image/bake.py),
# same as the standalone test/incus/setup.sh (#1943). XPF_BASE_RELEASE pins the
# Ubuntu release; IMAGE_VM/IMAGE_CT stay env-overridable for a different *Ubuntu*
# release, NOT a Debian fallback (the script now uses Ubuntu package names + a
# >= 6.18 kernel floor). Rollback is `git revert`, not a runtime IMAGE_VM swap.
# VM uses the /cloud (cloud-init) variant; the LAN-host container uses the
# plain non-cloud alias (no need for cloud-init in a container) — Copilot r2.
XPF_BASE_RELEASE="${XPF_BASE_RELEASE:-26.04}"
IMAGE_VM="${IMAGE_VM:-images:ubuntu/${XPF_BASE_RELEASE}/cloud}"
IMAGE_CT="${IMAGE_CT:-images:ubuntu/${XPF_BASE_RELEASE}}"
LAN_ADDR="${LAN_ADDR:-}"
LAN_GW="${LAN_GW:-}"

# SR-IOV: nictype=sriov for BOTH VM and container VFs. VMs previously used raw
# type:pci passthrough with the VF VLAN/trust set out-of-band on the host PF,
# but that host-PF state is cleared on a host reboot / PF reset and nothing
# re-applied it (the 2026-07-01 LAN de-isolation outage). nictype:sriov makes
# incus re-apply vlan=/mac_filtering on every VM start — durable + native.
SRIOV_PARENT="${SRIOV_PARENT:-eno6np1}"      # WAN SR-IOV parent (nictype:sriov)
SRIOV_LAN_PARENT="${SRIOV_LAN_PARENT:-}"     # LAN SR-IOV parent (nictype:sriov)

# WAN VF PCI addresses per VM (VF_PCI is legacy alias for VF_WAN_PCI)
if [[ -z "${VF_WAN_PCI+x}" ]]; then
	if [[ -z "${VF_PCI+x}" ]]; then
		VF_WAN_PCI=("0000:b7:06.0" "0000:b7:06.1")
	else
		VF_WAN_PCI=("${VF_PCI[@]}")
	fi
fi
VF_WAN_TRUST="${VF_WAN_TRUST:-true}"
# LAN VF PCI addresses per VM (empty = no LAN VF passthrough)
if [[ -z "${VF_LAN_PCI+x}" ]]; then VF_LAN_PCI=(); fi

# Network names (parameterized for remote)
NET_MGMT="${NET_MGMT:-incusbr0}"
NET_HEARTBEAT="${NET_HEARTBEAT:-xpf-heartbeat}"
NET_FABRIC="${NET_FABRIC:-xpf-fabric}"
# NET_CLAN: set to empty in env file to skip bridge-based LAN (SR-IOV LAN)
if [[ -z "${NET_CLAN+x}" ]]; then NET_CLAN="xpf-clan"; fi

# Config file path
CLUSTER_CONF="${CLUSTER_CONF:-${PROJECT_ROOT}/docs/ha-cluster.conf}"
SHARED_UMEM_PHASE0_ARTIFACT_DEST="${SHARED_UMEM_PHASE0_ARTIFACT_DEST:-/run/xpf/shared-umem-phase0.json}"
SHARED_UMEM_PHASE0_ARTIFACT_NODE0="${SHARED_UMEM_PHASE0_ARTIFACT_NODE0:-${PROJECT_ROOT}/test/incus/loss-userspace-shared-umem-phase0-node0.json}"
SHARED_UMEM_PHASE0_ARTIFACT_NODE1="${SHARED_UMEM_PHASE0_ARTIFACT_NODE1:-${PROJECT_ROOT}/test/incus/loss-userspace-shared-umem-phase0-node1.json}"

# Network definitions: name:subnet:nat (only for networks we manage)
NETWORKS=()
# Always manage heartbeat and fabric
NETWORKS+=("${NET_HEARTBEAT}:none:false")
NETWORKS+=("${NET_FABRIC}:none:false")
# Only manage cluster LAN bridge if it's set (not for SR-IOV LAN)
if [[ -n "$NET_CLAN" && "$NET_CLAN" != "none" ]]; then
	NETWORKS+=("${NET_CLAN}:none:false")
fi

info()  { echo "==> $*"; }
warn()  { echo "WARNING: $*" >&2; }
die()   { echo "ERROR: $*" >&2; exit 1; }

# Shared raw-deploy reconciliation + sha-verify helpers (#2162/#2176). Sourced
# after info/warn/die so the lib can use them.
# shellcheck source=deploy-lib.sh
source "${SCRIPT_DIR}/deploy-lib.sh"

# ── Helpers ───────────────────────────────────────────────────────────

run_on_host() {
	if [[ -n "${INCUS_REMOTE:-}" ]]; then
		ssh "$INCUS_REMOTE" "$@"
	else
		"$@"
	fi
}

suppress_host_parent_ipv6_ra() {
	local parent="$1"

	if [[ -z "$parent" ]]; then
		return
	fi

	# The host-side SR-IOV LAN parent should never learn the isolated LAN
	# prefix itself. If it accepts RAs, host traffic to the test LAN bypasses
	# the firewall and tries to resolve the destination directly on-link.
	info "Disabling IPv6 RA/autoconf on host parent $parent..."
	run_on_host sudo sysctl -qw \
		"net.ipv6.conf.${parent}.accept_ra=0" \
		"net.ipv6.conf.${parent}.autoconf=0" \
		"net.ipv6.conf.${parent}.router_solicitations=0"
	if ! run_on_host sudo ip -6 addr flush dev "$parent" scope global dynamic; then
		warn "targeted IPv6 dynamic address flush failed on host parent $parent; falling back to broader global-address flush"
		run_on_host sudo ip -6 addr flush dev "$parent" scope global ||
			die "failed to clear learned IPv6 global addresses from host parent $parent"
	fi
	run_on_host sudo ip -6 route flush dev "$parent" proto ra ||
		die "failed to clear RA-learned IPv6 routes from host parent $parent"
}

# Prefix instance name with remote if set: "loss:xpf-fw0" or "xpf-fw0"
r() {
	echo "${INCUS_REMOTE:+${INCUS_REMOTE}:}$1"
}

# Resolve VM name from node index (0 or 1)
vm_name() {
	case "$1" in
		0) echo "$VM0" ;;
		1) echo "$VM1" ;;
		*) die "Invalid node index: $1 (must be 0 or 1)" ;;
	esac
}

shared_umem_phase0_artifact_for_node() {
	case "$1" in
		0) echo "$SHARED_UMEM_PHASE0_ARTIFACT_NODE0" ;;
		1) echo "$SHARED_UMEM_PHASE0_ARTIFACT_NODE1" ;;
		*) die "Invalid node index: $1 (must be 0 or 1)" ;;
	esac
}

cluster_config_requests_shared_umem_phase0_artifact() {
	[[ -f "$CLUSTER_CONF" ]] && grep -Eq 'phase0-artifact-file|artifact-file' "$CLUSTER_CONF"
}

push_shared_umem_phase0_artifact() {
	local idx="$1"
	local rinst="$2"
	local artifact
	artifact=$(shared_umem_phase0_artifact_for_node "$idx")

	if ! cluster_config_requests_shared_umem_phase0_artifact; then
		return
	fi
	if [[ ! -f "$artifact" ]]; then
		die "Shared-UMEM Phase 0 artifact is configured but missing for node${idx}: $artifact"
	fi

	info "Pushing shared-UMEM Phase 0 artifact to node${idx}..."
	incus exec "$rinst" -- mkdir -p "$(dirname "$SHARED_UMEM_PHASE0_ARTIFACT_DEST")"
	incus file push "$artifact" "${rinst}${SHARED_UMEM_PHASE0_ARTIFACT_DEST}" --mode 0644
}

# Wait for incus agent to be ready inside a VM
wait_for_agent() {
	local inst="$1"
	local max="${2:-90}"
	local tries=0
	while ! incus exec "$(r "$inst")" -- true &>/dev/null; do
		sleep 2
		tries=$((tries + 1))
		if [[ $tries -ge $max ]]; then
			die "VM agent for $inst did not become ready after $((max * 2)) seconds"
		fi
	done
}

# ── Init ─────────────────────────────────────────────────────────────

cmd_init() {
	create_networks
	create_profile
	info "Init complete. Run '$0 create' next."
}

create_networks() {
	for entry in "${NETWORKS[@]}"; do
		IFS=: read -r name subnet nat <<< "$entry"
		if incus network show "$(r "$name")" &>/dev/null 2>&1; then
			info "Network $name already exists"
			continue
		fi
		info "Creating network $name (subnet=$subnet, nat=$nat)"
		incus network create "$(r "$name")" \
			ipv4.address="$subnet" \
			ipv4.nat="$nat" \
			ipv6.address=none
		# Jumbo frames on fabric bridge for cross-chassis throughput.
		if [[ "$name" == "$NET_FABRIC" ]]; then
			incus network set "$(r "$name")" bridge.mtu=9000
		fi
		# Enable IPv6 on cluster LAN bridge so incus doesn't strip IPv6
		# routes from containers. ra-param=*,0,0 suppresses default
		# router advertisements so only the firewall's embedded RA sender is used.
		if [[ "$name" == "$NET_CLAN" && "$NET_CLAN" != "none" ]]; then
			incus network set "$(r "$name")" \
				ipv6.address=fd42:cafe::1/64 \
				ipv6.nat=false \
				ipv6.dhcp=false \
				raw.dnsmasq=ra-param=*,0,0
		fi
	done
}

create_profile() {
	if incus profile show "$(r "$PROFILE")" &>/dev/null 2>&1; then
		info "Profile $PROFILE already exists, updating..."
		incus profile delete "$(r "$PROFILE")" 2>/dev/null || true
	fi
	info "Creating profile $PROFILE"
	incus profile create "$(r "$PROFILE")"

	# Build profile YAML dynamically based on network config
	local yaml
	yaml="config:
  limits.cpu: \"4\"
  limits.memory: 4GB
devices:
  root:
    path: /
    pool: default
    size: 20GB
    type: disk
  eth0:
    name: enp5s0
    network: ${NET_MGMT}
    type: nic
  eth1:
    name: enp6s0
    network: ${NET_HEARTBEAT}
    type: nic
  eth2:
    name: enp7s0
    network: ${NET_FABRIC}
    type: nic"

	# Only add LAN bridge NIC if NET_CLAN is set (not SR-IOV LAN)
	if [[ -n "$NET_CLAN" && "$NET_CLAN" != "none" ]]; then
		yaml+="
  eth3:
    name: enp8s0
    network: ${NET_CLAN}
    type: nic"
	fi

	echo "$yaml" | incus profile edit "$(r "$PROFILE")"
}

# ── Instance Management ──────────────────────────────────────────────

cmd_create() {
	if [[ -n "${SRIOV_LAN_PARENT:-}" ]]; then
		suppress_host_parent_ipv6_ra "$SRIOV_LAN_PARENT"
	fi

	# Create both VMs
	for idx in 0 1; do
		create_vm "$idx"
	done

	# Create test container on cluster LAN
	create_lan_host

	info "Cluster environment ready. Run '$0 deploy all' to push xpfd."
}

create_vm() {
	local idx="$1"
	local vm
	vm=$(vm_name "$idx")

	if incus info "$(r "$vm")" &>/dev/null 2>&1; then
		die "Instance $vm already exists. Run '$0 destroy' first."
	fi

	info "Launching VM $vm..."
	incus launch "$IMAGE_VM" "$(r "$vm")" --vm --profile "$PROFILE"

	info "Waiting for VM agent ($vm)..."
	wait_for_agent "$vm"

	# Stop VM to add SR-IOV VFs via PCI passthrough (hotplug doesn't work)
	info "Stopping VM to add SR-IOV VF(s)..."
	incus stop "$(r "$vm")" --force
	sleep 2

	# WAN VF: incus-managed SR-IOV nic (nictype:sriov), NOT raw type:pci
	# passthrough. incus re-applies the VF config on EVERY VM start, so the WAN
	# trunk survives a VM reboot AND a host reboot / PF reset. (The 2026-07-01
	# outage was a raw type:pci VF whose host-side VLAN/trust was set
	# out-of-band once at create and lost on the next host boot; nictype:sriov
	# makes incus own it — no systemd unit, no `ip link set vf` bolt-on.) No
	# access vlan = trunk, so the guest tags its own VLAN subinterfaces
	# (reth0.50/reth0.80); security.mac_filtering=false lets the guest set the
	# RETH virtual MAC — the incus-native equivalent of `ip link set vf trust
	# on`. incus allocates a free VF on the parent (VF_WAN_PCI is no longer
	# needed for the VM path).
	info "Adding WAN SR-IOV nic (parent=$SRIOV_PARENT) to $vm..."
	incus config device add "$(r "$vm")" wan-vf nic \
		nictype=sriov parent="$SRIOV_PARENT" security.mac_filtering=false

	# LAN VF: incus-managed SR-IOV nic with the access VLAN set via incus
	# (nictype:sriov vlan=), NOT raw type:pci + out-of-band `ip link set vf
	# vlan`. incus re-applies vlan= on EVERY VM start so the LAN stays isolated
	# across a VM reboot AND a host reboot / PF reset — the durable,
	# incus-native fix for the 2026-07-01 LAN de-isolation outage (a raw
	# type:pci VF's host-PF VLAN was set once at create and cleared on the next
	# host boot, reverting fw0/fw1's LAN VFs to an untagged trunk and cutting
	# off the cluster host). Gated on the LAN parent being set (SR-IOV LAN);
	# vlan= is added only when VF_LAN_VLAN is set (an untagged LAN omits it).
	# incus allocates a free VF on the parent (VF_LAN_PCI is no longer needed
	# for the VM path).
	if [[ -n "${SRIOV_LAN_PARENT:-}" ]]; then
		local lan_args=(nictype=sriov parent="$SRIOV_LAN_PARENT")
		if [[ -n "${VF_LAN_VLAN:-}" ]]; then
			lan_args+=(vlan="$VF_LAN_VLAN")
		fi
		info "Adding LAN SR-IOV nic (parent=$SRIOV_LAN_PARENT${VF_LAN_VLAN:+ vlan=$VF_LAN_VLAN}) to $vm..."
		incus config device add "$(r "$vm")" lan-vf nic "${lan_args[@]}"
	fi

	info "Starting VM with VF(s)..."
	incus start "$(r "$vm")"

	# Wait for agent again after restart
	wait_for_agent "$vm"

	provision_vm "$vm" "$idx"
	info "VM $vm ready."
}

provision_vm() {
	local vm="$1"
	local idx="$2"
	local rinst
	rinst=$(r "$vm")

	# Wait for systemd to be ready
	info "Waiting for system to be ready ($vm)..."
	local stries=0
	while ! incus exec "$rinst" -- systemctl is-system-running &>/dev/null 2>&1; do
		sleep 2
		stries=$((stries + 1))
		if [[ $stries -ge 30 ]]; then
			warn "systemd did not become ready after 60 seconds on $vm, continuing anyway"
			break
		fi
	done

	# Interface naming (fxp0, em0, ge-X/0/Y) is now handled by xpfd itself
	# at startup — no external script needed.

	info "Configuring sysctl ($vm)..."
	# #9725: transit forwarding starts closed; xpfd's transit gate opens it when
	# the dataplane is armed with a live attached link.
	incus exec "$rinst" -- bash -c 'cat > /etc/sysctl.d/99-bpf.conf <<EOF
net.core.bpf_jit_enable=1
# #9725: the transit knobs are NOT persisted here. xpfd's transit gate owns
# them, and a sysctl.d file is re-applied by any systemd-sysctl run, which
# would fight the gate under a running xpfd. Both default to 0 anyway.
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
EOF'
	# #1636 option B: lower neighbor retrans_time_ms 1000ms->250ms so a
	# dropped ARP/NDP solicit is re-driven ~4x sooner (cold-connect fix).
	# xpfd also writes these at start; this persists across reboots.
	incus exec "$rinst" -- bash -c 'cat > /etc/sysctl.d/99-xpf-neighbor.conf <<EOF
net.ipv4.neigh.default.retrans_time_ms = 250
net.ipv6.neigh.default.retrans_time_ms = 250
EOF'
	incus exec "$rinst" -- sysctl --system

	# Ubuntu 26.04 package names, version-exact against the stock image kernel
	# (#1943) — see the matching rationale in setup.sh. Deltas vs the old Debian
	# list: linux-headers-amd64 -> linux-headers-$(uname -r); linux-perf ->
	# linux-tools-$(uname -r); host -> bind9-host; golang dropped. NO
	# linux-modules-extra: the mlx5 SR-IOV VF drivers ship in the in-image
	# linux-modules package and no linux-modules-extra-* exists for this kernel.
	# frr-pythontools and ethtool exist on Ubuntu with the same names.
	info "Installing packages ($vm, this may take a few minutes)..."
	incus exec "$rinst" -- bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential clang llvm libbpf-dev linux-headers-$(uname -r) linux-tools-$(uname -r) tcpdump iproute2 iperf3 bpftool frr frr-pythontools strongswan strongswan-swanctl kea-dhcp4-server kea-dhcp6-server chrony ethtool mtr-tiny bind9-host pciutils curl wget ripgrep'

	# Ubuntu 26.04 ships a stock kernel >= 6.18, so the Debian-unstable kernel
	# dance is gone. Assert the floor and the SR-IOV VF driver presence (mlx5),
	# mirroring bake.py:227-242, so a regressed base fails loudly.
	info "Asserting kernel >= 6.18 and mlx5 driver present ($vm)..."
	incus exec "$rinst" -- bash -c 'kver=$(uname -r); dpkg --compare-versions "${kver%%-*}" ge 6.18 || { echo "FATAL: base kernel $kver < 6.18 (verifier floor)" >&2; exit 1; }; test -d /lib/modules/$kver/kernel/drivers/net/ethernet/mellanox || { echo "FATAL: mlx5 driver modules missing" >&2; exit 1; }' \
		|| die "base image kernel < 6.18 or mlx5 driver modules missing ($vm)"

	# Disable init_on_alloc via a grub.d drop-in (NOT a sed) — the Ubuntu
	# image's 50-*.cfg re-sets GRUB_CMDLINE_LINUX_DEFAULT, so a sed is lost.
	# Mirrors bake.py's GRUB_DROPIN. Keep a reboot so the change goes live.
	info "Disabling init_on_alloc for XDP performance ($vm, grub.d drop-in)..."
	incus exec "$rinst" -- bash -c 'cat > /etc/default/grub.d/99-xpf.cfg <<EOF
# xpf (#1943/#1879): init_on_alloc=0 in the virtio-net XDP path.
GRUB_CMDLINE_LINUX_DEFAULT="\$GRUB_CMDLINE_LINUX_DEFAULT init_on_alloc=0"
EOF'
	incus exec "$rinst" -- update-grub

	info "Rebooting VM to apply the init_on_alloc=0 grub change ($vm)..."
	incus restart "$(r "$vm")"
	local ktries=0
	while ! incus exec "$rinst" -- true &>/dev/null; do
		sleep 2
		ktries=$((ktries + 1))
		if [[ $ktries -ge 30 ]]; then
			warn "VM $vm did not come back after the grub-apply reboot"
			break
		fi
	done
	incus exec "$rinst" -- uname -r

	incus exec "$rinst" -- systemctl enable frr

	# Chrony: enable and clear default pool sources
	incus exec "$rinst" -- systemctl enable chrony
	incus exec "$rinst" -- bash -c 'sed -i "s/^pool /#pool /" /etc/chrony/chrony.conf; sed -i "s/^server /#server /" /etc/chrony/chrony.conf'
	incus exec "$rinst" -- mkdir -p /etc/chrony/sources.d

	# Write cluster node ID file for ${node} variable expansion
	info "Writing node-id file ($vm, node $idx)..."
	incus exec "$rinst" -- mkdir -p /etc/xpf
	incus exec "$rinst" -- bash -c "echo $idx > /etc/xpf/node-id"
}

create_lan_host() {
	local rinst
	rinst=$(r "$LAN_HOST")

	if incus info "$rinst" &>/dev/null 2>&1; then
		info "Container $LAN_HOST already exists, skipping"
		return
	fi

	info "Launching test container $LAN_HOST..."
	incus launch "$IMAGE_CT" "$rinst" -s default

	if [[ -n "$SRIOV_LAN_PARENT" ]]; then
		# SR-IOV LAN: incus picks a free VF, applies VLAN at host level
		local lan_host_args=(nictype=sriov parent="$SRIOV_LAN_PARENT")
		if [[ -n "${VF_LAN_VLAN:-}" ]]; then
			lan_host_args+=(vlan="${VF_LAN_VLAN}")
		fi
		info "Adding LAN SR-IOV VF (parent=$SRIOV_LAN_PARENT${VF_LAN_VLAN:+ vlan=$VF_LAN_VLAN}) to $LAN_HOST..."
		incus config device add "$rinst" eth0 nic "${lan_host_args[@]}"
	else
		# Bridge-based LAN
		incus config device add "$rinst" eth0 nic network="$NET_CLAN"
	fi
	incus restart "$rinst"

	info "Waiting for container to start..."
	sleep 3

	# Determine LAN IP config; allow env override for isolated labs.
	local lan_addr lan_gw
	if [[ -n "${LAN_ADDR}" && -n "${LAN_GW}" ]]; then
		lan_addr="${LAN_ADDR}"
		lan_gw="${LAN_GW}"
	elif [[ "$CLUSTER_CONF" == *"loss"* ]]; then
		lan_addr="10.0.89.102/24"
		lan_gw="10.0.89.1"
	else
		lan_addr="10.0.60.102/24"
		lan_gw="10.0.60.1"
	fi

	# Configure static IP
	info "Configuring static IP on $LAN_HOST ($lan_addr)..."
	incus exec "$rinst" -- bash -c "cat > /etc/systemd/network/10-cluster-lan.network <<EOF
[Match]
Name=eth0

[Network]
Address=${lan_addr}
Gateway=${lan_gw}
IPv6AcceptRA=true

[Link]
RequiredForOnline=no
EOF"
	incus exec "$rinst" -- systemctl restart systemd-networkd

	info "Installing packages on $LAN_HOST (may fail if firewall not yet deployed)..."
	if ! incus exec "$rinst" -- bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq iperf3 mtr-tiny pciutils tcpdump curl wget ripgrep' 2>/dev/null; then
		warn "Package install failed (firewall not running?). Re-run after deploy: incus exec $(r "$LAN_HOST") -- apt-get install -y iperf3 mtr-tiny tcpdump curl wget"
	fi

	info "Container $LAN_HOST ready ($lan_addr)."
}

# ── Destroy ──────────────────────────────────────────────────────────

cmd_destroy() {
	for inst in "$VM0" "$VM1" "$LAN_HOST"; do
		if incus info "$(r "$inst")" &>/dev/null 2>&1; then
			info "Stopping and deleting $inst..."
			incus stop "$(r "$inst")" --force 2>/dev/null || true
			incus delete "$(r "$inst")" --force
		else
			info "$inst does not exist"
		fi
	done

	# Optionally clean up networks and profile
	read -rp "Also remove networks and profile? [y/N] " answer
	if [[ "${answer,,}" == "y" ]]; then
		for entry in "${NETWORKS[@]}"; do
			IFS=: read -r name _ _ <<< "$entry"
			if incus network show "$(r "$name")" &>/dev/null 2>&1; then
				info "Deleting network $name"
				incus network delete "$(r "$name")"
			fi
		done
		if incus profile show "$(r "$PROFILE")" &>/dev/null 2>&1; then
			info "Deleting profile $PROFILE"
			incus profile delete "$(r "$PROFILE")"
		fi
	fi
	info "Destroy complete."
}

# ── Deploy ───────────────────────────────────────────────────────────

cmd_deploy() {
	local target="${1:-all}"

	case "$target" in
		0|1|all) ;;
		*) die "Usage: $0 deploy [0|1|all]" ;;
	esac

	# Dogfood deploy mode (#1917 increment B, C1). XPF_DEPLOY_DEB=1 builds
	# the .deb and drives the verified in-place cut-over (`xpfd upgrade
	# --rolling`), exercising the real upgrade mechanism every cycle. The
	# default (and XPF_DEPLOY_FAST=1) keeps the raw incus-file-push +
	# restart for the tight dev inner loop (no deb rebuild, no verified
	# cut). The deb path is opt-in until it is validated live on the loss
	# userspace cluster (it then becomes the CI/smoke default per the plan).
	#
	# #1875 lock discipline is PRESERVED: `make deb` builds OUTSIDE the
	# lock (it is multi-minute and local); only the install + cut-over
	# runs under the lock via the locked re-invocation below.

	# #1875: build OUTSIDE the lock — it is multi-minute and purely
	# local, and holding the shared-cluster lock across it would
	# starve other agents for no reason. The locked re-invocation
	# below skips the rebuild via XPF_CLUSTER_SKIP_BUILD.
	if [[ -z "${XPF_CLUSTER_SKIP_BUILD:-}" ]]; then
		if [[ "${XPF_DEPLOY_DEB:-}" = "1" ]]; then
			info "Building xpf .deb (dogfood in-place upgrade)..."
			make -C "$PROJECT_ROOT" deb
		else
			info "Building xpfd and cli..."
			make -C "$PROJECT_ROOT" build build-ctl
			if [[ -x "$HOME/.cargo/bin/cargo" || -n "$(command -v cargo 2>/dev/null)" ]]; then
				info "Building xpf-userspace-dp helper..."
				make -C "$PROJECT_ROOT" build-userspace-dp
			else
				warn "Rust toolchain not found; skipping xpf-userspace-dp build"
			fi
		fi
	fi

	# #1875: everything past this point mutates shared state —
	# including the host-parent IPv6-RA suppression (sysctl + addr +
	# route flush on the shared SR-IOV parent, Codex r2 F1) — and runs
	# under the cluster lock. Concurrent agents queue here with a
	# visible named-holder report instead of clobbering each other's
	# validation runs mid-phase (the #1875 incident).
	if ! xpf_cluster_lock_held; then
		_branch=$(git -C "$PROJECT_ROOT" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?')
		exec "${SCRIPT_DIR}/with-cluster.sh" \
			"cluster-setup deploy ${target} (${_branch})" \
			-- env XPF_CLUSTER_SKIP_BUILD=1 \
			"${SCRIPT_DIR}/cluster-setup.sh" deploy "$target"
	fi

	if [[ -n "${SRIOV_LAN_PARENT:-}" ]]; then
		suppress_host_parent_ipv6_ra "$SRIOV_LAN_PARENT"
	fi

	if [[ "${XPF_DEPLOY_DEB:-}" = "1" ]]; then
		case "$target" in
			0)   deploy_vm_deb 0 ;;
			1)   deploy_vm_deb 1 ;;
			all) deploy_rolling_deb ;;
		esac
	else
		case "$target" in
			0)   deploy_vm 0 ;;
			1)   deploy_vm 1 ;;
			all) deploy_rolling ;;
		esac
	fi

	# This cell changed the build ON PURPOSE. Re-baseline so the cell's
	# boundary check reports only a build that changed UNDER it — without
	# this, every deploy cell would cry wolf and the warning would be
	# trained away, which is the failure mode the check exists to avoid.
	# A no-op outside a with-cluster.sh cell.
	xpf_cluster_rebaseline_build
}

# deploy_vm_deb installs the .deb on a clustered node (STAGE-ONLY per the
# postinst HA-mode contract — node-id present => no local cut) and then
# drives the verified single-node cut via `xpfd upgrade --rolling`, which
# performs the controlled drain so the peer keeps forwarding. #1917 C1.
deploy_vm_deb() {
	local idx="$1"
	local vm rinst deb
	vm=$(vm_name "$idx")
	rinst=$(r "$vm")
	if ! incus info "$rinst" &>/dev/null 2>&1; then
		die "Instance $vm does not exist. Run '$0 create' first."
	fi
	# Locate the freshly-built .deb (Makefile deb: target output dir is
	# dist-deb/; install the runtime xpf_*.deb, NOT the xpf-appliance meta).
	deb=$(ls -t "$PROJECT_ROOT"/dist-deb/xpf_*.deb 2>/dev/null | head -1 || true)
	[[ -n "$deb" ]] || die "no xpf_*.deb found in dist-deb/ — run 'make deb' first (XPF_DEPLOY_DEB build)"

	info "Pushing $(basename "$deb") to $vm..."
	incus file push "$deb" "${rinst}/tmp/$(basename "$deb")"
	# apt install is STAGE-ONLY on a clustered node (node-id present): it
	# refreshes the staging path but does NOT cut the dataplane.
	incus exec "$rinst" -- apt-get install -y --reinstall "/tmp/$(basename "$deb")"

	# Drive the verified controlled-drain cut on THIS node (peer keeps
	# forwarding). Run on the node directly so the rolling driver sees the
	# local cluster state.
	info "Cutting over node${idx} via 'xpfd upgrade --rolling'..."
	incus exec "$rinst" -- /usr/local/share/xpf/staged/xpfd upgrade --rolling
	info "Cut-over complete for $vm."
}

# rolling_detect_secondary queries node0's `show chassis cluster status` and
# echoes the RG0 SECONDARY node index (0 or 1) — the node to upgrade FIRST so
# the primary keeps forwarding. The parse lives in deploy_rolling_secondary_node
# (deploy-lib.sh, unit-tested in deploy-lib-selftest.sh, #4009). Best-effort: a
# failed query falls through to the parser default (node1) without aborting the
# set -e pipeline.
#
# #4009: this REPLACES two divergent, defective detections — deploy_rolling's
# inline `grep "secondary:node0"` (never matched the space-separated status
# rows, so it silently upgraded node1 first even when node0 was the secondary →
# a spurious mid-deploy failover) and deploy_rolling_deb's `show chassis cluster
# information` / `Local state:` grep — with ONE tested SSOT parser.
rolling_detect_secondary() {
	incus exec "$(r "$VM0")" -- cli -c "show chassis cluster status" 2>/dev/null \
		| deploy_rolling_secondary_node || true
}

# reassert_primary_node0 leaves node0 the primary for EVERY redundancy group
# after a rolling deploy, so downstream smoke (apply-cos-config, test-failover)
# starts from the documented node0-primary steady state regardless of preempt
# config — removing the force-node0-primary workaround the HA batch scripts
# needed (#4009).
#
# #6591: the body moved into deploy-lib.sh so the self-test can drive it
# against the mocked incus, and it is FAIL-CLOSED — it dies rather than
# warning. It used to swallow an unreadable status, do nothing, and return
# success; the un-reasserted cluster was then discovered minutes later by an
# unrelated smoke target's preflight, where the first hypothesis is that the
# change under test broke HA.
reassert_primary_node0() {
	deploy_reassert_primary_node0 "$(r "$VM0")" "$(r "$VM1")"
}

# deploy_rolling_deb sequences the deb cut across both nodes (secondary
# first), so the cluster keeps forwarding through the whole upgrade, then
# re-asserts node0 primary for a deterministic post-deploy state (#4009).
deploy_rolling_deb() {
	local secondary primary
	secondary=$(rolling_detect_secondary)
	primary=$(( secondary == 0 ? 1 : 0 ))
	info "Rolling deb deploy: secondary=node${secondary}, primary=node${primary}"
	deploy_vm_deb "$secondary"
	sleep 5
	deploy_vm_deb "$primary"
	reassert_primary_node0
	info "Rolling deb deploy complete."
}

# Rolling deploy: secondary first, wait for sync, then primary.
# This preserves traffic flow — the primary continues forwarding while
# the secondary upgrades, then the upgraded secondary takes over when
# the primary restarts.
deploy_rolling() {
	# Determine which node is currently the RG0 secondary (deploy it first).
	# #4009: the old inline `grep "secondary:node0"` never matched the
	# space-separated `show chassis cluster status` rows, so this ALWAYS fell
	# through to node1-first — restarting the PRIMARY first (a spurious
	# mid-deploy failover) whenever node0 was the secondary. Now via the
	# tested parser in deploy-lib.sh.
	local secondary primary
	secondary=$(rolling_detect_secondary)
	primary=$(( secondary == 0 ? 1 : 0 ))

	info "Rolling deploy: secondary=node${secondary}, primary=node${primary}"

	# Phase 1: Deploy to secondary (traffic stays on primary).
	info "Phase 1: Deploying to secondary (node${secondary})..."
	deploy_vm "$secondary"

	# Wait for the secondary to come up and establish session sync.
	info "Waiting for node${secondary} to sync..."
	local vm_sec
	vm_sec=$(vm_name "$secondary")
	local retries=30
	while (( retries > 0 )); do
		if incus exec "$(r "$vm_sec")" -- cli -c "show chassis cluster status" 2>/dev/null | grep -q "primary\|secondary"; then
			break
		fi
		sleep 2
		(( retries-- ))
	done
	if (( retries == 0 )); then
		warn "Timed out waiting for node${secondary} — continuing anyway"
	fi
	# Extra settle time for session sync bulk transfer.
	sleep 5

	# Phase 2: Deploy to primary (secondary takes over via VRRP).
	info "Phase 2: Deploying to primary (node${primary})..."
	deploy_vm "$primary"

	# #4009: leave node0 the primary so downstream smoke starts from a known
	# state regardless of preempt config.
	reassert_primary_node0

	info "Rolling deploy complete."
}

deploy_vm() {
	local idx="$1"
	local vm
	vm=$(vm_name "$idx")
	local rinst
	rinst=$(r "$vm")

	if ! incus info "$rinst" &>/dev/null 2>&1; then
		die "Instance $vm does not exist. Run '$0 create' first."
	fi

	# #1864 pre-flight: verify the NEW binary's embedded shim object
	# against the node's kernel verifier BEFORE touching the running
	# daemon. The full ORDERING INVARIANT, CPU contract and rationale live
	# with the implementation in deploy-lib.sh; the invariant this call site
	# owns is its POSITION: nothing below it here (bpfrxd migration, pin
	# reconcile, systemctl stop, pkill, binary push) may be hoisted above it.
	# The 2026-06-10 incident was exactly a stop-then-load-fail that left the
	# node in config-only mode.
	#
	# #6493: extracted from this function into deploy-lib.sh so the standalone
	# test/incus deploy runs the SAME gate instead of a second hand copy.
	deploy_verify_dataplane_preflight "$rinst" "$PROJECT_ROOT/xpfd"

	# Migrate from old bpfrxd naming if present.
	incus exec "$rinst" -- systemctl stop bpfrxd 2>/dev/null || true
	incus exec "$rinst" -- /usr/local/sbin/bpfrxd cleanup 2>/dev/null || true
	incus exec "$rinst" -- systemctl disable bpfrxd 2>/dev/null || true
	incus exec "$rinst" -- rm -f /etc/systemd/system/bpfrxd.service 2>/dev/null || true
	incus exec "$rinst" -- rm -f /usr/local/sbin/bpfrxd 2>/dev/null || true
	incus exec "$rinst" -- rm -f /usr/local/sbin/bpfrx-userspace-dp 2>/dev/null || true
	incus exec "$rinst" -- bash -c 'if [ -d /etc/bpfrx ] && [ ! -d /etc/xpf ]; then mv /etc/bpfrx /etc/xpf; elif [ -d /etc/bpfrx ] && [ -d /etc/xpf ]; then shopt -s dotglob nullglob; for f in /etc/bpfrx/*; do base=$(basename "$f"); if [ ! -e "/etc/xpf/$base" ]; then cp -a "$f" "/etc/xpf/$base"; fi; done; shopt -u dotglob nullglob; rm -rf /etc/bpfrx; fi; if [ -f /etc/xpf/bpfrx.conf ] && [ ! -f /etc/xpf/xpf.conf ]; then mv /etc/xpf/bpfrx.conf /etc/xpf/xpf.conf; fi' 2>/dev/null || true

	# Reconcile prior #1917 in-place-upgrade residue BEFORE pushing binaries
	# (#2176). A stale 10-xpf-version.conf ExecStart pin (left by a deb dogfood)
	# would make systemd keep launching an OLD versioned binary after this raw
	# push, and dangling sbin symlinks into a removed versions/ dir would break
	# `incus file push`. This was hit live during the #2166 smoke and worked
	# around by hand — both silently produce a "successful" deploy of stale code.
	deploy_reconcile_stale_pin "$rinst"
	deploy_reconcile_dangling_sbin "$rinst"

	# Stop service gracefully, then clean BPF state for binary upgrade.
	# Order matters: systemctl stop sends SIGTERM (graceful socket close),
	# then xpfd cleanup removes pinned BPF maps/links.  The final
	# pkill -9 is a safety net only — if the daemon hung during shutdown
	# the binary is still "text file busy" and the push will fail.
	incus exec "$rinst" -- systemctl stop xpfd 2>/dev/null || true
	incus exec "$rinst" -- xpfd cleanup 2>/dev/null || true
	incus exec "$rinst" -- pkill -9 xpfd 2>/dev/null || true
	incus exec "$rinst" -- pkill -9 xpf-userspace-dp 2>/dev/null || true
	incus exec "$rinst" -- pkill -9 bpfrx-userspace-dp 2>/dev/null || true
	incus exec "$rinst" -- pkill -9 cli 2>/dev/null || true
	sleep 1

	# Push each binary, then HARD-verify its on-VM sha256 == the local build
	# (#2162/#2176). An `incus file push` can silently no-op and a local build
	# can be stale — either runs old code, the #1 false-result hazard.
	info "Pushing xpfd to $vm..."
	incus file push "$PROJECT_ROOT/xpfd" "${rinst}/usr/local/sbin/xpfd" --mode 0755
	deploy_verify_pushed_sha "$rinst" "$PROJECT_ROOT/xpfd" /usr/local/sbin/xpfd xpfd

	info "Pushing cli to $vm..."
	incus file push "$PROJECT_ROOT/cli" "${rinst}/usr/local/sbin/cli" --mode 0755
	deploy_verify_pushed_sha "$rinst" "$PROJECT_ROOT/cli" /usr/local/sbin/cli cli

	if [[ -f "$PROJECT_ROOT/xpf-userspace-dp" ]]; then
		info "Pushing xpf-userspace-dp to $vm..."
		incus file push "$PROJECT_ROOT/xpf-userspace-dp" "${rinst}/usr/local/sbin/xpf-userspace-dp" --mode 0755
		deploy_verify_pushed_sha "$rinst" "$PROJECT_ROOT/xpf-userspace-dp" /usr/local/sbin/xpf-userspace-dp xpf-userspace-dp
	else
		warn "xpf-userspace-dp not found locally; helper not pushed to $vm"
	fi

	# Push the single unified HA config (same file for both nodes)
	if [[ -f "$CLUSTER_CONF" ]]; then
		info "Pushing unified HA config to $vm..."
		incus exec "$rinst" -- mkdir -p /etc/xpf
		incus file push "$CLUSTER_CONF" "${rinst}/etc/xpf/xpf.conf"
		push_shared_umem_phase0_artifact "$idx" "$rinst"
		# Clear configstore DB so daemon bootstraps from the new text file.
		# Without this, the daemon loads the OLD config from active.json.
		incus exec "$rinst" -- rm -rf /etc/xpf/.configdb
	else
		warn "Config file $CLUSTER_CONF not found"
	fi

	# Ensure node-id file exists
	incus exec "$rinst" -- bash -c "echo $idx > /etc/xpf/node-id"

	# Disable radvd — embedded RA sender in xpfd replaces it
	incus exec "$rinst" -- systemctl disable --now radvd 2>/dev/null || true

	# Install systemd unit
	info "Installing systemd service on $vm..."
	incus file push "${SCRIPT_DIR}/xpfd.service" "${rinst}/etc/systemd/system/xpfd.service"
	incus exec "$rinst" -- systemctl daemon-reload
	incus exec "$rinst" -- systemctl enable --now xpfd

	# Backstop (#2176): assert the LIVE xpfd is the binary we just pushed and the
	# effective ExecStart is the base-unit path — a HARD failure if a version pin
	# survived or systemd is launching stale code.
	deploy_verify_running_xpfd "$rinst" "$PROJECT_ROOT/xpfd"

	info "Deploy complete for $vm."
}

# ── SSH / Status / Service ───────────────────────────────────────────

cmd_ssh() {
	local idx="${1:-}"
	[[ -z "$idx" ]] && die "Usage: $0 ssh 0|1"
	local vm
	vm=$(vm_name "$idx")
	if ! incus info "$(r "$vm")" &>/dev/null 2>&1; then
		die "Instance $vm does not exist."
	fi
	exec incus exec "$(r "$vm")" -- bash -l
}

cmd_status() {
	echo "── Instances ──"
	for inst in "$VM0" "$VM1" "$LAN_HOST"; do
		if incus info "$(r "$inst")" &>/dev/null 2>&1; then
			local state
			state=$(incus list "$(r "$inst")" -f csv -c s 2>/dev/null || echo "unknown")
			echo "  $inst: $state"
		else
			echo "  $inst: not created"
		fi
	done

	echo ""
	echo "── Service Status ──"
	for idx in 0 1; do
		local vm
		vm=$(vm_name "$idx")
		if incus info "$(r "$vm")" &>/dev/null 2>&1; then
			echo "  $vm:"
			incus exec "$(r "$vm")" -- systemctl is-active xpfd 2>/dev/null || echo "    (not installed)"
		fi
	done

	echo ""
	echo "── Networks ──"
	for entry in "${NETWORKS[@]}"; do
		IFS=: read -r name _ _ <<< "$entry"
		if incus network show "$(r "$name")" &>/dev/null 2>&1; then
			echo "  $name: $(incus network get "$(r "$name")" ipv4.address) nat=$(incus network get "$(r "$name")" ipv4.nat)"
		else
			echo "  $name: not created"
		fi
	done

	echo ""
	echo "── Profile ──"
	if incus profile show "$(r "$PROFILE")" &>/dev/null 2>&1; then
		echo "  $PROFILE: exists"
	else
		echo "  $PROFILE: not created"
	fi
}

cmd_logs() {
	local idx="${1:-}"
	[[ -z "$idx" ]] && die "Usage: $0 logs 0|1"
	local vm
	vm=$(vm_name "$idx")
	incus exec "$(r "$vm")" -- journalctl -u xpfd -n 50 --no-pager
}

cmd_journal() {
	local idx="${1:-}"
	[[ -z "$idx" ]] && die "Usage: $0 journal 0|1"
	local vm
	vm=$(vm_name "$idx")
	incus exec "$(r "$vm")" -- journalctl -u xpfd -f
}

cmd_start() {
	local target="${1:-all}"
	case "$target" in
		0)   incus exec "$(r "$VM0")" -- systemctl start xpfd; info "xpfd started on $VM0" ;;
		1)   incus exec "$(r "$VM1")" -- systemctl start xpfd; info "xpfd started on $VM1" ;;
		all) incus exec "$(r "$VM0")" -- systemctl start xpfd; incus exec "$(r "$VM1")" -- systemctl start xpfd; info "xpfd started on both VMs" ;;
		*)   die "Usage: $0 start [0|1|all]" ;;
	esac
}

cmd_stop() {
	local target="${1:-all}"
	case "$target" in
		0)   incus exec "$(r "$VM0")" -- systemctl stop xpfd; info "xpfd stopped on $VM0" ;;
		1)   incus exec "$(r "$VM1")" -- systemctl stop xpfd; info "xpfd stopped on $VM1" ;;
		all) incus exec "$(r "$VM0")" -- systemctl stop xpfd; incus exec "$(r "$VM1")" -- systemctl stop xpfd; info "xpfd stopped on both VMs" ;;
		*)   die "Usage: $0 stop [0|1|all]" ;;
	esac
}

cmd_restart() {
	local target="${1:-all}"
	case "$target" in
		0)   incus exec "$(r "$VM0")" -- systemctl restart xpfd; info "xpfd restarted on $VM0" ;;
		1)   incus exec "$(r "$VM1")" -- systemctl restart xpfd; info "xpfd restarted on $VM1" ;;
		all) incus exec "$(r "$VM0")" -- systemctl restart xpfd; incus exec "$(r "$VM1")" -- systemctl restart xpfd; info "xpfd restarted on both VMs" ;;
		*)   die "Usage: $0 restart [0|1|all]" ;;
	esac
}

# ── Main ─────────────────────────────────────────────────────────────

usage() {
	echo "Usage: $0 {init|create|destroy|deploy|ssh|status|logs|journal|start|stop|restart} [args]"
	echo ""
	echo "Commands:"
	echo "  init                 Create networks and profile"
	echo "  create               Launch both VMs + test container"
	echo "  destroy              Tear down VMs + container, optionally networks/profile"
	echo "  deploy [0|1|all]     Build xpfd and push to VM(s) (default: all)"
	echo "  ssh 0|1              Shell into VM"
	echo "  status               Show all VM/container/network status"
	echo "  logs 0|1             Show recent xpfd logs for VM"
	echo "  journal 0|1          Follow xpfd logs (live) for VM"
	echo "  start [0|1|all]      Start xpfd service (default: all)"
	echo "  stop [0|1|all]       Stop xpfd service (default: all)"
	echo "  restart [0|1|all]    Restart xpfd service (default: all)"
	exit 1
}

# #1875: mutating verbs serialize via require_cluster_cell (init
# creates/deletes networks+profiles; create/destroy launch/remove
# instances; start/stop/restart flip the daemon and VRRP mastership).
# deploy locks itself inside cmd_deploy (the build stays outside the
# lock). Read-only verbs (ssh/status/logs/journal) stay lock-free —
# ssh is interactive and must never hold the cluster lock.
case "${1:-}" in
	init)       require_cluster_cell init; cmd_init ;;
	create)     require_cluster_cell create; cmd_create ;;
	destroy)    require_cluster_cell destroy; cmd_destroy ;;
	deploy)     cmd_deploy "${2:-all}" ;;
	ssh)        cmd_ssh "${2:-}" ;;
	status)     cmd_status ;;
	logs)       cmd_logs "${2:-}" ;;
	journal)    cmd_journal "${2:-}" ;;
	start)      require_cluster_cell start "${2:-all}"; cmd_start "${2:-all}" ;;
	stop)       require_cluster_cell stop "${2:-all}"; cmd_stop "${2:-all}" ;;
	restart)    require_cluster_cell restart "${2:-all}"; cmd_restart "${2:-all}" ;;
	*)          usage ;;
esac
