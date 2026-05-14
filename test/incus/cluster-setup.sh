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

# Source env file for custom deployments (remote, SR-IOV config, etc.)
if [[ -n "${BPFRX_CLUSTER_ENV:-}" && -f "$BPFRX_CLUSTER_ENV" ]]; then
	# shellcheck disable=SC1090
	source "$BPFRX_CLUSTER_ENV"
fi

# Re-exec under incus-admin group if needed (preserve BPFRX_CLUSTER_ENV)
if ! incus list &>/dev/null 2>&1; then
	if getent group incus-admin &>/dev/null && id -nG | grep -qw incus-admin; then
		local_env=""
		if [[ -n "${BPFRX_CLUSTER_ENV:-}" ]]; then
			local_env="BPFRX_CLUSTER_ENV=$(printf '%q' "$BPFRX_CLUSTER_ENV") "
		fi
		exec sg incus-admin -c "${local_env}$(printf '%q ' "$0" "$@")"
	fi
fi

# ── Defaults (local cluster values if no env file) ───────────────────

INCUS_REMOTE="${INCUS_REMOTE:-}"
VM0="${VM0:-xpf-fw0}"
VM1="${VM1:-xpf-fw1}"
LAN_HOST="${LAN_HOST:-cluster-lan-host}"
PROFILE="${PROFILE:-xpf-cluster}"
IMAGE_VM="${IMAGE_VM:-images:debian/13}"
IMAGE_CT="${IMAGE_CT:-images:debian/13}"
LAN_ADDR="${LAN_ADDR:-}"
LAN_GW="${LAN_GW:-}"

# SR-IOV: PCI passthrough for VM VFs, nictype=sriov for container VFs
SRIOV_PARENT="${SRIOV_PARENT:-eno6np1}"
SRIOV_LAN_PARENT="${SRIOV_LAN_PARENT:-}"   # Container LAN: nictype=sriov parent

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

cluster_config_requests_shared_umem() {
	[[ -f "$CLUSTER_CONF" ]] && grep -q 'shared-umem' "$CLUSTER_CONF"
}

push_shared_umem_phase0_artifact() {
	local idx="$1"
	local rinst="$2"
	local artifact
	artifact=$(shared_umem_phase0_artifact_for_node "$idx")

	if ! cluster_config_requests_shared_umem; then
		return
	fi
	if [[ ! -f "$artifact" ]]; then
		die "Shared-UMEM config is enabled but Phase 0 artifact is missing for node${idx}: $artifact"
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

	# WAN VF (always present)
	local wan_pci="${VF_WAN_PCI[$idx]}"
	info "Adding WAN SR-IOV VF PCI $wan_pci to $vm..."
	incus config device add "$(r "$vm")" wan-vf pci address="$wan_pci"

	# Allow VLAN-tagged traffic from WAN VF guests. The HA lab uses guest
	# VLAN subinterfaces (e.g. reth0.50/reth0.80), which requires trust on
	# the passed-through VF.
	if [[ "${VF_WAN_TRUST}" == "true" && -n "${SRIOV_PARENT:-}" ]]; then
		local wan_vf_idx=""
		for vf_path in /sys/class/net/"${SRIOV_PARENT}"/device/virtfn*; do
			local vf_pci
			if [[ -n "${INCUS_REMOTE:-}" ]]; then
				vf_pci=$(ssh "$INCUS_REMOTE" "readlink -f '$vf_path' | xargs basename")
			else
				vf_pci=$(readlink -f "$vf_path" | xargs basename)
			fi
			if [[ "$vf_pci" == "$wan_pci" ]]; then
				wan_vf_idx=$(basename "$vf_path" | sed 's/virtfn//')
				break
			fi
		done
		if [[ -n "${wan_vf_idx:-}" ]]; then
			info "Setting host WAN VF trust on $SRIOV_PARENT vf $wan_vf_idx ($wan_pci)..."
			if [[ -n "${INCUS_REMOTE:-}" ]]; then
				ssh "$INCUS_REMOTE" "sudo ip link set dev $SRIOV_PARENT vf $wan_vf_idx trust on"
			else
				sudo ip link set dev "$SRIOV_PARENT" vf "$wan_vf_idx" trust on
			fi
		fi
	fi

	# LAN VF (optional — only if VF_LAN_PCI is configured)
	if [[ ${#VF_LAN_PCI[@]} -gt 0 ]]; then
		local lan_pci="${VF_LAN_PCI[$idx]}"
		info "Adding LAN SR-IOV VF PCI $lan_pci to $vm..."
		incus config device add "$(r "$vm")" lan-vf pci address="$lan_pci"
	fi

	# Set host-level VF VLAN for LAN VFs (PCI passthrough doesn't get incus vlan= option)
	if [[ -n "${VF_LAN_VLAN:-}" && -n "${SRIOV_LAN_PARENT:-}" && ${#VF_LAN_PCI[@]} -gt 0 ]]; then
		local lan_pci="${VF_LAN_PCI[$idx]}"
		# Find VF index from PCI address
		local vf_idx
		for vf_path in /sys/class/net/"${SRIOV_LAN_PARENT}"/device/virtfn*; do
			local vf_pci
			if [[ -n "${INCUS_REMOTE:-}" ]]; then
				vf_pci=$(ssh "$INCUS_REMOTE" "readlink -f '$vf_path' | xargs basename")
			else
				vf_pci=$(readlink -f "$vf_path" | xargs basename)
			fi
			if [[ "$vf_pci" == "$lan_pci" ]]; then
				vf_idx=$(basename "$vf_path" | sed 's/virtfn//')
				break
			fi
		done
		if [[ -n "${vf_idx:-}" ]]; then
			info "Setting host VF VLAN $VF_LAN_VLAN on $SRIOV_LAN_PARENT vf $vf_idx ($lan_pci)..."
			if [[ -n "${INCUS_REMOTE:-}" ]]; then
				ssh "$INCUS_REMOTE" "sudo ip link set dev $SRIOV_LAN_PARENT vf $vf_idx vlan $VF_LAN_VLAN"
			else
				sudo ip link set dev "$SRIOV_LAN_PARENT" vf "$vf_idx" vlan "$VF_LAN_VLAN"
			fi
		fi
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
	incus exec "$rinst" -- bash -c 'cat > /etc/sysctl.d/99-bpf.conf <<EOF
net.core.bpf_jit_enable=1
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
EOF'
	incus exec "$rinst" -- sysctl --system

	info "Installing packages ($vm, this may take a few minutes)..."
	incus exec "$rinst" -- bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential clang llvm libbpf-dev linux-headers-amd64 golang tcpdump iproute2 iperf3 bpftool frr strongswan strongswan-swanctl kea-dhcp4-server kea-dhcp6-server chrony ethtool mtr-tiny linux-perf host pciutils curl wget ripgrep'

	# Upgrade kernel to latest from Debian unstable
	info "Adding Debian unstable repo for kernel upgrade ($vm)..."
	incus exec "$rinst" -- bash -c 'cat > /etc/apt/sources.list.d/unstable.list <<EOF
deb http://deb.debian.org/debian unstable main
EOF
cat > /etc/apt/preferences.d/pin-stable <<EOF
Package: *
Pin: release a=trixie
Pin-Priority: 900

Package: linux-image-amd64 linux-headers-amd64 linux-image-* linux-headers-*
Pin: release a=unstable
Pin-Priority: 990
EOF'
	info "Installing latest kernel from unstable ($vm)..."
	incus exec "$rinst" -- bash -c 'DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-image-amd64 linux-headers-amd64'

	# Disable init_on_alloc for XDP performance
	info "Disabling init_on_alloc for XDP performance ($vm)..."
	incus exec "$rinst" -- sed -i 's/GRUB_CMDLINE_LINUX_DEFAULT="[^"]*"/GRUB_CMDLINE_LINUX_DEFAULT="quiet init_on_alloc=0"/' /etc/default/grub
	incus exec "$rinst" -- update-grub

	info "Rebooting VM for new kernel ($vm)..."
	incus restart "$(r "$vm")"
	local ktries=0
	while ! incus exec "$rinst" -- true &>/dev/null; do
		sleep 2
		ktries=$((ktries + 1))
		if [[ $ktries -ge 30 ]]; then
			warn "VM $vm did not come back after kernel upgrade reboot"
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

	if [[ -n "${SRIOV_LAN_PARENT:-}" ]]; then
		suppress_host_parent_ipv6_ra "$SRIOV_LAN_PARENT"
	fi

	info "Building xpfd and cli..."
	make -C "$PROJECT_ROOT" build build-ctl
	if [[ -x "$HOME/.cargo/bin/cargo" || -n "$(command -v cargo 2>/dev/null)" ]]; then
		info "Building xpf-userspace-dp helper..."
		make -C "$PROJECT_ROOT" build-userspace-dp
	else
		warn "Rust toolchain not found; skipping xpf-userspace-dp build"
	fi

	case "$target" in
		0)   deploy_vm 0 ;;
		1)   deploy_vm 1 ;;
		all) deploy_rolling ;;
		*)   die "Usage: $0 deploy [0|1|all]" ;;
	esac
}

# Rolling deploy: secondary first, wait for sync, then primary.
# This preserves traffic flow — the primary continues forwarding while
# the secondary upgrades, then the upgraded secondary takes over when
# the primary restarts.
deploy_rolling() {
	# Determine which node is currently secondary (deploy it first).
	local secondary=1
	local primary=0
	if incus exec "$(r "$VM0")" -- cli -c "show chassis cluster status" 2>/dev/null | grep -q "secondary:node0"; then
		secondary=0
		primary=1
	fi

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

	# Migrate from old bpfrxd naming if present.
	incus exec "$rinst" -- systemctl stop bpfrxd 2>/dev/null || true
	incus exec "$rinst" -- /usr/local/sbin/bpfrxd cleanup 2>/dev/null || true
	incus exec "$rinst" -- systemctl disable bpfrxd 2>/dev/null || true
	incus exec "$rinst" -- rm -f /etc/systemd/system/bpfrxd.service 2>/dev/null || true
	incus exec "$rinst" -- rm -f /usr/local/sbin/bpfrxd 2>/dev/null || true
	incus exec "$rinst" -- rm -f /usr/local/sbin/bpfrx-userspace-dp 2>/dev/null || true
	incus exec "$rinst" -- bash -c 'if [ -d /etc/bpfrx ] && [ ! -d /etc/xpf ]; then mv /etc/bpfrx /etc/xpf; elif [ -d /etc/bpfrx ] && [ -d /etc/xpf ]; then shopt -s dotglob nullglob; for f in /etc/bpfrx/*; do base=$(basename "$f"); if [ ! -e "/etc/xpf/$base" ]; then cp -a "$f" "/etc/xpf/$base"; fi; done; shopt -u dotglob nullglob; rm -rf /etc/bpfrx; fi; if [ -f /etc/xpf/bpfrx.conf ] && [ ! -f /etc/xpf/xpf.conf ]; then mv /etc/xpf/bpfrx.conf /etc/xpf/xpf.conf; fi' 2>/dev/null || true

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

	info "Pushing xpfd to $vm..."
	incus file push "$PROJECT_ROOT/xpfd" "${rinst}/usr/local/sbin/xpfd" --mode 0755

	info "Pushing cli to $vm..."
	incus file push "$PROJECT_ROOT/cli" "${rinst}/usr/local/sbin/cli" --mode 0755

	if [[ -f "$PROJECT_ROOT/xpf-userspace-dp" ]]; then
		info "Pushing xpf-userspace-dp to $vm..."
		incus file push "$PROJECT_ROOT/xpf-userspace-dp" "${rinst}/usr/local/sbin/xpf-userspace-dp" --mode 0755
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

case "${1:-}" in
	init)       cmd_init ;;
	create)     cmd_create ;;
	destroy)    cmd_destroy ;;
	deploy)     cmd_deploy "${2:-all}" ;;
	ssh)        cmd_ssh "${2:-}" ;;
	status)     cmd_status ;;
	logs)       cmd_logs "${2:-}" ;;
	journal)    cmd_journal "${2:-}" ;;
	start)      cmd_start "${2:-all}" ;;
	stop)       cmd_stop "${2:-all}" ;;
	restart)    cmd_restart "${2:-all}" ;;
	*)          usage ;;
esac
