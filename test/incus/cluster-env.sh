# shellcheck shell=bash
# Shared cluster test defaults.
#
# Makefile cluster validation is canonicalized on the isolated loss userspace
# cluster. Set BPFRX_CLUSTER_ENV, or CLUSTER_ENV via make, to point at another
# cluster env file. Set BPFRX_CLUSTER_ENV= to use cluster-setup.sh local defaults.

_xpf_cluster_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "${_xpf_cluster_script_dir}/../.." && pwd)}"

_xpf_default_cluster_env="${PROJECT_ROOT}/test/incus/loss-userspace-cluster.env"
if [[ -v BPFRX_CLUSTER_ENV ]]; then
	_xpf_cluster_env="$BPFRX_CLUSTER_ENV"
else
	_xpf_cluster_env="${_xpf_default_cluster_env}"
fi

if [[ -n "$_xpf_cluster_env" ]]; then
	case "$_xpf_cluster_env" in
		/*) ;;
		*) _xpf_cluster_env="${PROJECT_ROOT}/${_xpf_cluster_env}" ;;
	esac
	if [[ ! -f "$_xpf_cluster_env" ]]; then
		echo "ERROR: BPFRX_CLUSTER_ENV does not exist: $_xpf_cluster_env" >&2
		return 1
	fi
	# shellcheck disable=SC1090
	source "$_xpf_cluster_env"
	export BPFRX_CLUSTER_ENV="$_xpf_cluster_env"
fi

if [[ -n "${CLUSTER_CONF:-}" && "$CLUSTER_CONF" != /* ]]; then
	CLUSTER_CONF="${PROJECT_ROOT}/${CLUSTER_CONF}"
fi

_xpf_cluster_ref() {
	local inst="$1"
	if [[ -n "${INCUS_REMOTE:-}" && "$inst" != *:* ]]; then
		printf '%s:%s\n' "$INCUS_REMOTE" "$inst"
	else
		printf '%s\n' "$inst"
	fi
}

# Instance NAMES. The LAN host name is intentionally sourced from the
# cluster env's LAN_HOST (the loss userspace cluster sets
# LAN_HOST=cluster-userspace-host); this is the bridge that lets the
# HA test scripts read one variable ($CLUSTER_LAN_HOST) while every env
# file declares its LAN host as LAN_HOST. Do NOT re-file this as a
# variable-name mismatch — that was the (already-resolved) #5024 report.
FW0_NAME="${FW0_NAME:-${VM0:-xpf-fw0}}"
FW1_NAME="${FW1_NAME:-${VM1:-xpf-fw1}}"
CLUSTER_LAN_HOST_NAME="${CLUSTER_LAN_HOST_NAME:-${LAN_HOST:-cluster-lan-host}}"

# Resolve each instance ref THROUGH _xpf_cluster_ref, even when the
# caller sets FW0/FW1/CLUSTER_LAN_HOST explicitly, so a BARE override
# (e.g. `CLUSTER_LAN_HOST=cluster-userspace-host make test-failover`)
# still gets the cluster's incus remote prefixed. _xpf_cluster_ref is a
# no-op when the value already carries a `remote:` prefix or when the
# env declares no INCUS_REMOTE (the legacy local xpf-fw0/1 cluster), so
# the unset-default, fully-qualified-override, and legacy paths are all
# unchanged. Before #5024 a bare override skipped the prefix entirely
# and died `<host> is not running` on the default remote.
FW0="$(_xpf_cluster_ref "${FW0:-$FW0_NAME}")"
FW1="$(_xpf_cluster_ref "${FW1:-$FW1_NAME}")"
CLUSTER_LAN_HOST="$(_xpf_cluster_ref "${CLUSTER_LAN_HOST:-$CLUSTER_LAN_HOST_NAME}")"

LAN_HOST_IP="${LAN_HOST_IP:-${LAN_ADDR:-}}"
LAN_HOST_IP="${LAN_HOST_IP%%/*}"
LAN_HOST_IP="${LAN_HOST_IP:-10.0.60.102}"
LAN_VIP4="${LAN_VIP4:-${LAN_GW:-10.0.60.1}}"
LAN_VIP6="${LAN_VIP6:-2001:559:8585:cf01::1}"
WAN_GW4="${WAN_GW4:-172.16.50.1}"
WAN_VIP4="${WAN_VIP4:-172.16.50.6}"
IPERF_TARGET4="${IPERF_TARGET4:-172.16.100.200}"
IPERF_TARGET6="${IPERF_TARGET6:-2001:559:8585:100::200}"

# Wire-gate addressing (#16305). The VLAN-80/50 networks and the SR-IOV WAN
# parent are shared lab topology; only the per-cluster host octets differ.
# The DMZ (VLAN-50) prober reuses the mouse target's host octet (iperf
# target octet + 1) on its own subnet so each cluster's probers stay
# distinct (loss .201, tcp .211, udp .212). Explicit caller overrides
# (DMZ_ADDR, MOUSE_TARGET_*, ...) win; on the loss env every derived
# value equals the historical literal it replaces.
#
# Per-VLAN firewall gateways for the wire gates' reverse routes. The
# VLAN-80 (untrust/mouse) endpoint and the VLAN-50 (DMZ) endpoint sit on
# separate /24s, so each needs the firewall address on ITS OWN subnet as
# next hop: DMZ_GW4 on VLAN 50, WAN_GW80_4 on VLAN 80. WAN_VIP4 is NOT
# usable for either: on loss it is 172.16.50.6 (a VIP, not the .8 reth
# gateway the gate historically used), and a VLAN-50 address is not
# on-link for a VLAN-80 host (ip(8) refuses it). Cluster envs set both
# explicitly from their firewall config (loss .8/.8, tcp .10/.10,
# udp .11/.11); the defaults here keep loss/legacy byte-identical.
DMZ_GW4="${DMZ_GW4:-172.16.50.8}"
WAN_GW80_4="${WAN_GW80_4:-172.16.80.8}"
_xpf_iperf_host="${IPERF_TARGET4##*.}"
_xpf_iperf_host="${_xpf_iperf_host%%/*}"
WAN_PREFIX4="${WAN_PREFIX4:-172.16.80.0/24}"
DMZ_PREFIX4="${DMZ_PREFIX4:-172.16.50.0/24}"
LAN_PREFIX4="${LAN_PREFIX4:-${LAN_HOST_IP%.*}.0/24}"
DMZ_ADDR="${DMZ_ADDR:-172.16.50.$((_xpf_iperf_host + 1))}"
DMZ_TARGET_V6="${DMZ_TARGET_V6:-2001:559:8585:50::$((_xpf_iperf_host + 1))}"
DMZ_TARGET_PF="${DMZ_TARGET_PF:-${SRIOV_PARENT:-mlx0}}"
DMZ_TARGET_VLAN="${DMZ_TARGET_VLAN:-50}"
# Instance names (#16328): the VLAN-80 target is provisioned per cluster
# (loss xpf-mouse-target, tcp xpf-tcp-target, udp xpf-udp-target — the
# tcp/udp env files declare MOUSE_TARGET_NAME); the VLAN-50 DMZ prober
# keeps one name on every remote (xpf-zone-matrix-dmz, created by
# wire-zone-matrix via mouse-target-setup.sh). Refs are remote-qualified
# through _xpf_cluster_ref; explicit caller overrides win.
DMZ_TARGET_NAME="${DMZ_TARGET_NAME:-xpf-zone-matrix-dmz}"
DMZ_TARGET_REF="${DMZ_TARGET_REF:-$(_xpf_cluster_ref "$DMZ_TARGET_NAME")}"
MOUSE_TARGET_NAME="${MOUSE_TARGET_NAME:-xpf-mouse-target}"
MOUSE_TARGET_REF="${MOUSE_TARGET_REF:-$(_xpf_cluster_ref "$MOUSE_TARGET_NAME")}"
unset _xpf_iperf_host

export PROJECT_ROOT BPFRX_CLUSTER_ENV CLUSTER_CONF INCUS_REMOTE
export FW0 FW1 CLUSTER_LAN_HOST
export FW0_NAME FW1_NAME CLUSTER_LAN_HOST_NAME
export LAN_HOST_IP LAN_VIP4 LAN_VIP6 WAN_GW4 WAN_VIP4
export IPERF_TARGET4 IPERF_TARGET6
export WAN_PREFIX4 DMZ_PREFIX4 LAN_PREFIX4 DMZ_ADDR DMZ_TARGET_V6
export DMZ_TARGET_PF DMZ_TARGET_VLAN DMZ_TARGET_NAME DMZ_TARGET_REF
export MOUSE_TARGET_NAME MOUSE_TARGET_REF
export MOUSE_TARGET_V4 MOUSE_TARGET_V6 MOUSE_TARGET_PF DMZ_GW4 WAN_GW80_4
