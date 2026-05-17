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

FW0_NAME="${FW0_NAME:-${VM0:-xpf-fw0}}"
FW1_NAME="${FW1_NAME:-${VM1:-xpf-fw1}}"
CLUSTER_LAN_HOST_NAME="${CLUSTER_LAN_HOST_NAME:-${LAN_HOST:-cluster-lan-host}}"

FW0="${FW0:-$(_xpf_cluster_ref "$FW0_NAME")}"
FW1="${FW1:-$(_xpf_cluster_ref "$FW1_NAME")}"
CLUSTER_LAN_HOST="${CLUSTER_LAN_HOST:-$(_xpf_cluster_ref "$CLUSTER_LAN_HOST_NAME")}"

LAN_HOST_IP="${LAN_HOST_IP:-${LAN_ADDR:-}}"
LAN_HOST_IP="${LAN_HOST_IP%%/*}"
LAN_HOST_IP="${LAN_HOST_IP:-10.0.60.102}"
LAN_VIP4="${LAN_VIP4:-${LAN_GW:-10.0.60.1}}"
LAN_VIP6="${LAN_VIP6:-2001:559:8585:cf01::1}"
WAN_GW4="${WAN_GW4:-172.16.50.1}"
WAN_VIP4="${WAN_VIP4:-172.16.50.6}"
IPERF_TARGET4="${IPERF_TARGET4:-172.16.100.200}"
IPERF_TARGET6="${IPERF_TARGET6:-2001:559:8585:100::200}"

export PROJECT_ROOT BPFRX_CLUSTER_ENV CLUSTER_CONF
export FW0 FW1 CLUSTER_LAN_HOST
export FW0_NAME FW1_NAME CLUSTER_LAN_HOST_NAME
export LAN_HOST_IP LAN_VIP4 LAN_VIP6 WAN_GW4 WAN_VIP4
export IPERF_TARGET4 IPERF_TARGET6
