#!/usr/bin/env bash
#
# #5024 — self-test for the shared cluster-env resolver
# (test/incus/cluster-env.sh).
#
# The HA/failover smoke scripts (test-failover.sh and siblings) read
# ONE set of variables — $FW0, $FW1, $CLUSTER_LAN_HOST — but every
# cluster env file declares its own instance names (VM0/VM1/LAN_HOST)
# and its incus remote (INCUS_REMOTE). cluster-env.sh is the bridge:
# it must
#   (1) source the LAN host from LAN_HOST (NOT a hard-coded
#       cluster-lan-host — the #5024 misdiagnosis), and
#   (2) remote-qualify every instance ref with INCUS_REMOTE, INCLUDING
#       a caller's bare override, so `CLUSTER_LAN_HOST=<name>
#       make test-failover` reaches loss:<name> and not a stray
#       default-remote instance (the #5024 second failure).
#
# This is the RED-on-regression guard for both: reverting the
# LAN_HOST fallback or the always-remote-qualify makes a case below
# fail, naming the broken invariant. It is fully hermetic — no incus,
# no cluster, no network; it only sources cluster-env.sh in a clean
# `env -i` subshell and inspects the resolved variables.
#
# Usage: ./test/incus/cluster-env-selftest.sh   (rc 0 = all pass)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
ENV_SH="${PROJECT_ROOT}/test/incus/cluster-env.sh"

[[ -f "$ENV_SH" ]] || { echo "FAIL: cluster-env.sh not found at $ENV_SH" >&2; exit 1; }

PASS=0
ok()   { PASS=$((PASS + 1)); echo "PASS ($PASS): $*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# resolve <VAR> [ENV=VAL ...]
#   Source cluster-env.sh in a hermetic `env -i` subshell (only PATH +
#   PROJECT_ROOT carried, plus any caller-supplied overrides) and print
#   the resolved value of <VAR>. Keeping the environment empty means the
#   test never inherits a stray FW0/BPFRX_CLUSTER_ENV from the runner.
resolve() {
	local var="$1"; shift
	env -i PATH="$PATH" PROJECT_ROOT="$PROJECT_ROOT" "$@" \
		bash -c 'source "$PROJECT_ROOT/test/incus/cluster-env.sh" >/dev/null 2>&1
		         printf "%s" "${'"$var"'-}"'
}

eq() { # eq <label> <got> <want>
	[[ "$2" == "$3" ]] || fail "$1: got '$2', want '$3'"
	ok "$1 = $2"
}

# ── Case A: default env == loss userspace cluster ────────────────────
# No BPFRX_CLUSTER_ENV in the environment -> cluster-env.sh picks the
# canonical loss-userspace-cluster.env. Every ref must be loss:-qualified
# and the LAN host must be the env's cluster-userspace-host, NOT the
# legacy cluster-lan-host.
eq "loss FW0"              "$(resolve FW0)"              "loss:xpf-userspace-fw0"
eq "loss FW1"              "$(resolve FW1)"              "loss:xpf-userspace-fw1"
eq "loss CLUSTER_LAN_HOST" "$(resolve CLUSTER_LAN_HOST)" "loss:cluster-userspace-host"
eq "loss LAN_HOST_IP"      "$(resolve LAN_HOST_IP)"      "10.0.61.102"
eq "loss IPERF_TARGET4"    "$(resolve IPERF_TARGET4)"    "172.16.80.200"
eq "loss IPERF_TARGET6"    "$(resolve IPERF_TARGET6)"    "2001:559:8585:80::200"

# ── Case A2: tcp/udp envs derive their own wire addressing (#16305/#16306) ─
# Group12/wire gates must measure each cluster's own targets: tcp .210,
# udp .211, never the loss .200/.201 literals. DMZ (VLAN-50) probers reuse
# the iperf target octet + 1 (the mouse-target octet); the policy-deny
# sink is that same mouse target on VLAN 80.
# #16328: the VLAN-80 instance NAME is per-cluster too — tcp provisions
# xpf-tcp-target, udp xpf-udp-target (docs/incus-tcp-udp-plan.md); only
# loss has xpf-mouse-target. The DMZ prober name is shared.
for spec in "tcp 10.0.62 210 xpf-tcp-target" "udp 10.0.63 211 xpf-udp-target"; do
	read -r cname lanpfx octet tname <<<"$spec"
	envfile="BPFRX_CLUSTER_ENV=test/incus/${cname}-userspace-cluster.env"
	eq "${cname} LAN_PREFIX4"   "$(resolve LAN_PREFIX4 "$envfile")"   "${lanpfx}.0/24"
	eq "${cname} DMZ_ADDR"      "$(resolve DMZ_ADDR "$envfile")"      "172.16.50.$((octet + 1))"
	eq "${cname} DMZ_TARGET_V6" "$(resolve DMZ_TARGET_V6 "$envfile")" "2001:559:8585:50::$((octet + 1))"
	eq "${cname} MOUSE_TARGET_V4" "$(resolve MOUSE_TARGET_V4 "$envfile")" "172.16.80.${octet}"
	eq "${cname} MOUSE_TARGET_NAME" "$(resolve MOUSE_TARGET_NAME "$envfile")" "${tname}"
	eq "${cname} MOUSE_TARGET_REF" "$(resolve MOUSE_TARGET_REF "$envfile")" "${cname}:${tname}"
	eq "${cname} DMZ_TARGET_REF" "$(resolve DMZ_TARGET_REF "$envfile")" "${cname}:xpf-zone-matrix-dmz"
	eq "${cname} INCUS_REMOTE"  "$(resolve INCUS_REMOTE "$envfile")"  "${cname}"
	eq "${cname} IPERF_TARGET4" "$(resolve IPERF_TARGET4 "$envfile")" "172.16.80.${octet}"
	eq "${cname} DMZ_GW4"       "$(resolve DMZ_GW4 "$envfile")"       "172.16.50.$((octet - 200))"
	eq "${cname} WAN_GW80_4"    "$(resolve WAN_GW80_4 "$envfile")"    "172.16.80.$((octet - 200))"
	eq "${cname} IPERF_TARGET6" "$(resolve IPERF_TARGET6 "$envfile")" "2001:559:8585:80::${octet}"
done
# Loss derivation must reproduce the historical literals exactly.
eq "loss LAN_PREFIX4"     "$(resolve LAN_PREFIX4)"     "10.0.61.0/24"
eq "loss DMZ_ADDR"        "$(resolve DMZ_ADDR)"        "172.16.50.201"
eq "loss DMZ_TARGET_V6"   "$(resolve DMZ_TARGET_V6)"   "2001:559:8585:50::201"
eq "loss MOUSE_TARGET_V4" "$(resolve MOUSE_TARGET_V4)" "172.16.80.201"
eq "loss MOUSE_TARGET_NAME" "$(resolve MOUSE_TARGET_NAME)" "xpf-mouse-target"
eq "loss MOUSE_TARGET_REF" "$(resolve MOUSE_TARGET_REF)" "loss:xpf-mouse-target"
eq "loss DMZ_TARGET_REF"  "$(resolve DMZ_TARGET_REF)"  "loss:xpf-zone-matrix-dmz"
eq "loss INCUS_REMOTE"    "$(resolve INCUS_REMOTE)"    "loss"
eq "loss DMZ_TARGET_PF"   "$(resolve DMZ_TARGET_PF)"   "mlx0"
eq "loss DMZ_GW4"         "$(resolve DMZ_GW4)"         "172.16.50.8"
eq "loss WAN_GW80_4"      "$(resolve WAN_GW80_4)"      "172.16.80.8"
eq "loss WAN_VIP4 (not the gateway)" "$(resolve WAN_VIP4)" "172.16.50.6"
eq "loss DMZ_TARGET_VLAN" "$(resolve DMZ_TARGET_VLAN)" "50"
# #16213: the declarative primary alias derives from the cluster's iperf
# target — loss .200 (alias of the .201 mouse host); tcp/udp equal their
# pinned mouse address, so no second address is ever emitted there.
eq "loss TARGET_ALIAS_V4" "$(resolve TARGET_ALIAS_V4)" "172.16.80.200"
eq "tcp TARGET_ALIAS_V4"  "$(resolve TARGET_ALIAS_V4 BPFRX_CLUSTER_ENV=test/incus/tcp-userspace-cluster.env)" "172.16.80.210"
eq "udp TARGET_ALIAS_V4"  "$(resolve TARGET_ALIAS_V4 BPFRX_CLUSTER_ENV=test/incus/udp-userspace-cluster.env)" "172.16.80.211"
# Legacy (no remote): names stay bare, refs unqualified (#16328).
eq "legacy MOUSE_TARGET_REF" "$(resolve MOUSE_TARGET_REF BPFRX_CLUSTER_ENV=)" "xpf-mouse-target"
eq "legacy DMZ_TARGET_REF"   "$(resolve DMZ_TARGET_REF BPFRX_CLUSTER_ENV=)"   "xpf-zone-matrix-dmz"

# #5024 guards: the LAN host must NOT be the unreachable legacy default,
# and it must carry the loss: remote (a bare name hits the wrong remote).
lan="$(resolve CLUSTER_LAN_HOST)"
[[ "$lan" != "cluster-lan-host" ]] \
	|| fail "loss CLUSTER_LAN_HOST resolved to the legacy cluster-lan-host (#5024 LAN_HOST fallback dropped)"
[[ "$lan" == loss:* ]] \
	|| fail "loss CLUSTER_LAN_HOST '$lan' is not remote-qualified (#5024 INCUS_REMOTE prefix dropped)"
ok "loss LAN host is remote-qualified and not the legacy default"

# ── Case B: legacy local cluster (BPFRX_CLUSTER_ENV empty) ────────────
# Empty BPFRX_CLUSTER_ENV -> cluster-setup.sh local defaults, no
# INCUS_REMOTE -> bare instance names, no remote prefix.
eq "legacy FW0"              "$(resolve FW0 BPFRX_CLUSTER_ENV=)"              "xpf-fw0"
eq "legacy FW1"              "$(resolve FW1 BPFRX_CLUSTER_ENV=)"              "xpf-fw1"
eq "legacy CLUSTER_LAN_HOST" "$(resolve CLUSTER_LAN_HOST BPFRX_CLUSTER_ENV=)" "cluster-lan-host"
legacy_lan="$(resolve CLUSTER_LAN_HOST BPFRX_CLUSTER_ENV=)"
[[ "$legacy_lan" != *:* ]] \
	|| fail "legacy CLUSTER_LAN_HOST '$legacy_lan' unexpectedly carries a remote prefix"
ok "legacy LAN host stays bare (no INCUS_REMOTE, no prefix)"

# ── Case C: bare override on the loss cluster (the #5024 comment) ─────
# `CLUSTER_LAN_HOST=cluster-userspace-host make test-failover` must
# reach loss:cluster-userspace-host, NOT a bare name on the default
# remote (which died `... is not running`).
eq "loss + bare LAN override" \
	"$(resolve CLUSTER_LAN_HOST CLUSTER_LAN_HOST=cluster-userspace-host)" \
	"loss:cluster-userspace-host"
eq "loss + bare FW0 override" \
	"$(resolve FW0 FW0=custom-fw)" \
	"loss:custom-fw"

# ── Case D: fully-qualified override is idempotent (no double prefix) ─
eq "loss + qualified LAN override" \
	"$(resolve CLUSTER_LAN_HOST CLUSTER_LAN_HOST=loss:cluster-userspace-host)" \
	"loss:cluster-userspace-host"

# ── Case E: bare override on the legacy cluster stays bare ────────────
# No INCUS_REMOTE -> _xpf_cluster_ref is a no-op even for an override.
eq "legacy + bare LAN override" \
	"$(resolve CLUSTER_LAN_HOST BPFRX_CLUSTER_ENV= CLUSTER_LAN_HOST=myhost)" \
	"myhost"

echo "ALL ${PASS} CASES PASS"
