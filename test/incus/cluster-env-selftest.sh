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
# #18576: loss's v4 target is .202, which only xpf-mouse-target holds
# (.200 is also answered by the external v6 box). v6 stays ::200.
eq "loss IPERF_TARGET4"    "$(resolve IPERF_TARGET4)"    "172.16.80.202"
eq "loss IPERF_TARGET6"    "$(resolve IPERF_TARGET6)"    "2001:559:8585:80::200"

# ── Case A2: tcp/udp envs derive their own wire addressing (#16305/#16306) ─
# Group12/wire gates must measure each cluster's own targets: tcp .210,
# udp .211, never the loss .200/.201 literals. DMZ (VLAN-50) probers reuse
# the iperf target octet + 1 (the mouse-target octet); the policy-deny
# sink is that same mouse target on VLAN 80.
# #16328: the VLAN-80 instance NAME is per-cluster too — tcp provisions
# xpf-tcp-target, udp xpf-udp-target (docs/incus-tcp-udp-plan.md); only
# loss has xpf-mouse-target. The DMZ prober name is shared.
# #18558: the VLAN-50 RETH octet is NOT derived from the target octet any
# more. tcp/udp held .10/.11 (octet - 200) until a live ARP probe showed both
# addresses held by non-xpf devices on the shared segment; they moved to
# .42/.43, so the gateway octet is pinned per cluster in the spec.
for spec in "tcp 10.0.62 210 xpf-tcp-target 42" "udp 10.0.63 211 xpf-udp-target 43"; do
	read -r cname lanpfx octet tname wan50 <<<"$spec"
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
	eq "${cname} DMZ_GW4"       "$(resolve DMZ_GW4 "$envfile")"       "172.16.50.${wan50}"
	eq "${cname} WAN_VIP4"      "$(resolve WAN_VIP4 "$envfile")"      "172.16.50.${wan50}"
	eq "${cname} WAN_GW80_4"    "$(resolve WAN_GW80_4 "$envfile")"    "172.16.80.$((octet - 200))"
	eq "${cname} IPERF_TARGET6" "$(resolve IPERF_TARGET6 "$envfile")" "2001:559:8585:80::${octet}"
done
# Loss derivation must reproduce the historical literals exactly. The DMZ
# prober stays at .201 although the iperf target is .202 (#18576): the loss
# env pins it rather than taking the iperf octet + 1, which would be .203.
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
eq "loss WAN_VIP4" "$(resolve WAN_VIP4)" "172.16.50.8"
eq "loss DMZ_TARGET_VLAN" "$(resolve DMZ_TARGET_VLAN)" "50"
# The loss env pins its DMZ prober with ${VAR:-...}, so a caller override
# still wins, as it does for every derived name.
eq "loss + DMZ_ADDR override" "$(resolve DMZ_ADDR DMZ_ADDR=172.16.50.99)" "172.16.50.99"
eq "loss + DMZ_TARGET_V6 override" "$(resolve DMZ_TARGET_V6 DMZ_TARGET_V6=2001:559:8585:50::99)" "2001:559:8585:50::99"
# #8259/#18576: the elephant (iperf) and mouse targets stay distinct
# addresses on loss.
loss_t4="$(resolve IPERF_TARGET4)"
[[ "$loss_t4" != "$(resolve MOUSE_TARGET_V4)" ]] \
	|| fail "loss IPERF_TARGET4 ${loss_t4} collapsed onto MOUSE_TARGET_V4 (#8259 needs two addresses)"
ok "loss IPERF_TARGET4 differs from MOUSE_TARGET_V4"
# #16213: the declarative primary alias derives from the cluster's iperf
# target — loss .202 (alias of the .201 mouse host, .200 until #18576);
# tcp/udp equal their pinned mouse address, so no second address is ever
# emitted there.
eq "loss TARGET_ALIAS_V4" "$(resolve TARGET_ALIAS_V4)" "172.16.80.202"
eq "tcp TARGET_ALIAS_V4"  "$(resolve TARGET_ALIAS_V4 BPFRX_CLUSTER_ENV=test/incus/tcp-userspace-cluster.env)" "172.16.80.210"
eq "udp TARGET_ALIAS_V4"  "$(resolve TARGET_ALIAS_V4 BPFRX_CLUSTER_ENV=test/incus/udp-userspace-cluster.env)" "172.16.80.211"
# #18576: an EMPTY alias means "no alias" (mouse-target-setup.sh), so it
# must stay empty rather than be re-derived from IPERF_TARGET4.
eq "loss empty TARGET_ALIAS_V4 stays empty" "$(resolve TARGET_ALIAS_V4 TARGET_ALIAS_V4=)" ""
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

# ── Case F: no cluster env re-arms the #18576 excuse ─────────────────
# test-connectivity's iperf target claim cell FAILs any second ARP holder
# unless the env names IPERF_TARGET4_KNOWN_HOLDERS (then it SKIPs). loss's
# dual-held .200 was excused that way until #18576 moved the target. A
# re-added line would quietly turn a dual holder back into a SKIP, so no
# cluster env may set it (see test-connectivity.sh iperf_target_claim_cell).
for envf in "${PROJECT_ROOT}"/test/incus/*cluster.env; do
	rel="test/incus/${envf##*/}"
	got="$(resolve IPERF_TARGET4_KNOWN_HOLDERS BPFRX_CLUSTER_ENV="$rel")"
	[[ -z "$got" ]] \
		|| fail "${rel} sets IPERF_TARGET4_KNOWN_HOLDERS='${got}': a dual iperf-target holder would SKIP instead of FAIL (#18576)"
	ok "${rel} sets no IPERF_TARGET4_KNOWN_HOLDERS"
done

# ── Case G: a value left by ANOTHER cluster's env does not leak (#18576) ─
# Every per-cluster name resolves as ${NAME:-default}, so tcp's values,
# still set in the shell (or inherited as exports), used to read as caller
# overrides on a later loss load. That is how loss resolved
# MOUSE_TARGET_V4=.210 and MOUSE_TARGET_REF=tcp:xpf-tcp-target, the
# 2026-10-24 drift of loss's mouse-addr.service.
SEQ_TMP="$(mktemp -d)"
trap 'rm -rf "$SEQ_TMP"' EXIT
cat >"${SEQ_TMP}/seq.sh" <<'SEQ'
# seq.sh <mode> <var> <first-env> <second-env> [override]
# mode shell: both loads in one shell; mode child: the second load runs in a
# child that inherits the first load's exports. [override] is shell code
# run between the two loads (a real caller override), e.g.
# "export NAME=VALUE" or "NAME=(a b)".
mode="$1" var="$2" first="$3" second="$4" override="${5:-}"
BPFRX_CLUSTER_ENV="$first"
source "$PROJECT_ROOT/test/incus/cluster-env.sh" >/dev/null 2>&1
[[ -n "$override" ]] && eval "$override"
if [[ "$mode" == child ]]; then
	BPFRX_CLUSTER_ENV="$second" VAR="$var" bash -c \
		'source "$PROJECT_ROOT/test/incus/cluster-env.sh" >/dev/null 2>&1; printf "%s" "${!VAR-}"'
else
	BPFRX_CLUSTER_ENV="$second"
	source "$PROJECT_ROOT/test/incus/cluster-env.sh" >/dev/null 2>&1
	printf "%s" "${!var-}"
fi
SEQ
seq_resolve() { # <mode> <var> <first-env> <second-env> [override]
	env -i PATH="$PATH" PROJECT_ROOT="$PROJECT_ROOT" bash "${SEQ_TMP}/seq.sh" "$@"
}
TCP_ENV=test/incus/tcp-userspace-cluster.env
LOSS_ENV=test/incus/loss-userspace-cluster.env
for mode in shell child; do
	eq "tcp then loss (${mode}) MOUSE_TARGET_V4"  "$(seq_resolve "$mode" MOUSE_TARGET_V4 "$TCP_ENV" "$LOSS_ENV")"  "172.16.80.201"
	eq "tcp then loss (${mode}) TARGET_ALIAS_V4"  "$(seq_resolve "$mode" TARGET_ALIAS_V4 "$TCP_ENV" "$LOSS_ENV")"  "172.16.80.202"
	eq "tcp then loss (${mode}) DMZ_ADDR"         "$(seq_resolve "$mode" DMZ_ADDR "$TCP_ENV" "$LOSS_ENV")"         "172.16.50.201"
	eq "tcp then loss (${mode}) MOUSE_TARGET_REF" "$(seq_resolve "$mode" MOUSE_TARGET_REF "$TCP_ENV" "$LOSS_ENV")" "loss:xpf-mouse-target"
	eq "tcp then loss (${mode}) FW0"              "$(seq_resolve "$mode" FW0 "$TCP_ENV" "$LOSS_ENV")"              "loss:xpf-userspace-fw0"
	eq "loss then tcp (${mode}) MOUSE_TARGET_V4"  "$(seq_resolve "$mode" MOUSE_TARGET_V4 "$LOSS_ENV" "$TCP_ENV")"  "172.16.80.210"
	eq "loss then tcp (${mode}) MOUSE_TARGET_REF" "$(seq_resolve "$mode" MOUSE_TARGET_REF "$LOSS_ENV" "$TCP_ENV")" "tcp:xpf-tcp-target"
done
eq "loss then tcp TARGET_ALIAS_V4_DEPRECATED" "$(seq_resolve shell TARGET_ALIAS_V4_DEPRECATED "$LOSS_ENV" "$TCP_ENV")" ""
# loss-only names (and arrays) must not stay set when tcp is loaded next:
# Group12 would judge tcp in split mode against loss's external box.
eq "loss then tcp IPERF_TARGET_V4_V6_SAME_HOST" "$(seq_resolve shell IPERF_TARGET_V4_V6_SAME_HOST "$LOSS_ENV" "$TCP_ENV")" ""
eq "loss then tcp IPERF_TARGET6_SPLIT_HOLDER"   "$(seq_resolve shell IPERF_TARGET6_SPLIT_HOLDER "$LOSS_ENV" "$TCP_ENV")" ""
eq "loss then tcp VF_WAN_PCI (array)"           "$(seq_resolve shell VF_WAN_PCI "$LOSS_ENV" "$TCP_ENV")" ""
eq "loss then tcp VF_LAN_PCI (array)"           "$(seq_resolve shell VF_LAN_PCI "$LOSS_ENV" "$TCP_ENV")" ""
# A caller override set AFTER the first load is not a leak, and survives.
eq "tcp, override, loss: override wins" \
	"$(seq_resolve shell MOUSE_TARGET_V4 "$TCP_ENV" "$LOSS_ENV" "export MOUSE_TARGET_V4=172.16.80.99")" "172.16.80.99"
eq "tcp, override, loss (child): override wins" \
	"$(seq_resolve child MOUSE_TARGET_V4 "$TCP_ENV" "$LOSS_ENV" "export MOUSE_TARGET_V4=172.16.80.99")" "172.16.80.99"
# An array is compared WHOLE: changing only a later element is an override.
eq "loss, VF_WAN_PCI[1] override, tcp: array kept" \
	"$(seq_resolve shell 'VF_WAN_PCI[*]' "$LOSS_ENV" "$TCP_ENV" "VF_WAN_PCI=(0000:65:00.4 0000:65:00.9)")" "0000:65:00.4 0000:65:00.9"
# Re-loading the SAME env keeps every value (nothing is reset).
eq "loss, override, loss: override kept" \
	"$(seq_resolve shell MOUSE_TARGET_V4 "$LOSS_ENV" "$LOSS_ENV" "export MOUSE_TARGET_V4=172.16.80.99")" "172.16.80.99"

# ── Case H: census of env-file names vs the leak guard (#18576) ─────
# Every name an env file assigns must be either in cluster-env.sh's guard
# list (_xpf_cluster_env_names) or assigned by EVERY env file. Otherwise a
# load of another env leaves it set (the gap that let loss's split-mode
# names reach tcp). A new env variable cannot slip past this.
census_out="$(python3 - "$PROJECT_ROOT" <<'PY'
import pathlib, re, sys
root = pathlib.Path(sys.argv[1])
src = (root / "test/incus/cluster-env.sh").read_text()
m = re.search(r"^_xpf_cluster_env_names=\((.*?)^\)", src, re.S | re.M)
if not m:
    print("FAIL cannot find _xpf_cluster_env_names in cluster-env.sh"); sys.exit()
guard = set(m.group(1).split())
assign = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)(?:\[[^]]*\])?(?:\+)?=", re.M)
files = sorted((root / "test/incus").glob("*cluster.env"))
names = {f.name: set(assign.findall(f.read_text())) for f in files}
# Positive controls: the parser must see the files and known names in them.
if len(files) < 4:
    print(f"FAIL census found {len(files)} *cluster.env files, want at least 4"); sys.exit()
for need, f in (("IPERF_TARGET4", "loss-userspace-cluster.env"), ("VF_WAN_PCI", "loss-userspace-cluster.env"),
                ("MOUSE_TARGET_NAME", "tcp-userspace-cluster.env")):
    if need not in names.get(f, set()):
        print(f"FAIL census parser did not see {need} in {f}"); sys.exit()
everywhere = set.intersection(*names.values())
for f, ns in sorted(names.items()):
    for n in sorted(ns - everywhere - guard):
        print(f"FAIL {f} assigns {n}, which is neither in cluster-env.sh's guard list nor assigned by every *cluster.env")
# The every-env exemption holds only for an UNCONDITIONAL assignment: a
# `${NAME:-...}` default would keep the previous env's value.
for f in files:
    for n, val in re.findall(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(.*)$", f.read_text(), re.M):
        if n in everywhere - guard and re.match(r'"?\$\{' + n + r':?[-=]', val):
            print(f"FAIL {f.name} assigns exempt {n} conditionally ({val.strip()}); guard it or assign it unconditionally")
# Every name cluster-env.sh exports must be guarded, except the env selector
# itself and the guard's own record.
exported = set(" ".join(re.findall(r"^export\s+(.*)$", src, re.M)).split())
for n in sorted(exported - guard - {"PROJECT_ROOT", "BPFRX_CLUSTER_ENV", "_XPF_CLUSTER_ENV_FILE", "_XPF_CLUSTER_ENV_STATE"}):
    print(f"FAIL cluster-env.sh exports {n}, which is not in the guard list")
print(f"OK {len(files)} files, {len(set.union(*names.values()))} names, {len(guard)} guarded")
PY
)"
if grep -q '^FAIL' <<<"$census_out"; then
	fail "env-name census (#18576): $(grep '^FAIL' <<<"$census_out" | tr '\n' ' ')"
fi
ok "env-name census: ${census_out#OK }"

echo "ALL ${PASS} CASES PASS"
