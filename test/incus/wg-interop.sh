#!/usr/bin/env bash
#
# #1736 (#1703 S2b) — live kernel-WireGuard interop test + smoke.
#
# Proves the xpf S2a WireGuard datapath (#1432 / PR #1739) interops with
# an INDEPENDENT reference peer: the Linux kernel WireGuard module on a
# Debian-13 incus VM (loss:xpf-wg-peer, SR-IOV VF on mlx1 VLAN 3667,
# 10.0.61.103/24 — mirrors cluster-userspace-host's NIC path).
#
# Converged plan: docs/pr/1736-wg-interop/plan.md (PLAN-READY 3-of-3).
# Operator runbook: docs/wg-interop-runbook.md.
#
# Usage:
#   ./test/incus/wg-interop.sh preflight        # P0 checks + fast-path baseline
#   ./test/incus/wg-interop.sh provision        # create/reuse the peer VM
#   ./test/incus/wg-interop.sh configure        # keys + peer wg + xpf commit (P1)
#   ./test/incus/wg-interop.sh test [phase]     # p2|p4a|p3|p4b|p5|p6|p7|p8 (default: all)
#   ./test/incus/wg-interop.sh teardown [--keep]# remove config (+ peer unless --keep)
#   ./test/incus/wg-interop.sh all [--keep]     # everything in plan order
#
# Phase order (plan §5.2 + #9587 P8): P0 P1 P2 P4a P3 P4b P5 P6 P7 P8 teardown.
#
# Shared-cluster discipline: EVERY incus command runs under
# flock /tmp/xpf-cluster.lock + sg incus-admin. Long-running traffic is
# detached INSIDE the instances so the lock is never held across a
# multi-minute phase. The xpf config change is additive (a node0-scoped
# `groups node0 interfaces wg0` stanza PLUS a node0-scoped
# `security zones security-zone wg` that grants host-inbound ping to the
# wg0 inner address — see xpf_wg_commit) and both are removed at teardown.
#
# MANDATORY secondary suppression (plan §4): the wg0 stanza is scoped
# under `groups node0` so fw1 (which ALSO holds 10.0.61.1/24) never
# compiles it — an unscoped config would let fw1 initiate with the same
# WG identity and ratchet the peer's TAI64N high-water against fw0.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=wg-interop.env
source "${SCRIPT_DIR}/wg-interop.env"
# #1875: marker-aware locking. Bind the marker check to the SAME path
# inc() flocks, so a cell holding a different lock can never bypass
# this script's per-command serialization.
XPF_CLUSTER_LOCK="${WG_CLUSTER_LOCK}"
# shellcheck source=cluster-lock.sh
source "${SCRIPT_DIR}/cluster-lock.sh"
# #7792/#6440: the piped-stdin CLI is a REPL, not a batch runner -- it prints
# `error: ...` for a failed command, continues, and exits 0. Every config
# session below is gated on the CLI's own success MARKERS via this library
# rather than on the session exit status, which proves nothing.
# shellcheck source=./cos-apply-lib.sh
source "${SCRIPT_DIR}/cos-apply-lib.sh"

R="${WG_REMOTE}"
FW0="${R}:${WG_FW0}"
FW1="${R}:${WG_FW1}"
PEER="${R}:${WG_PEER}"
LANHOST="${R}:${WG_LAN_HOST}"

EVID="${WG_EVIDENCE_DIR:-/tmp/wg-interop-$(date +%Y%m%d-%H%M%S)}"
mkdir -p "${EVID}" 2>/dev/null || { echo "[wg-interop] FATAL: cannot create evidence dir ${EVID}" >&2; exit 1; }
SUMMARY="${EVID}/summary.txt"

KEEP_PEER=0
# Recovery-restart taint counter (Codex PR-review finding 2): the
# wedged-apply / leaked-port xpfd restarts keep a run going for
# triage, but a restart-recovered run must NOT be presented as clean
# merge evidence — the boot-time reapply can mask a broken live
# commit-apply path. Taints are surfaced at the end and `all` exits 2.
TAINTS=0

# Diagnostics are non-fatal by design (GPT round-6): a failed evidence
# write (missing/unwritable dir, full disk) must never flip control flow
# or mask an exit status. Lost evidence is visible as missing files.
log()  { echo "[wg-interop $(date +%H:%M:%S)] $*" | tee -a "${SUMMARY}" || true; }
pass() { log "PASS: $*"; }
fail() { log "FAIL: $*"; exit 1; }
warn() { log "WARN: $*"; }

# Evidence-safe transcript path (GPT round-6): echoes a writable path under
# EVID, or /dev/null when evidence is unavailable (missing/unwritable dir,
# non-writable file, failed creation). Always returns 0, so callers under
# `set -e` never die on evidence.
evidence_path() {
    local p="${EVID:-/nonexistent}/$1"
    if touch "$p" 2>/dev/null && [ -w "$p" ]; then
        printf '%s' "$p"
    else
        printf '/dev/null'
    fi
    return 0
}

# Teardown-on-failure that cannot mask the phase status (GPT round-6):
# transcript failures fall back to /dev/null with a retry there, and this
# helper always returns 0, so the trap's `exit ${CLEANED_RC}` carries the
# original rc. Teardown is idempotent, so a retry after a genuine failure
# only re-attempts cleanup.
run_teardown_on_fail() {
    local tf ts=0
    tf=$(evidence_path "teardown-on-fail.txt")
    # Probe the redirect before teardown starts: an outer-redirect failure
    # would otherwise suppress the cleanup entirely.
    if ! : >>"$tf" 2>/dev/null; then
        tf=/dev/null
    fi
    ( teardown >>"$tf" 2>&1 ) 2>/dev/null || ts=$?
    if [ "$ts" -ne 0 ]; then
        ts=0
        ( teardown >>/dev/null 2>&1 ) 2>/dev/null || ts=$?
    fi
    [ "$ts" -eq 0 ] || warn "failure-teardown itself failed (rc=$ts)" || true
    return 0
}

# ---------------------------------------------------------------------------
# Cluster command plumbing. flock serializes against other agents; sg
# grants the incus-admin group. printf %q-quoting survives the sg -c
# string boundary. stdin passes through (used for cli heredocs).
# #1875: inside a with-cluster.sh cell (valid marker from a live
# ancestor holder) the per-command flock is skipped — the cell already
# owns the cluster, and flocking the same file would deadlock against
# our own ancestor. Standalone behavior is byte-identical to before.
inc() {
    local q
    q=$(printf '%q ' incus "$@")
    if xpf_cluster_lock_held; then
        sg incus-admin -c "$q"
    else
        flock "${WG_CLUSTER_LOCK}" sg incus-admin -c "$q"
    fi
}

# Run a shell snippet inside an instance.
ish() { # ish <instance> <snippet>
    local inst="$1"; shift
    inc exec "$inst" -- sh -c "$*"
}

# Pipe stdin into the Junos-style CLI on fw0 (config sessions, shows).
fw0_cli() { inc exec "${FW0}" -- /usr/local/sbin/cli; }

# ---------------------------------------------------------------------------
# Small parsers.

# Max inter-seq gap (seconds, interval=1s) from `ping -D` output, plus
# received count: "GAP RECEIVED". End-truncation (trailing losses) is
# counted as a gap against the expected final seq.
ping_gap_stats() { # ping_gap_stats <file> <expected_count>
    # Portable (mawk-safe): no 3-arg match. Reply lines only (a
    # "Destination Host Unreachable" error line also carries icmp_seq).
    awk -v expect="$2" '
        / bytes from / && /time=/ {
            p = index($0, "icmp_seq=")
            if (!p) next
            s = substr($0, p + 9); sub(/[^0-9].*/, "", s); seq = s + 0
            if (last && seq > last + 1 && seq - last - 1 > gap) gap = seq - last - 1
            if (!first) first = seq
            last = seq; rcvd++ }
        END {
            if (!rcvd) { print expect, 0; exit }
            if (first > 1 && first - 1 > gap) gap = first - 1
            if (expect > last && expect - last > gap) gap = expect - last
            print gap + 0, rcvd + 0 }' "$1"
}

# Mbit/s from the iperf3 "[SUM] ... receiver" (or single-stream) line.
iperf_mbps() { # iperf_mbps <file>
    awk '/receiver/ && (/SUM/ || !sum_seen) {
            for (i = 1; i < NF; i++) if ($(i+1) ~ /bits\/sec/) { v = $i; u = $(i+1) }
            if (u == "Gbits/sec") v *= 1000
            else if (u == "Kbits/sec") v /= 1000
            else if (u == "bits/sec") v /= 1000000
            # Mbits/sec passes through unscaled.
            if (u ~ /bits\/sec/) out = v
            if (/SUM/) sum_seen = 1 }
        END { printf "%.0f\n", out+0 }' "$1"
}

# ---------------------------------------------------------------------------
# Key management. Keys are generated ON THE PEER with wireguard-tools
# (base64) and converted to hex for the xpf config (S6 owns base64).
KEYDIR="${EVID}/keys"

gen_keys() { # gen_keys [force] — force regenerates (fresh WG identity)
    mkdir -p "${KEYDIR}"
    if [ "${1:-}" = force ]; then
        # Fresh keys per configure: an engine-IDENTITY change is the
        # one teardown lever the coordinator reliably honors with
        # stop+join (config REMOVAL leaks the thread + bound port —
        # #1866), and fresh identities also keep the peer's TAI64N
        # high-water out of cross-run interactions.
        ish "${PEER}" 'rm -rf /tmp/wgkeys'
    fi
    ish "${PEER}" 'set -eu; umask 077; mkdir -p /tmp/wgkeys
        [ -s /tmp/wgkeys/peer.priv ] || wg genkey > /tmp/wgkeys/peer.priv
        [ -s /tmp/wgkeys/xpf.priv ]  || wg genkey > /tmp/wgkeys/xpf.priv
        wg pubkey < /tmp/wgkeys/peer.priv > /tmp/wgkeys/peer.pub
        wg pubkey < /tmp/wgkeys/xpf.priv  > /tmp/wgkeys/xpf.pub'
    b64_to_hex() { ish "${PEER}" "base64 -d < $1 | od -An -tx1 | tr -d ' \\n'"; }
    XPF_PRIV_HEX=$(b64_to_hex /tmp/wgkeys/xpf.priv)
    PEER_PUB_HEX=$(b64_to_hex /tmp/wgkeys/peer.pub)
    XPF_PUB_B64=$(ish "${PEER}" 'cat /tmp/wgkeys/xpf.pub')
    [ "${#XPF_PRIV_HEX}" -eq 64 ] || fail "xpf privkey hex length ${#XPF_PRIV_HEX} != 64"
    [ "${#PEER_PUB_HEX}" -eq 64 ] || fail "peer pubkey hex length ${#PEER_PUB_HEX} != 64"
    echo "${XPF_PUB_B64}" > "${KEYDIR}/xpf.pub.b64"
    echo "${PEER_PUB_HEX}" > "${KEYDIR}/peer.pub.hex"
    log "keys ready (xpf pub ${XPF_PUB_B64})"
}

# The predicate WireGuard actually needs is the LAN VIP
# (${WG_XPF_OUTER4}) being PRESENT on fw0 — the outer source address.
# After any xpfd restart/deploy fw0 comes up SECONDARY on ALL
# redundancy groups (preempt off) and the VIP is removed; the kernel
# then fails every WG send with a silent EINVAL (no route/source — the
# engine keeps retrying once per second and recovers by itself the
# moment the VIP returns; root-caused live 2026-06-11 via strace:
# sendto=EINVAL while backup, handshake within 5 s of failback).
# Checking "RG0 primary" alone is NOT sufficient — the VIP follows the
# reth's own RG. So: gate on the VIP, and if it is absent, fail back
# EVERY RG to node0 (an xpfd restart on fw0 — including this
# harness's own recovery restarts — leaves them all on node1).
fw0_has_wg_vip() {
    ish "${FW0}" "ip -4 addr show | grep -q ' ${WG_XPF_OUTER4}/'"
}

# Functional ARP check: the VIP ADDRESS can be present on BOTH nodes
# (and absent on a backup), so presence alone is not mastership. What
# WG actually needs is the peer's ARP for the VIP resolving to FW0's
# LAN MAC — otherwise the peer's handshake responses land on fw1,
# which has no WG engine (node0 scoping). Skips cleanly when the peer
# instance does not exist yet (preflight runs before provision).
peer_arp_resolves_to_fw0() {
    local fw0_mac peer_mac
    inc info "${PEER}" >/dev/null 2>&1 || return 0
    fw0_mac=$(ish "${FW0}" "ip -br link show ge-0-0-1 | awk '{print \$3}'") || return 1
    ish "${PEER}" "ping -c 1 -W 1 ${WG_XPF_OUTER4} >/dev/null 2>&1 || true"
    peer_mac=$(ish "${PEER}" "ip neigh show ${WG_XPF_OUTER4} | awk '{for(i=1;i<NF;i++) if (\$i==\"lladdr\") print \$(i+1)}'") || return 1
    [ -n "${fw0_mac}" ] && [ "${fw0_mac}" = "${peer_mac}" ]
}

# Config commits are only accepted on the RG0 primary, so mastership
# needs BOTH the dataplane predicate (VIP + peer ARP) and RG0 config
# primaryship (Codex delta-review F2 — VIP-RG and RG0 can sit on
# different nodes).
fw0_is_rg0_primary() {
    inc exec "${FW0}" -- /usr/local/sbin/cli <<'EOF' 2>/dev/null | grep -A2 "Redundancy group: 0" | grep -qE '^node0 .*primary'
show chassis cluster status
quit
EOF
}

# Which of the three mastership predicates are NOT satisfied, as a
# human-readable list.
#
# #8274: this exists because the AND below has THREE operands and every
# message about it named only the first. A run whose real fault was an
# unconfigured peer (so `peer_arp_resolves_to_fw0` could not resolve the
# VIP's MAC) reported "WG VIP absent on fw0" — while the VIP was plainly
# present on ge-0-0-1 — and sent the reader to check cluster mastership,
# which was fine. That cost a full cluster cycle to disbelieve.
#
# Note the asymmetry that makes the misdirection easy: `peer_arp_resolves_to_fw0`
# returns SUCCESS when the peer does not exist at all (it has nothing to ask),
# so the predicate is silently satisfied on a fresh cluster and only starts
# failing once a peer exists but is not yet addressed — the state a
# hand-seeded or half-torn-down peer is in.
mastership_unmet() {
    local unmet=""
    fw0_has_wg_vip || unmet="${unmet} VIP-absent-on-fw0"
    peer_arp_resolves_to_fw0 || unmet="${unmet} peer-ARP-does-not-resolve-to-fw0"
    fw0_is_rg0_primary || unmet="${unmet} fw0-not-RG0-primary"
    printf '%s' "${unmet# }"
}

ensure_wg_mastership() { # ensure_wg_mastership <label>
    local t
    for t in $(seq 1 12); do
        if fw0_has_wg_vip && peer_arp_resolves_to_fw0 && fw0_is_rg0_primary; then
            log "$1: WG VIP on fw0 + peer ARP agrees + RG0 primary (t=${t})"
            return 0
        fi
        sleep 2
    done
    warn "$1: mastership unmet [$(mastership_unmet)] — failing ALL redundancy groups back to node0"
    # Discover the configured RG ids from cluster status and fail each
    # back. Hardcoding 0/1 missed RG2 live (three RGs on this cluster).
    local rgs rg
    rgs=$(inc exec "${FW0}" -- /usr/local/sbin/cli <<'EOF' 2>/dev/null | sed -n 's/^Redundancy group: \([0-9]*\) .*/\1/p'
show chassis cluster status
quit
EOF
    )
    [ -n "${rgs}" ] || rgs="0 1"
    # Evidence must never preempt the failback itself: the transcript falls
    # back to /dev/null when EVID is unavailable (GPT round-6).
    local fbf
    fbf=$(evidence_path "$1-failback.txt")
    for rg in ${rgs}; do
        inc exec "${FW0}" -- /usr/local/sbin/cli <<EOF >> "$fbf" 2>&1
request chassis cluster failover redundancy-group ${rg} node 0
quit
EOF
    done
    # Stale peer ARP can outlive a mastership change (the peer caches
    # the OLD master's MAC); flush so the recheck re-resolves.
    if inc info "${PEER}" >/dev/null 2>&1; then
        # By ADDRESS, not dev: only containers keep the eth1 device
        # name; VMs enumerate by PCI (Codex delta-review F3).
        ish "${PEER}" "ip neigh flush to ${WG_XPF_OUTER4} 2>/dev/null || true"
    fi
    for t in $(seq 1 24); do
        if fw0_has_wg_vip && peer_arp_resolves_to_fw0 && fw0_is_rg0_primary; then
            log "$1: WG VIP + peer ARP + RG0 primaryship restored after failback (t=${t})"
            return 0
        fi
        sleep 2
    done
    # Name the survivors on the way out. The caller's `|| fail` message
    # cannot know which predicate lost, so it is said HERE, where it is
    # cheap to ask each one again.
    warn "$1: mastership STILL unmet after failback [$(mastership_unmet)]"
    return 1
}

# The deployed build must be THIS branch's build. The shared cluster
# has concurrent agents with deploy loops; a foreign binary swap turns
# into impossible-to-triage phase failures (lived twice in #1736: a
# foreign build without the WG collect fix produced a "deterministic
# wedge" that was really a stale binary). Compare the running
# Software version's g<sha> suffix against this checkout's HEAD.
check_build_identity() { # check_build_identity <label>
    local want raw got
    want=$(git -C "${SCRIPT_DIR}/../.." rev-parse HEAD 2>/dev/null) || return 0
    raw=$(inc exec "${FW0}" -- /usr/local/sbin/cli <<'EOF' 2>/dev/null | grep '^Software version: ' | head -1
show chassis cluster status
quit
EOF
    )
    if [ -z "${raw}" ]; then
        warn "$1: cannot read deployed software version (daemon mid-restart?)"
        return 1
    fi
    # Accept an optional -dirty suffix (the build stamps git describe
    # --dirty); a version line that EXISTS but cannot be parsed is
    # fail-CLOSED — an unparseable foreign build must not slip past the
    # exact guard this check was added for (Codex delta-review F1).
    got=$(printf '%s\n' "${raw}" | sed -n 's/^Software version: .*-g\([0-9a-f]*\)\(-dirty\)\{0,1\}$/\1/p')
    [ -n "${got}" ] || fail "$1: cannot parse deployed software version '${raw}' — refusing to run against an unidentifiable build"
    # The version suffix is an abbreviated sha; prefix-match against
    # the full HEAD sha so abbrev-length differences cannot bite.
    case "${want}" in
        "${got}"*) return 0 ;;
    esac
    fail "$1: deployed build g${got} != this branch ${want} — a concurrent deploy replaced the binaries; redeploy from this branch (make cluster-deploy) before running"
}

# ---------------------------------------------------------------------------
# P0 — preflight.
preflight() {
    log "P0: preflight"
    inc info "${FW0}" >/dev/null || fail "cannot reach ${FW0}"
    ish "${FW0}" 'systemctl is-active xpfd' | grep -q active || fail "xpfd not active on fw0"
    ish "${FW1}" 'systemctl is-active xpfd' | grep -q active || fail "xpfd not active on fw1"
    check_build_identity "preflight" || true
    ensure_wg_mastership "preflight" || fail "WG mastership not established on fw0 even after all-RG failback (the unmet predicate is named in the warning above) — WG sends would EINVAL"
    # Stale wg0 STANZA from a previous run: the config DB persists
    # across deploys (deploy pushes xpf.conf but the daemon loads the
    # DB first), so a prior run's stanza silently revives the engine at
    # boot. Seen live: the revived engine handshook with the leftover
    # peer BEFORE the harness flushed it, and the engine then held a
    # confirmed session it never re-initiates from (S5 — no timers), so
    # P1 timed out. Clean it with a real commit.
    if inc exec "${FW0}" -- /usr/local/sbin/cli <<'EOF' 2>/dev/null | grep -q "tunnel"
show configuration groups node0 interfaces wg0
quit
EOF
    then
        warn "stale wg0 stanza in active config — removing"
        wg_stanza_delete
    fi
    # #9587 P8: same staleness guards for the second tunnel.
    if inc exec "${FW0}" -- /usr/local/sbin/cli <<'EOF' 2>/dev/null | grep -q "tunnel"
show configuration groups node0 interfaces wg1
quit
EOF
    then
        warn "stale wg1 stanza in active config — removing"
        wg_stanza_delete
    fi
    # Stale wg0 NETDEV on fw0 is the documented S2a removal leak (the
    # TUN outlives the stanza, pkg/routing/tunnel.go AGY M1 note +
    # #1866) — self-clean it. On fw1 a wg0 netdev means the node0
    # scoping failed at some point: hard fail.
    if ish "${FW0}" 'ip link show wg0 >/dev/null 2>&1'; then
        warn "stale wg0 netdev on fw0 (S2a removal leak) — deleting"
        ish "${FW0}" 'ip link del wg0 2>/dev/null; true'
    fi
    if ish "${FW1}" 'ip link show wg0 >/dev/null 2>&1'; then
        fail "wg0 netdev on fw1 — node0 scoping was violated; investigate before running"
    fi
    if ish "${FW0}" 'ip link show wg1 >/dev/null 2>&1'; then
        warn "stale wg1 netdev on fw0 (S2a removal leak) — deleting"
        ish "${FW0}" 'ip link del wg1 2>/dev/null; true'
    fi
    if ish "${FW1}" 'ip link show wg1 >/dev/null 2>&1'; then
        fail "wg1 netdev on fw1 — node0 scoping was violated; investigate before running"
    fi
    # A pinned listen port with no stanza is the leaked control thread
    # (#1866); P1's restart fallback handles fw0. On fw1 it is a
    # scoping violation: hard fail.
    if ish "${FW1}" "ss -uln | grep -q ':${WG_LISTEN_PORT} '"; then
        fail "udp :${WG_LISTEN_PORT} bound on fw1 — scoping violation"
    fi
    if ish "${FW1}" "ss -uln | grep -q ':${WG_LISTEN_PORT2} '"; then
        fail "udp :${WG_LISTEN_PORT2} bound on fw1 — scoping violation"
    fi
    # Free mlx1 VF headroom (informational — incus auto-assigns).
    inc query "/1.0/resources" 2>/dev/null \
        | sed -n 's/.*"current_vfs"[: ]*\([0-9]*\).*/vfs:\1/p' | head -2 >> "${SUMMARY}" || true
    # Fast-path baseline (canonical VLAN-80 path, forward + reverse, v4+v6).
    log "P0: fast-path baseline iperf3 (P=12, 10 s each)"
    for dir in fwd rev; do
        for fam in 4 6; do
            tgt="${WG_IPERF_TARGET4}"; [ "$fam" = 6 ] && tgt="${WG_IPERF_TARGET6}"
            rflag=""; [ "$dir" = rev ] && rflag="-R"
            ish "${LANHOST}" "iperf3 -${fam} -c ${tgt} -P 12 -t 10 ${rflag} 2>&1" \
                > "${EVID}/p0-baseline-${dir}-v${fam}.txt" \
                || warn "baseline iperf3 ${dir} v${fam} failed (recorded)"
            log "P0 baseline ${dir} v${fam}: $(iperf_mbps "${EVID}/p0-baseline-${dir}-v${fam}.txt") Mbit/s"
        done
    done
    pass "P0 preflight"
}

# ---------------------------------------------------------------------------
# Provision the Debian-13 peer (idempotent). WG_PEER_TYPE=vm is the
# issue-literal default; WG_PEER_TYPE=container is the plan §4 fallback
# for VM-infra failures (kernel WireGuard is netns-aware, so the
# protocol/crypto stack is still the reference kernel implementation —
# it runs in the loss HOST kernel instead of a dedicated guest kernel).
# 2026-06-11 validation run used the container fallback: freshly
# created VMs from images:debian/{13,12} never bring up the incus-agent
# on the loss host (incus 6.21; pre-existing fw VMs unaffected), so VM
# exec is impossible there — recorded in the PR evidence.
provision() {
    log "provision: ${PEER} (type=${WG_PEER_TYPE})"
    if inc info "${PEER}" >/dev/null 2>&1; then
        log "peer exists — reusing"
    else
        if [ "${WG_PEER_TYPE}" = vm ]; then
            inc init images:debian/13 "${PEER}" --vm -c limits.cpu=2 -c limits.memory=2GiB
        else
            inc init images:debian/13 "${PEER}"
        fi
        # eth0 (default profile) = incusbr0 mgmt. Add the data VF NIC.
        inc config device add "${PEER}" eth1 nic nictype=sriov \
            parent="${WG_PEER_DATA_PARENT}" vlan="${WG_PEER_DATA_VLAN}"
        inc start "${PEER}"
    fi
    # Wait for exec (containers: immediate; VMs: agent bring-up).
    for _ in $(seq 1 60); do
        if ish "${PEER}" true 2>/dev/null; then break; fi
        sleep 5
    done
    ish "${PEER}" true || fail "peer not exec-reachable (VM agent dead? try WG_PEER_TYPE=container)"
    # Static config on the data NIC. Containers keep the device name
    # (eth1); VMs enumerate by PCI, so match by the incus-assigned MAC.
    local match
    if [ "${WG_PEER_TYPE}" = vm ]; then
        local mac
        mac=$(inc config get "${PEER}" volatile.eth1.hwaddr)
        [ -n "$mac" ] || fail "cannot determine peer data NIC MAC"
        match="MACAddress=${mac}"
    else
        match="Name=eth1"
    fi
    ish "${PEER}" "set -eu
cat > /etc/systemd/network/20-wgdata.network <<EOF
[Match]
${match}
[Network]
Address=${WG_PEER_LAN4}
Address=${WG_PEER_LAN6}
EOF
systemctl restart systemd-networkd; sleep 2"
    # Tools (via mgmt NIC).
    ish "${PEER}" 'command -v wg >/dev/null && command -v iperf3 >/dev/null && command -v tcpdump >/dev/null' \
        || ish "${PEER}" 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq wireguard-tools iperf3 tcpdump >/dev/null'
    # Data-path reachability to the xpf LAN VIP.
    ish "${PEER}" "ping -c 3 -W 2 ${WG_XPF_OUTER4}" > "${EVID}/provision-vip-ping.txt" \
        || fail "peer cannot reach ${WG_XPF_OUTER4} over the data NIC"
    pass "provision (peer up, ${WG_PEER_LAN4} on VLAN ${WG_PEER_DATA_VLAN}, VIP reachable)"
}

# ---------------------------------------------------------------------------
# Kernel wg on the peer. Role/endpoint vary by phase; this (re)creates
# wgref from scratch — it is ALSO the restart-runbook flush procedure
# (clears the peer's per-peer TAI64N high-water).
peer_wg_setup() { # peer_wg_setup [endpoint_spec] [allowed_ips] [mtu]
    local ep="${1:-}" allowed="${2:-${WG_INNER4_CIDR},${WG_INNER6_CIDR}}" mtu="${3:-1420}"
    local epflag=""
    [ -n "$ep" ] && epflag="endpoint $ep persistent-keepalive ${WG_PEER_KEEPALIVE}"
    ish "${PEER}" "set -eu
        ip link del ${WG_KERNEL_IFACE} 2>/dev/null || true
        ip link add ${WG_KERNEL_IFACE} type wireguard
        wg set ${WG_KERNEL_IFACE} private-key /tmp/wgkeys/peer.priv listen-port ${WG_LISTEN_PORT} \
            peer \$(cat /tmp/wgkeys/xpf.pub) allowed-ips ${allowed} ${epflag}
        ip addr add ${WG_INNER4_PEER}/24 dev ${WG_KERNEL_IFACE}
        ip -6 addr add ${WG_INNER6_PEER}/64 dev ${WG_KERNEL_IFACE}
        ip link set ${WG_KERNEL_IFACE} mtu ${mtu} up"
}

# #9587 P8 — second kernel wg device on the peer for the wg1 tunnel.
# Disjoint listen port + disjoint inner subnets. Both peer devices share
# the peer keypair and both xpf tunnels share the xpf identity (no bind
# collision: all four sockets sit on distinct ports); the peer tells the
# tunnels apart by device with per-device allowed-ips, keeping the two
# TAI64N domains separate.
peer_wg_setup2() { # peer_wg_setup2 [endpoint_spec] — empty (default) = responder, learns from xpf msg1
    local ep="${1:-}" epflag=""
    [ -n "$ep" ] && epflag="endpoint $ep persistent-keepalive ${WG_PEER_KEEPALIVE}"
    ish "${PEER}" "set -eu
        ip link del ${WG_KERNEL_IFACE2} 2>/dev/null || true
        ip link add ${WG_KERNEL_IFACE2} type wireguard
        wg set ${WG_KERNEL_IFACE2} private-key /tmp/wgkeys/peer.priv listen-port ${WG_LISTEN_PORT2} \
            peer \$(cat /tmp/wgkeys/xpf.pub) allowed-ips ${WG_INNER4_CIDR2},${WG_INNER6_CIDR2} ${epflag}
        ip addr add ${WG_INNER4_PEER2}/24 dev ${WG_KERNEL_IFACE2}
        ip -6 addr add ${WG_INNER6_PEER2}/64 dev ${WG_KERNEL_IFACE2}
        ip link set ${WG_KERNEL_IFACE2} mtu 1420 up"
}

# Delete the wg0 stanza in its OWN commit. A delete+set in one commit
# nets out to "identity unchanged" when the values match a previous
# run, and the S2a reload contract then reuses the live engine Arc —
# keeping its confirmed session. A standalone delete-commit tears the
# engine + control thread down so the following set-commit starts a
# FRESH engine (deterministic initiator state for P1).
wg_stanza_delete() {
    fw0_cli > "${EVID}/wg-stanza-delete.txt" 2>&1 <<EOF
configure
delete groups node0 security zones security-zone wg
delete groups node0 interfaces wg0
delete groups node0 interfaces wg1
commit
exit
quit
EOF
    # #7792: line-anchored marker. The previous unanchored `grep -qE "commit
    # complete"` was also satisfied by an `error: commit failed: ... commit
    # complete ...` line, so a failed commit could report success.
    cos_require_markers "wg stanza delete commit" "${EVID}/wg-stanza-delete.txt" \
        "$COS_MARKER_COMMIT" \
        || warn "wg stanza delete commit: $(tail -2 "${EVID}/wg-stanza-delete.txt")"
    sleep 2
}

# xpf config commit. with_endpoint=1 → initiator role (endpoint set).
#
# The WireGuard peer is a NAMED-INSTANCE keyed by its public key (#1434
# multi-peer schema, pkg/config/schema_interfaces.go): the config shape
# is `peer <public-key-hex> { allowed-ips; endpoint; ... }`. There is NO
# `public-key` child leaf — the pubkey IS the peer's instance arg. The
# old `peer public-key <hex>` / `peer allowed-ips <cidr>` form drifted
# from this schema: it created a bogus peer literally named "public-key"
# (and another named "allowed-ips"), and the commit check rejected it
# with `peer 0 has an invalid public key (got "public-key")` (#6279).
#
# with_predelete=1 (default) emits the belt `delete groups node0
# interfaces wg0` INSIDE the same commit so an already-present stanza is
# replaced in place (the P6 re-commit path — wg0 exists there).
# configure_p1 runs a standalone wg_stanza_delete before the fresh P1
# create, so it passes with_predelete=0: without the stanza present, the
# inline delete of an absent wg0 emitted a benign but confusing
# `path not found: no node matching "wg0"` on every clean run (#6279).
#
# HOST-INBOUND (#6279 P2 bit-rot): the same commit also puts wg0.0 in a
# node0-scoped `security zones security-zone wg` with
# `host-inbound-traffic system-services ping`. #3070 (2026-06-25, 15 days
# AFTER this harness was written) made zone host-inbound-traffic ENFORCED:
# a decap'd WireGuard inner packet is written to the wg0 TUN and firewalled
# by the KERNEL nftables `xpf_hostinbound` chain (dst-address keyed, grouped
# by zone). With wg0 in NO zone its inner address falls into the #4420 HI-2
# addressed-but-unzoned catch-all DROP, so a PEER-initiated inner ping to
# the xpf wg0 address is dropped (xpf->peer still works — the reply rides
# the chain's leading `ct state established,related accept`). The dedicated
# `wg` zone moves the inner v4+v6 addrs into a zoned `icmp/icmpv6 type
# echo-request accept` (mirrors the base config's gr-0/0/0.0 tunnel in the
# sfmix zone). The zone MUST be node0-scoped and torn down WITH wg0 in the
# same commit — a zone referencing an undefined interface is a strict commit
# reject (#5248), so the zone and interface are always created/deleted as a
# pair (xpf_wg_commit adds both; wg_stanza_delete + teardown delete both).
xpf_wg_commit() { # xpf_wg_commit <with_endpoint> [with_predelete=1]
    local ep_line="" del_line="delete groups node0 interfaces wg0"
    [ "$1" = 1 ] && ep_line="set groups node0 interfaces wg0 tunnel wireguard peer ${PEER_PUB_HEX} endpoint ${WG_PEER_LAN4%%/*}:${WG_LISTEN_PORT}"
    [ "${2:-1}" = 0 ] && del_line=""
    # Fail fast rather than committing a placeholder: the peer pubkey and
    # xpf privkey MUST each be exactly 64 hex chars (32-byte X25519) or
    # the commit check rejects the tunnel. This catches an empty or
    # unsubstituted capture (#6279) with a clear message at the point of
    # use, instead of a cryptic commit-check rejection downstream.
    [[ "${PEER_PUB_HEX}" =~ ^[0-9a-fA-F]{64}$ ]] \
        || fail "xpf commit: PEER_PUB_HEX is not a 64-hex key: '${PEER_PUB_HEX}'"
    [[ "${XPF_PRIV_HEX}" =~ ^[0-9a-fA-F]{64}$ ]] \
        || fail "xpf commit: XPF_PRIV_HEX is not a 64-hex key: '${XPF_PRIV_HEX}'"
    fw0_cli > "${EVID}/xpf-commit-$1.txt" 2>&1 <<EOF
configure
${del_line}
set groups node0 interfaces wg0 unit 0 family inet address ${WG_INNER4_XPF}/24
set groups node0 interfaces wg0 unit 0 family inet6 address ${WG_INNER6_XPF}/64
set groups node0 interfaces wg0 tunnel mode wireguard
set groups node0 interfaces wg0 tunnel wireguard listen-port ${WG_LISTEN_PORT}
set groups node0 interfaces wg0 tunnel wireguard private-key ${XPF_PRIV_HEX}
set groups node0 interfaces wg0 tunnel wireguard peer ${PEER_PUB_HEX} allowed-ips ${WG_INNER4_CIDR}
set groups node0 interfaces wg0 tunnel wireguard peer ${PEER_PUB_HEX} allowed-ips ${WG_INNER6_CIDR}
set groups node0 security zones security-zone wg interfaces wg0.0
set groups node0 security zones security-zone wg host-inbound-traffic system-services ping
${ep_line}
commit
exit
quit
EOF
    # #7792: line-anchored marker (see wg_stanza_delete).
    cos_require_markers "xpf commit ($1)" "${EVID}/xpf-commit-$1.txt" \
        "$COS_MARKER_COMMIT" \
        || fail "xpf commit failed: $(cat "${EVID}/xpf-commit-$1.txt")"
}

# #9587 P8 — second tunnel commit. ADDITIVE: unlike xpf_wg_commit this never
# touches wg0 (P2's single-tunnel control must keep passing with wg1
# present). Same xpf identity, distinct listen port (no kernel bind
# collision); wg1.0 joins the existing node0-scoped `wg` zone so its inner
# addresses get the same host-inbound ping posture as wg0.0.
xpf_wg_commit2() { # xpf_wg_commit2 <with_endpoint> — predelete of wg1 only, always inline
    local ep_line="" del_line="delete groups node0 interfaces wg1"
    [ "$1" = 1 ] && ep_line="set groups node0 interfaces wg1 tunnel wireguard peer ${PEER_PUB_HEX} endpoint ${WG_PEER_LAN4%%/*}:${WG_LISTEN_PORT2}"
    [[ "${PEER_PUB_HEX}" =~ ^[0-9a-fA-F]{64}$ ]] \
        || fail "xpf commit2: PEER_PUB_HEX is not a 64-hex key: '${PEER_PUB_HEX}'"
    [[ "${XPF_PRIV_HEX}" =~ ^[0-9a-fA-F]{64}$ ]] \
        || fail "xpf commit2: XPF_PRIV_HEX is not a 64-hex key: '${XPF_PRIV_HEX}'"
    fw0_cli > "${EVID}/xpf-commit2-$1.txt" 2>&1 <<EOF
configure
${del_line}
set groups node0 interfaces wg1 unit 0 family inet address ${WG_INNER4_XPF2}/24
set groups node0 interfaces wg1 unit 0 family inet6 address ${WG_INNER6_XPF2}/64
set groups node0 interfaces wg1 tunnel mode wireguard
set groups node0 interfaces wg1 tunnel wireguard listen-port ${WG_LISTEN_PORT2}
set groups node0 interfaces wg1 tunnel wireguard private-key ${XPF_PRIV_HEX}
set groups node0 interfaces wg1 tunnel wireguard peer ${PEER_PUB_HEX} allowed-ips ${WG_INNER4_CIDR2}
set groups node0 interfaces wg1 tunnel wireguard peer ${PEER_PUB_HEX} allowed-ips ${WG_INNER6_CIDR2}
set groups node0 security zones security-zone wg interfaces wg1.0
${ep_line}
commit
exit
quit
EOF
    # #7792: line-anchored marker (see wg_stanza_delete).
    cos_require_markers "xpf commit2 ($1)" "${EVID}/xpf-commit2-$1.txt" \
        "$COS_MARKER_COMMIT" \
        || fail "xpf commit2 failed: $(cat "${EVID}/xpf-commit2-$1.txt")"
}

wait_handshake() { # wait_handshake <deadline_s> <label>
    local t hs
    for t in $(seq 1 "$1"); do
        hs=$(ish "${PEER}" "wg show ${WG_KERNEL_IFACE} latest-handshakes | awk '{print \$2}'" || echo 0)
        if [ "${hs:-0}" -gt 0 ] 2>/dev/null; then
            log "$2: handshake at epoch ${hs} (t=${t}s)"
            return 0
        fi
        sleep 1
    done
    return 1
}

# P1's stronger, data-driven variant: each tick ALSO pushes one inner
# ping from fw0. Rationale (live forensics, 2026-06-11): the kernel
# responder marks latest-handshakes at msg2-send, but xpf-as-initiator
# emits no spontaneous post-handshake data (keepalive TX is S5), so a
# REUSED wg0 (no fresh IPv6 ND/RS chatter) can leave the tunnel
# established-but-silent and any peer-side accounting anomaly
# unprobed. The inner ping (a) is initiator DATA that force-confirms
# the responder keypair, (b) proves transport BOTH directions at P1,
# and (c) on success short-circuits independent of peer counter
# semantics. On timeout, capture a self-evidencing post-mortem BEFORE
# the trap teardown destroys the state.
wait_handshake_data_driven() { # wait_handshake_data_driven <deadline_s> <label>
    local t hs
    for t in $(seq 1 "$1"); do
        if ish "${FW0}" "ping -c 1 -W 1 ${WG_INNER4_PEER} >/dev/null 2>&1"; then
            log "$2: inner ping through the tunnel OK (t=${t}, transport proven)"
            return 0
        fi
        hs=$(ish "${PEER}" "wg show ${WG_KERNEL_IFACE} latest-handshakes | awk '{print \$2}'" || echo 0)
        if [ "${hs:-0}" -gt 0 ] 2>/dev/null; then
            log "$2: peer handshake epoch ${hs} (t=${t}) — confirming with inner ping"
            if ish "${FW0}" "ping -c 3 -W 2 ${WG_INNER4_PEER} >/dev/null 2>&1"; then
                log "$2: transport confirmed"
                return 0
            fi
        fi
    done
    # Post-mortem capture (survives the ERR-trap teardown).
    {
        echo "=== $2 post-mortem $(date -u +%H:%M:%S) ==="
        ish "${PEER}" "wg show ${WG_KERNEL_IFACE}" 2>&1 || true
        ish "${PEER}" "wg show ${WG_KERNEL_IFACE} transfer" 2>&1 || true
        ish "${FW0}" "ip -br addr show wg0; ss -uln | grep ':${WG_LISTEN_PORT} ' ; ip route get ${WG_PEER_LAN4%%/*} 2>&1" 2>&1 || true
        ish "${FW0}" "timeout 4 tcpdump -ni ge-0-0-1 -c 6 udp port ${WG_LISTEN_PORT} 2>&1" 2>&1 || true
    } > "${EVID}/$2-postmortem.txt" 2>&1
    warn "$2: post-mortem captured to ${EVID}/$2-postmortem.txt"
    return 1
}

# P1 — configure + initiator handshake.
configure_p1() {
    log "P1: keys + peer (responder) + xpf commit (initiator, node0-scoped)"
    gen_keys force
    peer_wg_setup ""   # peer responder: no endpoint — must learn from xpf msg1
    ensure_wg_mastership "p1" || fail "P1: WG mastership not established on fw0 even after all-RG failback (the unmet predicate is named in the warning above)"
    check_build_identity "p1" || true
    wg_stanza_delete   # remove any stale stanza (fresh-engine belt)
    # S2a removal-leak workaround (#1866): a leaked control thread from
    # a previous engine pins :51820 and would EADDRINUSE the fresh
    # thread. If the port is still bound with no stanza in the config,
    # restart xpfd for a deterministic clean slate.
    if ish "${FW0}" "ss -uln | grep -q ':${WG_LISTEN_PORT} '"; then
        TAINTS=$((TAINTS+1))
        warn "EVIDENCE-TAINT: leaked WG control thread pins :${WG_LISTEN_PORT} (#1866) — restarting xpfd"
        ish "${FW0}" 'systemctl restart xpfd'
        sleep 15
        ish "${FW0}" 'systemctl is-active xpfd' | grep -q active || fail "P1: xpfd restart failed"
        ensure_wg_mastership "p1-leak" || fail "P1: WG VIP not restored after leak-recovery restart + failback"
    fi
    # wg_stanza_delete above already removed any prior wg0 stanza, so the
    # fresh create needs no inline predelete (with_predelete=0) — avoids a
    # benign `no node matching "wg0"` on every clean P1 run (#6279).
    xpf_wg_commit 1 0
    # The apply pipeline (tunnels -> dataplane -> FRR) is asynchronous
    # relative to the CLI commit returning; poll for the TUN + bind
    # rather than asserting at a fixed offset.
    local t ok=0
    for t in $(seq 1 30); do
        if ish "${FW0}" 'ip -br addr show wg0 >/dev/null 2>&1' \
            && ish "${FW0}" "ss -uln | grep -q ':${WG_LISTEN_PORT} '"; then
            ok=1; log "P1: wg0 TUN + :${WG_LISTEN_PORT} bound (t=${t}s)"; break
        fi
        sleep 1
    done
    if [ "$ok" != 1 ]; then
        # The commit is in the config DB but the apply pipeline did not
        # run the tunnel step (wedged apply — the #1794/#1800 class).
        # A daemon restart re-applies from the DB at boot, which is
        # deterministic; recover once rather than failing the run.
        TAINTS=$((TAINTS+1))
        warn "EVIDENCE-TAINT: P1 commit landed but wg0/:${WG_LISTEN_PORT} never appeared — restarting xpfd (wedged apply)"
        ish "${FW0}" 'systemctl restart xpfd'
        sleep 20
        ish "${FW0}" 'systemctl is-active xpfd' | grep -q active || fail "P1: xpfd restart failed"
        ensure_wg_mastership "p1-wedge" || fail "P1: WG VIP not restored after wedge-recovery restart + failback"
        peer_wg_setup ""   # restart runbook: flush the peer after an xpfd restart
        for t in $(seq 1 45); do
            if ish "${FW0}" 'ip -br addr show wg0 >/dev/null 2>&1' \
                && ish "${FW0}" "ss -uln | grep -q ':${WG_LISTEN_PORT} '"; then
                ok=1; log "P1: wg0 up after wedge-recovery restart (t=${t}s)"; break
            fi
            sleep 1
        done
    fi
    [ "$ok" = 1 ] || fail "P1: wg0 TUN/:${WG_LISTEN_PORT} not up on fw0 (even after restart)"
    ish "${FW0}" 'ip -br addr show wg0' > "${EVID}/p1-fw0-wg0.txt"
    ish "${FW0}" "ss -uln | grep ':${WG_LISTEN_PORT} '" >> "${EVID}/p1-fw0-wg0.txt"
    # Secondary suppression asserts (plan §4).
    if ish "${FW1}" 'ip link show wg0 >/dev/null 2>&1'; then
        fail "P1: wg0 EXISTS on fw1 — node0 scoping failed (BLOCKING finding)"
    fi
    if ish "${FW1}" "ss -uln | grep -q ':${WG_LISTEN_PORT} '"; then
        fail "P1: fw1 bound :${WG_LISTEN_PORT} — node0 scoping failed"
    fi
    if ! wait_handshake_data_driven $((WG_HANDSHAKE_TIMEOUT_S / 2)) "P1"; then
        # The engine retries at 1/s and self-recovers the moment the
        # mastership/ARP conditions heal (proven live: handshake <5 s
        # after failback) — remediate and keep waiting instead of
        # failing fast on a transient post-deploy mastership split.
        warn "P1: no handshake at half-budget — remediating mastership/ARP"
        check_build_identity "p1-midwait" || true
        ensure_wg_mastership "p1-midwait" || fail "P1: mastership/ARP not restorable mid-wait"
        wait_handshake_data_driven $((WG_HANDSHAKE_TIMEOUT_S / 2)) "P1" \
            || fail "P1: no handshake/transport within ${WG_HANDSHAKE_TIMEOUT_S}s (xpf initiator vs kernel responder)"
    fi
    ish "${PEER}" "wg show ${WG_KERNEL_IFACE}" > "${EVID}/p1-wg-show.txt"
    pass "P1 initiator handshake (fw0-only wg0 + bind; fw1 clean)"
}

# ---------------------------------------------------------------------------
# P2 — bidirectional transport v4+v6 + tunnel iperf3 baseline.
test_p2() {
    log "P2: transport both directions, v4+v6"
    sleep "${WG_SETTLE_S}"
    ish "${FW0}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER4_PEER}" > "${EVID}/p2-fw0-v4.txt" \
        || fail "P2: xpf->peer inner v4 ping failed"
    ish "${FW0}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER6_PEER}" > "${EVID}/p2-fw0-v6.txt" \
        || fail "P2: xpf->peer inner v6 ping failed"
    ish "${PEER}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER4_XPF}" > "${EVID}/p2-peer-v4.txt" \
        || fail "P2: peer->xpf inner v4 ping failed"
    ish "${PEER}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER6_XPF}" > "${EVID}/p2-peer-v6.txt" \
        || fail "P2: peer->xpf inner v6 ping failed"
    ish "${PEER}" "wg show ${WG_KERNEL_IFACE} transfer" > "${EVID}/p2-transfer.txt"
    awk '{ if ($2+0 == 0 || $3+0 == 0) exit 1 }' "${EVID}/p2-transfer.txt" \
        || fail "P2: peer transfer counters not bidirectional: $(cat "${EVID}/p2-transfer.txt")"
    # iperf3 through the tunnel — breakage floor, NOT a perf gate.
    ish "${PEER}" "pkill -x iperf3 2>/dev/null; nohup iperf3 -s >/tmp/iperf3-server.log 2>&1 < /dev/null & sleep 1"
    ish "${FW0}" "iperf3 -c ${WG_INNER4_PEER} -t 5 2>&1" > "${EVID}/p2-iperf-fwd.txt" \
        || fail "P2: tunnel iperf3 forward failed"
    ish "${FW0}" "iperf3 -c ${WG_INNER4_PEER} -t 5 -R 2>&1" > "${EVID}/p2-iperf-rev.txt" \
        || fail "P2: tunnel iperf3 reverse failed"
    local f r
    f=$(iperf_mbps "${EVID}/p2-iperf-fwd.txt"); r=$(iperf_mbps "${EVID}/p2-iperf-rev.txt")
    log "P2 tunnel iperf3: fwd ${f} Mbit/s, rev ${r} Mbit/s (control-thread path)"
    [ "$f" -ge "${WG_TUNNEL_IPERF_FLOOR_MBPS}" ] || fail "P2: forward ${f} < floor ${WG_TUNNEL_IPERF_FLOOR_MBPS} Mbit/s"
    [ "$r" -ge "${WG_TUNNEL_IPERF_FLOOR_MBPS}" ] || fail "P2: reverse ${r} < floor ${WG_TUNNEL_IPERF_FLOOR_MBPS} Mbit/s"
    pass "P2 transport (v4+v6 both ways, tunnel TCP ${f}/${r} Mbit/s)"
}

# ---------------------------------------------------------------------------
# Shared rekey-run machinery: detached bidirectional 1 s pings + 5 s
# handshake sampling on the peer; lock held only for start/poll/collect.
rekey_run() { # rekey_run <label> <duration_s> <max_gap_s>
    local label="$1" dur="$2" maxgap="$3"
    log "${label}: ${dur}s bidirectional 1s pings + handshake sampling"
    ish "${PEER}" "rm -f /tmp/rk-*.log
        nohup ping -D -i 1 -c ${dur} ${WG_INNER4_XPF} > /tmp/rk-ping.log 2>&1 < /dev/null &
        nohup sh -c 'for i in \$(seq 1 $((dur / 5 + 2))); do
            echo \"\$(date +%s) \$(wg show ${WG_KERNEL_IFACE} latest-handshakes | awk \"{print \\\$2}\")\";
            sleep 5; done' > /tmp/rk-hs.log 2>&1 < /dev/null &"
    ish "${FW0}" "rm -f /tmp/rk-ping.log
        nohup ping -D -i 1 -c ${dur} ${WG_INNER4_PEER} > /tmp/rk-ping.log 2>&1 < /dev/null &"
    sleep $((dur + 25))
    ish "${PEER}" 'cat /tmp/rk-ping.log' > "${EVID}/${label}-peer-ping.txt"
    ish "${PEER}" 'cat /tmp/rk-hs.log'   > "${EVID}/${label}-handshakes.txt"
    ish "${FW0}"  'cat /tmp/rk-ping.log' > "${EVID}/${label}-fw0-ping.txt"
    # Handshake epoch must ADVANCE mid-run (a rekey happened).
    local distinct
    distinct=$(awk '$2+0 > 0 { print $2 }' "${EVID}/${label}-handshakes.txt" | sort -u | wc -l)
    [ "${distinct}" -ge 2 ] || fail "${label}: no rekey observed (distinct handshake epochs: ${distinct})"
    # Bounded loss/gap in both directions.
    local stats gap rcvd
    for side in peer fw0; do
        stats=$(ping_gap_stats "${EVID}/${label}-${side}-ping.txt" "${dur}")
        gap=${stats% *}; rcvd=${stats#* }
        log "${label} ${side}: received ${rcvd}/${dur}, max gap ${gap}s"
        [ "${gap}" -le "${maxgap}" ] || fail "${label}: ${side} gap ${gap}s > ${maxgap}s"
        [ "${rcvd}" -ge $((dur - maxgap - 5)) ] || fail "${label}: ${side} received ${rcvd}/${dur}"
    done
    pass "${label} (rekey survived: ${distinct} epochs, gaps bounded)"
}

# P4a — expiry-driven recovery on the xpf-initiated session.
test_p4a() { rekey_run "p4a" "${WG_P4A_DURATION_S}" "${WG_P4A_MAX_GAP_S}"; }

# P3 — responder role + endpoint learning (session-tearing rebuild).
test_p3() {
    log "P3: remove xpf endpoint (responder role); peer becomes initiator"
    fw0_cli > "${EVID}/p3-commit.txt" 2>&1 <<EOF
configure
delete groups node0 interfaces wg0 tunnel wireguard peer ${PEER_PUB_HEX} endpoint
commit
exit
quit
EOF
    # #7792: line-anchored marker (see wg_stanza_delete).
    cos_require_markers "P3 endpoint-removal commit" "${EVID}/p3-commit.txt" \
        "$COS_MARKER_COMMIT" \
        || fail "P3: endpoint-removal commit failed"
    sleep 3
    # Restart-runbook flush + reconfigure peer as INITIATOR.
    peer_wg_setup "${WG_XPF_OUTER4}:${WG_LISTEN_PORT}"
    wait_handshake "${WG_HANDSHAKE_TIMEOUT_S}" "P3" \
        || fail "P3: no handshake (kernel initiator vs xpf responder)"
    sleep "${WG_SETTLE_S}"
    ish "${PEER}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER4_XPF}" > "${EVID}/p3-peer-v4.txt" \
        || fail "P3: peer->xpf ping failed in responder mode"
    # xpf egress must use the LEARNED endpoint (no endpoint configured).
    ish "${FW0}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER4_PEER}" > "${EVID}/p3-fw0-v4.txt" \
        || fail "P3: xpf->peer ping failed (endpoint learning broken)"
    pass "P3 responder role + endpoint learning"
}

# P4b — seamless kernel-initiator rekey on the P3 session.
test_p4b() { rekey_run "p4b" "${WG_P4B_DURATION_S}" 3; }

# ---------------------------------------------------------------------------
# P5 — >MTU full-tunnel + fragmented-outer.
test_p5() {
    log "P5: >MTU full-tunnel (AllowedIPs 0/0) + fragmented outer"
    # tcpdump on both ends for the fragment proof.
    ish "${PEER}" "nohup tcpdump -ni any 'udp port ${WG_LISTEN_PORT} or ip[6:2] & 0x3fff != 0' -c 200 \
        > /tmp/p5-tcpdump.log 2>&1 < /dev/null & sleep 1"
    # Full-tunnel cryptokey routing + raised MTU on the peer side only
    # (wg set does not install routes; mgmt path stays usable).
    ish "${PEER}" "set -eu
        wg set ${WG_KERNEL_IFACE} peer \$(cat /tmp/wgkeys/xpf.pub) \
            allowed-ips 0.0.0.0/0,::/0 endpoint ${WG_XPF_OUTER4}:${WG_LISTEN_PORT} \
            persistent-keepalive ${WG_PEER_KEEPALIVE}
        ip link set ${WG_KERNEL_IFACE} mtu 1500"
    sleep 2
    # peer->xpf oversize: inner 1500 -> outer 1560 -> fragments (DF=0).
    local frag_ok=0
    if ish "${PEER}" "ping -c 5 -s 1472 -M dont -W 3 ${WG_INNER4_XPF}" > "${EVID}/p5-peer-oversize.txt"; then
        frag_ok=1
        log "P5: fragmented-outer decap SUCCEEDED (kernel reassembly path) — outcome (i)"
    else
        log "P5: fragmented-outer dropped — acceptable outcome (ii); verifying clean drop"
    fi
    # Wedge check: normal-size traffic must pass immediately after.
    ish "${PEER}" "ping -c 5 -W 2 ${WG_INNER4_XPF}" > "${EVID}/p5-peer-normal-after.txt" \
        || fail "P5: WEDGE — normal inner ping dead after oversize attempt"
    # xpf->peer oversize: inner fragmented at the wg0 TUN MTU (~1425).
    ish "${FW0}" "ping -c 5 -s 1472 -M dont -W 3 ${WG_INNER4_PEER}" > "${EVID}/p5-fw0-oversize.txt" \
        || fail "P5: xpf->peer inner-fragmentation case failed"
    ish "${PEER}" 'cat /tmp/p5-tcpdump.log 2>/dev/null' > "${EVID}/p5-tcpdump.txt" || true
    ish "${FW0}" 'systemctl is-active xpfd' | grep -q active || fail "P5: xpfd unhealthy after fragment exercise"
    # Restore.
    ish "${PEER}" "set -eu
        pkill -x tcpdump 2>/dev/null || true
        wg set ${WG_KERNEL_IFACE} peer \$(cat /tmp/wgkeys/xpf.pub) \
            allowed-ips ${WG_INNER4_CIDR},${WG_INNER6_CIDR} endpoint ${WG_XPF_OUTER4}:${WG_LISTEN_PORT} \
            persistent-keepalive ${WG_PEER_KEEPALIVE}
        ip link set ${WG_KERNEL_IFACE} mtu 1420"
    echo "frag_outcome=$([ $frag_ok = 1 ] && echo clean-success || echo clean-drop)" >> "${SUMMARY}"
    pass "P5 >MTU bounded (outer-frag outcome: $([ $frag_ok = 1 ] && echo 'clean success' || echo 'clean drop'); no wedge)"
}

# ---------------------------------------------------------------------------
# P6 — restart recovery + restart runbook.
test_p6() {
    log "P6: restore initiator config, restart xpfd, runbook flush"
    # ORDER MATTERS (root cause of the deterministic P6-pre dead-air,
    # 2026-06-11): the identity-changed commit spawns a fresh engine
    # that fires its initial handshake within ~1 s. Flushing the peer
    # AFTER the commit raced that: the fresh engine completed msg1/msg2
    # against the about-to-die wgref, marked the session CONFIRMED, the
    # flush then wiped the peer's state — and xpf holds a
    # confirmed-but-dead session it never re-initiates from (no
    # REJECT/retry timers until S5), so the wait's pings encap into a
    # black hole (the flushed peer's transfer stays 0/0: undecryptable
    # records are dropped pre-accounting). Flush the peer FIRST — the
    # same order every other phase already uses — so the fresh engine's
    # first handshake lands on the live peer state.
    peer_wg_setup ""  # fresh peer state BEFORE the commit (see above)
    xpf_wg_commit 1   # endpoint back (initiator role — the TAI64N-relevant case)
    wait_handshake_data_driven "${WG_HANDSHAKE_TIMEOUT_S}" "P6-pre" || fail "P6: pre-restart handshake failed"
    # Negative control: restart WITHOUT flushing the peer. TAI64N is
    # wall-clock-derived, so acceptance is the EXPECTED outcome with a
    # sane clock; observe-and-record either way (plan P6).
    ish "${FW0}" 'systemctl restart xpfd'
    sleep 15
    ish "${FW0}" 'systemctl is-active xpfd' | grep -q active || fail "P6: xpfd failed to restart"
    ensure_wg_mastership "p6" || fail "P6: WG VIP not restored after restart + failback"
    local pre post recovered=0 mode
    pre=$(ish "${PEER}" "wg show ${WG_KERNEL_IFACE} latest-handshakes | awk '{print \$2}'")
    if wait_handshake_data_driven $((WG_RESTART_RECOVER_S * 2)) "P6-noflush"; then
        recovered=1
        post=$(ish "${PEER}" "wg show ${WG_KERNEL_IFACE} latest-handshakes | awk '{print \$2}'")
        if [ "${post}" != "${pre}" ]; then
            log "P6 negative control: recovered WITHOUT peer flush (wall-clock TAI64N moved forward) — recorded"
        else
            log "P6 negative control: transport up without a fresh peer handshake epoch — recorded"
        fi
    else
        log "P6 negative control: no recovery without flush — runbook flush case"
    fi
    if [ "${recovered}" = 1 ]; then
        # SAME TRAP as P6-pre (ORDER MATTERS above): the engine now
        # holds a LIVE confirmed session. Flushing the peer here would
        # manufacture the S5 confirmed-but-dead blackhole (no
        # rekey/retry timers until S5 — wg/peer.rs TODO) and dead-air
        # deterministically. The runbook flush is only reachable — and
        # only needed — when the no-flush recovery fails (TAI64N replay
        # guard / clock step), matching the runbook's own wording.
        log "P6: runbook flush SKIPPED — no-flush recovery already confirmed a live session"
        mode="no-flush recovery"
    else
        peer_wg_setup ""   # runbook flush: clears the peer's TAI64N high-water
        wait_handshake_data_driven "${WG_RESTART_RECOVER_S}" "P6-flush" \
            || fail "P6: no handshake/transport within ${WG_RESTART_RECOVER_S}s after runbook flush"
        mode="runbook flush validated"
    fi
    ish "${FW0}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER4_PEER}" > "${EVID}/p6-after.txt" \
        || fail "P6: tunnel traffic dead after restart"
    pass "P6 restart recovery (${mode})"
}

# ---------------------------------------------------------------------------
# P7 — fast-path no-regress with WG configured + tunnel up.
test_p7() {
    log "P7: fast-path no-regress (WG configured, tunnel up)"
    for dir in fwd rev; do
        for fam in 4 6; do
            tgt="${WG_IPERF_TARGET4}"; [ "$fam" = 6 ] && tgt="${WG_IPERF_TARGET6}"
            rflag=""; [ "$dir" = rev ] && rflag="-R"
            ish "${LANHOST}" "iperf3 -${fam} -c ${tgt} -P 12 -t 10 ${rflag} 2>&1" \
                > "${EVID}/p7-${dir}-v${fam}.txt" || fail "P7: iperf3 ${dir} v${fam} failed"
            local now base
            now=$(iperf_mbps "${EVID}/p7-${dir}-v${fam}.txt")
            base=$(iperf_mbps "${EVID}/p0-baseline-${dir}-v${fam}.txt" 2>/dev/null || echo 0)
            log "P7 ${dir} v${fam}: ${now} Mbit/s (baseline ${base})"
            if [ "${base}" -gt 0 ] && [ "${now}" -lt $((base * 70 / 100)) ]; then
                fail "P7: ${dir} v${fam} ${now} < 70% of baseline ${base} Mbit/s"
            fi
        done
    done
    pass "P7 fast-path no-regress"
}

# ---------------------------------------------------------------------------
# P8 (#9587) — two steered listen ports end to end. wg0 (P2's
# single-tunnel control) must keep passing WITH wg1 present; wg1 must
# pass on its own port in both families and both directions (permit);
# removing wg1's v6 cryptokey route must drop v6 while v4 passes, and
# restoring it must heal (deny + restore). Evidence is ping + peer
# transfer counters per tunnel per family, PLUS engine-activity witnesses
# (per-tunnel encap/decap growth shows live crypto both ways on the
# configured ports; no unsteered-port drops were counted). These witness
# steering config + liveness — never which path served the records
# (encap/decap counters are engine-wide, shared with the control thread)
# and never the absence of kernel-path delivery (the #9594 residual
# delivers without dropping). The deny exercises per-family
# cryptokey-routing at the encap AllowedIPs gate (either datapath may
# enforce it). Implementing genuinely worker-exclusive proof is DEFERRED
# to #10038, as is zone/session-level per-port policy proof.
# The steered-set drop counters ride in the local fail-on-revert cells,
# not here.

wait_handshake2() { # wait_handshake2 <deadline_s> <label>
    local t hs
    for t in $(seq 1 "$1"); do
        if ish "${FW0}" "ping -c 1 -W 1 ${WG_INNER4_PEER2} >/dev/null 2>&1"; then
            log "$2: wg1 inner ping through the tunnel OK (t=${t}, transport proven)"
            return 0
        fi
        hs=$(ish "${PEER}" "wg show ${WG_KERNEL_IFACE2} latest-handshakes | awk '{print \$2}'" || echo 0)
        if [ "${hs:-0}" -gt 0 ] 2>/dev/null; then
            log "$2: wg1 peer handshake epoch ${hs} (t=${t}) — confirming with inner ping"
            if ish "${FW0}" "ping -c 3 -W 2 ${WG_INNER4_PEER2} >/dev/null 2>&1"; then
                log "$2: wg1 transport confirmed"
                return 0
            fi
        fi
    done
    {
        echo "=== $2 post-mortem $(date -u +%H:%M:%S) ==="
        ish "${PEER}" "wg show ${WG_KERNEL_IFACE2}" 2>&1 || true
        ish "${PEER}" "wg show ${WG_KERNEL_IFACE2} transfer" 2>&1 || true
        ish "${FW0}" "ip -br addr show wg1; ss -uln | grep ':${WG_LISTEN_PORT2} ' 2>&1" 2>&1 || true
    } > "${EVID}/$2-postmortem.txt" 2>&1
    warn "$2: post-mortem captured to ${EVID}/$2-postmortem.txt"
    return 1
}

# Engine-activity witnesses: ping success alone is a weak steering signal.
# These counters are NOT worker-exclusive — encap/decap are engine-wide
# (the control thread bumps the same engine on socket records: dispatch.rs
# try_decap/try_encap) — so growth proves the tunnel carried live crypto
# both ways on the configured ports (steering-config + liveness witnesses),
# never which path served the records. Unsteered drops must not grow across
# our traffic: no unsteered-port drops were counted. Queried straight from
# the helper status socket on fw0; an absent tunnel row fails loudly rather
# than passing silently.
wg_tunnel_counters() { # wg_tunnel_counters <tunnel> — prints "encap decap unsteered"
    ish "${FW0}" "python3 -c \"
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(10)
s.connect('/run/xpf/userspace-dp.sock')
s.sendall(b'{\\\"type\\\": \\\"status\\\"}\n')
buf = b''
while True:
    c = s.recv(65536)
    if not c: break
    buf += c
st = json.loads(buf).get('status', {})
for t in st.get('wg_tunnels', []):
    if t.get('tunnel') == '$1':
        print(t.get('encap_packets', 0), t.get('decap_packets', 0), t.get('rx_unsteered_transport_drops', 0))
\""
}

test_p8_twoport() {
    log "P8: second tunnel wg1 (:${WG_LISTEN_PORT2}) + single-tunnel control recheck"
    ensure_wg_mastership "p8" || fail "P8: WG mastership not established"
    peer_wg_setup2 ""   # peer responder for wg1; xpf initiates (mirrors P1 roles)
    xpf_wg_commit2 1
    local t ok=0
    for t in $(seq 1 30); do
        if ish "${FW0}" 'ip -br addr show wg1 >/dev/null 2>&1' \
            && ish "${FW0}" "ss -uln | grep -q ':${WG_LISTEN_PORT2} '"; then
            ok=1; log "P8: wg1 TUN + :${WG_LISTEN_PORT2} bound (t=${t}s)"; break
        fi
        sleep 1
    done
    [ "$ok" = 1 ] || fail "P8: wg1 TUN/:${WG_LISTEN_PORT2} not up on fw0"
    # Node0 scoping for the second tunnel (mirrors the P1 asserts).
    if ish "${FW1}" 'ip link show wg1 >/dev/null 2>&1'; then
        fail "P8: wg1 EXISTS on fw1 — node0 scoping failed (BLOCKING finding)"
    fi
    if ish "${FW1}" "ss -uln | grep -q ':${WG_LISTEN_PORT2} '"; then
        fail "P8: fw1 bound :${WG_LISTEN_PORT2} — node0 scoping failed"
    fi
    wait_handshake2 "${WG_HANDSHAKE_TIMEOUT_S}" "P8" \
        || fail "P8: no wg1 handshake/transport (xpf initiator vs kernel responder)"
    sleep "${WG_SETTLE_S}"
    # Engine-activity baselines (see wg_tunnel_counters): captured after the
    # handshake so keepalive noise settles, before any P8 traffic.
    read -r wg0_e0 wg0_d0 wg0_u0 <<<"$(wg_tunnel_counters wg0)"
    read -r wg1_e0 wg1_d0 wg1_u0 <<<"$(wg_tunnel_counters wg1)"
    [ -n "${wg0_e0}" ] || fail "P8: no engine counters for wg0 (helper status missing tunnel)"
    [ -n "${wg1_e0}" ] || fail "P8: no engine counters for wg1 (helper status missing tunnel)"
    log "P8 engine baselines: wg0 encap=${wg0_e0} decap=${wg0_d0} unsteered=${wg0_u0}; wg1 encap=${wg1_e0} decap=${wg1_d0} unsteered=${wg1_u0}"
    # PERMIT, per tunnel per family per direction. wg0 first: the P2
    # control must stay green with wg1 present (adding a steered port
    # must not break the first tunnel).
    ish "${FW0}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER4_PEER}" > "${EVID}/p8-wg0-fw0-v4.txt" \
        || fail "P8: wg0 xpf->peer v4 regressed with wg1 present"
    ish "${FW0}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER6_PEER}" > "${EVID}/p8-wg0-fw0-v6.txt" \
        || fail "P8: wg0 xpf->peer v6 regressed with wg1 present"
    ish "${PEER}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER4_XPF}" > "${EVID}/p8-wg0-peer-v4.txt" \
        || fail "P8: wg0 peer->xpf v4 regressed with wg1 present"
    ish "${PEER}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER6_XPF}" > "${EVID}/p8-wg0-peer-v6.txt" \
        || fail "P8: wg0 peer->xpf v6 regressed with wg1 present"
    ish "${FW0}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER4_PEER2}" > "${EVID}/p8-wg1-fw0-v4.txt" \
        || fail "P8: wg1 xpf->peer inner v4 ping failed"
    ish "${FW0}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER6_PEER2}" > "${EVID}/p8-wg1-fw0-v6.txt" \
        || fail "P8: wg1 xpf->peer inner v6 ping failed"
    ish "${PEER}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER4_XPF2}" > "${EVID}/p8-wg1-peer-v4.txt" \
        || fail "P8: wg1 peer->xpf inner v4 ping failed"
    ish "${PEER}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER6_XPF2}" > "${EVID}/p8-wg1-peer-v6.txt" \
        || fail "P8: wg1 peer->xpf inner v6 ping failed"
    ish "${PEER}" "wg show ${WG_KERNEL_IFACE2} transfer" > "${EVID}/p8-wg1-transfer.txt"
    awk '{ if ($2+0 == 0 || $3+0 == 0) exit 1 }' "${EVID}/p8-wg1-transfer.txt" \
        || fail "P8: wg1 peer transfer counters not bidirectional: $(cat "${EVID}/p8-wg1-transfer.txt")"
    # Engine-activity verdict: both tunnels' engine encap AND decap must
    # have grown across the permit traffic above (live crypto both ways on
    # the configured ports), and no unsteered-port drops were counted. This
    # witnesses steering config + liveness — never which path served the
    # records (the counters are engine-wide, shared with the control
    # thread) and never the absence of kernel-path delivery (the #9594
    # residual delivers without dropping); zone/session-level proof stays
    # outstanding for a live #10038 world.
    read -r wg0_e1 wg0_d1 wg0_u1 <<<"$(wg_tunnel_counters wg0)"
    [ -n "${wg0_e1}" ] || fail "P8: lost wg0 engine counters after permit traffic"
    read -r wg1_e1 wg1_d1 wg1_u1 <<<"$(wg_tunnel_counters wg1)"
    [ -n "${wg1_e1}" ] || fail "P8: lost wg1 engine counters after permit traffic"
    log "P8 engine counters after permit: wg0 encap=${wg0_e1} decap=${wg0_d1} unsteered=${wg0_u1}; wg1 encap=${wg1_e1} decap=${wg1_d1} unsteered=${wg1_u1}"
    [ "${wg0_e1}" -gt "${wg0_e0}" ] && [ "${wg0_d1}" -gt "${wg0_d0}" ] \
        || fail "P8: wg0 engine encap/decap did not grow (tunnel carried nothing?)"
    [ "${wg1_e1}" -gt "${wg1_e0}" ] && [ "${wg1_d1}" -gt "${wg1_d0}" ] \
        || fail "P8: wg1 engine encap/decap did not grow (tunnel carried nothing?)"
    [ "${wg0_u1}" = "${wg0_u0}" ] && [ "${wg1_u1}" = "${wg1_u0}" ] \
        || fail "P8: unsteered drops grew during permit traffic"
    # DENY: drop wg1's v6 cryptokey route on xpf; v6 must stop while v4
    # keeps passing (same tunnel, same window — proves per-family deny,
    # not tunnel-down). Then restore and re-prove v6.
    fw0_cli > "${EVID}/p8-deny-commit.txt" 2>&1 <<EOF
configure
delete groups node0 interfaces wg1 tunnel wireguard peer ${PEER_PUB_HEX} allowed-ips ${WG_INNER6_CIDR2}
commit
exit
quit
EOF
    cos_require_markers "P8 deny commit" "${EVID}/p8-deny-commit.txt" \
        "$COS_MARKER_COMMIT" \
        || fail "P8: deny commit failed"
    sleep 3
    if ish "${FW0}" "ping -c 5 -W 2 ${WG_INNER6_PEER2} >/dev/null 2>&1"; then
        fail "P8: wg1 v6 ping PASSED with its cryptokey route removed — deny broken"
    fi
    log "P8: wg1 v6 correctly denied with route removed"
    ish "${FW0}" "ping -c 5 -i 0.5 -W 2 ${WG_INNER4_PEER2}" > "${EVID}/p8-wg1-deny-v4-control.txt" \
        || fail "P8: wg1 v4 died during the v6 deny window — tunnel down, not per-family deny"
    fw0_cli > "${EVID}/p8-restore-commit.txt" 2>&1 <<EOF
configure
set groups node0 interfaces wg1 tunnel wireguard peer ${PEER_PUB_HEX} allowed-ips ${WG_INNER6_CIDR2}
commit
exit
quit
EOF
    cos_require_markers "P8 restore commit" "${EVID}/p8-restore-commit.txt" \
        "$COS_MARKER_COMMIT" \
        || fail "P8: restore commit failed"
    sleep 3
    ish "${FW0}" "ping -c 10 -i 0.5 -W 2 ${WG_INNER6_PEER2}" > "${EVID}/p8-wg1-restored-v6.txt" \
        || fail "P8: wg1 v6 did not heal after route restore"
    pass "P8 two-port (wg0 control green + wg1 v4+v6 both ways, deny+restore)"
}

# ---------------------------------------------------------------------------
# Teardown. Removes the xpf stanza, the leaked TUN (S2a known
# limitation: removed-from-config WG TUNs persist), and the peer VM.
teardown() {
    # GPT round-5: cleanup runs independently of evidence availability. If
    # EVID is gone or unwritable, shadow SUMMARY (dynamically scoped: covers
    # log/warn/pass here and in every function teardown calls) so no
    # diagnostic write can abort the cleanup.
    if [ ! -d "${EVID:-/nonexistent}" ] || [ ! -w "${EVID:-/nonexistent}" ]; then
        local SUMMARY=/dev/null
    fi
    log "teardown"
    # Config commits only apply on the RG0 primary; a teardown that
    # silently fails leaves a poisoned cluster for the next run
    # (AGY PR-review F2 — observed live as a "node is not primary"
    # refusal reported as PASS).
    ensure_wg_mastership "teardown" || fail "teardown: WG VIP/mastership not restorable — cannot commit the stanza removal"
    local tcommit
    tcommit=$(evidence_path "teardown-commit.txt")
    fw0_cli > "$tcommit" 2>&1 <<EOF
configure
delete groups node0 security zones security-zone wg
delete groups node0 interfaces wg0
delete groups node0 interfaces wg1
commit
exit
quit
EOF
    # #7792: teardown is idempotent, so EITHER marker is a success -- the
    # stanza was removed, or it was already absent. cos_require_markers
    # requires ALL of its markers, so this disjunction uses the single-marker
    # predicate twice rather than forcing an AND that would fail on a re-run.
    # Both are line-anchored, which the previous `grep -qE` was not.
    # Evidence-independent cleanup: without a transcript the commit still ran
    # above, but verification is impossible — say so loudly instead of
    # asserting success.
    if [ "$tcommit" = /dev/null ]; then
        warn "teardown: no evidence transcript, stanza removal UNVERIFIED" || true
    else
        cos_transcript_has_marker "$tcommit" "$COS_MARKER_COMMIT" \
            || cos_transcript_has_marker "$tcommit" "path not found" \
            || fail "teardown commit failed: $(tail -3 "$tcommit" 2>/dev/null || echo '(transcript unreadable)')"
    fi
    ish "${FW0}" 'ip link del wg0 2>/dev/null; ip link del wg1 2>/dev/null; true'
    for n in "${FW0}" "${FW1}"; do
        if ish "$n" 'ip link show wg0 >/dev/null 2>&1'; then
            fail "teardown: wg0 still present on $n"
        fi
        if ish "$n" 'ip link show wg1 >/dev/null 2>&1'; then
            fail "teardown: wg1 still present on $n"
        fi
        if ish "$n" "ss -uln | grep -q ':${WG_LISTEN_PORT} '"; then
            fail "teardown: :${WG_LISTEN_PORT} still bound on $n"
        fi
        if ish "$n" "ss -uln | grep -q ':${WG_LISTEN_PORT2} '"; then
            fail "teardown: :${WG_LISTEN_PORT2} still bound on $n"
        fi
    done
    if [ "${KEEP_PEER}" = 1 ]; then
        log "teardown: KEEPING ${PEER} (--keep) — document for the parent smoke"
    else
        inc delete -f "${PEER}" 2>/dev/null || true
    fi
    ish "${FW0}" "ping -c 3 -W 2 ${WG_IPERF_TARGET4} >/dev/null" || warn "teardown: fast-path ping check failed"
    pass "teardown (both nodes clean)"
}

# ---------------------------------------------------------------------------
usage() { sed -n '3,28p' "$0"; exit 2; }

CMD="${1:-}"; shift || true
for a in "$@"; do [ "$a" = "--keep" ] && KEEP_PEER=1; done

case "${CMD}" in
    preflight) preflight ;;
    provision) provision ;;
    configure) configure_p1 ;;
    test)
        # Validate BEFORE arming cleanup: a typo'd phase must usage-exit
        # without tearing down a live setup.
        [[ "${1:-all}" =~ ^(p2|p4a|p3|p4b|p5|p6|p7|p8|all)$ ]] || usage
        # Failure cleanup: a mid-phase failure must not leave stanzas/peer
        # behind. `fail()` exits directly, which never fires an ERR trap —
        # and this path previously had no trap at all. The EXIT trap runs
        # run_teardown_on_fail on any nonzero exit; the helper always
        # returns 0, so the original status is preserved. --keep still
        # keeps the peer for triage.
        trap 'rc=$?; if [ -z "${CLEANED:-}" ]; then CLEANED=1; CLEANED_RC=$rc; if [ $rc -ne 0 ]; then warn "FAILURE rc=${rc} — running teardown (peer kept for triage if --keep)" || true; run_teardown_on_fail; fi; fi; exit ${CLEANED_RC:-0}' EXIT
        gen_keys   # idempotent — reloads persisted keys for standalone phases
        case "${1:-all}" in
            p2)  test_p2 ;; p4a) test_p4a ;; p3) test_p3 ;; p4b) test_p4b ;;
            p5)  test_p5 ;; p6)  test_p6 ;;  p7) test_p7 ;; p8) test_p8_twoport ;;
            all) test_p2; test_p4a; test_p3; test_p4b; test_p5; test_p6; test_p7; test_p8_twoport ;;
            *) usage ;;
        esac ;;
    teardown) teardown ;;
    all)
        # Same failure-cleanup discipline as `test)` above, replacing the old
        # ERR trap (which `fail()`'s direct exits never fired). See
        # run_teardown_on_fail: cleanup cannot mask the phase status.
        trap 'rc=$?; if [ -z "${CLEANED:-}" ]; then CLEANED=1; CLEANED_RC=$rc; if [ $rc -ne 0 ]; then warn "FAILURE rc=${rc} — running teardown (peer kept for triage if --keep)" || true; run_teardown_on_fail; fi; fi; exit ${CLEANED_RC:-0}' EXIT
        preflight; provision; configure_p1
        test_p2; test_p4a; test_p3; test_p4b; test_p5; test_p6; test_p7; test_p8_twoport
        trap - EXIT
        teardown
        CLEANED=1
        if [ "${TAINTS}" -gt 0 ]; then
            warn "${TAINTS} recovery restart(s) used — evidence TAINTED; rerun clean for merge evidence"
            exit 2
        fi ;;
    *) usage ;;
esac

log "evidence: ${EVID}"
