// Early host-input barrier (#10751).
//
// On every normal post-first-commit cold boot, systemd-networkd applies the
// persisted 10-xpf-*.network files (static addresses + IPv6 link-locals) BEFORE
// xpfd starts (xpfd orders After=network-online.target frr.service, and
// wait-online is disabled), while the host-inbound table is installed only in
// the first apply tail. The only boot-time nft unit is FORWARD-only by design
// (xpf-transit-closed.service: INPUT/OUTPUT are never touched), so every
// host-bound listener that starts from persisted config (sshd with no
// ListenAddress, charon, bgpd, kea/chrony where enabled) is reachable with NO
// host-input enforcement until the first apply lands.
//
// This file closes the window with a SEPARATE inet table, installed by a
// SEPARATE Before-networkd unit (xpf-input-closed.service) via a SEPARATE
// `xpfd input-barrier close` command. It is deliberately NOT part of
// transit_barrier.go: TestTransitBarrierBootUnitFailsClosed9852 pins that file
// as forward-only (no ChainHookInput), so piggybacking the input hook there is
// ruled out — this barrier lives, installs, and removes independently.
//
// SHAPE. Table inet xpf_input_barrier, one base chain `input` (type filter,
// hook input, priority 12, policy DROP) with only config-free admits:
//
//  1. iifname "lo" accept — local IPC (FRR daemons rendezvous over 127.0.0.1).
//  2. ct state established,related accept.
//  3. meta l4proto { 50, 51 } accept (host-terminated ESP/AH).
//  4. ICMPv6 errors/PMTUD and ND; ICMPv4 errors/PMTUD.
//  5. meta l4proto { 89, 112 } accept (OSPF and VRRP control plane).
//  6. TCP dport { 179, 4785 } accept (BGP and xpf HA session sync).
//  7. UDP dport { 520, 521, 3784, 3785, 4784 } accept (RIP/RIPng, BFD,
//     xpf HA heartbeat).
//
// Rules 2-4 are hostInboundFenceMandatoryAdmitsNetlink(p, nil): the SAME shared
// admits as the #5644 cold-boot fence and #5789 gap fence, minus configured
// WireGuard ports (unknown before config loads). Rules 5-7 preserve the
// config-free FRR and HA protocols needed during the boot handoff. The firewall
// service ports (including SSH, IKE UDP 500/4500, DHCP server, web/API, and
// monitoring) are deliberately absent; no config is read to authorize them.
// No named counters, no address scoping — at Before-networkd install time NO
// addresses exist yet, so a daddr-scoped fence is unexpressable and policy DROP
// is the fail-closed shape. Only return traffic, loopback, core L3, and the
// routing/HA control plane pass.
//
// PRIORITY. 12 evaluates STRICTLY AFTER the whole local-delivery cluster
// (lo0 0 < host-inbound 10 < gap 11). Before the first apply the barrier stands
// alone and drops everything new. During handoff, base-chain ACCEPTs from the
// real host-inbound table do not prevent a later base chain from dropping the
// packet, so this barrier may temporarily reject traffic the real table would
// allow. That is intentionally fail-closed; terminal DROPs remain enforced.
// Removing this chain restores the configured host-input posture.
// FAMILY. inet only, matching xpf_hostinbound. Locally-delivered IP packets
// always traverse the inet input hook regardless of ingress interface, so no
// bridge leg is needed (unlike forward, where bridged frames never consult the
// inet hook at all).
//
// LIFECYCLE. Install is replace-on-call (idempotent: the boot unit and any
// retry converge). Removal is idempotent (absent -> nil) and happens ONLY in
// the daemon's first-apply handoff, after a successful real host-inbound
// install, a successful cold-boot/gap fence install, or a successful
// no-enforcement teardown — never before enforcement (or intended
// non-enforcement) is established. A genuine removal failure is returned so the
// caller stays visibly fail-closed rather than believing the barrier lifted.
package nftables

import (
	"fmt"

	"github.com/google/nftables"
)

// EarlyInputBarrierTableName is the inet table the #10751 pre-networkd unit
// installs before systemd-networkd brings up any address, and the daemon's
// first apply removes once host-input enforcement (or intended
// non-enforcement) is established.
const EarlyInputBarrierTableName = "xpf_input_barrier"

// earlyInputBarrierPriority is the hook-input priority of the barrier chain.
// It is strictly greater than the whole local-delivery cluster (lo0 0 <
// host-inbound 10 < gap 11) so the barrier backstops, never shadows, the real
// enforcement during the handoff overlap. See the file doc comment.
const earlyInputBarrierPriority = hostInboundGapPriority + 1

// earlyInputBarrierControlTCPPorts are the config-free TCP listener ports needed
// by FRR BGP and xpf's TCP session-sync control link.
var earlyInputBarrierControlTCPPorts = []uint16{179, 4785}

// earlyInputBarrierControlUDPPorts are the config-free UDP listener ports needed
// by xpf heartbeat, FRR RIP/RIPng and BFD.
var earlyInputBarrierControlUDPPorts = []uint16{520, 521, 3784, 3785, 4784}

// earlyInputBarrierControlIPProtocols are FRR OSPF (89) and VRRP (112).
var earlyInputBarrierControlIPProtocols = []uint8{89, 112}

const earlyInputBarrierLoopback = "lo"

// InstallEarlyInputBarrier installs the #10751 boot input barrier: an inet-only
// input-hook chain with policy DROP and just config-free host/FRR/HA admits.
// Replace-on-call makes boot retries converge to the same shape.

func (in *netlinkInstaller) InstallEarlyInputBarrier() error {
	c, err := in.newConn()
	if err != nil {
		return fmt.Errorf("nftables conn: %w", err)
	}
	exists, err := tableExists(c, EarlyInputBarrierTableName)
	if err != nil {
		return err
	}
	tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: EarlyInputBarrierTableName}
	if exists {
		c.DelTable(tbl)
	}
	tbl = c.AddTable(tbl)
	chain := c.AddChain(earlyInputBarrierChain(tbl))
	p := &nlPlan{c: c, table: tbl, chain: chain}
	emitEarlyInputBarrierAdmits(p)
	if p.err != nil {
		return p.err
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("nftables flush %s: %w", EarlyInputBarrierTableName, err)
	}
	return nil
}

// RemoveEarlyInputBarrier removes the #10751 boot input barrier. Idempotent:
// absent -> nil. A genuine kernel failure IS returned, because a barrier that
// could not be removed leaves the box input-superset-closed and the caller
// must be able to see it.
func (in *netlinkInstaller) RemoveEarlyInputBarrier() error {
	return in.DeleteTable(EarlyInputBarrierTableName)
}

// earlyInputBarrierChain builds the barrier base chain: filter/input at the
// backstop priority with policy DROP.
func earlyInputBarrierChain(tbl *nftables.Table) *nftables.Chain {
	prio := nftables.ChainPriority(earlyInputBarrierPriority)
	policy := nftables.ChainPolicyDrop
	return &nftables.Chain{
		Name:     "input",
		Table:    tbl,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: &prio,
		Policy:   &policy,
	}
}

// emitEarlyInputBarrierAdmits queues loopback, shared mandatory L3 admits, and
// the fixed routing/HA control-plane protocols and ports. Everything else falls
// through to the chain's DROP policy.
func emitEarlyInputBarrierAdmits(p *nlPlan) {
	p.rule().iifname([]string{earlyInputBarrierLoopback}).emit(verdictAccept()...)
	hostInboundFenceMandatoryAdmitsNetlink(p, nil)
	p.rule().l4protoSet(earlyInputBarrierControlIPProtocols).emit(verdictAccept()...)
	p.rule().l4Port(protoTCP, "dport", portsFromUint16(earlyInputBarrierControlTCPPorts), false).emit(verdictAccept()...)
	p.rule().l4Port(protoUDP, "dport", portsFromUint16(earlyInputBarrierControlUDPPorts), false).emit(verdictAccept()...)
}
