// Early host-input barrier (#10751).
//
// On every normal post-first-commit cold boot, systemd-networkd applies the
// persisted 10-xpf-*.network files (static addresses + IPv6 link-locals) BEFORE
// xpfd starts (xpfd orders After=network-online.target frr.service, and
// wait-online is disabled), while the host-inbound table is installed only in
// the first apply tail. Without this pre-networkd guard, every host-bound
// listener that starts from persisted config (sshd with no ListenAddress,
// charon, bgpd, kea/chrony where enabled) would be reachable without
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
//  5. UDP dport 68 in inet, UDP dport 546 in inet6 (DHCP/DHCPv6 client
//     replies, family-split — without these a DHCP-pending boot could never
//     acquire the lease that ends barrier retention).
//
// Rules 2-4 are hostInboundFenceMandatoryAdmitsNetlink(p): the shared,
// scope-independent admits used by the #5644 cold-boot fence and #5789 gap
// fence. WireGuard zones are unknown before config loads, so this barrier does
// not emit a WG exception. Rule 5 admits only DHCP CLIENT ports, family-split
// to match steady state (dhcp→ip, dhcpv6→ip6):
// from-any dport-only, reaching dhclient parsing which validates transaction
// IDs (the DHCP server ports 67/547 stay blocked).
//
// WAN-REACHABILITY DURING THE WINDOW (pre-networkd install → first handoff).
// Loopback is local-only; established/related admits return traffic only;
// ESP/AH without an SA is dropped by XFRM; ICMP errors/PMTUD/ND/RA are
// kernel-processed mandatory L3 with no userspace listener; DHCP-client
// replies are from-any dport-only (daddr breadth is forced — no addresses
// exist pre-networkd to scope to — and sport pairing would exceed the
// steady-state dport-only shape). Every other protocol is CLOSED until
// handoff: SSH 22, BGP 179, IKE 500/4500, OSPF 89, VRRP 112, RIP 520/521,
// BFD 3784/3785, HA heartbeat 4784 and session sync 4785, DHCP server,
// web/API, monitoring. FRR routing protocols and HA control converge after
// the first host-inbound handoff (HA listeners start after the first apply,
// so nothing is lost; FRR daemons retry). No config is read to authorize
// anything; no named counters. Only return traffic, loopback, core L3, and
// DHCP-client replies pass.
//
// BOOTSTRAP VARIANT. Bootstrap swaps this table for a lifeline-admitting
// form (leading `iifname {lifelines} accept`): NON-lifeline data and
// link-local ingress stay DROP-closed, but whole lifeline NICs — including
// their link-local addresses — are open, and a default-route fallback NIC
// is admitted whole when no verified management identity (record/leaf)
// exists. The admit set prefers verified identity (persisted record,
// explicit leaf, OQ-D fxp0 narrowing) over name guesses; the zero-identity
// fallback is recovery necessity, logged. The first commit converges to
// configured policy.
//
// PRIORITY. 12 evaluates STRICTLY AFTER the whole local-delivery cluster
// (lo0 0 < host-inbound 10 < gap 11). Before the first apply the barrier stands
// alone and drops everything new. During handoff, an ACCEPT in the real
// host-inbound base chain does NOT bypass this later base chain, so the barrier
// still drops unadmitted traffic throughout the overlap. That overlap is the
// install-to-delete window inside one apply tail: configured SSH/IKE/new
// services may drop once and retry (TCP/IKE retransmit), which is acceptable
// versus fail-open. Terminal DROPs remain enforced. Removing this chain restores
// the configured host-input posture.
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
// non-enforcement) is established. Bootstrap (which suppresses the ordinary
// apply) instead swaps the table for the lifeline-admitting variant, keeping
// data and link-local ingress closed while recovery stays reachable. A
// genuine removal failure is returned so the caller stays visibly fail-closed
// rather than believing the barrier lifted.
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

// earlyInputBarrierDHCPv4ClientPort and earlyInputBarrierDHCPv6ClientPort are
// the DHCP (68) and DHCPv6 (546) client ports, admitted family-split
// (v4/68, v6/546). Offers arrive here; without this admit a DHCP-pending
// boot deadlocks (no lease → barrier retained → offers dropped → no lease).
const (
	earlyInputBarrierDHCPv4ClientPort = 68
	earlyInputBarrierDHCPv6ClientPort = 546
)

const earlyInputBarrierLoopback = "lo"

// InstallEarlyInputBarrier installs the #10751 boot input barrier: an inet-only
// input-hook chain with policy DROP and just config-free loopback/L3/DHCP-client
// admits. Replace-on-call makes boot retries converge to the same shape.
func (in *netlinkInstaller) InstallEarlyInputBarrier() error {
	return in.installEarlyInputBarrier(nil)
}

// InstallEarlyInputBarrierWithLifelineAdmit installs the same barrier table
// with one additional leading rule: `iifname {lifelines} accept`. Bootstrap
// swaps the global barrier for this variant (same table name, so the ordinary
// apply handoff removes it unchanged): data and link-local ingress stay
// DROP-closed while the management lifeline stays reachable for recovery.
// Replace-on-call, like the base install. An empty lifeline set installs the
// base shape.
func (in *netlinkInstaller) InstallEarlyInputBarrierWithLifelineAdmit(lifelines []string) error {
	return in.installEarlyInputBarrier(lifelines)
}

func (in *netlinkInstaller) installEarlyInputBarrier(lifelines []string) error {
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
	emitEarlyInputBarrierAdmitsWithLifeline(p, lifelines)
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

// EarlyInputBarrierPresent reports whether the #10751 boot input barrier
// table is currently installed.
func (in *netlinkInstaller) EarlyInputBarrierPresent() (bool, error) {
	c, err := in.newConn()
	if err != nil {
		return false, fmt.Errorf("nftables conn: %w", err)
	}
	return tableExists(c, EarlyInputBarrierTableName)
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

// emitEarlyInputBarrierAdmits queues loopback, the shared mandatory L3 admits,
// and DHCP-client replies. Everything else falls through to the chain's DROP
// policy. FRR/HA ingress is deliberately deferred until the first host-inbound
// handoff (see the file doc comment) — no from-any service pinholes.
func emitEarlyInputBarrierAdmits(p *nlPlan) {
	emitEarlyInputBarrierAdmitsWithLifeline(p, nil)
}

// emitEarlyInputBarrierAdmitsWithLifeline adds a leading `iifname {lifelines}
// accept` (bootstrap recovery) ahead of the base admits. Empty lifelines
// emit the base shape unchanged.
func emitEarlyInputBarrierAdmitsWithLifeline(p *nlPlan, lifelines []string) {
	if len(lifelines) > 0 {
		p.rule().iifname(lifelines).emit(verdictAccept()...)
	}
	p.rule().iifname([]string{earlyInputBarrierLoopback}).emit(verdictAccept()...)
	hostInboundFenceMandatoryAdmitsNetlink(p)
	emitEarlyInputBarrierDHCPClient(p)
}

// emitEarlyInputBarrierDHCPClient admits DHCP-client replies, family-split:
// UDP dport 68 in inet, UDP dport 546 in inet6. A single dport-only rule in
// the inet table would admit 68-on-v6 and 546-on-v4 too; steady state gates
// dhcp→ip and dhcpv6→ip6 and the barrier matches it (family is knowable
// config-free). dport-only (no sport/iifname/daddr): daddr breadth is forced
// pre-networkd and sport pairing would exceed steady state; dhclient
// validates transaction IDs.
func emitEarlyInputBarrierDHCPClient(p *nlPlan) {
	r4 := p.rule()
	r4.needNfproto(famV4)
	r4.l4Port(protoUDP, "dport", portsFromUint16([]uint16{earlyInputBarrierDHCPv4ClientPort}), false).emit(verdictAccept()...)
	r6 := p.rule()
	r6.needNfproto(famV6)
	r6.l4Port(protoUDP, "dport", portsFromUint16([]uint16{earlyInputBarrierDHCPv6ClientPort}), false).emit(verdictAccept()...)
}
