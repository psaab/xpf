package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
)

// checkVIPReadiness verifies that RETH interfaces for the given RG exist and
// have operational carrier (IFLA_OPERSTATE up, not merely admin IFF_UP), so
// that VIPs can actually be added. Used in no-reth-vrrp / private-rg-election
// mode where there are no VRRP instances to gate readiness.
func (d *Daemon) checkVIPReadiness(rgID int) (bool, []string) {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return true, nil // no config = nothing to check
	}
	linkByName := d.linkByNameFn
	if linkByName == nil {
		linkByName = netlink.LinkByName
	}
	return checkVIPReadinessForConfig(cfg, rgID, linkByName)
}

func (d *Daemon) checkNoRethTakeoverReadiness(rgID int) (bool, []string) {
	ready, reasons := d.checkVIPReadiness(rgID)
	// #7162: the bounded STARTUP hold. RETH VRRP mode suppresses preemption
	// until bulk session sync completes; this is the no-RETH equivalent, and
	// without it a node here promotes an RG before any conntrack/NAT state has
	// arrived and resets every established flow.
	//
	// This is a bounded hold, NOT a `cluster.IsSyncReady()` conjunct. The
	// difference is the whole of #110: a continuous sync term has no bound while
	// the sync channel is down, so it blocks promotion indefinitely in exactly
	// the degraded-peer case preemption exists for. This term goes false on its
	// own after noRethSyncHoldTimeout regardless of sync state or peer state.
	if d.inNoRethSyncHold() {
		ready = false
		reasons = append(reasons,
			"session sync startup hold: bulk sync not yet complete")
	}
	return ready, reasons
}

// checkVIPReadinessForConfig verifies that RETH interfaces for the given RG
// exist and have operational carrier. Pure function for testability.
//
// Carrier state is read via cluster.LinkAttrsUp (IFLA_OPERSTATE, with the
// IFF_UP admin-flag fallback only on OperUnknown), NOT the bare admin flag.
// xpfd admin-ups every managed interface, so IFF_UP stays set even after a
// cable pull — OR-ing it in (the pre-#2090 behavior) would judge a
// carrier-down VIP interface ready and let a node take over VIPs on a dead
// link (a black hole). This is the no-reth-vrrp sibling of #2070.
//
// vrrp.RethVIPsForRG keys this map by the resolved physical member /
// VLAN sub-interface name, which on VLAN-tagged reths commonly reports
// OperUnknown — hence the OperUnknown admin-flag fallback inside
// cluster.LinkAttrsUp is load-bearing here.
func checkVIPReadinessForConfig(cfg *config.Config, rgID int, linkByName func(string) (netlink.Link, error)) (bool, []string) {
	vipMap := vrrp.RethVIPsForRG(cfg, rgID)
	if len(vipMap) == 0 {
		return true, nil // no VIPs for this RG
	}
	var reasons []string
	for ifName := range vipMap {
		link, err := linkByName(ifName)
		if err != nil {
			reasons = append(reasons, fmt.Sprintf("vip interface %s not found", ifName))
			continue
		}
		if !cluster.LinkAttrsUp(link.Attrs()) {
			reasons = append(reasons, fmt.Sprintf("vip interface %s down", ifName))
		}
	}
	return len(reasons) == 0, reasons
}

// isNoRethVRRP returns true when RETH VRRP is not in use, meaning the
// daemon directly manages VIPs/GARPs without VRRP instances. Private-RG
// election is the compiler default, so a compiled cluster config with no
// mode flag already returns true; opting out with no-private-rg-election
// (and no no-reth-vrrp) restores legacy RETH VRRP and returns false.
func (d *Daemon) isNoRethVRRP() bool {
	cc := d.clusterConfig()
	return cc != nil && !cc.UsesRethVRRP()
}

func directVIPOwnershipDesired(localState cluster.NodeState) bool {
	return localState == cluster.StatePrimary
}

func (d *Daemon) shouldOwnDirectVIPs(rgID int) bool {
	if d.cluster == nil {
		return false
	}
	local := d.cluster.GroupState(rgID)
	if local == nil {
		return false
	}
	return directVIPOwnershipDesired(local.State)
}

func (d *Daemon) directVIPOwnershipApplied(rgID int) bool {
	d.directVIPMu.Lock()
	defer d.directVIPMu.Unlock()
	if d.directVIPOwned == nil {
		d.directVIPOwned = make(map[int]bool)
	}
	return d.directVIPOwned[rgID]
}

func (d *Daemon) addDirectVIPs(rgID int) int {
	if d.directAddVIPsFn != nil {
		return d.directAddVIPsFn(rgID)
	}
	return d.directAddVIPs(rgID)
}

func (d *Daemon) removeDirectVIPs(rgID int) int {
	if d.directRemoveVIPsFn != nil {
		return d.directRemoveVIPsFn(rgID)
	}
	return d.directRemoveVIPs(rgID)
}

func (d *Daemon) addDirectStableLinkLocal(rgID int) {
	if d.directAddStableLLFn != nil {
		d.directAddStableLLFn(rgID)
		return
	}
	d.addStableRethLinkLocal(rgID)
}

func (d *Daemon) removeDirectStableLinkLocal(rgID int) {
	if d.directRemoveStableLLFn != nil {
		d.directRemoveStableLLFn(rgID)
		return
	}
	d.removeStableRethLinkLocal(rgID)
}

func (d *Daemon) reconcileDirectVIPOwnership(rgID int, reason string) {
	d.applyDirectVIPOwnership(rgID, d.shouldOwnDirectVIPs(rgID), reason)
}

func (d *Daemon) applyDirectVIPOwnership(rgID int, want bool, reason string) {
	d.directVIPMu.Lock()
	if d.directVIPOwned == nil {
		d.directVIPOwned = make(map[int]bool)
	}
	prev := d.directVIPOwned[rgID]
	if want {
		added := d.addDirectVIPs(rgID)
		d.addDirectStableLinkLocal(rgID)
		if !prev {
			d.applyRethServicesForRG(rgID)
		}
		d.directVIPOwned[rgID] = true
		announce := !prev || added > 0
		cfg := d.store.ActiveConfig()
		d.directVIPMu.Unlock()
		if announce {
			d.scheduleDirectAnnounce(rgID, reason)
			if cfg != nil {
				// #1197: takeover must re-validate STALE entries
				// too; resolveNeighbors skips REACHABLE/STALE/
				// PERMANENT, so a stale snapshot would persist.
				// Use forceProbeNeighbors instead (no skip-stale).
				go d.forceProbeNeighbors(cfg)
				go d.resolveNeighbors(cfg) // covers cold/missing
			}
		}
		return
	}

	d.cancelDirectAnnounce(rgID)
	removed := d.removeDirectVIPs(rgID)
	d.removeDirectStableLinkLocal(rgID)
	d.directVIPOwned[rgID] = false
	d.directVIPMu.Unlock()
	if prev || removed > 0 {
		d.clearRethServicesForRG(rgID)
	}
}

// directAddVIPs adds VIPs for RETH interfaces in the given RG using netlink.
// IPv6 addresses are added with IFA_F_NODAD to avoid DAD delays.
// Idempotent — skips addresses that already exist. Returns the number of
// addresses actually added (non-EEXIST).
func (d *Daemon) directAddVIPs(rgID int) int {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return 0
	}
	var added int
	vipMap := vrrp.RethVIPsForRG(cfg, rgID)
	for ifName, addrs := range vipMap {
		linkByName := d.linkByNameFn
		if linkByName == nil {
			linkByName = netlink.LinkByName
		}
		link, err := linkByName(ifName)
		if err != nil {
			if d.shouldWarnVIPIface(ifName) {
				slog.Warn("directAddVIPs: interface not found", "iface", ifName, "err", err)
			}
			continue
		}
		// Interface exists now — clear any previous warning suppression
		d.clearVIPWarning(ifName)
		for _, cidr := range addrs {
			addr, err := netlink.ParseAddr(cidr)
			if err != nil {
				slog.Warn("directAddVIPs: bad address", "addr", cidr, "err", err)
				continue
			}
			if addr.IP.To4() == nil {
				addr.Flags = unix.IFA_F_NODAD
			}
			if err := netlink.AddrAdd(link, addr); err != nil {
				if !errors.Is(err, syscall.EEXIST) {
					slog.Warn("directAddVIPs: failed to add", "iface", ifName, "addr", cidr, "err", err)
				}
			} else {
				slog.Info("directAddVIPs: added VIP", "iface", ifName, "addr", cidr)
				added++
			}
		}
	}
	return added
}

// directRemoveVIPs removes VIPs for RETH interfaces in the given RG.
// Ignores "not found" errors for idempotency. Returns the number of
// addresses actually removed.
func (d *Daemon) directRemoveVIPs(rgID int) int {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return 0
	}
	var removed int
	vipMap := vrrp.RethVIPsForRG(cfg, rgID)
	for ifName, addrs := range vipMap {
		linkByName := d.linkByNameFn
		if linkByName == nil {
			linkByName = netlink.LinkByName
		}
		link, err := linkByName(ifName)
		if err != nil {
			continue // interface may not exist yet
		}
		for _, cidr := range addrs {
			addr, err := netlink.ParseAddr(cidr)
			if err != nil {
				continue
			}
			if err := netlink.AddrDel(link, addr); err != nil {
				if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
					slog.Warn("directRemoveVIPs: failed to remove", "iface", ifName, "addr", cidr, "err", err)
				}
			} else {
				slog.Info("directRemoveVIPs: removed VIP", "iface", ifName, "addr", cidr)
				removed++
			}
		}
	}
	return removed
}

// addStableRethLinkLocal adds the stable router link-local address to all
// RETH interfaces for the given RG. This address is shared across cluster
// nodes (no nodeID component) so hosts see the same IPv6 router identity
// regardless of which node is primary. Managed like a VIP: only present
// on the MASTER node.
//
// Placement is the single definition in pkg/config
// (Config.StableRethLinkLocalPlacements, #17049): per-unit (#15684,
// #16686), a configured link-local on one unit replaces the stable LL on
// THAT unit only, and the netdev is selected by unit.VlanID > 0 — a tagged
// unit 0 lives on <member>.<vlan-id>, not the bare member.
func (d *Daemon) addStableRethLinkLocal(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return
	}
	for _, p := range cfg.StableRethLinkLocalPlacements(rgID) {
		addStableLLToInterfaceFn(p.Netdev, p.Addr)
	}
}

func addStableLLToInterface(ifName string, ll net.IP) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{IP: ll, Mask: net.CIDRMask(128, 128)},
		Flags: unix.IFA_F_NODAD,
	}
	if err := netlink.AddrAdd(link, addr); err != nil {
		if !errors.Is(err, syscall.EEXIST) {
			slog.Warn("failed to add stable link-local", "iface", ifName, "addr", ll, "err", err)
		}
	} else {
		slog.Info("added stable router link-local", "iface", ifName, "addr", ll)
	}
}

// removeStableRethLinkLocal removes the stable router link-local address
// from all RETH interfaces for the given RG. Called on BACKUP transition.
// The sweep set is Config.RemoveNetdevs (#17049): every unit's
// VlanID-selected netdev plus the bare member, with no placement predicate,
// so an address installed by an older rule is still found.
func (d *Daemon) removeStableRethLinkLocal(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return
	}
	stableLL := config.StableRethLinkLocal(cfg.Chassis.Cluster.ClusterID, rgID)
	for _, netdev := range cfg.RemoveNetdevs(rgID) {
		removeStableLLFromInterfaceFn(netdev, stableLL)
	}
}

func removeStableLLFromInterface(ifName string, ll net.IP) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return
	}
	addr := &netlink.Addr{
		IPNet: &net.IPNet{IP: ll, Mask: net.CIDRMask(128, 128)},
	}
	if err := netlink.AddrDel(link, addr); err != nil {
		if !errors.Is(err, syscall.ENOENT) && !errors.Is(err, syscall.ESRCH) && !errors.Is(err, syscall.EADDRNOTAVAIL) {
			slog.Warn("failed to remove stable link-local", "iface", ifName, "addr", ll, "err", err)
		}
	} else {
		slog.Info("removed stable router link-local", "iface", ifName, "addr", ll)
	}
}

func (d *Daemon) directAnnounceActive(rgID int, seq uint64) bool {
	d.directAnnounceMu.Lock()
	current := d.directAnnounceSeq[rgID]
	d.directAnnounceMu.Unlock()
	if current != seq {
		return false
	}
	d.rgStatesMu.RLock()
	s := d.rgStates[rgID]
	d.rgStatesMu.RUnlock()
	return s != nil && s.IsActive()
}

func (d *Daemon) cancelDirectAnnounce(rgID int) {
	d.directAnnounceMu.Lock()
	defer d.directAnnounceMu.Unlock()
	if d.directAnnounceSeq == nil {
		d.directAnnounceSeq = make(map[int]uint64)
	}
	d.directAnnounceSeq[rgID]++
}

func (d *Daemon) scheduleDirectAnnounce(rgID int, reason string) {
	d.directAnnounceMu.Lock()
	if d.directAnnounceSeq == nil {
		d.directAnnounceSeq = make(map[int]uint64)
	}
	d.directAnnounceSeq[rgID]++
	seq := d.directAnnounceSeq[rgID]
	schedule := append([]time.Duration(nil), d.directAnnounceSchedule...)
	sendFn := d.directSendGARPsFn
	d.directAnnounceMu.Unlock()
	if len(schedule) == 0 {
		schedule = []time.Duration{0}
	}
	if sendFn == nil {
		sendFn = d.directSendGARPs
	}
	slog.Info("direct-mode re-announce scheduled", "rg", rgID, "reason", reason, "bursts", len(schedule))
	start := time.Now()
	burstOffset := 0
	if len(schedule) > 0 && schedule[0] == 0 {
		if d.directAnnounceActive(rgID, seq) {
			sendFn(rgID)
			slog.Info("direct-mode re-announce sent", "rg", rgID, "reason", reason, "burst", 1, "total", len(schedule))
		}
		schedule = schedule[1:]
		burstOffset = 1
	}
	if len(schedule) == 0 {
		return
	}
	go func() {
		for idx, at := range schedule {
			if wait := time.Until(start.Add(at)); wait > 0 {
				timer := time.NewTimer(wait)
				<-timer.C
			}
			if !d.directAnnounceActive(rgID, seq) {
				return
			}
			sendFn(rgID)
			slog.Info("direct-mode re-announce sent", "rg", rgID, "reason", reason, "burst", idx+1+burstOffset, "total", len(schedule)+burstOffset)
		}
	}()
}

// directGARPBurstFn and directNABurstFn are seams over the cluster gated burst
// senders so directSendGARPs' #2898 abdication gate is unit-testable without
// raw-socket I/O. directProxyNABurstFn uses the same gate but selects a valid
// interface source address distinct from the proxy target.
var (
	directGARPBurstFn    = cluster.SendGratuitousARPBurstGated
	directNABurstFn      = cluster.SendGratuitousIPv6BurstGated
	directProxyNABurstFn = cluster.SendProxyGratuitousIPv6BurstGated
)

// addStableLLToInterfaceFn / removeStableLLFromInterfaceFn are the netlink
// side-effect seams for the stable link-local add/remove decisions. They are
// package vars so a test can drive addStableRethLinkLocal /
// removeStableRethLinkLocal without real netlink (#15684).
var (
	addStableLLToInterfaceFn      = addStableLLToInterface
	removeStableLLFromInterfaceFn = removeStableLLFromInterface
)

// directARPProbeFn is the supplementary gateway ARP-probe sender used by
// directSendGARPs. It is a package var so tests can capture the sender/target
// that directSendGARPs passes — proving the probe carries the VIP as the ARP
// sender (#2152) and targets the in-subnet first host (network+1, #3922) —
// without performing real AF_PACKET I/O. Mirrors vrrp.arpProbeFn.
var directARPProbeFn = cluster.SendARPProbe

// directBurstStillValid returns a cluster.BurstStillValid predicate for the
// direct-mode GARP/NA follow-up loops (#2898). seq is the directAnnounceSeq
// captured at burst start. The predicate reports true only while this RG still
// owns its VIPs (directVIPOwned) AND no newer announce has superseded this burst
// (directAnnounceSeq unchanged). It takes the same locks as the rest of the
// direct-mode announce machinery and holds them only momentarily — it is invoked
// once per follow-up frame, between the loop's 50ms sleeps, never across a sleep.
//
// This is the direct-mode analogue of the VRRP garpEpoch/master-state gate from
// #2867/#2894: an abdication (applyDirectVIPOwnership want=false →
// cancelDirectAnnounce bumps the sequence and clears directVIPOwned) or a newer
// announce (sequence bump) during the count*50ms burst window stops the
// remaining follow-up frames, so an abdicated RG stops re-poisoning neighbor
// caches for a VIP it no longer owns.
func (d *Daemon) directBurstStillValid(rgID int, seq uint64) cluster.BurstStillValid {
	return func() bool {
		d.directAnnounceMu.Lock()
		curSeq := d.directAnnounceSeq[rgID]
		d.directAnnounceMu.Unlock()
		if curSeq != seq {
			return false
		}
		d.directVIPMu.Lock()
		owned := d.directVIPOwned != nil && d.directVIPOwned[rgID]
		d.directVIPMu.Unlock()
		return owned
	}
}

// warnGARPClampOnce reports whether the #5695 "gratuitous-arp-count clamped"
// warning for rgID has not yet been logged, recording it so subsequent
// direct-mode bursts for the same RG stay silent. directSendGARPs runs on the
// per-failover path, so the clamp warning must fire at most once per RG (the
// logging rules forbid a per-send Warn).
func (d *Daemon) warnGARPClampOnce(rgID int) bool {
	d.garpClampWarnMu.Lock()
	defer d.garpClampWarnMu.Unlock()
	if d.garpClampWarned == nil {
		d.garpClampWarned = make(map[int]bool)
	}
	if d.garpClampWarned[rgID] {
		return false
	}
	d.garpClampWarned[rgID] = true
	return true
}

// directSender returns the shared announce sender wired to this
// package's test seams (#17052).
func (d *Daemon) directSender() cluster.AnnounceSender {
	return cluster.AnnounceSender{
		GARP:    directGARPBurstFn,
		NA:      directNABurstFn,
		ProxyNA: directProxyNABurstFn,
		Probe:   directARPProbeFn,
	}
}

// announceTargetsFor builds the full ordered announce set for rgID,
// filling gateway probes via the single derivation in pkg/vrrp (#3922).
func announceTargetsFor(cfg *config.Config, rgID int) []cluster.AnnounceTarget {
	return cluster.AnnounceTargets(cfg, rgID, vrrp.GatewayProbeTarget)
}

// directSendGARPs sends the full failover announcement for rgID in
// direct mode via the shared engine (#17052): VIP GARP/NA bursts +
// gateway probes, per-unit router-LL NAs, and the pool announce. The
// frame sequence, the single #5695 clamp and the #8405 64-address
// bound live in pkg/cluster (SendAnnounceTargets); this wrapper keeps
// the #2898 ownership fence and the per-RG clamp warn-once.
func (d *Daemon) directSendGARPs(rgID int) {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	d.directAnnounceMu.Lock()
	seq := d.directAnnounceSeq[rgID]
	d.directAnnounceMu.Unlock()
	stillValid := d.directBurstStillValid(rgID, seq)
	_, configured, clamped := cluster.AnnounceBurstCount(cfg, rgID)
	if clamped && d.warnGARPClampOnce(rgID) {
		slog.Warn("directSendGARPs: gratuitous-arp-count clamped to runtime safety maximum",
			"rg", rgID, "configured", configured,
			"clamped", clusterClampedCount(cfg, rgID),
			"max", config.GratuitousARPBurstClamp)
	}
	res := cluster.SendAnnounceTargets(announceTargetsFor(cfg, rgID), stillValid, d.directSender())
	if res.PoolTruncated && d.warnPoolTruncOnce(rgID) {
		slog.Warn("directSendGARPs: pool proxy-ARP/NDP announce truncated",
			"rg", rgID, "attempted", res.PoolAttempted,
			"max", cluster.PoolAnnounceMaxAddresses,
			"consequence", "the remaining pool addresses rely on upstream neighbor-discovery ageing")
	}
}

func clusterClampedCount(cfg *config.Config, rgID int) int {
	c, _, _ := cluster.AnnounceBurstCount(cfg, rgID)
	return c
}

// legacyNonVIPAnnouncePending reports whether the legacy-VRRP non-VIP
// announce (#17052) is still owed for rgID at the current activation.
// It is a pure read (no marker mutation): the announce is owed while
// the RG is active at an activation generation not yet claimed. The
// generation is the rg-state machine's activationSeq — it increments
// ONLY on inactive->active transitions, never on no-change inputs —
// so a reconcile tick at the same activation never re-owes it. The
// marker is cleared explicitly on the deactivation arms (see
// clearLegacyNonVIPAnnounce), not as a side effect of this check.
func (d *Daemon) legacyNonVIPAnnouncePending(rgID int) bool {
	if d.isNoRethVRRP() {
		return false
	}
	d.rgStatesMu.RLock()
	s := d.rgStates[rgID]
	d.rgStatesMu.RUnlock()
	if s == nil {
		return false
	}
	active, generation := s.CurrentActivation()
	if !active {
		return false
	}
	d.nonVIPAnnounceMu.Lock()
	defer d.nonVIPAnnounceMu.Unlock()
	return d.nonVIPAnnounced[rgID] != generation
}

// clearLegacyNonVIPAnnounce drops the per-activation claim for rgID so
// the next activation re-announces (#17052). Called explicitly from
// every deactivation arm — cluster demotion, VRRP BACKUP and the
// reconcile deactivation path in daemon_ha.go — never as a side effect
// of a pending check, so a producer that merely observes an inactive
// RG cannot silently consume the lifecycle event.
func (d *Daemon) clearLegacyNonVIPAnnounce(rgID int) {
	d.nonVIPAnnounceMu.Lock()
	defer d.nonVIPAnnounceMu.Unlock()
	delete(d.nonVIPAnnounced, rgID)
}

// convergeLegacyNonVIPAnnounce sends the non-VIP announce exactly once
// per activation generation when it is still owed (#17052, the #16696
// level-triggered pattern applied to announcements). Every producer
// that observes an activation -- cluster-primary, VRRP MASTER, and the
// periodic reconcile -- funnels through here, so cluster-first ordering
// (the default userspace / non-strict case, where SetCluster consumes
// the edge and ForceRGMaster then reports Changed=false to the VRRP
// handler) can no longer swallow the announce, and no producer can
// double-burst a generation another producer already claimed.
//
// The claim is atomic: the (active, generation) pair is read in ONE
// rg-state lock hold (CurrentActivation) and the generation observed
// there is the one claimed under nonVIPAnnounceMu BEFORE any frame is
// sent, so a racing producer cannot interleave a second burst and a
// newer generation arriving between the read and the claim is never
// silently consumed — it stays unclaimed and the next producer (or the
// same call's caller on its next pass) sends for it. Keyed to the
// activation generation, NOT CurrentDesired's epoch: epoch bumps on
// every reconcileLocked input (every 2s reconcile pass), which would
// re-send the full burst forever.
func (d *Daemon) convergeLegacyNonVIPAnnounce(rgID int) {
	if d.isNoRethVRRP() {
		return
	}
	d.rgStatesMu.RLock()
	s := d.rgStates[rgID]
	d.rgStatesMu.RUnlock()
	if s == nil {
		return
	}
	active, generation := s.CurrentActivation()
	if !active {
		return
	}
	d.nonVIPAnnounceMu.Lock()
	if d.nonVIPAnnounced == nil {
		d.nonVIPAnnounced = make(map[int]uint64)
	}
	if d.nonVIPAnnounced[rgID] == generation {
		d.nonVIPAnnounceMu.Unlock()
		return
	}
	d.nonVIPAnnounced[rgID] = generation
	d.nonVIPAnnounceMu.Unlock()
	d.sendVRRPModeNonVIPAnnounce(rgID)
}

// sendVRRPModeNonVIPAnnounce sends, in legacy VRRP mode, the non-VIP
// half of the shared target set on RG activation (#17052): the router
// link-local NAs and the pool GARPs/NAs that pkg/vrrp never sends (it
// owns only the VIPs). Gated on continued mastership via rgState.
// Producers reach this ONLY through convergeLegacyNonVIPAnnounce, which
// owns the exactly-once claim for the activation generation.
func (d *Daemon) sendVRRPModeNonVIPAnnounce(rgID int) {
	if d.isNoRethVRRP() {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	stillValid := func() bool {
		d.rgStatesMu.RLock()
		s := d.rgStates[rgID]
		d.rgStatesMu.RUnlock()
		return s != nil && s.IsActive()
	}
	if !stillValid() {
		return
	}
	_, configured, clamped := cluster.AnnounceBurstCount(cfg, rgID)
	if clamped && d.warnGARPClampOnce(rgID) {
		slog.Warn("vrrp-mode announce: gratuitous-arp-count clamped to runtime safety maximum",
			"rg", rgID, "configured", configured,
			"clamped", clusterClampedCount(cfg, rgID),
			"max", config.GratuitousARPBurstClamp)
	}
	res := cluster.SendAnnounceTargets(cluster.NonVIPAnnounceTargets(cfg, rgID), stillValid, d.directSender())
	if res.PoolTruncated && d.warnPoolTruncOnce(rgID) {
		slog.Warn("vrrp-mode announce: pool proxy-ARP/NDP announce truncated",
			"rg", rgID, "attempted", res.PoolAttempted,
			"max", cluster.PoolAnnounceMaxAddresses,
			"consequence", "the remaining pool addresses rely on upstream neighbor-discovery ageing")
	}
}

// resetVIPWarnings drops the VIP warning-suppression set so a new config gets
// fresh warnings (#7532). Safe to call concurrently with the reconcile path.
func (d *Daemon) resetVIPWarnings() {
	d.vipWarnedMu.Lock()
	defer d.vipWarnedMu.Unlock()
	d.vipWarnedIfaces = nil
}

// shouldWarnVIPIface reports whether this interface's "interface not found"
// warning should be emitted now, and records that it was (#7532).
//
// The check and the record are ONE critical section on purpose. Splitting them —
// as the open-coded version did — lets two reconcile passes both observe "not
// yet warned" and both log, which is the spam the set exists to prevent, on top
// of being a racy map write.
func (d *Daemon) shouldWarnVIPIface(ifName string) bool {
	d.vipWarnedMu.Lock()
	defer d.vipWarnedMu.Unlock()
	if d.vipWarnedIfaces == nil {
		d.vipWarnedIfaces = make(map[string]bool)
	}
	if d.vipWarnedIfaces[ifName] {
		return false
	}
	d.vipWarnedIfaces[ifName] = true
	return true
}

// clearVIPWarning forgets this interface's suppression so a later disappearance
// warns again (#7532). A nil map deletes nothing, which is the intended no-op.
func (d *Daemon) clearVIPWarning(ifName string) {
	d.vipWarnedMu.Lock()
	defer d.vipWarnedMu.Unlock()
	delete(d.vipWarnedIfaces, ifName)
}

// proxyARPAnnounceMaxAddresses is retained as the daemon spelling of
// the shared bound (#17052: the constant now lives in pkg/cluster).
const proxyARPAnnounceMaxAddresses = cluster.PoolAnnounceMaxAddresses

// warnPoolTruncOnce mirrors warnGARPClampOnce for the pool-truncation
// warning: at most once per RG (never per failover).
func (d *Daemon) warnPoolTruncOnce(rgID int) bool {
	d.garpClampWarnMu.Lock()
	defer d.garpClampWarnMu.Unlock()
	if d.poolTruncWarned == nil {
		d.poolTruncWarned = make(map[int]bool)
	}
	if d.poolTruncWarned[rgID] {
		return false
	}
	d.poolTruncWarned[rgID] = true
	return true
}

// announceProxyARPPoolAddresses sends ONE gratuitous ARP per IPv4 pool
// address and ONE unsolicited NA per IPv6 pool address for rgID, via
// the shared announce engine (#17052). Kept as a named entry point for
// the #8405/#12172 tests; production failover announce goes through
// directSendGARPs / sendVRRPModeNonVIPAnnounce, which include these
// targets in the full set. stillValid is REQUIRED (#17158): a nil
// predicate is refused up front, once, rather than failing per address
// inside the gated senders.
func (d *Daemon) announceProxyARPPoolAddresses(cfg *config.Config, rgID int, stillValid cluster.BurstStillValid) {
	if cfg == nil || rgID <= 0 {
		return
	}
	if stillValid == nil {
		// #17158: the burst predicate is required. A nil predicate here
		// would be refused by every burst sender anyway; refuse once,
		// up front, rather than logging a send failure per address.
		slog.Warn("directSendGARPs: pool announce refused (nil burst predicate)",
			"rg", rgID)
		return
	}
	res := cluster.SendAnnounceTargets(cluster.PoolAnnounceTargets(cfg, rgID), stillValid, d.directSender())
	if res.PoolTruncated && d.warnPoolTruncOnce(rgID) {
		slog.Warn("directSendGARPs: pool proxy-ARP/NDP announce truncated",
			"rg", rgID, "attempted", res.PoolAttempted,
			"max", cluster.PoolAnnounceMaxAddresses,
			"consequence", "the remaining pool addresses rely on upstream neighbor-discovery ageing")
	}
	if res.Sent > 0 {
		slog.Info("directSendGARPs: announced pool proxy-ARP/NDP addresses",
			"rg", rgID, "count", res.Sent)
	}
}
