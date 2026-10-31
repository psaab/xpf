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

// directAddVIPs converges rgID's RETH VIPs for the RG OWNER: adds every
// configured VIP that is absent (IPv6 with IFA_F_NODAD), stamps each as
// xpf-owned, and deletes every stamped leftover the config no longer assigns
// to its netdev (#18573 — a renumbered or removed RETH address). Idempotent.
// Returns the number of addresses actually created. See
// reconcileDirectVIPAddrs (direct_vip_reconcile_18573.go).
func (d *Daemon) directAddVIPs(rgID int) int {
	added, _ := d.reconcileDirectVIPAddrs(rgID, true)
	return added
}

// directRemoveVIPs converges rgID's RETH VIPs for a NON-owner: deletes every
// configured VIP of the RG (stamped or not) and every stamped leftover, so a
// former owner also drops an address a commit renumbered away (#18573).
// Idempotent; returns the number of addresses actually removed.
func (d *Daemon) directRemoveVIPs(rgID int) int {
	_, removed := d.reconcileDirectVIPAddrs(rgID, false)
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
// marker is cleared on real deactivation and after a total send failure
// (Sent == 0 && FirstErr != nil), not as a side effect of this check.
// Partial delivery remains claimed to avoid duplicating successful targets.
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
	claimed, ok := d.nonVIPAnnounced[rgID]
	return !ok || claimed < generation
}

// clearLegacyNonVIPAnnounce drops claims no newer than the deactivated
// generation. A late deactivation cleanup must not erase a new claim
// created by a concurrent reactivation (#17052).
func (d *Daemon) clearLegacyNonVIPAnnounce(rgID int, generation uint64) {
	d.nonVIPAnnounceMu.Lock()
	defer d.nonVIPAnnounceMu.Unlock()
	if claimed, ok := d.nonVIPAnnounced[rgID]; ok && claimed <= generation {
		delete(d.nonVIPAnnounced, rgID)
	}
}

// claimLegacyNonVIPAnnounce records generation only when it does not
// regress an existing claim. The map membership check distinguishes a
// missing claim from a stored generation zero.
func (d *Daemon) claimLegacyNonVIPAnnounce(rgID int, generation uint64) bool {
	d.nonVIPAnnounceMu.Lock()
	defer d.nonVIPAnnounceMu.Unlock()
	if d.nonVIPAnnounced == nil {
		d.nonVIPAnnounced = make(map[int]uint64)
	}
	if claimed, ok := d.nonVIPAnnounced[rgID]; ok && claimed >= generation {
		return false
	}
	d.nonVIPAnnounced[rgID] = generation
	return true
}

// convergeLegacyNonVIPAnnounce attempts the non-VIP announce for the
// current activation generation (#17052, the #16696 level-triggered
// pattern applied to announcements). Every producer that observes an
// activation -- cluster-primary, VRRP MASTER, and periodic reconcile --
// funnels through here, so cluster-first ordering (the default userspace /
// non-strict case, where SetCluster consumes the edge and ForceRGMaster
// then reports Changed=false to the VRRP handler) cannot swallow it.
//
// The claim is atomic: the (active, generation) pair is read in ONE
// rg-state lock hold (CurrentActivation) and the observed generation is
// claimed under nonVIPAnnounceMu BEFORE any frame is sent, preventing
// concurrent producers from double-sending it. Claims are monotonic
// under that mutex: an existing claim at or beyond the observed
// generation is never overwritten by an older observation (a producer
// that read generation 2 before a reactivation claimed 3 must not
// regress the marker to 2 and so re-admit generation 3 -- or re-send
// generation 2 -- on a later pass). Absence (entry deleted by the
// deactivation clear or the all-failed release) is distinguished from
// a stored value so a missing entry is always claimable.
//
// The send is bound to the claim: sendVRRPModeNonVIPAnnounce rechecks,
// immediately before the first frame and as the stillValid gate for
// every follow-up/pool frame, that the RG is still active at exactly
// this generation and that this generation is still the claimed one.
// A claimant delayed past a deactivate/reactivate cycle therefore emits
// nothing for its stale generation; the new activation's own producer
// claims and sends the new generation. This predicate form is smaller
// than holding nonVIPAnnounceMu through the send: the mutex stays a
// short claim lock (pending checks and deactivation clears are never
// blocked behind frame I/O), and the same predicate already gates
// pool/follow-up frames via SendAnnounceTargets.
//
// If every non-VIP send fails (Sent == 0 && FirstErr != nil), only this
// generation's claim is released so the next producer/reconcile pass
// can retry; partial success stays claimed to avoid duplicating
// delivered targets. Keyed to the activation generation, NOT
// CurrentDesired's epoch: epoch bumps on every reconcileLocked input
// (every 2s reconcile pass), which would re-send the full burst forever.
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
	if !d.claimLegacyNonVIPAnnounce(rgID, generation) {
		return
	}
	res := d.sendVRRPModeNonVIPAnnounce(rgID, generation)
	if res.Sent == 0 && res.FirstErr != nil {
		// No non-VIP target accepted a frame. Release only this
		// activation's claim so the next producer/reconcile pass can
		// retry; a partial success remains at-most-once to avoid
		// duplicating already-delivered targets.
		slog.Warn("vrrp-mode announce: all non-VIP targets failed; retrying on next producer/reconcile pass",
			"rg", rgID, "err", res.FirstErr)
		d.nonVIPAnnounceMu.Lock()
		if claimed, ok := d.nonVIPAnnounced[rgID]; ok && claimed == generation {
			delete(d.nonVIPAnnounced, rgID)
		}
		d.nonVIPAnnounceMu.Unlock()
	}
}

// nonVIPAnnounceClaimCurrent reports whether generation is still the
// claimed generation for rgID AND the RG is still active at exactly
// that generation (#17052). It is the generation-bound validity
// predicate for a claimed send: deactivation (inactive), reactivation
// (a newer generation), a newer claim, or the all-failed release of
// this claim each make a delayed claimant's send a no-op.
func (d *Daemon) nonVIPAnnounceClaimCurrent(rgID int, generation uint64) bool {
	d.rgStatesMu.RLock()
	s := d.rgStates[rgID]
	d.rgStatesMu.RUnlock()
	if s == nil {
		return false
	}
	// Sample activation only after acquiring the claim mutex so this
	// predicate cannot pair an old activation read with a current claim.
	d.nonVIPAnnounceMu.Lock()
	defer d.nonVIPAnnounceMu.Unlock()
	claimed, ok := d.nonVIPAnnounced[rgID]
	if !ok || claimed != generation {
		return false
	}
	active, current := s.CurrentActivation()
	return active && current == generation
}

// sendVRRPModeNonVIPAnnounce sends, in legacy VRRP mode, the non-VIP
// half of the shared target set on RG activation (#17052): the router
// link-local NAs and the pool GARPs/NAs that pkg/vrrp never sends (it
// owns only the VIPs). It is bound to the caller's activation claim:
// the RG must still be active at exactly this generation, with this
// generation still claimed, before the first frame and (via stillValid)
// before every follow-up/pool frame.
func (d *Daemon) sendVRRPModeNonVIPAnnounce(rgID int, generation uint64) cluster.AnnounceResult {
	if d.isNoRethVRRP() {
		return cluster.AnnounceResult{}
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return cluster.AnnounceResult{}
	}
	stillValid := func() bool {
		return d.nonVIPAnnounceClaimCurrent(rgID, generation)
	}
	if !stillValid() {
		return cluster.AnnounceResult{}
	}
	_, configured, clamped := cluster.AnnounceBurstCount(cfg, rgID)
	if clamped && d.warnGARPClampOnce(rgID) {
		slog.Warn("vrrp-mode announce: gratuitous-arp-count clamped to runtime safety maximum",
			"rg", rgID, "configured", configured,
			"clamped", clusterClampedCount(cfg, rgID),
			"max", config.GratuitousARPBurstClamp)
	}
	targets := cluster.NonVIPAnnounceTargets(cfg, rgID)
	if !stillValid() {
		return cluster.AnnounceResult{}
	}
	res := cluster.SendAnnounceTargets(targets, stillValid, d.directSender())
	if res.PoolTruncated && d.warnPoolTruncOnce(rgID) {
		slog.Warn("vrrp-mode announce: pool proxy-ARP/NDP announce truncated",
			"rg", rgID, "attempted", res.PoolAttempted,
			"max", cluster.PoolAnnounceMaxAddresses,
			"consequence", "the remaining pool addresses rely on upstream neighbor-discovery ageing")
	}
	return res
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
