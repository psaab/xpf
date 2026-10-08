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

// isNoRethVRRP returns true when no-reth-vrrp is explicitly configured,
// meaning the daemon directly manages VIPs/GARPs without VRRP instances.
// Default (no flag) uses VRRP for RETH failover.
func (d *Daemon) isNoRethVRRP() bool {
	cc := d.clusterConfig()
	return cc != nil && (cc.NoRethVRRP || cc.PrivateRGElection)
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
func (d *Daemon) addStableRethLinkLocal(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return
	}
	clusterID := cfg.Chassis.Cluster.ClusterID
	stableLL := cluster.StableRethLinkLocal(clusterID, rgID)
	rethToPhys := cfg.RethToPhysical()

	rgOwners := cfg.RethRGOwners() // #6781
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		// #6781: RG ownership from the shared predicate. The name test this
		// replaces excluded a structurally valid redundant pair not spelled
		// reth*, so its group got VIPs from both ownership modes but no stable
		// link-local — VRRP mastering an interface nothing else manages.
		if owns, ok := rgOwners[ifName]; !ok || owns != rgID {
			continue
		}
		// Skip interfaces with an explicitly configured link-local address —
		// the user's configured LL replaces the auto-generated stable LL.
		if rethUnitHasConfiguredLinkLocal(ifc, 0) {
			slog.Debug("skipping stable LL (explicit LL configured)", "iface", ifName)
			continue
		}
		physName := ifc.Name
		if phys, ok := rethToPhys[ifc.Name]; ok {
			physName = phys
		}
		linuxName := config.LinuxIfName(physName)
		addStableLLToInterface(linuxName, stableLL)
		for unitNum := range ifc.Units {
			if unitNum > 0 && rethUnitHasIPv6(ifc, unitNum) {
				unit := ifc.Units[unitNum]
				if unit == nil { // #6780
					continue
				}
				subIface := linuxName
				if unit.VlanID > 0 {
					subIface = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
				}
				addStableLLToInterface(subIface, stableLL)
			}
		}
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
func (d *Daemon) removeStableRethLinkLocal(rgID int) {
	if d.store == nil {
		return
	}
	cfg := d.store.ActiveConfig()
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return
	}
	clusterID := cfg.Chassis.Cluster.ClusterID
	stableLL := cluster.StableRethLinkLocal(clusterID, rgID)
	rethToPhys := cfg.RethToPhysical()

	rgOwners := cfg.RethRGOwners() // #6781
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil {
			continue
		}
		// #6781: RG ownership from the shared predicate. The name test this
		// replaces excluded a structurally valid redundant pair not spelled
		// reth*, so its group got VIPs from both ownership modes but no stable
		// link-local — VRRP mastering an interface nothing else manages.
		if owns, ok := rgOwners[ifName]; !ok || owns != rgID {
			continue
		}
		physName := ifc.Name
		if phys, ok := rethToPhys[ifc.Name]; ok {
			physName = phys
		}
		linuxName := config.LinuxIfName(physName)
		removeStableLLFromInterface(linuxName, stableLL)
		for unitNum := range ifc.Units {
			if unitNum > 0 {
				unit := ifc.Units[unitNum]
				if unit == nil { // #6780
					continue
				}
				subIface := linuxName
				if unit.VlanID > 0 {
					subIface = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
				}
				removeStableLLFromInterface(subIface, stableLL)
			}
		}
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
// raw-socket I/O. Production wires them to the cluster gated senders, which send
// the first (immediate) frame unconditionally and gate only the 50ms follow-up
// loop on the supplied BurstStillValid predicate.
var (
	directGARPBurstFn = cluster.SendGratuitousARPBurstGated
	directNABurstFn   = cluster.SendGratuitousIPv6BurstGated
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

// directSendGARPs sends gratuitous ARP/IPv6 NA bursts for all VIPs in the
// given RG. Reads per-RG GratuitousARPCount (default 3).
func (d *Daemon) directSendGARPs(rgID int) {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	// #2898: capture the announce sequence at burst start and gate every 50ms
	// follow-up frame on continued direct-mode ownership of this RG's VIPs. The
	// first (immediate) frame in each cluster burst is sent unconditionally;
	// only the follow-ups are gated (mirrors the VRRP path in #2867/#2894).
	d.directAnnounceMu.Lock()
	seq := d.directAnnounceSeq[rgID]
	d.directAnnounceMu.Unlock()
	stillValid := d.directBurstStillValid(rgID, seq)
	// Read per-RG GARP count.
	garpCount := 3
	if cc := cfg.Chassis.Cluster; cc != nil {
		for _, rg := range cc.RedundancyGroups {
			if rg.ID == rgID && rg.GratuitousARPCount > 0 {
				garpCount = rg.GratuitousARPCount
			}
		}
	}
	// #5695 (codex-182 M16): clamp the configured count to the runtime safety
	// maximum before it drives per-VIP raw-socket bursts. Without the clamp an
	// unbounded count would fan (count-1) 50ms follow-up frames per VIP on
	// every direct-mode failover — a self-inflicted CPU/socket-exhaustion
	// vector. Warn at most ONCE per RG (directSendGARPs runs on the
	// per-failover path — never Warn per send).
	if clamped, was := config.ClampGratuitousARPCount(garpCount); was {
		if d.warnGARPClampOnce(rgID) {
			slog.Warn("directSendGARPs: gratuitous-arp-count clamped to runtime safety maximum",
				"rg", rgID, "configured", garpCount, "clamped", clamped,
				"max", config.GratuitousARPBurstClamp)
		}
		garpCount = clamped
	}

	vipMap := vrrp.RethVIPsForRG(cfg, rgID)
	for ifName, addrs := range vipMap {
		for _, cidr := range addrs {
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if ip.To4() != nil {
				if err := directGARPBurstFn(ifName, ip, garpCount, stillValid); err != nil {
					slog.Warn("directSendGARPs: GARP failed", "iface", ifName, "ip", ip, "err", err)
				}
				// Send a directed ARP probe to the subnet's first usable host
				// (network address + 1, the most common gateway) so a router
				// that ignores broadcast gratuitous ARP still re-binds the VIP
				// to our MAC. The target derivation is the single source of
				// truth vrrp.GatewayProbeTarget: it respects the actual prefix
				// length and returns ok=false on /31 (RFC 3021) and /32 where
				// no in-subnet gateway host exists. Pre-#3922 this site forced
				// the network address's last octet to .1, which lands OUTSIDE
				// the subnet on /25+ or a non-.0 network (e.g. 10.0.61.18/28 →
				// 10.0.61.1, outside .16-.31) → the probe went to a foreign
				// address and the real gateway's ARP cache was never updated →
				// post-failover blackhole. #2377 fixed the analogous forced-.1
				// in vrrp.sendGARP but missed this direct-mode site.
				_, ipNet, _ := net.ParseCIDR(cidr)
				if ipNet != nil {
					if gw, ok := vrrp.GatewayProbeTarget(ipNet); ok && !gw.Equal(ip.To4()) {
						// Skip when network+1 is the VIP itself — otherwise we
						// would probe ourselves. Use the VIP as the ARP sender
						// so the gateway re-binds VIP -> our MAC, not the
						// primary IP -> MAC (#2152).
						if err := directARPProbeFn(ifName, ip.To4(), gw); err != nil {
							slog.Warn("directSendGARPs: ARP probe failed", "iface", ifName, "gw", gw, "err", err)
						}
					}
				}
			} else {
				if err := directNABurstFn(ifName, ip, garpCount, stillValid); err != nil {
					slog.Warn("directSendGARPs: IPv6 NA failed", "iface", ifName, "ip", ip, "err", err)
				}
			}
		}
	}

	// Send NA burst for router link-local so hosts update neighbor cache for
	// the router identity (not just VIPs). Uses the explicitly configured
	// link-local if present, otherwise the auto-generated stable LL.
	// Send on base interface AND all VLAN sub-interfaces (separate L2 domains).
	if cfg.Chassis.Cluster != nil {
		stableLL := cluster.StableRethLinkLocal(cfg.Chassis.Cluster.ClusterID, rgID)
		rethToPhys := cfg.RethToPhysical()
		seen := make(map[string]bool)
		rgOwners := cfg.RethRGOwners() // #6781
		for ifName, ifc := range cfg.Interfaces.Interfaces {
			if ifc == nil {
				continue
			}
			if owns, ok := rgOwners[ifName]; !ok || owns != rgID { // #6781
				continue
			}
			// Use configured link-local if present, otherwise stable LL.
			routerLL := stableLL
			if unit, ok := ifc.Units[0]; ok {
				for _, addr := range unit.Addresses {
					ip, _, err := net.ParseCIDR(addr)
					if err == nil && ip.IsLinkLocalUnicast() && ip.To4() == nil {
						routerLL = ip
						break
					}
				}
			}
			physName := ifc.Name
			if phys, ok := rethToPhys[ifc.Name]; ok {
				physName = phys
			}
			linuxName := config.LinuxIfName(physName)
			// Send on base interface.
			if !seen[linuxName] {
				seen[linuxName] = true
				if err := directNABurstFn(linuxName, routerLL, garpCount, stillValid); err != nil {
					slog.Warn("directSendGARPs: router link-local NA failed",
						"iface", linuxName, "ip", routerLL, "err", err)
				}
			}
			// Send on each VLAN sub-interface.
			for _, unit := range ifc.Units {
				if unit == nil { // #6780
					continue
				}
				if unit.VlanID > 0 {
					subIface := fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
					if !seen[subIface] {
						seen[subIface] = true
						if err := directNABurstFn(subIface, routerLL, garpCount, stillValid); err != nil {
							slog.Warn("directSendGARPs: router link-local NA failed",
								"iface", subIface, "ip", routerLL, "err", err)
						}
					}
				}
			}
		}
	}

	// #8405: announce the POOL addresses too, not just the VIPs.
	//
	// #8297 stopped the standby ANSWERING proxy-ARP for a pool address on an RG
	// it does not own. That is necessary and not sufficient: removing a
	// responder does not invalidate a binding already cached upstream. Measured
	// on the cluster -- the seven misdelivered SYN-ACKs carried the STANDBY's
	// MAC (`02:bf:72:16:01:01`) on a non-promiscuous NIC, so they were
	// addressed to it, so the upstream had the pool address bound to the
	// standby. The new owner has to ANNOUNCE rather than wait for the upstream
	// to re-resolve on its own schedule.
	d.announceProxyARPPoolAddresses(cfg, rgID, stillValid)
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

// proxyARPAnnounceMaxAddresses bounds how many pool addresses one RG's
// ownership change announces.
//
// #8405. A proxy-arp statement expands to at most proxyARPMaxExpandedHosts
// (256) addresses and an interface may carry several, so an unbounded announce
// would fan hundreds of raw-socket sends per failover — recreating the
// self-inflicted CPU/socket-exhaustion vector that GratuitousARPBurstClamp
// exists to prevent, arriving through a different door.
//
// 64 is chosen against the shape of the fault rather than as a round number: a
// pool address needs announcing only if an upstream has it CACHED, which
// requires it to have been used for translation, and a deployment translating
// through more than 64 distinct pool addresses in the lifetime of one upstream
// neighbor entry is not the one this fix is for. Exceeding it warns once per RG
// and announces the first 64 in configured order — deterministic, so the same
// addresses are announced on every failover rather than an arbitrary subset.
const proxyARPAnnounceMaxAddresses = 64

// announceProxyARPPoolAddresses sends ONE gratuitous ARP for each IPv4
// proxy-ARP pool address and ONE unsolicited NA for each IPv6 proxy-NDP pool
// address on the interfaces belonging to rgID.
//
// ONE, not a burst. The burst exists to survive loss when a single VIP must be
// re-bound; here the job is breadth — invalidating one upstream binding per
// address — and depth × breadth is what turns this into a storm. A missed
// announce is recovered by the upstream's own neighbor-discovery ageing, which
// was the pre-#8405 behavior for every address.
//
// #8621: that recovery sentence is TRUE ONLY NOW. It assumes the upstream's
// re-ARP gets an answer, and until #8621 nothing answered for a pool address
// inside its own egress interface's connected subnet -- every arm of the
// kernel's proxy branch is gated on the route egressing a DIFFERENT device than
// the request arrived on, so the NTF_PROXY entry and the `proxy_arp` sysctl the
// daemon installs were both inert there. This announce was therefore the ONLY
// thing that ever bound the address upstream, and the "recovery" was an ageing
// timer into a blackhole. The userspace responder
// (daemon_proxyarp_responder_8621.go) is what makes the assumption hold.
//
// The RG filter is `proxyARPRedundancyGroupFor`, the SAME predicate #8297's
// suppression uses. That is deliberate: this announces exactly the set the
// standby stops answering for, so the two cannot disagree about which
// addresses belong to which RG. A divergence there would announce an address
// this node does not own — telling the upstream to send us traffic for an RG
// the peer is primary for, which is worse than the stale binding being fixed.
func (d *Daemon) announceProxyARPPoolAddresses(cfg *config.Config, rgID int, stillValid cluster.BurstStillValid) {
	if cfg == nil || rgID <= 0 {
		return
	}
	sent := 0
	attempted := 0
	truncated := false
	for _, entry := range cfg.Security.NAT.ProxyARP {
		if proxyARPRedundancyGroupFor(cfg, entry.Interface) != rgID {
			continue
		}
		ifName := cfg.ResolveKernelIfName(entry.Interface)
		if ifName == "" {
			continue
		}
		for _, cidr := range entry.Addresses {
			if stillValid != nil && !stillValid() {
				return // ownership moved again mid-announce; stop rather than lie
			}
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				if ip = net.ParseIP(cidr); ip == nil {
					continue
				}
			}
			if attempted >= proxyARPAnnounceMaxAddresses {
				truncated = true
				break
			}
			// Bound attempted sends, not only successful announcements: a
			// failed raw-socket send must not reopen the per-failover budget.
			attempted++
			if ip.To4() != nil {
				if err := directGARPBurstFn(ifName, ip, 1, stillValid); err != nil {
					slog.Warn("directSendGARPs: pool proxy-ARP announce failed",
						"iface", ifName, "ip", ip, "rg", rgID, "err", err)
					continue
				}
			} else {
				if err := directNABurstFn(ifName, ip, 1, stillValid); err != nil {
					slog.Warn("directSendGARPs: pool proxy-NDP announce failed",
						"iface", ifName, "ip", ip, "rg", rgID, "err", err)
					continue
				}
			}
			sent++
		}
		if truncated {
			break
		}
	}
	if truncated && d.warnGARPClampOnce(rgID) {
		slog.Warn("directSendGARPs: pool proxy-ARP/NDP announce truncated",
			"rg", rgID, "announced", sent, "attempted", attempted,
			"max", proxyARPAnnounceMaxAddresses,
			"consequence", "the remaining pool addresses rely on upstream neighbor-discovery ageing")
	}
	if sent > 0 {
		slog.Info("directSendGARPs: announced pool proxy-ARP/NDP addresses",
			"rg", rgID, "count", sent)
	}
}
