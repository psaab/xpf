package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/vrrp"
)

// checkVIPReadiness verifies that RETH interfaces for the given RG exist and
// are operationally UP, so that VIPs can actually be added. Used in
// private-rg-election mode where there are no VRRP instances to gate readiness.
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
	return d.checkVIPReadiness(rgID)
}

func (d *Daemon) takeoverReadinessForRG(rgID int, ifReady bool, ifReasons []string, fabricReady, noRethVRRP bool) (bool, []string) {
	var takeoverGateReady bool
	var takeoverGateReasons []string
	if noRethVRRP {
		// This reduces the no-RETH VRRP/takeover gate component to
		// whether VIP ownership can be established on the local node.
		takeoverGateReady, takeoverGateReasons = d.checkNoRethTakeoverReadiness(rgID)
	} else if d.vrrpMgr != nil {
		hasRETH := rgHasRETH(d.store.ActiveConfig(), rgID)
		takeoverGateReady, takeoverGateReasons = d.vrrpMgr.RGVRRPReady(rgID, hasRETH)
	} else {
		takeoverGateReady = true // no VRRP = always ready
	}

	userspaceReady, userspaceReasons := d.checkUserspaceTakeoverReadiness(rgID)
	ready := ifReady && takeoverGateReady && fabricReady && userspaceReady

	var reasons []string
	reasons = append(reasons, ifReasons...)
	reasons = append(reasons, takeoverGateReasons...)
	if !fabricReady {
		reasons = append(reasons, "fabric forwarding path not ready")
	}
	reasons = append(reasons, userspaceReasons...)
	return ready, reasons
}

// checkVIPReadinessForConfig verifies that RETH interfaces for the given RG
// exist and are operationally UP. Pure function for testability.
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
		up := link.Attrs().OperState == netlink.OperUp ||
			link.Attrs().Flags&net.FlagUp != 0
		if !up {
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
			if d.vipWarnedIfaces == nil {
				d.vipWarnedIfaces = make(map[string]bool)
			}
			if !d.vipWarnedIfaces[ifName] {
				slog.Warn("directAddVIPs: interface not found", "iface", ifName, "err", err)
				d.vipWarnedIfaces[ifName] = true
			}
			continue
		}
		// Interface exists now — clear any previous warning suppression
		delete(d.vipWarnedIfaces, ifName)
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

	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup != rgID {
			continue
		}
		if !strings.HasPrefix(ifName, "reth") {
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

	for ifName, ifc := range cfg.Interfaces.Interfaces {
		if ifc.RedundancyGroup != rgID {
			continue
		}
		if !strings.HasPrefix(ifName, "reth") {
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

// directSendGARPs sends gratuitous ARP/IPv6 NA bursts for all VIPs in the
// given RG. Reads per-RG GratuitousARPCount (default 3).
func (d *Daemon) directSendGARPs(rgID int) {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return
	}
	// Read per-RG GARP count.
	garpCount := 3
	if cc := cfg.Chassis.Cluster; cc != nil {
		for _, rg := range cc.RedundancyGroups {
			if rg.ID == rgID && rg.GratuitousARPCount > 0 {
				garpCount = rg.GratuitousARPCount
			}
		}
	}

	vipMap := vrrp.RethVIPsForRG(cfg, rgID)
	for ifName, addrs := range vipMap {
		for _, cidr := range addrs {
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			if ip.To4() != nil {
				if err := cluster.SendGratuitousARPBurst(ifName, ip, garpCount); err != nil {
					slog.Warn("directSendGARPs: GARP failed", "iface", ifName, "ip", ip, "err", err)
				}
				// Send ARP probe to gateway (.1) to update upstream ARP caches.
				_, ipNet, _ := net.ParseCIDR(cidr)
				if ipNet != nil {
					gw := make(net.IP, len(ipNet.IP))
					copy(gw, ipNet.IP)
					gw[len(gw)-1] = 1
					if err := cluster.SendARPProbe(ifName, gw); err != nil {
						slog.Warn("directSendGARPs: ARP probe failed", "iface", ifName, "gw", gw, "err", err)
					}
				}
			} else {
				if err := cluster.SendGratuitousIPv6Burst(ifName, ip, garpCount); err != nil {
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
		for ifName, ifc := range cfg.Interfaces.Interfaces {
			if ifc.RedundancyGroup != rgID || !strings.HasPrefix(ifName, "reth") {
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
				if err := cluster.SendGratuitousIPv6Burst(linuxName, routerLL, garpCount); err != nil {
					slog.Warn("directSendGARPs: router link-local NA failed",
						"iface", linuxName, "ip", routerLL, "err", err)
				}
			}
			// Send on each VLAN sub-interface.
			for _, unit := range ifc.Units {
				if unit.VlanID > 0 {
					subIface := fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
					if !seen[subIface] {
						seen[subIface] = true
						if err := cluster.SendGratuitousIPv6Burst(subIface, routerLL, garpCount); err != nil {
							slog.Warn("directSendGARPs: router link-local NA failed",
								"iface", subIface, "ip", routerLL, "err", err)
						}
					}
				}
			}
		}
	}
}
