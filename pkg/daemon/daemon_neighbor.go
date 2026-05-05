// Package daemon implements the xpf daemon lifecycle.
package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// #1197: preinstallSnapshotNeighbors was deleted. It unconditionally
// pushed the userspace-dp's in-memory neighbor snapshot back into
// the kernel ARP table every 15s, which would revert kernel-learned
// fresher MACs to stale snapshot MACs and break forwarding until
// xpfd restart. The replacement is event-driven: see
// daemon_neighbor_listener.go for the RTM_NEWNEIGH/DELNEIGH listener
// (kernel-as-authority) and forceProbeNeighbors for the periodic
// proactive ARP/NS probe that keeps kernel entries fresh.

// resolveNeighbors proactively triggers ARP/NDP resolution for all known
// next-hops, gateways, NAT destinations, and address-book host entries.
// This ensures bpf_fib_lookup returns SUCCESS (with valid MAC addresses)
// instead of NO_NEIGH for the first packet.
//
// Runtime: the synchronous portion collects targets via netlink RouteGet +
// NeighList (~1-2ms each), then fires ICMP/NS probes as goroutines. For a
// typical config with 2-5 next-hops, the blocking phase completes in <10ms.
// The 500ms sleep at the end waits for ARP replies; callers that cannot
// afford the sleep should invoke this from a goroutine.
func (d *Daemon) resolveNeighbors(cfg *config.Config) {
	d.resolveNeighborsInner(cfg, true)
}

// neighborProbeTarget is the (IP, linkIndex) pair for a neighbor
// xpfd wants to probe via ARP/NDP. Used by both resolveNeighborsInner
// and forceProbeNeighbors (#1197).
type neighborProbeTarget struct {
	neighborIP net.IP
	linkIndex  int
}

// collectNeighborProbeTargets returns the deduped target list
// xpfd actively cares about: static-route next-hops, DHCP gateways,
// backup router, DNAT pool addresses, static NAT translated
// addresses, address-book host entries (/32 and /128 only).
//
// #1197: extracted from resolveNeighborsInner so both that
// function and forceProbeNeighbors share one source of truth for
// the configured-target set.
func (d *Daemon) collectNeighborProbeTargets(cfg *config.Config) []neighborProbeTarget {
	var targets []neighborProbeTarget
	seen := make(map[string]bool)
	if cfg == nil {
		return nil
	}

	addByLink := func(ip net.IP, linkIndex int) {
		key := fmt.Sprintf("%s@%d", ip, linkIndex)
		if seen[key] {
			return
		}
		seen[key] = true
		targets = append(targets, neighborProbeTarget{neighborIP: ip, linkIndex: linkIndex})
	}

	addByIP := func(ipStr string) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return
		}
		routes, err := netlink.RouteGet(ip)
		if err != nil || len(routes) == 0 {
			return
		}
		neighborIP := ip
		if gw := routes[0].Gw; gw != nil && !gw.IsUnspecified() {
			neighborIP = gw
		}
		addByLink(neighborIP, routes[0].LinkIndex)
	}

	addByName := func(ipStr, ifName string) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return
		}
		resolved := resolveJunosIfName(cfg, ifName)
		link, err := netlink.LinkByName(resolved)
		if err != nil {
			return
		}
		addByLink(ip, link.Attrs().Index)
	}

	addByIPOrConfig := func(ipStr string) {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return
		}
		routes, err := netlink.RouteGet(ip)
		if err == nil && len(routes) > 0 {
			neighborIP := ip
			if gw := routes[0].Gw; gw != nil && !gw.IsUnspecified() {
				neighborIP = gw
			}
			addByLink(neighborIP, routes[0].LinkIndex)
			return
		}
		for name, ifc := range cfg.Interfaces.Interfaces {
			if ifc == nil {
				continue
			}
			for unitNum, unit := range ifc.Units {
				if unit == nil {
					continue
				}
				for _, addrStr := range unit.Addresses {
					_, ipNet, err := net.ParseCIDR(addrStr)
					if err != nil || !ipNet.Contains(ip) {
						continue
					}
					linuxName := resolveJunosIfName(cfg, name)
					if unit.VlanID > 0 {
						linuxName = fmt.Sprintf("%s.%d", linuxName, unit.VlanID)
					} else if unitNum != 0 {
						linuxName = fmt.Sprintf("%s.%d", linuxName, unitNum)
					}
					link, err := netlink.LinkByName(linuxName)
					if err != nil {
						continue
					}
					addByLink(ip, link.Attrs().Index)
					return
				}
			}
		}
	}

	// 1. Static route next-hops
	allStaticRoutes := append(cfg.RoutingOptions.StaticRoutes, cfg.RoutingOptions.Inet6StaticRoutes...)
	for _, sr := range allStaticRoutes {
		if sr.Discard {
			continue
		}
		for _, nh := range sr.NextHops {
			if nh.Address == "" {
				continue
			}
			if nh.Interface != "" {
				addByName(nh.Address, nh.Interface)
			} else {
				addByIPOrConfig(nh.Address)
			}
		}
	}
	for _, ri := range cfg.RoutingInstances {
		for _, sr := range append(ri.StaticRoutes, ri.Inet6StaticRoutes...) {
			if sr.Discard {
				continue
			}
			for _, nh := range sr.NextHops {
				if nh.Address == "" {
					continue
				}
				if nh.Interface != "" {
					addByName(nh.Address, nh.Interface)
				} else {
					addByIPOrConfig(nh.Address)
				}
			}
		}
	}

	// 2. DHCP-learned gateways
	if d.dhcp != nil {
		for _, lease := range d.dhcp.Leases() {
			if lease.Gateway.IsValid() {
				addByName(lease.Gateway.String(), lease.Interface)
			}
		}
	}

	// 3. Backup router next-hop
	if cfg.System.BackupRouter != "" {
		addByIP(cfg.System.BackupRouter)
	}

	// 4. DNAT pool addresses
	if cfg.Security.NAT.Destination != nil {
		for _, pool := range cfg.Security.NAT.Destination.Pools {
			if pool.Address != "" {
				addByIP(stripCIDR(pool.Address))
			}
		}
	}

	// 5. Static NAT translated addresses
	for _, rs := range cfg.Security.NAT.Static {
		for _, rule := range rs.Rules {
			if rule.Then != "" {
				addByIP(stripCIDR(rule.Then))
			}
		}
	}

	// 6. Address-book host entries (/32 and /128 only)
	if cfg.Security.AddressBook != nil {
		for _, addr := range cfg.Security.AddressBook.Addresses {
			ip, ipNet, err := net.ParseCIDR(addr.Value)
			if err != nil {
				continue
			}
			ones, bits := ipNet.Mask.Size()
			if ones == bits {
				addByIP(ip.String())
			}
		}
	}

	return targets
}

func (d *Daemon) resolveNeighborsInner(cfg *config.Config, waitForReplies bool) {
	// #1197 v3 (Codex code-review #5): use the shared
	// collectNeighborProbeTargets helper instead of duplicating
	// the target-collection logic inline. This is the canonical
	// target source — drift between resolveNeighborsInner and
	// forceProbeNeighbors is impossible.
	targets := d.collectNeighborProbeTargets(cfg)

	// Resolve each target via ping (triggers kernel ARP/NDP resolution)
	resolved := 0
	for _, t := range targets {
		link, err := netlink.LinkByIndex(t.linkIndex)
		if err != nil {
			continue
		}
		ifName := link.Attrs().Name
		family := netlink.FAMILY_V4
		if t.neighborIP.To4() == nil {
			family = netlink.FAMILY_V6
		}
		// Skip if neighbor already exists and is usable
		neighs, _ := netlink.NeighList(t.linkIndex, family)
		skip := false
		for _, n := range neighs {
			if n.IP.Equal(t.neighborIP) && (n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT)) != 0 {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		resolved++
		// Trigger proactive neighbor discovery.
		// IPv4 continues to use ping so the kernel owns ARP resolution.
		// IPv6 additionally sends an explicit NS before pinging so the
		// failover path also nudges peer neighbor caches directly.
		go func(ip net.IP, iface string) {
			if ip.To4() == nil {
				if err := cluster.SendNDSolicitationFromInterface(iface, ip); err != nil {
					slog.Debug("neighbor warmup: IPv6 NS probe failed",
						"iface", iface, "ip", ip, "err", err)
				}
			}
			sendICMPProbe(iface, ip)
		}(t.neighborIP, ifName)
	}

	if resolved > 0 {
		slog.Info("proactive neighbor resolution", "resolving", resolved, "total_targets", len(targets))
		if waitForReplies {
			// Brief pause to allow ARP responses
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// cleanFailedNeighbors deletes NUD_FAILED neighbor entries on all interfaces
// and proactively pings the IP to pre-populate ARP/NDP for fast recovery.
//
// When a host goes down, the kernel marks its ARP/NDP entry as FAILED and
// retains it for ~60 seconds (gc_staletime). During that window, packets
// XDP_PASS'd for NO_NEIGH resolution are silently dropped by the kernel
// because it refuses to re-resolve a FAILED entry. Deleting the entry and
// pinging ensures ARP/NDP is resolved before the next forwarded packet.
func (d *Daemon) cleanFailedNeighbors() int {
	type probe struct {
		ip    net.IP
		iface string
	}
	var probes []probe
	cleaned := 0
	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		neighs, err := netlink.NeighList(0, family)
		if err != nil {
			continue
		}
		for i := range neighs {
			if neighs[i].State&netlink.NUD_FAILED != 0 {
				// Capture interface name for probing before delete.
				link, linkErr := netlink.LinkByIndex(neighs[i].LinkIndex)
				if err := netlink.NeighDel(&neighs[i]); err == nil {
					cleaned++
					if linkErr == nil {
						probes = append(probes, probe{
							ip:    neighs[i].IP,
							iface: link.Attrs().Name,
						})
					}
				}
			}
		}
	}
	if cleaned > 0 {
		slog.Debug("cleaned failed neighbor entries", "count", cleaned)
	}
	// Reprobe cleaned neighbors so the kernel's table repopulates before
	// the next forwarded packet. IPv4 keeps the existing ARP probe path.
	// IPv6 now sends an explicit NS instead of waiting for passive later
	// traffic to trigger NDP.
	for _, p := range probes {
		if p.ip.To4() != nil {
			cluster.SendARPProbe(p.iface, p.ip)
		} else {
			if err := cluster.SendNDSolicitationFromInterface(p.iface, p.ip); err != nil {
				slog.Debug("failed-neighbor reprobe: IPv6 NS failed",
					"iface", p.iface, "ip", p.ip, "err", err)
			}
		}
	}
	return cleaned
}

// runPeriodicNeighborResolution manages periodic neighbor upkeep:
//   - Every 5 seconds: clean NUD_FAILED neighbor entries so the kernel
//     retries ARP/NDP on the next forwarded packet (fast recovery).
//   - Every 15 seconds: proactively resolve known forwarding targets
//     (gateways, DNAT pools, etc.) to keep ARP/NDP entries warm.
//   - In cluster mode: continuously refresh snapshot-learned neighbors and
//     session-derived neighbor cache entries so standby forwarding stays ready
//     without activation-time warmup.
//
// Runs once immediately at start to avoid a blind spot.
// Fetches fresh active config on each tick so config changes take effect.
func (d *Daemon) runPeriodicNeighborResolution(ctx context.Context) {
	// Immediate first run — don't wait for first tick.
	// resolveNeighbors handles cold-start configured targets;
	// forceProbeNeighbors handles stale snapshot keys (only
	// useful once a snapshot exists, which it doesn't yet at
	// startup). On the first 15s tick once snapshot is warm,
	// both run with non-overlapping target sets.
	if cfg := d.store.ActiveConfig(); cfg != nil {
		d.resolveNeighbors(cfg)
		d.maintainClusterNeighborReadiness()
	}
	d.cleanFailedNeighbors()

	const (
		cleanInterval   = 5 * time.Second
		resolveInterval = 15 * time.Second
	)
	cleanTicker := time.NewTicker(cleanInterval)
	resolveTicker := time.NewTicker(resolveInterval)
	defer cleanTicker.Stop()
	defer resolveTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-cleanTicker.C:
			d.cleanFailedNeighbors()
		case <-resolveTicker.C:
			if cfg := d.store.ActiveConfig(); cfg != nil {
				d.resolveNeighbors(cfg)
				// #1197: force-probe ALL monitored neighbors
				// (including STALE/DELAY/PROBE) so kernel
				// re-validates entries that resolveNeighbors
				// would skip. Replies update kernel ARP →
				// RTM_NEWNEIGH → listener regenerates snapshot.
				d.forceProbeNeighbors(cfg)
				d.maintainClusterNeighborReadiness()
			}
		}
	}
}

// maintainClusterNeighborReadiness runs every 15 seconds (via the resolve
// ticker in runPeriodicNeighborResolution) when HA is active. It refreshes
// kernel neighbor entries and spawns warmNeighborCache which iterates the
// full session table and sends one UDP probe per unique src/dst IP. The
// session walk can be large; an atomic guard prevents overlapping runs if
// a single pass exceeds one tick interval.
func (d *Daemon) maintainClusterNeighborReadiness() {
	if d.cluster == nil {
		return
	}
	// #1197: preinstall removed; the listener (daemon_neighbor_listener.go)
	// keeps the snapshot in sync with kernel via netlink events,
	// and the periodic forceProbeNeighbors tick keeps kernel entries
	// fresh via proactive ARP/NS.
	if !d.neighborWarmupInFlight.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer d.neighborWarmupInFlight.Store(false)
		d.warmNeighborCache()
	}()
}
