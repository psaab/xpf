package daemon

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// ensureFabricIPVLAN creates an IPVLAN L2 interface on top of parent for
// fabric IP addressing. The parent keeps its ge-X-0-Y name (XDP/TC attaches
// there); the IPVLAN carries the fabric IP used for session sync.
// Idempotent: skips creation if the IPVLAN already exists on the correct parent.
func ensureFabricIPVLAN(parent, name string, addrs []string) error {
	parentLink, err := netlink.LinkByName(parent)
	if err != nil {
		return fmt.Errorf("parent %s: %w", parent, err)
	}

	// Ensure parent is UP — IPVLAN inherits carrier from parent.
	netlink.LinkSetUp(parentLink)

	// Set jumbo MTU on parent for fabric throughput — IPVLAN inherits
	// parent MTU as upper bound, so parent must be set first.
	if parentLink.Attrs().MTU < 9000 {
		if err := netlink.LinkSetMTU(parentLink, 9000); err != nil {
			slog.Warn("fabric: failed to set parent MTU 9000",
				"parent", parent, "err", err)
		}
	}

	// Check if IPVLAN already exists on correct parent.
	if existing, err := netlink.LinkByName(name); err == nil {
		if existing.Attrs().ParentIndex == parentLink.Attrs().Index {
			// Already correct — reconcile addresses, MTU, and ensure UP (#127).
			if existing.Attrs().MTU < 9000 {
				netlink.LinkSetMTU(existing, 9000)
			}
			reconcileIPVLANAddrs(existing, name, addrs)
			netlink.LinkSetUp(existing)
			return nil
		}
		// Wrong parent — remove and recreate.
		netlink.LinkDel(existing)
	}

	ipvlan := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        name,
			ParentIndex: parentLink.Attrs().Index,
		},
		Mode: netlink.IPVLAN_MODE_L2,
	}
	if err := netlink.LinkAdd(ipvlan); err != nil {
		return fmt.Errorf("create IPVLAN %s on %s: %w", name, parent, err)
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("find created IPVLAN %s: %w", name, err)
	}

	// Set jumbo MTU on IPVLAN overlay (must not exceed parent MTU).
	if err := netlink.LinkSetMTU(link, 9000); err != nil {
		slog.Warn("fabric IPVLAN: failed to set MTU 9000",
			"name", name, "err", err)
	}

	// Add configured addresses.
	for _, addrStr := range addrs {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			slog.Warn("fabric IPVLAN: invalid address", "addr", addrStr, "err", err)
			continue
		}
		if err := netlink.AddrReplace(link, addr); err != nil {
			slog.Warn("fabric IPVLAN: failed to add address",
				"name", name, "addr", addrStr, "err", err)
		}
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}
	slog.Info("created fabric IPVLAN", "name", name, "parent", parent,
		"addrs", addrs)
	return nil
}

// reconcileIPVLANAddrs adds missing addresses and removes stale ones from an
// existing IPVLAN interface (#127). Called when ensureFabricIPVLAN finds the
// overlay already exists on the correct parent.
func reconcileIPVLANAddrs(link netlink.Link, name string, desired []string) {
	// Build set of desired addresses (normalized to CIDR strings).
	want := make(map[string]*netlink.Addr, len(desired))
	for _, addrStr := range desired {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			slog.Warn("fabric IPVLAN: invalid address in config", "addr", addrStr, "err", err)
			continue
		}
		want[addr.IPNet.String()] = addr
	}

	// Get current addresses.
	existing, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		slog.Warn("fabric IPVLAN: failed to list addresses", "name", name, "err", err)
		return
	}

	// Remove stale addresses not in desired set.
	have := make(map[string]bool, len(existing))
	for _, a := range existing {
		key := a.IPNet.String()
		have[key] = true
		if _, ok := want[key]; !ok {
			if err := netlink.AddrDel(link, &a); err != nil {
				slog.Warn("fabric IPVLAN: failed to remove stale address",
					"name", name, "addr", key, "err", err)
			} else {
				slog.Info("fabric IPVLAN: removed stale address",
					"name", name, "addr", key)
			}
		}
	}

	// Add missing addresses.
	for key, addr := range want {
		if !have[key] {
			if err := netlink.AddrReplace(link, addr); err != nil {
				slog.Warn("fabric IPVLAN: failed to add address",
					"name", name, "addr", key, "err", err)
			} else {
				slog.Info("fabric IPVLAN: added missing address",
					"name", name, "addr", key)
			}
		}
	}
}

// CleanupFabricIPVLANs removes all fabric IPVLAN interfaces (fab0, fab1).
func CleanupFabricIPVLANs() {
	for _, name := range []string{"fab0", "fab1"} {
		if link, err := netlink.LinkByName(name); err == nil {
			if _, ok := link.(*netlink.IPVlan); ok {
				netlink.LinkDel(link)
				slog.Info("removed fabric IPVLAN", "name", name)
			}
		}
	}
}

// resolveFabricParent returns the Linux name of the physical parent interface
// for a fabric interface (e.g. fab0 → ge-0-0-0). Falls back to fabName if
// no LocalFabricMember is configured (legacy mode).
func (d *Daemon) resolveFabricParent(fabName string) string {
	cfg := d.store.ActiveConfig()
	if cfg == nil {
		return fabName
	}
	if ifCfg, ok := cfg.Interfaces.Interfaces[fabName]; ok && ifCfg.LocalFabricMember != "" {
		return config.LinuxIfName(ifCfg.LocalFabricMember)
	}
	return fabName
}

// populateFabricFwd resolves the fabric interface MACs and populates the
// fabric_fwd BPF map for cross-chassis packet redirect during failback.
// fabIface is the physical parent (XDP attachment point); overlay is the
// IPVLAN child where the sync IP lives (neighbor resolution target, #129).
// If overlay is empty, fabIface is used for both (legacy/no-IPVLAN mode).
// Attempts immediately on startup with fast 500ms retries (10 attempts),
// then falls back to 30s periodic refresh.
func (d *Daemon) populateFabricFwd(ctx context.Context, fabIface, overlay, peerAddr string) {
	peerIP := net.ParseIP(peerAddr)
	if peerIP == nil {
		slog.Warn("cluster: invalid fabric peer address", "addr", peerAddr)
		return
	}
	if overlay == "" {
		overlay = fabIface
	}

	// Store fabric config for RefreshFabricFwd.
	d.fabricMu.Lock()
	d.fabricIface = fabIface
	d.fabricOverlay = overlay
	d.fabricPeerIP = peerIP
	d.fabricMu.Unlock()

	// Fast initial population: attempt immediately, then 500ms retries.
	for i := 0; i < 10; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}

		// Actively probe for neighbor entry on the overlay (#129).
		d.probeFabricNeighbor(ctx, overlay, peerIP)

		if d.refreshFabricFwd(ctx, fabIface, overlay, peerIP, i == 0) {
			break
		}
		if i == 9 {
			slog.Warn("cluster: fabric_fwd not populated after fast retries, continuing with periodic refresh")
		}
	}

	// Periodic refresh every 30s as safety net, plus event-driven
	// refresh via fabricRefreshCh from netlink monitor (#124).
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.refreshFabricFwd(ctx, fabIface, overlay, peerIP, false)
		case <-d.fabricRefreshCh:
			d.refreshFabricFwd(ctx, fabIface, overlay, peerIP, false)
		}
	}
}

// probeFabricNeighbor triggers ARP/NDP resolution for the fabric peer
// if no neighbor entry exists. Uses ping (not arping) because arping's
// PF_PACKET raw sockets don't populate the kernel ARP table with XDP attached.
func (d *Daemon) probeFabricNeighbor(ctx context.Context, fabIface string, peerIP net.IP) {
	link, err := netlink.LinkByName(fabIface)
	if err != nil {
		return
	}

	neighFamily := netlink.FAMILY_V4
	if peerIP.To4() == nil {
		neighFamily = netlink.FAMILY_V6
	}
	neighs, _ := netlink.NeighList(link.Attrs().Index, neighFamily)
	for _, n := range neighs {
		if n.IP.Equal(peerIP) && len(n.HardwareAddr) == 6 &&
			(n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT|netlink.NUD_DELAY|netlink.NUD_PROBE)) != 0 {
			return // Entry exists, no probe needed.
		}
	}

	// No neighbor entry — trigger ARP/NDP resolution via raw ICMP probe.
	sendICMPProbe(fabIface, peerIP)

	// Also probe on the parent interface if this is an IPVLAN overlay.
	// After crash recovery, the IPVLAN overlay may not respond to ARP
	// (stale MAC, vrf-mgmt routing isolation). The parent (ge-X-0-0)
	// is a real NIC on the same L2 segment — ARP on it is more reliable.
	// Additionally, send IPv6 ff02::1 multicast on the parent to populate
	// the NDP table with the peer's MAC as a fallback.
	if parentIdx := link.Attrs().ParentIndex; parentIdx > 0 {
		if parent, err := netlink.LinkByIndex(parentIdx); err == nil {
			parentName := parent.Attrs().Name
			sendICMPProbe(parentName, peerIP)
			sendIPv6MulticastProbe(parentName, parentIdx)
		}
	}
}

// sendICMPProbe sends a single raw ICMP/ICMPv6 echo request bound to
// the given interface. This triggers kernel ARP/NDP resolution without
// shelling out to ping. Non-blocking: sendto MSG_DONTWAIT.
func sendICMPProbe(iface string, target net.IP) {
	if target.To4() != nil {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		// ICMP echo: type=8, code=0, checksum=0xf7ff, id=0, seq=0
		icmp := [8]byte{8, 0, 0xf7, 0xff, 0, 0, 0, 0}
		sa := &unix.SockaddrInet4{}
		copy(sa.Addr[:], target.To4())
		_ = unix.Sendto(fd, icmp[:], unix.MSG_DONTWAIT, sa)
	} else {
		fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
		// ICMPv6 auto-checksum at offset 2
		_ = unix.SetsockoptInt(fd, unix.IPPROTO_ICMPV6, unix.IPV6_CHECKSUM, 2)
		// ICMPv6 echo: type=128, code=0, checksum=0 (kernel fills), id=0, seq=0
		icmp6 := [8]byte{128, 0, 0, 0, 0, 0, 0, 0}
		sa6 := &unix.SockaddrInet6{}
		copy(sa6.Addr[:], target.To16())
		_ = unix.Sendto(fd, icmp6[:], unix.MSG_DONTWAIT, sa6)
	}
}

// sendIPv6MulticastProbe sends an ICMPv6 echo request to ff02::1 (all-nodes
// multicast) on the given interface. All link-local nodes respond, populating
// the IPv6 neighbor table with their MACs. This provides a reliable fallback
// for discovering the fabric peer's MAC when IPv4 ARP fails (e.g. after
// crash recovery with RETH MAC changes on IPVLAN overlays).
func sendIPv6MulticastProbe(iface string, ifindex int) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
	if err != nil {
		return
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_ICMPV6, unix.IPV6_CHECKSUM, 2)
	// ICMPv6 echo request: type=128, code=0, checksum=0 (kernel fills)
	icmp6 := [8]byte{128, 0, 0, 0, 0, 0, 0, 1}
	sa6 := &unix.SockaddrInet6{ZoneId: uint32(ifindex)}
	// ff02::1 — all-nodes link-local multicast
	copy(sa6.Addr[:], net.ParseIP("ff02::1").To16())
	_ = unix.Sendto(fd, icmp6[:], unix.MSG_DONTWAIT, sa6)
}

func (d *Daemon) logFabricRefreshFailure(slot int, msg string, args ...any) {
	d.fabricMu.Lock()
	now := time.Now()
	last := d.lastFabricLog0
	if slot == 1 {
		last = d.lastFabricLog1
	}
	if now.Sub(last) < 2*time.Second {
		d.fabricMu.Unlock()
		return
	}
	if slot == 0 {
		d.lastFabricLog0 = now
	} else {
		d.lastFabricLog1 = now
	}
	d.fabricMu.Unlock()
	slog.Info(msg, args...)
}

func (d *Daemon) fabricEntryPopulated(slot int) bool {
	d.fabricMu.RLock()
	defer d.fabricMu.RUnlock()
	if slot == 1 {
		return d.fabric1Populated
	}
	return d.fabricPopulated
}

func (d *Daemon) retainFabricFwdOnNeighborMiss(slot int, peerIP net.IP, overlay string, logWaiting bool) bool {
	if !d.fabricEntryPopulated(slot) {
		if logWaiting {
			if slot == 1 {
				slog.Info("cluster: waiting for fabric1 peer neighbor entry",
					"peer", peerIP, "overlay", overlay)
			} else {
				slog.Info("cluster: waiting for fabric peer neighbor entry",
					"peer", peerIP, "overlay", overlay)
			}
		} else if slot == 1 {
			d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (missing peer neighbor)",
				"peer", peerIP, "overlay", overlay)
		} else {
			d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (missing peer neighbor)",
				"peer", peerIP, "overlay", overlay)
		}
		return false
	}

	if slot == 1 {
		d.logFabricRefreshFailure(1, "cluster: retaining fabric1_fwd despite missing peer neighbor",
			"peer", peerIP, "overlay", overlay)
	} else {
		d.logFabricRefreshFailure(0, "cluster: retaining fabric_fwd despite missing peer neighbor",
			"peer", peerIP, "overlay", overlay)
	}
	return true
}

// refreshFabricFwd resolves fabric link/neighbor state and updates the
// fabric_fwd BPF map. Returns true on success. Called during initial
// population and periodic drift correction.
// fabIface is the physical parent (for ifindex/MAC); overlay is the IPVLAN
// child where the sync IP lives (for neighbor resolution, #129).
func (d *Daemon) refreshFabricFwd(ctx context.Context, fabIface, overlay string, peerIP net.IP, logWaiting bool) bool {
	link, err := netlink.LinkByName(fabIface)
	if err != nil {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (link not found)",
			"interface", fabIface, "err", err)
		d.clearFabricFwd0(ctx)
		return false
	}
	localMAC := link.Attrs().HardwareAddr
	if len(localMAC) != 6 {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (invalid local mac)",
			"interface", fabIface, "local_mac", localMAC)
		d.clearFabricFwd0(ctx)
		return false
	}

	// Check oper-state: non-UP interfaces cannot forward (#122).
	operState := link.Attrs().OperState
	if operState != netlink.OperUp && operState != netlink.OperUnknown {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (link not operational)",
			"interface", fabIface, "oper_state", operState)
		d.clearFabricFwd0(ctx)
		return false
	}

	// Increase fabric txqueuelen for generic XDP.
	if link.Attrs().TxQLen < 10000 {
		if err := netlink.LinkSetTxQLen(link, 10000); err != nil {
			slog.Warn("cluster: failed to set fabric txqueuelen",
				"interface", fabIface, "err", err)
		}
	}

	// Resolve peer MAC from ARP/NDP table on the overlay interface (#129).
	// The sync IP lives on the overlay (fab0/fab1), so neighbor entries
	// are associated with the overlay's ifindex, not the parent's.
	neighLink := link
	if overlay != fabIface {
		if ol, err := netlink.LinkByName(overlay); err == nil {
			neighLink = ol
		}
	}
	neighFamily := netlink.FAMILY_V4
	if peerIP.To4() == nil {
		neighFamily = netlink.FAMILY_V6
	}

	validState := netlink.NUD_REACHABLE | netlink.NUD_STALE | netlink.NUD_PERMANENT | netlink.NUD_DELAY | netlink.NUD_PROBE

	neighs, err := netlink.NeighList(neighLink.Attrs().Index, neighFamily)
	if err != nil {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (neighbor list)",
			"overlay", neighLink.Attrs().Name, "peer", peerIP, "err", err)
		d.clearFabricFwd0(ctx)
		return false
	}
	var peerMAC net.HardwareAddr
	for _, n := range neighs {
		if n.IP.Equal(peerIP) && len(n.HardwareAddr) == 6 &&
			(n.State&validState) != 0 {
			peerMAC = n.HardwareAddr
			break
		}
	}

	// Fallback: if overlay ARP failed, try the parent interface's neighbor
	// tables (both IPv4 and IPv6). After crash recovery, the IPVLAN overlay
	// may not resolve ARP due to stale MAC or VRF isolation, but the parent
	// (ge-X-0-0) is a real NIC on the same L2 — its ARP/NDP is reliable.
	if peerMAC == nil {
		parentIdx := neighLink.Attrs().ParentIndex
		if parentIdx == 0 {
			parentIdx = link.Attrs().Index // use fabric parent directly
		}
		// Check parent IPv4 neighbors for the peer IP.
		parentNeighs, _ := netlink.NeighList(parentIdx, neighFamily)
		for _, n := range parentNeighs {
			if n.IP.Equal(peerIP) && len(n.HardwareAddr) == 6 &&
				(n.State&validState) != 0 {
				peerMAC = n.HardwareAddr
				slog.Info("cluster: fabric peer MAC resolved via parent ARP",
					"peer_mac", peerMAC, "overlay", overlay)
				break
			}
		}
		// Check parent IPv6 NDP neighbors (populated via ff02::1 probe).
		if peerMAC == nil {
			v6Neighs, _ := netlink.NeighList(parentIdx, netlink.FAMILY_V6)
			for _, n := range v6Neighs {
				if len(n.HardwareAddr) != 6 || (n.State&validState) == 0 {
					continue
				}
				if !n.IP.IsLinkLocalUnicast() {
					continue
				}
				if bytes.Equal(n.HardwareAddr, localMAC) {
					continue
				}
				peerMAC = n.HardwareAddr
				slog.Info("cluster: fabric peer MAC resolved via parent IPv6 NDP",
					"peer_mac", peerMAC, "peer_ll", n.IP, "overlay", overlay)
				break
			}
		}
	}

	if peerMAC == nil {
		if d.retainFabricFwdOnNeighborMiss(0, peerIP, overlay, logWaiting) {
			return true
		}
		d.clearFabricFwd0(ctx)
		return false
	}

	// Use parent's ifindex for redirect — XDP runs on the parent.
	info := dataplane.FabricFwdInfo{
		Ifindex: uint32(link.Attrs().Index),
	}
	copy(info.PeerMAC[:], peerMAC)
	copy(info.LocalMAC[:], localMAC)

	// Find a non-VRF interface for zone-decoded FIB lookups.
	// Prefer the fabric interface itself (known UP, non-VRF).
	// Fall back to loopback (ifindex 1): always present, always
	// UP, never a VRF member — deterministic across reboots.
	info.FIBIfindex = uint32(link.Attrs().Index)
	if link.Attrs().MasterIndex != 0 {
		// Fabric link is a VRF member — use loopback for
		// main-table FIB lookups (avoids l3mdev interference).
		info.FIBIfindex = 1
	}

	if d.dp == nil {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (dataplane not ready)")
		return false
	}
	if err := d.dp.HA().SetFabricForwarding(ctx, dataplane.FabricID(0), info); err != nil {
		slog.Warn("cluster: failed to update fabric_fwd map", "err", err)
		return false
	}

	d.fabricMu.Lock()
	d.fabricPopulated = true
	d.fabricMu.Unlock()

	slog.Info("cluster: fabric_fwd updated",
		"interface", fabIface, "ifindex", info.Ifindex,
		"fib_ifindex", info.FIBIfindex,
		"local_mac", localMAC, "peer_mac", peerMAC)

	// Push updated fabric MACs to userspace helper so it can do
	// cross-chassis fabric redirect. The initial snapshot may have
	// been built before the peer MAC was resolved.
	if d.dp != nil {
		d.dp.HA().SyncFabricState(ctx)
	}

	return true
}

// clearFabricFwd0 writes a zeroed FabricFwdInfo to key=0 if a valid entry
// was previously written, ensuring the dataplane falls back (#121).
func (d *Daemon) clearFabricFwd0(ctx context.Context) {
	d.fabricMu.RLock()
	populated := d.fabricPopulated
	d.fabricMu.RUnlock()
	if !populated || d.dp == nil {
		return
	}
	if err := d.dp.HA().SetFabricForwarding(ctx, dataplane.FabricID(0), dataplane.FabricFwdInfo{}); err != nil {
		slog.Warn("cluster: failed to clear fabric_fwd[0]", "err", err)
		return
	}
	d.fabricMu.Lock()
	d.fabricPopulated = false
	d.fabricMu.Unlock()
	slog.Info("cluster: fabric_fwd[0] cleared (path down)")
}

// populateFabricFwd1 resolves the secondary fabric interface MACs and populates
// the fabric_fwd BPF map entry at key=1 for cross-chassis packet redirect.
// Mirrors populateFabricFwd but writes to key=1 via UpdateFabricFwd1.
func (d *Daemon) populateFabricFwd1(ctx context.Context, fabIface, overlay, peerAddr string) {
	peerIP := net.ParseIP(peerAddr)
	if peerIP == nil {
		slog.Warn("cluster: invalid fabric1 peer address", "addr", peerAddr)
		return
	}
	if overlay == "" {
		overlay = fabIface
	}

	// Store fabric1 config for RefreshFabricFwd.
	d.fabricMu.Lock()
	d.fabricIface1 = fabIface
	d.fabricOverlay1 = overlay
	d.fabricPeerIP1 = peerIP
	d.fabricMu.Unlock()

	// Fast initial population: attempt immediately, then 500ms retries.
	for i := 0; i < 10; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(500 * time.Millisecond):
			}
		}

		// Probe on the overlay (#129).
		d.probeFabricNeighbor(ctx, overlay, peerIP)

		if d.refreshFabricFwd1(ctx, fabIface, overlay, peerIP, i == 0) {
			break
		}
		if i == 9 {
			slog.Warn("cluster: fabric1_fwd not populated after fast retries, continuing with periodic refresh")
		}
	}

	// Periodic refresh every 30s as safety net, plus event-driven
	// refresh via fabricRefreshCh from netlink monitor (#124).
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.refreshFabricFwd1(ctx, fabIface, overlay, peerIP, false)
		case <-d.fabricRefreshCh:
			d.refreshFabricFwd1(ctx, fabIface, overlay, peerIP, false)
		}
	}
}

// refreshFabricFwd1 resolves secondary fabric link/neighbor state and updates
// the fabric_fwd BPF map at key=1. Returns true on success.
// fabIface is the physical parent; overlay is the IPVLAN child (#129).
func (d *Daemon) refreshFabricFwd1(ctx context.Context, fabIface, overlay string, peerIP net.IP, logWaiting bool) bool {
	link, err := netlink.LinkByName(fabIface)
	if err != nil {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (link not found)",
			"interface", fabIface, "err", err)
		d.clearFabricFwd1(ctx)
		return false
	}
	localMAC := link.Attrs().HardwareAddr
	if len(localMAC) != 6 {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (invalid local mac)",
			"interface", fabIface, "local_mac", localMAC)
		d.clearFabricFwd1(ctx)
		return false
	}

	// Check oper-state: non-UP interfaces cannot forward (#122).
	operState := link.Attrs().OperState
	if operState != netlink.OperUp && operState != netlink.OperUnknown {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (link not operational)",
			"interface", fabIface, "oper_state", operState)
		d.clearFabricFwd1(ctx)
		return false
	}

	// Increase fabric txqueuelen for generic XDP.
	if link.Attrs().TxQLen < 10000 {
		if err := netlink.LinkSetTxQLen(link, 10000); err != nil {
			slog.Warn("cluster: failed to set fabric1 txqueuelen",
				"interface", fabIface, "err", err)
		}
	}

	// Resolve peer MAC from overlay interface (#129).
	neighLink := link
	if overlay != fabIface {
		if ol, err := netlink.LinkByName(overlay); err == nil {
			neighLink = ol
		}
	}
	neighFamily := netlink.FAMILY_V4
	if peerIP.To4() == nil {
		neighFamily = netlink.FAMILY_V6
	}
	neighs, err := netlink.NeighList(neighLink.Attrs().Index, neighFamily)
	if err != nil {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (neighbor list)",
			"overlay", neighLink.Attrs().Name, "peer", peerIP, "err", err)
		d.clearFabricFwd1(ctx)
		return false
	}
	var peerMAC net.HardwareAddr
	for _, n := range neighs {
		if n.IP.Equal(peerIP) && len(n.HardwareAddr) == 6 &&
			(n.State&(netlink.NUD_REACHABLE|netlink.NUD_STALE|netlink.NUD_PERMANENT|netlink.NUD_DELAY|netlink.NUD_PROBE)) != 0 {
			peerMAC = n.HardwareAddr
			break
		}
	}
	if peerMAC == nil {
		if d.retainFabricFwdOnNeighborMiss(1, peerIP, overlay, logWaiting) {
			return true
		}
		d.clearFabricFwd1(ctx)
		return false
	}

	info := dataplane.FabricFwdInfo{
		Ifindex: uint32(link.Attrs().Index),
	}
	copy(info.PeerMAC[:], peerMAC)
	copy(info.LocalMAC[:], localMAC)

	info.FIBIfindex = uint32(link.Attrs().Index)
	if link.Attrs().MasterIndex != 0 {
		info.FIBIfindex = 1
	}

	if d.dp == nil {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (dataplane not ready)")
		return false
	}
	if err := d.dp.HA().SetFabricForwarding(ctx, dataplane.FabricID(1), info); err != nil {
		slog.Warn("cluster: failed to update fabric1_fwd map", "err", err)
		return false
	}

	d.fabricMu.Lock()
	d.fabric1Populated = true
	d.fabricMu.Unlock()

	slog.Info("cluster: fabric1_fwd updated",
		"interface", fabIface, "ifindex", info.Ifindex,
		"fib_ifindex", info.FIBIfindex,
		"local_mac", localMAC, "peer_mac", peerMAC)
	return true
}

// clearFabricFwd1 writes a zeroed FabricFwdInfo to key=1 if a valid entry
// was previously written, ensuring the dataplane falls back (#121).
func (d *Daemon) clearFabricFwd1(ctx context.Context) {
	d.fabricMu.RLock()
	populated := d.fabric1Populated
	d.fabricMu.RUnlock()
	if !populated || d.dp == nil {
		return
	}
	if err := d.dp.HA().SetFabricForwarding(ctx, dataplane.FabricID(1), dataplane.FabricFwdInfo{}); err != nil {
		slog.Warn("cluster: failed to clear fabric_fwd[1]", "err", err)
		return
	}
	d.fabricMu.Lock()
	d.fabric1Populated = false
	d.fabricMu.Unlock()
	slog.Info("cluster: fabric_fwd[1] cleared (path down)")
}

// RefreshFabricFwd triggers an immediate refresh of the fabric_fwd BPF map.
// Call this on link state changes, neighbor changes, or failover transitions.
// Refreshes both fab0 (key=0) and fab1 (key=1) entries.
func (d *Daemon) RefreshFabricFwd() {
	d.fabricMu.RLock()
	fabIface := d.fabricIface
	overlay := d.fabricOverlay
	peerIP := d.fabricPeerIP
	fabIface1 := d.fabricIface1
	overlay1 := d.fabricOverlay1
	peerIP1 := d.fabricPeerIP1
	probeAt0 := d.lastFabricProbe
	probeAt1 := d.lastFabricProbe1
	d.fabricMu.RUnlock()
	if fabIface != "" && peerIP != nil {
		if time.Since(probeAt0) >= 2*time.Second {
			d.fabricMu.Lock()
			if time.Since(d.lastFabricProbe) >= 2*time.Second {
				d.lastFabricProbe = time.Now()
				go d.probeFabricNeighbor(context.Background(), overlayOrParent(overlay, fabIface), peerIP)
			}
			d.fabricMu.Unlock()
		}
		d.refreshFabricFwd(context.Background(), fabIface, overlay, peerIP, false)
	}
	if fabIface1 != "" && peerIP1 != nil {
		if time.Since(probeAt1) >= 2*time.Second {
			d.fabricMu.Lock()
			if time.Since(d.lastFabricProbe1) >= 2*time.Second {
				d.lastFabricProbe1 = time.Now()
				go d.probeFabricNeighbor(context.Background(), overlayOrParent(overlay1, fabIface1), peerIP1)
			}
			d.fabricMu.Unlock()
		}
		d.refreshFabricFwd1(context.Background(), fabIface1, overlay1, peerIP1, false)
	}
}

func overlayOrParent(overlay, parent string) string {
	if overlay != "" {
		return overlay
	}
	return parent
}

// monitorFabricState subscribes to netlink link and neighbor updates and
// triggers immediate fabric_fwd refresh when fabric interfaces or their
// neighbor entries change (#124). The 30s ticker in populateFabricFwd
// remains as a safety net.
func (d *Daemon) monitorFabricState(ctx context.Context) {
	linkUpdates := make(chan netlink.LinkUpdate, 64)
	linkDone := make(chan struct{})
	if err := netlink.LinkSubscribe(linkUpdates, linkDone); err != nil {
		slog.Warn("cluster: failed to subscribe to link updates for fabric monitor", "err", err)
		return
	}

	neighUpdates := make(chan netlink.NeighUpdate, 64)
	neighDone := make(chan struct{})
	if err := netlink.NeighSubscribe(neighUpdates, neighDone); err != nil {
		slog.Warn("cluster: failed to subscribe to neigh updates for fabric monitor", "err", err)
		close(linkDone)
		return
	}

	slog.Info("cluster: fabric state monitor started (link + neighbor)")

	for {
		select {
		case <-ctx.Done():
			close(linkDone)
			close(neighDone)
			return
		case update, ok := <-linkUpdates:
			if !ok {
				return
			}
			name := update.Attrs().Name
			d.fabricMu.RLock()
			isFabric := name == d.fabricIface || name == d.fabricIface1 ||
				name == d.fabricOverlay || name == d.fabricOverlay1
			d.fabricMu.RUnlock()
			if isFabric {
				slog.Debug("cluster: fabric link state change detected",
					"interface", name, "oper_state", update.Attrs().OperState)
				d.triggerFabricRefresh()
			}
		case update, ok := <-neighUpdates:
			if !ok {
				return
			}
			d.fabricMu.RLock()
			isPeer := (d.fabricPeerIP != nil && update.IP.Equal(d.fabricPeerIP)) ||
				(d.fabricPeerIP1 != nil && update.IP.Equal(d.fabricPeerIP1))
			d.fabricMu.RUnlock()
			if isPeer {
				slog.Debug("cluster: fabric peer neighbor change detected",
					"ip", update.IP, "type", update.Type)
				d.triggerFabricRefresh()
			}
		}
	}
}

// triggerFabricRefresh sends a non-blocking signal to the fabric refresh
// channel, waking populateFabricFwd/populateFabricFwd1 loops.
func (d *Daemon) triggerFabricRefresh() {
	select {
	case d.fabricRefreshCh <- struct{}{}:
	default:
		// Already pending — no need to queue another.
	}
}
