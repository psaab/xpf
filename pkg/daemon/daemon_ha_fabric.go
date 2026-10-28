package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"time"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/linuxsock"
)

// ensureFabricIPVLAN creates an IPVLAN L2 interface on top of parent for
// fabric IP addressing. The parent keeps its ge-X-0-Y name (XDP/TC attaches
// there); the IPVLAN carries the fabric IP used for session sync.
// Idempotent: skips creation if the IPVLAN already exists on the correct parent.
// configuredMTU is the fabric interface's configured MTU. The fabric floor
// remains 9000 when it is absent or lower; a configured jumbo above that floor
// is the exact value reconciled on both parent and overlay (#10216).
//
// #17221: configured addresses are fail-closed exactly like the MTU. Both
// branches end with fabricOverlayReady on a fresh lookup, so an address
// write that fails (or does not take) returns an error instead of a commit
// that reports a healthy overlay carrying no session-sync address.
func ensureFabricIPVLAN(parent, name string, addrs []string, configuredMTU int) error {
	parentLink, err := fabricLinkByName17221(parent)
	if err != nil {
		return fmt.Errorf("parent %s: %w", parent, err)
	}

	// Ensure parent is UP — IPVLAN inherits carrier from parent.
	_ = fabricLinkSetUp17221(parentLink)

	wantMTU := fabricMTU10216(configuredMTU)

	// Check if IPVLAN already exists on the correct parent. A decrease must
	// lower the overlay first; Linux rejects a parent decrease while an upper
	// IPVLAN still advertises the larger MTU.
	if existing, err := fabricLinkByName17221(name); err == nil && existing != nil && existing.Attrs() != nil {
		if existing.Attrs().ParentIndex == parentLink.Attrs().Index {
			if err := reconcileFabricMTUPair10216(parent, parentLink, name, existing, wantMTU); err != nil {
				return err
			}
			if err := reconcileIPVLANAddrs(existing, name, addrs); err != nil {
				return fmt.Errorf("fabric IPVLAN %s address reconciliation: %w", name, err)
			}
			if err := fabricLinkSetUp17221(existing); err != nil {
				return fmt.Errorf("bring up %s: %w", name, err)
			}
			fresh, err := fabricLinkByName17221(name)
			if err != nil {
				return fmt.Errorf("find reconciled IPVLAN %s: %w", name, err)
			}
			if err := fabricOverlayReady(fresh, addrs, wantMTU); err != nil {
				return fmt.Errorf("fabric IPVLAN %s not ready: %w", name, err)
			}
			return nil
		}
		// Wrong parent — remove and recreate. Routed through the helper so
		// a failed delete is logged as an error and surfaces via the
		// LinkAdd below (EEXIST) rather than a false "removed" record.
		if err := (&Daemon{}).deleteFabricOverlay(existing, "wrong parent: remove and recreate"); err != nil {
			return fmt.Errorf("remove wrong-parent fabric IPVLAN %s: %w", name, err)
		}
	}

	// New overlays have no upper-device ordering constraint, so reconcile the
	// parent before creation. The overlay is reconciled again after LinkAdd.
	if err := reconcileFabricMTU10216(parent, parentLink, wantMTU); err != nil {
		return fmt.Errorf("fabric parent %s MTU reconciliation: %w", parent, err)
	}
	ipvlan := &netlink.IPVlan{
		LinkAttrs: netlink.LinkAttrs{
			Name:        name,
			ParentIndex: parentLink.Attrs().Index,
		},
		Mode: netlink.IPVLAN_MODE_L2,
	}
	if err := fabricLinkAdd17221(ipvlan); err != nil {
		return fmt.Errorf("create IPVLAN %s on %s: %w", name, parent, err)
	}

	link, err := fabricLinkByName17221(name)
	if err != nil {
		return fmt.Errorf("find created IPVLAN %s: %w", name, err)
	}

	// Set the overlay MTU exactly to the parent/configured target and verify
	// through a fresh lookup; a warn-only write makes the desired state
	// applied-by-nobody (#10216).
	if err := reconcileFabricMTU10216(name, link, wantMTU); err != nil {
		return fmt.Errorf("fabric IPVLAN %s MTU reconciliation: %w", name, err)
	}

	// Add configured addresses. A warn-only write makes the address the
	// overlay exists to carry applied-by-nobody (#17221): there is no other
	// writer, so a failure must reach the caller.
	for _, addrStr := range addrs {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			return fmt.Errorf("fabric IPVLAN %s: invalid address %q: %w", name, addrStr, err)
		}
		if err := fabricAddrReplace17221(link, addr); err != nil {
			return fmt.Errorf("fabric IPVLAN %s: add address %s: %w", name, addrStr, err)
		}
	}

	if err := fabricLinkSetUp17221(link); err != nil {
		return fmt.Errorf("bring up %s: %w", name, err)
	}
	fresh, err := fabricLinkByName17221(name)
	if err != nil {
		return fmt.Errorf("find created IPVLAN %s: %w", name, err)
	}
	if err := fabricOverlayReady(fresh, addrs, wantMTU); err != nil {
		return fmt.Errorf("fabric IPVLAN %s not ready: %w", name, err)
	}
	present, err := fabricPresentAddrs(fresh)
	if err != nil {
		return fmt.Errorf("fabric IPVLAN %s: list addresses: %w", name, err)
	}
	slog.Info("created fabric IPVLAN", "name", name, "parent", parent,
		"addrs", present, "mtu", wantMTU)
	return nil
}

// Address/link seams (#17221) mirroring the fabricLinkByName10216 /
// fabricLinkSetMTU10216 pattern, so the fail-closed address contract is
// testable without a real IPVLAN. Production values are the netlink ops.
var (
	fabricLinkByName17221 = netlink.LinkByName
	fabricLinkAdd17221    = netlink.LinkAdd
	fabricLinkSetUp17221  = netlink.LinkSetUp
	fabricAddrList17221   = func(link netlink.Link) ([]netlink.Addr, error) {
		return netlink.AddrList(link, netlink.FAMILY_ALL)
	}
	fabricAddrReplace17221 = netlink.AddrReplace
	fabricAddrDel17221     = netlink.AddrDel
)

// fabricPresentAddrs returns the addresses currently on link, normalized to
// CIDR strings and sorted for stable logging and comparison.
func fabricPresentAddrs(link netlink.Link) ([]string, error) {
	addrs, err := fabricAddrList17221(link)
	if err != nil {
		return nil, err
	}
	present := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if a.IPNet == nil {
			continue
		}
		present = append(present, a.IPNet.String())
	}
	sort.Strings(present)
	return present, nil
}

// fabricOverlayMissingAddrs returns the normalized CIDR strings among want
// that are absent from link. Invalid configured addresses are errors: a
// fabric address that cannot be parsed can never be ready.
func fabricOverlayMissingAddrs(link netlink.Link, want []string) ([]string, error) {
	desired := make(map[string]bool, len(want))
	for _, addrStr := range want {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			return nil, fmt.Errorf("invalid address %q: %w", addrStr, err)
		}
		desired[addr.IPNet.String()] = true
	}
	present, err := fabricPresentAddrs(link)
	if err != nil {
		return nil, err
	}
	have := make(map[string]bool, len(present))
	for _, p := range present {
		have[p] = true
	}
	var missing []string
	for k := range desired {
		if !have[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	return missing, nil
}

// fabricOverlayReady is the readiness predicate ensureFabricIPVLAN ends
// with on a fresh lookup in both branches (#17221): administratively up,
// at the desired MTU, and carrying every configured address. The reassert
// gate (missingFabricOverlays) shares its address half through
// fabricOverlayMissingAddrs, so the gate and the actuator cannot disagree
// about whether the fabric address is present.
func fabricOverlayReady(link netlink.Link, addrs []string, wantMTU int) error {
	if link == nil || link.Attrs() == nil {
		return fmt.Errorf("no link attributes")
	}
	attrs := link.Attrs()
	name := attrs.Name
	if attrs.Flags&net.FlagUp == 0 {
		return fmt.Errorf("fabric IPVLAN %s is not administratively up", name)
	}
	if attrs.MTU != wantMTU {
		return fmt.Errorf("fabric IPVLAN %s MTU %d, want %d", name, attrs.MTU, wantMTU)
	}
	missing, err := fabricOverlayMissingAddrs(link, addrs)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("fabric IPVLAN %s missing addresses %v", name, missing)
	}
	return nil
}

// reconcileIPVLANAddrs adds missing addresses and removes stale ones from an
// existing IPVLAN interface (#127). Called when ensureFabricIPVLAN finds the
// overlay already exists on the correct parent.
//
// #17221: a failure to LIST, a failed AddrReplace of a desired address, or a
// desired address still missing afterwards is returned — the fabric address
// has no other writer, so warn-only made it applied-by-nobody. A stale-delete
// failure stays warn-only: the extra address is cleaned by the next reconcile
// and does not strand session sync.
func reconcileIPVLANAddrs(link netlink.Link, name string, desired []string) error {
	want := make(map[string]*netlink.Addr, len(desired))
	for _, addrStr := range desired {
		addr, err := netlink.ParseAddr(addrStr)
		if err != nil {
			return fmt.Errorf("invalid address %q: %w", addrStr, err)
		}
		want[addr.IPNet.String()] = addr
	}
	existing, err := fabricAddrList17221(link)
	if err != nil {
		return fmt.Errorf("list addresses: %w", err)
	}
	have := make(map[string]bool, len(existing))
	for _, a := range existing {
		if a.IPNet == nil {
			continue
		}
		key := a.IPNet.String()
		have[key] = true
		if _, ok := want[key]; !ok {
			if err := fabricAddrDel17221(link, &a); err != nil {
				slog.Warn("fabric IPVLAN: failed to remove stale address",
					"name", name, "addr", key, "err", err)
			} else {
				slog.Info("fabric IPVLAN: removed stale address",
					"name", name, "addr", key)
			}
		}
	}
	for key, addr := range want {
		if !have[key] {
			if err := fabricAddrReplace17221(link, addr); err != nil {
				return fmt.Errorf("add address %s: %w", key, err)
			}
			slog.Info("fabric IPVLAN: added missing address",
				"name", name, "addr", key)
		}
	}
	// Verify through a fresh listing: a successful AddrReplace whose
	// address is still absent is still applied-by-nobody.
	missing, err := fabricOverlayMissingAddrs(link, desired)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("addresses still missing after reconcile: %v", missing)
	}
	return nil
}

// fabricOverlayNames are every fabric IPVLAN this daemon can create.
//
// #8372: single-sourced because two callers now enumerate them —
// CleanupFabricIPVLANs (the `xpfd cleanup` subcommand) and the reassert loop's
// reaper. Two hardcoded copies of "which devices are ours" is a rule that
// silently stops covering a third device, and the reaper's failure mode there
// is the quiet one: it would simply never notice the new device had gone stale.
func fabricOverlayNames() []string { return []string{"fab0", "fab1"} }

// deleteFabricOverlay deletes one fabric IPVLAN through the fabricLinkDel
// seam (#17224). Info is logged only on success — a failed delete leaves the
// device in place, so claiming "removed" for it would log a state transition
// that never happened. On failure it logs Error carrying `reason` and returns
// the error so callers that can act on it (fail the delete, retry) may.
func (d *Daemon) deleteFabricOverlay(link netlink.Link, reason string) error {
	name := ""
	if link != nil && link.Attrs() != nil {
		name = link.Attrs().Name
	}
	if err := d.fabricLinkDel(link); err != nil {
		slog.Error("fabric IPVLAN delete failed",
			"name", name, "reason", reason, "err", err)
		return err
	}
	slog.Info("removed fabric IPVLAN", "name", name, "reason", reason)
	return nil
}

// CleanupFabricIPVLANs removes all fabric IPVLAN interfaces (fab0, fab1).
func CleanupFabricIPVLANs() {
	d := &Daemon{}
	for _, name := range fabricOverlayNames() {
		if link, err := netlink.LinkByName(name); err == nil {
			if _, ok := link.(*netlink.IPVlan); ok {
				_ = d.deleteFabricOverlay(link, "xpfd cleanup")
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
	if ifCfg, ok := cfg.Interfaces.Interfaces[fabName]; ok && ifCfg != nil && ifCfg.LocalFabricMember != "" {
		return config.LinuxIfName(ifCfg.LocalFabricMember)
	}
	return fabName
}

// populateFabricFwd resolves the fabric interface MACs and populates the
// fabric peer for cross-chassis redirect during failback (#17044: live resolver in pkg/dataplane/userspace).
// fabIface is the physical parent (XDP attachment point); overlay is the
// IPVLAN child where the sync IP lives (neighbor resolution target, #129).
// If overlay is empty, fabIface is used for both (legacy/no-IPVLAN mode).
// Attempts immediately on startup with fast 500ms retries (10 attempts),
// then falls back to 30s periodic refresh.
// refreshCh is this loop's OWN event-driven refresh channel, handed in by value
// at launch (#4958). The loop reads it directly rather than d.fabricRefreshCh so
// a comms restart that swaps the shared field cannot race this receive; the
// sender (triggerFabricRefresh) targets whatever channel the live epoch
// published.
func (d *Daemon) populateFabricFwd(ctx context.Context, fabIface, overlay, peerAddr string, refreshCh chan struct{}) {
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
	peerChanged := !d.fabricPeerIP.Equal(peerIP)
	if peerChanged {
		d.fabricPeerMAC = nil
	}
	d.fabricPeerIP = peerIP
	d.fabricMu.Unlock()
	if peerChanged {
		dpuserspace.RegisterFabricPeerMACConstraint(peerAddr, nil)
	}

	// Fast initial population: attempt immediately, then 500ms retries.
	for i := 0; i < 10; i++ {
		// Honour cancellation before EVERY attempt, including the first. The
		// probe below dials the overlay and transmits a neighbour solicitation
		// (ff02::1) / ARP request, so a caller whose context is ALREADY
		// cancelled — shutdown, or a superseded fabric epoch — must not put one
		// more frame on the wire. Before this the check lived inside the
		// `i > 0` sleep arm, so iteration 0 probed unconditionally.
		if ctx.Err() != nil {
			return
		}
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
			slog.Warn("cluster: fabric peer not resolved after fast retries, continuing with periodic refresh")
		}
	}

	// Periodic refresh every 30s as safety net, plus event-driven
	// refresh via fabricRefreshCh from the netlink monitor (#124). fab0
	// reads its own channel; fab1 reads fabricRefreshCh1 (#4038).
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.refreshFabricFwd(ctx, fabIface, overlay, peerIP, false)
		case <-refreshCh:
			d.refreshFabricFwd(ctx, fabIface, overlay, peerIP, false)
		}
	}
}

// probeFabricNeighbor triggers ARP/NDP resolution for the fabric peer
// if no neighbor entry exists. Uses ping (not arping) because arping's
// PF_PACKET raw sockets don't populate the kernel ARP table with XDP attached.
func (d *Daemon) probeFabricNeighbor(ctx context.Context, fabIface string, peerIP net.IP) {
	// Route the reads through the Daemon seams like the rest of the fabric
	// refresh. These were direct netlink calls, which meant a test that
	// reached this function bypassed both seams and hit the real kernel —
	// dumping neighbours and, on a miss, transmitting a raw ICMP probe and an
	// ff02::1 solicitation on a live NIC (#6595).
	//
	// NOTE for future tests: seaming the reads makes the LOOKUP hermetic, not
	// the whole function. A seam that returns a synthetic link with no matching
	// neighbour still falls through to the sendICMPProbe / sendIPv6MulticastProbe
	// transmits below, which are real sockets on a real interface name. A test
	// that must exercise this path should make fabricLinkByName return an error
	// (as TestFabricPeerIdentityClearedOnPeerChange does) so it returns before
	// any transmit.
	link, err := d.fabricLinkByName(fabIface)
	if err != nil {
		return
	}

	neighFamily := netlink.FAMILY_V4
	if peerIP.To4() == nil {
		neighFamily = netlink.FAMILY_V6
	}
	neighs, _ := d.fabricNeighList(link.Attrs().Index, neighFamily)
	for _, n := range neighs {
		if n.IP.Equal(peerIP) && dpuserspace.FabricNeighUsable(n) {
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
		fd, err := linuxsock.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
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
		fd, err := linuxsock.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
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
	fd, err := linuxsock.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_ICMPV6)
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

// fabricLinkByName / fabricNeighList route the fabric refresh's netlink reads
// through the Daemon seams so a test can drive resolution against a synthetic
// link + neighbour table (#6554). Both fall back to the real netlink call when
// the seam is unset (a Daemon built by a path that does not run the
// constructor).
func (d *Daemon) fabricLinkByName(name string) (netlink.Link, error) {
	if d.linkByNameFn != nil {
		return d.linkByNameFn(name)
	}
	return netlink.LinkByName(name)
}

// fabricLinkDel removes a link, through a seam so the #8372 reaper is testable
// without netlink.
func (d *Daemon) fabricLinkDel(link netlink.Link) error {
	if d.linkDelFn != nil {
		return d.linkDelFn(link)
	}
	return netlink.LinkDel(link)
}

func (d *Daemon) fabricNeighList(ifindex, family int) ([]netlink.Neigh, error) {
	if d.neighListFn != nil {
		return d.neighListFn(ifindex, family)
	}
	return netlink.NeighList(ifindex, family)
}

// fabricPeerMACHint returns the last address-matched peer MAC observed for the
// given fabric slot, or nil if the peer's fabric address has never resolved
// since this daemon started (or since the configured peer last changed).
func (d *Daemon) fabricPeerMACHint(slot int) net.HardwareAddr {
	d.fabricMu.RLock()
	defer d.fabricMu.RUnlock()
	if slot == 1 {
		return d.fabricPeerMAC1
	}
	return d.fabricPeerMAC
}

// rememberFabricPeerMAC records a peer MAC learned from an ADDRESS-MATCHED
// neighbour entry — i.e. the MAC that actually answered for the configured
// fabric peer address. This is the identity the NDP link-local fallback is
// later constrained to (#6554). It is deliberately NOT called from the
// fallback: a fallback result must never promote itself into the identity it
// is checked against, or one bad selection would pin every later refresh.
// An address-matched observation always overwrites, so a legitimately changed
// peer MAC (NIC replacement, RETH member swap) self-heals on the next
// successful ARP/NDP resolution rather than being locked out.
func (d *Daemon) rememberFabricPeerMAC(slot int, mac net.HardwareAddr) {
	if len(mac) != 6 {
		return
	}
	stored := make(net.HardwareAddr, 6)
	copy(stored, mac)
	d.fabricMu.Lock()
	var peerIP net.IP
	if slot == 1 {
		d.fabricPeerMAC1 = stored
		peerIP = d.fabricPeerIP1
	} else {
		d.fabricPeerMAC = stored
		peerIP = d.fabricPeerIP
	}
	d.fabricMu.Unlock()
	// #15918: publish the identity to the live userspace resolver so its
	// link-local fallback is constrained identically even on snapshot builds
	// that never pass through a daemon refresh.
	if peerIP != nil {
		dpuserspace.RegisterFabricPeerMACConstraint(peerIP.String(), stored)
	}
}

// selectFabricPeerLinkLocalMAC is retained as a thin delegate to the single
// authoritative implementation in pkg/dataplane/userspace (#15918). Before
// #15918 the daemon had its own copy while the live userspace resolver
// (buildFabricPeerMAC) had no link-local leg at all, so the fallback latched
// fabricPopulated/readiness while FabricSnapshot.PeerMAC stayed empty and
// Rust skipped the fabric. Delegating guarantees the MAC the daemon accepts
// is exactly the MAC the helper publishes. The selection contract (identity-
// constrained, fail-closed on ambiguity) is documented on
// dpuserspace.SelectFabricPeerLinkLocalMAC.
func selectFabricPeerLinkLocalMAC(
	neighs []netlink.Neigh,
	localMAC, expected net.HardwareAddr,
) (mac net.HardwareAddr, peerLL net.IP, candidates int, reason string) {
	return dpuserspace.SelectFabricPeerLinkLocalMAC(neighs, localMAC, expected)
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
		d.logFabricRefreshFailure(1, "cluster: retaining fabric1 peer despite missing peer neighbor",
			"peer", peerIP, "overlay", overlay)
	} else {
		d.logFabricRefreshFailure(0, "cluster: retaining fabric peer despite missing peer neighbor",
			"peer", peerIP, "overlay", overlay)
	}
	return true
}

// refreshFabricFwd resolves fabric link/neighbor state via the live
// resolver in pkg/dataplane/userspace (#17044). Returns true on success.
func (d *Daemon) refreshFabricFwd(ctx context.Context, fabIface, overlay string, peerIP net.IP, logWaiting bool) bool {
	return d.refreshFabricPeer(ctx, 0, fabIface, overlay, peerIP, logWaiting)
}

// refreshFabricPeer is the single daemon fabric refresh (#17044). The
// live resolver in pkg/dataplane/userspace decides the peer MAC; the
// daemon only gates on link state, remembers address-matched identity
// for the link-local constraint, latches readiness, and pushes
// SyncFabricState. No fabric_fwd map write remains.
func (d *Daemon) refreshFabricPeer(ctx context.Context, slot int, fabIface, overlay string, peerIP net.IP, logWaiting bool) bool {
	link, err := d.fabricLinkByName(fabIface)
	if err != nil {
		d.logFabricRefreshFailure(slot, "cluster: fabric refresh failed (link not found)",
			"interface", fabIface, "err", err)
		d.clearFabricPeer(ctx, slot)
		return false
	}
	localMAC := link.Attrs().HardwareAddr
	if len(localMAC) != 6 {
		d.logFabricRefreshFailure(slot, "cluster: fabric refresh failed (invalid local mac)",
			"interface", fabIface, "local_mac", localMAC)
		d.clearFabricPeer(ctx, slot)
		return false
	}
	operState := link.Attrs().OperState
	if operState != netlink.OperUp && operState != netlink.OperUnknown {
		d.logFabricRefreshFailure(slot, "cluster: fabric refresh failed (link not operational)",
			"interface", fabIface, "oper_state", operState)
		d.clearFabricPeer(ctx, slot)
		return false
	}
	if link.Attrs().TxQLen < 10000 {
		if err := netlink.LinkSetTxQLen(link, 10000); err != nil {
			slog.Warn("cluster: failed to set fabric txqueuelen",
				"interface", fabIface, "err", err)
		}
	}
	neighLink := link
	if overlay != fabIface {
		if ol, err := d.fabricLinkByName(overlay); err == nil {
			neighLink = ol
		}
	}
	neighFamily := netlink.FAMILY_V4
	if peerIP.To4() == nil {
		neighFamily = netlink.FAMILY_V6
	}
	overlayIdx := neighLink.Attrs().Index
	parentIdx := neighLink.Attrs().ParentIndex
	if parentIdx == 0 {
		parentIdx = link.Attrs().Index
	}
	// Identity hint: an address-matched neighbour is a real binding.
	// Scan overlay then parent so rememberFabricPeerMAC arms the
	// constraint the live resolver's link-local fallback checks. The
	// resolver re-reads the same tables; this scan only records identity.
scan:
	for _, idx := range []int{overlayIdx, parentIdx} {
		neighs, err := d.fabricNeighList(idx, neighFamily)
		if err != nil {
			continue
		}
		for _, n := range neighs {
			if n.IP.Equal(peerIP) && dpuserspace.FabricNeighUsable(n) {
				d.rememberFabricPeerMAC(slot, n.HardwareAddr)
				break scan // overlay priority, matching the resolver's order (#17044 fold)
			}
		}
	}
	resolver := d.fabricPeerResolver()
	var res dpuserspace.FabricPeerResolution
	if resolver != nil {
		res = resolver.ResolveFabricPeer(slot, overlayIdx, parentIdx, peerIP.String(), localMAC)
	} else {
		res = dpuserspace.ResolveFabricPeer(overlayIdx, parentIdx, peerIP.String(), localMAC)
	}
	peerMAC := res.PeerMAC
	if peerMAC == nil {
		if d.retainFabricFwdOnNeighborMiss(slot, peerIP, overlay, logWaiting) {
			return true
		}
		d.clearFabricPeer(ctx, slot)
		return false
	}
	rt := d.dataplane()
	if rt == nil {
		d.logFabricRefreshFailure(slot, "cluster: fabric refresh failed (dataplane not ready)")
		return false
	}
	d.fabricMu.Lock()
	if slot == 1 {
		d.fabric1Populated = true
	} else {
		d.fabricPopulated = true
	}
	d.fabricMu.Unlock()
	slog.Info("cluster: fabric peer resolved",
		"interface", fabIface, "ifindex", link.Attrs().Index,
		"local_mac", localMAC, "peer_mac", peerMAC)
	rt.HA().SyncFabricState(ctx)
	return true
}

// fabricPeerResolver returns the live resolver when the published
// dataplane exposes it, else nil (caller uses the package function,
// which reads the same kernel tables).
func (d *Daemon) fabricPeerResolver() dpuserspace.FabricPeerResolver {
	rt := d.dataplane()
	if rt == nil {
		return nil
	}
	if p, ok := rt.(dpuserspace.FabricPeerResolver); ok {
		return p
	}
	if u, ok := rt.(interface{ Unwrap() any }); ok {
		if p, ok := u.Unwrap().(dpuserspace.FabricPeerResolver); ok {
			return p
		}
	}
	// Production publishes NewLegacyDataPlaneAdapter(New()) (Boot), which
	// exposes the Manager via Manager() rather than the resolver directly.
	if mp, ok := rt.(interface{ Manager() *dpuserspace.Manager }); ok {
		if m := mp.Manager(); m != nil {
			return m
		}
	}
	return nil
}

// clearFabricPeer clears the slot's populated latch on path down (#121
// retained as readiness state; there is no map entry to zero any more).
func (d *Daemon) clearFabricPeer(_ context.Context, slot int) {
	d.fabricMu.Lock()
	if slot == 1 {
		was := d.fabric1Populated
		d.fabric1Populated = false
		d.fabricMu.Unlock()
		if was {
			slog.Info("cluster: fabric1 peer cleared (path down)")
		}
		return
	}
	was := d.fabricPopulated
	d.fabricPopulated = false
	d.fabricMu.Unlock()
	if was {
		slog.Info("cluster: fabric peer cleared (path down)")
	}
}

func (d *Daemon) clearFabricFwd0(ctx context.Context) { d.clearFabricPeer(ctx, 0) }
func (d *Daemon) clearFabricFwd1(ctx context.Context) { d.clearFabricPeer(ctx, 1) }

// populateFabricFwd1 resolves the secondary fabric interface MACs and populates
// the secondary fabric peer for cross-chassis redirect (#17044).
// Mirrors populateFabricFwd for slot 1.
// refreshCh is fab1's OWN event-driven refresh channel, handed in by value at
// launch (#4958) — see populateFabricFwd for the rationale.
func (d *Daemon) populateFabricFwd1(ctx context.Context, fabIface, overlay, peerAddr string, refreshCh chan struct{}) {
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
	peer1Changed := !d.fabricPeerIP1.Equal(peerIP)
	if peer1Changed {
		d.fabricPeerMAC1 = nil
	}
	d.fabricPeerIP1 = peerIP
	d.fabricMu.Unlock()
	if peer1Changed {
		dpuserspace.RegisterFabricPeerMACConstraint(peerAddr, nil)
	}

	// Fast initial population: attempt immediately, then 500ms retries.
	for i := 0; i < 10; i++ {
		// Same pre-probe cancellation check as populateFabricFwd — iteration 0
		// must not transmit when the context is already cancelled.
		if ctx.Err() != nil {
			return
		}
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
			slog.Warn("cluster: fabric1 peer not resolved after fast retries, continuing with periodic refresh")
		}
	}

	// Periodic refresh every 30s as safety net, plus event-driven
	// refresh via fabricRefreshCh1 from netlink monitor (#124). fab1 has
	// its OWN channel (#4038): a single shared channel is drained by
	// exactly one waiting goroutine per send, so with both fab0 and fab1
	// selecting on one channel a trigger woke only one of them and the
	// other fabric's event was dropped until the 30s safety-net tick.
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.refreshFabricFwd1(ctx, fabIface, overlay, peerIP, false)
		case <-refreshCh:
			d.refreshFabricFwd1(ctx, fabIface, overlay, peerIP, false)
		}
	}
}

// refreshFabricFwd1 resolves secondary fabric state via the live
// resolver (#17044). Returns true on success.
func (d *Daemon) refreshFabricFwd1(ctx context.Context, fabIface, overlay string, peerIP net.IP, logWaiting bool) bool {
	return d.refreshFabricPeer(ctx, 1, fabIface, overlay, peerIP, logWaiting)
}

// RefreshFabricFwd triggers an immediate fabric peer refresh.
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
// triggers immediate fabric peer refresh when fabric interfaces or their
// neighbor entries change (#124). The 30s ticker in populateFabricFwd
// remains as a safety net.
//
// The vishvananda/netlink subscribe goroutine treats ANY receive error as
// terminal — on a recoverable ENOBUFS it closes the update channel. The
// pre-#4031 loop returned on that close, permanently disabling fabric
// monitoring AND leaking the sibling subscription's socket. The pair now
// runs as two nlWatch instances (#17064) sharing one ordered lifecycle:
// link subscribes first, then neigh, then the catch-up refresh; a close
// or failure of either tears down BOTH (no sibling leak) and both
// resubscribe after the shared backoff. nlWatch now also reports fabric
// receive errors (previously no ErrorCallback). Exits only on ctx cancel.
func (d *Daemon) monitorFabricState(ctx context.Context) {
	slog.Info("cluster: fabric state monitor started (link + neighbor)")
	linkSubscribe := d.fabricLinkSubscribe
	if linkSubscribe == nil {
		linkSubscribe = defaultFabricLinkSubscribe
	}
	neighSubscribe := d.fabricNeighSubscribe
	if neighSubscribe == nil {
		neighSubscribe = defaultFabricNeighSubscribe
	}
	backoff := d.fabricStateResubBackoff
	if backoff <= 0 {
		backoff = nlWatchBackoffDefault
	}
	for {
		if ctx.Err() != nil {
			return
		}
		linkW := nlWatch[netlink.LinkUpdate]{
			Name:      "fabric-link",
			Subscribe: linkSubscribe,
			Buf:       64,
			OnEvent: func(update netlink.LinkUpdate) {
				if update.Attrs() == nil {
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
			},
		}
		neighW := nlWatch[netlink.NeighUpdate]{
			Name:      "fabric-neigh",
			Subscribe: neighSubscribe,
			Buf:       64,
			OnEvent: func(update netlink.NeighUpdate) {
				d.fabricMu.RLock()
				isPeer := (d.fabricPeerIP != nil && update.IP.Equal(d.fabricPeerIP)) ||
					(d.fabricPeerIP1 != nil && update.IP.Equal(d.fabricPeerIP1))
				d.fabricMu.RUnlock()
				if isPeer {
					slog.Debug("cluster: fabric peer neighbor change detected",
						"ip", update.IP, "type", update.Type)
					d.triggerFabricRefresh()
				}
			},
		}
		if !runPairNL(ctx, linkW, neighW, func() { d.triggerFabricRefresh() }) {
			return
		}
		if !nlWatchBackoffWait(ctx, backoff) {
			return
		}
	}
}

// triggerFabricRefresh sends a non-blocking signal to BOTH fabric refresh
// channels, waking the populateFabricFwd (fab0) and populateFabricFwd1
// (fab1) loops. The netlink monitor and readiness gate do not tag events
// per-fabric, so any fabric event re-resolves both entries — matching the
// synchronous RefreshFabricFwd, which also refreshes fab0 and fab1.
//
// Each fabric owns its own channel (#4038). A single shared channel is
// received by exactly one waiting goroutine per send, so a lone trigger
// woke only fab0 or fab1 (whichever won the race) and the other fabric's
// event was lost until the 30s safety-net tick. Signaling both channels
// guarantees every configured fabric acts on the event immediately.
func (d *Daemon) triggerFabricRefresh() {
	// Snapshot the live epoch's channels under clusterCommsMu (#4958): the
	// constructor publishes them and stopClusterComms nils them, so a bare
	// field read here would race the swap. A nil channel (comms stopped or
	// fab1 not configured) falls through the default arm — a nil-channel send
	// never fires.
	ch0, ch1 := d.snapshotFabricRefreshChans()
	select {
	case ch0 <- struct{}{}:
	default:
		// fab0 already has a refresh pending — no need to queue another.
	}
	select {
	case ch1 <- struct{}{}:
	default:
		// fab1 already has a refresh pending (or fab1 is not configured
		// and its channel is nil — a nil-channel send never fires, so
		// the default arm handles that too). No need to queue another.
	}
}
