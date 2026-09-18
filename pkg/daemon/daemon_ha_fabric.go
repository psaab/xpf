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
func ensureFabricIPVLAN(parent, name string, addrs []string, configuredMTU int) error {
	parentLink, err := netlink.LinkByName(parent)
	if err != nil {
		return fmt.Errorf("parent %s: %w", parent, err)
	}

	// Ensure parent is UP — IPVLAN inherits carrier from parent.
	netlink.LinkSetUp(parentLink)

	// Set the configured fabric MTU on the parent before creating/reconciling
	// the overlay. The overlay cannot exceed its parent.
	wantMTU := fabricMTU10216(configuredMTU)
	if err := reconcileFabricMTU10216(parent, parentLink, wantMTU); err != nil {
		return fmt.Errorf("fabric parent %s MTU reconciliation: %w", parent, err)
	}

	// Check if IPVLAN already exists on correct parent.
	if existing, err := netlink.LinkByName(name); err == nil {
		if existing.Attrs().ParentIndex == parentLink.Attrs().Index {
			// Already correct — reconcile addresses, MTU, and ensure UP (#127).
			if err := reconcileFabricMTU10216(name, existing, wantMTU); err != nil {
				return fmt.Errorf("fabric IPVLAN %s MTU reconciliation: %w", name, err)
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

	// Set the overlay MTU exactly to the parent/configured target and verify
	// through a fresh lookup; a warn-only write makes the desired state
	// applied-by-nobody (#10216).
	if err := reconcileFabricMTU10216(name, link, wantMTU); err != nil {
		return fmt.Errorf("fabric IPVLAN %s MTU reconciliation: %w", name, err)
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
		"addrs", addrs, "mtu", wantMTU)
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

// fabricOverlayNames are every fabric IPVLAN this daemon can create.
//
// #8372: single-sourced because two callers now enumerate them —
// CleanupFabricIPVLANs (the `xpfd cleanup` subcommand) and the reassert loop's
// reaper. Two hardcoded copies of "which devices are ours" is a rule that
// silently stops covering a third device, and the reaper's failure mode there
// is the quiet one: it would simply never notice the new device had gone stale.
func fabricOverlayNames() []string { return []string{"fab0", "fab1"} }

// CleanupFabricIPVLANs removes all fabric IPVLAN interfaces (fab0, fab1).
func CleanupFabricIPVLANs() {
	for _, name := range fabricOverlayNames() {
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
	if ifCfg, ok := cfg.Interfaces.Interfaces[fabName]; ok && ifCfg != nil && ifCfg.LocalFabricMember != "" {
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
	// A re-pointed fabric is a DIFFERENT peer chassis, so the cached
	// address-matched MAC no longer identifies it. Drop it rather than let the
	// NDP fallback keep pinning the old peer's MAC (#6554) — the same
	// same-parent peer-REPLACEMENT hazard the Rust link merge guards (#5686).
	if !d.fabricPeerIP.Equal(peerIP) {
		d.fabricPeerMAC = nil
	}
	d.fabricPeerIP = peerIP
	d.fabricMu.Unlock()

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
			slog.Warn("cluster: fabric_fwd not populated after fast retries, continuing with periodic refresh")
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
	defer d.fabricMu.Unlock()
	if slot == 1 {
		d.fabricPeerMAC1 = stored
		return
	}
	d.fabricPeerMAC = stored
}

// selectFabricPeerLinkLocalMAC picks the fabric peer's MAC out of the fabric
// PARENT's IPv6 neighbour table when the peer's configured fabric address
// itself failed to resolve (#6554).
//
// This is the last-resort leg of peer-MAC resolution: probeFabricNeighbor
// deliberately seeds the parent's NDP table by pinging ff02::1 (all-nodes
// link-local multicast), so EVERY IPv6-speaking host on the fabric segment
// answers and lands in that table. The pre-#6554 code then took the first
// non-self link-local entry it saw. On a correctly-cabled back-to-back fabric
// the only other host is the peer chassis, but the fabric is not always a
// private point-to-point link, and picking a stranger's MAC is silent: the
// refresh reports success, latches fabricPopulated (which feeds the RG
// takeover-readiness gate), and logs a peer MAC that belongs to an unrelated
// adjacent host.
//
// The selection is therefore constrained to the peer's identity, strongest
// constraint first:
//
//   - expected != nil — an address-matched resolution has been seen before, so
//     the MAC that answered for the configured peer address is known. Accept
//     ONLY that MAC. A decoy cannot match it.
//   - expected == nil — nothing address-matched has ever been observed (cold
//     start / crash recovery, the case this fallback exists for). Fall back to
//     the point-to-point fabric assumption, but CHECK it instead of assuming
//     it: accept the sole eligible neighbour, and REFUSE when the segment
//     presents more than one. An ambiguous segment is exactly the topology the
//     permissive form mis-resolved on.
//
// Refusal is fail-closed by design: it returns no MAC, which leaves the caller
// on the existing "peer neighbour missing" path (retain a previously-good
// entry, else clear). That is the same state the node already occupies whenever
// the peer genuinely does not resolve, and it does NOT blackhole cross-chassis
// traffic — the userspace dataplane's redirect takes its destination MAC from
// FabricSnapshot.peer_mac, which is resolved independently and strictly by
// peer address in pkg/dataplane/userspace/fabric.go (buildFabricPeerMAC).
// Silently keeping the permissive behaviour would leave the defect reachable
// exactly on the shared segment where it matters.
//
// Candidates are deduplicated by MAC so a peer that owns several link-local
// addresses on the same NIC (EUI-64 plus a stable-privacy or manually
// configured address) still counts as one host and does not trip the
// ambiguity refusal.
//
// reason is empty on success and carries an operator-facing explanation on
// refusal. peerLL is the accepted neighbour's link-local address, for logging.
func selectFabricPeerLinkLocalMAC(
	neighs []netlink.Neigh,
	localMAC, expected net.HardwareAddr,
) (mac net.HardwareAddr, peerLL net.IP, candidates int, reason string) {
	type candidate struct {
		mac net.HardwareAddr
		ip  net.IP
	}
	var eligible []candidate
	seen := make(map[string]struct{}, len(neighs))
	for _, n := range neighs {
		if !dpuserspace.FabricNeighUsable(n) {
			continue
		}
		if !n.IP.IsLinkLocalUnicast() {
			continue
		}
		// A group-bit MAC is a multicast/broadcast destination, never a
		// unicast peer NIC — it can only be a mis-parsed or synthetic entry.
		if n.HardwareAddr[0]&0x01 != 0 {
			continue
		}
		if bytes.Equal(n.HardwareAddr, localMAC) {
			continue
		}
		key := n.HardwareAddr.String()
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		eligible = append(eligible, candidate{mac: n.HardwareAddr, ip: n.IP})
	}

	if len(expected) == 6 {
		for _, c := range eligible {
			if bytes.Equal(c.mac, expected) {
				return c.mac, c.ip, len(eligible), ""
			}
		}
		return nil, nil, len(eligible),
			"no link-local neighbour carries the known fabric peer MAC"
	}

	switch len(eligible) {
	case 0:
		return nil, nil, 0, "no eligible link-local neighbour on the fabric parent"
	case 1:
		return eligible[0].mac, eligible[0].ip, 1, ""
	default:
		return nil, nil, len(eligible),
			"ambiguous fabric segment: multiple link-local neighbours and no " +
				"address-matched peer MAC to identify the peer chassis"
	}
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
	link, err := d.fabricLinkByName(fabIface)
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
		if ol, err := d.fabricLinkByName(overlay); err == nil {
			neighLink = ol
		}
	}
	neighFamily := netlink.FAMILY_V4
	if peerIP.To4() == nil {
		neighFamily = netlink.FAMILY_V6
	}

	neighs, err := d.fabricNeighList(neighLink.Attrs().Index, neighFamily)
	if err != nil {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (neighbor list)",
			"overlay", neighLink.Attrs().Name, "peer", peerIP, "err", err)
		d.clearFabricFwd0(ctx)
		return false
	}
	var peerMAC net.HardwareAddr
	for _, n := range neighs {
		if n.IP.Equal(peerIP) && dpuserspace.FabricNeighUsable(n) {
			peerMAC = n.HardwareAddr
			break
		}
	}
	// An address-matched hit is a real identity binding: this MAC answered for
	// the CONFIGURED peer address. Remember it so the link-local fallback below
	// has a peer identity to check against on a later refresh (#6554).
	if peerMAC != nil {
		d.rememberFabricPeerMAC(0, peerMAC)
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
		parentNeighs, _ := d.fabricNeighList(parentIdx, neighFamily)
		for _, n := range parentNeighs {
			if n.IP.Equal(peerIP) && dpuserspace.FabricNeighUsable(n) {
				peerMAC = n.HardwareAddr
				// Still address-matched — same identity binding as above.
				d.rememberFabricPeerMAC(0, peerMAC)
				slog.Info("cluster: fabric peer MAC resolved via parent ARP",
					"peer_mac", peerMAC, "overlay", overlay)
				break
			}
		}
		// Check parent IPv6 NDP neighbors (populated via the ff02::1 probe).
		// This leg has NO peer address to match on, so it is constrained to the
		// peer's identity by selectFabricPeerLinkLocalMAC and fails closed when
		// the segment cannot be shown to hold exactly the peer (#6554).
		if peerMAC == nil {
			v6Neighs, _ := d.fabricNeighList(parentIdx, netlink.FAMILY_V6)
			mac, peerLL, nCandidates, reason := selectFabricPeerLinkLocalMAC(
				v6Neighs, localMAC, d.fabricPeerMACHint(0))
			switch {
			case mac != nil:
				peerMAC = mac
				slog.Info("cluster: fabric peer MAC resolved via parent IPv6 NDP",
					"peer_mac", peerMAC, "peer_ll", peerLL, "overlay", overlay)
			case nCandidates > 0:
				// Candidates existed but none could be attributed to the peer.
				// Throttled: this runs on every neighbour event plus the 30s tick.
				d.logFabricRefreshFailure(0,
					"cluster: fabric peer MAC NDP fallback refused (unidentified neighbour)",
					"reason", reason, "candidates", nCandidates,
					"peer", peerIP, "overlay", overlay)
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

	rt := d.dataplane()
	if rt == nil {
		d.logFabricRefreshFailure(0, "cluster: fabric refresh failed (dataplane not ready)")
		return false
	}
	if err := rt.HA().SetFabricForwarding(ctx, dataplane.FabricID(0), info); err != nil {
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
	// been built before the peer MAC was resolved. #2114 (Codex PR
	// #6743 r3-7): reuse the snapshot from above — the map update and
	// the helper sync are one coupled operation, and a second load
	// could observe a mid-refresh clear (map updated, sync skipped).
	rt.HA().SyncFabricState(ctx)

	return true
}

// clearFabricFwd0 writes a zeroed FabricFwdInfo to key=0 if a valid entry
// was previously written, ensuring the dataplane falls back (#121).
func (d *Daemon) clearFabricFwd0(ctx context.Context) {
	d.fabricMu.RLock()
	populated := d.fabricPopulated
	d.fabricMu.RUnlock()
	rt := d.dataplane()
	if !populated || rt == nil {
		return
	}
	if err := rt.HA().SetFabricForwarding(ctx, dataplane.FabricID(0), dataplane.FabricFwdInfo{}); err != nil {
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
	// Peer replacement invalidates the cached identity — see populateFabricFwd.
	if !d.fabricPeerIP1.Equal(peerIP) {
		d.fabricPeerMAC1 = nil
	}
	d.fabricPeerIP1 = peerIP
	d.fabricMu.Unlock()

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
			slog.Warn("cluster: fabric1_fwd not populated after fast retries, continuing with periodic refresh")
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

// refreshFabricFwd1 resolves secondary fabric link/neighbor state and updates
// the fabric_fwd BPF map at key=1. Returns true on success.
// fabIface is the physical parent; overlay is the IPVLAN child (#129).
func (d *Daemon) refreshFabricFwd1(ctx context.Context, fabIface, overlay string, peerIP net.IP, logWaiting bool) bool {
	link, err := d.fabricLinkByName(fabIface)
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
		if ol, err := d.fabricLinkByName(overlay); err == nil {
			neighLink = ol
		}
	}
	neighFamily := netlink.FAMILY_V4
	if peerIP.To4() == nil {
		neighFamily = netlink.FAMILY_V6
	}
	neighs, err := d.fabricNeighList(neighLink.Attrs().Index, neighFamily)
	if err != nil {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (neighbor list)",
			"overlay", neighLink.Attrs().Name, "peer", peerIP, "err", err)
		d.clearFabricFwd1(ctx)
		return false
	}
	var peerMAC net.HardwareAddr
	for _, n := range neighs {
		if n.IP.Equal(peerIP) && dpuserspace.FabricNeighUsable(n) {
			peerMAC = n.HardwareAddr
			break
		}
	}
	// fab1 has no link-local fallback leg — its only resolution is
	// address-matched — but record the identity anyway so the two slots keep
	// the same contract if a fallback is ever added here (#6554).
	if peerMAC != nil {
		d.rememberFabricPeerMAC(1, peerMAC)
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

	rt := d.dataplane()
	if rt == nil {
		d.logFabricRefreshFailure(1, "cluster: fabric1 refresh failed (dataplane not ready)")
		return false
	}
	if err := rt.HA().SetFabricForwarding(ctx, dataplane.FabricID(1), info); err != nil {
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
	rt := d.dataplane()
	if !populated || rt == nil {
		return
	}
	if err := rt.HA().SetFabricForwarding(ctx, dataplane.FabricID(1), dataplane.FabricFwdInfo{}); err != nil {
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

// fabricStateResubBackoffDefault is the delay between a fabric netlink
// subscription close (a recoverable ENOBUFS receive-buffer overflow or other
// transient receive error) and the resubscribe attempt (#4031).
const fabricStateResubBackoffDefault = 2 * time.Second

// defaultFabricLinkSubscribe is the production fabricLinkSubscribe seam (#4031).
func defaultFabricLinkSubscribe(ch chan<- netlink.LinkUpdate, done <-chan struct{}) error {
	return netlink.LinkSubscribe(ch, done)
}

// defaultFabricNeighSubscribe is the production fabricNeighSubscribe seam (#4031).
func defaultFabricNeighSubscribe(ch chan<- netlink.NeighUpdate, done <-chan struct{}) error {
	return netlink.NeighSubscribe(ch, done)
}

// monitorFabricState subscribes to netlink link and neighbor updates and
// triggers immediate fabric_fwd refresh when fabric interfaces or their
// neighbor entries change (#124). The 30s ticker in populateFabricFwd
// remains as a safety net.
//
// The vishvananda/netlink subscribe goroutine treats ANY receive error as
// terminal — on a recoverable ENOBUFS receive-buffer overflow (a burst of
// link/neighbor events overruns the socket) it closes the update channel. The
// pre-#4031 loop returned on that close, permanently disabling fabric
// monitoring for the daemon's lifetime AND leaking the sibling subscription's
// netlink socket (its done channel was never closed, so its done-watcher
// goroutine never released the fd). A missed fabric up/down transition then
// caused HA mis-behavior (stale fabric-up blackhole or a missed fabric-down
// failover). The loop now delegates one subscription lifetime to
// runFabricStateSubscription, which RESUBSCRIBES on a recoverable close and
// closes BOTH netlink sockets on every path. Because ENOBUFS means events were
// DROPPED, each fresh subscription re-syncs fabric forwarding via
// triggerFabricRefresh to catch up on any transition missed during the
// overflow. It exits only on context cancellation (#4031).
func (d *Daemon) monitorFabricState(ctx context.Context) {
	slog.Info("cluster: fabric state monitor started (link + neighbor)")
	for {
		if !d.runFabricStateSubscription(ctx) {
			return // context cancelled — clean exit
		}
		// The subscription closed on a recoverable receive error (ENOBUFS or
		// similar) or a subscribe failure. Back off briefly, then resubscribe.
		// The catch-up refresh runs inside runFabricStateSubscription once the
		// fresh subscriptions are live, so no fabric transition window is lost.
		backoff := d.fabricStateResubBackoff
		if backoff <= 0 {
			backoff = fabricStateResubBackoffDefault
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
	}
}

// runFabricStateSubscription owns ONE pair of netlink subscriptions (link +
// neighbor) for the fabric-state monitor. It returns true when a subscription
// closed on a recoverable receive error (or a subscribe failure) — the caller
// should back off and resubscribe — and false when ctx was cancelled (the
// caller should exit). Both done channels are closed exactly once on every
// path via defer, so neither netlink socket leaks on any exit or resubscribe
// (the #4031 fd-leak fix) (#124).
func (d *Daemon) runFabricStateSubscription(ctx context.Context) bool {
	linkSubscribe := d.fabricLinkSubscribe
	if linkSubscribe == nil {
		linkSubscribe = defaultFabricLinkSubscribe
	}
	neighSubscribe := d.fabricNeighSubscribe
	if neighSubscribe == nil {
		neighSubscribe = defaultFabricNeighSubscribe
	}

	linkUpdates := make(chan netlink.LinkUpdate, 64)
	linkDone := make(chan struct{})
	if err := linkSubscribe(linkUpdates, linkDone); err != nil {
		slog.Warn("cluster: failed to subscribe to link updates for fabric monitor", "err", err)
		// The subscribe may have started its done-watcher goroutine before
		// failing; close done to avoid leaking it. Recoverable — retry.
		close(linkDone)
		return true
	}
	defer close(linkDone)

	neighUpdates := make(chan netlink.NeighUpdate, 64)
	neighDone := make(chan struct{})
	if err := neighSubscribe(neighUpdates, neighDone); err != nil {
		slog.Warn("cluster: failed to subscribe to neigh updates for fabric monitor", "err", err)
		// linkDone is closed by the deferred close above. Close neighDone too
		// (defensive: a done-watcher may already be running). Recoverable.
		close(neighDone)
		return true
	}
	defer close(neighDone)

	// Re-sync fabric forwarding now that both subscriptions are live so any
	// link/neighbor transition missed during a prior overflow (or racing this
	// enumeration) is caught up. Idempotent — a non-blocking refresh signal.
	d.triggerFabricRefresh()

	for {
		select {
		case <-ctx.Done():
			return false // clean exit; both done channels closed by defer
		case update, ok := <-linkUpdates:
			if !ok {
				// The netlink subscribe goroutine closes the channel on ANY
				// receive error, including a recoverable ENOBUFS. Resubscribe;
				// the deferred closes release BOTH netlink sockets (no leak).
				slog.Warn("cluster: fabric link-update subscription closed, resubscribing")
				return true
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
				slog.Warn("cluster: fabric neigh-update subscription closed, resubscribing")
				return true
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
