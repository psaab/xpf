package userspace

import (
	"bytes"
	"net"
	"net/netip"
	"sort"
	"sync"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// buildFabricSnapshots builds the fabric rows against a FRESH kernel xfrm
// sample. buildSnapshot uses buildFabricSnapshotsFrom instead, so the interface
// rows and the fabric parents are judged against ONE sample.
//
// SyncFabricState (manager_ha.go) uses this form for the MAC/ifindex/link-state
// half and then discards the freshly sampled verdict — see alignFabricVerdicts,
// which is also where the reason lives. An earlier revision of this comment said
// SyncFabricState "has no interface rows to agree with", and that was simply
// wrong: its rows are written back into m.lastSnapshot beside the existing
// interface rows on both planes, so its sample has to agree with theirs.
func buildFabricSnapshots(cfg *config.Config) []FabricSnapshot {
	liveXfrm, _ := sampleLiveXfrmNetdevs()
	return buildFabricSnapshotsFrom(cfg, liveXfrm)
}

// alignFabricVerdicts returns fresh fabric rows carrying the device-level
// VERDICT the applied snapshot already holds for each parent netdev.
//
// #6691 round 11. A fabric refresh (SyncFabricState, called after every
// refreshFabricFwdSlot) re-resolves peer MACs for cross-chassis forwarding; round 10
// made it re-decide ParentUnbindable as a side effect, because the verdict is
// computed inside the same builder. That is a partial view of a changing kernel:
//
//   - It DESYNCHRONISES THE TWO PLANES. Neither side replans on a refresh —
//     Rust's `update_fabrics` swaps snapshot.fabrics in place (replan_queues runs
//     only from the apply path), and the Go ingress-adjudication map was
//     installed at apply time. The next partial republish (route overlay,
//     scheduler, #5134 worker arm — all `next := *m.lastSnapshot`) then ships the
//     new verdict and makes Rust replan while the Go map still carries the old
//     answer. An ifindex in the ingress map with no READY binding is
//     drop_degraded_transit (BINDING_MISSING), the unsafe direction.
//   - It MIXES SAMPLES. The interface rows are only ever re-derived by a full
//     build, so a refreshed fabric verdict is evidence from a different instant
//     than the rows it shares a snapshot with.
//
// A binding verdict is a property of the APPLIED snapshot — taken once, with the
// rows it must agree with, and changed only by applying a new one, which is also
// the single moment both planes recompute together. A kernel that acquires an
// xfrm device under a member's name is picked up at that next apply exactly as
// it is for every interface row, so nothing is lost that was not already
// deferred.
//
// Matched by parent NETDEV, which is the identity both planes key on
// (snapshot_refuses_parent_netdev is name-keyed). A row with no stored
// counterpart keeps its fresh verdict: fabric rows are derived from
// m.lastSnapshot.Config, the same config the stored rows were built from, so a
// new parent netdev cannot appear without a config change — and a config change
// arrives through a full apply, which re-derives both halves anyway.
//
// #16023: LinkAuthenticated is deliberately NOT aligned. It is CONFIG
// authority (the operator's chassis-cluster attestation as compiled into
// m.lastSnapshot.Config), freshly derived by buildFabricSnapshotsFrom on
// every sample — including a delete of fabric-interface-authenticated,
// which therefore arrives here already false. Carrying the stored value
// forward (as ParentUnbindable is carried) would keep a revoked attestation
// alive through every SyncFabricState refresh until the next full apply.
func alignFabricVerdicts(fresh []FabricSnapshot, applied *ConfigSnapshot) []FabricSnapshot {
	if applied == nil || len(fresh) == 0 {
		return fresh
	}
	stored := make(map[string]bool, len(applied.Fabrics))
	for _, fab := range applied.Fabrics {
		if fab.ParentLinuxName == "" {
			continue
		}
		stored[fab.ParentLinuxName] = fab.ParentUnbindable
	}
	out := make([]FabricSnapshot, len(fresh))
	copy(out, fresh)
	for i := range out {
		if verdict, ok := stored[out[i].ParentLinuxName]; ok {
			out[i].ParentUnbindable = verdict
		}
	}
	return out
}

func buildFabricSnapshotsFrom(cfg *config.Config, liveXfrm map[string]bool) []FabricSnapshot {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	cc := cfg.Chassis.Cluster
	type fabricInput struct {
		name string
		peer string
		// linkAuthenticated is the #16023 operator attestation for this link.
		linkAuthenticated bool
	}
	inputs := []fabricInput{
		{name: cc.FabricInterface, peer: cc.FabricPeerAddress, linkAuthenticated: cc.FabricLinkAuthenticated},
		{name: cc.Fabric1Interface, peer: cc.Fabric1PeerAddress, linkAuthenticated: cc.Fabric1LinkAuthenticated},
	}
	var out []FabricSnapshot
	seen := make(map[string]struct{}, len(inputs))
	for _, in := range inputs {
		if in.name == "" {
			continue
		}
		if _, ok := seen[in.name]; ok {
			continue
		}
		seen[in.name] = struct{}{}
		ifCfg := cfg.Interfaces.Interfaces[in.name]
		if ifCfg == nil {
			continue
		}
		parentName := ifCfg.LocalFabricMember
		parentLinux := config.LinuxIfName(parentName)
		parentIfindex, _, parentMAC, _ := buildLinkSnapshot(parentLinux)
		overlayLinux := config.LinuxIfName(in.name)
		overlayIfindex, _, _, _ := buildLinkSnapshot(overlayLinux)
		rxQueues := 0
		if parentLinux != "" {
			rxQueues = userspaceRXQueueCount(parentLinux)
		}
		peerMAC := buildFabricPeerMAC(overlayIfindex, parentIfindex, in.peer, parseMACOrNil(parentMAC), fabricPeerMACConstraint(in.peer))
		out = append(out, FabricSnapshot{
			Name:              in.name,
			ParentInterface:   parentName,
			ParentLinuxName:   parentLinux,
			ParentIfindex:     parentIfindex,
			ParentUnbindable:  fabricParentUnbindable(cfg, parentName, parentLinux, liveXfrm),
			OverlayLinux:      overlayLinux,
			OverlayIfindex:    overlayIfindex,
			RXQueues:          rxQueues,
			PeerAddress:       in.peer,
			LocalMAC:          parentMAC,
			PeerMAC:           peerMAC,
			Up:                fabricParentUp(parentLinux),
			LinkAuthenticated: in.linkAuthenticated,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

// fabricParentUnbindable is the device-level verdict for a fabric parent
// netdev: may the userspace dataplane bind an AF_XDP socket to it?
//
// #6691 round 10, and it exists because A FABRIC MEMBER NEEDS NO INTERFACE
// STANZA. `set interfaces fab0 fabric-options member-interfaces ge-0/0/0` names
// ge-0/0/0 without creating a row for it, so the parent netdev can reach the
// ingress-adjudication map and the RSS allowlist — the fabric loops push it
// there — while no InterfaceSnapshot owns it. userspaceRefusedNetdevs is built
// from ROWS, so it had no evidence about such a netdev and, being a
// unanimity rule over an empty bucket, returned "not refused". Round 9 read
// that as an ADMISSION and let an unbindable ownerless parent through both
// loops on both planes.
//
// The fix is not a fourth conjunct on the tally. It is that AN EMITTED FABRIC
// PARENT IS AN OWNER OF ITS NETDEV: the fabric contributes that netdev to the
// same sets a row does, on its own account, so it must carry a verdict and be
// counted (snapshotNetdevVotes). This function is that verdict, and it is
// deliberately computed by handing a synthetic row to userspaceUnbindableNetdev
// rather than by restating the classes — the class table stays the single
// authority on what makes a netdev unbindable, so a class added there covers
// fabric parents without anyone remembering to.
//
// WHERE THE VERDICT IS CONSULTED (#6691 round 11): only where NO interface row
// owns the netdev. Round 10 counted it as a co-owner beside any row, which made
// one device two owners judged from different evidence, and a disagreement is
// read as an admission. Two ways to produce one were reachable — a canonical
// alias (fixed below by keying the stanza lookup on the netdev) and a re-sampled
// kernel (fixed by alignFabricVerdicts) — but the rule change is what makes a
// third one harmless. So this verdict is authoritative exactly where it is the
// only evidence there is, which is the case it was written for.
//
// The synthetic row carries exactly the fields the class table reads:
//
//   - Name — the CONFIG name (`ge-0/0/0`), which is what the fxp/em/fab/lo0
//     arms shape-test. A fabric parent is never itself `fab*`; the fab arm
//     refuses the OVERLAY, which is a different netdev.
//   - Tunnel — the parent's interface-level `tunnel` stanza, read through
//     interfaceConfigForNetdev so the stanza is found under EITHER spelling of
//     the device's name, mirroring what the BASE row would carry. A UNIT-level
//     tunnel is deliberately not read: it makes the unit row unbindable and
//     leaves the base row bindable, and the fabric binds the base netdev.
//   - SecureTunnel — snapshotSecureTunnel against the SHARED sample, so an
//     ownerless parent gets both halves of the evidence a row would get: an
//     IPsec bind-interface naming it, OR kernel link kind `xfrm`. The kernel
//     half is the reachable one here, and it is why this cannot be answered
//     from config alone: a slot-shaped netdev created out of band is both a
//     legal fabric member and a refused device.
//
// An empty parent name is bindable-by-default: nothing is emitted for it (the
// fabric loops guard on the name/ifindex), so there is no netdev to judge.
func fabricParentUnbindable(cfg *config.Config, parentName, parentLinux string, liveXfrm map[string]bool) bool {
	if parentLinux == "" {
		return false
	}
	parentTunnel := false
	if parentCfg := interfaceConfigForNetdev(cfg, parentLinux); parentCfg != nil {
		parentTunnel = parentCfg.Tunnel != nil
	}
	return userspaceUnbindableNetdev(InterfaceSnapshot{
		Name:         parentName,
		LinuxName:    parentLinux,
		Tunnel:       parentTunnel,
		SecureTunnel: snapshotSecureTunnel(cfg, parentName, parentLinux, liveXfrm),
	})
}

// interfaceConfigForNetdev returns the authored interface stanza whose NETDEV is
// linuxName, or nil when no stanza describes that device.
//
// #6691 round 11: keyed on the netdev, not on the authored spelling. LinuxIfName
// maps '/' to '-' and nothing else, so `gr-0/0/3` and `gr-0-0-3` are two legal
// authored names for ONE device — and a fabric member and its interface stanza
// routinely carry different ones, because the member MUST be slot-spelled with
// slashes for InterfaceSlot to resolve it to a node while the stanza name is a
// wildcard the schema accepts either way. An exact map lookup missed the stanza
// and returned a verdict about a device the config does describe, which under
// round 10's co-voting fabric admitted a refused GRE device.
//
// The exact hit is tried first as a fast path — it can only hit a stanza whose
// own name is already the Linux name, so it selects what the scan would.
//
// The scan takes the lexicographically LAST matching name rather than the first
// one the map hands back. A committed config cannot have two:
// validateInterfaceNameCollisionStrict (pkg/config) rejects one where two
// authored names canonicalize to a single Linux name. But a verdict must not be
// decided by Go's map iteration order on a config that never reached that gate,
// and "last" is not arbitrary — it is the same name that validator names as the
// winner ("the lexicographically later name would silently win") when two
// stanzas contend for one device. The verdict then describes the stanza that
// wins the device.
func interfaceConfigForNetdev(cfg *config.Config, linuxName string) *config.InterfaceConfig {
	if cfg == nil || linuxName == "" {
		return nil
	}
	if ifc, ok := config.LookupInterface(cfg, linuxName); ok {
		return ifc
	}
	var (
		bestName string
		best     *config.InterfaceConfig
	)
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil || config.LinuxIfName(name) != linuxName {
			continue
		}
		if best == nil || name > bestName {
			bestName, best = name, ifc
		}
	}
	return best
}

// linkByNameFn resolves a kernel link by name. It is a package var so tests
// can drive link-state verdicts without real interfaces (#11404) -- the same
// shape as fabricNeighListFn below and liveXfrmNetdevs (interfaces.go).
// Production never assigns it.
var linkByNameFn = netlink.LinkByName

// kernelLinkUp reports whether a RESOLVED kernel link is usable for
// forwarding: administratively up and not in a definite down oper-state.
// Only OperDown, OperLowerLayerDown and OperNotPresent return false --
// OperUp, OperUnknown, OperDormant and OperTesting count as up, because many
// virtual/overlay parents report OperUnknown with a live carrier and
// mis-marking a healthy link down diverts traffic wrongly (#4082). Shared by
// the fabric-parent verdict and the per-row interface LinkUp wire (#11404).
func kernelLinkUp(link netlink.Link) bool {
	if link == nil {
		return false
	}
	attrs := link.Attrs()
	// An administratively-down link can never forward.
	if attrs.Flags&net.FlagUp == 0 {
		return false
	}
	switch attrs.OperState {
	case netlink.OperDown, netlink.OperLowerLayerDown, netlink.OperNotPresent:
		return false
	default:
		return true
	}
}

// linuxLinkUp reports whether the named kernel link is usable for forwarding
// (#4082, #11404). Administrative-down and operational-down/not-present states
// are definite evidence of a down link; other resolved states remain usable.
// An empty name or failed lookup reports down.
func linuxLinkUp(linuxName string) bool {
	if linuxName == "" {
		return false
	}
	link, err := linkByNameFn(linuxName)
	if err != nil || link == nil {
		return false
	}
	return kernelLinkUp(link)
}

// fabricParentUp reports whether the fabric parent link's carrier/oper state is
// usable for forwarding (#4082). The cross-chassis redirect egresses over the
// parent ifindex, so a DOWN parent means the redirect would blackhole; the Rust
// selection prefers a fabric whose parent reports up and fails open when no
// fabric reports up.
func fabricParentUp(linuxName string) bool {
	return linuxLinkUp(linuxName)
}

// fabricNeighListFn is the netlink neighbour enumerator used by the fabric
// peer-MAC resolver, indirected so a test can drive buildFabricPeerMAC itself
// against a synthetic neighbour table (#7443).
//
// #6598 hardened the selection but bound only the extracted helper
// (selectFabricPeerMAC) and pkg/daemon's call sites. buildFabricPeerMAC -- the
// LIVE resolver, whose result becomes FabricSnapshot.PeerMAC and reaches the
// dataplane as the cross-chassis redirect destination -- called netlink
// directly, so no test could execute it and reverting its body to the
// pre-#6598 inline loop left the whole suite green. The seam is what makes the
// fail-on-revert assertion reach the function the issue names.
//
// Same shape as ruleListFn (routes.go) and as the d.linkByNameFn/d.neighListFn
// seams pkg/daemon added for exactly this purpose in #6554.
var fabricNeighListFn = netlink.NeighList

// FabricNeighValidStates is the NUD mask of neighbour states whose hardware
// address is usable for forwarding. INCOMPLETE/FAILED/NONE carry no address, or
// retain a stale one, and are excluded. NUD_NOARP is excluded because it does
// not establish a resolved unicast peer.
//
// The state bits match usableNUD
// (pkg/daemon/daemon_neighbor_listener.go); both reject NUD_NOARP. The fabric
// predicate additionally requires a six-byte Ethernet address because it
// installs one specific peer MAC, while the general listener publishes
// resolved neighbors to the forwarding snapshot.
//
// Keep both masks in sync when the Rust neighbor-state accept rules change.
// Their separate definitions reflect the package boundary and different
// surrounding validation, not a policy difference in which NUD states resolve.
//
// It lives here, in the package that owns the LIVE fabric peer-MAC resolver,
// and pkg/daemon consumes it. Both packages resolve the same thing -- which MAC
// currently answers for the fabric peer -- so any disagreement between them is
// a defect by construction, never a legitimate difference of policy. That is
// the case for one definition rather than two agreeing ones (#6598).
const FabricNeighValidStates = netlink.NUD_REACHABLE | netlink.NUD_STALE |
	netlink.NUD_PERMANENT | netlink.NUD_DELAY | netlink.NUD_PROBE

// FabricNeighUsable reports whether a neighbour entry's link-layer address may
// be used as a fabric forwarding destination: a 6-byte Ethernet address in a
// NUD state that means the kernel believes it.
//
// The length check is not redundant with the state check. A NUD_STALE entry is
// a perfectly valid state whose HardwareAddr can still be a non-Ethernet or
// truncated address on a non-Ethernet link, and the dataplane copies exactly
// six bytes into the redirect header.
func FabricNeighUsable(n netlink.Neigh) bool {
	return len(n.HardwareAddr) == 6 && n.State&FabricNeighValidStates != 0
}

func parseMACOrNil(s string) net.HardwareAddr {
	if s == "" {
		return nil
	}
	mac, err := net.ParseMAC(s)
	if err != nil || len(mac) != 6 {
		return nil
	}
	return mac
}

// selectFabricPeerMAC returns the link-layer address of the first entry in
// neighs that both answers for ip and is usable for forwarding, or nil.
//
// Split out from buildFabricPeerMAC so the selection can be tested without a
// netlink socket or root: the defect this guards is entirely in which entries
// are ACCEPTED, and that decision should not require the kernel to reproduce.
func selectFabricPeerMAC(neighs []netlink.Neigh, ip net.IP) net.HardwareAddr {
	for _, neigh := range neighs {
		if neigh.IP == nil || !neigh.IP.Equal(ip) {
			continue
		}
		if !FabricNeighUsable(neigh) {
			continue
		}
		return neigh.HardwareAddr
	}
	return nil
}

// SelectFabricPeerLinkLocalMAC picks the fabric peer's MAC out of the fabric
// PARENT's IPv6 neighbour table when the peer's configured fabric address
// itself failed to resolve (#6554, #15918).
//
// This is the SINGLE authoritative implementation of the identity-constrained
// link-local fallback. pkg/daemon's refreshFabricFwdSlot and the
// live userspace resolver buildFabricPeerMAC both call it, so a MAC the daemon
// accepts (and latches the slot populated on) is exactly the MAC the helper
// publishes in FabricSnapshot.PeerMAC. Before #15918 the daemon had its own
// copy and the live resolver had none: the fallback populated the retired BPF
// map and the readiness flag while PeerMAC stayed empty and Rust skipped the
// fabric as UnresolvedPeerMac.
//
// Selection, strongest constraint first:
//   - expected != nil (6 bytes): an address-matched resolution has been seen
//     before, so only a neighbour bearing that MAC is accepted.
//   - expected == nil: accept the sole eligible neighbour (deduped by MAC);
//     refuse when the segment presents more than one distinct MAC.
//
// Eligible: usable NUD state, link-local unicast IP, 6-byte non-multicast MAC,
// not the local fabric parent MAC. Refusal returns nil with a reason.
// peerLL is the accepted neighbour's link-local address, for logging.
func SelectFabricPeerLinkLocalMAC(
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
		if !FabricNeighUsable(n) {
			continue
		}
		if n.IP == nil || !n.IP.IsLinkLocalUnicast() {
			continue
		}
		if n.HardwareAddr[0]&0x01 != 0 {
			continue
		}
		if len(localMAC) == 6 && bytes.Equal(n.HardwareAddr, localMAC) {
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

// fabricPeerMACOverrides holds daemon-supplied identity constraints for the
// link-local fallback, keyed by CANONICAL configured peer address (#15918,
// review fold). The daemon owns the address-matched identity hint (it
// observes ARP/NDP for the configured peer and clears it on peer
// replacement); it registers the hint here so buildFabricSnapshots — also
// called from full snapshot builds without a daemon round-trip — constrains
// its fallback identically. All register/lookup/clear paths go through
// fabricPeerKey so equivalent spellings (e.g. expanded vs compressed IPv6)
// cannot miss: registration used peerIP.String() (canonical) while lookup
// used raw config text, which dropped the known-peer constraint and let a
// sole decoy link-local neighbour be accepted. Guarded by
// fabricPeerMACOverridesMu.
var (
	fabricPeerMACOverridesMu sync.RWMutex
	fabricPeerMACOverrides   = map[string]net.HardwareAddr{}
)

// fabricPeerKey is the single canonical key for a configured fabric peer
// address. Parseable addresses canonicalize via netip with Unmap, so every
// spelling of one address — expanded/compressed IPv6, and IPv4-mapped
// ::ffff:a.b.c.d vs dotted a.b.c.d — collapses to one key. Unmap matters
// because the daemon registers via net.IP.String(), which renders a
// mapped address dotted, while netip.Addr.String() retains the mapped
// form; without it that spelling lost the constraint again (#15923
// re-review). Zone is preserved by String on the unmapped address.
// Unparseable text keys verbatim so register/clear/lookup still agree.
func fabricPeerKey(peer string) string {
	if addr, err := netip.ParseAddr(peer); err == nil {
		return addr.Unmap().String()
	}
	return peer
}

// fabricPeerKeyValid reports whether peer parses as an IP address (the
// Rust build_fabric_link_or_skip peer-address admission, Go side).
func fabricPeerKeyValid(peer string) bool {
	_, err := netip.ParseAddr(peer)
	return err == nil
}

// RegisterFabricPeerMACConstraint records (or, with a nil/short MAC, clears)
// the known peer MAC for a configured fabric peer address (#15918). A clear
// prunes the entry (peer replacement / removal), so no stale identity can
// bind a later fabric that reuses the slot.
func RegisterFabricPeerMACConstraint(peer string, mac net.HardwareAddr) {
	if peer == "" {
		return
	}
	key := fabricPeerKey(peer)
	fabricPeerMACOverridesMu.Lock()
	defer fabricPeerMACOverridesMu.Unlock()
	if len(mac) != 6 {
		delete(fabricPeerMACOverrides, key)
		return
	}
	stored := make(net.HardwareAddr, 6)
	copy(stored, mac)
	fabricPeerMACOverrides[key] = stored
}

func fabricPeerMACConstraint(peer string) net.HardwareAddr {
	key := fabricPeerKey(peer)
	fabricPeerMACOverridesMu.RLock()
	defer fabricPeerMACOverridesMu.RUnlock()
	mac, ok := fabricPeerMACOverrides[key]
	if !ok || len(mac) != 6 {
		return nil
	}
	out := make(net.HardwareAddr, 6)
	copy(out, mac)
	return out
}

// buildFabricPeerMAC resolves the MAC that currently answers for the fabric
// peer address, or "" if none does.
//
// This is the LIVE resolver: its result becomes FabricSnapshot.PeerMAC and
// reaches the dataplane as the cross-chassis redirect destination.
//
// Resolution order (#6554/#15683/#15918/#17044 — this is now the ONLY resolver; the daemon latches readiness on it):
//  1. address-matched neighbour for the configured peer IP on overlay, then
//     parent (existing #6598/#7443 behaviour, NUD/length-gated);
//  2. if that fails, the identity-constrained parent IPv6 link-local fallback
//     (SelectFabricPeerLinkLocalMAC) — the sole/known-peer neighbour the
//     ff02::1 probe seeds. This makes the daemon's link-local acceptance
//     usable by the helper instead of readiness-only.
//
// localMAC is the fabric parent's own MAC (excluded from fallback
// candidates); expected is the last address-matched peer MAC, or nil.
//
// Returning "" is a deliberate degrade: Rust treats empty peer_mac as
// UNRESOLVED (FabricSkipReason::UnresolvedPeerMac) rather than forwarding
// to a MAC the peer may not own.
func buildFabricPeerMAC(overlayIfindex, parentIfindex int, peer string, localMAC, expected net.HardwareAddr) string {
	return buildFabricPeerMACWithNeighbours(overlayIfindex, parentIfindex, peer, localMAC, expected, fabricNeighListFn)
}

func buildFabricPeerMACWithNeighbours(overlayIfindex, parentIfindex int, peer string, localMAC, expected net.HardwareAddr, listFn func(int, int) ([]netlink.Neigh, error)) string {
	ip := net.ParseIP(peer)
	if ip == nil {
		return ""
	}
	family := netlink.FAMILY_V4
	if ip.To4() == nil {
		family = netlink.FAMILY_V6
	}
	for _, ifindex := range []int{overlayIfindex, parentIfindex} {
		if ifindex <= 0 {
			continue
		}
		neighs, err := listFn(ifindex, family)
		if err != nil {
			continue
		}
		if mac := selectFabricPeerMAC(neighs, ip); mac != nil {
			return mac.String()
		}
	}
	if parentIfindex > 0 && !ip.IsLinkLocalUnicast() {
		if v6Neighs, err := listFn(parentIfindex, netlink.FAMILY_V6); err == nil {
			if mac, _, _, _ := SelectFabricPeerLinkLocalMAC(v6Neighs, localMAC, expected); mac != nil {
				return mac.String()
			}
		}
	}
	return ""
}

// ResolveFabricPeerWithNeighbours is ResolveFabricPeer over an explicit
// neighbour enumerator, so daemon tests can drive the live resolver over
// the same synthetic tables as the daemon refresh (#17044).
func ResolveFabricPeerWithNeighbours(overlayIfindex, parentIfindex int, peer string, localMAC net.HardwareAddr, listFn func(int, int) ([]netlink.Neigh, error)) FabricPeerResolution {
	out := FabricPeerResolution{LocalMAC: localMAC, Ifindex: parentIfindex}
	if listFn == nil {
		listFn = fabricNeighListFn
	}
	s := buildFabricPeerMACWithNeighbours(overlayIfindex, parentIfindex, peer, localMAC, fabricPeerMACConstraint(peer), listFn)
	if s == "" {
		out.Reason = "no usable fabric peer neighbour"
		return out
	}
	mac, err := net.ParseMAC(s)
	if err != nil || len(mac) != 6 {
		out.Reason = "resolved fabric peer MAC is not a 6-byte Ethernet address"
		return out
	}
	out.PeerMAC = mac
	return out
}

// FabricPeerResolution is the daemon-facing result of the live fabric
// peer resolver (#17044). PeerMAC empty means unresolved; Reason names
// why (empty when resolved). LocalMAC/Ifindex describe the fabric parent.
type FabricPeerResolution struct {
	PeerMAC  net.HardwareAddr
	LocalMAC net.HardwareAddr
	Ifindex  int
	Reason   string
}

// FabricPeerResolver is implemented by *Manager.
type FabricPeerResolver interface {
	ResolveFabricPeer(slot int, overlayIfindex, parentIfindex int, peer string, localMAC net.HardwareAddr) FabricPeerResolution
}

// ResolveFabricPeer is the single live resolver (#17044): its result is
// both the helper's FabricSnapshot.PeerMAC source (via buildFabricPeerMAC)
// and the daemon's slot-populated readiness input. It consults the
// daemon-registered identity constraint exactly as buildFabricSnapshotsFrom
// does, so both paths agree by construction.
func ResolveFabricPeer(overlayIfindex, parentIfindex int, peer string, localMAC net.HardwareAddr) FabricPeerResolution {
	out := FabricPeerResolution{LocalMAC: localMAC, Ifindex: parentIfindex}
	s := buildFabricPeerMAC(overlayIfindex, parentIfindex, peer, localMAC, fabricPeerMACConstraint(peer))
	if s == "" {
		out.Reason = "no usable fabric peer neighbour"
		return out
	}
	mac, err := net.ParseMAC(s)
	if err != nil || len(mac) != 6 {
		out.Reason = "resolved fabric peer MAC is not a 6-byte Ethernet address"
		return out
	}
	out.PeerMAC = mac
	return out
}

// ResolveFabricPeer implements FabricPeerResolver on the userspace Manager.
func (m *Manager) ResolveFabricPeer(_ int, overlayIfindex, parentIfindex int, peer string, localMAC net.HardwareAddr) FabricPeerResolution {
	return ResolveFabricPeer(overlayIfindex, parentIfindex, peer, localMAC)
}
