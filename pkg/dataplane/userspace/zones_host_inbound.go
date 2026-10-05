package userspace

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// ZoneHostInboundView is the per-zone host-inbound-traffic enforcement view for
// the KERNEL-nftables primary path (#3070). Ordinary host-bound traffic to a
// firewall interface IP / VRRP VIP (SSH, ping, OSPF/BGP to the box) is shunted
// to the Linux kernel by the XDP shim before it ever reaches userspace-dp, so
// the authoritative host-inbound enforcement for those packets must live in the
// kernel `chain input` (mirroring the lo0-filter precedent). The userspace-dp
// LocalDelivery check (forwarding/host_inbound.rs) remains the secondary path
// for the narrow subset that DOES reach the XSK (DNAT-to-self, static-NAT to a
// firewall service, embedded-ICMP, DNS edge cases).
//
// One or more views are produced per host-inbound-CONFIGURED zone, split by
// effective per-interface token set when overrides apply. Each carries allowed
// Junos tokens, the resolved firewall-local host addresses (bare IPs, prefix
// stripped) by family, and the ingress scope that owns those tokens. The daemon
// applies local-address rules plus ingress-scoped catalog multicast rules.
type ZoneHostInboundView struct {
	Zone string
	// Interfaces lists the interface refs whose EFFECTIVE host-inbound token
	// set (the interface-level override when one is declared, else the
	// zone-level set — #6515 replace semantics, #3362) equals this view's
	// SystemServices/Protocols. A zone with no per-interface override yields a
	// single view per zone covering all its interfaces (pre-#3362 shape); a zone
	// with an override yields one view per distinct effective token set, each
	// scoped to that set's interface addresses and ingress. Sorted;
	// informational/test only (nft emission consumes both scope fields).
	Interfaces     []string
	SystemServices []string
	Protocols      []string
	// MulticastRules is the expanded family/group dimension of Protocols.
	MulticastRules []config.HostInboundMulticastRule
	V4Addrs        []string // bare host IPv4 addresses (no prefix)
	V6Addrs        []string // bare host IPv6 addresses (no prefix)
	// Screen flood limits are mirrored into the kernel input backstop because
	// PASS_TO_KERNEL rows bypass the userspace worker's screen stage.
	ICMPFloodThreshold   uint32
	UDPFloodThreshold    uint32
	SYNFloodThreshold    uint32
	SYNFloodSrcThreshold uint32
	AlarmWithoutDrop     bool

	// IngressNetdevs (#9637) are the kernel netdevs whose arriving host-bound
	// packets this view judges, whichever local address they name, plus routing
	// multicast packets addressed to catalog groups. They come from the view's
	// own interfaces, minus three kinds: a netdev another view also claims, a
	// lifeline's netdev, and a netdev enslaved to an l3mdev VRF. VRF slaves are
	// represented by their VRF master, visible at LOCAL_IN. See
	// hostInboundViewIngressNetdevsWithMasters.
	IngressNetdevs []string
	// IngressDenyNetdevs (#10431) are netdevs whose host-inbound claims could
	// not be assigned to one unambiguous view (for example, a shared parent).
	// The renderer applies destination-owner service rights first, then emits a
	// counted fail-closed catch-all for unmatched traffic before destination-only
	// rules. They are attached to one view only so each ambiguous rule set is
	// emitted once.
	IngressDenyNetdevs []string
}

// stableRethLinkLocalTarget identifies one logical interface on which the
// daemon may install the deterministic RETH router link-local. The value is
// deliberately derived from config, not a live interface snapshot: the
// address is present only on the MASTER, while host-inbound daddr scope must be
// identical on MASTER, BACKUP, and during the cold-boot fence.
type stableRethLinkLocalTarget struct {
	iface string
	addr  string
}

// stableRethLinkLocalTargets mirrors daemon.addStableRethLinkLocal. That
// routine installs fe80::bf72:<cluster>:<rg> on the RETH base device and on
// IPv6-bearing non-zero units. Unit 0 with no VLAN collapses onto the base
// device, so the unit-qualified name is the host-inbound zone identity for
// that address; a VLAN unit 0 is a distinct device and the stable address
// remains on the base identity. An explicit unit-0 link-local suppresses the
// daemon-managed address for the whole RETH interface.
//
// This helper is intentionally local to pkg/dataplane/userspace: importing
// pkg/cluster here would create the existing cluster → dataplane dependency
// cycle. Keep the byte construction in parity with cluster.StableRethLinkLocal
// (pkg/cluster/reth.go).
func stableRethLinkLocalTargets(cfg *config.Config) []stableRethLinkLocalTarget {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	owners := cfg.RethRGOwners()
	if len(owners) == 0 {
		return nil
	}
	clusterID := cfg.Chassis.Cluster.ClusterID
	ifNames := make([]string, 0, len(owners))
	for ifName := range owners {
		ifNames = append(ifNames, ifName)
	}
	sort.Strings(ifNames)

	var out []stableRethLinkLocalTarget
	for _, ifName := range ifNames {
		rgID := owners[ifName]
		if rgID <= 0 {
			// RG 0 is the cluster control group, not a RETH service group.
			continue
		}
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil || stableRethUnitHasConfiguredLinkLocal(ifc, 0) {
			continue
		}
		addr := stableRethLinkLocalString(clusterID, rgID)

		// addStableRethLinkLocal always puts the address on the base netdev.
		// A native unit-0 row is the same host-inbound identity; a VLAN unit
		// 0 is distinct, so retain the bare interface identity there.
		baseRef := ifName
		if unit0 := ifc.Units[0]; unit0 != nil && unit0.VlanID == 0 {
			baseRef = fmt.Sprintf("%s.0", ifName)
		}
		out = append(out, stableRethLinkLocalTarget{iface: baseRef, addr: addr})

		unitNums := make([]int, 0, len(ifc.Units))
		for unitNum := range ifc.Units {
			if unitNum > 0 {
				unitNums = append(unitNums, unitNum)
			}
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := ifc.Units[unitNum]
			if !stableRethUnitHasIPv6(unit) {
				continue
			}
			out = append(out, stableRethLinkLocalTarget{
				iface: fmt.Sprintf("%s.%d", ifName, unitNum),
				addr:  addr,
			})
		}
	}
	return out
}

func stableRethLinkLocalString(clusterID, rgID int) string {
	return net.IP{0xfe, 0x80, 0, 0, 0, 0, 0, 0,
		0, 0, 0xbf, 0x72, 0, byte(clusterID), 0, byte(rgID)}.String()
}

func stableRethUnitHasConfiguredLinkLocal(ifc *config.InterfaceConfig, unitNum int) bool {
	if ifc == nil {
		return false
	}
	unit := ifc.Units[unitNum]
	if unit == nil {
		return false
	}
	for _, raw := range unit.Addresses {
		ip, _, err := net.ParseCIDR(raw)
		if err == nil && ip.To4() == nil && ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

func stableRethUnitHasIPv6(unit *config.InterfaceUnit) bool {
	if unit == nil {
		return false
	}
	for _, raw := range unit.Addresses {
		if strings.Contains(raw, ":") {
			return true
		}
	}
	return unit.DHCPv6
}

// hostInboundScopeLinkAddr reports whether a snapshot address row is kernel
// scope-link: a self-assigned IPv6 link-local (or an IPv4 169.254 fallback)
// the kernel owns without any lease or config. Such an address never
// satisfies host-inbound RESOLUTION intent (#10751 R4-1): a DHCPv6 client
// awaiting its first lease sits beside the fe80::/64 the kernel assigned at
// link-up, and counting it as "resolved" would hand the early input barrier
// off while the lease's global address is still uncovered. Explicitly
// configured link-locals (a static fe80::/64, the deterministic stable RETH
// LL) carry scope-universe / config provenance and still resolve — only
// kernel scope-link rows are excluded. Follows the routes.go lens (skip
// non-routable scopes), narrowed to exactly SCOPE_LINK.
func hostInboundScopeLinkAddr(a InterfaceAddressSnapshot) bool {
	return a.Scope == int(netlink.SCOPE_LINK)
}

// hostInboundAddrKey identifies a configured address by logical unit ref plus
// family plus bare host IP (no prefix length — rendering detail, not
// identity). Per-unit on purpose: a static fe80::/64 on unit A must never
// satisfy unit B's lease intent.
func hostInboundAddrKey(unitRef, family, host string) string {
	return unitRef + "/" + family + "/" + host
}

// configuredHostInboundAddrKeys returns the set of (unit ref, family, host)
// identities explicitly carried in unit.Addresses, for
// configured-provenance checks.
func configuredHostInboundAddrKeys(cfg *config.Config) map[string]bool {
	keys := map[string]bool{}
	if cfg == nil {
		return keys
	}
	for ifName, iface := range cfg.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		for un, unit := range iface.Units {
			if unit == nil {
				continue
			}
			unitRef := fmt.Sprintf("%s.%d", ifName, un)
			for _, raw := range unit.Addresses {
				host := hostIPFromCIDR(raw)
				if host == "" {
					continue
				}
				fam := "inet"
				if strings.Contains(host, ":") {
					fam = "inet6"
				}
				keys[hostInboundAddrKey(unitRef, fam, host)] = true
			}
		}
	}
	return keys
}

// hostInboundScopeLinkUnresolved reports whether a snapshot row is a kernel
// scope-link address the pending-intent predicate must ignore: self-assigned
// link-local with NO configured provenance on that same unit. A scope-link
// row whose (family, host) is explicitly configured ON THE ROW'S UNIT still
// resolves — the merge prefers live rows, so a configured fe80::/64 already
// installed on the kernel reads back as scope-link (the kernel derives link
// scope for fe80::/10), and ignoring it would stick the scope pending
// forever with the barrier never handing off. Keyed by logical unit ref so
// a static address on unit A cannot satisfy a DHCP-pending unit B that
// happens to carry the same automatic value.
func hostInboundScopeLinkUnresolved(unitRef string, a InterfaceAddressSnapshot, configuredKeys map[string]bool) bool {
	if !hostInboundScopeLinkAddr(a) {
		return false
	}
	return !configuredKeys[hostInboundAddrKey(unitRef, a.Family, hostIPFromCIDR(a.Address))]
}

// BuildZoneHostInboundViewsFromSnapshots renders zone views from ONE caller-
// supplied address snapshot instead of sampling the kernel itself (#10751
// R4-2). The daemon's apply path samples once and threads that snapshot
// through the install inputs AND the handoff decision, so a lease landing
// mid-apply cannot skew the installed ruleset against the retention verdict.
// Installed semantics are include-all (identical to BuildZoneHostInboundViews):
// kernel link-locals stay in the deny set — the chain is `policy accept`, so
// dropping them from the destinations would leave link-local host input
// admitted post-handoff.
func BuildZoneHostInboundViewsFromSnapshots(cfg *config.Config, snaps []InterfaceSnapshot) []ZoneHostInboundView {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	return buildZoneHostInboundViewsFromSnaps(cfg, snaps, false)
}

// BuildZoneHostInboundViews renders zone views from a FRESH kernel snapshot.
// See buildZoneHostInboundViewsFromSnaps for the shared core.
func BuildZoneHostInboundViews(cfg *config.Config) []ZoneHostInboundView {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	return buildZoneHostInboundViewsFromSnaps(cfg, buildInterfaceSnapshots(cfg), false)
}

// buildZoneHostInboundViewsFromSnaps is the shared zone-view core: one
// ZoneHostInboundView per configured security zone (#3070; #3405 default-deny
// parity — every zone enforces, see below), resolving each zone's
// firewall-local host addresses via the caller-supplied interface snapshot
// PLUS each zone's RETH VRRP virtual addresses (#3172, resolved from config
// so they scope the deny on the backup node too, where the VIP is not yet
// live on the kernel interface), and the deterministic stable RETH router
// link-local (#10303), with configured management/cluster-control lifeline
// interfaces excluded from the address set. excludeScopeLink drops
// kernel scope-link rows from the snapshot walk (pending-intent scoping,
// #10751 R4-1); installed views pass false so link-locals stay denied.
//
// Address completeness (#3224 — non-reproducing): the snapshot builder resolves
// each interface's addresses through buildLinkSnapshot -> AddrList(FAMILY_ALL),
// which enumerates EVERY kernel address with no scope/flag/dynamic filtering.
// So DHCP / DHCPv6-learned addresses are captured exactly like static ones —
// a DHCP-only interface with a live lease yields a NON-empty address set and IS
// scoped by the deny. (xpfd disables IPv6 RA on every managed interface in
// pkg/networkd, so DHCPv6 is the only IPv6 dynamic-address path and the same
// snapshot captures it; SLAAC is not a separate case.) A DHCP/DHCPv6 change
// classified for full recompile runs serialized applyConfig. This view and its
// nft deny are re-rendered for that invocation only if the apply reaches
// applyTailReconciles. A required protocol-gate error can return before that
// tail, so applyHostInboundFilter does not run and retry/re-render waits for a
// later applicable successful reconcile that reaches the tail. #5791 separately
// owns callbacks classified into the management-only branch. #3224 was filed on
// the premise that DHCP addresses fell out of scope (FAIL OPEN); that does not
// reproduce because the live snapshot has always carried them — see
// TestBuildZoneHostInboundViewsScopesKernelLearnedAddr, which exercises this
// real path with a config-absent kernel address.
//
// #3405: a zone that declared NO host-inbound-traffic stanza is NOT omitted —
// it is treated as an empty stanza and gets a catch-all DROP scoped to its
// firewall-local addresses (Junos default-deny: deny every host-bound
// service/protocol not explicitly permitted). A configured zone with no static
// or live address yet (e.g. a DHCP WAN before its first lease, or a backup before
// VIP install) has no unicast destination set to enforce. Its eligible ingress
// view still applies catalog-group multicast policy. Address appearance makes
// the local address available to a later snapshot; it does not itself prove
// re-render or nft publication. That transient local-address fail-open window is
// surfaced by AddresslessEnforcingZones (#3698) through a transition warning
// and xpf_host_inbound_addressless_zones gauge.
func buildZoneHostInboundViewsFromSnaps(cfg *config.Config, snaps []InterfaceSnapshot, excludeScopeLink bool) []ZoneHostInboundView {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	ifaceSnaps := snaps
	// Configured-provenance set for the scope-link intent filter below
	// (built once: the snapshot walk consults it per row).
	configuredAddrs := configuredHostInboundAddrKeys(cfg)
	// Lifeline interfaces (fxp0 plus explicitly configured chassis-cluster
	// control/fabric interfaces) are excluded from host-inbound deny scoping so
	// management / cluster-control traffic is never denied (#3277).
	lifelines := hostInboundLifelineSet(cfg)
	lifelineShared := hostInboundLifelineSharedAddrsFromSnaps(cfg, snaps)
	// #9637: netdevs that can never be an ingress scope.
	vrfEnslaved := config.HostInboundVRFEnslavedNetdevs(cfg)
	vrfMasters := hostInboundVRFMasterNetdevs(cfg, ifaceSnaps)
	if len(vrfMasters) > 0 {
		if vrfEnslaved == nil {
			vrfEnslaved = map[string]bool{}
		}
		for slave := range vrfMasters {
			vrfEnslaved[slave] = true
		}
	}
	// #3362: per-interface host-inbound override lookup (ref → override, with
	// physical→unit expansion). An interface that declares an override is
	// described ENTIRELY by it — the zone-level set is REPLACED, not unioned
	// (#6515); interfaces in the same zone
	// with the SAME effective set share one view (one nft address set), so a zone
	// with NO override produces exactly one view per zone (pre-#3362 shape).
	overrideByIface := buildInterfaceHostInboundMap(cfg)

	// Each emitted view is a group keyed by (zone, effective-token signature).
	// Addresses accumulate per group; groups are created for every eligible
	// interface even when it currently has no addresses, so ingress-scoped
	// multicast policy still applies during addressless startup.
	type group struct {
		zone   string
		svc    []string
		proto  []string
		v4, v6 []string
		seen4  map[string]bool
		seen6  map[string]bool
		ifaces map[string]bool
	}
	groups := make(map[string]*group)
	getGroup := func(zone string, svc, proto []string, iface string) *group {
		// #3721: group by a CANONICAL (sorted, deduped) token signature so two
		// interfaces whose EFFECTIVE admission sets are semantically identical but
		// authored in a different order ([ssh ping] vs [ping ssh]) fall into ONE
		// group — one nft rule block + one deny counter — instead of the
		// order-sensitive strings.Join keying two groups that inflate the nft
		// payload / `nft -f` replace time on a large trunk. The group keeps the
		// FIRST-seen authored svc/proto order for display fidelity; enforcement
		// keys on the address set plus the accept-token set, both
		// order-independent, so this is behavior-preserving (identical admission,
		// fewer duplicate blocks). Shares config.CanonicalHostInboundTokenSig with
		// the commit gate and the ambiguity reporter so all three agree on what
		// counts as "the same set".
		sig := zone + "\x00" + config.CanonicalHostInboundTokenSig(svc, proto)
		g := groups[sig]
		if g == nil {
			g = &group{
				zone: zone, svc: svc, proto: proto,
				seen4: map[string]bool{}, seen6: map[string]bool{},
				ifaces: map[string]bool{},
			}
			groups[sig] = g
		}
		if iface != "" {
			g.ifaces[iface] = true
		}
		return g
	}
	addAddr := func(g *group, host string) {
		if strings.Contains(host, ":") {
			if !g.seen6[host] {
				g.seen6[host] = true
				g.v6 = append(g.v6, host)
			}
		} else if !g.seen4[host] {
			g.seen4[host] = true
			g.v4 = append(g.v4, host)
		}
	}
	// configured reports whether a zone enforces host-inbound at all. #3405:
	// EVERY configured security zone enforces host-inbound (Junos/vSRX
	// default-deny parity) — a zone with interfaces but NO `host-inbound-traffic`
	// stanza is treated identically to an empty stanza (`host-inbound-traffic
	// { }`): it scopes a catch-all kernel DROP to its firewall-local addresses,
	// denying every host-bound service/protocol not explicitly permitted. Before
	// #3405 a no-stanza zone was skipped entirely (admit-all), a permit-all
	// management-plane exposure on any zone the operator never locked down. The
	// management / cluster-control lifeline interfaces (fxp0 plus explicitly
	// configured control/fabric links) are excluded from the address sets below,
	// and the established / ESP-AH / ND / PMTUD accepts precede every drop, so an
	// ESTABLISHED management session and HA control traffic survive. A NEW
	// management connection used not to be covered by that argument — a management
	// address shared onto a non-lifeline interface was in that zone's drop set,
	// and only a zone that ADMITS the service put an accept in front of it.
	// Since #7284 the exclusion is by address VALUE as well
	// as by interface: an address on a lifeline is withheld from any view that
	// would deny it with NO accept, so the no-stanza zone no longer strands it. A
	// zone that DOES admit the service keeps the address, because its accept
	// already protects management and its drop still expresses policy for every
	// other service. See docs/host-inbound-service-matrix.md, "Lifeline exclusion is by address VALUE, in the fence and the real table".
	// A zone-level stanza or any per-interface override (#3362) still further
	// scopes what the zone admits.
	configured := func(zone *config.ZoneConfig) bool {
		return zone != nil
	}

	// Seed a zone-default group (zone-level effective tokens, no override) for
	// every configured zone so each configured zone yields at least one view —
	// even when its only interface is a lifeline (no address contributed). Non-
	// overridden interfaces accumulate addresses into this same group. Fully
	// overridden or addressless zones retain empty address views; eligible
	// addressless ingress still receives catalog-group policy.
	zoneNamesSorted := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNamesSorted = append(zoneNamesSorted, name)
	}
	sort.Strings(zoneNamesSorted)
	quarantined := config.ZoneQuarantineExclusions(zoneNamesSorted)
	for _, name := range zoneNamesSorted {
		if _, drop := quarantined[name]; drop {
			continue
		}
		zone := cfg.Security.Zones[name]
		if !configured(zone) {
			continue
		}
		svc, proto := effectiveHostInboundTokens(zone, "", nil)
		getGroup(name, svc, proto, "")
	}

	// #11011: use the same StableZoneID exclusion set as snapshot quarantine.
	// The VIP and stable-RETH walks below read raw config identities rather than
	// the post-quarantine interface rows, so they must explicitly skip a zone
	// removed from the published snapshot.

	// #9637: which (zone, token signature) groups claim each netdev, for the
	// views' ingress scopes. A netdev is recorded here whether or not its
	// interface carries an address, so an address-less zone still judges what
	// arrives on it.
	netdevSigs := map[string]map[string]bool{}
	lifelineNetdevs := map[string]bool{}
	claimNetdev := func(netdev, sig string) {
		if netdev == "" {
			return
		}
		if netdevSigs[netdev] == nil {
			netdevSigs[netdev] = map[string]bool{}
		}
		netdevSigs[netdev][sig] = true
	}

	// Per-interface static/learned addresses from the resolved snapshots.
	for _, snap := range ifaceSnaps {
		if hostInboundLifelineInterface(snap.Name, lifelines) {
			lifelineNetdevs[snap.LinuxName] = true // #9637: never an ingress scope
			continue
		}
		if snap.Zone == "" {
			continue
		}
		if _, drop := quarantined[snap.Zone]; drop {
			continue
		}
		// #5699: a PHYSICAL (no-unit) snapshot whose unit 0 COLLAPSES onto the
		// SAME kernel netdev carries the identical live addresses as that unit-0
		// snapshot — buildLinkSnapshot(base-linux) and buildLinkSnapshot(unit0-
		// linux) enumerate the same kernel addresses. But the base ref keys them
		// under overrideByIface[base] (base-level override only), while unit 0
		// keys them under overrideByIface[base.0] (base ∪ unit-0 override, the
		// dataplane-additive #3720 resolution). When a per-interface override on
		// the unit-0 ref makes those two signatures differ, the SINGLE live
		// address is emitted into TWO views with conflicting admit sets — the
		// kernel host-inbound chain matches destination address only, so the
		// verdict is order-dependent (a deterministic false-deny). Unit 0's view
		// is the authoritative carrier (its merged override matches enforcement),
		// so skip the base's redundant contribution.
		//
		// Gate strictly on the ACTUAL same-netdev collapse, NOT merely
		// "unit 0 exists": a VLAN unit 0 (VlanID>0) or a tunnel-mapped unit 0
		// resolves to a DISTINCT netdev (snapshotLinuxName -> "<base>.<vlan>" /
		// the tunnel name), so base and unit-0 enumerate DISJOINT addresses.
		// Skipping the base there would DROP the base netdev's own live address
		// from every host-inbound view — no longer deny-scoped, the kernel input
		// chain falls through to `policy accept` (FAIL-OPEN). Compare the unit-0
		// resolved linux name to the base snapshot's linux name so the skip fires
		// only when they are literally the same kernel device.
		// #9821 #22: structural row identity — a dotted base name is a base
		// row, not a unit row, so the collapse-dedup applies to it.
		if !snap.IsUnit {
			if ifc := cfg.Interfaces.Interfaces[snap.Name]; ifc != nil {
				if u0 := ifc.Units[0]; u0 != nil &&
					snapshotLinuxName(cfg, snap.Name, ifc, u0) == snap.LinuxName {
					continue
				}
			}
		}
		zone := cfg.Security.Zones[snap.Zone]
		if !configured(zone) {
			continue
		}
		svc, proto := effectiveHostInboundTokens(zone, snap.Name, overrideByIface[snap.Name])
		// #9637: only a unit row's netdev is an ingress identity. A physical
		// row's netdev is either the trunk parent of VLAN units, whose frames
		// arrive on the subunit netdevs, or the netdev its unit 0 collapses onto,
		// which that unit claims. Claiming a trunk parent would have one zone
		// judge untagged frames no unit owns.
		// #9821 #22: structural — only unit rows claim netdevs, so a dotted
		// base row's netdev is claimed by its collapsing unit, not twice.
		if snap.IsUnit {
			claimNetdev(snap.LinuxName, snap.Zone+"\x00"+config.CanonicalHostInboundTokenSig(svc, proto))
		}
		g := getGroup(snap.Zone, svc, proto, snap.Name)
		for _, a := range snap.Addresses {
			if excludeScopeLink && hostInboundScopeLinkUnresolved(snap.Name, a, configuredAddrs) {
				continue
			}
			host := hostIPFromCIDR(a.Address)
			if host == "" {
				continue
			}
			addAddr(g, host)
		}
	}

	// VRRP RETH VIPs (#3172): the host-inbound destination address set must
	// also include each zone's RETH virtual IPs, not only the static interface
	// addresses resolved above. A VIP is present on the kernel interface ONLY of
	// the node that currently owns the redundancy group (master); on the backup
	// node the VIP is absent from buildLinkSnapshot's live address list, so
	// without this the kernel host-inbound deny would not be scoped to the VIP
	// and `chain input` would fall through to `policy accept` (FAIL-OPEN) for
	// VIP-destined host-bound traffic. The VIPs are identical on both nodes, so
	// resolving them from config (unit.VRRPGroups[*].VirtualAddresses) scopes the
	// deny consistently regardless of mastership. The seen maps dedup against the
	// live snapshot, so on the master node (where the VIP is already live) the
	// result is byte-identical. Lifeline interfaces (fxp0 plus explicitly
	// configured control/fabric links) are excluded, mirroring the static-address
	// path; standalone (no-VRRP) zones are untouched.
	// The VIP is added to its interface's EFFECTIVE-token group (#3362), so a VIP
	// on an overridden interface is scoped by that interface's override.
	zoneByIface := buildInterfaceZoneMap(cfg)
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for n := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, n)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		iface := cfg.Interfaces.Interfaces[ifName]
		if iface == nil {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for u := range iface.Units {
			unitNums = append(unitNums, u)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := iface.Units[un]
			if unit == nil || len(unit.VRRPGroups) == 0 {
				continue
			}
			unitName := fmt.Sprintf("%s.%d", ifName, un)
			if hostInboundLifelineInterface(unitName, lifelines) {
				continue
			}
			zoneName := zoneByIface[unitName]
			if zoneName == "" {
				continue
			}
			if _, drop := quarantined[zoneName]; drop {
				continue
			}
			zone := cfg.Security.Zones[zoneName]
			if !configured(zone) {
				continue
			}
			svc, proto := effectiveHostInboundTokens(zone, unitName, overrideByIface[unitName])
			vgKeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				vgKeys = append(vgKeys, k)
			}
			sort.Strings(vgKeys)
			for _, k := range vgKeys {
				vg := unit.VRRPGroups[k]
				if vg == nil {
					continue
				}
				for _, vip := range vg.VirtualAddresses {
					if host := hostIPFromCIDR(vip); host != "" {
						addAddr(getGroup(zoneName, svc, proto, unitName), host)
					}
				}
			}
		}
	}
	// Stable RETH router link-locals (#10303): unlike an ordinary interface
	// address, fe80::bf72:<cluster>:<rg> exists only while the RG is MASTER.
	// Its host-inbound destination scope must nevertheless be present on both
	// nodes and before the first successful commit, so derive it from the
	// deterministic RETH/cluster config rather than ifaceSnaps' live addresses.
	// The target walk mirrors addStableRethLinkLocal and adds the address to the
	// target unit's effective token group, just like the VIP walk above.
	for _, target := range stableRethLinkLocalTargets(cfg) {
		if hostInboundLifelineInterface(target.iface, lifelines) {
			continue
		}
		zoneName := zoneByIface[target.iface]
		if zoneName == "" {
			continue
		}
		if _, drop := quarantined[zoneName]; drop {
			continue
		}
		zone := cfg.Security.Zones[zoneName]
		if !configured(zone) {
			continue
		}
		svc, proto := effectiveHostInboundTokens(zone, target.iface, overrideByIface[target.iface])
		addAddr(getGroup(zoneName, svc, proto, target.iface), target.addr)
	}

	// Emit groups deterministically: the signature begins with the zone name,
	// so sorting by signature orders views by zone then by token set. Addresses
	// within a view are sorted for a reproducible nft payload.
	sigs := make([]string, 0, len(groups))
	for sig := range groups {
		sigs = append(sigs, sig)
	}
	ambiguousIngressNetdevs := hostInboundViewIngressDenyNetdevs(netdevSigs, lifelineNetdevs, vrfEnslaved, vrfMasters)
	screenProfilesByZone := make(map[string]ScreenProfileSnapshot)
	for _, screen := range buildScreenSnapshots(cfg) {
		screenProfilesByZone[screen.Zone] = screen
	}

	sort.Strings(sigs)
	out := make([]ZoneHostInboundView, 0, len(sigs))
	for _, sig := range sigs {
		g := groups[sig]
		ifaces := make([]string, 0, len(g.ifaces))
		for name := range g.ifaces {
			ifaces = append(ifaces, name)
		}
		sort.Strings(ifaces)
		// Addresses are kept in accumulation order (static interface addresses
		// first, then VRRP VIPs) — NOT sorted — to preserve the pre-#3362 nft
		// payload ordering. Order is deterministic: snapshots come from
		// sorted-name iteration and VIPs from sorted interface/unit/group walks.
		v4, v6 := g.v4, g.v6
		// #7284: a view with NO admit tokens emits a pure catch-all DROP for its
		// addresses — the #3405 default-deny. Withhold from it any address VALUE
		// that also lives on a lifeline interface.
		//
		// Scoped to the empty-admit case ON PURPOSE, and this is the whole
		// reason the subtraction is not simply the fence's. A view that DOES
		// admit something (the #6492 Finding A topology: the management address
		// shared onto a zone that permits ssh) emits `accept ssh` before the
		// catch-all drop, so management already survives there and the drop
		// still expresses a real policy for every OTHER service on that address.
		// Withholding the address from that view would delete the accept and the
		// deny together, leaving every host service reachable on it — a far
		// wider hole than the lockout being fixed.
		//
		// An empty-admit view has no such policy to preserve: its only possible
		// outcome for the address is a drop with no accept, which for a
		// management address is a lockout of NEW connections and, through the
		// shared #5566 set, a teardown of the ESTABLISHED one.
		if len(g.svc) == 0 && len(g.proto) == 0 {
			v4 = withoutLifelineShared(v4, lifelineShared)
			v6 = withoutLifelineShared(v6, lifelineShared)
		}
		view := ZoneHostInboundView{
			Zone:                 g.zone,
			Interfaces:           ifaces,
			SystemServices:       g.svc,
			Protocols:            g.proto,
			MulticastRules:       config.HostInboundMulticastRules(g.proto),
			V4Addrs:              v4,
			V6Addrs:              v6,
			IngressNetdevs:       hostInboundViewIngressNetdevsWithMasters(sig, netdevSigs, lifelineNetdevs, vrfEnslaved, vrfMasters),
			ICMPFloodThreshold:   screenProfilesByZone[g.zone].ICMPFloodThreshold,
			UDPFloodThreshold:    screenProfilesByZone[g.zone].UDPFloodThreshold,
			SYNFloodThreshold:    screenProfilesByZone[g.zone].SYNFloodThreshold,
			SYNFloodSrcThreshold: screenProfilesByZone[g.zone].SYNFloodSrcThreshold,
			AlarmWithoutDrop:     screenProfilesByZone[g.zone].AlarmWithoutDrop,
		}
		if len(out) == 0 {
			view.IngressDenyNetdevs = ambiguousIngressNetdevs
		}
		out = append(out, view)
	}
	return out
}

// hostInboundVRFMasterNetdevs maps every snapshot row claimed by a non-
// forwarding routing instance to the l3mdev master visible at LOCAL_IN
// (#6619, #9754, #10431). InterfaceSnapshot.RoutingInstance already carries
// the same bare-member fan-down used by the production VRF binder, including
// tagged children of a bare routing-instance member.
func hostInboundVRFMasterNetdevs(cfg *config.Config, snaps []InterfaceSnapshot) map[string]string {
	if cfg == nil || len(cfg.RoutingInstances) == 0 || len(snaps) == 0 {
		return nil
	}
	vrfs := map[string]bool{}
	for _, ri := range cfg.RoutingInstances {
		// Mirror the production binder (bindRoutingInstanceMembers): skip
		// forwarding instances and reserved names. Quarantined instances are
		// already removed from cfg.RoutingInstances by the compiler, so the
		// reserved check is belt-and-braces for hand-built configs.
		if ri != nil && ri.Name != "" && ri.InstanceType != "forwarding" && !config.IsReservedRoutingInstanceName(ri.Name) {
			vrfs[ri.Name] = true
		}
	}
	out := map[string]string{}
	for _, snap := range snaps {
		if snap.LinuxName == "" || !vrfs[snap.RoutingInstance] {
			continue
		}
		master := config.LinuxIfName("vrf-" + snap.RoutingInstance)
		if previous, exists := out[snap.LinuxName]; exists && previous != master {
			// A malformed or hand-built snapshot can still carry one collapsed
			// netdev under two VRF names. Strict config rejects that ownership
			// conflict and tolerant compilation removes both memberships before
			// snapshot build; retain this fail-closed guard for callers that
			// bypass that compiler boundary. The kernel device can be enslaved
			// to one master only, so either candidate is a guess. Scoping to one
			// risks judging the wrong VRF, and denying both candidates would drop
			// all host traffic on two VRFs for one ambiguous device.
			// The claims stage skips the empty target, so no ingress scope is
			// emitted for it.
			out[snap.LinuxName] = ""
			continue
		}
		if out[snap.LinuxName] == "" {
			out[snap.LinuxName] = master
		}
	}
	return out
}

// hostInboundIngressClaims rewrites raw interface claims to the netdev names
// visible at LOCAL_IN and groups signatures by that effective target. A target
// with multiple signatures is ambiguous and must not be assigned to a view.
func hostInboundIngressClaims(netdevSigs map[string]map[string]bool, lifelineNetdevs, vrfEnslaved map[string]bool, vrfMasters map[string]string) map[string]map[string]bool {
	// Lifelines are excluded by their effective LOCAL_IN identity. This keeps
	// the invariant here, where both normal and ambiguous-scope callers share
	// it, instead of relying on the builder to pre-mark every mapped master.
	effectiveLifelines := map[string]bool{}
	for netdev := range lifelineNetdevs {
		target := netdev
		if vrfEnslaved[netdev] {
			target = vrfMasters[netdev]
		}
		if target != "" {
			effectiveLifelines[target] = true
		}
	}

	out := map[string]map[string]bool{}
	for netdev, sigs := range netdevSigs {
		if effectiveLifelines[netdev] {
			continue
		}
		target := netdev
		if vrfEnslaved[netdev] {
			target = vrfMasters[netdev]
			if target == "" {
				continue
			}
		}
		if effectiveLifelines[target] {
			continue
		}
		if out[target] == nil {
			out[target] = map[string]bool{}
		}
		for sig := range sigs {
			out[target][sig] = true
		}
	}
	return out
}

// hostInboundViewIngressNetdevsWithMasters returns, sorted, the effective
// netdevs a view judges by ingress (#9637/#10431). A raw VRF slave becomes its
// VRF master; shared or otherwise ambiguous targets go to neither view.
func hostInboundViewIngressNetdevsWithMasters(sig string, netdevSigs map[string]map[string]bool, lifelineNetdevs, vrfEnslaved map[string]bool, vrfMasters map[string]string) []string {
	claims := hostInboundIngressClaims(netdevSigs, lifelineNetdevs, vrfEnslaved, vrfMasters)
	var out []string
	for netdev, sigs := range claims {
		if len(sigs) == 1 && sigs[sig] {
			out = append(out, netdev)
		}
	}
	sort.Strings(out)
	return out
}

// hostInboundViewIngressDenyNetdevs returns the effective netdevs whose claims
// remain ambiguous after VRF-master normalization. The renderer attaches this
// list to one view, applies destination-owner service rights, then emits a
// counted fail-closed drop for unmatched traffic.
func hostInboundViewIngressDenyNetdevs(netdevSigs map[string]map[string]bool, lifelineNetdevs, vrfEnslaved map[string]bool, vrfMasters map[string]string) []string {
	claims := hostInboundIngressClaims(netdevSigs, lifelineNetdevs, vrfEnslaved, vrfMasters)
	var out []string
	for netdev, sigs := range claims {
		if len(sigs) > 1 {
			out = append(out, netdev)
		}
	}
	sort.Strings(out)
	return out
}

// hostInboundViewIngressNetdevs preserves the narrow helper used by existing
// unit tests and callers that do not have VRF master mappings.
func hostInboundViewIngressNetdevs(sig string, netdevSigs map[string]map[string]bool, lifelineNetdevs, vrfEnslaved map[string]bool) []string {
	return hostInboundViewIngressNetdevsWithMasters(sig, netdevSigs, lifelineNetdevs, vrfEnslaved, nil)
}

// withoutLifelineShared returns addrs with every address that also lives on a
// lifeline interface removed, preserving order. Returns the input untouched
// when nothing is withheld so the common path allocates nothing.
func withoutLifelineShared(addrs []string, shared map[string]bool) []string {
	if len(addrs) == 0 || len(shared) == 0 {
		return addrs
	}
	drop := false
	for _, a := range addrs {
		if shared[a] {
			drop = true
			break
		}
	}
	if !drop {
		return addrs
	}
	kept := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if !shared[a] {
			kept = append(kept, a)
		}
	}
	return kept
}

// UnzonedHostInboundZoneLabel is the reserved sentinel label for host-inbound
// drops with no uniquely attributable source zone: addresses on interfaces
// assigned to NO zone (#4420 HI-2) and unmatched traffic on ambiguous ingress
// netdevs (#11331). It reuses the Junos self-traffic context token "junos-host",
// which can NEVER name an operator-defined zone, so its nft named-counter
// object cannot collide with a real per-zone counter. The #3361 scraper recovers
// the stable zone="junos-host" label; unzoned and ambiguous drops aggregate there.
const UnzonedHostInboundZoneLabel = "junos-host"

// BuildUnzonedHostInboundAddrs returns the firewall-local host addresses (bare
// IPs, prefix stripped, split by family) of interfaces that carry an address but
// are assigned to NO security zone (#4420 HI-2).
//
// xpfd applies an interface's configured / leased address regardless of zone
// membership (pkg/dataplane/compiler_iface.go builds the networkd managed set
// from cfg.Interfaces, not from zones), yet BuildZoneHostInboundViews scopes the
// kernel host-inbound default-deny ONLY to ZONED addresses. The kernel
// `xpf_hostinbound` chain runs with `policy accept`, so host-bound traffic to an
// addressed-but-unzoned interface falls through to accept — the host stack is
// exposed on it with no host-inbound admission. That is a fail-open, and a
// deviation from Junos, where an interface not in a security zone passes no
// flow / host-inbound traffic at all. This builder collects those addresses so
// the daemon can emit a catch-all DROP scoping them, restoring the Junos
// fail-closed posture and mirroring the #3405 per-zone default-deny.
//
// Scope / safety:
//   - Addressed interfaces outside all zones are fail-closed even when the
//     config has no security zones; this is the zone-less addressed-interface
//     fix for #11068. Unaddressed interfaces add no destination rule.
//   - Management / cluster-control LIFELINE INTERFACES (fxp0 and configured
//     control / fabric links) are excluded exactly as the zone path excludes
//     them, AND (#7284) so is any address VALUE that lives on a lifeline. Both
//     are needed. The interface check answers "is the snapshot I am walking a
//     lifeline"; the value check answers the question a destination-only drop
//     actually poses, since the rule carries no iifname (#3718).
//     Before the value check, a management address ALSO configured on an
//     unzoned interface was contributed by that interface's snapshot and landed
//     in this set with an EMPTY admit set, so the real table dropped NEW
//     management connections to it and the #5566 reconcile — fed from this same
//     set — flushed its ESTABLISHED entries. See
//     docs/host-inbound-service-matrix.md, "Lifeline exclusion is by address
//     VALUE, in the fence and the real table".
//   - Addresses already scoped by a zone view are subtracted, so a (mis)config
//     placing one firewall-local address on both a zoned and an unzoned
//     interface never yields a duplicate / conflicting rule for the same daddr.
//   - Unzoned interfaces are NOT AF_XDP-bound (only zoned dataplane interfaces
//     get the shim), so their host-bound traffic is delivered entirely through
//     the kernel; the kernel nft deny is the sole and sufficient enforcement
//     point and no userspace-dp (AF_XDP) change is required.
func buildUnzonedHostInboundAddrsFromSnaps(cfg *config.Config, snaps []InterfaceSnapshot) (v4, v6 []string) {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil, nil
	}
	lifelines := hostInboundLifelineSet(cfg)
	lifelineShared := hostInboundLifelineSharedAddrsFromSnaps(cfg, snaps)
	quarantined := quarantinedZoneNames(cfg)
	// Addresses already covered by a zone deny — exclude so the unzoned catch-all
	// never duplicates or conflicts with a zone rule for the same daddr.
	zoned := map[string]bool{}
	for _, view := range buildZoneHostInboundViewsFromSnaps(cfg, snaps, false) {
		for _, a := range view.V4Addrs {
			zoned[a] = true
		}
		for _, a := range view.V6Addrs {
			zoned[a] = true
		}
	}
	seen4 := map[string]bool{}
	seen6 := map[string]bool{}
	addUnzoned := func(host string) {
		if host == "" || zoned[host] || lifelineShared[host] {
			return
		}
		if strings.Contains(host, ":") {
			if !seen6[host] {
				seen6[host] = true
				v6 = append(v6, host)
			}
		} else if !seen4[host] {
			seen4[host] = true
			v4 = append(v4, host)
		}
	}
	for _, snap := range snaps {
		if hostInboundLifelineInterface(snap.Name, lifelines) {
			continue
		}
		if snap.Zone != "" {
			if _, drop := quarantined[snap.Zone]; !drop {
				continue
			}
		}
		for _, a := range snap.Addresses {
			addUnzoned(hostIPFromCIDR(a.Address))
		}
	}
	// Stable RETH link-locals are config-derived too. Ordinary unzoned targets
	// and targets whose zone was quarantined are not represented by the zone
	// views, so carry their deterministic IPv6 address into the unzoned
	// catch-all. Surviving zoned targets were already added above.
	zoneByIface := buildInterfaceZoneMap(cfg)
	for _, target := range stableRethLinkLocalTargets(cfg) {
		zoneName := zoneByIface[target.iface]
		if hostInboundLifelineInterface(target.iface, lifelines) {
			continue
		}
		if zoneName != "" {
			if _, drop := quarantined[zoneName]; !drop {
				continue
			}
		}
		addUnzoned(target.addr)
	}

	// A quarantined zone or contested membership is unzoned for host-inbound
	// purposes. InterfaceZoneMap omits those bindings, so it cannot identify
	// the source of a configured VIP; reconstruct only the relevant keys from
	// authored zone references and place their VIPs in the catch-all deny set.
	quarantinedMemberships := config.QuarantinedZoneInterfaceKeys(cfg)
	if len(quarantined) > 0 || len(quarantinedMemberships) > 0 {
		quarantinedVIPUnits := make(map[string]struct{})
		for zoneName, zone := range cfg.Security.Zones {
			if zone == nil {
				continue
			}
			_, zoneDropped := quarantined[zoneName]
			for _, rawRef := range zone.Interfaces {
				for _, key := range config.InterfaceUnitRefKeys(cfg, rawRef) {
					_, membershipDropped := quarantinedMemberships[key]
					if zoneDropped || membershipDropped {
						quarantinedVIPUnits[key] = struct{}{}
					}
				}
			}
		}
		ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
		for name := range cfg.Interfaces.Interfaces {
			ifNames = append(ifNames, name)
		}
		sort.Strings(ifNames)
		for _, ifName := range ifNames {
			iface := cfg.Interfaces.Interfaces[ifName]
			if iface == nil {
				continue
			}
			unitNums := make([]int, 0, len(iface.Units))
			for un := range iface.Units {
				unitNums = append(unitNums, un)
			}
			sort.Ints(unitNums)
			for _, un := range unitNums {
				unit := iface.Units[un]
				if unit == nil {
					continue
				}
				unitName := fmt.Sprintf("%s.%d", ifName, un)
				if hostInboundLifelineInterface(unitName, lifelines) {
					continue
				}
				if _, drop := quarantinedVIPUnits[unitName]; !drop {
					continue
				}
				for _, vg := range unit.VRRPGroups {
					if vg == nil {
						continue
					}
					for _, vip := range vg.VirtualAddresses {
						addUnzoned(hostIPFromCIDR(vip))
					}
				}
			}
		}
	}

	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

// BuildUnzonedHostInboundAddrs renders the unzoned catch-all from a FRESH
// kernel snapshot. It includes addressed configs with no security zones (#11068).
// See buildUnzonedHostInboundAddrsFromSnaps.
func BuildUnzonedHostInboundAddrs(cfg *config.Config) (v4, v6 []string) {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil, nil
	}
	return buildUnzonedHostInboundAddrsFromSnaps(cfg, buildInterfaceSnapshots(cfg))
}

// BuildUnzonedHostInboundAddrsFromSnapshots renders the unzoned catch-all
// from ONE caller-supplied snapshot (#10751 R4-2); the zone views it subtracts
// are rendered from the SAME snapshot so install inputs cannot skew mid-apply.
// Includes addressed configs with no security zones (#11068).
func BuildUnzonedHostInboundAddrsFromSnapshots(cfg *config.Config, snaps []InterfaceSnapshot) (v4, v6 []string) {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil, nil
	}
	return buildUnzonedHostInboundAddrsFromSnaps(cfg, snaps)
}

// BuildUnzonedDHCPUnleasedNetdevs returns sorted LOCAL_IN netdev names for
// unzoned, non-lifeline DHCP families without a resolved address, split by
// family (#10751 R7-B/F8-A). Such an interface has no destination for the
// unzoned catch-all, but its first lease is reachable before the debounced
// re-apply. The daemon renders a LAST-placed family-guarded `iifname <dev>
// meta nfproto <fam> meta pkttype host drop`; address rules and non-unicast
// fall-through remain authoritative. DHCPv4 reception uses AF_PACKET; the
// persistent DHCPv6 admit is separately restricted to server source port 547,
// client destination port 546, and link-local or All_DHCP_Relay_Agents_and_Servers
// destinations. Thus acquisition is not shadowed by the pending-family drop.
// VRF-enslaved unzoned units remain excluded: at LOCAL_IN iifname shows the
// shared master, so a catch-all there would shadow siblings and the slave-name
// rule would never match. They retain lease-callback convergence instead; any
// non-lifeline DHCP lease forces a full recompile that installs destination
// DROPs (dhcpLeaseChangeRequiresRecompile, pinned by
// TestDHCPLeaseChangeRequiresRecompile_VRFEnslavedNonLifeline10751). The
// accepted window is lease-install to debounced re-apply (~2s plus apply time),
// the same address-appearance-to-apply lag class as #3698. Lifelines are
// skipped (management must survive).
func BuildUnzonedDHCPUnleasedNetdevs(cfg *config.Config, snaps []InterfaceSnapshot) (v4, v6 []string) {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return nil, nil
	}
	lifelines := hostInboundLifelineSet(cfg)
	zoneByIface := buildInterfaceZoneMap(cfg)
	vrfEnslaved := config.HostInboundVRFEnslavedNetdevs(cfg)
	configuredAddrs := configuredHostInboundAddrKeys(cfg)
	// Per-unit resolved families, same lens as the per-interface intent
	// detector (unconfigured scope-link rows never resolve).
	hasFam := make(map[string]map[string]bool)
	for _, snap := range snaps {
		for _, a := range snap.Addresses {
			if hostInboundScopeLinkUnresolved(snap.Name, a, configuredAddrs) {
				continue
			}
			if hostIPFromCIDR(a.Address) == "" {
				continue
			}
			m := hasFam[snap.Name]
			if m == nil {
				m = map[string]bool{}
				hasFam[snap.Name] = m
			}
			m[a.Family] = true
		}
	}
	seenV4 := map[string]bool{}
	seenV6 := map[string]bool{}
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for n := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, n)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		iface := cfg.Interfaces.Interfaces[ifName]
		if iface == nil {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for un := range iface.Units {
			unitNums = append(unitNums, un)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := iface.Units[un]
			if unit == nil {
				continue
			}
			unitRef := fmt.Sprintf("%s.%d", ifName, un)
			if hostInboundLifelineInterface(unitRef, lifelines) {
				continue
			}
			if zoneByIface[unitRef] != "" {
				continue
			}
			fam := hasFam[unitRef]
			v4unleased := unit.DHCP && !fam["inet"]
			v6unleased := (unit.DHCPv6 || unit.DHCPv6Client != nil) && !fam["inet6"]
			if !v4unleased && !v6unleased {
				continue
			}
			linuxName := snapshotLinuxName(cfg, ifName, iface, unit)
			if linuxName == "" || vrfEnslaved[linuxName] {
				continue
			}
			if v4unleased && !seenV4[linuxName] {
				seenV4[linuxName] = true
				v4 = append(v4, linuxName)
			}
			if v6unleased && !seenV6[linuxName] {
				seenV6[linuxName] = true
				v6 = append(v6, linuxName)
			}
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

// HostInboundDHCPBackstops lists DHCP backstop netdevs by family and
// separately identifies the configured VRF-slave subset needing sdifname.
type HostInboundDHCPBackstops struct {
	V4          []string
	V6          []string
	VRFSlavesV4 []string
	VRFSlavesV6 []string
}

// BuildDHCPHostInboundBackstopNetdevs combines unzoned pending-lease backstops
// with persistent interface backstops for DHCP families in enforcing zones.
// The latter stay installed after an address appears until configuration
// removes DHCP intent or makes the effective zone policy full-admit; this
// closes the address-appearance-to-debounced-reapply window (#11577). VRF
// membership is derived from configured virtual-router ownership, not the
// current link state, so the sdifname guard is present before enslavement.
func BuildDHCPHostInboundBackstopNetdevs(cfg *config.Config, snaps []InterfaceSnapshot) HostInboundDHCPBackstops {
	if cfg == nil || len(cfg.Interfaces.Interfaces) == 0 {
		return HostInboundDHCPBackstops{}
	}
	backstops := HostInboundDHCPBackstops{}
	backstops.V4, backstops.V6 = BuildUnzonedDHCPUnleasedNetdevs(cfg, snaps)
	zoned := buildZonedDHCPHostInboundBackstopNetdevs(cfg)
	seenV4, seenV6 := make(map[string]bool, len(backstops.V4)+len(zoned.V4)), make(map[string]bool, len(backstops.V6)+len(zoned.V6))
	for _, dev := range backstops.V4 {
		seenV4[dev] = true
	}
	for _, dev := range backstops.V6 {
		seenV6[dev] = true
	}
	for _, dev := range zoned.V4 {
		if !seenV4[dev] {
			seenV4[dev] = true
			backstops.V4 = append(backstops.V4, dev)
		}
	}
	for _, dev := range zoned.V6 {
		if !seenV6[dev] {
			seenV6[dev] = true
			backstops.V6 = append(backstops.V6, dev)
		}
	}
	sort.Strings(backstops.V4)
	sort.Strings(backstops.V6)
	backstops.VRFSlavesV4 = zoned.VRFSlavesV4
	backstops.VRFSlavesV6 = zoned.VRFSlavesV6
	return backstops
}

func buildZonedDHCPHostInboundBackstopNetdevs(cfg *config.Config) HostInboundDHCPBackstops {
	backstops := HostInboundDHCPBackstops{}
	vrfEnslaved := config.HostInboundDHCPVRFEnslavedNetdevs(cfg)
	lifelines := hostInboundLifelineSet(cfg)
	zoneByIface := buildInterfaceZoneMap(cfg)
	overrides := buildInterfaceHostInboundMap(cfg)
	quarantined := quarantinedZoneNames(cfg)
	seenV4, seenV6, seenVRFV4, seenVRFV6 := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		iface := cfg.Interfaces.Interfaces[ifName]
		if iface == nil {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for number := range iface.Units {
			unitNums = append(unitNums, number)
		}
		sort.Ints(unitNums)
		for _, number := range unitNums {
			unit := iface.Units[number]
			if unit == nil {
				continue
			}
			unitRef := fmt.Sprintf("%s.%d", ifName, number)
			zoneName := zoneByIface[unitRef]
			zone := cfg.Security.Zones[zoneName]
			if zoneName == "" || zone == nil || hostInboundLifelineInterface(unitRef, lifelines) {
				continue
			}
			if _, excluded := quarantined[zoneName]; excluded {
				continue
			}
			services, _ := effectiveHostInboundTokens(zone, unitRef, overrides[unitRef])
			fullAdmit := false
			for _, service := range services {
				if config.HostInboundFullAdmitService(service) {
					fullAdmit = true
					break
				}
			}
			if fullAdmit {
				continue
			}
			linuxName := snapshotLinuxName(cfg, ifName, iface, unit)
			if linuxName == "" {
				continue
			}
			if unit.DHCP && !seenV4[linuxName] {
				seenV4[linuxName] = true
				backstops.V4 = append(backstops.V4, linuxName)
			}
			if (unit.DHCPv6 || unit.DHCPv6Client != nil) && !seenV6[linuxName] {
				seenV6[linuxName] = true
				backstops.V6 = append(backstops.V6, linuxName)
			}
			if !vrfEnslaved[linuxName] {
				continue
			}
			if unit.DHCP && !seenVRFV4[linuxName] {
				seenVRFV4[linuxName] = true
				backstops.VRFSlavesV4 = append(backstops.VRFSlavesV4, linuxName)
			}
			if (unit.DHCPv6 || unit.DHCPv6Client != nil) && !seenVRFV6[linuxName] {
				seenVRFV6[linuxName] = true
				backstops.VRFSlavesV6 = append(backstops.VRFSlavesV6, linuxName)
			}
		}
	}
	sort.Strings(backstops.V4)
	sort.Strings(backstops.V6)
	sort.Strings(backstops.VRFSlavesV4)
	sort.Strings(backstops.VRFSlavesV6)
	return backstops
}

// HostInboundLifelineIngressNetdevs returns the sorted linux netdev names
// of true lifelines whose ingress must keep management reachability to
// lifeline-shared values (#10751 M1/Opus9): fxp0 plus the linux names of every
// configured control/fabric unit recognized by HostInboundLifelineInterface.
// Bare em0/fab<N> names are not exempt unless the config assigns them a
// lifeline role (#11068). This MIRRORS the withhold-side interface definition:
// an interface whose addresses get withheld must have its ingress excepted in
// the gap, or the exception under-covers and strands management.
//
// Per-member discrimination (Opus9 round-9): the set carries NO vrf-mgmt
// blanket. The gap renders TWO exception rules per family — iifname for
// unenslaved lifelines plus meta sdifname for VRF-enslaved members (LOCAL_IN
// shows the master; sdif recovers the slave, kernel 5.17+) — so a non-lifeline
// member stays denied while an enslaved configured lifeline is admitted.
func HostInboundLifelineIngressNetdevs(cfg *config.Config) []string {
	set := map[string]bool{"fxp0": true}
	if cfg != nil {
		lifelines := hostInboundLifelineSet(cfg)
		for ifName, iface := range cfg.Interfaces.Interfaces {
			if iface == nil {
				continue
			}
			for un, unit := range iface.Units {
				if unit == nil {
					continue
				}
				if !hostInboundLifelineInterface(fmt.Sprintf("%s.%d", ifName, un), lifelines) {
					continue
				}
				if ln := snapshotLinuxName(cfg, ifName, iface, unit); ln != "" {
					set[ln] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// forEachFirewallLocalAddr visits every (interface ref, address) pair that makes
// an address firewall-local: the live/configured interface addresses from the
// canonical snapshot builder, configured VRRP virtual addresses, and the
// deterministic stable RETH link-locals used by HA.
//
// Extracted so the fence and the real table derive "which addresses live on a
// lifeline" from ONE walk (#7284). They previously did not, and that divergence
// IS this bug: the fence partitioned per ADDRESS VALUE while the real table
// tested only the interface whose snapshot it happened to be walking, so a
// management address shared onto a second interface was withheld from the fence
// and denied by the real table.
//
// Ordering is deterministic (interface names then unit numbers then VRRP group
// keys) because the fence's residual set is emitted in iteration order.
func forEachFirewallLocalAddrFromSnaps(cfg *config.Config, snaps []InterfaceSnapshot, visit func(ifName, cidr string)) {
	if cfg == nil {
		return
	}
	// Live + configured interface addresses, via the same snapshot builder that
	// populates the dataplane (so DHCP/DHCPv6-learned addresses are included
	// exactly like static ones — the #3224 argument).
	for _, snap := range snaps {
		for _, a := range snap.Addresses {
			visit(snap.Name, a.Address)
		}
	}
	// Configured VRRP virtual addresses. A VIP is live on the kernel interface
	// of the RG master only, so on the backup node the snapshot above misses it
	// (#3172). This walk is not restricted to ZONED units: a VIP on an unzoned
	// interface is still a firewall-local address.
	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for n := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, n)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		iface := cfg.Interfaces.Interfaces[ifName]
		if iface == nil {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for u := range iface.Units {
			unitNums = append(unitNums, u)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := iface.Units[un]
			if unit == nil || len(unit.VRRPGroups) == 0 {
				continue
			}
			unitName := fmt.Sprintf("%s.%d", ifName, un)
			vgKeys := make([]string, 0, len(unit.VRRPGroups))
			for k := range unit.VRRPGroups {
				vgKeys = append(vgKeys, k)
			}
			sort.Strings(vgKeys)
			for _, k := range vgKeys {
				vg := unit.VRRPGroups[k]
				if vg == nil {
					continue
				}
				for _, vip := range vg.VirtualAddresses {
					visit(unitName, vip)
				}
			}
		}
	}
	// The stable RETH address is installed only on the MASTER, but it remains
	// firewall-local for host-inbound scope on the BACKUP and before the first
	// commit. Include it in the same deterministic walk used by the cold-boot
	// fence, so zoned and zone-less configurations share one source of truth.
	for _, target := range stableRethLinkLocalTargets(cfg) {
		visit(target.iface, target.addr)
	}

}

// forEachFirewallLocalAddr visits every firewall-local (interface, address)
// pair from a FRESH kernel snapshot. See forEachFirewallLocalAddrFromSnaps.
func forEachFirewallLocalAddr(cfg *config.Config, visit func(ifName, cidr string)) {
	if cfg == nil {
		return
	}
	forEachFirewallLocalAddrFromSnaps(cfg, buildInterfaceSnapshots(cfg), visit)
}

// hostInboundLifelineSharedAddrs returns the bare host address VALUES that live
// on at least one lifeline interface (#7284).
//
// This is the address-VALUE half of the lifeline exclusion. The per-snapshot
// hostInboundLifelineInterface check answers "is the interface I am walking a
// lifeline"; this answers "is this address ALSO reachable as a management
// address", which is the question a destination-only drop rule actually poses.
// Host-inbound drops carry no iifname (#3718), so arriving on the lifeline does
// not exempt an address the real table denies by destination.
func hostInboundLifelineSharedAddrsFromSnaps(cfg *config.Config, snaps []InterfaceSnapshot) map[string]bool {
	lifelines := hostInboundLifelineSet(cfg)
	shared := map[string]bool{}
	forEachFirewallLocalAddrFromSnaps(cfg, snaps, func(ifName, cidr string) {
		if !hostInboundLifelineInterface(ifName, lifelines) {
			return
		}
		if host := hostIPFromCIDR(cidr); host != "" {
			shared[host] = true
		}
	})
	return shared
}

// hostInboundLifelineSharedAddrs returns lifeline address values from a FRESH
// kernel snapshot. See hostInboundLifelineSharedAddrsFromSnaps.
func hostInboundLifelineSharedAddrs(cfg *config.Config) map[string]bool {
	return hostInboundLifelineSharedAddrsFromSnaps(cfg, buildInterfaceSnapshots(cfg))
}

// FenceAddrSets is the FENCE-ONLY drop scope of the cold-boot fail-closed fence
// (#6492). It is deliberately NOT the real ruleset's scope: the fence is the
// real table with every per-service ACCEPT removed, so the two scopes have
// different safety obligations and BuildFenceAddrSets is the only place that
// difference is expressed.
//
// Finding A (lifeline lockout). The real table can safely deny a firewall-local
// address that is ALSO configured on a lifeline interface, because its
// per-service accepts (the mgmt zone's `host-inbound-traffic system-services
// ssh`) precede the catch-all DROP and still admit the management session. The
// fence has no such accepts, and its drop rule carries no `iifname` qualifier —
// it renders as a bare `ip daddr <addr> drop`. So an address shared between
// e.g. `fxp0.0` and a zoned data interface (a topology xpf explicitly accepts,
// pkg/config/dup_host_local_address_3718_test.go) would have every NEW
// management connection to it dropped for the whole fence window. WithheldV4 /
// WithheldV6 are exactly those shared addresses: they are removed from the
// fence's drop set and reported so the operator sees what the fence did not
// cover. The address stays denied by the REAL table's catch-all whenever the
// real table loads; only the fence stands down for it.
//
// Finding B (zone-less fail-open). BuildZoneHostInboundViews has no zones to
// render, while BuildUnzonedHostInboundAddrs carries every addressed
// non-lifeline interface into the real-table and fence catch-all (#11068).
// Host-inbound / lo0 filters are independently valid without zones
// (pkg/config/compiler_filter_ref_3296_test.go), so on a zone-less-but-addressed
// router a failed lo0 install still needs the fence's address-derived drops.
// The fence drop set is derived from firewall-local ADDRESSES (every
// non-lifeline interface address plus every configured VRRP virtual address),
// not from zone membership. There is no "are there zones?" branch: the
// address walk is the same in both cases and simply yields more than the zone
// views do when zones are absent or incomplete.
//
// Views keeps the per-zone shape (one drop rule per zone per family, and the
// zone counts the fence logs); UnzonedV4/UnzonedV6 carry every remaining
// firewall-local address the views do not already scope — the #4420 HI-2
// unzoned set plus the zone-less and VIP-on-unzoned-interface residue.
type FenceAddrSets struct {
	Views      []ZoneHostInboundView
	UnzonedV4  []string
	UnzonedV6  []string
	WithheldV4 []string
	WithheldV6 []string
	// UnleasedV4/V6 are LOCAL_IN netdevs protected by a family-guarded DHCP
	// backstop: unzoned units are included while that family has no address,
	// and enforcing-zone units remain included for as long as DHCP intent is
	// configured. DHCP-client admits are placed before destination rules and
	// interface DROPs after them.
	UnleasedV4 []string
	UnleasedV6 []string
	// UnleasedVRFSlavesV4/V6 are the configured VRF-slave subset, matched by
	// sdifname; config ownership keeps the guard present before enslavement.
	UnleasedVRFSlavesV4 []string
	UnleasedVRFSlavesV6 []string
	// Unzoned input scopes for catalog-group default-deny during cold boot.
	UnzonedIngressNetdevs   []string
	UnzonedIngressVRFSlaves []string
}

// BuildFenceAddrSets derives the cold-boot fence's drop scope from cfg and the
// zone views the real ruleset would use (#6492). See FenceAddrSets.
//
// The returned Views are COPIES: the caller's views still carry the shared
// lifeline addresses, because the REAL table must keep denying them.
func buildFenceAddrSetsFromSnaps(cfg *config.Config, snaps []InterfaceSnapshot, views []ZoneHostInboundView) FenceAddrSets {
	out := FenceAddrSets{Views: views}
	if cfg == nil {
		return out
	}
	out.UnzonedIngressNetdevs, out.UnzonedIngressVRFSlaves =
		BuildUnzonedHostInboundIngressNetdevsFromSnapshots(cfg, snaps, views)
	lifelines := hostInboundLifelineSet(cfg)
	onLifeline := map[string]bool{}
	local := map[string]bool{}
	note := func(ifName, cidr string) {
		host := hostIPFromCIDR(cidr)
		if host == "" {
			return
		}
		if hostInboundLifelineInterface(ifName, lifelines) {
			onLifeline[host] = true
			return
		}
		local[host] = true
	}
	forEachFirewallLocalAddrFromSnaps(cfg, snaps, note)

	// Finding A: withhold every address that ALSO lives on a lifeline
	// interface, both from the per-zone views and from the residual set.
	splitFams := func(addrs []string) (v4, v6 []string) {
		for _, a := range addrs {
			if strings.Contains(a, ":") {
				v6 = append(v6, a)
			} else {
				v4 = append(v4, a)
			}
		}
		return v4, v6
	}
	keep := func(addrs []string) []string {
		if len(addrs) == 0 {
			return addrs
		}
		kept := make([]string, 0, len(addrs))
		for _, a := range addrs {
			if !onLifeline[a] {
				kept = append(kept, a)
			}
		}
		return kept
	}
	covered := map[string]bool{}
	fenceViews := make([]ZoneHostInboundView, 0, len(views))
	for _, v := range views {
		fv := v
		fv.V4Addrs = keep(v.V4Addrs)
		fv.V6Addrs = keep(v.V6Addrs)
		for _, a := range fv.V4Addrs {
			covered[a] = true
		}
		for _, a := range fv.V6Addrs {
			covered[a] = true
		}
		fenceViews = append(fenceViews, fv)
	}
	out.Views = fenceViews

	// Finding B: everything firewall-local the zone views did not scope.
	rest := make([]string, 0, len(local))
	withheld := make([]string, 0, len(local))
	for a := range local {
		switch {
		case onLifeline[a]:
			withheld = append(withheld, a)
		case !covered[a]:
			rest = append(rest, a)
		}
	}
	sort.Strings(rest)
	sort.Strings(withheld)
	out.UnzonedV4, out.UnzonedV6 = splitFams(rest)
	out.WithheldV4, out.WithheldV6 = splitFams(withheld)
	backstops := BuildDHCPHostInboundBackstopNetdevs(cfg, snaps)
	out.UnleasedV4, out.UnleasedV6 = backstops.V4, backstops.V6
	out.UnleasedVRFSlavesV4, out.UnleasedVRFSlavesV6 = backstops.VRFSlavesV4, backstops.VRFSlavesV6
	return out
}

// BuildFenceAddrSets derives the cold-boot fence's drop scope from cfg, a
// FRESH kernel snapshot, and the zone views the real ruleset would use
// (#6492). See FenceAddrSets and buildFenceAddrSetsFromSnaps.
//
// The returned Views are COPIES: the caller's views still carry the shared
// lifeline addresses, because the REAL table must keep denying them.
func BuildFenceAddrSets(cfg *config.Config, views []ZoneHostInboundView) FenceAddrSets {
	return buildFenceAddrSetsFromSnaps(cfg, buildInterfaceSnapshots(cfg), views)
}

// BuildFenceAddrSetsFromSnapshots derives the fence's drop scope from ONE
// caller-supplied snapshot (#10751 R4-2); the caller renders views from the
// SAME snapshot so install inputs cannot skew mid-apply.
func BuildFenceAddrSetsFromSnapshots(cfg *config.Config, snaps []InterfaceSnapshot, views []ZoneHostInboundView) FenceAddrSets {
	return buildFenceAddrSetsFromSnaps(cfg, snaps, views)
}
