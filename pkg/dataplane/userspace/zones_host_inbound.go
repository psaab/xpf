package userspace

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
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
// One view is produced per host-inbound-CONFIGURED zone, carrying the zone's
// allowed Junos tokens plus its resolved firewall-local host addresses (bare
// IPs, prefix stripped), split by family. The daemon maps the tokens to nft
// matches and emits accept-the-listed / deny-the-rest rules scoped to those
// addresses.
type ZoneHostInboundView struct {
	Zone string
	// Interfaces lists the interface refs whose EFFECTIVE host-inbound token
	// set (the interface-level override when one is declared, else the
	// zone-level set — #6515 replace semantics, #3362) equals this view's
	// SystemServices/Protocols. A zone with no per-interface override yields a
	// single view per zone covering all its interfaces (pre-#3362 shape); a zone
	// with an override yields one view per distinct effective token set, each
	// scoped to that set's interface addresses. Sorted; informational/test only
	// (the nft emission keys on the address set, which is per-interface).
	Interfaces     []string
	SystemServices []string
	Protocols      []string
	V4Addrs        []string // bare host IPv4 addresses (no prefix)
	V6Addrs        []string // bare host IPv6 addresses (no prefix)
	// IngressNetdevs (#9637) are the kernel netdevs whose arriving host-bound
	// packets this view judges, whichever local address they name. They come
	// from the view's own interfaces, minus three kinds: a netdev another view
	// also claims, a lifeline's netdev, and a netdev enslaved to an l3mdev VRF.
	// See hostInboundViewIngressNetdevs. Empty means the view judges by
	// destination address only, as before #9637.
	IngressNetdevs []string
}

// BuildZoneHostInboundViews returns one ZoneHostInboundView per configured
// security zone (#3070; #3405 default-deny parity — every zone enforces, see
// below), resolving each zone's firewall-local
// host addresses via the canonical interface-snapshot builder (the same
// resolution that populates the dataplane) PLUS each zone's RETH VRRP virtual
// addresses (#3172, resolved from config so they scope the deny on the backup
// node too, where the VIP is not yet live on the kernel interface), with
// management/cluster-control lifeline interfaces (fxp0 / em0 / fab*) excluded
// from the address set.
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
// service/protocol not explicitly permitted). The only no-address case left is a
// configured zone whose interfaces have neither a static config address nor any
// live kernel address yet (e.g. a DHCP WAN before its first lease, or a backup
// node before VIP install): it yields an empty address set and the daemon emits
// no deny for it. Address appearance makes the address available to a later
// snapshot; it does not itself prove re-render or nft publication. That
// transient fail-open admit window is surfaced to operators by
// AddresslessEnforcingZones (#3698) — the daemon logs a state-transition warning
// and exports xpf_host_inbound_addressless_zones while the window is open, so it
// is no longer silent.
func BuildZoneHostInboundViews(cfg *config.Config) []ZoneHostInboundView {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	ifaceSnaps := buildInterfaceSnapshots(cfg)
	// Lifeline interfaces (fxp0 + the configured chassis-cluster
	// control-interface / fabric interfaces, plus the em0/fab* defaults) are
	// excluded from host-inbound deny scoping so management / cluster-control
	// traffic is never denied (#3277).
	lifelines := hostInboundLifelineSet(cfg)
	lifelineShared := hostInboundLifelineSharedAddrs(cfg)
	// #9637: netdevs that can never be an ingress scope.
	vrfEnslaved := config.HostInboundVRFEnslavedNetdevs(cfg)
	// #3362: per-interface host-inbound override lookup (ref → override, with
	// physical→unit expansion). An interface that declares an override is
	// described ENTIRELY by it — the zone-level set is REPLACED, not unioned
	// (#6515); interfaces in the same zone
	// with the SAME effective set share one view (one nft address set), so a zone
	// with NO override produces exactly one view per zone (pre-#3362 shape).
	overrideByIface := buildInterfaceHostInboundMap(cfg)

	// Each emitted view is a group keyed by (zone, effective-token signature).
	// Addresses accumulate per group; a group is created lazily on its first
	// address so a configured-but-address-less interface stays omitted. A later
	// snapshot can include an appeared address; this builder does not schedule or
	// publish the re-render.
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
	// management / cluster-control lifeline interfaces (fxp0/em0/fab*) are
	// excluded from the address sets below, and the established / ESP-AH / ND /
	// PMTUD accepts precede every drop, so an ESTABLISHED management session and HA
	// control traffic survive. A NEW management connection used not to be covered
	// by that argument — a management address shared onto a non-lifeline interface
	// was in that zone's drop set, and only a zone that ADMITS the service put an
	// accept in front of it. Since #7284 the exclusion is by address VALUE as well
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
	// even when its only interface is a lifeline (no address contributed) — the
	// pre-#3362 "one view per configured zone" contract. Non-overridden
	// interfaces accumulate their addresses into this same group (identical
	// signature); fully-overridden / address-less zones keep an empty view (the
	// daemon emits no deny for it).
	zoneNamesSorted := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNamesSorted = append(zoneNamesSorted, name)
	}
	sort.Strings(zoneNamesSorted)
	for _, name := range zoneNamesSorted {
		zone := cfg.Security.Zones[name]
		if !configured(zone) {
			continue
		}
		svc, proto := effectiveHostInboundTokens(zone, "", nil)
		getGroup(name, svc, proto, "")
	}

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
		if !strings.Contains(snap.Name, ".") {
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
		if strings.Contains(snap.Name, ".") {
			claimNetdev(snap.LinuxName, snap.Zone+"\x00"+config.CanonicalHostInboundTokenSig(svc, proto))
		}
		var g *group
		for _, a := range snap.Addresses {
			host := hostIPFromCIDR(a.Address)
			if host == "" {
				continue
			}
			if g == nil {
				g = getGroup(snap.Zone, svc, proto, snap.Name)
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
	// result is byte-identical. Lifeline interfaces (fxp0/em0/fab*) are excluded,
	// mirroring the static-address path; standalone (no-VRRP) zones are untouched.
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

	// Emit groups deterministically: the signature begins with the zone name,
	// so sorting by signature orders views by zone then by token set. Addresses
	// within a view are sorted for a reproducible nft payload.
	sigs := make([]string, 0, len(groups))
	for sig := range groups {
		sigs = append(sigs, sig)
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
		out = append(out, ZoneHostInboundView{
			Zone:           g.zone,
			Interfaces:     ifaces,
			SystemServices: g.svc,
			Protocols:      g.proto,
			V4Addrs:        v4,
			V6Addrs:        v6,
			IngressNetdevs: hostInboundViewIngressNetdevs(sig, netdevSigs, lifelineNetdevs, vrfEnslaved),
		})
	}
	return out
}

// hostInboundViewIngressNetdevs returns, sorted, the netdevs a view judges by
// ingress (#9637): the ones this view's group claims and no other group does.
// It leaves out:
//   - a netdev claimed by two groups, in one zone or in two. Whichever group's
//     rules came first would decide, which is the #3718 ambiguity in another
//     shape;
//   - a lifeline's netdev, so management and cluster control are never judged
//     by a data zone;
//   - a netdev enslaved to an l3mdev VRF (#6619). At LOCAL_IN, iifname names the
//     VRF master, so a rule naming the slave would match nothing.
//
// A packet that arrives on a left-out netdev is still judged by the
// destination-address rules, exactly as before #9637.
func hostInboundViewIngressNetdevs(sig string, netdevSigs map[string]map[string]bool, lifelineNetdevs, vrfEnslaved map[string]bool) []string {
	var out []string
	for netdev, sigs := range netdevSigs {
		if len(sigs) != 1 || !sigs[sig] || lifelineNetdevs[netdev] || vrfEnslaved[netdev] {
			continue
		}
		out = append(out, netdev)
	}
	sort.Strings(out)
	return out
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

// UnzonedHostInboundZoneLabel is the sentinel zone label under which the kernel
// host-inbound catch-all deny for firewall-local addresses on interfaces
// assigned to NO security zone is counted (#4420 HI-2). It reuses the reserved
// Junos self-traffic context token "junos-host": that token can NEVER name an
// operator-defined security zone (validateReservedZoneNamesStrict rejects it),
// so the nft named-counter object it yields (nftables.HostInboundDenyCounterName)
// can never collide with a real per-zone deny counter, and the #3361 scraper
// (ParseHostInboundDenyCounterName) recovers a stable, self-explanatory
// zone="junos-host" label for these "traffic to the host with no source zone"
// host-inbound drops.
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
//   - Only meaningful when the operator uses the zone model at all (>= 1 zone):
//     a zone-less bootstrap / degenerate config is left untouched (nil), so this
//     never turns a no-zones box into deny-all host-inbound.
//   - Management / cluster-control LIFELINE INTERFACES (fxp0 / em0 / fab*, plus
//     the configured control / fabric links) are excluded exactly as the zone
//     path excludes them, AND (#7284) so is any address VALUE that lives on a
//     lifeline. Both are needed. The interface check answers "is the snapshot I
//     am walking a lifeline"; the value check answers the question a
//     destination-only drop actually poses, since the rule carries no iifname
//     (#3718) and so cannot tell the lifeline ingress path from any other.
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
func BuildUnzonedHostInboundAddrs(cfg *config.Config) (v4, v6 []string) {
	if cfg == nil || len(cfg.Security.Zones) == 0 || len(cfg.Interfaces.Interfaces) == 0 {
		return nil, nil
	}
	lifelines := hostInboundLifelineSet(cfg)
	lifelineShared := hostInboundLifelineSharedAddrs(cfg)
	// Addresses already covered by a zone deny — exclude so the unzoned catch-all
	// never duplicates or conflicts with a zone rule for the same daddr.
	zoned := map[string]bool{}
	for _, view := range BuildZoneHostInboundViews(cfg) {
		for _, a := range view.V4Addrs {
			zoned[a] = true
		}
		for _, a := range view.V6Addrs {
			zoned[a] = true
		}
	}
	seen4 := map[string]bool{}
	seen6 := map[string]bool{}
	for _, snap := range buildInterfaceSnapshots(cfg) {
		if snap.Zone != "" || hostInboundLifelineInterface(snap.Name, lifelines) {
			continue
		}
		for _, a := range snap.Addresses {
			host := hostIPFromCIDR(a.Address)
			if host == "" || zoned[host] {
				continue
			}
			// #7284: withhold an address VALUE that also lives on a lifeline.
			// The snapshot check above is an INTERFACE exclusion; this is the
			// value one. The unzoned set is pure-deny by construction — no
			// service accept precedes an unzoned catch-all drop — so leaving a
			// management address here denies NEW management connections and,
			// because the same set feeds the #5566 reconcile, tears down the
			// ESTABLISHED one on the next apply.
			if lifelineShared[host] {
				continue
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
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

// forEachFirewallLocalAddr visits every (interface ref, address) pair that makes
// an address firewall-local: the live/configured interface addresses from the
// canonical snapshot builder, plus configured VRRP virtual addresses.
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
func forEachFirewallLocalAddr(cfg *config.Config, visit func(ifName, cidr string)) {
	if cfg == nil {
		return
	}
	// Live + configured interface addresses, via the same snapshot builder that
	// populates the dataplane (so DHCP/DHCPv6-learned addresses are included
	// exactly like static ones — the #3224 argument).
	for _, snap := range buildInterfaceSnapshots(cfg) {
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
func hostInboundLifelineSharedAddrs(cfg *config.Config) map[string]bool {
	lifelines := hostInboundLifelineSet(cfg)
	shared := map[string]bool{}
	forEachFirewallLocalAddr(cfg, func(ifName, cidr string) {
		if !hostInboundLifelineInterface(ifName, lifelines) {
			return
		}
		if host := hostIPFromCIDR(cidr); host != "" {
			shared[host] = true
		}
	})
	return shared
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
// Finding B (zone-less fail-open). BuildZoneHostInboundViews and
// BuildUnzonedHostInboundAddrs both return nothing when the config declares no
// security zone, because the real host-inbound default-deny is a zone-model
// construct. Host-inbound / lo0 filters are independently valid without zones
// (pkg/config/compiler_filter_ref_3296_test.go), so on a zone-less-but-addressed
// router a failed lo0 install produced a `policy accept` fence shell with ZERO
// drops — fail-OPEN, defeating the fence. The fence's drop set is therefore
// derived from the firewall-local ADDRESSES (every non-lifeline interface
// address plus every configured VRRP virtual address), not from zone
// membership. There is no "are there zones?" branch: the address walk is the
// same in both cases and simply yields more than the zone views do when zones
// are absent or incomplete.
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
}

// BuildFenceAddrSets derives the cold-boot fence's drop scope from cfg and the
// zone views the real ruleset would use (#6492). See FenceAddrSets.
//
// The returned Views are COPIES: the caller's views still carry the shared
// lifeline addresses, because the REAL table must keep denying them.
func BuildFenceAddrSets(cfg *config.Config, views []ZoneHostInboundView) FenceAddrSets {
	out := FenceAddrSets{Views: views}
	if cfg == nil {
		return out
	}
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
	forEachFirewallLocalAddr(cfg, note)

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
	return out
}
