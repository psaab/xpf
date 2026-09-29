package userspace

import (
	"fmt"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// AddresslessEnforcingZone names a configured host-inbound-ENFORCING security
// zone that currently resolves NO firewall-local address across its non-lifeline
// interfaces (#3698). Such a zone contributes nothing to the kernel-nft
// host-inbound deny scoping (BuildZoneHostInboundViews yields an empty address
// set for it, and applyHostInboundFilter emits no deny), so host-bound packets
// to a freshly-usable address can reach the kernel input path without the zone's
// intended default-deny — a transient fail-open admit window. The window
// self-heals once an address is installed (DHCP lease / VRRP VIP / commit
// re-render), but is otherwise SILENT; this type carries the machine-readable
// signal the daemon logs and exports so the window is observable.
type AddresslessEnforcingZone struct {
	Zone string
	// Interfaces are the non-lifeline interface refs assigned to the zone
	// (exactly as authored under `security zones <z> interfaces <ref>`), sorted.
	// At least one is present — a zone whose only interfaces are lifelines
	// (fxp0 plus explicitly configured cluster-control/fabric links) is NOT
	// reported, since lifeline traffic is intentionally never host-inbound-denied.
	Interfaces []string
}

// addresslessEnforcingZonesFromSnapshots is the AddresslessEnforcingZones
// core over ONE caller-supplied snapshot. Scoping reads the zone views
// rendered from that snapshot with kernel scope-link rows EXCLUDED (#10751
// R4-1): a zone whose only addresses are self-assigned link-locals is still
// awaiting its intended (global/ULA/lease) addresses — WHEN it has DHCP
// intent to acquire more. A link-local-only zone with NO DHCP client is
// already fully enforced (the installed deny covers its only reachable
// addresses and no lease will ever arrive), so it is scoped, not reported
// (#10751 R5-A). Explicitly configured link-locals (static fe80::/64,
// stable RETH LL) still scope — only unconfigured kernel scope-link rows
// are excluded, and only for DHCP-intent zones.
func addresslessEnforcingZonesFromSnapshots(cfg *config.Config, snaps []InterfaceSnapshot) []AddresslessEnforcingZone {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	// A zone is "scoped" iff at least one of its scope-aware views carries
	// an address (non-link-local or configured link-local). A zone whose
	// only addresses are unconfigured kernel link-locals stays reported
	// ONLY when some non-lifeline unit in the zone runs a DHCP client
	// (lease intent outstanding — the DHCPv6 case); without DHCP intent
	// the installed link-local deny already covers everything reachable
	// and no lease will arrive, so reporting it would hold the early
	// barrier forever over an already-enforced scope. Truly addressless
	// zones (no address at all) stay reported regardless — conservative
	// pre-existing behavior for unaddressed interfaces.
	scoped := make(map[string]bool)
	for _, v := range buildZoneHostInboundViewsFromSnaps(cfg, snaps, true) {
		if len(v.V4Addrs) > 0 || len(v.V6Addrs) > 0 {
			scoped[v.Zone] = true
		}
	}
	scopedAny := make(map[string]bool)
	for _, v := range buildZoneHostInboundViewsFromSnaps(cfg, snaps, false) {
		if len(v.V4Addrs) > 0 || len(v.V6Addrs) > 0 {
			scopedAny[v.Zone] = true
		}
	}
	lifelines := hostInboundLifelineSet(cfg)
	zoneByIface := buildInterfaceZoneMap(cfg)
	dhcpIntent := make(map[string]bool)
	for ifName, iface := range cfg.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		for un, unit := range iface.Units {
			if unit == nil || (!unit.DHCP && !unit.DHCPv6 && unit.DHCPv6Client == nil) {
				continue
			}
			unitRef := fmt.Sprintf("%s.%d", ifName, un)
			if hostInboundLifelineInterface(unitRef, lifelines) {
				continue
			}
			if zone := zoneByIface[unitRef]; zone != "" {
				dhcpIntent[zone] = true
			}
		}
	}
	names := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		names = append(names, name)
	}
	sort.Strings(names)
	var out []AddresslessEnforcingZone
	for _, name := range names {
		if scoped[name] {
			continue
		}
		if scopedAny[name] && !dhcpIntent[name] {
			// Link-local-only with no DHCP intent: the installed deny
			// already covers its only reachable addresses.
			continue
		}
		zone := cfg.Security.Zones[name]
		if zone == nil {
			continue
		}
		ifaces := make([]string, 0, len(zone.Interfaces))
		seen := make(map[string]bool, len(zone.Interfaces))
		for _, ref := range zone.Interfaces {
			ref = strings.TrimSpace(ref)
			if ref == "" || seen[ref] || hostInboundLifelineInterface(ref, lifelines) {
				continue
			}
			seen[ref] = true
			ifaces = append(ifaces, ref)
		}
		if len(ifaces) == 0 {
			// Only lifeline (or no) interfaces — no fail-open window to report.
			continue
		}
		sort.Strings(ifaces)
		out = append(out, AddresslessEnforcingZone{Zone: name, Interfaces: ifaces})
	}
	return out
}

// AddresslessEnforcingZones returns, in sorted zone order, the configured
// host-inbound-enforcing zones currently in the transient fail-open admit window
// (#3698): a zone that has at least one non-lifeline interface assigned yet
// resolves NO firewall-local address (no static config address, no live kernel
// address, no VRRP VIP). The "is this zone scoped by any address" decision is
// read back from the zone-view builder itself — the same core that drives the
// nft emission — so this observability signal tracks what
// applyHostInboundFilter enforces. Kernel scope-link addresses (self-assigned
// IPv6 link-locals, IPv4 169.254 fallbacks) do NOT scope a DHCP-intent zone
// (#10751 R4-1): they are automatic at link-up, not the intended
// global/ULA/lease addresses, so a DHCP zone with only link-locals is still
// awaiting enforcement scope and stays reported (the daemon installs a deny
// for the link-locals AND retains the early barrier until a routable
// address resolves). A link-local-only zone with NO DHCP client is scoped,
// not reported: its installed link-local deny already covers everything
// reachable and no lease will arrive (#10751 R5-A).
//
// Excluded (NOT reported), so the signal stays low-noise and precise:
//   - zones that resolve any non-link-local address (static / DHCP-learned /
//     VRRP VIP / configured link-local) — scoped;
//   - link-local-only zones with no DHCP intent — installed LL deny covers
//     all reachable addresses, nothing further expected;
//   - zones whose only interfaces are lifelines (fxp0 plus explicitly configured
//     control/fabric links) — lifeline traffic is never denied, so there is no
//     fail-open to surface;
//   - zones with no interfaces assigned — nothing to protect.
func AddresslessEnforcingZones(cfg *config.Config) []AddresslessEnforcingZone {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	return addresslessEnforcingZonesFromSnapshots(cfg, buildInterfaceSnapshots(cfg))
}

// AddresslessDHCPPending is the only fail-open reason the per-interface reporter
// emits (#3710). Static and VRRP-VIP addresses are injected into the enforced
// deny set from config regardless of link/lease state (see
// BuildZoneHostInboundViews), so they never leave a per-interface fail-open
// window. The only per-interface/per-family transient gap that materializes is a
// DHCP / DHCPv6 client that has not yet acquired a lease in that family — the
// window the issue documents (DHCP WAN before its first lease; a dual-stack edge
// whose v6 lease lands after v4).
const AddresslessDHCPPending = "dhcp-pending"

// AddresslessEnforcingInterface names a single {zone, interface-unit, family}
// that is in the transient host-inbound fail-open admit window (#3710) at a finer
// granularity than AddresslessEnforcingZones (#3698). The zone-level signal marks
// a zone "scoped" (and stays silent) the moment ANY of its interfaces resolves an
// address in EITHER family, so a MIXED zone hides the gap: a DHCP-pending
// interface beside a statically-addressed sibling, or the IPv6 side of a
// dual-stack interface whose v6 lease has not landed while its v4 already has.
// Host-inbound ENFORCEMENT is per-destination-address and per-family (the kernel
// chain emits `<fam> daddr <set> ... drop` separately for inet and inet6), so
// those per-interface/per-family gaps are real fail-open windows the zone-level
// collapse cannot express. This type carries the refined signal.
type AddresslessEnforcingInterface struct {
	// Zone is the configured security zone the interface is assigned to.
	Zone string
	// Interface is the logical unit ref (e.g. "ge-0-0-1.0"), the granularity at
	// which host-inbound addresses, DHCP clients and VRRP VIPs are configured.
	Interface string
	// Family is the Junos family whose lease is pending: "inet" (IPv4) or
	// "inet6" (IPv6).
	Family string
	// Reason is why the family currently resolves no address. Always
	// AddresslessDHCPPending today (the only per-interface transient window this
	// builder can produce); carried as a field so alerts can group on it and so a
	// future reason (should one become observable) is additive.
	Reason string
}

// addresslessEnforcingInterfacesFromSnapshots is the
// AddresslessEnforcingInterfaces core over ONE caller-supplied snapshot. A
// DHCP/DHCPv6 family is resolved only by a NON-scope-link address (#10751
// R4-1): the kernel's automatic fe80::/64 never satisfies a DHCPv6 client's
// lease intent, and a 169.254 fallback never satisfies DHCP.
func addresslessEnforcingInterfacesFromSnapshots(cfg *config.Config, snaps []InterfaceSnapshot) []AddresslessEnforcingInterface {
	if cfg == nil || len(cfg.Security.Zones) == 0 || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	lifelines := hostInboundLifelineSet(cfg)
	zoneByIface := buildInterfaceZoneMap(cfg)

	// Per-unit resolved-family presence, from the SAME sources the views
	// core scopes the kernel deny with: the interface snapshots (static
	// config addresses merged with live kernel addresses) and the
	// configured VRRP VIPs — MINUS UNCONFIGURED kernel scope-link rows,
	// which never satisfy lease intent (#10751 R4-1). A scope-link row
	// whose address is explicitly configured still marks (the merge
	// prefers live rows, so a configured fe80::/64 already installed on
	// the kernel reads back as scope-link). A family present here is
	// already covered by the deny, so it is NOT a fail-open window.
	configuredAddrs := configuredHostInboundAddrKeys(cfg)
	hasFam := make(map[string]map[string]bool)
	mark := func(name, family string) {
		m := hasFam[name]
		if m == nil {
			m = make(map[string]bool, 2)
			hasFam[name] = m
		}
		m[family] = true
	}
	for _, snap := range snaps {
		for _, a := range snap.Addresses {
			if hostInboundScopeLinkUnresolved(snap.Name, a, configuredAddrs) {
				continue
			}
			if hostIPFromCIDR(a.Address) != "" {
				mark(snap.Name, a.Family)
			}
		}
	}
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
		for un, unit := range iface.Units {
			if unit == nil {
				continue
			}
			unitName := fmt.Sprintf("%s.%d", ifName, un)
			for _, vg := range unit.VRRPGroups {
				if vg == nil {
					continue
				}
				for _, vip := range vg.VirtualAddresses {
					host := hostIPFromCIDR(vip)
					if host == "" {
						continue
					}
					if strings.Contains(host, ":") {
						mark(unitName, "inet6")
					} else {
						mark(unitName, "inet")
					}
				}
			}
		}
	}

	var out []AddresslessEnforcingInterface
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
			zoneName := zoneByIface[unitName]
			if zoneName == "" {
				continue
			}
			if zone := cfg.Security.Zones[zoneName]; zone == nil {
				continue
			}
			// inet: a v4 DHCP client with no resolved v4 address yet.
			if unit.DHCP && !hasFam[unitName]["inet"] {
				out = append(out, AddresslessEnforcingInterface{
					Zone: zoneName, Interface: unitName,
					Family: "inet", Reason: AddresslessDHCPPending,
				})
			}
			// inet6: a v6 DHCP client with no resolved v6 address yet. xpfd
			// disables IPv6 RA on every managed interface, so DHCPv6 (stateful or
			// the dhcpv6-client stanza) is the only dynamic v6 path — SLAAC is not
			// a separate case (see BuildZoneHostInboundViews).
			if (unit.DHCPv6 || unit.DHCPv6Client != nil) && !hasFam[unitName]["inet6"] {
				out = append(out, AddresslessEnforcingInterface{
					Zone: zoneName, Interface: unitName,
					Family: "inet6", Reason: AddresslessDHCPPending,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Zone != out[j].Zone {
			return out[i].Zone < out[j].Zone
		}
		if out[i].Interface != out[j].Interface {
			return out[i].Interface < out[j].Interface
		}
		return out[i].Family < out[j].Family
	})
	return out
}

// AddresslessEnforcingInterfaces returns, in sorted (zone, interface, family)
// order, the per-interface/per-family host-inbound fail-open windows (#3710) that
// the zone-level AddresslessEnforcingZones (#3698) collapses away. An entry is
// reported for a non-lifeline logical unit assigned to a configured
// host-inbound-enforcing zone when, for a family, the unit has a DHCP / DHCPv6
// client configured (`family inet { dhcp; }` / `family inet6 { dhcpv6; }` /
// dhcpv6-client) but currently resolves NO address in that family across the same
// resolution the views core scopes the kernel deny with: static /
// live-kernel addresses (interface snapshots) plus configured VRRP VIPs —
// excluding kernel scope-link rows, which never satisfy lease intent (#10751
// R4-1: a DHCPv6 client beside only its automatic fe80::/64 is still pending).
//
// Only DHCP-pending is reported (see AddresslessDHCPPending): a static address or
// a VRRP VIP is scoped into the enforced deny from config regardless of link or
// lease state, so it never opens a per-interface window. Gating on a configured
// DHCP client (rather than "any family with no address") is what keeps the signal
// low-noise: an IPv4-only interface is NOT reported as addressless in inet6,
// because it never intends to acquire a v6 address, so there is no window to
// surface. The window self-heals the moment the lease lands (the resolved family
// set gains the address and the entry disappears), exactly like the zone-level
// signal.
//
// The zone-level xpf_host_inbound_addressless_zones remains a coarser
// compatibility aggregate; this per-interface signal is strictly more sensitive
// by design and is exported alongside it, not in place of it.
func AddresslessEnforcingInterfaces(cfg *config.Config) []AddresslessEnforcingInterface {
	if cfg == nil || len(cfg.Security.Zones) == 0 || len(cfg.Interfaces.Interfaces) == 0 {
		return nil
	}
	return addresslessEnforcingInterfacesFromSnapshots(cfg, buildInterfaceSnapshots(cfg))
}

// HostInboundPendingIntentFromSnapshots reports whether any configured
// enforcement scope is still unresolved in ONE caller-supplied snapshot
// (#10751 R4-2): the coarse zone-level window or the fine per-unit/family
// DHCP window. The daemon's handoff decision calls this over its handoff
// re-sample — the same sample its newcomer check compares — so the install
// inputs, the retention verdict, and the change check all derive from
// observed snapshots instead of re-sampling the kernel piecemeal.
func HostInboundPendingIntentFromSnapshots(cfg *config.Config, snaps []InterfaceSnapshot) bool {
	if len(addresslessEnforcingZonesFromSnapshots(cfg, snaps)) > 0 {
		return true
	}
	return len(addresslessEnforcingInterfacesFromSnapshots(cfg, snaps)) > 0
}

// AmbiguousHostInboundAddress names a firewall-local address that is
// host-inbound-reachable from more than one security zone / effective
// host-inbound token set with DIFFERING admission (#3718 Option B). The kernel
// host-inbound nftables chain matches on destination address ONLY (no
// ingress-interface predicate) over a single global input chain, so such an
// address's admission verdict is decided order-dependently by whichever zone
// sorts first — and the kernel path can disagree with the ingress-scoped
// userspace-dp host_inbound_admits path (split-brain). The commit-time gate
// (config.validateDuplicateHostLocalAddressStrict) hard-rejects this on the
// strict path, but a tolerant / peer-synced load (#1960) can slip one through;
// this type carries the machine-readable runtime signal the daemon logs and the
// API exports (xpf_host_inbound_ambiguous_addresses) so the ambiguity — which is
// NOT self-healing — is observable rather than silent.
type AmbiguousHostInboundAddress struct {
	// Address is the bare firewall-local host IP (no prefix).
	Address string
	// Family is the Junos family name: "inet" (IPv4) or "inet6" (IPv6).
	Family string
	// Zones are the distinct security zones that render a host-inbound rule
	// block for Address, sorted. At least two are present when the ambiguity is
	// cross-zone; a same-zone-only entry (differing #3362 per-interface
	// overrides on the same address) carries the single zone.
	Zones []string
}

// AmbiguousHostInboundAddresses returns, in sorted (family, address) order, the
// firewall-local addresses that are host-inbound-reachable from more than one
// DISTINCT effective host-inbound token set (#3718 Option B). The set of scopes
// per address is read back from BuildZoneHostInboundViews — the exact same
// builder that drives the kernel nft emission — so the observability signal can
// never disagree with what is actually rendered: an address is reported iff the
// builder produces two rule blocks for it whose EFFECTIVE admission differs
// (config.CanonicalHostInboundTokenSig, the shared SSOT the commit-time gate
// also uses).
//
// A duplicated address with IDENTICAL host-inbound service sets across its zones
// is NOT reported — it renders the same accept+drop block twice (order-
// independent, both paths agree), so it is a deliberate-duplicate false-positive
// the low-noise contract avoids. Management / cluster-control lifeline
// interfaces (fxp0 plus explicitly configured control/fabric links) contribute
// no address (they are excluded from deny scoping), so a shared management
// address never surfaces here either.
func AmbiguousHostInboundAddresses(cfg *config.Config) []AmbiguousHostInboundAddress {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	type acc struct {
		sigs  map[string]bool
		zones map[string]bool
	}
	byAddr := make(map[string]*acc)
	record := func(family, addr, sig, zone string) {
		key := family + "\x00" + addr
		a := byAddr[key]
		if a == nil {
			a = &acc{sigs: make(map[string]bool), zones: make(map[string]bool)}
			byAddr[key] = a
		}
		a.sigs[sig] = true
		a.zones[zone] = true
	}
	for _, v := range BuildZoneHostInboundViews(cfg) {
		sig := config.CanonicalHostInboundTokenSig(v.SystemServices, v.Protocols)
		for _, a := range v.V4Addrs {
			record("inet", a, sig, v.Zone)
		}
		for _, a := range v.V6Addrs {
			record("inet6", a, sig, v.Zone)
		}
	}
	keys := make([]string, 0, len(byAddr))
	for k := range byAddr {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []AmbiguousHostInboundAddress
	for _, k := range keys {
		a := byAddr[k]
		if len(a.sigs) < 2 {
			continue
		}
		parts := strings.SplitN(k, "\x00", 2)
		zones := make([]string, 0, len(a.zones))
		for z := range a.zones {
			zones = append(zones, z)
		}
		sort.Strings(zones)
		out = append(out, AmbiguousHostInboundAddress{
			Address: parts[1],
			Family:  parts[0],
			Zones:   zones,
		})
	}
	return out
}
