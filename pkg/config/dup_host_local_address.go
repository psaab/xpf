package config

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// dup_host_local_address.go is the commit-time fail-closed gate for #3718
// (Option B): a firewall-local address (a configured interface address or a
// VRRP VIP) that is host-inbound-reachable from more than one security zone
// with DIFFERING host-inbound service/protocol sets.
//
// Why it matters: the kernel host-inbound nftables chain
// (pkg/daemon/daemon_nft.go emitHostInboundZone) matches on DESTINATION ADDRESS
// ONLY — it carries no ingress-interface / VRF / zone predicate, and there is a
// single global `inet xpf_hostinbound` input chain. So when two zones resolve
// the SAME local address they emit two rule blocks keyed on the same daddr, in
// zone-sort order, and the earlier-sorting zone decides the packet regardless
// of which zone / interface the traffic actually ingresses. A zero-service zone
// emits only a terminal catch-all drop for the address, so if it sorts first it
// drops every host-bound service the other zone opened (or the inverse admits
// what the owning zone denied). Worse, the userspace-dp secondary path
// (forwarding/host_inbound.rs host_inbound_admits) is ALREADY ingress-zone
// scoped, so the kernel daddr path and the userspace path can render OPPOSITE
// verdicts on the same packet — a genuine split-brain. Neither is gated by any
// existing strict validator (validateZoneInterfaceMembershipStrict enforces
// interface OWNERSHIP uniqueness, not ADDRESS uniqueness), so a strict-valid
// config reaches this ambiguity.
//
// This is Option B of the converged #3718 research plan: fail closed at commit
// on the ambiguous case and expose it at runtime (see
// dataplane/userspace.AmbiguousHostInboundAddresses + the
// xpf_host_inbound_ambiguous_addresses metric). Option A (an iifname / ingress
// predicate on the kernel chain — the semantically-correct Junos model, and
// what host_inbound_admits already does) and Option C (per-VRF host-inbound
// chains that would SUPPORT deliberate overlapping address space) are deferred
// follow-ons: Option A carries a management-lockout regression risk that needs
// the netdev-enumeration audit + loss-cluster lab validation, and Option C is a
// larger architectural fork. See docs/host-inbound-traffic.md.
//
// The gate keys on "same (family, host address) contributing to >1 DISTINCT
// effective host-inbound token set", NOT merely ">1 zone", so it does NOT
// false-positive on a deliberate duplicate:
//   - same address in two zones with IDENTICAL host-inbound service sets renders
//     the same accept+drop block twice — order-independent, both paths agree, so
//     it is allowed;
//   - same address in one zone dedups to a single block — allowed;
//   - differing verdicts arise from two zones with different host-inbound sets
//     OR one zone with per-interface #3362 overrides that differ, and only those
//     are rejected.
// It covers IPv4 (H01) + IPv6 (M02) static interface addresses AND VRRP VIPs
// (M03), and the cross-zone subset of same-address-across-routing-instances
// (M04) — a zone is not VRF-scoped in xpf, so overlapping-VRF address reuse
// surfaces as the cross-zone case here (intentional overlap needs Option C to
// be SUPPORTED; Option B rejects it fail-closed). Management / cluster-control
// lifeline interfaces (fxp0 / em0 / fab* / configured control+fabric) are
// excluded, mirroring the runtime deny-scoping, so a shared management address
// is never flagged.
//
// Strict on the commit / commit-check path (CompileConfig — hard-reject);
// downgraded to a cfg.Warnings entry on the tolerant load / peer-sync paths
// (CompileConfigLenient / CompileConfigForNodeLenient, flag
// lenientDuplicateHostLocalAddress) so an already-persisted or peer-synced
// config an older binary accepted still BOOTS (#1960 no-brick). On that tolerant
// path the ambiguity is NOT self-healing — the kernel emits an order-dependent
// rule — so AmbiguousHostInboundAddresses + the metric are the operator's
// runtime signal. Iteration is fully sorted so the first-reported error is
// deterministic across runs.

// CanonicalHostInboundTokenSig returns a canonical, order-independent signature
// of an EFFECTIVE host-inbound admission set (system-services ∪ protocols),
// lower-cased, trimmed, de-duplicated, and sorted within each list. It is the
// SSOT for comparing "do these two host-inbound scopes admit the same set" and
// is shared by the commit-time gate here and the runtime reporter
// (dataplane/userspace.AmbiguousHostInboundAddresses) so the two paths can never
// disagree on what counts as a DIFFERING service set. The two lists are joined
// with a separator that can never appear in a token, so an empty set (Junos
// default-deny) has a stable distinct signature.
func CanonicalHostInboundTokenSig(svc, proto []string) string {
	norm := func(in []string) string {
		seen := make(map[string]bool, len(in))
		out := make([]string, 0, len(in))
		for _, t := range in {
			t = strings.ToLower(strings.TrimSpace(t))
			if t == "" || seen[t] {
				continue
			}
			seen[t] = true
			out = append(out, t)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	return norm(svc) + "\x1f" + norm(proto)
}

// hostLocalAddrFamily normalizes a "ip/prefix" or bare-IP string to its bare
// host IP plus the Junos family name ("inet" / "inet6"). Returns "", "" if the
// value is unparseable.
func hostLocalAddrFamily(s string) (host, family string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	var ip net.IP
	if parsed, _, err := net.ParseCIDR(s); err == nil && parsed != nil {
		ip = parsed
	} else if parsed := net.ParseIP(s); parsed != nil {
		ip = parsed
	} else {
		return "", ""
	}
	if ip.To4() != nil {
		return ip.String(), "inet"
	}
	return ip.String(), "inet6"
}

// buildZoneInterfaceMapLocal builds the logical-interface-key -> zone lookup the
// same way pkg/dataplane/userspace.buildInterfaceZoneMap does (first-writer-wins
// over the SORTED zone names, base/unit expansion via zoneIfaceLogicalKeys).
// pkg/config cannot import pkg/dataplane, so it is rebuilt locally here; the
// key-expansion SSOT (zoneIfaceLogicalKeys) is shared, so the two stay aligned.
func buildZoneInterfaceMapLocal(cfg *Config) map[string]string {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	out := make(map[string]string)
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, zn := range zoneNames {
		zone := cfg.Security.Zones[zn]
		if zone == nil {
			continue
		}
		for _, iface := range zone.Interfaces {
			if iface == "" {
				continue
			}
			for _, key := range zoneIfaceLogicalKeys(cfg, iface) {
				if _, ok := out[key]; !ok {
					out[key] = zn
				}
			}
		}
	}
	return out
}

// mergeHostInboundOverrideLocal mirrors
// pkg/dataplane/userspace.mergeHostInboundTraffic: it returns a NEW
// *HostInboundTraffic whose token lists are the order-preserving UNION of a and
// b (a first, then b's not-already-present tokens). It backs the #3720 additive
// physical→unit override resolution so the commit-time gate classifies the same
// effective set the runtime does. Returns nil only when both inputs are nil.
func mergeHostInboundOverrideLocal(a, b *HostInboundTraffic) *HostInboundTraffic {
	if a == nil && b == nil {
		return nil
	}
	appendUnique := func(dst *[]string, src []string) {
		for _, t := range src {
			dup := false
			for _, e := range *dst {
				if e == t {
					dup = true
					break
				}
			}
			if !dup {
				*dst = append(*dst, t)
			}
		}
	}
	out := &HostInboundTraffic{}
	if a != nil {
		appendUnique(&out.SystemServices, a.SystemServices)
		appendUnique(&out.Protocols, a.Protocols)
	}
	if b != nil {
		appendUnique(&out.SystemServices, b.SystemServices)
		appendUnique(&out.Protocols, b.Protocols)
	}
	return out
}

// buildHostInboundOverrideMapLocal mirrors
// pkg/dataplane/userspace.buildInterfaceHostInboundMap: per-interface
// host-inbound overrides (#3362) keyed by the interface ref. A physical
// override is expanded onto each of its configured units (skipping a unit owned
// by a DIFFERENT zone — #3720 M01) and MERGED (unioned) with any unit-level
// override rather than the sorted-first physical ref shadowing the unit (the
// #3720 first-writer-wins bug) — both are interface-level statements, so they
// union with each other even though the result REPLACES the zone level (#6515). Rebuilt locally because pkg/config cannot import
// pkg/dataplane; the effective set it produces per unit therefore matches the
// runtime builder exactly, so the commit gate and the runtime reporter classify
// the same unit identically.
func buildHostInboundOverrideMapLocal(cfg *Config) map[string]*HostInboundTraffic {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	zoneByIface := buildZoneInterfaceMapLocal(cfg)
	out := make(map[string]*HostInboundTraffic)
	zoneNames := make([]string, 0, len(cfg.Security.Zones))
	for name := range cfg.Security.Zones {
		zoneNames = append(zoneNames, name)
	}
	sort.Strings(zoneNames)
	for _, zn := range zoneNames {
		zone := cfg.Security.Zones[zn]
		if zone == nil || len(zone.InterfaceHostInbound) == 0 {
			continue
		}
		refs := make([]string, 0, len(zone.InterfaceHostInbound))
		for ref := range zone.InterfaceHostInbound {
			refs = append(refs, ref)
		}
		sort.Strings(refs)
		for _, ref := range refs {
			hib := zone.InterfaceHostInbound[ref]
			if ref == "" || hib == nil {
				continue
			}
			// #9821: bare-vs-unit decided by the split (declared-first),
			// mirroring ResolveInterfaceHostInbound. Unit keys are the raw
			// spelling plus — multi-dot only — the canonical Literal the
			// gate probes: `p.0.01`-authored overrides must govern `p.0.1`
			// rows. Single-dot keeps raw-only (the pre-existing padded
			// gate miss is preserved exactly, not fixed as a drive-by).
			s := cfg.SplitInterfaceUnitRef(ref)
			if s.HasUnit {
				// Logical unit ref: most specific — merge onto any physical-
				// inherited set (both are INTERFACE-level statements and union
				// with each other, #3720).
				out[ref] = mergeHostInboundOverrideLocal(out[ref], hib)
				if s.Literal != ref && strings.Count(ref, ".") > 1 {
					out[s.Literal] = mergeHostInboundOverrideLocal(out[s.Literal], hib)
				}
				continue
			}
			if _, ok := out[ref]; !ok {
				out[ref] = hib
			}
			if ifCfg := cfg.Interfaces.Interfaces[s.Base]; ifCfg != nil {
				for unitNum := range ifCfg.Units {
					un := fmt.Sprintf("%s.%d", s.Base, unitNum)
					if z := zoneByIface[un]; z != "" && z != zn {
						continue // #3720 M01: do not leak cross-zone
					}
					out[un] = mergeHostInboundOverrideLocal(out[un], hib)
				}
			}
		}
	}
	return out
}

// effectiveHostInboundSigLocal returns the canonical signature of the EFFECTIVE
// host-inbound admission set for one interface unit: the per-interface override
// when the unit declares one, else the zone-level set (#3362; #6515 replace
// semantics). It mirrors pkg/dataplane/userspace.effectiveHostInboundTokens
// feeding CanonicalHostInboundTokenSig, so the commit gate and the runtime
// reporter classify the same unit identically — the whole point of this gate is
// that two zones claiming one firewall-local address with DIFFERING admission is
// rejected, and a signature computed from a different combination rule than
// enforcement uses would compare the wrong sets.
// #7490 added the unit ref. The zone-level `dhcp` / `bootp` authorization is
// withheld per INTERFACE, so a signature computed without knowing which unit it
// describes would compare a set enforcement does not use — and this gate's only
// job is to compare the sets enforcement uses. Concretely: two zones claiming
// one firewall-local address, identical but for one of them running a DHCP
// server, now have DIFFERING admission and must be rejected; without the ref
// their signatures would collide and the gate would pass.
func effectiveHostInboundSigLocal(zone *ZoneConfig, ref string, override *HostInboundTraffic) string {
	var zoneSvc, zoneProto []string
	if zone != nil && zone.HostInboundTraffic != nil {
		zoneSvc = zone.ZoneLevelSystemServicesFor(zone.HostInboundTraffic.SystemServices, ref)
		zoneProto = zone.HostInboundTraffic.Protocols
	}
	var ovSvc, ovProto []string
	if override != nil {
		ovSvc = override.SystemServices
		ovProto = override.Protocols
	}
	overridden := override != nil
	return CanonicalHostInboundTokenSig(
		EffectiveHostInboundTokens(zoneSvc, ovSvc, overridden),
		EffectiveHostInboundTokens(zoneProto, ovProto, overridden))
}

// validateDuplicateHostLocalAddressStrict implements the #3718 Option B
// commit-time gate documented at the top of this file. It returns the first
// (in sorted family+address order) firewall-local address that is
// host-inbound-reachable from more than one security zone / effective
// host-inbound token set with DIFFERING admission, naming the address and the
// contributing zones.
func validateDuplicateHostLocalAddressStrict(cfg *Config) error {
	if cfg == nil || len(cfg.Security.Zones) == 0 {
		return nil
	}
	lifelines := HostInboundLifelineSet(cfg)
	zoneByIface := buildZoneInterfaceMapLocal(cfg)
	overrideByIface := buildHostInboundOverrideMapLocal(cfg)

	// Per (family, host IP): the set of distinct effective token signatures and
	// the zones contributing them.
	type claim struct {
		sigs  map[string]bool
		zones map[string]bool
	}
	claims := make(map[string]*claim)
	record := func(family, host, zone, sig string) {
		key := family + "\x00" + host
		c := claims[key]
		if c == nil {
			c = &claim{sigs: make(map[string]bool), zones: make(map[string]bool)}
			claims[key] = c
		}
		c.sigs[sig] = true
		c.zones[zone] = true
	}

	ifNames := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		ifc := cfg.Interfaces.Interfaces[ifName]
		if ifc == nil {
			continue
		}
		unitNums := make([]int, 0, len(ifc.Units))
		for un := range ifc.Units {
			unitNums = append(unitNums, un)
		}
		sort.Ints(unitNums)
		for _, un := range unitNums {
			unit := ifc.Units[un]
			if unit == nil {
				continue
			}
			unitName := fmt.Sprintf("%s.%d", ifName, un)
			if HostInboundLifelineInterface(unitName, lifelines) {
				continue
			}
			zoneName := zoneByIface[unitName]
			if zoneName == "" {
				zoneName = zoneByIface[ifName]
			}
			if zoneName == "" {
				continue
			}
			zone := cfg.Security.Zones[zoneName]
			if zone == nil {
				continue
			}
			// #3720: overrideByIface already expands a physical override onto its
			// same-zone units and MERGES a unit-level override on top, so the
			// per-unit entry IS the authoritative effective override. No bare-
			// physical fallback: a nil entry means the physical override was
			// quarantined as cross-zone (M01), and pulling overrideByIface[ifName]
			// here would reintroduce that cross-zone leak.
			override := overrideByIface[unitName]
			sig := effectiveHostInboundSigLocal(zone, unitName, override)

			for _, a := range unit.Addresses {
				if host, family := hostLocalAddrFamily(a); host != "" {
					record(family, host, zoneName, sig)
				}
			}
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
					if host, family := hostLocalAddrFamily(vip); host != "" {
						record(family, host, zoneName, sig)
					}
				}
			}
		}
	}

	keys := make([]string, 0, len(claims))
	for k := range claims {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c := claims[k]
		if len(c.sigs) < 2 {
			continue
		}
		parts := strings.SplitN(k, "\x00", 2)
		family, host := parts[0], parts[1]
		famLabel := "IPv4"
		if family == "inet6" {
			famLabel = "IPv6"
		}
		zones := make([]string, 0, len(c.zones))
		for z := range c.zones {
			zones = append(zones, z)
		}
		sort.Strings(zones)
		return fmt.Errorf(
			"host-local %s address %s is host-inbound-reachable from multiple security zones (%s) with DIFFERING host-inbound service/protocol sets; the kernel host-inbound nftables chain matches destination address only (no ingress-interface predicate) and uses a single global input chain, so the host-inbound admission verdict for this address is decided order-dependently by whichever zone sorts first — a zone-isolation failure, and the kernel path can even disagree with the ingress-scoped userspace-dp path (split-brain). Give the address a single host-inbound policy: assign it to one zone, or make the host-inbound-traffic service/protocol sets identical across the zones that share it (#3718)",
			famLabel, host, strings.Join(zones, ", "))
	}
	return nil
}
