package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// resolve9063 builds a dual-tenant trunk — ge-0/0/0 unit 0 (untagged, IPv6) and
// unit 20 (VLAN 20, IPv6) — with routing-instance blue claiming `vrfMember`, and
// returns the interface the DEFAULT-table link-local static next-hop resolved
// to ("" = it did not resolve).
//
// One physical port and nothing else, deliberately: the resolver returns
// nothing when the link-local candidate is ambiguous, so a third IPv6 interface
// anywhere in the fixture makes every arm read "" for a reason that has nothing
// to do with the defect. My first version had exactly that and its positive
// control caught it.
func resolve9063(t *testing.T, vrfMember string) string {
	t.Helper()
	text := "interfaces {\n" +
		" ge-0/0/0 {\n" +
		"  unit 0 { family inet6 { address 2001:db8:aa::1/64; } }\n" +
		"  unit 20 { vlan-id 20; family inet6 { address 2001:db8:bb::1/64; } }\n" +
		" }\n}\n" +
		"routing-instances { blue { instance-type vrf; interface " + vrfMember + "; } }\n" +
		"routing-options { rib inet6.0 { static { route 2001:db8:ff::/64 next-hop fe80::9; } } }\n"
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, byNextHop := range inferIPv6StaticNextHopInterfaces(cfg, nil) {
		if iface, ok := byNextHop["fe80::9"]; ok {
			return iface
		}
	}
	return ""
}

// #9063: `logicalUnitDeviceKey` collapses a unit with no vlan-id and unit number
// 0 to the BARE base — correctly, because `ge-0-0-0` IS the kernel device name
// for that unit. But the consumers could then not tell `ge-0/0/0.0` from the
// whole-port `ge-0/0/0`, so a VRF holding ONE unit-0 member discarded every
// `ge-0-0-0.<vlan>` prefix from the default pool.
//
// For a GLOBAL-UNICAST next-hop that is harmless: the render emits a scopeless
// `ipv6 route <p> <gw>` and FRR resolves it recursively. For a LINK-LOCAL
// next-hop FRR rejects a scopeless route, so the static never installs and the
// prefix blackholes. A dual-tenant trunk — VRF on unit 0, a tagged unit on the
// same port in the default table — is the routine layout that reaches it.
func TestVRFUnit0DoesNotClaimTaggedSiblings9063(t *testing.T) {
	// THE DEFECT: the VRF holds unit 0 of the port. The tagged unit stays in the
	// default table and its prefix must remain available.
	if got := resolve9063(t, "ge-0/0/0.0"); got != "ge-0-0-0.20" {
		t.Errorf("VRF on ge-0/0/0.0 resolved %q, want ge-0-0-0.20. The unit-0 claim "+
			"discarded every ge-0-0-0.<vlan> prefix from the default pool, so the "+
			"link-local static renders scopeless, FRR rejects it, and the prefix "+
			"blackholes", got)
	}

	// NARROWNESS 1: a WHOLE-DEVICE claim must still take the whole port.
	// Without this, "stop the base match" is satisfied by deleting it — and a
	// VRF that claims `ge-0/0/0` really does own every unit on it.
	if got := resolve9063(t, "ge-0/0/0"); got != "" {
		t.Errorf("VRF claiming the whole device ge-0/0/0 left %q in the default "+
			"pool; a bare reference names the PORT and owns its sub-units", got)
	}

	// NARROWNESS 2 (the mirror): a TAGGED claim must not take unit 0 either.
	// This is the same collapse read the other way, and it is what makes the
	// two arms above a distinction rather than a coincidence.
	if got := resolve9063(t, "ge-0/0/0.20"); got != "ge-0-0-0" {
		t.Errorf("VRF on ge-0/0/0.20 resolved %q, want ge-0-0-0 — a tagged claim "+
			"must leave unit 0 in the default table", got)
	}
}

// resolveInVRF9063 puts the link-local static route INSIDE the routing
// instance, so the resolution runs against the VRF's own candidate pool.
func resolveInVRF9063(t *testing.T, vrfMember string) string {
	t.Helper()
	text := "interfaces {\n" +
		" ge-0/0/0 {\n" +
		"  unit 0 { family inet6 { address 2001:db8:aa::1/64; } }\n" +
		"  unit 20 { vlan-id 20; family inet6 { address 2001:db8:bb::1/64; } }\n" +
		" }\n}\n" +
		"routing-instances { blue { instance-type vrf; interface " + vrfMember + ";\n" +
		"  routing-options { rib blue.inet6.0 { static { route 2001:db8:ff::/64 next-hop fe80::9; } } }\n" +
		"} }\n"
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Keep the whole-device narrowness row non-vacuous: it must resolve against
	// the intended route compiled into blue's IPv6 table, not pass because the
	// compiler silently discarded the fixture route.
	foundRoute := false
	for _, ri := range cfg.RoutingInstances {
		if ri == nil || ri.Name != "blue" {
			continue
		}
		for _, route := range ri.Inet6StaticRoutes {
			if route == nil || route.Destination != "2001:db8:ff::/64" {
				continue
			}
			for _, nextHop := range route.NextHops {
				if nextHop.Address == "fe80::9" {
					foundRoute = true
					break
				}
			}
		}
	}
	if !foundRoute {
		t.Fatal("compiled VRF blue is missing IPv6 static route 2001:db8:ff::/64 via fe80::9")
	}
	// The resolver keys VRF entries as "vrf-<name>", not "<name>"; take any
	// non-default table rather than restating that spelling, so a rename of the
	// prefix does not silently turn this case into a no-op that passes.
	for vrf, byNextHop := range inferIPv6StaticNextHopInterfaces(cfg, nil) {
		if vrf == "" {
			continue
		}
		if iface, ok := byNextHop["fe80::9"]; ok {
			return iface
		}
	}
	return ""
}

// THE INCLUSION SIDE, which the exclusion cells above cannot see.
//
// `collectPrefixesForInterface` pulls prefixes INTO the VRF pool for the same
// collapsed key, so a unit-0 claim absorbed every `ge-0-0-0.<vlan>` prefix as
// well. That is invisible from the default-table cells — the tagged prefix is
// still in the default pool, so those keep passing — and a mutation reverting
// only this side survived them.
//
// Observed through a VRF-SCOPED route: with the tagged sibling wrongly in the
// pool there are two link-local candidates and the resolver returns nothing, so
// a VRF's own link-local static route stops resolving.
func TestVRFPoolDoesNotAbsorbTaggedSiblings9063(t *testing.T) {
	if got := resolveInVRF9063(t, "ge-0/0/0.0"); got != "ge-0-0-0" {
		t.Errorf("a VRF-scoped link-local next-hop resolved %q, want ge-0-0-0. The "+
			"unit-0 member pulled ge-0-0-0.20 into the VRF candidate pool, making "+
			"the link-local ambiguous — so the VRF's own static route no longer "+
			"resolves either", got)
	}

	// NARROWNESS: a WHOLE-DEVICE member SHOULD pull both units in, and then the
	// link-local really is ambiguous. Without this row, "stop pulling siblings"
	// is satisfied by never pulling them, which breaks the bare-reference
	// spelling.
	if got := resolveInVRF9063(t, "ge-0/0/0"); got != "" {
		t.Errorf("a whole-device member resolved %q; it owns BOTH units, so the "+
			"link-local is genuinely ambiguous and must not resolve", got)
	}
}

// The dual site: `collectPrefixesForInterface` pulls prefixes INTO the VRF pool
// for the same key. One root cause, two sites — and fixing only the exclusion
// side leaves the inclusion side over-pulling, which is invisible from the
// exclusion cell above.
func TestVRFUnit0DoesNotPullTaggedSiblingsIn9063(t *testing.T) {
	// A VRF claiming unit 0 must not absorb the tagged unit's prefix. If it
	// did, that prefix would be gone from the default pool and the arm below
	// would read "" — the same observable as the exclusion defect, which is
	// why the inclusion side needs naming rather than inferring.
	if got := resolve9063(t, "ge-0/0/0.0"); got == "" {
		t.Error("the tagged unit's prefix left the default pool on a unit-0 claim: " +
			"either the base-match exclusion fired, or collectPrefixesForInterface " +
			"pulled it into the VRF")
	}
}
