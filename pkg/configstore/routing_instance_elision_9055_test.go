package configstore

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// ri9055 wraps a routing-instance body, braced or elided, in a config the
// strict gate accepts.
func ri9055(t *testing.T, body string) *config.RoutingInstanceConfig {
	t.Helper()
	text := "interfaces { ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } } }\n" +
		"routing-instances { " + body + " }\n"
	cfg, err := CheckText(text, 0)
	if err != nil {
		t.Fatalf("strict commit-check REJECTED %q: %v", body, err)
	}
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ri1" {
			return ri
		}
	}
	t.Fatalf("no routing instance ri1 compiled from %q", body)
	return nil
}

// #9055: compileRoutingInstances hand-rolled a keyword switch that implemented
// THREE of the EIGHT keywords its own admission helper names. Both spellings
// commit clean, through configstore.CheckText — the commit gate, not
// CompileConfig — and the elided one silently loses the body.
//
// Driven through the STRICT pipeline deliberately: this is an
// operator-reachable divergence, and a cell on CompileConfig would measure the
// tolerant Load/SyncApply channel while reporting on `commit`.
func TestElidedRoutingInstanceKeepsRoutingOptions9055(t *testing.T) {
	const opts = "routing-options { static { route 10.9.0.0/16 next-hop 10.0.1.9; } }"

	braced := ri9055(t, "ri1 { instance-type vrf; "+opts+" }")
	// REFERENCE ARM: the braced spelling must actually carry the route, or the
	// equality below is between two empties.
	if len(braced.StaticRoutes) != 1 {
		t.Fatalf("the BRACED control compiled %d static routes, want 1",
			len(braced.StaticRoutes))
	}

	elided := ri9055(t, "ri1 "+opts)
	if len(elided.StaticRoutes) != len(braced.StaticRoutes) {
		t.Errorf("elided routing-options compiled %d static routes, braced %d — the "+
			"VRF's static route is silently gone on a commit that reported success",
			len(elided.StaticRoutes), len(braced.StaticRoutes))
	}
	if len(elided.StaticRoutes) == 1 && elided.StaticRoutes[0].Destination != braced.StaticRoutes[0].Destination {
		t.Errorf("elided route destination %q != braced %q",
			elided.StaticRoutes[0].Destination, braced.StaticRoutes[0].Destination)
	}
}

// The protocols row is NOT a plain drop — it is KEYWORD THEFT. The OSPF area's
// interface token fell through to the `interface` case and was bound as a VRF
// member, so one accepted statement produced two wrong outcomes: OSPF vanished
// AND an interface silently changed routing table.
func TestElidedRoutingInstanceDoesNotStealTheOSPFInterface9055(t *testing.T) {
	const proto = "protocols { ospf { area 0.0.0.0 { interface ge-0/0/1.0; } } }"
	// #11310: the RI must own ge-0/0/1.0 before OSPF can reference it.
	// Membership is declared on BOTH spellings. In the elided spelling the
	// member precedes the protocols container (a container keyword takes
	// the rest of the run; a member placed after the protocols body parses
	// as a separate instance refused by #9323, and a member fused inside
	// the run trips the #8437 sibling gate). The theft discriminator below
	// compares the member LISTS with duplicates included (never as sets:
	// {X,X} == {X} would be blind to the duplicate): a regressed elided
	// parse re-binding the OSPF token as a member duplicates the existing
	// member — and ri.Interfaces is a plain append with no dedup, so the
	// duplicate shows up as a list difference.
	braced := ri9055(t, "ri1 { instance-type vrf; interface ge-0/0/1.0; "+proto+" }")
	elided := ri9055(t, "ri1 instance-type vrf interface ge-0/0/1.0 "+proto)

	// THE THEFT. Asserted against the braced control rather than against a
	// hardcoded empty list, so it stays true if the braced spelling ever does
	// legitimately record an interface here.
	if !reflect.DeepEqual(elided.Interfaces, braced.Interfaces) {
		t.Errorf("elided protocols bound %v as VRF member interfaces, braced bound "+
			"%v. The OSPF area's interface token fell through to the `interface` "+
			"case: the interface silently changed routing table, which is an "+
			"isolation change and not only a routing one",
			elided.Interfaces, braced.Interfaces)
	}
	// And the protocol itself must survive. Compared to the braced control for
	// the same reason.
	if (elided.OSPF == nil) != (braced.OSPF == nil) {
		t.Errorf("elided OSPF present=%v, braced present=%v — the adjacency vanishes "+
			"on a commit that reports success", elided.OSPF != nil, braced.OSPF != nil)
	}
}

// PARITY (F1 hardening): the theft check above sees theft only as a DUPLICATE
// member, which a future ri.Interfaces de-duplication would hide. This cell
// does not depend on duplicates or on #11310 staying strict: both spellings
// of the no-member pair must reach the SAME verdict, and if both commit their
// instances must be DeepEqual (the 9620 agree-harness shape). Under theft the
// refused — RED either way. Under a drop regression the verdict arm
// fires first today; the instances-differ arm trips only if #11310
// ever stops rejecting the braced no-member spelling.
func TestElidedRoutingInstanceNoMemberParity9055(t *testing.T) {
	const proto = "protocols { ospf { area 0.0.0.0 { interface ge-0/0/1.0; } } }"
	iface := "interfaces { ge-0/0/1 { unit 0 { family inet { address 10.0.1.1/24; } } } }\n"
	ec, eerr := CheckText(iface+"routing-instances { ri1 instance-type vrf "+proto+" }\n", 0)
	bc, berr := CheckText(iface+"routing-instances { ri1 { instance-type vrf; "+proto+" } }\n", 0)
	if (eerr == nil) != (berr == nil) {
		t.Errorf("no-member pair reaches different verdicts: elided err=%v, braced err=%v", eerr, berr)
	} else if eerr == nil && !reflect.DeepEqual(ec.RoutingInstances, bc.RoutingInstances) {
		t.Errorf("no-member pair commits different instances:\n elided %s\n braced %s",
			json9620(ec.RoutingInstances), json9620(bc.RoutingInstances))
	}
}

// NARROWNESS: the three keywords that already worked must be unchanged, and an
// instance with NO body must still compile to nothing extra. Without these, a
// fix that re-dispatched everything into the property loop would satisfy the
// rows above while breaking the spellings that were correct.
func TestElidedRoutingInstanceValueKeywordsUnchanged9055(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"instance-type", "ri1 instance-type vrf"},
		{"description", `ri1 description "the vrf"`},
		{"interface", "ri1 interface ge-0/0/1.0"},
		{"instance-type then interface", "ri1 instance-type vrf interface ge-0/0/1.0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			elided := ri9055(t, tc.body)
			braced := ri9055(t, "ri1 { "+bodyToBraced9055(tc.body)+" }")
			if elided.InstanceType != braced.InstanceType {
				t.Errorf("instance-type: elided %q braced %q", elided.InstanceType, braced.InstanceType)
			}
			if elided.Description != braced.Description {
				t.Errorf("description: elided %q braced %q", elided.Description, braced.Description)
			}
			if len(elided.Interfaces) != len(braced.Interfaces) {
				t.Errorf("interfaces: elided %v braced %v", elided.Interfaces, braced.Interfaces)
			}
		})
	}
}

// bodyToBraced9055 turns "ri1 instance-type vrf interface x" into
// "instance-type vrf; interface x;" — the braced spelling of the same body.
func bodyToBraced9055(elided string) string {
	rest := elided[len("ri1 "):]
	out := ""
	toks := splitTokens9055(rest)
	for i := 0; i < len(toks); {
		kw := toks[i]
		i++
		var vals []string
		for i < len(toks) && !isRIKeyword9055(toks[i]) {
			vals = append(vals, toks[i])
			i++
		}
		out += kw
		for _, v := range vals {
			out += " " + v
		}
		out += "; "
	}
	return out
}

func isRIKeyword9055(t string) bool {
	switch t {
	case "instance-type", "description", "interface", "routing-options",
		"protocols", "vrf-target", "vrf-table-label", "route-distinguisher":
		return true
	}
	return false
}

func splitTokens9055(s string) []string {
	var out []string
	cur := ""
	inQ := false
	for _, r := range s {
		switch {
		case r == '"':
			inQ = !inQ
			cur += string(r)
		case r == ' ' && !inQ:
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
		default:
			cur += string(r)
		}
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
