package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// #9620 (H7): the #8662 normalizer rewrites a brace-elided routing instance
// into its braced shape, before group expansion and SchemaValidate. Before
// this, the compiler read the Keys run itself, after both, so a packed body was
// compiled from a node neither had seen (see normalizeElidedRoutingInstance9620).
// At 0e950bd5b the strict compile accepted all of these:
//
//	ri1 routing-options static route 10.9.0.0/16 next-hop 10.0.0.2;  0 static routes
//	ri1 protocols bgp group G peer-as 65001 neighbor 10.0.0.1;       BGP=nil
//	ri2 protocols ospf area 0.0.0.0 interface ge-0/0/1.0;            OSPF=nil, ge-0/0/1.0 bound as a VRF member
//	ri1 protocols bgp group G description foo;                       instance Description="foo"
//
// THE PROPERTY is the #8921 one: normalizing the elided spelling yields the
// same tree as normalizing the braced spelling. Identical trees compile and
// validate identically. So the tree cell is the claim, and the compile cell
// measures its consequence on the fields that were lost.
var elidedInstanceCells9620 = []struct {
	name, elided, braced string
}{
	{"routing-options static",
		`ri1 routing-options static route 10.9.0.0/16 next-hop 10.0.0.2;`,
		`ri1 { routing-options static route 10.9.0.0/16 next-hop 10.0.0.2; }`},
	{"protocols bgp",
		`ri1 instance-type virtual-router protocols bgp group G peer-as 65001 neighbor 10.0.0.1;`,
		`ri1 { instance-type virtual-router; protocols bgp group G peer-as 65001 neighbor 10.0.0.1; }`},
	{"protocols ospf interface",
		`ri2 instance-type virtual-router protocols ospf area 0.0.0.0 interface ge-0/0/1.0;`,
		`ri2 { instance-type virtual-router; protocols ospf area 0.0.0.0 interface ge-0/0/1.0; }`},
	{"protocols bgp description",
		`ri1 instance-type virtual-router protocols bgp group G description foo;`,
		`ri1 { instance-type virtual-router; protocols bgp group G description foo; }`},
	{"value spelled as a keyword",
		`ri1 description routing-options instance-type virtual-router interface ge-0/0/1.0;`,
		`ri1 { description routing-options; instance-type virtual-router; interface ge-0/0/1.0; }`},
	{"quoted vrf-target value spelled as a keyword",
		`ri1 vrf-target "routing-options" instance-type virtual-router;`,
		`ri1 { vrf-target "routing-options"; instance-type virtual-router; }`},
	{"interface run then a property then a body",
		`ri1 interface ge-0/0/1.0 ge-0/0/2.0 instance-type virtual-router routing-options static route 10.9.0.0/16 next-hop 10.0.0.2;`,
		`ri1 { interface ge-0/0/1.0 ge-0/0/2.0; instance-type virtual-router; routing-options static route 10.9.0.0/16 next-hop 10.0.0.2; }`},
	{"apply-groups after a value",
		`ri1 instance-type vrf apply-groups G;`,
		`ri1 { instance-type vrf; apply-groups G; }`},
	{"apply-groups-except before a body",
		`ri1 apply-groups-except G routing-options static route 10.9.0.0/16 next-hop 10.0.0.2;`,
		`ri1 { apply-groups-except G; routing-options static route 10.9.0.0/16 next-hop 10.0.0.2; }`},
	{"apply group named like a keyword",
		`ri1 apply-groups description instance-type vrf;`,
		`ri1 { apply-groups description; instance-type vrf; }`},
	{"bracketed interface list",
		`ri1 interface [ ge-0/0/1.0 ge-0/0/2.0 ] instance-type vrf;`,
		`ri1 { interface [ ge-0/0/1.0 ge-0/0/2.0 ]; instance-type vrf; }`},
	{"keyword last with a braced body",
		`ri1 routing-options { static { route 10.9.0.0/16 next-hop 10.0.0.2; } }`,
		`ri1 { routing-options { static { route 10.9.0.0/16 next-hop 10.0.0.2; } } }`},
	{"packed head with a braced body",
		`ri1 routing-options static { route 10.9.0.0/16 next-hop 10.0.0.2; }`,
		`ri1 { routing-options static { route 10.9.0.0/16 next-hop 10.0.0.2; } }`},
	{"undeclared token after a value extends its statement",
		`ri1 instance-type virtual-router bogus-kw foo;`,
		`ri1 { instance-type virtual-router bogus-kw foo; }`},
	{"undeclared keyword first takes the run",
		`ri1 bogus-kw foo instance-type vrf;`,
		`ri1 { bogus-kw foo instance-type vrf; }`},
	{"multi-token value",
		`ri1 instance-type vrf vrf-target export target:65000:1 route-distinguisher 65000:1;`,
		`ri1 { instance-type vrf; vrf-target export target:65000:1; route-distinguisher 65000:1; }`},
	{"quoted instance name",
		`"ri 1" instance-type virtual-router;`,
		`"ri 1" { instance-type virtual-router; }`},
	{"value keyword with a braced body",
		`ri1 instance-type virtual-router { interface ge-0/0/1.0; }`,
		`ri1 { instance-type virtual-router; interface ge-0/0/1.0; }`},
	{"flag keyword",
		`ri1 vrf-table-label instance-type vrf;`,
		`ri1 { vrf-table-label; instance-type vrf; }`},
}

func TestElidedRoutingInstanceNormalizesToTheBracedTree9620(t *testing.T) {
	for _, c := range elidedInstanceCells9620 {
		for _, wrap := range []struct{ name, pre, post string }{
			{"top level", `routing-instances { `, ` }`},
			{"inside groups", `groups { G { routing-instances { `, ` } } }`},
		} {
			t.Run(c.name+"/"+wrap.name, func(t *testing.T) {
				elided := parse8921(t, "elided", wrap.pre+c.elided+wrap.post)
				braced := parse8921(t, "braced", wrap.pre+c.braced+wrap.post)
				if elided == nil || braced == nil {
					return
				}
				normalizeCompactStanzas(elided)
				normalizeCompactStanzas(braced)
				if !sameTree8921(elided, braced) {
					t.Errorf("elided %q normalizes to a different tree than braced %q (#9620)\n elided:\n%s braced:\n%s",
						c.elided, c.braced, treeText8921(elided), treeText8921(braced))
				}
			})
		}
	}
}

// Quotes and brackets must not move a statement boundary. The text renderings
// (show configuration, HA sync, rollback files) drop leaf provenance, so a split
// that read it would bind `interface [ ge-0/0/0.0 protocols ]` into the VRF on
// this node and only `ge-0/0/0.0` on a peer that parsed the rendered text.
// Whether an authored value that spells a keyword should stay a value is #9635.
func TestElidedRoutingInstanceSplitIgnoresAuthoredProvenance9620(t *testing.T) {
	for _, c := range []struct{ authored, plain string }{
		{`ri1 instance-type vrf interface [ ge-0/0/0.0 protocols ];`, `ri1 instance-type vrf interface ge-0/0/0.0 protocols;`},
		{`ri1 instance-type vrf interface ge-0/0/0.0 "protocols";`, `ri1 instance-type vrf interface ge-0/0/0.0 protocols;`},
		{`ri1 interface [ description protocols ];`, `ri1 interface description protocols;`},
	} {
		a := parse8921(t, "authored", `routing-instances { `+c.authored+` }`)
		p := parse8921(t, "plain", `routing-instances { `+c.plain+` }`)
		if a == nil || p == nil {
			continue
		}
		normalizeCompactStanzas(a)
		normalizeCompactStanzas(p)
		if got, want := keysShape9620(a.Children), keysShape9620(p.Children); got != want {
			t.Errorf("quotes or brackets moved a statement boundary (#9620)\n authored %q ->\n%s plain %q ->\n%s",
				c.authored, got, c.plain, want)
		}
	}
}

// keysShape9620 renders the Keys structure only, without quote or bracket masks.
func keysShape9620(nodes []*Node) string {
	var b strings.Builder
	var walk func(ns []*Node, depth int)
	walk = func(ns []*Node, depth int) {
		for _, n := range ns {
			if n == nil {
				continue
			}
			fmt.Fprintf(&b, "%s%q\n", strings.Repeat("  ", depth), n.Keys)
			walk(n.Children, depth+1)
		}
	}
	walk(nodes, 0)
	return b.String()
}

// An apply statement under routing-instances is not an instance (#9657). The
// rewrite must leave it for group expansion.
func TestApplyStatementUnderRoutingInstancesIsNotRewritten9620(t *testing.T) {
	for _, text := range []string{
		`routing-instances { apply-groups G; }`,
		`routing-instances { apply-groups-except G; }`,
		`routing-instances { apply-macro M; }`,
	} {
		tree := parse8921(t, "apply", text)
		if tree == nil {
			continue
		}
		before := treeText8921(tree)
		normalizeCompactStanzas(tree)
		if after := treeText8921(tree); after != before {
			t.Errorf("%q was rewritten as a routing instance (#9620)\n before:\n%s after:\n%s", text, before, after)
		}
	}
}

// The compiled consequence, on the fields the witnesses lost. Each elided
// spelling is compiled beside its braced spelling, with an absolute check on
// both, so a change that broke them the same way cannot pass.
func TestElidedRoutingInstanceCompilesLikeBraced9620(t *testing.T) {
	staticRoute := func(ri *RoutingInstanceConfig) string {
		if len(ri.StaticRoutes) != 1 {
			return "want 1 static route, the VRF lost its route: got " + jsonString9620(ri.StaticRoutes)
		}
		return ""
	}
	checks := map[string]func(ri *RoutingInstanceConfig) string{
		"routing-options static": staticRoute,
		"protocols bgp": func(ri *RoutingInstanceConfig) string {
			if ri.InstanceType != "virtual-router" || ri.BGP == nil || len(ri.BGP.Neighbors) != 1 ||
				ri.BGP.Neighbors[0].Address != "10.0.0.1" || ri.BGP.Neighbors[0].PeerAS != 65001 {
				return "want virtual-router with BGP neighbor 10.0.0.1 peer-as 65001: got " + jsonString9620(ri)
			}
			return ""
		},
		"protocols ospf interface": func(ri *RoutingInstanceConfig) string {
			if len(ri.Interfaces) != 0 {
				return "want no instance interfaces: the OSPF area's interface was bound as a VRF " +
					"member, moving it out of the default table: got " + jsonString9620(ri.Interfaces)
			}
			if ri.OSPF == nil {
				return "want OSPF compiled, the adjacency is never configured: got nil"
			}
			return ""
		},
		"protocols bgp description": func(ri *RoutingInstanceConfig) string {
			if ri.Description != "" || ri.BGP == nil {
				return "want an empty instance description and BGP compiled; the BGP group's " +
					"description was read as the instance's: got " + jsonString9620(ri)
			}
			return ""
		},
		"value spelled as a keyword": func(ri *RoutingInstanceConfig) string {
			if ri.Description != "routing-options" || ri.InstanceType != "virtual-router" ||
				!reflect.DeepEqual(ri.Interfaces, []string{"ge-0/0/1.0"}) || len(ri.StaticRoutes) != 0 {
				return "want description routing-options, virtual-router, [ge-0/0/1.0], no routes: got " +
					jsonString9620(ri)
			}
			return ""
		},
		"interface run then a property then a body": func(ri *RoutingInstanceConfig) string {
			if ri.InstanceType != "virtual-router" || len(ri.StaticRoutes) != 1 ||
				!reflect.DeepEqual(ri.Interfaces, []string{"ge-0/0/1.0", "ge-0/0/2.0"}) {
				return "want virtual-router, [ge-0/0/1.0 ge-0/0/2.0], 1 static route: got " + jsonString9620(ri)
			}
			return ""
		},
	}
	for _, c := range elidedInstanceCells9620 {
		check := checks[c.name]
		if check == nil {
			continue
		}
		for _, lenient := range []bool{false, true} {
			mode := "strict"
			if lenient {
				mode = "lenient"
			}
			t.Run(c.name+"/"+mode, func(t *testing.T) {
				elided, okE := compileInstance9620(t, "elided", c.elided, lenient)
				braced, okB := compileInstance9620(t, "braced", c.braced, lenient)
				if okB {
					if msg := check(braced); msg != "" {
						t.Errorf("CONTROL braced %q: %s", c.braced, msg)
					}
				}
				if !okE {
					return
				}
				if msg := check(elided); msg != "" {
					t.Errorf("elided %q: %s (#9620)", c.elided, msg)
				}
				if okB && !reflect.DeepEqual(elided, braced) {
					t.Errorf("elided and braced spellings compile differently (#9620)\n elided %q -> %s\n braced %q -> %s",
						c.elided, jsonString9620(elided), c.braced, jsonString9620(braced))
				}
			})
		}
	}
}

func compileInstance9620(t *testing.T, label, instance string, lenient bool) (*RoutingInstanceConfig, bool) {
	t.Helper()
	text := `interfaces { ge-0/0/1 { unit 0 { family inet { address 10.1.0.1/24; } } } ` +
		`ge-0/0/2 { unit 0 { family inet { address 10.2.0.1/24; } } } } ` +
		`routing-instances { ` + instance + ` }`
	tr, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Errorf("%s %q: fixture must parse: %v", label, instance, perrs)
		return nil, false
	}
	compile := CompileConfig
	if lenient {
		compile = CompileConfigLenient
	}
	cfg, err := compile(tr)
	if err != nil {
		t.Errorf("%s %q: compile: %v", label, instance, err)
		return nil, false
	}
	if len(cfg.RoutingInstances) != 1 {
		t.Errorf("%s %q: %d routing instances compiled, want 1", label, instance, len(cfg.RoutingInstances))
		return nil, false
	}
	return cfg.RoutingInstances[0], true
}

// jsonString9620 renders a value for a failure message. JSON follows pointers,
// where %+v would print addresses that differ between two equal values.
func jsonString9620(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}
