package configstore

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9620: an elided routing instance must meet the SAME commit gate as the braced
// spelling. Before the rewrite moved into the normalizer, the compiler read the
// elided body after SchemaValidate and after group expansion, so the gate never
// saw it. Measured through CheckText at 0e950bd5b; rows marked (master) were
// live in the shape #9055's compiler-side re-dispatch handled:
//
//	hold-time 1 under an elided protocols body     accepted, HoldTime=1 (master)    braced: refused
//	apply-groups under an elided routing-options   route with no next-hop (master)  braced: next-hop inherited
//	vrf-target export target:65000:1               committed                        braced: committed
//
// Every cell requires the two spellings to AGREE: both refused, or both
// committed with identical routing instances. Cells with an absolute
// expectation also check it, so a change that broke both spellings the same way
// cannot pass. The agree-only cell pins parity for a spelling whose verdict
// belongs to #9736, not here.
func TestElidedRoutingInstanceMeetsTheBracedCommitGate9620(t *testing.T) {
	grp := `groups { G { routing-instances { ri1 { routing-options { static { route 10.9.0.0/16 { next-hop 10.0.0.2; } } } } } } } `
	as := `routing-options { autonomous-system 65000; } `
	cells := []struct {
		name, prefix, elided, braced string
		refusal                      string // a substring the refusal must name; "" means both must commit
		agree                        bool   // only require the two spellings to reach the same verdict
		check                        func(cfg *config.Config) string
	}{
		{
			name:    "hold-time packed past the keyword",
			prefix:  as,
			elided:  `ri1 instance-type virtual-router protocols bgp group G { peer-as 65001; hold-time 1; neighbor 10.0.0.1; }`,
			braced:  `ri1 { instance-type virtual-router; protocols bgp group G { peer-as 65001; hold-time 1; neighbor 10.0.0.1; } }`,
			refusal: "hold-time",
		},
		{
			name:    "hold-time in the last-position shape",
			prefix:  as,
			elided:  `ri1 protocols { bgp { group G { peer-as 65001; hold-time 1; neighbor 10.0.0.1; } } }`,
			braced:  `ri1 { protocols { bgp { group G { peer-as 65001; hold-time 1; neighbor 10.0.0.1; } } } }`,
			refusal: "hold-time",
		},
		{
			name:   "apply-groups under a body packed past the keyword",
			prefix: grp,
			elided: `ri1 routing-options static route 10.9.0.0/16 { apply-groups G; }`,
			braced: `ri1 { routing-options static route 10.9.0.0/16 { apply-groups G; } }`,
			check:  nextHopInherited9620,
		},
		{
			name:   "apply-groups in the last-position shape",
			prefix: grp,
			elided: `ri1 routing-options { static { route 10.9.0.0/16 { apply-groups G; } } }`,
			braced: `ri1 { routing-options { static { route 10.9.0.0/16 { apply-groups G; } } } }`,
			check:  nextHopInherited9620,
		},
		{
			name:    "undeclared keyword first",
			elided:  `ri1 bogus-kw foo instance-type virtual-router;`,
			braced:  `ri1 { bogus-kw foo instance-type virtual-router; }`,
			refusal: "bogus-kw",
		},
		{
			name:   "undeclared token after a value, same line",
			elided: `ri1 instance-type virtual-router firewall family inet filter f1 term t then discard;`,
			braced: `ri1 { instance-type virtual-router firewall family inet filter f1 term t then discard; }`,
			agree:  true,
		},
		{
			name:   "multi-token vrf-target",
			elided: `ri1 instance-type vrf route-distinguisher 65000:1 vrf-target export target:65000:1;`,
			braced: `ri1 { instance-type vrf; route-distinguisher 65000:1; vrf-target export target:65000:1; }`,
			check: func(cfg *config.Config) string {
				if len(cfg.RoutingInstances) != 1 || cfg.RoutingInstances[0].InstanceType != "vrf" {
					return "want one vrf instance, got " + json9620(cfg.RoutingInstances)
				}
				return ""
			},
		},
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			ec, eerr := CheckText(c.prefix+`routing-instances { `+c.elided+` }`, -1)
			bc, berr := CheckText(c.prefix+`routing-instances { `+c.braced+` }`, -1)
			if c.agree {
				if (eerr == nil) != (berr == nil) {
					t.Errorf("elided %q and braced %q reach different verdicts (#9620): elided err=%v, braced err=%v",
						c.elided, c.braced, eerr, berr)
				} else if eerr == nil && !reflect.DeepEqual(ec.RoutingInstances, bc.RoutingInstances) {
					t.Errorf("elided and braced spellings commit different routing instances (#9620)\n elided %s\n braced %s",
						json9620(ec.RoutingInstances), json9620(bc.RoutingInstances))
				}
				return
			}
			if c.refusal != "" {
				if berr == nil || !strings.Contains(berr.Error(), c.refusal) {
					t.Errorf("CONTROL braced %q: want a refusal naming %q, got %v", c.braced, c.refusal, berr)
				}
				if eerr == nil || !strings.Contains(eerr.Error(), c.refusal) {
					t.Errorf("elided %q: want a refusal naming %q, as the braced spelling gets; got %v (#9620)",
						c.elided, c.refusal, eerr)
				}
				return
			}
			if berr != nil {
				t.Errorf("CONTROL braced %q: want a commit, got %v", c.braced, berr)
			}
			if eerr != nil {
				t.Errorf("elided %q: want a commit, as the braced spelling gets; got %v (#9620)", c.elided, eerr)
			}
			if berr != nil || eerr != nil {
				return
			}
			if msg := c.check(bc); msg != "" {
				t.Errorf("CONTROL braced %q: %s", c.braced, msg)
			}
			if msg := c.check(ec); msg != "" {
				t.Errorf("elided %q: %s (#9620)", c.elided, msg)
			}
			if !reflect.DeepEqual(ec.RoutingInstances, bc.RoutingInstances) {
				t.Errorf("elided and braced spellings commit different routing instances (#9620)\n elided %s\n braced %s",
					json9620(ec.RoutingInstances), json9620(bc.RoutingInstances))
			}
		})
	}
}

func nextHopInherited9620(cfg *config.Config) string {
	if len(cfg.RoutingInstances) != 1 || len(cfg.RoutingInstances[0].StaticRoutes) != 1 {
		return "want 1 instance with 1 static route, got " + json9620(cfg.RoutingInstances)
	}
	r := cfg.RoutingInstances[0].StaticRoutes[0]
	if len(r.NextHops) != 1 || r.NextHops[0].Address != "10.0.0.2" {
		return "want next-hop 10.0.0.2 inherited from group G, got " + json9620(r)
	}
	return ""
}

// json9620 renders a value for a failure message. JSON follows pointers, where
// %+v would print addresses.
func json9620(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return string(b)
}
