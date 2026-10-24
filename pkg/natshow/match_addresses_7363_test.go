package natshow

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// match_addresses_7363_test.go — #7363.
//
// The rule-detail renderers described a rule's address match from the SINGULAR
// back-compat field alone, and were wrong in BOTH directions:
//
//   - a rule scoped only by `match destination-address-name` rendered as
//     `0.0.0.0/0`, i.e. as matching EVERY destination;
//   - a bracket list `[ A B C ]` rendered only `A`.
//
// The rule may be installed perfectly in both cases. What is wrong is the
// surface's description of WHICH TRAFFIC IT MATCHES, which is why this is not
// a variant of #6534's "rendered as if installed" work and does not share its
// fix.

func matchCfg7363(dst config.NATMatch, src config.NATMatch) *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.Destination = &config.DestinationNATConfig{
		Pools: map[string]*config.NATPool{"dp1": {Name: "dp1", Address: "10.0.30.5"}},
		RuleSets: []*config.NATRuleSet{{
			Name: "drs", FromZone: "untrust",
			Rules: []*config.NATRule{{
				Name: "d1", Match: dst, Then: config.NATThen{PoolName: "dp1"},
			}},
		}},
	}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"sp1": {Name: "sp1", Addresses: []string{"203.0.113.1"}},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name: "srs", FromZone: "trust", ToZone: "untrust",
		Rules: []*config.NATRule{{
			Name: "s1", Match: src, Then: config.NATThen{PoolName: "sp1"},
		}},
	}}
	return cfg
}

func renderDest7363(t *testing.T, m config.NATMatch) string {
	t.Helper()
	var b bytes.Buffer
	RenderDestRuleDetail(context.Background(), &b, matchCfg7363(m, config.NATMatch{}), nil, nil)
	return b.String()
}

func renderSource7363(t *testing.T, m config.NATMatch) string {
	t.Helper()
	var b bytes.Buffer
	RenderSourceRuleDetail(context.Background(), &b, matchCfg7363(config.NATMatch{}, m), nil, nil)
	return b.String()
}

// CASE 1, the over-broad direction: a name-scoped rule must not claim 0.0.0.0/0.
func TestNameScopedDestRuleDoesNotRenderAsAny7363(t *testing.T) {
	out := renderDest7363(t, config.NATMatch{
		DestinationAddressName:  "NOPE",
		DestinationAddressNames: []string{"NOPE"},
	})
	if !strings.Contains(out, "NOPE") {
		t.Errorf("the address-book name the rule is scoped by does not appear:\n%s", out)
	}
	if strings.Contains(out, "Destination addresses: 0.0.0.0/0") {
		t.Errorf("a rule scoped by `match destination-address-name NOPE` rendered as "+
			"0.0.0.0/0 — the surface says it matches EVERY destination when it is "+
			"scoped to one address-book entry (#7363):\n%s", out)
	}
}

// CASE 2, the under-broad direction: a bracket list must render every element.
func TestBracketListDestRuleRendersEveryAddress7363(t *testing.T) {
	out := renderDest7363(t, config.NATMatch{
		DestinationAddress:   "10.1.0.0/16",
		DestinationAddresses: []string{"10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"},
	})
	for _, want := range []string{"10.1.0.0/16", "10.2.0.0/16", "10.3.0.0/16"} {
		if !strings.Contains(out, want) {
			t.Errorf("bracket-list element %q is missing; the operator is shown a "+
				"NARROWER scope than is configured (#7363):\n%s", want, out)
		}
	}
	// The singular field is the FIRST element of the plural, so a fix that
	// concatenated both would print 10.1.0.0/16 twice.
	if n := strings.Count(out, "10.1.0.0/16"); n != 1 {
		t.Errorf("the first address appears %d times; the singular field is the first "+
			"element of the plural and must not be joined to it", n)
	}
}

// The source renderer had the SAME shape. A fix to only the destination side
// would leave `show security nat source rule` still lying.
func TestSourceRuleRendersFullMatchOnBothSides7363(t *testing.T) {
	out := renderSource7363(t, config.NATMatch{
		SourceAddressName:       "SRCNAME",
		SourceAddressNames:      []string{"SRCNAME"},
		DestinationAddresses:    []string{"192.0.2.0/24", "198.51.100.0/24"},
		DestinationAddressNames: []string{"DSTNAME"},
	})
	for _, want := range []string{"SRCNAME", "192.0.2.0/24", "198.51.100.0/24", "DSTNAME"} {
		if !strings.Contains(out, want) {
			t.Errorf("source-rule detail is missing %q (#7363):\n%s", want, out)
		}
	}
	if strings.Contains(out, "Source addresses:      0.0.0.0/0") {
		t.Errorf("a name-scoped SOURCE rule rendered as 0.0.0.0/0:\n%s", out)
	}
}

// A rule may carry BOTH a CIDR and an address-book name; dropping either half
// reintroduces the defect for the mixed case.
func TestMixedCidrAndNameRendersBoth7363(t *testing.T) {
	out := renderDest7363(t, config.NATMatch{
		DestinationAddress:      "203.0.113.0/24",
		DestinationAddresses:    []string{"203.0.113.0/24"},
		DestinationAddressName:  "BOOKNAME",
		DestinationAddressNames: []string{"BOOKNAME"},
	})
	for _, want := range []string{"203.0.113.0/24", "BOOKNAME"} {
		if !strings.Contains(out, want) {
			t.Errorf("mixed CIDR+name match is missing %q (#7363):\n%s", want, out)
		}
	}
}

// CONTROL. A genuinely unscoped rule must STILL render 0.0.0.0/0.
//
// Without this, a "fix" that removed the wildcard fallback entirely would
// satisfy every cell above and render a blank where the operator needs to see
// that the rule really does match everything.
func TestUnscopedRuleStillRendersAny7363(t *testing.T) {
	out := renderDest7363(t, config.NATMatch{DestinationPort: 443})
	if !strings.Contains(out, "0.0.0.0/0") {
		t.Errorf("an unscoped rule must still render 0.0.0.0/0; a blank would hide "+
			"that it matches every destination:\n%s", out)
	}
}

// The helper itself, at the boundaries the renderers cannot easily reach.
// Inputs are the accessor outputs (#16143): plural superseding singular is
// the accessors' job, so the helper only joins the two lists.
func TestNatMatchAddressesPluralSupersedesSingular7363(t *testing.T) {
	cases := []struct {
		name         string
		cidrs, names []string
		want         string
	}{
		{name: "empty", want: ""},
		{name: "singular cidr only", cidrs: []string{"10.0.0.0/8"}, want: "10.0.0.0/8"},
		{name: "plural", cidrs: []string{"10.0.0.0/8", "10.1.0.0/16"}, want: "10.0.0.0/8 10.1.0.0/16"},
		{name: "singular name only", names: []string{"N"}, want: "N"},
		{name: "plural names", names: []string{"N", "M"}, want: "N M"},
		{name: "cidr and name together", cidrs: []string{"10.0.0.0/8"}, names: []string{"N"}, want: "10.0.0.0/8 N"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := natMatchAddresses(tc.cidrs, tc.names)
			if got != tc.want {
				t.Errorf("natMatchAddresses = %q, want %q", got, tc.want)
			}
		})
	}
}
