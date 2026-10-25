package natshow

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16681: NAT64 show must surface the full authored scope on BOTH CLIs.
// Pre-fix neither renderer printed SourceAddresses/SourceAddressNames
// and the gRPC ShowText renderer also omitted FromZones /
// FromRoutingInstances, so a scoped rule-set read as match-any.

func nat64ScopedFixture16681() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p64": {Name: "p64", Addresses: []string{"203.0.113.1"}},
	}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{
		{
			Name:                 "scoped64",
			Prefix:               "64:ff9b::/96",
			SourcePool:           "p64",
			FromZone:             "trust",
			FromZones:            []string{"trust", "dmz"},
			FromRoutingInstance:  "blue",
			FromRoutingInstances: []string{"blue", "red"},
			SourceAddress:        "2001:db8:1::/48",
			SourceAddresses:      []string{"2001:db8:1::/48", "2001:db8:2::/48"},
			SourceAddressName:    "v6-clients",
			SourceAddressNames:   []string{"v6-clients", "v6-partners"},
		},
	}
	return cfg
}

func TestRenderNAT64Scoped16681(t *testing.T) {
	var b strings.Builder
	RenderNAT64(&b, nat64ScopedFixture16681(), nil)
	out := b.String()
	for _, want := range []string{
		"NAT64 rule-set: scoped64\n",
		"  Prefix:      64:ff9b::/96\n",
		"  From zones:   trust, dmz\n",
		"  From routing-instances: blue, red\n",
		"  Source addresses: 2001:db8:1::/48, 2001:db8:2::/48\n",
		"  Source address-names: v6-clients, v6-partners\n",
		"  Source pool:  p64\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("RenderNAT64 missing %q\nout:\n%s", want, out)
		}
	}
}

// Singular-only fixtures (hand-built / pre-union configs) must still
// render through the singular fallback, exactly as the local CLI did.
func TestRenderNAT64SingularFallback16681(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{
		{
			Name:                "legacy64",
			Prefix:              "64:ff9b::/96",
			FromZone:            "trust",
			FromRoutingInstance: "blue",
			SourceAddress:       "2001:db8::/32",
			SourceAddressName:   "book1",
		},
	}
	var b strings.Builder
	RenderNAT64(&b, cfg, nil)
	out := b.String()
	for _, want := range []string{
		"  From zones:   trust\n",
		"  From routing-instances: blue\n",
		"  Source addresses: 2001:db8::/32\n",
		"  Source address-names: book1\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("singular fallback missing %q\nout:\n%s", want, out)
		}
	}
}

// #16604: a lowered explicit-master RI member ("") renders as authored
// `default`, never as a blank entry — preserved from the local CLI.
func TestRenderNAT64DefaultRI16681(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.NAT.NAT64 = []*config.NAT64RuleSet{
		{Name: "def64", Prefix: "64:ff9b::/96", FromRoutingInstances: []string{""}},
	}
	var b strings.Builder
	RenderNAT64(&b, cfg, nil)
	if !strings.Contains(b.String(), "  From routing-instances: default\n") {
		t.Errorf("explicit-master RI must render as default:\n%s", b.String())
	}
}

func TestRenderNAT64Empty16681(t *testing.T) {
	var b strings.Builder
	RenderNAT64(&b, nil, nil)
	if b.String() != "No NAT64 rule-sets configured\n" {
		t.Errorf("nil cfg = %q", b.String())
	}
	var b2 strings.Builder
	RenderNAT64(&b2, &config.Config{}, nil)
	if b2.String() != "No NAT64 rule-sets configured\n" {
		t.Errorf("empty cfg = %q", b2.String())
	}
}

// #16547 runtime verdict must fold in only when the config verdict is
// empty, and must not annotate an armed rule-set.
func TestRenderNAT64RuntimeVerdict16681(t *testing.T) {
	cfg := nat64ScopedFixture16681()
	var b strings.Builder
	RenderNAT64(&b, cfg, RuntimeVerdicts{"scoped64": "iface_snat_egress_overlap"})
	if !strings.Contains(b.String(), "NOT INSTALLED") {
		t.Errorf("runtime-quarantined NAT64 rule-set not annotated:\n%s", b.String())
	}
	var b2 strings.Builder
	RenderNAT64(&b2, cfg, RuntimeVerdicts{"other": "iface_snat_egress_overlap"})
	if strings.Contains(b2.String(), "NOT INSTALLED") {
		t.Errorf("armed NAT64 rule-set annotated from unrelated verdict:\n%s", b2.String())
	}
}
