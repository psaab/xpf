package natshow

import (
	"context"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16547: the shared detail renderer must annotate a runtime-quarantined
// rule and suppress its translation-hits line. The pool here is usable by
// definition, so only the runtime map can produce the banner.

func runtimeCfg16547() *config.Config {
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{
		"p1": {Name: "p1", Addresses: []string{"203.0.113.10"}},
	}
	cfg.Security.NAT.Source = []*config.NATRuleSet{{
		Name: "rs1", FromZone: "trust", ToZone: "untrust",
		Rules: []*config.NATRule{{
			Name: "r1",
			Then: config.NATThen{PoolName: "p1"},
		}},
	}}
	return cfg
}

func TestRenderSourceRuleDetailRuntimeQuarantine16547(t *testing.T) {
	var b strings.Builder
	RenderSourceRuleDetailWithRuntime(context.Background(), &b, runtimeCfg16547(), nil, nil,
		RuntimeVerdicts{"r1": "iface_snat_egress_overlap"})
	out := b.String()
	if !strings.Contains(out, "NOT INSTALLED") {
		t.Fatalf("runtime-quarantined rule renders armed:\n%s", out)
	}
	if !strings.Contains(out, "interface") {
		t.Errorf("banner does not name the interface overlap:\n%s", out)
	}
}

func TestRenderSourceRuleDetailRuntimeControl16547(t *testing.T) {
	// Nil runtime map: byte-shape of the config-only render (no banner).
	var b strings.Builder
	RenderSourceRuleDetail(context.Background(), &b, runtimeCfg16547(), nil, nil)
	if strings.Contains(b.String(), "NOT INSTALLED") {
		t.Fatalf("config-only render gained a banner:\n%s", b.String())
	}
	// Empty runtime verdict for the rule: still armed.
	var b2 strings.Builder
	RenderSourceRuleDetailWithRuntime(context.Background(), &b2, runtimeCfg16547(), nil, nil,
		RuntimeVerdicts{"other": "iface_snat_egress_overlap"})
	if strings.Contains(b2.String(), "NOT INSTALLED") {
		t.Fatalf("unrelated runtime verdict annotated r1:\n%s", b2.String())
	}
}
