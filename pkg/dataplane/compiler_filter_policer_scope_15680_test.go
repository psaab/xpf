package dataplane

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

type policerRecordingDP struct {
	recordingFilterDP
	policers map[uint32]PolicerConfig
}

func (d *policerRecordingDP) SetPolicerConfig(id uint32, cfg PolicerConfig) error {
	if d.policers == nil {
		d.policers = make(map[uint32]PolicerConfig)
	}
	d.policers[id] = cfg
	return nil
}

// #15680: the retired-eBPF compiler must allocate a distinct
// policer_configs slot per (family, filter, term, policer) instance.
// Pre-fix it allocated one slot per definition name, so both terms below
// shared PolicerID 1 (one token bucket).
func TestCompileFirewallFiltersAllocatesPolicerPerTerm15680(t *testing.T) {
	cfg := &config.Config{}
	cfg.Firewall.Policers = map[string]*config.PolicerConfig{
		"shared": {Name: "shared", BandwidthLimit: 8000, BurstSizeLimit: 1000},
		"orphan": {Name: "orphan", BandwidthLimit: 4000, BurstSizeLimit: 500},
	}
	mkTerm := func(name string) *config.FirewallFilterTerm {
		return &config.FirewallFilterTerm{Name: name, Action: "accept", Policer: "shared"}
	}
	cfg.Firewall.FiltersInet = map[string]*config.FirewallFilter{
		"edge": {Name: "edge", Terms: []*config.FirewallFilterTerm{mkTerm("first"), mkTerm("second")}},
	}
	cfg.Firewall.FiltersInet6 = map[string]*config.FirewallFilter{
		"edge": {Name: "edge", Terms: []*config.FirewallFilterTerm{mkTerm("first")}},
	}

	dp := &policerRecordingDP{}
	result := &CompileResult{}
	if err := compileFirewallFilters(dp, cfg, result); err != nil {
		t.Fatalf("compileFirewallFilters: %v", err)
	}
	// 3 term-scoped instances + 1 unreferenced name-scoped slot.
	if len(dp.policers) != 4 {
		t.Fatalf("programmed %d policer slots, want 4 (3 term-scoped + 1 unreferenced): %v", len(dp.policers), dp.policers)
	}
	if len(dp.rules) != 3 {
		t.Fatalf("programmed %d rules, want 3", len(dp.rules))
	}
	seen := make(map[uint8]bool)
	for _, rule := range dp.rules {
		if rule.PolicerID == 0 {
			t.Fatalf("rule %+v has no policer", rule)
		}
		if seen[rule.PolicerID] {
			t.Fatalf("policer slot %d shared by multiple terms; rules=%+v", rule.PolicerID, dp.rules)
		}
		seen[rule.PolicerID] = true
	}
	for id, pcfg := range dp.policers {
		if id == 0 {
			t.Fatal("policer slot 0 programmed (0 means no policer)")
		}
		if pcfg.RateBytesSec != 8000 && pcfg.RateBytesSec != 4000 {
			t.Fatalf("slot %d rate = %d, want a definition rate", id, pcfg.RateBytesSec)
		}
	}
}
