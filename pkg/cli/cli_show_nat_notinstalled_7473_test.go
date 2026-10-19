package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #7473: every NAT summary renderer must annotate a rule the builder refused.
//
// PER FUNCTION, NOT PER SURFACE. Five surfaces and eight renderers means seven
// renderers can be wrong while a surface-level cell passes, if the cells happen
// to exercise the same one per surface. Each row below names one function and
// calls it directly.
//
// EVERY ROW CARRIES ITS OWN CONTROL. A renderer that consults the predicate and
// one that does not produce IDENTICAL output for an ARMED rule, so a fixture
// with only armed rules passes for both implementations and proves nothing.
// Each row therefore renders a DISARMED config (expects the annotation) and an
// ARMED config (expects its absence). The armed leg is what makes the disarmed
// leg mean something: together they show the renderer FOLLOWS the predicate
// rather than printing the banner unconditionally.

const notInstalled7473 = "NOT INSTALLED"

// disarmedSourceCfg: pool "p1" has no members, so SourceNATPoolUnusableReason
// returns empty_pool and every rule translating via it is not installed.
func disarmedSourceCfg() *config.Config {
	return &config.Config{Security: config.SecurityConfig{NAT: config.NATConfig{
		SourcePools: map[string]*config.NATPool{"p1": {Name: "p1"}},
		Source: []*config.NATRuleSet{{
			Name: "rs1", FromZone: "trust", ToZone: "untrust",
			Rules: []*config.NATRule{{
				Name:  "r1",
				Match: config.NATMatch{SourceAddress: "10.0.0.0/8"},
				Then:  config.NATThen{PoolName: "p1"},
			}},
		}},
	}}}
}

// armedSourceCfg: the same shape with a usable pool.
func armedSourceCfg() *config.Config {
	cfg := disarmedSourceCfg()
	cfg.Security.NAT.SourcePools["p1"] = &config.NATPool{Name: "p1", Address: "192.0.2.10"}
	return cfg
}

// disarmedDestCfg: the rule references a pool that EXISTS but carries no
// address, so DestinationNATRuleExcludedReason excludes it.
//
// The pool must exist. An earlier version pointed the rule at an undefined pool
// name, which excludes the rule correctly but leaves the two POOL-iterating
// renderers (showNATDestinationPool, showNATDestinationSummary) with nothing to
// walk — they iterate dnat.Pools, and a pool that is not in the map is never
// visited. Both rows passed vacuously until the per-function table caught it; a
// per-surface test would have been satisfied by the other destination
// renderers and never exercised these two at all.
func disarmedDestCfg() *config.Config {
	return &config.Config{Security: config.SecurityConfig{NAT: config.NATConfig{
		Destination: &config.DestinationNATConfig{
			Pools: map[string]*config.NATPool{"dp1": {Name: "dp1"}},
			RuleSets: []*config.NATRuleSet{{
				Name: "drs1", FromZone: "untrust", ToZone: "trust",
				Rules: []*config.NATRule{{
					Name:  "dr1",
					Match: config.NATMatch{DestinationAddress: "203.0.113.1/32"},
					Then:  config.NATThen{PoolName: "dp1"},
				}},
			}},
		},
	}}}
}

// armedDestCfg: the same shape with the pool given an address.
func armedDestCfg() *config.Config {
	cfg := disarmedDestCfg()
	cfg.Security.NAT.Destination.Pools["dp1"] = &config.NATPool{Name: "dp1", Address: "192.0.2.50"}
	return cfg
}

func TestNATSummaryRenderersAnnotateNotInstalled7473(t *testing.T) {
	for _, tc := range []struct {
		fn       string
		disarmed *config.Config
		armed    *config.Config
		call     func(c *CLI, cfg *config.Config) error
	}{
		{"showNATSourceRuleAll", disarmedSourceCfg(), armedSourceCfg(),
			func(c *CLI, cfg *config.Config) error { return c.showNATSourceRuleAll(cfg, "") }},
		{"showNATSourceRuleSet", disarmedSourceCfg(), armedSourceCfg(),
			func(c *CLI, cfg *config.Config) error { return c.showNATSourceRuleSet(cfg, "rs1") }},
		{"showNATSourceSummary", disarmedSourceCfg(), armedSourceCfg(),
			func(c *CLI, cfg *config.Config) error { return c.showNATSourceSummary(cfg) }},
		{"showNATDestination", disarmedDestCfg(), armedDestCfg(),
			func(c *CLI, cfg *config.Config) error { return c.showNATDestination(cfg, nil) }},
		{"showNATDestinationPool", disarmedDestCfg(), armedDestCfg(),
			func(c *CLI, cfg *config.Config) error { return c.showNATDestinationPool(cfg, "") }},
		{"showNATDestinationRuleAll", disarmedDestCfg(), armedDestCfg(),
			func(c *CLI, cfg *config.Config) error { return c.showNATDestinationRuleAll(cfg, "") }},
		{"showNATDestinationRuleSet", disarmedDestCfg(), armedDestCfg(),
			func(c *CLI, cfg *config.Config) error { return c.showNATDestinationRuleSet(cfg, "drs1") }},
		{"showNATDestinationSummary", disarmedDestCfg(), armedDestCfg(),
			func(c *CLI, cfg *config.Config) error { return c.showNATDestinationSummary(cfg) }},
	} {
		t.Run(tc.fn, func(t *testing.T) {
			c := &CLI{}

			out := captureStdout(t, func() {
				if err := tc.call(c, tc.disarmed); err != nil {
					t.Fatalf("%s(disarmed): %v", tc.fn, err)
				}
			})
			if !strings.Contains(out, notInstalled7473) {
				t.Errorf("%s renders a rule the builder REFUSED without saying so.\n"+
					"An operator reading this sees a rule that looks live, and any hit "+
					"counter beside it reads as \"no traffic matched\" rather than \"not "+
					"armed\".\ngot:\n%s", tc.fn, out)
			}

			// The control. Without it this row would also pass for a renderer
			// that prints the banner unconditionally.
			armedOut := captureStdout(t, func() {
				if err := tc.call(c, tc.armed); err != nil {
					t.Fatalf("%s(armed): %v", tc.fn, err)
				}
			})
			if strings.Contains(armedOut, notInstalled7473) {
				t.Errorf("%s annotates an ARMED rule as not installed — the renderer is "+
					"printing the banner unconditionally rather than consulting the "+
					"predicate.\ngot:\n%s", tc.fn, armedOut)
			}
		})
	}
}

// Guards the fixtures themselves. If the predicates ever stop disarming these
// shapes, every row above silently degrades into "renders without crashing" —
// the disarmed leg would find nothing to annotate and the armed control would
// pass trivially, so the whole table would go green while testing nothing.
func TestNATNotInstalledFixturesActuallyDisarm7473(t *testing.T) {
	src := disarmedSourceCfg()
	if got := sourceNATRuleNotInstalled(src, src.Security.NAT.Source[0].Rules[0]); got == "" {
		t.Error("the disarmed SOURCE fixture is not actually disarmed; every source row above is vacuous")
	}
	armedSrc := armedSourceCfg()
	if got := sourceNATRuleNotInstalled(armedSrc, armedSrc.Security.NAT.Source[0].Rules[0]); got != "" {
		t.Errorf("the ARMED source fixture is disarmed (%q); the control legs above prove nothing", got)
	}

	dst := disarmedDestCfg()
	if got := destNATRuleNotInstalled(dst, dst.Security.NAT.Destination.RuleSets[0].Rules[0]); got == "" {
		t.Error("the disarmed DEST fixture is not actually disarmed; every destination row above is vacuous")
	}
	armedDst := armedDestCfg()
	if got := destNATRuleNotInstalled(armedDst, armedDst.Security.NAT.Destination.RuleSets[0].Rules[0]); got != "" {
		t.Errorf("the ARMED dest fixture is disarmed (%q); the control legs above prove nothing", got)
	}
}
