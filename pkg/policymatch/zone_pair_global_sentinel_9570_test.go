package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9570: `show security match-policies` must agree with the helper for all three
// spellings of a zone-pair stanza naming `junos-global`, on the TOLERANT compile
// channel (config.CompileConfigLenient). Before the fix the both-sided spelling
// returned the default verdict here while the helper permitted every zone pair.

func compileLenientSet9570(t *testing.T, lines []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, l := range lines {
		p, err := config.ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile refused the fixture: %v", err)
	}
	return cfg
}

func lines9570(extra ...string) []string {
	return append([]string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
		"set security policies default-policy deny-all",
	}, extra...)
}

func policyLines9570(prefix, action string) []string {
	return []string{prefix + "match source-address any", prefix + "match destination-address any", prefix + "match application any", prefix + "then " + action}
}

func query9570(from, to string) Query {
	return Query{FromZone: from, ToZone: to, SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"), Protocol: "tcp", SrcPort: 40000, DstPort: 443}
}

func TestZonePairGlobalSentinelSimulatorReportsTheRefusal9570(t *testing.T) {
	for _, tc := range []struct{ name, from, to string }{
		{"from-side", "junos-global", "trust"},
		{"to-side", "trust", "junos-global"},
		{"both-sided", "junos-global", "junos-global"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileLenientSet9570(t, lines9570(policyLines9570(
				"set security policies from-zone "+tc.from+" to-zone "+tc.to+" policy p1 ", "permit")...))
			for _, q := range []Query{query9570("dmz", "untrust"), query9570("trust", "untrust")} {
				res := Match(cfg, q)
				if !res.ContentRejected {
					t.Errorf("%s->%s: the helper refuses this snapshot, but the simulator reported "+
						"Matched=%v DefaultUsed=%v Action=%v", q.FromZone, q.ToZone, res.Matched, res.DefaultUsed, res.Action)
				}
				if res.Matched {
					t.Errorf("%s->%s: a refused snapshot enforces no policy, yet the simulator matched %q", q.FromZone, q.ToZone, res.PolicyName)
				}
			}
		})
	}
}

// The accepting controls: a real global policy and a healthy zone-pair rule keep
// their verdicts. A simulator that reported every config refused would pass the
// cell above and fail these.
func TestZonePairGlobalSentinelSimulatorControls9570(t *testing.T) {
	t.Run("real global permit is still matched as global", func(t *testing.T) {
		cfg := compileLenientSet9570(t, lines9570(policyLines9570("set security policies global policy g1 ", "permit")...))
		res := Match(cfg, query9570("dmz", "untrust"))
		if res.ContentRejected || !res.Matched || !res.Global || res.Action != config.PolicyPermit {
			t.Fatalf("want a global permit, got %+v", res)
		}
	})
	t.Run("healthy zone-pair rule keeps its verdict", func(t *testing.T) {
		cfg := compileLenientSet9570(t, lines9570(policyLines9570("set security policies from-zone trust to-zone untrust policy p1 ", "permit")...))
		if res := Match(cfg, query9570("trust", "untrust")); res.ContentRejected || !res.Matched || res.Action != config.PolicyPermit {
			t.Fatalf("want trust->untrust permit, got %+v", res)
		}
		if res := Match(cfg, query9570("dmz", "untrust")); res.ContentRejected || res.Matched || !res.DefaultUsed {
			t.Fatalf("want the default for an unrelated pair, got %+v", res)
		}
	})
}
