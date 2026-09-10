package policymatch

import (
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9571: `show security match-policies` on a leniently-loaded deny-first
// duplicate. Before the fix the simulator agreed with the dataplane that the
// merged policy PERMITS (so it could not flag it); it must now report the
// helper's refusal. Channel: config.CompileConfigLenient.

func lenientHier9571(t *testing.T, text string) *config.Config {
	t.Helper()
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile refused the fixture: %v", err)
	}
	return cfg
}

func TestFoldWidenedDuplicateSimulatorReportsTheRefusal9571(t *testing.T) {
	const anyM = `match { source-address any; destination-address any; application any; }`
	zp := func(body string) string {
		return `security { zones { security-zone trust; security-zone untrust; } policies { from-zone trust to-zone untrust { ` + body + ` } } }`
	}
	gl := func(body string) string {
		return `security { zones { security-zone trust; security-zone untrust; } policies { global { ` + body + ` } } }`
	}
	q := Query{FromZone: "trust", ToZone: "untrust", SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"), Protocol: "tcp", SrcPort: 40000, DstPort: 443}
	for _, tc := range []struct{ name, text string }{
		{"zone-pair deny then permit", zp(`policy p1 { ` + anyM + ` then { deny; } } policy p1 { ` + anyM + ` then { permit; } }`)},
		{"global deny then permit", gl(`policy p1 { ` + anyM + ` then { deny; } } policy p1 { ` + anyM + ` then { permit; } }`)},
		{"union, probing a source only the deny names", zp(
			`policy p1 { match { source-address 10.0.1.0/25; destination-address any; application any; } then { deny; } } ` +
				`policy p1 { match { source-address 10.0.1.128/25; destination-address any; application any; } then { permit; } }`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := Match(lenientHier9571(t, tc.text), q)
			if !res.ContentRejected || res.Matched {
				t.Fatalf("#9571: want the refusal reported, got Matched=%v Action=%v ContentRejected=%v", res.Matched, res.Action, res.ContentRejected)
			}
		})
	}

	t.Run("#8752 control keeps its deny verdict", func(t *testing.T) {
		res := Match(lenientHier9571(t, zp(`policy p1 { `+anyM+` then { permit; } } policy p1 { then { deny; } }`)), q)
		if res.ContentRejected || !res.Matched || res.Action != config.PolicyDeny {
			t.Fatalf("want a matched deny, got %+v", res)
		}
	})
	t.Run("distinct names keep first-match deny", func(t *testing.T) {
		res := Match(lenientHier9571(t, zp(`policy p1 { `+anyM+` then { deny; } } policy p2 { `+anyM+` then { permit; } }`)), q)
		if res.ContentRejected || res.PolicyName != "p1" || res.Action != config.PolicyDeny {
			t.Fatalf("want p1 deny, got %+v", res)
		}
	})
}
