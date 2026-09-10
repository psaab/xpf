package policymatch

import (
	"net"
	"testing"
)

// #9584 — `show security match-policies` must report the helper's
// DuplicateRuleId refusal instead of a first-match verdict. Channel:
// config.CompileConfigLenient.
func TestDuplicateRuleIdentitySimulatorReportsTheRefusal9584(t *testing.T) {
	const anyM = `match { source-address any; destination-address any; application any; }`
	const z = `zones { security-zone trust; security-zone untrust; }`
	pol := func(n, a string) string { return `policy ` + n + ` { ` + anyM + ` then { ` + a + `; } }` }
	q := Query{FromZone: "trust", ToZone: "untrust", SrcIP: net.ParseIP("10.0.1.5"), DstIP: net.ParseIP("10.0.2.5"), Protocol: "tcp", SrcPort: 40000, DstPort: 80}
	for _, tc := range []struct {
		name     string
		text     string
		rejected bool
	}{
		{"two security roots", `security { ` + z + ` policies { from-zone trust to-zone untrust { ` + pol("p1", "deny") + ` } } }
security { policies { from-zone trust to-zone untrust { ` + pol("p1", "permit") + ` } } }`, true},
		{"two stanzas for one zone pair", `security { ` + z + ` policies { from-zone trust to-zone untrust { ` + pol("p1", "deny") + ` } from-zone trust to-zone untrust { ` + pol("p1", "permit") + ` } } }`, true},
		{"two global blocks", `security { ` + z + ` policies { global { ` + pol("g1", "deny") + ` } global { ` + pol("g1", "permit") + ` } } }`, true},
		{"control: distinct names", `security { ` + z + ` policies { from-zone trust to-zone untrust { ` + pol("p1", "deny") + ` } } }
security { policies { from-zone trust to-zone untrust { ` + pol("p2", "permit") + ` } } }`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := Match(lenientHier9571(t, tc.text), q)
			if tc.rejected && (!res.ContentRejected || res.Matched) {
				t.Fatalf("#9584: the helper refuses this snapshot, but the simulator reported Matched=%v Policy=%q", res.Matched, res.PolicyName)
			}
			if !tc.rejected && (res.ContentRejected || !res.Matched || res.PolicyName != "p1") {
				t.Fatalf("control must keep its first-match verdict, got %+v", res)
			}
		})
	}
}
