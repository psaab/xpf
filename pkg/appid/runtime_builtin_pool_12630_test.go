package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestBuiltinPoolOnOffParity_12630 pins #12630: when a user application
// covers a builtin/predefined tuple (UDP/4500 here), the AppID-off tuple
// fallback must rank user + predefined applications in ONE pool —
// port-constrained tier beats protocol-only, then lowest assigned app_id —
// exactly as the AppID-on dataplane catalog does. The old off path checked
// user apps first and only then the builtin table, so it returned the user
// name where the enabled catalog stamps junos-ike-nat (or vice versa).
func TestBuiltinPoolOnOffParity_12630(t *testing.T) {
	cases := []struct {
		name string
		app  *config.Application // nil = no user app
		want string
	}{
		{"protocol-only user loses to exact predefined", &config.Application{Name: "my-udp", Protocol: "udp"}, "junos-ike-nat"},
		{"exact user loses same-tier lowest-id to predefined", &config.Application{Name: "my-natt", Protocol: "udp", DestinationPort: "4500"}, "junos-ike-nat"},
		{"range user loses same-tier lowest-id to predefined", &config.Application{Name: "my-range", Protocol: "udp", DestinationPort: "4000-5000"}, "junos-ike-nat"},
		{"exact user with lower id wins same-tier over predefined", &config.Application{Name: "my-udp", Protocol: "udp", DestinationPort: "4500"}, "my-udp"},
		{"non-covering user leaves predefined label", &config.Application{Name: "my-other", Protocol: "udp", DestinationPort: "9999"}, "junos-ike-nat"},
		{"no user app keeps predefined label", nil, "junos-ike-nat"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			userApps := map[string]*config.Application{}
			var refs []string
			if tc.app != nil {
				userApps[tc.app.Name] = tc.app
				refs = append(refs, tc.app.Name)
			}
			enabledCfg := &config.Config{Applications: config.ApplicationsConfig{Applications: userApps}}
			enabledCfg.Services.ApplicationIdentification = true
			cat, err := BuildCatalog(enabledCfg)
			if err != nil {
				t.Fatalf("BuildCatalog(enabled): %v", err)
			}
			inRange := func(lo, hi, p uint16) bool { return (lo == 0 && hi == 0) || (lo <= p && p <= hi) }
			var winID uint16
			winConstrained := false
			for _, e := range cat.Entries {
				if e.Protocol != 17 || !inRange(e.DstPortLow, e.DstPortHigh, 4500) || !inRange(e.SrcPortLow, e.SrcPortHigh, 40000) {
					continue
				}
				constrained := e.DstPortLow != 0 || e.DstPortHigh != 0 || e.SrcPortLow != 0 || e.SrcPortHigh != 0
				if winID == 0 || (constrained && !winConstrained) || (constrained == winConstrained && e.AppID < winID) {
					winID, winConstrained = e.AppID, constrained
				}
			}
			if winID == 0 {
				t.Fatal("enabled catalog has no UDP/4500 entry")
			}
			enabledName := ResolveSessionName(cat.AppNames, enabledCfg, 17, 40000, 4500, winID)
			if enabledName != tc.want {
				t.Fatalf("enabled winner = %q (id %d), want %q", enabledName, winID, tc.want)
			}
			disabledCfg := &config.Config{Applications: config.ApplicationsConfig{Applications: userApps}}
			disabledCfg.Services.ApplicationIdentification = false
			// Compare modes only when the OFF catalog references the builtin,
			// since unreferenced builtins are intentionally not fallback labels.
			refs = append(refs, "junos-ike-nat")
			disabledCfg.Security.GlobalPolicies = []*config.Policy{{Name: "ref", Match: config.PolicyMatch{Applications: refs}}}
			offCat, err := BuildCatalog(disabledCfg)
			if err != nil {
				t.Fatalf("BuildCatalog(disabled): %v", err)
			}
			offName := ResolveSessionName(offCat.AppNames, disabledCfg, 17, 40000, 4500, 0)
			if offName != enabledName {
				t.Fatalf("AppID on/off label split for UDP/4500: off=%q on=%q, want %q", offName, enabledName, tc.want)
			}
		})
	}
}
