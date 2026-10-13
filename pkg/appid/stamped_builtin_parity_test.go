package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func stampedWinner(t *testing.T, cat Catalog, proto uint8, srcPort, dstPort uint16) string {
	t.Helper()
	inRange := func(lo, hi, p uint16) bool { return (lo == 0 && hi == 0) || (lo <= p && p <= hi) }
	var winID uint16
	winConstrained := false
	for _, e := range cat.Entries {
		if e.Protocol != proto || !inRange(e.DstPortLow, e.DstPortHigh, dstPort) || !inRange(e.SrcPortLow, e.SrcPortHigh, srcPort) {
			continue
		}
		constrained := e.DstPortLow != 0 || e.DstPortHigh != 0 || e.SrcPortLow != 0 || e.SrcPortHigh != 0
		if winID == 0 || (constrained && !winConstrained) || (constrained == winConstrained && e.AppID < winID) {
			winID, winConstrained = e.AppID, constrained
		}
	}
	if winID == 0 {
		return Unknown
	}
	return cat.AppNames[winID]
}

func TestStampedUnstampedBuiltinParity_12731(t *testing.T) {
	cases := []struct {
		name   string
		app    *config.Application
		refs   []string
		proto  uint8
		src    uint16
		dst    uint16
		want   string
	}{
		{"unreferenced builtin http", nil, []string{"junos-ssh"}, 6, 40000, 80, Unknown},
		{"unreferenced builtin https", nil, []string{"junos-ssh"}, 6, 40000, 443, Unknown},
		{"unreferenced builtin ike-nat", nil, []string{"junos-ssh"}, 17, 40000, 4500, Unknown},
		{"referenced builtin ssh control", nil, []string{"junos-ssh"}, 6, 40000, 22, "junos-ssh"},
		{"unknown tuple", nil, []string{"junos-ssh"}, 6, 40000, 9999, Unknown},
		{"user app no builtin overlap", &config.Application{Name: "my-web", Protocol: "tcp", DestinationPort: "8080"}, []string{"my-web", "junos-ssh"}, 6, 40000, 8080, "my-web"},
		{"user protocol-only vs unreferenced builtin", &config.Application{Name: "my-udp", Protocol: "udp"}, []string{"my-udp", "junos-ssh"}, 17, 40000, 4500, "my-udp"},
		{"same-tier lowest-id tie-break", &config.Application{Name: "my-natt", Protocol: "udp", DestinationPort: "4500"}, []string{"my-natt", "junos-ssh"}, 17, 40000, 4500, "my-natt"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			userApps := map[string]*config.Application{}
			if tc.app != nil {
				userApps[tc.app.Name] = tc.app
			}
			cfg := &config.Config{Applications: config.ApplicationsConfig{Applications: userApps}}
			cfg.Services.ApplicationIdentification = false
			cfg.Security.GlobalPolicies = []*config.Policy{{Name: "ref", Match: config.PolicyMatch{Applications: tc.refs}}}
			cat, err := BuildCatalog(cfg)
			if err != nil {
				t.Fatalf("BuildCatalog(off): %v", err)
			}
			stamped := stampedWinner(t, cat, tc.proto, tc.src, tc.dst)
			if stamped != tc.want {
				t.Fatalf("stamped (catalog) label = %q, want %q (AppNames=%v)", stamped, tc.want, cat.AppNames)
			}
			unstamped := ResolveSessionName(cat.AppNames, cfg, tc.proto, tc.src, tc.dst, 0)
			if unstamped != tc.want {
				t.Fatalf("unstamped (fallback) label = %q, want %q", unstamped, tc.want)
			}
			if stamped != unstamped {
				t.Fatalf("stamped/unstamped split: stamped=%q unstamped=%q", stamped, unstamped)
			}
		})
	}
}

func TestCatalogNamesOffRemainsReferencedOnly_12731(t *testing.T) {
	cfg := &config.Config{}
	cfg.Security.GlobalPolicies = []*config.Policy{{Name: "ref", Match: config.PolicyMatch{Applications: []string{"junos-ssh"}}}}
	names, err := CatalogNames(cfg, false)
	if err != nil {
		t.Fatalf("CatalogNames(false): %v", err)
	}
	if len(names) != 1 || names[0] != "junos-ssh" {
		t.Fatalf("CatalogNames(false) = %v, want only the referenced builtin", names)
	}
}
