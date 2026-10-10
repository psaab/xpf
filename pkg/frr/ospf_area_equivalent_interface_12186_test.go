package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestOSPFAreaEquivalentIDInterfaceDedupe12186(t *testing.T) {
	for _, ids := range [][2]string{{"0", "0.0.0.0"}, {"0.0.0.0", "0"}} {
		name := ids[0] + " then " + ids[1]
		t.Run("ospfv2 "+name, func(t *testing.T) {
			ospf := &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: ids[0], Interfaces: []*config.OSPFInterface{{Name: "eth0", Cost: 10, Passive: ids[0] == "0", AuthType: "simple", AuthKey: config.Secret("first-secret")}}},
				{ID: ids[1], Interfaces: []*config.OSPFInterface{{Name: "eth0", Cost: 20, Passive: ids[1] == "0", AuthType: "simple", AuthKey: config.Secret("second-secret")}}},
			}}
			got := (&Manager{}).generateProtocols(ospf, nil, nil, nil, nil, "", 0, nil, nil)
			if count := strings.Count(got, "\ninterface eth0\n"); count != 1 {
				t.Fatalf("rendered %d interface blocks for equivalent area IDs; want one:\n%s", count, got)
			}
			if count := strings.Count(got, "passive-interface eth0\n"); count != 1 {
				t.Fatalf("rendered %d duplicate passive directives; want one:\n%s", count, got)
			}
			for _, want := range []string{"ip ospf cost 10\n", "ip ospf authentication-key first-secret\n", "ip ospf area " + ids[0] + "\n"} {
				if !strings.Contains(got, want) {
					t.Errorf("first equivalent-area fragment missing %q:\n%s", want, got)
				}
			}
			for _, absent := range []string{"ip ospf cost 20\n", "ip ospf authentication-key second-secret\n", "ip ospf area " + ids[1] + "\n"} {
				if strings.Contains(got, absent) {
					t.Errorf("duplicate equivalent-area fragment emitted %q:\n%s", absent, got)
				}
			}
		})

		t.Run("ospfv3 "+name, func(t *testing.T) {
			ospf := &config.OSPFv3Config{Areas: []*config.OSPFv3Area{
				{ID: ids[0], Interfaces: []*config.OSPFv3Interface{{Name: "eth0", Cost: 10, Passive: ids[0] == "0"}}},
				{ID: ids[1], Interfaces: []*config.OSPFv3Interface{{Name: "eth0", Cost: 20, Passive: ids[1] == "0"}}},
			}}
			got := (&Manager{}).generateProtocols(nil, ospf, nil, nil, nil, "", 0, nil, nil)
			if count := strings.Count(got, "\ninterface eth0\n"); count != 1 {
				t.Fatalf("rendered %d interface blocks for equivalent area IDs; want one:\n%s", count, got)
			}
			if count := strings.Count(got, "ipv6 ospf6 passive\n"); count != 1 {
				t.Fatalf("rendered %d duplicate passive directives; want one:\n%s", count, got)
			}
			for _, want := range []string{"ipv6 ospf6 cost 10\n", "ipv6 ospf6 area " + ids[0] + "\n"} {
				if !strings.Contains(got, want) {
					t.Errorf("first equivalent-area fragment missing %q:\n%s", want, got)
				}
			}
			for _, absent := range []string{"ipv6 ospf6 cost 20\n", "ipv6 ospf6 area " + ids[1] + "\n"} {
				if strings.Contains(got, absent) {
					t.Errorf("duplicate equivalent-area fragment emitted %q:\n%s", absent, got)
				}
			}
		})
	}
}
