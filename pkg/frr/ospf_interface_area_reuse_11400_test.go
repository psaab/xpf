package frr

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestOSPFInterfaceAreaReuseRendererKeepsFirst11400(t *testing.T) {
	for _, tc := range []struct {
		name string
		v2   *config.OSPFConfig
		v3   *config.OSPFv3Config
		area string
		cost string
	}{
		{
			name: "ospfv2",
			v2: &config.OSPFConfig{Areas: []*config.OSPFArea{
				{ID: "0.0.0.0", Interfaces: []*config.OSPFInterface{{Name: "eth0", Cost: 10, Passive: true}}},
				{ID: "0.0.0.1", Interfaces: []*config.OSPFInterface{{Name: "eth0", Cost: 20}}},
			}},
			area: " ip ospf area 0.0.0.0\n",
			cost: " ip ospf cost 10\n",
		},
		{
			name: "ospfv3",
			v3: &config.OSPFv3Config{Areas: []*config.OSPFv3Area{
				{ID: "0.0.0.0", Interfaces: []*config.OSPFv3Interface{{Name: "eth0", Cost: 10, Passive: true}}},
				{ID: "0.0.0.1", Interfaces: []*config.OSPFv3Interface{{Name: "eth0", Cost: 20}}},
			}},
			area: " ipv6 ospf6 area 0.0.0.0\n",
			cost: " ipv6 ospf6 cost 10\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			previous := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
			defer slog.SetDefault(previous)

			got := (&Manager{}).generateProtocols(tc.v2, tc.v3, nil, nil, nil, "", 0, nil, nil)
			if count := strings.Count(got, "\ninterface eth0\n"); count != 1 {
				t.Fatalf("rendered %d interface blocks for one FRR interface; want first-area block only:\n%s", count, got)
			}
			if !strings.Contains(got, tc.area) || !strings.Contains(got, tc.cost) {
				t.Fatalf("first area assignment/settings were not preserved:\n%s", got)
			}
			if strings.Contains(got, "area 0.0.0.1") || strings.Contains(got, "cost 20") {
				t.Fatalf("later conflicting area reached the FRR output:\n%s", got)
			}
			if !strings.Contains(logs.String(), "dropping an "+map[bool]string{true: "OSPFv3", false: "OSPF"}[tc.v3 != nil]+" interface assigned to multiple areas") ||
				!strings.Contains(logs.String(), `interface=eth0`) || !strings.Contains(logs.String(), `dropped_area=0.0.0.1`) {
				t.Fatalf("renderer did not warn about the dropped area assignment: %s", logs.String())
			}
			if tc.v2 != nil && strings.Count(got, "passive-interface eth0\n") != 1 {
				t.Fatalf("OSPFv2 passive-interface setting was not deduplicated with the first area:\n%s", got)
			}
		})
	}
}
