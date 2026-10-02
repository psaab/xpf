package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #11401: ospf6d accepts area <id> stub [no-summary] and
// area <id> nssa [no-summary] in router ospf6 config mode. Rendering only the
// per-interface `ipv6 ospf6 area` activation leaves the area's LSA policy at
// normal defaults, silently defeating Junos area-type configuration.
func TestOSPFv3AreaTypesRenderUnderRouterOspf6_11401(t *testing.T) {
	m := New()
	ospfv3 := &config.OSPFv3Config{
		RouterID: "10.0.0.1",
		Areas: []*config.OSPFv3Area{
			{ID: "0.0.0.1", AreaType: "stub"},
			{ID: "0.0.0.2", AreaType: "nssa"},
			{ID: "0.0.0.3", AreaType: "stub", NoSummary: true},
			{ID: "0.0.0.4", AreaType: "nssa", NoSummary: true},
			{ID: "0.0.0.5"}, // normal area stays at FRR defaults
		},
	}
	got := m.generateProtocols(nil, ospfv3, nil, nil, nil, "", 0, nil, nil)
	stanza := ospf6Stanza10037(t, got)
	for _, want := range []string{
		" area 0.0.0.1 stub\n",
		" area 0.0.0.2 nssa\n",
		" area 0.0.0.3 stub no-summary\n",
		" area 0.0.0.4 nssa no-summary\n",
	} {
		if !strings.Contains(stanza, want) {
			t.Errorf("router ospf6 stanza missing %q:\n%s", want, stanza)
		}
	}
	if strings.Contains(stanza, "area 0.0.0.5") {
		t.Errorf("normal area must not get a type command:\n%s", stanza)
	}

	vrf := &config.OSPFv3Config{Areas: []*config.OSPFv3Area{
		{ID: "0.0.0.6", AreaType: "nssa", NoSummary: true},
	}}
	vrfGot := m.generateProtocols(nil, vrf, nil, nil, nil, "tenant", 0, nil, nil)
	if !strings.Contains(vrfGot, "router ospf6 vrf tenant\n area 0.0.0.6 nssa no-summary\n") {
		t.Errorf("routing-instance OSPFv3 type did not reach the FRR router stanza:\n%s", vrfGot)
	}
}
