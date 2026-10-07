package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestRedistributePolicyMapsAreProtocolSpecific12065(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PrefixLists: map[string]*config.PrefixList{
			"TENS": {Name: "TENS", Prefixes: []string{"10.0.0.0/8"}},
			"CONN": {Name: "CONN", Prefixes: []string{"192.0.2.0/24"}},
		},
		PolicyStatements: map[string]*config.PolicyStatement{
			"TO-OSPF": {
				Name: "TO-OSPF",
				Terms: []*config.PolicyTerm{
					{Name: "static-only", FromProtocols: []string{"static"}, PrefixList: []string{"TENS"}, Action: "accept"},
					{Name: "connected-only", FromProtocols: []string{"direct"}, PrefixList: []string{"CONN"}, Action: "accept"},
				},
				DefaultAction: "reject",
			},
		},
	}
	fc := &FullConfig{
		PolicyOptions: po,
		OSPF: &config.OSPFConfig{
			Areas:  []*config.OSPFArea{{ID: "0.0.0.0"}},
			Export: []string{"TO-OSPF"},
		},
	}

	got := New().buildManagedSection(fc)
	for _, want := range []string{
		"redistribute connected route-map TO-OSPF-connected-xpf-redist\n",
		"redistribute static route-map TO-OSPF-static-xpf-redist\n",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing protocol-specific attachment %q:\n%s", want, got)
		}
	}

	staticMap := routeMapBlock12065(got, "TO-OSPF-static-xpf-redist")
	connectedMap := routeMapBlock12065(got, "TO-OSPF-connected-xpf-redist")
	if staticMap == "" || connectedMap == "" {
		t.Fatalf("protocol-specific route-map definition missing:\n%s", got)
	}
	if !strings.Contains(staticMap, "match ip address prefix-list TENS") || strings.Contains(staticMap, "match ip address prefix-list CONN") {
		t.Errorf("static route-map has terms outside static's policy subset:\n%s", staticMap)
	}
	if !strings.Contains(connectedMap, "match ip address prefix-list CONN") || strings.Contains(connectedMap, "match ip address prefix-list TENS") {
		t.Errorf("connected route-map has terms outside connected's policy subset:\n%s", connectedMap)
	}
	for name, body := range map[string]string{"static": staticMap, "connected": connectedMap} {
		if strings.Contains(body, "match source-protocol ") {
			t.Errorf("%s IGP route-map uses unsupported source-protocol match:\n%s", name, body)
		}
	}
}

func routeMapBlock12065(configText, name string) string {
	header := "route-map " + name + " "
	var body strings.Builder
	started := false
	for _, line := range strings.Split(configText, "\n") {
		if strings.HasPrefix(line, "route-map ") {
			if started && !strings.HasPrefix(line, header) {
				break
			}
			started = strings.HasPrefix(line, header)
		}
		if started {
			body.WriteString(line)
			body.WriteByte('\n')
		}
	}
	return body.String()
}
