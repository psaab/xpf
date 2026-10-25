package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #16577: a tolerant-loaded term poisoned to reject keeps its authored
// unknown protocol token in FromProtocols; the renderer must omit the
// `match source-protocol` line (FRR would reject it and degrade the whole
// managed reload) while still rendering the bare deny. Junos ospf3 renders
// as ospf6 through the SSOT alias.
func TestPolicyRenderOmitsUnknownSourceProtocol16577(t *testing.T) {
	m := &Manager{frrConf: "/dev/null"}
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"P": {
				Name: "P",
				Terms: []*config.PolicyTerm{
					{Name: "bad", FromProtocols: []string{"aggregate"}, Action: "reject"},
					{Name: "v3", FromProtocols: []string{"ospf3"}, Action: "accept"},
					{Name: "ok", FromProtocols: []string{"static"}, Action: "accept"},
				},
			},
		},
	}
	got := m.generatePolicyOptions(po, nil)
	if strings.Contains(got, "source-protocol aggregate") {
		t.Errorf("renderer emitted the FRR-invalid token:\n%s", got)
	}
	if !strings.Contains(got, "route-map P deny 10\nexit") {
		t.Errorf("poisoned term must render as a bare deny sequence:\n%s", got)
	}
	if !strings.Contains(got, "match source-protocol ospf6") {
		t.Errorf("ospf3 must render as ospf6:\n%s", got)
	}
	if !strings.Contains(got, "match source-protocol static") {
		t.Errorf("resolvable sibling term lost its match:\n%s", got)
	}
}
