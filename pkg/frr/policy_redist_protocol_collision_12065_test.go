package frr

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func redistProtocolCollisionConfig(withOperatorCollision bool) *FullConfig {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"SHARED": {
				Name:  "SHARED",
				Terms: []*config.PolicyTerm{{Name: "static", FromProtocols: []string{"static"}, Action: "accept"}},
			},
		},
	}
	if withOperatorCollision {
		po.PolicyStatements["SHARED-static-xpf-redist"] = &config.PolicyStatement{
			Name:  "SHARED-static-xpf-redist",
			Terms: []*config.PolicyTerm{{Name: "term", FromProtocols: []string{"connected"}, Action: "accept"}},
		}
	}
	return &FullConfig{
		PolicyOptions: po,
		OSPF: &config.OSPFConfig{
			Areas:  []*config.OSPFArea{{ID: "0.0.0.0"}},
			Export: []string{"SHARED"},
		},
	}
}

func TestRedistProtocolMapCollisionRefused12065(t *testing.T) {
	fc := redistProtocolCollisionConfig(true)
	err := New().ApplyFull(fc)
	if err == nil {
		t.Fatal("ApplyFull accepted a generated-map/operator-policy collision")
	}
	for _, want := range []string{"SHARED", "SHARED-static-xpf-redist"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestRedistProtocolMapNoCollisionRenders12065(t *testing.T) {
	fc := redistProtocolCollisionConfig(false)
	if err := redistProtocolMapCollision(fc.PolicyOptions); err != nil {
		t.Fatalf("redistProtocolMapCollision flagged a non-colliding policy: %v", err)
	}
	got := New().buildManagedSection(fc)
	for _, want := range []string{
		"redistribute static route-map SHARED-static-xpf-redist\n",
		"route-map SHARED-static-xpf-redist permit 10\n",
		"route-map SHARED-static-xpf-redist deny 20\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q:\n%s", want, got)
		}
	}
}

func TestRedistProtocolMapGeneratedVsGeneratedRefused12065(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"A": {
				Name:  "A",
				Terms: []*config.PolicyTerm{{Name: "t", FromProtocols: []string{"b-static"}, Action: "accept"}},
			},
			"A-b": {
				Name:  "A-b",
				Terms: []*config.PolicyTerm{{Name: "t", FromProtocols: []string{"static"}, Action: "accept"}},
			},
		},
	}
	err := redistProtocolMapCollision(po)
	if err == nil || !strings.Contains(err.Error(), "same redistribute route-map") {
		t.Fatalf("expected generated-vs-generated refusal, got %v", err)
	}
}
