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

func TestRedistProtocolMapUnknownTokenNoGeneratedMap12065(t *testing.T) {
	// Generated-vs-generated collision with canonical tokens (#14698):
	// policy "A" with proto token "b" would have generated
	// "A-b-xpf-redist" pre-fix only if "b" passed through raw — it
	// did via the old "b-static" fixture, whose final name
	// "A-b-static-xpf-redist" collided with policy "A-b" proto
	// "static". Post-#14698 unknown tokens enrol nothing, so that
	// exact algebra is unreachable; the reachable canonical shape is
	// the reserved-suffix operator policy below, plus a direct unit
	// pin that the generated-vs-generated branch still fires when two
	// enrolled (policy, proto) pairs produce the same final name —
	// constructible only via a proto token that canonicalizes onto
	// another policy's name segment: policy "A" proto "static"
	// generates "A-static-xpf-redist"; policy "A-static" proto
	// "xpf-redist" is not a known proto, so instead assert the belt
	// over the alias pair: "A" [direct] and "A" is one policy. The
	// branch is therefore exercised here through its reachable
	// sibling: an operator policy named exactly a generated name
	// (already covered by TestRedistProtocolMapCollisionRefused12065)
	// and, for generated-vs-generated, by feeding the belt a policy
	// set where two policies generate the same name through the
	// direct->connected canonicalization across a name boundary:
	// "A-connected" [static] generates "A-connected-static-xpf-redist"
	// and "A" [connected, static] generates both
	// "A-connected-xpf-redist" and "A-static-xpf-redist" — distinct.
	// Hence: assert no false refusal for the canonical set, and that
	// an unknown token generates nothing to collide.
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
	if err := redistProtocolMapCollision(po); err != nil {
		t.Fatalf("unknown-token policy must generate no map to collide, got %v", err)
	}
	// Control: the canonical pair alone is clean.
	po2 := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"A-b": {
				Name:  "A-b",
				Terms: []*config.PolicyTerm{{Name: "t", FromProtocols: []string{"static"}, Action: "accept"}},
			},
		},
	}
	if err := redistProtocolMapCollision(po2); err != nil {
		t.Fatalf("canonical policy flagged: %v", err)
	}
}

// Generated-vs-generated branch (#12065) still fires post-#14698 via
// frrName aliasing: policies "A b" and "A_b" with proto static both
// generate a redist map; frrName hashes single-token-unsafe names, so
// use the reachable alias instead — two policies whose names are the
// same single token after the map-name join is impossible, so drive
// the branch through redistProtocolMapCollisionFiltered directly with
// a protocolsFor that returns the same proto for both policies.
func TestRedistProtocolMapGeneratedVsGeneratedBranch12065(t *testing.T) {
	po := &config.PolicyOptionsConfig{
		PolicyStatements: map[string]*config.PolicyStatement{
			"A":   {Name: "A", Terms: []*config.PolicyTerm{{Name: "t", FromProtocols: []string{"static"}, Action: "accept"}}},
			"A-b": {Name: "A-b", Terms: []*config.PolicyTerm{{Name: "t", FromProtocols: []string{"static"}, Action: "accept"}}},
		},
	}
	err := redistProtocolMapCollisionFiltered(po, func(ps *config.PolicyStatement) []string {
		// Force both policies onto the same generated name:
		// "A" + "b-static" and "A-b" + "static" both yield
		// "A-b-static-xpf-redist" at the name-algebra level.
		if ps.Name == "A" {
			return []string{"b-static"}
		}
		return []string{"static"}
	})
	if err == nil || !strings.Contains(err.Error(), "same redistribute route-map") {
		t.Fatalf("expected generated-vs-generated refusal, got %v", err)
	}
}
