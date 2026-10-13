package config

import (
	"testing"
)

// #9156 (V020): a flat-set run under `tunnel` whose head is an UNTYPED leaf
// carried every later statement past the strict commit gate and the reader kept
// only the head.
//
// Every arm carries the SEPARATE-LINES spelling of the identical statement as
// the oracle in the same run. Without it a cell cannot tell "the run expanded"
// from "my fixture never reached the tunnel reader".

func tunnelSet9156(t *testing.T, lines ...string) *TunnelConfig {
	t.Helper()
	tree := &ConfigTree{}
	lines = append(lines, "set routing-instances VR1 instance-type virtual-router")
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("parse %q: %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", l, err)
		}
	}
	if err := SchemaValidateWithDefinitions(tree, tree, nil); err != nil {
		t.Fatalf("STRICT REJECT (the arm cannot be read): %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	for _, ifc := range cfg.Interfaces.Interfaces {
		for _, u := range ifc.Units {
			if u.Tunnel != nil {
				return u.Tunnel
			}
		}
		if ifc.Tunnel != nil {
			return ifc.Tunnel
		}
	}
	t.Fatalf("no tunnel compiled")
	return nil
}

func TestTunnelFlatRunSurvivesAnUntypedHead9156(t *testing.T) {
	// ORACLE: the same two statements on separate lines.
	oracle := tunnelSet9156(t,
		"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 unit 0 tunnel destination 10.0.0.2",
	)
	if oracle.Source != "10.0.0.1" || oracle.Destination != "10.0.0.2" {
		t.Fatalf("ORACLE: separate lines give src=%q dst=%q — the control is broken, so "+
			"no arm below can be read", oracle.Source, oracle.Destination)
	}

	// #9157 MOVED THE ADMISSION HEAD, and this is the part of the change that
	// touches another issue's guard, so it is written down rather than absorbed.
	//
	// Every arm below used `keepalive-retry 5` as the untyped head. #9157 typed
	// that leaf (ValueInteger, 1..255) because an unbounded retry count made the
	// runtime's `Failures >= MaxRetries` check unreachable, and a TYPED head is
	// rejected by validateModifierChild:
	//
	//	set … tunnel keepalive-retry 5 source 10.0.0.1 destination 10.0.0.2
	//	  -> interfaces gr-0/0/0 unit 0 tunnel keepalive-retry:
	//	     unknown modifier "source"
	//
	// So these four arms would t.Fatalf on the STRICT REJECT and stop measuring
	// what they are for. The cell's SUBJECT is "an untyped head must not swallow
	// the run", not "keepalive-retry specifically", and `routing-instance` is the
	// container's OTHER untyped head -- named as such by #9156's own doc comment,
	// still untyped, and already exercised by the sibling cell below. Re-pointing
	// the fixture keeps the subject; deleting the arms would have removed the
	// coverage while looking like a passing suite.
	//
	// The head that LEFT is pinned in the other direction by
	// TestKeepaliveRetryHeadIsRejectedOnceTyped9157, so "keepalive-retry no
	// longer admits a run" is asserted rather than merely no longer tested.
	for _, tc := range []struct {
		name  string
		lines []string
	}{
		{"A: head swallows BOTH endpoints", []string{
			"set interfaces gr-0/0/0 unit 0 tunnel routing-instance destination VR1 source 10.0.0.1 destination 10.0.0.2",
		}},
		{"B: source on its own line, DESTINATION eaten", []string{
			"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1",
			"set interfaces gr-0/0/0 unit 0 tunnel routing-instance destination VR1 destination 10.0.0.2",
		}},
		{"C: destination on its own line, SOURCE eaten", []string{
			"set interfaces gr-0/0/0 unit 0 tunnel destination 10.0.0.2",
			"set interfaces gr-0/0/0 unit 0 tunnel routing-instance destination VR1 source 10.0.0.1",
		}},
		{"interface-level, not unit-level", []string{
			"set interfaces gr-0/0/0 tunnel routing-instance destination VR1 source 10.0.0.1 destination 10.0.0.2",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tunnelSet9156(t, tc.lines...)
			if got.Source != oracle.Source || got.Destination != oracle.Destination {
				t.Errorf("one-line run gives src=%q dst=%q; the separate-lines oracle "+
					"gives src=%q dst=%q. B is the harmful shape: a source with no "+
					"destination passes the routing side's endpoint screen, so the TUN "+
					"is created, brought up and addressed while the dataplane holds no "+
					"endpoint for it",
					got.Source, got.Destination, oracle.Source, oracle.Destination)
			}
		})
	}
}

// TestTunnelRoutingInstanceHeadDoesNotEatTheSource9156 is the second admission
// head, and it is a DIFFERENT shape: `routing-instance` owns a body, so the run
// nests two levels down and expandFlatRun alone cannot see it.
//
//	tunnel routing-instance destination VR1 source 10.0.0.1
//	  [routing-instance] > [destination VR1] > [source 10.0.0.1]
//	                                            ^ a leaf of TUNNEL, illegal here
//
// hoistAndSplitRun8939 lifts it precisely because it is UNAMBIGUOUSLY foreign —
// legal in `tunnel`, illegal under `routing-instance`.
func TestTunnelRoutingInstanceHeadDoesNotEatTheSource9156(t *testing.T) {
	oracle := tunnelSet9156(t,
		"set interfaces gr-0/0/0 unit 0 tunnel routing-instance destination VR1",
		"set interfaces gr-0/0/0 unit 0 tunnel source 10.0.0.1",
	)
	got := tunnelSet9156(t,
		"set interfaces gr-0/0/0 unit 0 tunnel routing-instance destination VR1 source 10.0.0.1",
	)
	if oracle.Source != "10.0.0.1" {
		t.Fatalf("ORACLE: separate lines give src=%q, want 10.0.0.1", oracle.Source)
	}
	if got.Source != oracle.Source {
		t.Errorf("one-line run gives src=%q, the oracle gives src=%q", got.Source, oracle.Source)
	}
	if got.RoutingInstance != oracle.RoutingInstance {
		t.Errorf("lifting `source` must not disturb the routing-instance: one-line %q, "+
			"oracle %q", got.RoutingInstance, oracle.RoutingInstance)
	}
}

// TestTypedHeadIsStillRejected9156 pins the arm that already worked.
//
// The gate rejects a run whose head is TYPED, and that rejection is the reason
// the untyped-head form was the only operator-reachable spelling. Nothing here
// should relax it: expanding a run at the READER must not make the strict gate
// accept a spelling it refused.
func TestTypedHeadIsStillRejected9156(t *testing.T) {
	tree := &ConfigTree{}
	for _, l := range []string{
		"set interfaces gr-0/0/0 unit 0 tunnel destination 10.0.0.2 keepalive-retry 5",
	} {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("%v", err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("%v", err)
		}
	}
	err := SchemaValidateWithDefinitions(tree, tree, nil)
	if err == nil {
		t.Fatalf("a TYPED head must still be rejected — the run expansion is a READER " +
			"change and must not widen what the commit gate accepts")
	}
	if !contains9156(err.Error(), "unknown modifier") {
		t.Errorf("the rejection must still name the modifier: %v", err)
	}
}

func contains9156(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}

// TestTunnelEndpointPredicateIsShared9156 pins the ONE predicate.
//
// EmitTunnelEndpointNames (what the DATAPLANE learns) required both endpoints;
// collectAppliedTunnels (what the ROUTING side creates) required only a source,
// and its per-unit loop required nothing at all. That disagreement is what turns
// a lost `destination` into a device that is created, brought up and addressed
// while the dataplane holds no endpoint for it.
func TestTunnelEndpointPredicateIsShared9156(t *testing.T) {
	for _, tc := range []struct {
		name string
		tun  *TunnelConfig
		want bool
	}{
		{"both endpoints", &TunnelConfig{Mode: "gre", Source: "10.0.0.1", Destination: "10.0.0.2"}, true},
		{"source only — the blackhole shape", &TunnelConfig{Mode: "gre", Source: "10.0.0.1"}, false},
		{"destination only", &TunnelConfig{Mode: "gre", Destination: "10.0.0.2"}, false},
		{"neither", &TunnelConfig{Mode: "gre"}, false},
		{"wireguard needs neither (#1432/#1736)", &TunnelConfig{Mode: "wireguard"}, true},
		{"nil", nil, false},
	} {
		if got := TunnelHasUsableEndpoints(tc.tun); got != tc.want {
			t.Errorf("%s: TunnelHasUsableEndpoints = %v, want %v", tc.name, got, tc.want)
		}
	}

	// AGREEMENT, not restatement: the emitter must admit exactly what the
	// predicate admits. A cell that only tested the predicate would pass while
	// the emitter kept its own copy.
	cfg := &Config{}
	cfg.Interfaces.Interfaces = map[string]*InterfaceConfig{
		"gr-0/0/0": {Name: "gr-0/0/0", Tunnel: &TunnelConfig{Name: "gr-0-0-0", Mode: "gre", Source: "10.0.0.1"}},
		"gr-0/0/1": {Name: "gr-0/0/1", Tunnel: &TunnelConfig{Name: "gr-0-0-1", Mode: "gre", Source: "10.0.0.1", Destination: "10.0.0.2"}},
	}
	names := EmitTunnelEndpointNames(cfg)
	if len(names) != 1 {
		t.Fatalf("emitter returned %d endpoints, want 1 — only the complete tunnel", len(names))
	}
	if names[0].Name != "gr-0/0/1" {
		t.Errorf("emitter kept %q, want the tunnel with BOTH endpoints", names[0].Name)
	}
}
