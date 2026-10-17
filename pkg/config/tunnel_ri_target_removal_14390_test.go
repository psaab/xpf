package config

import (
	"strings"
	"testing"
)

// TestTolerantBadTunnelRITargetRemovesTunnel14390 pins #14390: on the
// tolerant (lenient) load/sync path, a tunnel whose explicit
// routing-instance target is undefined, a forwarding instance, or
// reserved for the management VRF must be REMOVED (the #9909 posture),
// not cleared into the default routing domain. Clearing installed the
// tunnel in domain 0 — a VRF escape from the domain the operator chose.
//
// Controls: a valid VRF target and a tunnel with no explicit target
// must survive lenient compile unchanged.
func TestTolerantBadTunnelRITargetRemovesTunnel14390(t *testing.T) {
	badTargets := []struct {
		name         string
		target       string
		instanceType string
	}{
		{name: "undefined", target: "missing"},
		{name: "forwarding", target: "fwd", instanceType: "forwarding"},
		{name: "reserved management", target: "mgmt"},
	}
	for _, level := range []string{"interface", "unit"} {
		for _, tc := range badTargets {
			t.Run(level+"/"+tc.name, func(t *testing.T) {
				cfg, err := CompileConfigLenient(tunnelRITargetTree12520(t, tc.target, level, tc.instanceType))
				if err != nil {
					t.Fatalf("tolerant compile rejected bad target %q: %v", tc.target, err)
				}
				// Exactly one #12520 warning naming the target.
				warnings := 0
				for _, w := range cfg.Warnings {
					if strings.Contains(w, "#12520") && strings.Contains(w, tc.target) {
						warnings++
					}
				}
				if warnings != 1 {
					t.Fatalf("got %d #12520 warnings naming %q, want 1: %v", warnings, tc.target, cfg.Warnings)
				}
				ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
				if ifc == nil {
					t.Fatalf("interface gr-0/0/0 missing after tolerant compile")
				}
				if level == "interface" {
					if ifc.Tunnel != nil {
						t.Fatalf("bad-target interface tunnel survived tolerant compile: %+v (RoutingInstance=%q)", ifc.Tunnel, ifc.Tunnel.RoutingInstance)
					}
					if _, ok := ifc.Units[0]; ok {
						t.Fatalf("unit inheriting removed interface tunnel survived: %+v", ifc.Units[0])
					}
				} else {
					if _, ok := ifc.Units[0]; ok {
						t.Fatalf("unit carrying bad-target tunnel survived tolerant compile: %+v", ifc.Units[0])
					}
				}
				for _, ep := range EmitTunnelEndpointNames(cfg) {
					t.Errorf("tunnel endpoint %s emitted after bad-target removal (RoutingInstance=%q)", ep.Name, ep.Tunnel.RoutingInstance)
				}
			})
		}
	}

	t.Run("valid VRF target survives lenient", func(t *testing.T) {
		cfg, err := CompileConfigLenient(tunnelRITargetTree12520(t, "blue", "interface", "virtual-router"))
		if err != nil {
			t.Fatalf("tolerant compile rejected valid VRF target: %v", err)
		}
		if got := tunnelConfigAtLevel12520(cfg, "interface"); got == nil || got.RoutingInstance != "blue" {
			t.Fatalf("valid tunnel = %+v, want RoutingInstance blue", got)
		}
		if eps := EmitTunnelEndpointNames(cfg); len(eps) != 1 {
			t.Fatalf("emitted endpoints = %v, want 1", eps)
		}
	})

	t.Run("no explicit target survives lenient", func(t *testing.T) {
		cfg, err := CompileConfigLenient(treeFromSet(t, []string{
			"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
			"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
			"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
		}))
		if err != nil {
			t.Fatalf("tolerant compile: %v", err)
		}
		if got := tunnelConfigAtLevel12520(cfg, "interface"); got == nil {
			t.Fatalf("untargeted tunnel removed on tolerant compile")
		}
		if eps := EmitTunnelEndpointNames(cfg); len(eps) != 1 {
			t.Fatalf("emitted endpoints = %v, want 1", eps)
		}
	})

	// Non-colliding IPIP tunnel with a bad target: same removal via the
	// shared claim set (no GRE-collision belt covers it today).
	t.Run("ipip bad target removed", func(t *testing.T) {
		cfg, err := CompileConfigLenient(treeFromSet(t, []string{
			"set interfaces ip-0/0/0 tunnel source 192.0.2.1",
			"set interfaces ip-0/0/0 tunnel destination 192.0.2.2",
			"set interfaces ip-0/0/0 tunnel routing-instance destination missing",
			"set interfaces ip-0/0/0 unit 0 family inet address 10.10.10.1/30",
		}))
		if err != nil {
			t.Fatalf("tolerant compile: %v", err)
		}
		ifc := cfg.Interfaces.Interfaces["ip-0/0/0"]
		if ifc != nil && ifc.Tunnel != nil {
			t.Fatalf("bad-target IPIP tunnel survived: %+v", ifc.Tunnel)
		}
		for _, ep := range EmitTunnelEndpointNames(cfg) {
			t.Errorf("IPIP endpoint %s emitted after removal", ep.Name)
		}
	})

	// Sibling control: an interface tunnel with a bad target is removed,
	// but a unit on the same interface whose own tunnel targets a valid
	// VRF (authored explicitly, overriding the cloned bad target) survives.
	t.Run("valid unit tunnel survives bad interface target", func(t *testing.T) {
		cfg, err := CompileConfigLenient(treeFromSet(t, []string{
			"set interfaces gr-0/0/0 tunnel source 192.0.2.1",
			"set interfaces gr-0/0/0 tunnel destination 192.0.2.2",
			"set interfaces gr-0/0/0 tunnel routing-instance destination missing",
			"set interfaces gr-0/0/0 unit 0 family inet address 10.10.10.1/30",
			"set interfaces gr-0/0/0 unit 1 tunnel source 192.0.2.5",
			"set interfaces gr-0/0/0 unit 1 tunnel destination 192.0.2.6",
			"set interfaces gr-0/0/0 unit 1 tunnel routing-instance destination blue",
			"set interfaces gr-0/0/0 unit 1 family inet address 10.10.20.1/30",
			"set routing-instances blue instance-type virtual-router",
		}))
		if err != nil {
			t.Fatalf("tolerant compile: %v", err)
		}
		ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
		if ifc.Tunnel != nil {
			t.Fatalf("bad interface tunnel survived: %+v", ifc.Tunnel)
		}
		u1, ok := ifc.Units[1]
		if !ok || u1 == nil || u1.Tunnel == nil || u1.Tunnel.RoutingInstance != "blue" {
			t.Fatalf("valid unit tunnel not preserved: %v", ifc.Units)
		}
		if _, ok := ifc.Units[0]; ok {
			t.Fatalf("inheriting unit 0 survived interface removal: %+v", ifc.Units[0])
		}
	})
}
