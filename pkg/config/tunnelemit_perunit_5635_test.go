package config

import "testing"

// buildTree (ParseSetCommand + SetPath, NOT NewParser) is defined in
// compiler_equal_flow_worker_cap_test.go and reused here.

// findEmittedTunnel returns the emitted per-unit TunnelConfig for the given
// unit-qualified ref, or nil if the emitter did not produce that ref.
func findEmittedTunnel(eps []TunnelEndpointName, name string) *TunnelConfig {
	for _, ep := range eps {
		if ep.Name == name {
			return ep.Tunnel
		}
	}
	return nil
}

// TestEmitTunnelEndpointNamesPreservesPerUnitGREOverrides is the #5635
// RED-on-revert gate. A GRE interface carries BOTH an interface-level tunnel
// stanza and a per-unit tunnel stanza on unit 7 that overrides EVERY field —
// key, source and destination endpoint, TTL, and routing-instance — with
// values distinct from the interface-level defaults. The compiler stores those
// overrides in unit.Tunnel (cloneForUnit + the unit-level tunnel parse).
//
// Before the fix, EmitTunnelEndpointNames took the iface.Tunnel != nil branch
// and emitted the INTERFACE-LEVEL tunnel object for every unit, so the
// dataplane snapshot builder (buildTunnelEndpointSnapshots) and the commit-time
// collision gate saw the interface-level defaults for gr-0/0/0.7 and the
// per-unit key/endpoint/TTL/routing-instance were silently dropped from the
// emitted (round-tripped) config. The fix emits the unit's OWN TunnelConfig.
func TestEmitTunnelEndpointNamesPreservesPerUnitGREOverrides(t *testing.T) {
	cmds := []string{
		// Interface-level tunnel: complete endpoint + distinct key/ttl/RI.
		"set interfaces gr-0/0/0 tunnel source 10.0.0.1",
		"set interfaces gr-0/0/0 tunnel destination 10.0.0.2",
		"set interfaces gr-0/0/0 tunnel key 1000",
		"set interfaces gr-0/0/0 tunnel ttl 10",
		"set interfaces gr-0/0/0 tunnel routing-instance destination IFACE-VR",
		// Per-unit tunnel on unit 7 overriding EVERY field with distinct
		// values. cloneForUnit seeds it from the interface-level tunnel; the
		// unit-level parse then overrides each field.
		"set interfaces gr-0/0/0 unit 7 tunnel source 10.7.7.1",
		"set interfaces gr-0/0/0 unit 7 tunnel destination 10.7.7.2",
		"set interfaces gr-0/0/0 unit 7 tunnel key 7777",
		"set interfaces gr-0/0/0 unit 7 tunnel ttl 77",
		"set interfaces gr-0/0/0 unit 7 tunnel routing-instance destination UNIT-VR",
		"set interfaces gr-0/0/0 unit 7 family inet address 10.7.0.1/30",
		"set routing-instances IFACE-VR instance-type virtual-router",
		"set routing-instances UNIT-VR instance-type virtual-router",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}

	// Sanity: the compiler must have stored the per-unit overrides on
	// unit.Tunnel (this is the committed intent the emit must reflect).
	ifc := cfg.Interfaces.Interfaces["gr-0/0/0"]
	if ifc == nil || ifc.Tunnel == nil {
		t.Fatal("gr-0/0/0 interface-level tunnel not found")
	}
	u7 := ifc.Units[7]
	if u7 == nil || u7.Tunnel == nil {
		t.Fatal("gr-0/0/0 unit 7 per-unit tunnel not found")
	}
	if u7.Tunnel.Key != 7777 || u7.Tunnel.Source != "10.7.7.1" ||
		u7.Tunnel.Destination != "10.7.7.2" || u7.Tunnel.TTL != 77 ||
		u7.Tunnel.RoutingInstance != "UNIT-VR" {
		t.Fatalf("compiler did not store per-unit overrides: %+v", u7.Tunnel)
	}

	// The emit must carry the unit's own tunnel, not the interface-level one.
	emitted := EmitTunnelEndpointNames(cfg)
	tun := findEmittedTunnel(emitted, "gr-0/0/0.7")
	if tun == nil {
		t.Fatalf("gr-0/0/0.7 not emitted; got %d endpoints: %+v", len(emitted), emitted)
	}

	if tun.Key != 7777 {
		t.Errorf("emitted Key = %d, want 7777 (per-unit override dropped — #5635)", tun.Key)
	}
	if tun.Source != "10.7.7.1" {
		t.Errorf("emitted Source = %q, want 10.7.7.1 (per-unit override dropped — #5635)", tun.Source)
	}
	if tun.Destination != "10.7.7.2" {
		t.Errorf("emitted Destination = %q, want 10.7.7.2 (per-unit override dropped — #5635)", tun.Destination)
	}
	if tun.TTL != 77 {
		t.Errorf("emitted TTL = %d, want 77 (per-unit override dropped — #5635)", tun.TTL)
	}
	if tun.RoutingInstance != "UNIT-VR" {
		t.Errorf("emitted RoutingInstance = %q, want UNIT-VR (per-unit override dropped — #5635)", tun.RoutingInstance)
	}

	// Explicitly assert the emit did NOT fall back to the interface-level
	// defaults — this is precisely what the pre-fix code emitted.
	if tun.Key == ifc.Tunnel.Key && tun.Destination == ifc.Tunnel.Destination {
		t.Errorf("emitted the interface-level tunnel for gr-0/0/0.7 (key=%d dst=%q) — per-unit overrides lost",
			tun.Key, tun.Destination)
	}
}

// TestEmitTunnelEndpointNamesUnitWithoutStanzaInheritsInterfaceTunnel guards the
// fallback path the #5635 fix must not regress: an interface-level tunnel with a
// unit that has NO tunnel stanza still emits the interface-level tunnel for that
// unit (the interface-level endpoint applies to every unit).
func TestEmitTunnelEndpointNamesUnitWithoutStanzaInheritsInterfaceTunnel(t *testing.T) {
	cmds := []string{
		"set interfaces gr-0/0/0 tunnel source 198.51.100.1",
		"set interfaces gr-0/0/0 tunnel destination 198.51.100.2",
		"set interfaces gr-0/0/0 tunnel key 42",
		// unit 3 has no per-unit tunnel stanza — only an address.
		"set interfaces gr-0/0/0 unit 3 family inet address 10.3.0.1/30",
	}
	cfg, err := CompileConfig(buildTree(t, cmds))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	emitted := EmitTunnelEndpointNames(cfg)
	tun := findEmittedTunnel(emitted, "gr-0/0/0.3")
	if tun == nil {
		t.Fatalf("gr-0/0/0.3 not emitted; got %+v", emitted)
	}
	if tun.Source != "198.51.100.1" || tun.Destination != "198.51.100.2" || tun.Key != 42 {
		t.Errorf("no-stanza unit did not inherit interface-level tunnel: src=%q dst=%q key=%d",
			tun.Source, tun.Destination, tun.Key)
	}
}
