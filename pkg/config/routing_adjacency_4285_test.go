package config

import "testing"

func compileSetsAdj4285(t *testing.T, cmds []string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	// The schema gate must ACCEPT these leaves — before #4285/#4286 they were
	// unknown to setSchema. RED-on-revert: SchemaValidate rejects the unknown
	// leaf. (cfg is always nil at this gate; see schema_walk.go.)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("SchemaValidate rejected an adjacency leaf: %v", err)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return c
}

// #4285 (fable-review-167 R-1): OSPF/OSPFv3 interface hello/dead/retransmit
// timers and DR priority must survive the parser + compiler. RED-on-revert:
// the leaves drop silently (schema/compiler have no case) and the struct
// fields stay zero.
func TestOSPFInterfaceTimersCompiled_4285(t *testing.T) {
	c := compileSetsAdj4285(t, []string{
		"set protocols ospf area 0 interface ge-0-0-1 hello-interval 1",
		"set protocols ospf area 0 interface ge-0-0-1 dead-interval 3",
		"set protocols ospf area 0 interface ge-0-0-1 retransmit-interval 5",
		"set protocols ospf area 0 interface ge-0-0-1 priority 200",
		"set protocols ospf3 area 0 interface ge-0-0-1 hello-interval 2",
		"set protocols ospf3 area 0 interface ge-0-0-1 dead-interval 6",
		"set protocols ospf3 area 0 interface ge-0-0-1 retransmit-interval 7",
		"set protocols ospf3 area 0 interface ge-0-0-1 priority 0",
	})

	if c.Protocols.OSPF == nil || len(c.Protocols.OSPF.Areas) != 1 {
		t.Fatal("expected one compiled OSPF area")
	}
	ifs := c.Protocols.OSPF.Areas[0].Interfaces
	if len(ifs) != 1 {
		t.Fatalf("expected one OSPF interface, got %d", len(ifs))
	}
	v4 := ifs[0]
	if v4.HelloInterval != 1 || v4.DeadInterval != 3 || v4.RetransmitInt != 5 || v4.Priority != 200 || !v4.HasPriority {
		t.Errorf("OSPFv2 timers/priority not compiled: %+v", v4)
	}

	if c.Protocols.OSPFv3 == nil || len(c.Protocols.OSPFv3.Areas) != 1 {
		t.Fatal("expected one compiled OSPFv3 area")
	}
	v6 := c.Protocols.OSPFv3.Areas[0].Interfaces[0]
	if v6.HelloInterval != 2 || v6.DeadInterval != 6 || v6.RetransmitInt != 7 {
		t.Errorf("OSPFv3 timers not compiled: %+v", v6)
	}
	// priority 0 is a valid explicit value ("never DR"); HasPriority marks it
	// so it is not conflated with unset.
	if v6.Priority != 0 || !v6.HasPriority {
		t.Errorf("OSPFv3 priority 0 not compiled (Priority=%d HasPriority=%v)", v6.Priority, v6.HasPriority)
	}
}

// An OSPF interface without a `priority` leaf compiles to HasPriority == false
// so the renderer omits the line and FRR keeps its default DR priority.
// RED-on-revert: the HasPriority gate is required for this.
func TestOSPFInterfacePriorityUnsetSentinel_4285(t *testing.T) {
	c := compileSetsAdj4285(t, []string{
		"set protocols ospf area 0 interface ge-0-0-1 cost 5",
	})
	iface := c.Protocols.OSPF.Areas[0].Interfaces[0]
	if iface.HasPriority {
		t.Errorf("unset OSPF priority marked HasPriority=true (Priority=%d)", iface.Priority)
	}
}

// #4286 (fable-review-167 R-2): BGP group-level local-address (update-source),
// passive, hold-time, and per-group local-as must survive the parser +
// compiler and reach every neighbor in the group. RED-on-revert: the leaves
// drop silently.
//
// The peer is eBGP-shaped (peer-as 65002 != router local-as 65001): FRR's
// `neighbor X local-as` is an eBGP-oriented knob and can be rejected on an
// iBGP-shaped peer, so the local-as case is modelled on an eBGP peer.
func TestBGPGroupLocalAddressCompiled_4286(t *testing.T) {
	c := compileSetsAdj4285(t, []string{
		"set protocols bgp group ext local-address 10.255.0.1",
		"set protocols bgp group ext local-as 65100",
		"set protocols bgp group ext hold-time 30",
		"set protocols bgp group ext passive",
		"set protocols bgp local-as 65001",
		"set protocols bgp group ext neighbor 10.255.0.2 peer-as 65002",
	})

	if c.Protocols.BGP == nil || len(c.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("expected one compiled BGP neighbor")
	}
	n := c.Protocols.BGP.Neighbors[0]
	if n.LocalAddress != "10.255.0.1" {
		t.Errorf("neighbor LocalAddress = %q, want 10.255.0.1", n.LocalAddress)
	}
	if n.LocalAS != 65100 {
		t.Errorf("neighbor LocalAS = %d, want 65100", n.LocalAS)
	}
	if n.HoldTime != 30 {
		t.Errorf("neighbor HoldTime = %d, want 30", n.HoldTime)
	}
	if !n.Passive {
		t.Errorf("neighbor Passive = false, want true")
	}
}

// A per-neighbor local-address overrides the group default (Junos
// most-specific-wins).
func TestBGPNeighborLocalAddressOverride_4286(t *testing.T) {
	c := compileSetsAdj4285(t, []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group ibgp local-address 10.255.0.1",
		"set protocols bgp group ibgp neighbor 10.255.0.2 peer-as 65001",
		"set protocols bgp group ibgp neighbor 10.255.0.2 local-address 10.255.9.9",
	})
	n := c.Protocols.BGP.Neighbors[0]
	if n.LocalAddress != "10.255.9.9" {
		t.Errorf("per-neighbor LocalAddress override = %q, want 10.255.9.9", n.LocalAddress)
	}
}
