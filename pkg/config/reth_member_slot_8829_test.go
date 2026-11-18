package config

import "testing"

func rethCfg8829(node int, members ...string) *Config {
	c := &Config{}
	c.Chassis.Cluster = &ClusterConfig{NodeID: node}
	c.Interfaces.Interfaces = map[string]*InterfaceConfig{}
	for _, m := range members {
		c.Interfaces.Interfaces[m] = &InterfaceConfig{Name: m, RedundantParent: "reth0"}
	}
	return c
}

// TestRethResolvesLocalMemberInBothSpellings8829 asserts the RESOLVED MEMBER,
// not that resolution returned something.
//
// #8829: on node 1, `reth0` resolved to `ge-0-0-0` — NODE 0's member — whenever
// the members were written in the operational dash spelling. RethToPhysical
// scores 2=local, 0=peer, 1=slot-unknown; InterfaceSlot returned -1 for a dash
// name, so BOTH members scored 1 and the tie broke ALPHABETICALLY.
//
// A node driving the peer's physical port is not a degraded mode. It is why
// this asserts WHICH member, and why "resolution succeeded" would be true in
// every broken case.
func TestRethResolvesLocalMemberInBothSpellings8829(t *testing.T) {
	for _, c := range []struct {
		name    string
		node    int
		members []string
		want    string
	}{
		{"node 0, slash", 0, []string{"ge-0/0/0", "ge-7/0/0"}, "ge-0/0/0"},
		{"node 1, slash", 1, []string{"ge-0/0/0", "ge-7/0/0"}, "ge-7/0/0"},
		{"node 0, DASH", 0, []string{"ge-0-0-0", "ge-7-0-0"}, "ge-0-0-0"},
		{"node 1, DASH", 1, []string{"ge-0-0-0", "ge-7-0-0"}, "ge-7-0-0"},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := rethCfg8829(c.node, c.members...).RethToPhysical()["reth0"]
			if got != c.want {
				t.Errorf("node %d resolved reth0 to %q, want %q. Driving the PEER's physical "+
					"member is not a degraded mode — the local node programs a port it does "+
					"not own (#8829)", c.node, got, c.want)
			}
		})
	}
}

// TestInterfaceSlotParsesBothSpellings8829 pins the parse, including the names
// that must STAY unparseable — every caller's `>= 0` guard depends on -1
// meaning "carries no FPC slot", so widening it too far would make unrelated
// names participate in node-alignment decisions.
func TestInterfaceSlotParsesBothSpellings8829(t *testing.T) {
	for _, c := range []struct {
		name string
		want int
	}{
		{"ge-0/0/7", 0}, {"ge-7/0/7", 7}, {"xe-3/1/2", 3}, {"ge-0/0/0.0", 0},
		{"ge-0-0-7", 0}, {"ge-7-0-7", 7}, {"ge-0-0-0.0", 0},
		// Must remain -1: no FPC slot at all.
		{"fab0", -1}, {"em0", -1}, {"reth0", -1}, {"st0.1", -1}, {"lo0", -1},
		// A dash that is not a slot number. NOTE `some-name` returns early (no
		// second separator) and so does NOT exercise the numeric guard — the
		// cases below do, and mutation showed they were missing: dropping the
		// Atoi error check SURVIVED until they were added, because every
		// "must stay -1" case bailed before reaching it.
		{"some-name", -1},
		{"ge-abc/0/0", -1},
		{"ge-abc-0-0", -1},
		{"ge--0-0", -1},
	} {
		if got := InterfaceSlot(c.name); got != c.want {
			t.Errorf("InterfaceSlot(%q) = %d, want %d. A name with no FPC slot must stay -1: "+
				"callers gate node-alignment on `>= 0`, so a false positive makes an "+
				"unrelated name subject to cluster-node checks (#8829)", c.name, got, c.want)
		}
	}
}

// TestAlignmentGateSeesBothSpellings8829 is the second and more dangerous half:
// the gate is `InterfaceSlot(...) >= 0`, so the spelling that could not be
// parsed was the spelling that SKIPPED VALIDATION.
//
// Asserts the strict/tolerant split explicitly. A wrong-node name must be
// refused at commit and must still LOAD on the tolerant path — otherwise this
// fix turns a misresolving config into an unbootable one, which is the #8814
// shape.
func TestAlignmentGateSeesBothSpellings8829(t *testing.T) {
	// `node 0` is the leaf the compiler reads. The fixture used to spell it
	// `node-id 0`, which nothing read: it was dropped silently, and the
	// default node 0 hid that, until #16456 (088d3c99ab) refused unknown
	// chassis cluster statements (#18847).
	mk := func(iface string) string {
		return `chassis { cluster { node 0; reth-count 1; ` +
			`authentication-key "s3cret-cluster-key-value"; } ` +
			`device-map { interface ` + iface + ` { pci 0000:01:00.0; } } }`
	}
	for _, c := range []struct {
		name       string
		iface      string
		wantReject bool
	}{
		// CONTROL: a LOCAL slot must stay acceptable, or "rejects" below could
		// mean the gate rejects everything.
		{"slash local slot 0", "ge-0/0/3", false},
		{"dash  local slot 0", "ge-0-0-3", false},
		{"slash PEER slot 7", "ge-7/0/3", true},
		{"dash  PEER slot 7", "ge-7-0-3", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			tr, perrs := NewParser(mk(c.iface)).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture must parse: %v", perrs)
			}
			_, serr := CompileConfig(tr)
			if c.wantReject && serr == nil {
				t.Errorf("strict commit ACCEPTED %q, whose FPC slot belongs to the PEER node. "+
					"The alignment gate is `InterfaceSlot(...) >= 0`, so a name it cannot "+
					"parse skips validation entirely (#8829)", c.iface)
			}
			if !c.wantReject && serr != nil {
				t.Errorf("strict commit rejected %q, which is local to this node: %v", c.iface, serr)
			}
			// The tolerant path must still load it either way (#1319): a
			// persisted config that committed under an older build must boot.
			if _, lerr := CompileConfigLenient(tr); lerr != nil {
				t.Errorf("CompileConfigLenient FAILED for %q: %v\nA node must boot a config "+
					"already on disk; tightening a commit gate must not make one "+
					"unbootable (#8829)", c.iface, lerr)
			}
		})
	}
}
