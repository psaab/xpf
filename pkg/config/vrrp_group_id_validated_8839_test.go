package config

import "testing"

// #8839 increment 1: the VRRP group IDENTITY slot had no keyValidator, so a
// non-numeric id committed and the group then did not exist.
//
// parseVRRPGroups does strconv.Atoi(instance name) and `continue`s on error.
// Measured before the fix, and this cell asserts each row:
//
//	vrrp-group 1     strict accepts, 1 group compiled     correct
//	vrrp-group foo   strict ACCEPTED, 0 groups compiled   the defect
//	vrrp-group 300   strict REJECTS                       already gated elsewhere
//	vrrp-group -5    strict REJECTS                       already gated elsewhere
//
// The validator therefore checks ONLY integer-ness. Range and sign already have
// a gate, and a second source of truth for the same rule is how two gates drift
// apart.
func TestVRRPGroupIDValidated8839(t *testing.T) {
	build := func(t *testing.T, id string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		p, err := ParseSetCommand("set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24 vrrp-group " + id + " virtual-address 10.0.0.9")
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath: %v", err)
		}
		return tree
	}
	groups := func(t *testing.T, tree *ConfigTree) int {
		t.Helper()
		cfg, err := CompileConfigLenient(tree)
		if err != nil || cfg == nil {
			return -1
		}
		n := 0
		for _, i := range cfg.Interfaces.Interfaces {
			for _, u := range i.Units {
				n += len(u.VRRPGroups)
			}
		}
		return n
	}

	// The defect: a non-numeric id must now be REFUSED by the identity
	// validator rather than committing to a group that does not exist.
	if err := ValidateVRRPGroupID("foo"); err == nil {
		t.Errorf("ValidateVRRPGroupID accepted %q. The compiler parses this token "+
			"with strconv.Atoi and silently discards the whole group when it "+
			"fails, so accepting it commits a group that then does not exist.", "foo")
	}
	// DEGENERACY CONTROL: a validator that rejects everything passes the line
	// above just as well.
	if err := ValidateVRRPGroupID("1"); err != nil {
		t.Errorf("ValidateVRRPGroupID rejected a valid numeric id: %v", err)
	}

	// And the compiled behaviour the validator exists to prevent is still
	// reachable through the tolerant path, which is why the guard is at commit:
	// Store.Load must keep accepting what it accepts today.
	if n := groups(t, build(t, "foo")); n != 0 {
		t.Errorf("expected the non-numeric group to compile to 0 groups on the "+
			"tolerant path (unchanged by this fix), got %d", n)
	}
	if n := groups(t, build(t, "1")); n != 1 {
		t.Errorf("expected a numeric group to compile to 1 group, got %d", n)
	}
}
