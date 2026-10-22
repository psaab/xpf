package config

import (
	"strings"
	"testing"
)

// #8845: after #8844 closed the SPELLING route into a silently-broken PFS,
// three VALUE routes remained, all silent, and they are not the same defect:
//
//	keys group14    PFSGroup=14   correct
//	keys nonsense   PFSGroup=0    silently DISABLED
//	keys            PFSGroup=0    silently DISABLED (empty value)
//	keys group99    PFSGroup=99   PFS nominally ON with a group that does NOT EXIST
//
// The first two are the #8844 property again -- indistinguishable from never
// configuring PFS, because 0 is a legitimate "disabled" value. `group99` is the
// OPPOSITE failure sharing one line of code: not disabled, misconfigured, and it
// fails later and elsewhere with a diagnostic that will not name this stanza.
//
// REMEDY: the leaf becomes a TYPED leaf carrying ValidateDHGroup, which is the
// single source of truth already shared with the proposal-level `dh-group` leaf
// and, through config.DHGroupKeyword, with ipsec.formatDHGroup (#8597). No
// second list of valid groups is introduced.
//
// The commit path rejects all three; the TOLERANT path is deliberately
// unchanged, which is the binding constraint and is asserted below.
func TestPFSKeysValueRoutes8845(t *testing.T) {
	build := func(t *testing.T, val string) *ConfigTree {
		t.Helper()
		cmd := "set security ipsec policy p1 perfect-forward-secrecy keys"
		if val != "" {
			cmd += " " + val
		}
		tree := &ConfigTree{}
		p, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("parse %q: %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("setpath %q: %v", cmd, err)
		}
		return tree
	}

	// 1. All three broken routes are REJECTED at commit, each naming the value.
	for _, tc := range []struct{ name, val, want string }{
		{"invalid-group", "group99", "unsupported DH group 99"},
		{"non-numeric", "nonsense", "not a valid DH group"},
		{"empty-value", "", "missing value"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := SchemaValidate(build(t, tc.val))
			if err == nil {
				t.Fatalf("commit ACCEPTED `keys %s`. Before #8845 this compiled to "+
					"PFSGroup=%s -- either silently disabled, or nominally enabled "+
					"with a group strongSwan will refuse. Neither is detectable "+
					"downstream, because 0 is a legitimate \"disabled\" value.",
					tc.val, map[string]string{"group99": "99", "nonsense": "0", "": "0"}[tc.val])
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("commit rejected `keys %s` but not for the expected reason.\n"+
					"  got:  %v\n  want substring: %q\n"+
					"A rejection for the WRONG reason reads as a working guard.",
					tc.val, err, tc.want)
			}
		})
	}

	// 2. DEGENERACY CONTROL. A validator that rejected everything would satisfy
	//    every assertion above. Valid groups must pass, and be COMPILED.
	t.Run("valid-groups-accepted", func(t *testing.T) {
		for _, v := range []string{"group14", "14", "group19", "group2"} {
			tree := build(t, v)
			if err := SchemaValidate(tree); err != nil {
				t.Errorf("commit rejected the valid group %q: %v", v, err)
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("compile %q: %v", v, err)
			}
			if p := cfg.Security.IPsec.Policies["p1"]; p == nil || p.PFSGroup == 0 {
				t.Errorf("valid group %q did not reach the config (PFSGroup=0)", v)
			}
		}
	})

	// 3. THE BINDING CONSTRAINT: the tolerant path must keep accepting all
	//    three. `keys` is reachable on that path, and a node booting an already
	//    persisted config must not start failing to load.
	t.Run("tolerant-path-still-accepts", func(t *testing.T) {
		for _, v := range []string{"group99", "nonsense", ""} {
			if _, err := CompileConfigLenient(build(t, v)); err != nil {
				t.Errorf("CompileConfigLenient REJECTED `keys %q`: %v\n"+
					"Store.Load and SyncApply use this path. A new rejection here "+
					"bricks a node that boots an existing config, which is why this "+
					"fix is a commit-time validator and NOT a compiler change.", v, err)
			}
		}
	})

	// 4. The validator is only ARMED because the leaf is a TYPED leaf.
	//    walkSchemaNode gates on isTypedLeaf() && validator != nil, so a
	//    validator on an untyped leaf is SILENTLY INERT -- it compiles, it reads
	//    as wired, and it never runs. Measured during this fix: with the
	//    validator alone and no valueType, SchemaValidate returned nil for
	//    group99 AND nonsense. This asserts the arming, not just the validator.
	t.Run("leaf-is-typed-so-the-validator-is-armed", func(t *testing.T) {
		n := setSchema.children["security"].children["ipsec"].children["policy"]
		if n == nil {
			t.Fatal("security ipsec policy not found")
		}
		pfs := n.children["perfect-forward-secrecy"]
		if pfs == nil {
			t.Fatal("perfect-forward-secrecy not declared (#8844)")
		}
		keys := pfs.children["keys"]
		if keys == nil {
			t.Fatal("`keys` not declared under perfect-forward-secrecy (#8844)")
		}
		if keys.validator == nil {
			t.Error("`keys` has no validator")
		}
		if !keys.isTypedLeaf() {
			t.Error("`keys` is not a TYPED leaf, so its validator is silently inert: " +
				"walkSchemaNode gates on isTypedLeaf() && validator != nil. Setting " +
				"a validator without a valueType looks wired and never runs.")
		}
	})
}
