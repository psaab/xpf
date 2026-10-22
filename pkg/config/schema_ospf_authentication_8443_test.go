package config

import (
	"strings"
	"testing"
)

// ospfAuthTreeHier8443 builds one hierarchical tree from an inner spelling
// under an OSPF interface.
func ospfAuthTreeHier8443(t *testing.T, inner string) *ConfigTree {
	t.Helper()
	src := `protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { ` + inner + ` } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	return tree
}

// ospfAuthTreeSet8443 builds the same config through the flat-`set` path, which
// is how an operator actually types it. Both spellings must reach the same
// verdict; a gate that only holds on one of them is half a gate.
func ospfAuthTreeSet8443(t *testing.T, tail string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	line := "set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 " + tail
	path, err := ParseSetCommand(line)
	if err != nil {
		t.Fatalf("fixture did not parse: %v", err)
	}
	tree.SetPath(path)
	return tree
}

// TestOSPFInterfaceAuthenticationIsClosedWorld8443 is the #8443 gate.
//
// The harm is fail-OPEN and silent: an unmatched keyword under
// `authentication { }` leaves OSPFInterface.AuthType empty, the renderer emits
// nothing, and the adjacency comes up UNAUTHENTICATED while `show
// configuration` echoes the operator's authentication block back at them. Every
// surface they can check agrees with them.
func TestOSPFInterfaceAuthenticationIsClosedWorld8443(t *testing.T) {
	rows := []struct {
		name    string
		hier    string
		set     string
		wantErr string // "" = must COMMIT
	}{
		// The four shapes that committed clean and left the adjacency
		// unauthenticated or unkeyed.
		{
			name:    "a misspelled algorithm keyword is rejected",
			hier:    `authentication { md5-typo 1 { key "SEKRIT"; } }`,
			set:     `authentication md5-typo 1 key "SEKRIT"`,
			wantErr: "md5-typo",
		},
		{
			name: "a misspelled key child of md5 is rejected",
			hier: `authentication { md5 1 { keyy "SEKRIT"; } }`,
			set:  `authentication md5 1 keyy "SEKRIT"`,
			// closedWorld inherits DOWN, which is what reaches this level.
			wantErr: "keyy",
		},
		{
			name:    "the IS-IS/RIP authentication-type spelling is rejected under OSPF",
			hier:    `authentication-type md5;`,
			set:     `authentication-type md5`,
			wantErr: "authentication-type",
		},
		{
			// The same leaf with a value that IS meaningful elsewhere. The
			// refusal must not depend on the value looking wrong.
			name:    "authentication-type simple is rejected too",
			hier:    `authentication-type simple;`,
			set:     `authentication-type simple`,
			wantErr: "authentication-type",
		},

		// CONTROLS. Without these the rows above are satisfied by a gate that
		// rejects the whole subtree.
		{
			name: "md5 with a key still commits",
			hier: `authentication { md5 1 { key "SEKRIT"; } }`,
			set:  `authentication md5 1 key "SEKRIT"`,
		},
		{
			name: "simple-password still commits",
			hier: `authentication { simple-password "SEKRIT"; }`,
			set:  `authentication simple-password "SEKRIT"`,
		},
		{
			// A sibling leaf on the same interface, to show the closed world is
			// scoped to `authentication` and did not swallow the level above.
			name: "an unrelated interface leaf still commits",
			hier: `hello-interval 5;`,
			set:  `hello-interval 5`,
		},
	}

	check := func(t *testing.T, tree *ConfigTree, wantErr string) {
		t.Helper()
		err := SchemaValidate(tree)
		if wantErr == "" {
			if err != nil {
				t.Fatalf("must commit, got: %v", err)
			}
			return
		}
		if err == nil {
			t.Fatalf("must be rejected, but SchemaValidate accepted it")
		}
		if !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("rejected for the wrong reason\n  want substring: %q\n  got: %v",
				wantErr, err)
		}
	}

	for _, row := range rows {
		t.Run(row.name+" [hierarchical]", func(t *testing.T) {
			check(t, ospfAuthTreeHier8443(t, row.hier), row.wantErr)
		})
		t.Run(row.name+" [flat set]", func(t *testing.T) {
			check(t, ospfAuthTreeSet8443(t, row.set), row.wantErr)
		})
	}
}

// TestOSPFAuthClosedWorldReachesTheRoutingInstanceCopy8443 exists because the
// OSPF schema is duplicated: once at `protocols ospf` and once under
// `routing-instances <name> protocols ospf`. Every cell above drives only the
// top-level copy, so a fix applied to one and not the other passes all of them.
// That exact split is what #8258 tracks as a class, and #8473's own census
// needed a dedicated row for the routing-instance copies for the same reason.
func TestOSPFAuthClosedWorldReachesTheRoutingInstanceCopy8443(t *testing.T) {
	rows := []struct {
		name    string
		inner   string
		wantErr string
	}{
		{"misspelled algorithm", `authentication { md5-typo 1 { key "SEKRIT"; } }`, "md5-typo"},
		{"authentication-type leaf", `authentication-type md5;`, "authentication-type"},
		{"md5 with a key still commits (CONTROL)", `authentication { md5 1 { key "SEKRIT"; } }`, ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			src := `routing-instances { VRF-A { protocols { ospf { area 0.0.0.0 { ` +
				`interface ge-0/0/0.0 { ` + row.inner + ` } } } } } }`
			tree, perrs := NewParser(src).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture did not parse: %v", perrs)
			}
			err := SchemaValidate(tree)
			if row.wantErr == "" {
				if err != nil {
					t.Fatalf("must commit, got: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("the routing-instance copy is not gated — the fix " +
					"landed on the top-level OSPF schema only")
			}
			if !strings.Contains(err.Error(), row.wantErr) {
				t.Fatalf("rejected for the wrong reason\n  want: %q\n  got: %v",
					row.wantErr, err)
			}
		})
	}
}

// TestOSPFAuthGateDidNotCloseTheInterfaceWorld8443 pins the SCOPE of this
// change, which is as much a part of it as the rejections are.
//
// Closing the whole OSPF `interface` world would also catch `authentication-type`
// — it was measured, and the pkg/config suite stayed green — but it converts
// every unmodeled protocol leaf from inert to refused, which is the #8296 class
// and a much larger decision than #8443's scope. This cell reds if a later
// change makes that flip incidentally, so the decision has to be taken
// deliberately rather than inherited.
func TestOSPFAuthGateDidNotCloseTheInterfaceWorld8443(t *testing.T) {
	tree := ospfAuthTreeHier8443(t, `frobnicate 7;`)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("the OSPF interface level is still OPEN-world by design "+
			"(#8296 tracks the flip); this change was scoped to the "+
			"`authentication` subtree and the `authentication-type` leaf, "+
			"and something has widened it: %v", err)
	}
}
