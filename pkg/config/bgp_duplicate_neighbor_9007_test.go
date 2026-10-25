package config

import (
	"strings"
	"testing"
)

// #9007: the same BGP neighbor address in two `protocols bgp group` blocks
// committed clean with zero warnings. One address renders once per group that
// names it, so FRR received two `remote-as`, two `timers`, two DIVERGENT
// `password` lines and two `bfd` peer blocks for one peer -- resolved by
// render order, silently, while `show` kept reporting both groups as authored.
//
// Name the channel: this constraint is not schema-expressible (it is a
// relation between two subtrees), so SchemaValidate never sees it. The two
// channels that matter are
//
//	CompileConfig         STRICT compiler gates; reached from compileTreeStrict
//	                      (Store.Commit / commit-check) -- must REJECT
//	CompileConfigLenient  tolerant gates; backs Store.Load and HA SyncApply --
//	                      must WARN and must NOT reject (#1960)
func buildTree9007(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, c := range cmds {
		p, err := ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	return tree
}

func TestBGPDuplicateNeighborChannels9007(t *testing.T) {
	dup := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group ga peer-as 65002",
		"set protocols bgp group ga neighbor 192.0.2.1 authentication-key secretA",
		"set protocols bgp group gb peer-as 65003",
		"set protocols bgp group gb neighbor 192.0.2.1 authentication-key secretB",
	}
	// Control: two DISTINCT addresses across two groups is ordinary config.
	distinct := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group ga peer-as 65002",
		"set protocols bgp group ga neighbor 192.0.2.1 authentication-key secretA",
		"set protocols bgp group gb peer-as 65003",
		"set protocols bgp group gb neighbor 192.0.2.2 authentication-key secretB",
	}
	// Control: the SAME address in two different routing instances is
	// legitimate -- separate VRFs peering with one address is ordinary. The
	// gate partitions by BGP instance, so this must stay accepted. Without
	// that partition the gate would false-reject real configs.
	crossInstance := []string{
		"set protocols bgp local-as 65001",
		"set protocols bgp group ga peer-as 65002",
		"set protocols bgp group ga neighbor 192.0.2.1 authentication-key secretA",
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols bgp local-as 65010",
		"set routing-instances VR1 protocols bgp group gv peer-as 65011",
		"set routing-instances VR1 protocols bgp group gv neighbor 192.0.2.1 authentication-key secretC",
	}
	// Control, and the load-bearing one: the compiler emits one *BGPNeighbor
	// per AST NODE, so a single authored neighbor extended by a second set
	// command occupies TWO nodes and yields TWO entries -- both in group G,
	// one carrying the import policy. This is ordinary flat-set authoring
	// (and the shape pkg/config's own slot-escape fixtures use). It must
	// COMMIT CLEAN: the entries render redundantly but correctly, and the
	// second is what carries `activate` plus the route-map. A gate keyed on
	// the address alone blames the operator for a compiler artifact.
	sameGroupSplitNode := []string{
		"set policy-options policy-statement PS then accept",
		"set protocols bgp local-as 65001",
		"set protocols bgp group G type internal",
		"set protocols bgp group G peer-as 65001",
		"set protocols bgp group G neighbor 10.0.2.2",
		"set protocols bgp group G neighbor 10.0.2.2 import PS",
	}
	// The duplicate inside ONE routing instance must still be caught -- the
	// partition must not become a blanket exemption for instance scopes.
	dupInInstance := []string{
		"set routing-instances VR1 instance-type virtual-router",
		"set routing-instances VR1 protocols bgp local-as 65010",
		"set routing-instances VR1 protocols bgp group gv peer-as 65011",
		"set routing-instances VR1 protocols bgp group gv neighbor 192.0.2.1 authentication-key secretC",
		"set routing-instances VR1 protocols bgp group gw peer-as 65012",
		"set routing-instances VR1 protocols bgp group gw neighbor 192.0.2.1 authentication-key secretD",
	}

	cases := []struct {
		name      string
		cmds      []string
		wantRej   bool
		wantMsg   []string // substrings the diagnostic must carry
		wantScope string
	}{
		{name: "duplicate-across-groups", cmds: dup, wantRej: true,
			wantMsg: []string{"192.0.2.1", "more than one group", "ga", "gb"}},
		{name: "distinct-addresses", cmds: distinct, wantRej: false},
		{name: "same-group-split-across-nodes", cmds: sameGroupSplitNode, wantRej: false},
		{name: "same-address-different-instances", cmds: crossInstance, wantRej: false},
		{name: "duplicate-inside-one-instance", cmds: dupInInstance, wantRej: true,
			wantMsg: []string{"192.0.2.1", "more than one group", "gv", "gw"}, wantScope: "routing-instance VR1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// --- CHANNEL: CompileConfig (strict; Store.Commit) ---
			_, strictErr := CompileConfig(buildTree9007(t, tc.cmds...))
			if !tc.wantRej {
				if strictErr != nil {
					t.Fatalf("commit channel REJECTED a legitimate config: %v", strictErr)
				}
			} else {
				if strictErr == nil {
					t.Fatalf("commit channel ACCEPTED a duplicate neighbor -- this is the #9007 defect")
				}
				for _, want := range tc.wantMsg {
					if !strings.Contains(strictErr.Error(), want) {
						t.Fatalf("diagnostic omits %q (an operator cannot find the collision "+
							"without both group names): %v", want, strictErr)
					}
				}
				if tc.wantScope != "" && !strings.Contains(strictErr.Error(), tc.wantScope) {
					t.Fatalf("diagnostic omits the scope %q: %v", tc.wantScope, strictErr)
				}
			}

			// --- CHANNEL: CompileConfigLenient (Store.Load / HA SyncApply) ---
			// #1960: may gain a WARNING, never a REJECTION.
			cfg, lenErr := CompileConfigLenient(buildTree9007(t, tc.cmds...))
			if lenErr != nil {
				t.Fatalf("tolerant path gained a NEW REJECTION (#1960 violation): %v", lenErr)
			}
			var warned bool
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "duplicate neighbor") {
					warned = true
				}
			}
			if tc.wantRej && !warned {
				t.Fatalf("tolerant path admitted the duplicate in SILENCE (%d warning(s): %v)",
					len(cfg.Warnings), cfg.Warnings)
			}
			if !tc.wantRej && warned {
				t.Fatalf("tolerant path warned about a legitimate config: %v", cfg.Warnings)
			}
		})
	}
}
