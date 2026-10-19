package config

import (
	"fmt"
	"testing"
)

// #15137 (A88-01): after #14409, a neighbor's `import P` / `export P`
// where P happens to spell a neighbor-grammar keyword (passive,
// default-originate, remove-private, loops, description, ...) compiled
// to NO policy plus that keyword's flag. The fused-multi-leaf splitter
// in bgpNeighborBody14409 treated a STANDALONE multi leaf's value as a
// fused packed statement: it cut at the keyword, installed the flag,
// and the export/import case then wiped the inherited group list and
// appended nothing. Under `no bgp ebgp-requires-policy` (#14584) the
// eBGP peer is unfiltered in that direction.
//
// Regression property: a policy named after a keyword compiles to
// Import/Export=[name] in every spelling — braced, packed (brace-elided
// hierarchical) and flat-set — with NO flag line from the name, while a
// genuinely fused packed run (`export EP authentication-key K`) and a
// bracketed / quoted keyword-named policy keep working.

func bgpNeighbors15137(t *testing.T, text string) []*BGPNeighbor {
	t.Helper()
	ns := bgpNeighborsStrict14409(t, text)
	if len(ns) != 1 {
		t.Fatalf("got %d neighbors, want 1", len(ns))
	}
	return ns
}

// keywordPolicies15137 is the acceptance matrix from the issue: every
// keyword that is also a neighbor statement name. `loops` additionally
// needs a value in its own grammar, so its fused form is exercised
// separately; here it is a policy NAME.
var keywordPolicies15137 = []string{
	"passive",
	"default-originate",
	"remove-private",
	"loops",
	"description",
	"peer-as",
	"authentication-key",
	"hold-time",
	"local-as",
	"local-address",
	"multihop",
	"route-reflector-client",
	"bfd-liveness-detection",
	"family",
}

func assertNoKeywordFlag15137(t *testing.T, n *BGPNeighbor, policy string) {
	t.Helper()
	if n.Passive {
		t.Errorf("policy %q: Passive = true, want false (the name is a policy, not the passive flag)", policy)
	}
	if n.DefaultOriginate {
		t.Errorf("policy %q: DefaultOriginate = true, want false", policy)
	}
	if n.RemovePrivateAS {
		t.Errorf("policy %q: RemovePrivateAS = true, want false", policy)
	}
	if n.AllowASIn != 0 {
		t.Errorf("policy %q: AllowASIn = %d, want 0 (the name is a policy, not the loops statement)", policy, n.AllowASIn)
	}
	if n.Description != "" && policy != "description" {
		// A policy literally named "description" must not become the
		// neighbor description either; the description check below
		// covers the empty case uniformly.
		t.Errorf("policy %q: Description = %q, want empty", policy, n.Description)
	}
	if n.Description != "" && policy == "description" {
		t.Errorf("policy %q: Description = %q, want empty (the name is a policy, not a description statement)", policy, n.Description)
	}
	if n.RouteReflectorClient {
		t.Errorf("policy %q: RouteReflectorClient = true, want false", policy)
	}
	if n.BFD {
		t.Errorf("policy %q: BFD = true, want false", policy)
	}
	if got := string(n.AuthPassword); got != "" {
		t.Errorf("policy %q: AuthPassword = %q, want empty", policy, got)
	}
	if n.PeerAS != 65001 {
		t.Errorf("policy %q: PeerAS = %d, want 65001 (group peer-as must survive)", policy, n.PeerAS)
	}
}

func TestBGPNeighborKeywordNamedPolicyBraced15137(t *testing.T) {
	for _, policy := range keywordPolicies15137 {
		for _, dir := range []string{"import", "export"} {
			t.Run(dir+"_"+policy, func(t *testing.T) {
				// Group carries its own import/export so the test also
				// proves the neighbor's own policy REPLACES (not wipes
				// to empty) the inherited list (#5277).
				text := fmt.Sprintf(`protocols { bgp { group G1 { peer-as 65001; import GIMP; export GEXP;
					neighbor 10.0.0.1 { %s %s; } } } }`, dir, policy)
				n := bgpNeighbors15137(t, text)[0]
				if dir == "import" {
					if len(n.Import) != 1 || n.Import[0] != policy {
						t.Errorf("braced %s %s: Import = %v, want [%s]", dir, policy, n.Import, policy)
					}
					if len(n.Export) != 1 || n.Export[0] != "GEXP" {
						t.Errorf("braced %s %s: Export = %v, want inherited [GEXP]", dir, policy, n.Export)
					}
				} else {
					if len(n.Export) != 1 || n.Export[0] != policy {
						t.Errorf("braced %s %s: Export = %v, want [%s]", dir, policy, n.Export, policy)
					}
					if len(n.Import) != 1 || n.Import[0] != "GIMP" {
						t.Errorf("braced %s %s: Import = %v, want inherited [GIMP]", dir, policy, n.Import)
					}
				}
				assertNoKeywordFlag15137(t, n, policy)
			})
		}
	}
}

func TestBGPNeighborKeywordNamedPolicyPacked15137(t *testing.T) {
	// Packed (brace-elided) neighbor line: `neighbor 10.0.0.1 import P;`
	// The #8662 fold synthesizes the very same [import P] child, so this
	// shape must agree with the braced one.
	for _, policy := range keywordPolicies15137 {
		for _, dir := range []string{"import", "export"} {
			t.Run(dir+"_"+policy, func(t *testing.T) {
				text := fmt.Sprintf(`protocols { bgp { group G1 { peer-as 65001; import GIMP; export GEXP;
					neighbor 10.0.0.1 %s %s; } } }`, dir, policy)
				n := bgpNeighbors15137(t, text)[0]
				if dir == "import" {
					if len(n.Import) != 1 || n.Import[0] != policy {
						t.Errorf("packed %s %s: Import = %v, want [%s]", dir, policy, n.Import, policy)
					}
				} else {
					if len(n.Export) != 1 || n.Export[0] != policy {
						t.Errorf("packed %s %s: Export = %v, want [%s]", dir, policy, n.Export, policy)
					}
				}
				assertNoKeywordFlag15137(t, n, policy)
			})
		}
	}
}

func TestBGPNeighborKeywordNamedPolicyFlatSet15137(t *testing.T) {
	for _, policy := range keywordPolicies15137 {
		for _, dir := range []string{"import", "export"} {
			t.Run(dir+"_"+policy, func(t *testing.T) {
				tree := &ConfigTree{}
				for _, cmd := range []string{
					"set protocols bgp group G1 peer-as 65001",
					"set protocols bgp group G1 import GIMP",
					"set protocols bgp group G1 export GEXP",
					fmt.Sprintf("set protocols bgp group G1 neighbor 10.0.0.1 %s %s", dir, policy),
				} {
					path, err := ParseSetCommand(cmd)
					if err != nil {
						t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
					}
					if err := tree.SetPath(path); err != nil {
						t.Fatalf("SetPath(%v): %v", path, err)
					}
				}
				cfg, err := CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("CompileConfigLenient: %v", err)
				}
				if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
					t.Fatalf("flat-set %s %s: neighbors = %v, want 1", dir, policy, cfg.Protocols.BGP)
				}
				n := cfg.Protocols.BGP.Neighbors[0]
				if dir == "import" {
					if len(n.Import) != 1 || n.Import[0] != policy {
						t.Errorf("flat-set %s %s: Import = %v, want [%s]", dir, policy, n.Import, policy)
					}
				} else {
					if len(n.Export) != 1 || n.Export[0] != policy {
						t.Errorf("flat-set %s %s: Export = %v, want [%s]", dir, policy, n.Export, policy)
					}
				}
				assertNoKeywordFlag15137(t, n, policy)
			})
		}
	}
}

// Controls: the #14409 fused shapes must keep splitting, and a
// keyword-named policy in a bracketed or quoted spelling — or followed
// by a genuinely fused statement — must keep its values.
func TestBGPNeighborKeywordPolicyControls15137(t *testing.T) {
	// Fused packed run: export EP followed by authentication-key.
	n := bgpNeighbors15137(t, `protocols { bgp { group G1 { peer-as 65001;
		neighbor 10.0.0.1 export EP authentication-key NEIGHBORKEY; } } }`)[0]
	if len(n.Export) != 1 || n.Export[0] != "EP" {
		t.Errorf("fused control: Export = %v, want [EP]", n.Export)
	}

	// Fused with a keyword-named FIRST policy: `export passive
	// authentication-key K` is the packed spelling of braced
	// `export passive; authentication-key K;` — the policy is
	// "passive" AND the key arrives.
	n = bgpNeighbors15137(t, `protocols { bgp { group G1 { peer-as 65001;
		neighbor 10.0.0.1 export passive authentication-key NEIGHBORKEY; } } }`)[0]
	if len(n.Export) != 1 || n.Export[0] != "passive" {
		t.Errorf("fused keyword-policy control: Export = %v, want [passive]", n.Export)
	}
	if got := string(n.AuthPassword); got != "NEIGHBORKEY" {
		t.Errorf("fused keyword-policy control: AuthPassword = %q, want NEIGHBORKEY", got)
	}
	if n.Passive {
		t.Errorf("fused keyword-policy control: Passive = true, want false")
	}

	// Bracketed list containing a keyword-named policy stays a list.
	n = bgpNeighbors15137(t, `protocols { bgp { group G1 { peer-as 65001;
		neighbor 10.0.0.1 { export [ passive EP ]; } } } }`)[0]
	if len(n.Export) != 2 || n.Export[0] != "passive" || n.Export[1] != "EP" {
		t.Errorf("bracket control: Export = %v, want [passive EP]", n.Export)
	}
	if n.Passive {
		t.Errorf("bracket control: Passive = true, want false")
	}

	// Quoted keyword-named policy stays a policy.
	n = bgpNeighbors15137(t, `protocols { bgp { group G1 { peer-as 65001;
		neighbor 10.0.0.1 { import "passive"; } } } }`)[0]
	if len(n.Import) != 1 || n.Import[0] != "passive" {
		t.Errorf("quoted control: Import = %v, want [passive]", n.Import)
	}
	if n.Passive {
		t.Errorf("quoted control: Passive = true, want false")
	}

	// Ordinary (non-keyword) policies in every shape — the neighbouring
	// legitimate behaviour through the same code path.
	n = bgpNeighbors15137(t, `protocols { bgp { group G1 { peer-as 65001;
		neighbor 10.0.0.1 { import NORMAL; export ALSO; } } } }`)[0]
	if len(n.Import) != 1 || n.Import[0] != "NORMAL" || len(n.Export) != 1 || n.Export[0] != "ALSO" {
		t.Errorf("ordinary control: Import=%v Export=%v, want [NORMAL]/[ALSO]", n.Import, n.Export)
	}
}
