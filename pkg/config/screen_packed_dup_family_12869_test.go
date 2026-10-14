package config

import (
	"strings"
	"testing"
)

// #12869: a packed ids-option tail synthesizes SIBLING family nodes
// (packedBody, #5180/#6683), but the #5180 family walk in
// validateDuplicateNamedBlockAST inspects only the authored Children of the
// ids-option node — which are empty for the packed spelling. A repeated
// family therefore slipped the strict duplicate gate while compileScreen,
// reading each family with FindChild, silently dropped every guard in the
// later sibling. The hierarchical spelling of the same statement is
// REJECTED; the packed spelling compiled clean and lost config fail-open.
//
// The fix normalises each ids-option node's body with the same packedBody
// expansion compileScreen uses before the family multiplicity walk, so both
// spellings report the duplicate through the identical diagnostic.
var packedDupFamilies12869 = []struct {
	fam   string
	stmts [2]string // two DISTINCT authorings of one family by one profile
}{
	{"icmp", [2]string{"icmp ping-death", "icmp fragment"}},
	{"ip", [2]string{"ip source-route-option", "ip tear-drop"}},
	{"tcp", [2]string{"tcp land", "tcp winnuke"}},
	{"udp", [2]string{"udp flood threshold 444", "udp flood threshold 555"}},
	{"limit-session", [2]string{"limit-session source-ip-based 10", "limit-session destination-ip-based 20"}},
}

func screen12869(t *testing.T, src string) (*Config, error) {
	t.Helper()
	tree := parseHier5180(t, src)
	if len(tree.Children) == 0 {
		t.Fatalf("fixture parsed to an empty tree: %q", src)
	}
	return CompileConfig(tree)
}

func TestPackedRepeatedScreenFamilyRejected_12869(t *testing.T) {
	for _, c := range packedDupFamilies12869 {
		t.Run(c.fam+" packed repeat rejected", func(t *testing.T) {
			src := `security { screen { ids-option s1 ` + c.stmts[0] + ` ` + c.stmts[1] + `; } }`
			_, err := screen12869(t, src)
			if err == nil {
				t.Fatalf("packed repeated %q family compiled clean; the later guard is silently dropped", c.fam)
			}
			if !strings.Contains(err.Error(), "family") || !strings.Contains(err.Error(), c.fam) || !strings.Contains(err.Error(), "s1") {
				t.Fatalf("error should name the duplicate screen family and profile, got: %v", err)
			}
		})

		t.Run(c.fam+" hierarchical repeat still rejected", func(t *testing.T) {
			// Each family appears as its own block under one ids-option.
			src := `security { screen { ids-option s1 { ` + c.fam + ` { ` +
				strings.TrimPrefix(c.stmts[0], c.fam+" ") + `; } ` + c.fam + ` { ` +
				strings.TrimPrefix(c.stmts[1], c.fam+" ") + `; } } } }`
			_, err := screen12869(t, src)
			if err == nil {
				t.Fatalf("hierarchical repeated %q family compiled clean", c.fam)
			}
			if !strings.Contains(err.Error(), "family") || !strings.Contains(err.Error(), c.fam) {
				t.Fatalf("error should identify duplicate family %q, got: %v", c.fam, err)
			}
		})

		t.Run(c.fam+" single packed family still compiles", func(t *testing.T) {
			src := `security { screen { ids-option s1 ` + c.stmts[0] + `; } }`
			cfg, err := screen12869(t, src)
			if err != nil {
				t.Fatalf("single packed %q family must compile, got: %v", c.fam, err)
			}
			if len(cfg.Security.Screen) != 1 || cfg.Security.Screen["s1"] == nil {
				t.Fatalf("expected one compiled screen profile, got %d", len(cfg.Security.Screen))
			}
		})
	}

	t.Run("packed triple repeat rejected", func(t *testing.T) {
		src := `security { screen { ids-option s1 tcp land tcp winnuke icmp ping-death tcp syn-frag; } }`
		if _, err := screen12869(t, src); err == nil || !strings.Contains(err.Error(), "tcp") {
			t.Fatalf("triple tcp repeat must be rejected naming tcp, got: %v", err)
		}
	})

	t.Run("packed distinct families compile", func(t *testing.T) {
		src := `security { screen { ids-option s1 icmp ping-death ip tear-drop tcp land; } }`
		cfg, err := screen12869(t, src)
		if err != nil {
			t.Fatalf("distinct packed families must compile, got: %v", err)
		}
		if len(cfg.Security.Screen) != 1 {
			t.Fatalf("expected one profile, got %d", len(cfg.Security.Screen))
		}
		p := cfg.Security.Screen["s1"]
		if p == nil || !p.ICMP.PingDeath || !p.IP.TearDrop || !p.TCP.Land {
			t.Fatalf("distinct packed families lost a guard: %+v", p)
		}
	})

	t.Run("tolerant load warns for packed repeated family", func(t *testing.T) {
		tree := parseHier5180(t, `security { screen { ids-option s1 icmp ping-death icmp fragment; } }`)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("tolerant load must warn rather than reject, got: %v", err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "family") && strings.Contains(w, "icmp") {
				return
			}
		}
		t.Fatalf("tolerant load should warn for the packed duplicate family, got: %v", cfg.Warnings)
	})

	t.Run("flat-set repeated family statements merge", func(t *testing.T) {
		tree := setTree5180(t, []string{
			"set security screen ids-option s1 icmp ping-death",
			"set security screen ids-option s1 icmp fragment",
		})
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("flat-set repeated family statements must merge and compile, got: %v", err)
		}
		p := cfg.Security.Screen["s1"]
		if len(cfg.Security.Screen) != 1 || p == nil || !p.ICMP.PingDeath || !p.ICMP.Fragment {
			t.Fatalf("flat-set merge lost a guard: %+v", cfg.Security.Screen)
		}
	})
}
