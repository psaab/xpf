package config

import (
	"strings"
	"testing"
)

// #11793: the BGP prefix-limit `maximum` leaf was an untyped `args:1` leaf,
// and parsePrefixLimit swallowed its Atoi error into 0 — which the typed
// config reads as UNLIMITED (PrefixLimitInet/Inet6 comment in types_routing.go).
// Garbage (`maximum banana`) thus silently REMOVED the cap the operator wrote,
// and a value above uint32 (4294967296) reached the FRR renderer verbatim —
// one vtysh-rejected line fails the whole managed-section reload (#1880/#2223).
//
// Channel split (the #1319/#1960 doctrine, same as the #11794 MD5 key-id fix):
// SchemaValidate types the leaf so operator commits hard-reject garbage and
// out-of-range values; the compiler parses the leaf with a distinct error
// return (never zero), so the strict path rejects even when SchemaValidate is
// bypassed, the tolerant path warns and preserves any inherited neighbor cap,
// and the FRR render belt independently bounds values.

func bgpPrefixLimitTree11793(t *testing.T, family, value string) *ConfigTree {
	t.Helper()
	return flatTreeFromSets(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external neighbor 10.0.0.2",
		"set protocols bgp group external family "+family+" unicast prefix-limit maximum "+value)
}

// The schema leaf rejects garbage, 0, negatives, and >4294967295 at
// commit-check, in BOTH spellings (flat set and hierarchical), while the
// 1..4294967295 boundaries still commit.
func TestBGPPrefixLimitMaximumSchemaGate11793(t *testing.T) {
	bad := []string{"banana", "0", "-5", "4294967296", "99999999999999999999"}
	for _, tok := range bad {
		t.Run("reject-"+tok, func(t *testing.T) {
			if err := SchemaValidate(bgpPrefixLimitTree11793(t, "inet", tok), nil); err == nil {
				t.Fatalf("SchemaValidate accepted prefix-limit maximum %q; want commit rejection", tok)
			} else if !strings.Contains(err.Error(), "maximum") {
				t.Fatalf("rejection for maximum %q must name the maximum leaf: %v", tok, err)
			}
			src := `protocols { bgp { local-as 65001; group external { peer-as 65002; neighbor 10.0.0.2; family { inet { unicast { prefix-limit { maximum ` + tok + `; } } } } } } }`
			tree, perrs := NewParser(src).Parse()
			if len(perrs) > 0 {
				t.Fatalf("fixture did not parse: %v", perrs)
			}
			if err := SchemaValidate(tree, nil); err == nil {
				t.Fatalf("hierarchical: SchemaValidate accepted prefix-limit maximum %q; want commit rejection", tok)
			} else if !strings.Contains(err.Error(), "maximum") {
				t.Fatalf("hierarchical: rejection for maximum %q must name the maximum leaf: %v", tok, err)
			}
		})
	}
	for _, tok := range []string{"1", "1000", "4294967295"} {
		t.Run("accept-"+tok, func(t *testing.T) {
			if err := SchemaValidate(bgpPrefixLimitTree11793(t, "inet", tok), nil); err != nil {
				t.Fatalf("SchemaValidate rejected in-range prefix-limit maximum %q: %v", tok, err)
			}
		})
	}
}

// The strict compile path rejects a malformed/out-of-range maximum even when
// the config bypasses SchemaValidate, naming the neighbor and the invalid
// domain. Without this, garbage compiled to 0 = unlimited and silently
// REMOVED the operator's cap.
func TestBGPPrefixLimitMaximumStrictCompileRejects11793(t *testing.T) {
	for _, tc := range []struct {
		family string
		tok    string
	}{
		{"inet", "banana"},
		{"inet", "0"},
		{"inet", "-5"},
		{"inet", "4294967296"},
		{"inet6", "banana"},
		{"inet6", "4294967296"},
	} {
		t.Run(tc.family+"-reject-"+tc.tok, func(t *testing.T) {
			_, err := CompileConfig(bgpPrefixLimitTree11793(t, tc.family, tc.tok))
			if err == nil {
				t.Fatal("CompileConfig accepted a malformed prefix-limit maximum; want strict rejection")
			}
			if !strings.Contains(err.Error(), "BGP group") {
				t.Fatalf("strict error must name the BGP group: %v", err)
			}
			if !strings.Contains(err.Error(), "prefix-limit") && !strings.Contains(err.Error(), "maximum") {
				t.Fatalf("strict error must name the prefix-limit maximum leaf: %v", err)
			}
		})
	}
}

// Control: in-range maxima still compile AND bind (the compiled limit is the
// configured value, not a fallback), and an unset limit stays 0 = unlimited.
func TestBGPPrefixLimitMaximumValidBinds11793(t *testing.T) {
	for _, tc := range []struct {
		tok  string
		want int
	}{{"1", 1}, {"1000", 1000}, {"4294967295", 4294967295}} {
		t.Run("maximum-"+tc.tok, func(t *testing.T) {
			cfg, err := CompileConfig(bgpPrefixLimitTree11793(t, "inet", tc.tok))
			if err != nil {
				t.Fatalf("CompileConfig rejected in-range prefix-limit maximum %q: %v", tc.tok, err)
			}
			if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) == 0 {
				t.Fatal("no BGP neighbors compiled")
			}
			if got := cfg.Protocols.BGP.Neighbors[0].PrefixLimitInet; got != tc.want {
				t.Fatalf("PrefixLimitInet = %d, want %d", got, tc.want)
			}
		})
	}
	tree := flatTreeFromSets(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external neighbor 10.0.0.2")
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig rejected a neighbor with no prefix-limit: %v", err)
	}
	n := cfg.Protocols.BGP.Neighbors[0]
	if n.PrefixLimitInet != 0 || n.PrefixLimitInet6 != 0 {
		t.Fatalf("unset limits = (%d, %d), want (0, 0) = unlimited",
			n.PrefixLimitInet, n.PrefixLimitInet6)
	}
}

// The tolerant load / peer-sync path warns (naming the group and invalid
// value) instead of hard-erroring (#1960 no-brick); the malformed group limit
// does not become a fabricated numeric prefix-limit.
func TestBGPPrefixLimitMaximumLenientWarns11793(t *testing.T) {
	for _, tok := range []string{"banana", "4294967296"} {
		t.Run("warn-"+tok, func(t *testing.T) {
			cfg, err := CompileConfigLenient(bgpPrefixLimitTree11793(t, "inet", tok))
			if err != nil {
				t.Fatalf("CompileConfigLenient hard-rejected prefix-limit maximum %q (want warn): %v", tok, err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "external") &&
					(strings.Contains(w, "prefix-limit") || strings.Contains(w, "maximum")) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("lenient compile produced no prefix-limit warning naming the group; got %v", cfg.Warnings)
			}
		})
	}
}

// The RI copy shares the SAME bgp schema pointer as the global one (#9351), so
// a validator on the global node reaches it — but this cell pins the
// routing-instances verdict directly so a future split reds loud.
func TestBGPPrefixLimitMaximumReachesTheRoutingInstanceCopy11793(t *testing.T) {
	src := `routing-instances { VRF-A { protocols { bgp { local-as 65001; group external { peer-as 65002; neighbor 10.0.0.2; family { inet { unicast { prefix-limit { maximum banana; } } } } } } } } }`
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v", perrs)
	}
	if err := SchemaValidate(tree, nil); err == nil {
		t.Fatal("SchemaValidate accepted an RI prefix-limit maximum banana; want commit rejection")
	} else if !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("RI rejection must name the maximum leaf: %v", err)
	}
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("CompileConfig accepted an RI prefix-limit maximum banana; want strict rejection")
	}
}

// The schema pointer is shared between top-level and routing-instance BGP,
// but the group and per-neighbor prefix-limit paths are separately declared.
// Pin both address families at both scopes so no declaration remains untyped.
func TestBGPPrefixLimitMaximumSchemaGateAllSites11793(t *testing.T) {
	cases := []struct {
		name string
		set  string
	}{
		{"group-inet", "set protocols bgp group external family inet unicast prefix-limit maximum banana"},
		{"group-inet6", "set protocols bgp group external family inet6 unicast prefix-limit maximum banana"},
		{"neighbor-inet", "set protocols bgp group external neighbor 10.0.0.2 family inet unicast prefix-limit maximum banana"},
		{"neighbor-inet6", "set protocols bgp group external neighbor 10.0.0.2 family inet6 unicast prefix-limit maximum banana"},
		{"routing-instance-group-inet", "set routing-instances VRF-A protocols bgp group external family inet unicast prefix-limit maximum banana"},
		{"routing-instance-group-inet6", "set routing-instances VRF-A protocols bgp group external family inet6 unicast prefix-limit maximum banana"},
		{"routing-instance-neighbor-inet", "set routing-instances VRF-A protocols bgp group external neighbor 10.0.0.2 family inet unicast prefix-limit maximum banana"},
		{"routing-instance-neighbor-inet6", "set routing-instances VRF-A protocols bgp group external neighbor 10.0.0.2 family inet6 unicast prefix-limit maximum banana"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := flatTreeFromSets(t,
				"set protocols bgp local-as 65001",
				"set protocols bgp group external peer-as 65002",
				tc.set)
			if err := SchemaValidate(tree, nil); err == nil {
				t.Fatalf("SchemaValidate accepted %q; want maximum-prefix token rejection", tc.set)
			} else if !strings.Contains(err.Error(), "maximum") {
				t.Fatalf("schema error for %q does not name maximum: %v", tc.set, err)
			}
		})
	}
}

// A malformed per-neighbor override must not erase a valid inherited group
// cap on the tolerant path. Strict compilation rejects it instead.
func TestBGPPrefixLimitMaximumInvalidOverridePreservesGroupCap11793(t *testing.T) {
	tree := flatTreeFromSets(t,
		"set protocols bgp local-as 65001",
		"set protocols bgp group external peer-as 65002",
		"set protocols bgp group external family inet unicast prefix-limit maximum 4000",
		"set protocols bgp group external neighbor 10.0.0.2",
		"set protocols bgp group external neighbor 10.0.0.2 family inet unicast prefix-limit maximum banana")
	if _, err := CompileConfig(tree); err == nil ||
		!strings.Contains(err.Error(), "10.0.0.2") ||
		!strings.Contains(err.Error(), "maximum") {
		t.Fatalf("strict compile error = %v, want named invalid neighbor prefix-limit", err)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile rejected malformed legacy override: %v", err)
	}
	if len(cfg.Protocols.BGP.Neighbors) != 1 {
		t.Fatalf("compiled %d neighbors, want one", len(cfg.Protocols.BGP.Neighbors))
	}
	if got := cfg.Protocols.BGP.Neighbors[0].PrefixLimitInet; got != 4000 {
		t.Fatalf("invalid override changed inherited maximum to %d, want preserved 4000", got)
	}
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "10.0.0.2") && strings.Contains(warning, "maximum") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("tolerant compile did not warn with neighbor and maximum token: %v", cfg.Warnings)
	}
}
