package config

import (
	"fmt"
	"strings"
	"testing"
)

// #10081's census population is the eight firewall from-level prefix-list
// leaves that #10073 changed from flag-shaped schema nodes (args:0) to valued
// nodes (args:1): source/destination under any, inet, inet6, and implicit inet.
// Keep deriving the rows from the #2419 schema walk rather than copying a
// second schema list. The explicit floor below is the anti-vacuity guard.
func prefixListPackedCensusRows10081(t *testing.T) []struct {
	family string
	leaf   string
	site   string
} {
	t.Helper()
	want := map[string]bool{}
	for _, family := range []string{"any", "inet", "inet6", "implicit"} {
		for _, leaf := range []string{"source-prefix-list", "destination-prefix-list"} {
			want[family+"/"+leaf] = true
		}
	}
	var rows []struct {
		family string
		leaf   string
		site   string
	}
	for _, site := range collectCompactSites() {
		path := strings.Join(site.container, " ")
		if !strings.HasPrefix(path, "firewall ") ||
			!strings.HasSuffix(path, " term xpfarg from") ||
			(site.leaf != "source-prefix-list" && site.leaf != "destination-prefix-list") {
			continue
		}
		family := "implicit"
		parts := strings.Fields(path)
		if len(parts) >= 3 && parts[1] == "family" {
			family = parts[2]
		}
		key := family + "/" + site.leaf
		if !want[key] {
			continue
		}
		rows = append(rows, struct {
			family string
			leaf   string
			site   string
		}{family: family, leaf: site.leaf, site: path + " " + site.leaf})
		delete(want, key)
	}
	if len(rows) != 8 || len(want) != 0 {
		t.Fatalf("#10081 census population = %d rows, missing %v; want all eight family/direction prefix-list leaves", len(rows), want)
	}
	return rows
}

func prefixListPackedFixture10081(family, leaf, operand string, braced bool) string {
	from := fmt.Sprintf("from %s %s;", leaf, operand)
	if braced {
		from = fmt.Sprintf("from { %s %s; }", leaf, operand)
	}
	filter := fmt.Sprintf("filter F { term T { %s then { accept; } } }", from)
	prefixList := "policy-options { prefix-list AAA { 10.0.0.0/8; 2001:db8::/32; } } "
	if family == "implicit" {
		return prefixList + "firewall { " + filter + " }"
	}
	return fmt.Sprintf("%sfirewall { family %s { %s } }", prefixList, family, filter)
}

func prefixListRefsForLeaf10081(term *FirewallFilterTerm, leaf string) []PrefixListRef {
	if leaf == "destination-prefix-list" {
		return term.DestPrefixLists
	}
	return term.SourcePrefixLists
}

func parsePrefixList10081(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(src).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture did not parse: %v\n%s", perrs, src)
	}
	return tree
}

// TestFilterPackedPrefixListCensus10081 is the dual-shape census guard. The
// valued row proves that a packed reference survives as a named typed ref; the
// valueless row proves that the same packed site remains loud and records its
// leaf rather than widening to an unconstrained term. A schema revert from
// args:1 to args:0 reds the valued half because AAA then disappears from the
// compiled ref, which is the exact #10081 failure mode.
func TestFilterPackedPrefixListCensus10081(t *testing.T) {
	for _, row := range prefixListPackedCensusRows10081(t) {
		t.Run(row.site, func(t *testing.T) {
			bracedValued := parsePrefixList10081(t, prefixListPackedFixture10081(row.family, row.leaf, "AAA", true))
			packedValued := parsePrefixList10081(t, prefixListPackedFixture10081(row.family, row.leaf, "AAA", false))
			bracedCfg, err := CompileConfig(bracedValued)
			if err != nil {
				t.Fatalf("braced valued control must be strict-clean: %v", err)
			}
			packedCfg, err := CompileConfig(packedValued)
			if err != nil {
				t.Fatalf("packed valued ref must be strict-clean: %v", err)
			}
			bracedTerm := prefixListTerm10073(t, bracedCfg, row.family)
			packedTerm := prefixListTerm10073(t, packedCfg, row.family)
			for spelling, term := range map[string]*FirewallFilterTerm{"braced": bracedTerm, "packed": packedTerm} {
				refs := prefixListRefsForLeaf10081(term, row.leaf)
				if len(refs) != 1 || refs[0].Name != "AAA" || refs[0].Except {
					t.Fatalf("%s valued ref = %+v, want one named AAA ref", spelling, refs)
				}
			}
			if !cfgEqual(bracedCfg, packedCfg) {
				t.Fatalf("valued packed and braced configs differ; packed ref was not lowered equivalently")
			}

			bracedValueless := parsePrefixList10081(t, prefixListPackedFixture10081(row.family, row.leaf, "", true))
			packedValueless := parsePrefixList10081(t, prefixListPackedFixture10081(row.family, row.leaf, "", false))
			for spelling, tree := range map[string]*ConfigTree{"braced": bracedValueless, "packed": packedValueless} {
				_, err := CompileConfig(tree)
				if err == nil || !strings.Contains(err.Error(), row.leaf) {
					t.Fatalf("%s valueless shape must be rejected naming %s, got %v", spelling, row.leaf, err)
				}
			}
			for spelling, tree := range map[string]*ConfigTree{"braced": bracedValueless, "packed": packedValueless} {
				cfg, err := CompileConfigLenient(tree)
				if err != nil {
					t.Fatalf("%s valueless shape must warn, not fail: %v", spelling, err)
				}
				term := prefixListTerm10073(t, cfg, row.family)
				if len(prefixListRefsForLeaf10081(term, row.leaf)) != 0 {
					t.Fatalf("%s valueless shape unexpectedly retained a prefix-list ref: %+v", spelling, term)
				}
				if len(term.ValuelessFrom) != 1 || term.ValuelessFrom[0] != row.leaf {
					t.Fatalf("%s valueless marker = %v, want [%s]", spelling, term.ValuelessFrom, row.leaf)
				}
			}
		})
	}
}

// TestFilterFromPackedValuedPrefixList10081 pins the issue's exact spelling,
// independently of the generated census population and its family controls.
func TestFilterFromPackedValuedPrefixList10081(t *testing.T) {
	tree := parsePrefixList10081(t, `policy-options { prefix-list AAA { 10.0.0.0/8; } }
firewall { family inet { filter F { term T { from source-prefix-list AAA; then { discard; } } } } }`)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("exact #10081 packed valued ref must be strict-clean: %v", err)
	}
	term := prefixListTerm10073(t, cfg, "inet")
	if refs := term.SourcePrefixLists; len(refs) != 1 || refs[0].Name != "AAA" || refs[0].Except {
		t.Fatalf("exact #10081 packed source-prefix-list ref = %+v, want [{Name:AAA Except:false}]", refs)
	}
	if len(term.ValuelessFrom) != 0 || len(term.UnknownFrom) != 0 {
		t.Fatalf("exact #10081 valued ref carried a failure marker: ValuelessFrom=%v UnknownFrom=%v", term.ValuelessFrom, term.UnknownFrom)
	}
}
