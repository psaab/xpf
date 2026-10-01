package config

import (
	"fmt"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #9351: `routing-instances <n> protocols ...` and the global `protocols ...`
// are ONE grammar — compileRoutingInstances calls the same compileProtocols on
// the per-instance node — but they used to be TWO schema declarations, and the
// per-instance one had drifted to a strict subset.
//
// That is not a completion gap. SetPath resolves a flat-set statement's packed
// tail THROUGH THE SCHEMA, so an undeclared keyword ends the walk and the
// remaining tokens are packed onto the last node's key, where nothing reads
// them. The braced spelling of the same statement was unaffected the whole
// time, which is why the suite was blind: every fixture that configures a
// per-instance protocol writes braces.
//
// Every cell below drives BOTH spellings, and the flat-set cells carry the
// GLOBAL spelling of the identical statement as a positive control in the same
// run — without it a cell cannot tell "the per-instance path works" from "my
// fixture never reached a compiler at all".

func setTree9351(t *testing.T, lines ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, l := range lines {
		p, err := ParseSetCommand(l)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", l, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", l, err)
		}
	}
	return tree
}

func bracedTree9351(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, perrs := NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse braced fixture: %v", perrs)
	}
	return tree
}

func compile9351(t *testing.T, tree *ConfigTree) *Config {
	t.Helper()
	// These fixtures exercise protocol-tree parsing, not missing router-AS
	// validation. Give any BGP example a valid process AS so #11313 cannot
	// preempt the parser behavior under test.
	formatted := tree.Format()
	if strings.Contains(formatted, "protocols") && strings.Contains(formatted, "bgp") {
		path, err := ParseSetCommand("set routing-options autonomous-system 65000")
		if err != nil {
			t.Fatalf("ParseSetCommand(router AS fixture): %v", err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(router AS fixture): %v", err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func instanceBGP9351(t *testing.T, cfg *Config, name string) *BGPConfig {
	t.Helper()
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == name {
			if ri.BGP == nil {
				t.Fatalf("routing instance %s has no BGP", name)
			}
			return ri.BGP
		}
	}
	t.Fatalf("routing instance %s not compiled", name)
	return nil
}

func neighbor9351(t *testing.T, bgp *BGPConfig, addr string) *BGPNeighbor {
	t.Helper()
	for _, n := range bgp.Neighbors {
		if n.Address == addr {
			return n
		}
	}
	t.Fatalf("neighbor %s not compiled (have %d)", addr, len(bgp.Neighbors))
	return nil
}

// TestPerInstanceBGPNeighbourSubKeywordSurvivesFlatSet9351 is the defect.
//
// `local-address` is the BGP session source. Before the fix the per-instance
// flat-set spelling compiled it to "" — byte-identical to never configuring
// it — on a clean commit with no error and no warning.
func TestPerInstanceBGPNeighbourSubKeywordSurvivesFlatSet9351(t *testing.T) {
	// POSITIVE CONTROL: the identical statement at global scope, same run.
	// If this arm ever stops producing 10.0.0.2 the per-instance arm below
	// proves nothing, because the reader itself would be broken.
	gcfg := compile9351(t, setTree9351(t,
		"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
		"set protocols bgp group g1 neighbor 10.0.0.1 local-address 10.0.0.2",
	))
	if gcfg.Protocols.BGP == nil {
		t.Fatalf("CONTROL: global BGP did not compile")
	}
	gn := neighbor9351(t, gcfg.Protocols.BGP, "10.0.0.1")
	if gn.LocalAddress != "10.0.0.2" {
		t.Fatalf("CONTROL: global local-address = %q, want 10.0.0.2 — the control is broken, "+
			"so the per-instance arm below cannot be read", gn.LocalAddress)
	}

	cfg := compile9351(t, setTree9351(t,
		"set routing-instances VRF-A instance-type vrf",
		"set routing-instances VRF-A protocols bgp group g1 peer-as 65001",
		"set routing-instances VRF-A protocols bgp group g1 neighbor 10.0.0.1 local-address 10.0.0.2",
	))
	n := neighbor9351(t, instanceBGP9351(t, cfg, "VRF-A"), "10.0.0.1")
	if n.LocalAddress != "10.0.0.2" {
		t.Errorf("per-instance flat-set local-address = %q, want 10.0.0.2 "+
			"(the same spelling at global scope gives %q)", n.LocalAddress, gn.LocalAddress)
	}
	if n.PeerAS != 65001 {
		t.Errorf("per-instance peer-as = %d, want 65001", n.PeerAS)
	}
}

// TestPerInstanceBGPNeighbourSubKeywordSurvivesBraced9351 pins the spelling
// that already worked. The fix reshapes the flat-set walk; nothing about the
// braced walk should move, and a cell that only drove flat-set could not tell.
func TestPerInstanceBGPNeighbourSubKeywordSurvivesBraced9351(t *testing.T) {
	cfg := compile9351(t, bracedTree9351(t, `
routing-instances {
    VRF-A {
        instance-type vrf;
        protocols {
            bgp {
                group g1 {
                    peer-as 65001;
                    neighbor 10.0.0.1 {
                        local-address 10.0.0.2;
                    }
                }
            }
        }
    }
}
`))
	n := neighbor9351(t, instanceBGP9351(t, cfg, "VRF-A"), "10.0.0.1")
	if n.LocalAddress != "10.0.0.2" {
		t.Errorf("per-instance braced local-address = %q, want 10.0.0.2", n.LocalAddress)
	}
	if n.PeerAS != 65001 {
		t.Errorf("per-instance braced peer-as = %d, want 65001", n.PeerAS)
	}
}

// TestPerInstanceRIPBlockSurvivesFlatSet9351 covers the wider half the issue
// did not record: `rip` was not declared per-instance AT ALL, so the packing
// happened one level higher and the ENTIRE protocol block collapsed onto a
// single leaf under `protocols`. ri.RIP came back non-nil and empty, which is
// the worst shape — "configured, and every value is the zero value".
func TestPerInstanceRIPBlockSurvivesFlatSet9351(t *testing.T) {
	cfg := compile9351(t, setTree9351(t,
		"set routing-instances VRF-A instance-type vrf",
		"set routing-instances VRF-A protocols rip group r1 neighbor ge-0/0/0.0",
	))
	var rip *RIPConfig
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "VRF-A" {
			rip = ri.RIP
		}
	}
	if rip == nil {
		t.Fatalf("per-instance RIP did not compile at all")
	}
	if len(rip.Interfaces) != 1 || rip.Interfaces[0] != "ge-0/0/0.0" {
		t.Errorf("per-instance flat-set RIP interfaces = %v, want [ge-0/0/0.0]", rip.Interfaces)
	}
}

// perInstanceSpelling9351 is one statement expressed three ways: the global
// flat-set form (the control), the per-instance flat-set form (the defect),
// and the per-instance braced form (the spelling that always worked).
type perInstanceSpelling9351 struct {
	name       string
	globalSet  []string
	instSet    []string
	instBraced string
	// read pulls the value under test out of a compiled routing instance;
	// readGlobal pulls the same value out of the global compile.
	read       func(*testing.T, *RoutingInstanceConfig) string
	readGlobal func(*testing.T, *Config) string
	want       string
}

// TestPerInstanceProtocolsSpellingsAgree9351 is the packed-vs-braced cell.
//
// The two spellings put the SAME tokens in DIFFERENT places in the AST, so a
// cell that drives one says nothing about the other. Each row asserts three
// things in one run: the global control produces `want`, the per-instance
// FLAT-SET form produces `want`, and the per-instance BRACED form produces
// `want`.
func TestPerInstanceProtocolsSpellingsAgree9351(t *testing.T) {
	rows := []perInstanceSpelling9351{
		{
			name:      "bgp neighbour local-address",
			globalSet: []string{"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001", "set protocols bgp group g1 neighbor 10.0.0.1 local-address 10.0.0.2"},
			instSet: []string{
				"set routing-instances V instance-type vrf",
				"set routing-instances V protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
				"set routing-instances V protocols bgp group g1 neighbor 10.0.0.1 local-address 10.0.0.2",
			},
			instBraced: `routing-instances { V { instance-type vrf; protocols { bgp { group g1 { neighbor 10.0.0.1 { peer-as 65001; local-address 10.0.0.2; } } } } } }`,
			read: func(t *testing.T, ri *RoutingInstanceConfig) string {
				if ri.BGP == nil || len(ri.BGP.Neighbors) == 0 {
					return "<no neighbour>"
				}
				return ri.BGP.Neighbors[0].LocalAddress
			},
			readGlobal: func(t *testing.T, c *Config) string {
				if c.Protocols.BGP == nil || len(c.Protocols.BGP.Neighbors) == 0 {
					return "<no neighbour>"
				}
				return c.Protocols.BGP.Neighbors[0].LocalAddress
			},
			want: "10.0.0.2",
		},
		{
			name:      "bgp neighbour description",
			globalSet: []string{"set protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001", "set protocols bgp group g1 neighbor 10.0.0.1 description upstream"},
			instSet: []string{
				"set routing-instances V instance-type vrf",
				"set routing-instances V protocols bgp group g1 neighbor 10.0.0.1 peer-as 65001",
				"set routing-instances V protocols bgp group g1 neighbor 10.0.0.1 description upstream",
			},
			instBraced: `routing-instances { V { instance-type vrf; protocols { bgp { group g1 { neighbor 10.0.0.1 { peer-as 65001; description upstream; } } } } } }`,
			read: func(t *testing.T, ri *RoutingInstanceConfig) string {
				if ri.BGP == nil || len(ri.BGP.Neighbors) == 0 {
					return "<no neighbour>"
				}
				return ri.BGP.Neighbors[0].Description
			},
			readGlobal: func(t *testing.T, c *Config) string {
				if c.Protocols.BGP == nil || len(c.Protocols.BGP.Neighbors) == 0 {
					return "<no neighbour>"
				}
				return c.Protocols.BGP.Neighbors[0].Description
			},
			want: "upstream",
		},
		{
			name:      "bgp group-level local-address",
			globalSet: []string{"set protocols bgp group g1 peer-as 65001", "set protocols bgp group g1 local-address 10.9.9.9", "set protocols bgp group g1 neighbor 10.0.0.1"},
			instSet: []string{
				"set routing-instances V instance-type vrf",
				"set routing-instances V protocols bgp group g1 peer-as 65001",
				"set routing-instances V protocols bgp group g1 local-address 10.9.9.9",
				"set routing-instances V protocols bgp group g1 neighbor 10.0.0.1",
			},
			instBraced: `routing-instances { V { instance-type vrf; protocols { bgp { group g1 { peer-as 65001; local-address 10.9.9.9; neighbor 10.0.0.1; } } } } }`,
			read: func(t *testing.T, ri *RoutingInstanceConfig) string {
				if ri.BGP == nil || len(ri.BGP.Neighbors) == 0 {
					return "<no neighbour>"
				}
				return ri.BGP.Neighbors[0].LocalAddress
			},
			readGlobal: func(t *testing.T, c *Config) string {
				if c.Protocols.BGP == nil || len(c.Protocols.BGP.Neighbors) == 0 {
					return "<no neighbour>"
				}
				return c.Protocols.BGP.Neighbors[0].LocalAddress
			},
			want: "10.9.9.9",
		},
		{
			name:      "rip group neighbour",
			globalSet: []string{"set protocols rip group r1 neighbor ge-0/0/0.0"},
			instSet: []string{
				"set routing-instances V instance-type vrf",
				"set routing-instances V protocols rip group r1 neighbor ge-0/0/0.0",
			},
			instBraced: `routing-instances { V { instance-type vrf; protocols { rip { group r1 { neighbor ge-0/0/0.0; } } } } }`,
			read: func(t *testing.T, ri *RoutingInstanceConfig) string {
				if ri.RIP == nil {
					return "<no rip>"
				}
				return strings.Join(ri.RIP.Interfaces, ",")
			},
			readGlobal: func(t *testing.T, c *Config) string {
				if c.Protocols.RIP == nil {
					return "<no rip>"
				}
				return strings.Join(c.Protocols.RIP.Interfaces, ",")
			},
			want: "ge-0/0/0.0",
		},
		{
			name:      "ospf area interface hello-interval",
			globalSet: []string{"set protocols ospf area 0.0.0.0 interface ge-0/0/0.0 hello-interval 3"},
			instSet: []string{
				"set routing-instances V instance-type vrf",
				"set routing-instances V protocols ospf area 0.0.0.0 interface ge-0/0/0.0 hello-interval 3",
			},
			instBraced: `routing-instances { V { instance-type vrf; protocols { ospf { area 0.0.0.0 { interface ge-0/0/0.0 { hello-interval 3; } } } } } }`,
			read: func(t *testing.T, ri *RoutingInstanceConfig) string {
				if ri.OSPF == nil || len(ri.OSPF.Areas) == 0 || len(ri.OSPF.Areas[0].Interfaces) == 0 {
					return "<no ospf interface>"
				}
				return fmt.Sprint(ri.OSPF.Areas[0].Interfaces[0].HelloInterval)
			},
			readGlobal: func(t *testing.T, c *Config) string {
				if c.Protocols.OSPF == nil || len(c.Protocols.OSPF.Areas) == 0 || len(c.Protocols.OSPF.Areas[0].Interfaces) == 0 {
					return "<no ospf interface>"
				}
				return fmt.Sprint(c.Protocols.OSPF.Areas[0].Interfaces[0].HelloInterval)
			},
			want: "3",
		},
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			gv := row.readGlobal(t, compile9351(t, setTree9351(t, row.globalSet...)))
			if gv != row.want {
				t.Fatalf("CONTROL: global flat-set gives %q, want %q — the control is broken, "+
					"so neither per-instance arm below can be read", gv, row.want)
			}

			var flat, braced string
			for _, ri := range compile9351(t, setTree9351(t, row.instSet...)).RoutingInstances {
				if ri.Name == "V" {
					flat = row.read(t, ri)
				}
			}
			for _, ri := range compile9351(t, bracedTree9351(t, row.instBraced)).RoutingInstances {
				if ri.Name == "V" {
					braced = row.read(t, ri)
				}
			}
			if flat != row.want {
				t.Errorf("per-instance FLAT-SET gives %q, want %q (global control gives %q)", flat, row.want, gv)
			}
			if braced != row.want {
				t.Errorf("per-instance BRACED gives %q, want %q (global control gives %q)", braced, row.want, gv)
			}
		})
	}
}

// protocolsKeywordField9351 maps a `protocols` schema keyword to the
// ProtocolsConfig field compileProtocols fills from it. Both directions are
// asserted total below, so this table cannot be quietly left behind when a new
// protocol is declared or a field is renamed.
var protocolsKeywordField9351 = map[string]string{
	"ospf":                 "OSPF",
	"ospf3":                "OSPFv3",
	"bgp":                  "BGP",
	"rip":                  "RIP",
	"isis":                 "ISIS",
	"lldp":                 "LLDP",
	"router-advertisement": "RouterAdvertisement",
}

// routingInstanceProtocolCopySet9351 reads the `ri.X = proto.X` assignments out
// of compileRoutingInstances. This is the WIRING, not a restatement of it: the
// per-instance schema's member set is defined by which protocols the compiler
// actually copies into the instance, so the census derives it from the source
// rather than from a second list that can drift.
func routingInstanceProtocolCopySet9351(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("compiler_routing.go")
	if err != nil {
		t.Fatalf("read compiler_routing.go: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s*ri\.([A-Za-z0-9]+)\s*=\s*proto\.([A-Za-z0-9]+)\s*$`)
	got := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(src), -1) {
		if m[1] != m[2] {
			t.Errorf("compiler_routing.go copies proto.%s into ri.%s — the census assumes the "+
				"names match; update it deliberately", m[2], m[1])
		}
		got[m[2]] = true
	}
	if len(got) == 0 {
		t.Fatalf("VOID: found no `ri.X = proto.X` assignments in compiler_routing.go — the census " +
			"scanned for a shape that no longer exists and would pass vacuously")
	}
	return got
}

// TestRoutingInstanceProtocolsShareTheGlobalGrammar9351 is the census that
// stops the drift from regrowing.
//
// It asserts three things, in the direction that matters for each:
//
//   - a protocol the compiler COPIES into the instance MUST be declared
//     per-instance (or its flat-set spelling silently packs — the #9351 defect);
//   - a protocol the compiler does NOT copy must NOT be declared per-instance
//     (or completion offers a keyword whose value is discarded);
//   - a declared subtree must be the SAME POINTER as the global one, which is
//     what makes a second declaration impossible rather than merely discouraged.
func TestRoutingInstanceProtocolsShareTheGlobalGrammar9351(t *testing.T) {
	copySet := routingInstanceProtocolCopySet9351(t)

	// Totality 1: the keyword table covers exactly the global protocols children.
	var globalKeys, tableKeys []string
	for k := range schemaProtocols.children {
		globalKeys = append(globalKeys, k)
	}
	for k := range protocolsKeywordField9351 {
		tableKeys = append(tableKeys, k)
	}
	sort.Strings(globalKeys)
	sort.Strings(tableKeys)
	if !reflect.DeepEqual(globalKeys, tableKeys) {
		t.Fatalf("protocolsKeywordField9351 covers %v but `protocols` declares %v — a new protocol "+
			"keyword must be given a per-instance verdict here, not skipped", tableKeys, globalKeys)
	}

	// Totality 2: every table value names a real ProtocolsConfig field, and every
	// ProtocolsConfig field is named by the table.
	pt := reflect.TypeOf(ProtocolsConfig{})
	var protoFields, tableFields []string
	for i := 0; i < pt.NumField(); i++ {
		protoFields = append(protoFields, pt.Field(i).Name)
	}
	for _, v := range protocolsKeywordField9351 {
		tableFields = append(tableFields, v)
	}
	sort.Strings(protoFields)
	sort.Strings(tableFields)
	if !reflect.DeepEqual(protoFields, tableFields) {
		t.Fatalf("protocolsKeywordField9351 names %v but ProtocolsConfig has %v", tableFields, protoFields)
	}

	rit := reflect.TypeOf(RoutingInstanceConfig{})
	for _, kw := range globalKeys {
		field := protocolsKeywordField9351[kw]
		copied := copySet[field]
		if _, ok := rit.FieldByName(field); copied && !ok {
			t.Errorf("compiler copies proto.%s into ri.%s but RoutingInstanceConfig has no such field", field, field)
		}
		declared := schemaRoutingInstanceProtocols.children[kw]

		switch {
		case copied && declared == nil:
			t.Errorf("`protocols %s` is copied into the routing instance (ri.%s = proto.%s) but is NOT "+
				"declared under `routing-instances <n> protocols`. Its flat-set spelling will PACK and "+
				"the values are dropped silently — this is #9351.", kw, field, field)
		case !copied && declared != nil:
			t.Errorf("`protocols %s` is declared under `routing-instances <n> protocols` but the compiler "+
				"never copies proto.%s into the instance, so completion offers a keyword whose value is "+
				"discarded. Either wire the copy or drop the declaration.", kw, field)
		case copied && declared != schemaProtocols.children[kw]:
			t.Errorf("`routing-instances <n> protocols %s` is a SEPARATE schema node from `protocols %s`. "+
				"They must be the same pointer — a second declaration is exactly the drift that produced "+
				"#9351 (68 paths against the global node's 169).", kw, kw)
		}
	}
}

// flatSetShape9351 returns the chain of node keys SetPath produces for one
// flat-set statement, which is the thing the packing defect changes.
func flatSetShape9351(t *testing.T, line string) string {
	t.Helper()
	tree := &ConfigTree{}
	p, err := ParseSetCommand(line)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", line, err)
	}
	if err := tree.SetPath(p); err != nil {
		t.Fatalf("SetPath(%q): %v", line, err)
	}
	var parts []string
	for cur := tree.Children; len(cur) > 0; cur = cur[0].Children {
		parts = append(parts, strings.Join(cur[0].Keys, " "))
	}
	return strings.Join(parts, " | ")
}

func enumProtocolsPaths9351(n *schemaNode, path []string, out *[][]string, depth int) {
	if depth > 8 {
		return
	}
	if len(n.children) == 0 && n.wildcard == nil {
		if len(path) > 0 {
			*out = append(*out, append([]string{}, path...))
		}
		return
	}
	keys := make([]string, 0, len(n.children))
	for k := range n.children {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c := n.children[k]
		seg := []string{k}
		for i := 0; i < c.args; i++ {
			seg = append(seg, fmt.Sprintf("V%d", len(path)+i))
		}
		enumProtocolsPaths9351(c, append(path, seg...), out, depth+1)
	}
	if n.wildcard != nil {
		enumProtocolsPaths9351(n.wildcard, append(path, "W"), out, depth+1)
	}
}

// TestPerInstanceProtocolsFlatSetShapeMatchesGlobal9351 is the total claim.
//
// For EVERY leaf path of the global `protocols` schema whose protocol the
// compiler copies into a routing instance, the flat-set AST that SetPath
// produces inside a routing instance must be identical to the one it produces
// at global scope. Measured before the fix: 53 of 122 enumerated paths
// differed. The population is derived here rather than listed, so a subtree
// added to the global grammar joins this claim automatically.
func TestPerInstanceProtocolsFlatSetShapeMatchesGlobal9351(t *testing.T) {
	copySet := routingInstanceProtocolCopySet9351(t)

	var paths [][]string
	enumProtocolsPaths9351(schemaProtocols, nil, &paths, 0)
	if len(paths) < 50 {
		t.Fatalf("VOID: enumerated only %d protocols paths; the walker is not reaching the grammar "+
			"and every comparison below would be vacuous", len(paths))
	}

	checked, mismatched := 0, 0
	for _, pth := range paths {
		if !copySet[protocolsKeywordField9351[pth[0]]] {
			continue // not copied into the instance; see the census cell above
		}
		checked++
		suffix := strings.Join(pth, " ")
		global := flatSetShape9351(t, "set protocols "+suffix)
		inst := flatSetShape9351(t, "set routing-instances VRF protocols "+suffix)
		trimmed := strings.TrimPrefix(inst, "routing-instances | VRF | ")
		if trimmed == inst {
			t.Fatalf("VOID: per-instance shape %q did not carry the expected prefix, so the "+
				"comparison is not comparing what it claims", inst)
		}
		if trimmed != global {
			mismatched++
			if mismatched <= 10 {
				t.Errorf("flat-set shape differs for `%s`:\n  global       %s\n  per-instance %s",
					suffix, global, trimmed)
			}
		}
	}
	if checked == 0 {
		t.Fatalf("VOID: no path was checked — the copy set and the enumeration did not intersect")
	}
	if mismatched > 0 {
		t.Errorf("%d of %d copied-protocol paths pack differently inside a routing instance", mismatched, checked)
	}
	t.Logf("compared %d flat-set paths across the copied protocols (%d enumerated in total)", checked, len(paths))
}

// TestPerInstanceBGPNeighbourElidedSpellingHasNoGateToDisarm9351 keeps the
// hand measurement #8690's census demanded for the three sites this change
// admitted, as a CELL rather than as a comment in that census's tables.
//
// Making `routing-instances <n> protocols` the global node gave three global
// BGP-neighbour sites per-instance twins:
// `... neighbor <ip> peer-as`, `... export`, `... import`. #8690's rule is that
// a newly admitted site must be measured by hand with a type-VALID value
// before it is written into either of its tables, because that bucket is where
// a real gate disarm hides. The measurement is four legs — braced and elided,
// each with the normalizer pass off and on — and for the policy leaves the
// verdict is not enough, because "accepted" and "accepted with the policy
// dropped" are the same verdict.
func TestPerInstanceBGPNeighbourElidedSpellingHasNoGateToDisarm9351(t *testing.T) {
	const policy = "policy-options { policy-statement pol1 { then accept; } }\n"
	compile := func(text string, skipPass bool) (*Config, error) {
		text = `routing-options { autonomous-system 65000; } ` + text
		tree, perrs := NewParser(text).Parse()
		if len(perrs) > 0 {
			t.Fatalf("parse: %v", perrs)
		}
		return compileConfigWithOpts(tree, compileOpts{skipCompactNormalize: skipPass})
	}

	// --- peer-as: a gate DOES fire, and it objects to the DROP, not the shape.
	bracedAS := `routing-instances { V { instance-type vrf; protocols { bgp { group g1 { type external; neighbor 10.0.0.2 { peer-as 65001; } } } } } }`
	elidedAS := `routing-instances { V { instance-type vrf; protocols { bgp { group g1 { type external; neighbor 10.0.0.2 peer-as 65001; } } } } }`
	for _, skip := range []bool{true, false} {
		if _, err := compile(bracedAS, skip); err != nil {
			t.Fatalf("BRACED peer-as must be legitimate in both passes (skipPass=%v): %v", skip, err)
		}
	}
	_, offErr := compile(elidedAS, true)
	if offErr == nil {
		t.Errorf("with the pass DISABLED the elided peer-as should be dropped and REJECTED; " +
			"an acceptance here means the reading below is not measuring what it claims")
	} else if !strings.Contains(offErr.Error(), "missing/invalid peer-as") {
		// Assert the MESSAGE, not merely the failure: a rejection for some other
		// reason would score this cell green while the gate under discussion is
		// silent.
		t.Errorf("the pass-disabled rejection must name the MISSING VALUE, which is what makes "+
			"this a benign disarm rather than a real one; got %q", offErr)
	}
	if _, err := compile(elidedAS, false); err != nil {
		t.Errorf("with the pass ENABLED the elided peer-as must survive and the same gate accept: %v", err)
	}

	// --- export / import: NO gate fires in any leg, so the verdict cannot
	// distinguish "carried" from "dropped". Read the compiled value.
	neighbourPolicies := func(cfg *Config) (string, string) {
		for _, ri := range cfg.RoutingInstances {
			if ri.Name == "V" && ri.BGP != nil && len(ri.BGP.Neighbors) > 0 {
				n := ri.BGP.Neighbors[0]
				return strings.Join(n.Export, ","), strings.Join(n.Import, ",")
			}
		}
		return "<no neighbour>", "<no neighbour>"
	}
	braced := policy + `routing-instances { V { instance-type vrf; protocols { bgp { group g1 { type external; peer-as 65001; neighbor 10.0.0.2 { export pol1; import pol1; } } } } } }`
	elided := policy + `routing-instances { V { instance-type vrf; protocols { bgp { group g1 { type external; peer-as 65001; neighbor 10.0.0.2 export pol1; } } } } }`
	for _, tc := range []struct {
		name string
		text string
		skip bool
	}{
		{"braced/pass-off", braced, true},
		{"braced/pass-on", braced, false},
		{"elided/pass-off", elided, true},
		{"elided/pass-on", elided, false},
	} {
		if _, err := compile(tc.text, tc.skip); err != nil {
			t.Errorf("%s: no gate should fire on the export/import sites, got %v", tc.name, err)
		}
	}
	bOn, _ := compile(braced, false)
	be, bi := neighbourPolicies(bOn)
	if be != "pol1" || bi != "pol1" {
		t.Fatalf("CONTROL: braced export/import = %q/%q, want pol1/pol1", be, bi)
	}
	eOff, _ := compile(elided, true)
	if ex, _ := neighbourPolicies(eOff); ex != "" {
		t.Errorf("with the pass DISABLED the elided export should be DROPPED (that is the #9351 "+
			"defect and what makes the pass load-bearing here); got %q", ex)
	}
	eOn, _ := compile(elided, false)
	if ex, _ := neighbourPolicies(eOn); ex != "pol1" {
		t.Errorf("with the pass ENABLED the elided export must reach the neighbour like the braced "+
			"spelling does; got %q, braced gives %q", ex, be)
	}
}
