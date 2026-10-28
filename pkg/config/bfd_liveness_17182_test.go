package config

import "testing"

// #17182 (R4-Q21-03): the five `bfd-liveness-detection` sites must
// compile identically through the single reader
// (parseBFDLiveness17182). Each row supplies the same BFD intent
// (minimum-interval 300, multiplier 3, or inherited from the BGP
// group) in the two spellings the issue names — braced block and
// flat-set split — and asserts the compiled triplet matches.
// BGP-neighbor inherits the group's BFD when it has none of its own,
// so its "flat-set" row authors the group value and expects the
// neighbor to inherit it; its braced row authors the neighbor's own
// override. Both must land on (true, 300, 3).

type bfdSite17182 struct {
	name    string
	braced  string // hierarchical text
	setCmds []string
	get     func(*Config) (bfd bool, interval, mult int, ok bool)
}

func bfdSites17182() []bfdSite17182 {
	ospfGet := func(c *Config) (bool, int, int, bool) {
		if c.Protocols.OSPF == nil || len(c.Protocols.OSPF.Areas) == 0 || len(c.Protocols.OSPF.Areas[0].Interfaces) == 0 {
			return false, 0, 0, false
		}
		f := c.Protocols.OSPF.Areas[0].Interfaces[0]
		return f.BFD, f.BFDInterval, f.BFDMultiplier, true
	}
	ospf3Get := func(c *Config) (bool, int, int, bool) {
		if c.Protocols.OSPFv3 == nil || len(c.Protocols.OSPFv3.Areas) == 0 || len(c.Protocols.OSPFv3.Areas[0].Interfaces) == 0 {
			return false, 0, 0, false
		}
		f := c.Protocols.OSPFv3.Areas[0].Interfaces[0]
		return f.BFD, f.BFDInterval, f.BFDMultiplier, true
	}
	isisGet := func(c *Config) (bool, int, int, bool) {
		if c.Protocols.ISIS == nil || len(c.Protocols.ISIS.Interfaces) == 0 {
			return false, 0, 0, false
		}
		f := c.Protocols.ISIS.Interfaces[0]
		return f.BFD, f.BFDInterval, f.BFDMultiplier, true
	}
	bgpNeighborGet := func(c *Config) (bool, int, int, bool) {
		if c.Protocols.BGP == nil || len(c.Protocols.BGP.Neighbors) == 0 {
			return false, 0, 0, false
		}
		n := c.Protocols.BGP.Neighbors[0]
		return n.BFD, n.BFDInterval, n.BFDMultiplier, true
	}
	return []bfdSite17182{
		{
			name: "ospf",
			braced: `protocols { ospf { area 0.0.0.0 { interface ge-0/0/1.0 {
				bfd-liveness-detection { minimum-interval 300; multiplier 3; } } } } }`,
			setCmds: []string{
				"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 bfd-liveness-detection minimum-interval 300",
				"set protocols ospf area 0.0.0.0 interface ge-0/0/1.0 bfd-liveness-detection multiplier 3",
			},
			get: ospfGet,
		},
		{
			name: "ospf3",
			braced: `protocols { ospf3 { area 0.0.0.0 { interface ge-0/0/1.0 {
				bfd-liveness-detection { minimum-interval 300; multiplier 3; } } } } }`,
			setCmds: []string{
				"set protocols ospf3 area 0.0.0.0 interface ge-0/0/1.0 bfd-liveness-detection minimum-interval 300",
				"set protocols ospf3 area 0.0.0.0 interface ge-0/0/1.0 bfd-liveness-detection multiplier 3",
			},
			get: ospf3Get,
		},
		{
			name: "isis",
			braced: `protocols { isis { net 49.0001.0100.0000.0001.00;
				interface ge-0/0/1.0 { bfd-liveness-detection { minimum-interval 300; multiplier 3; } } } }`,
			setCmds: []string{
				"set protocols isis net 49.0001.0100.0000.0001.00",
				"set protocols isis interface ge-0/0/1.0 bfd-liveness-detection minimum-interval 300",
				"set protocols isis interface ge-0/0/1.0 bfd-liveness-detection multiplier 3",
			},
			get: isisGet,
		},
		{
			name: "bgp-group",
			braced: `protocols { bgp { local-as 65001; group G { peer-as 65002;
				bfd-liveness-detection { minimum-interval 300; multiplier 3; }
				neighbor 10.0.2.1; } } }`,
			setCmds: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group G peer-as 65002",
				"set protocols bgp group G bfd-liveness-detection minimum-interval 300",
				"set protocols bgp group G bfd-liveness-detection multiplier 3",
				"set protocols bgp group G neighbor 10.0.2.1",
			},
			get: bgpNeighborGet,
		},
		{
			name: "bgp-neighbor",
			braced: `protocols { bgp { local-as 65001; group G { peer-as 65002;
				neighbor 10.0.2.1 { bfd-liveness-detection { minimum-interval 300; multiplier 3; } } } } }`,
			setCmds: []string{
				"set protocols bgp local-as 65001",
				"set protocols bgp group G peer-as 65002",
				"set protocols bgp group G neighbor 10.0.2.1 bfd-liveness-detection minimum-interval 300",
				"set protocols bgp group G neighbor 10.0.2.1 bfd-liveness-detection multiplier 3",
			},
			get: bgpNeighborGet,
		},
	}
}

// TestBFDLivenessParity17182 is the 5-paths x {braced, flat-set split}
// table the issue's acceptance criterion names. Every cell must
// compile to (BFD=true, interval=300, multiplier=3). Before #17182
// each cell was read by a separate hand-copied reader; a grammar
// change landing at one site left the others behind. The consolidated
// reader makes divergence structurally impossible — this cell proves
// all five dispatch sites actually reach it in both spellings.
func TestBFDLivenessParity17182(t *testing.T) {
	for _, site := range bfdSites17182() {
		t.Run(site.name+"/braced", func(t *testing.T) {
			cfg := compileHierStrict(t, site.braced)
			bfd, interval, mult, ok := site.get(cfg)
			if !ok {
				t.Fatalf("no compiled entity for %s braced", site.name)
			}
			if !bfd || interval != 300 || mult != 3 {
				t.Errorf("%s braced: BFD=%v interval=%d multiplier=%d, want true/300/3", site.name, bfd, interval, mult)
			}
		})
		t.Run(site.name+"/flat-set", func(t *testing.T) {
			cfg := compileSetStrict(t, site.setCmds...)
			bfd, interval, mult, ok := site.get(cfg)
			if !ok {
				t.Fatalf("no compiled entity for %s flat-set", site.name)
			}
			if !bfd || interval != 300 || mult != 3 {
				t.Errorf("%s flat-set: BFD=%v interval=%d multiplier=%d, want true/300/3", site.name, bfd, interval, mult)
			}
		})
	}
}

// TestBFDLivenessFieldWiseMerge17182 pins the field-wise merge the
// consolidated reader must preserve (Rev18229 B1): a
// `bfd-liveness-detection` node naming only ONE leaf must not wipe the
// other field already carried by the target. The former readers only
// assigned leaves that were present and parsed, so a neighbor seeded
// with group values kept the group's interval when it overrode only
// the multiplier, and find-or-create interface fragments merged
// field-wise. A zero-started reader result assigned wholesale breaks
// both.
func TestBFDLivenessFieldWiseMerge17182(t *testing.T) {
	bgpNeighbor := func(c *Config) (bool, int, int, bool) {
		if c.Protocols.BGP == nil || len(c.Protocols.BGP.Neighbors) == 0 {
			return false, 0, 0, false
		}
		n := c.Protocols.BGP.Neighbors[0]
		return n.BFD, n.BFDInterval, n.BFDMultiplier, true
	}
	ospfIface := func(c *Config) (bool, int, int, bool) {
		if c.Protocols.OSPF == nil || len(c.Protocols.OSPF.Areas) == 0 || len(c.Protocols.OSPF.Areas[0].Interfaces) == 0 {
			return false, 0, 0, false
		}
		f := c.Protocols.OSPF.Areas[0].Interfaces[0]
		return f.BFD, f.BFDInterval, f.BFDMultiplier, true
	}
	ospf3Iface := func(c *Config) (bool, int, int, bool) {
		if c.Protocols.OSPFv3 == nil || len(c.Protocols.OSPFv3.Areas) == 0 || len(c.Protocols.OSPFv3.Areas[0].Interfaces) == 0 {
			return false, 0, 0, false
		}
		f := c.Protocols.OSPFv3.Areas[0].Interfaces[0]
		return f.BFD, f.BFDInterval, f.BFDMultiplier, true
	}
	isisIface := func(c *Config) (bool, int, int, bool) {
		if c.Protocols.ISIS == nil || len(c.Protocols.ISIS.Interfaces) == 0 {
			return false, 0, 0, false
		}
		f := c.Protocols.ISIS.Interfaces[0]
		return f.BFD, f.BFDInterval, f.BFDMultiplier, true
	}

	t.Run("bgp-group-interval200-mult5-neighbor-only-mult4", func(t *testing.T) {
		cfg := compileHierStrict(t, `protocols { bgp { local-as 65001; group G { peer-as 65002;
			bfd-liveness-detection { minimum-interval 200; multiplier 5; }
			neighbor 10.0.2.1 { bfd-liveness-detection { multiplier 4; } } } } }`)
		bfd, interval, mult, ok := bgpNeighbor(cfg)
		if !ok {
			t.Fatal("no compiled BGP neighbor")
		}
		if !bfd || interval != 200 || mult != 4 {
			t.Errorf("BFD=%v interval=%d multiplier=%d, want true/200/4 (group interval inherited, neighbor multiplier wins)", bfd, interval, mult)
		}
	})
	t.Run("bgp-group-interval200-mult5-neighbor-only-mult4-flat-set", func(t *testing.T) {
		cfg := compileSetStrict(t,
			"set protocols bgp local-as 65001",
			"set protocols bgp group G peer-as 65002",
			"set protocols bgp group G bfd-liveness-detection minimum-interval 200",
			"set protocols bgp group G bfd-liveness-detection multiplier 5",
			"set protocols bgp group G neighbor 10.0.2.1 bfd-liveness-detection multiplier 4",
		)
		bfd, interval, mult, ok := bgpNeighbor(cfg)
		if !ok {
			t.Fatal("no compiled BGP neighbor")
		}
		if !bfd || interval != 200 || mult != 4 {
			t.Errorf("BFD=%v interval=%d multiplier=%d, want true/200/4 (group interval inherited, neighbor multiplier wins)", bfd, interval, mult)
		}
	})
	t.Run("ospf-two-fragments-interval300-then-mult3", func(t *testing.T) {
		cfg := compileHierStrict(t, `protocols { ospf { area 0.0.0.0 {
			interface ge-0/0/1.0 { bfd-liveness-detection { minimum-interval 300; } }
			interface ge-0/0/1.0 { bfd-liveness-detection { multiplier 3; } } } } }`)
		bfd, interval, mult, ok := ospfIface(cfg)
		if !ok {
			t.Fatal("no compiled OSPF interface")
		}
		if !bfd || interval != 300 || mult != 3 {
			t.Errorf("BFD=%v interval=%d multiplier=%d, want true/300/3 (fragments merge field-wise)", bfd, interval, mult)
		}
	})
	t.Run("ospf3-two-fragments-interval300-then-mult3", func(t *testing.T) {
		cfg := compileHierStrict(t, `protocols { ospf3 { area 0.0.0.0 {
			interface ge-0/0/1.0 { bfd-liveness-detection { minimum-interval 300; } }
			interface ge-0/0/1.0 { bfd-liveness-detection { multiplier 3; } } } } }`)
		bfd, interval, mult, ok := ospf3Iface(cfg)
		if !ok {
			t.Fatal("no compiled OSPFv3 interface")
		}
		if !bfd || interval != 300 || mult != 3 {
			t.Errorf("BFD=%v interval=%d multiplier=%d, want true/300/3 (fragments merge field-wise)", bfd, interval, mult)
		}
	})
	t.Run("isis-two-fragments-interval300-then-mult3", func(t *testing.T) {
		cfg := compileHierStrict(t, `protocols { isis { net 49.0001.0100.0000.0001.00;
			interface ge-0/0/1.0 { bfd-liveness-detection { minimum-interval 300; } }
			interface ge-0/0/1.0 { bfd-liveness-detection { multiplier 3; } } } }`)
		bfd, interval, mult, ok := isisIface(cfg)
		if !ok {
			t.Fatal("no compiled IS-IS interface")
		}
		if !bfd || interval != 300 || mult != 3 {
			t.Errorf("BFD=%v interval=%d multiplier=%d, want true/300/3 (fragments merge field-wise)", bfd, interval, mult)
		}
	})
	// Tolerant path: an unparseable present leaf keeps the inherited
	// value (the former readers dropped it without touching the field),
	// while a parseable sibling leaf still applies.
	t.Run("bgp-neighbor-unparseable-interval-keeps-group-interval", func(t *testing.T) {
		cfg := compileHierLenient(t, `protocols { bgp { local-as 65001; group G { peer-as 65002;
			bfd-liveness-detection { minimum-interval 200; multiplier 5; }
			neighbor 10.0.2.1 { bfd-liveness-detection { minimum-interval abc; multiplier 4; } } } } }`)
		bfd, interval, mult, ok := bgpNeighbor(cfg)
		if !ok {
			t.Fatal("no compiled BGP neighbor")
		}
		if !bfd || interval != 200 || mult != 4 {
			t.Errorf("BFD=%v interval=%d multiplier=%d, want true/200/4 (unparseable interval keeps group value, multiplier wins)", bfd, interval, mult)
		}
	})
	t.Run("ospf-unparseable-second-fragment-keeps-first-fragment", func(t *testing.T) {
		cfg := compileHierLenient(t, `protocols { ospf { area 0.0.0.0 {
			interface ge-0/0/1.0 { bfd-liveness-detection { minimum-interval 300; multiplier 5; } }
			interface ge-0/0/1.0 { bfd-liveness-detection { minimum-interval abc; } } } } }`)
		bfd, interval, mult, ok := ospfIface(cfg)
		if !ok {
			t.Fatal("no compiled OSPF interface")
		}
		if !bfd || interval != 300 || mult != 5 {
			t.Errorf("BFD=%v interval=%d multiplier=%d, want true/300/5 (unparseable leaf keeps prior fragment values)", bfd, interval, mult)
		}
	})
}

// TestBFDLivenessSchemaFactoryFresh17182 pins the fresh-pointer
// invariant: bfdLivenessSchema17182 must return independent nodes so
// TestEveryBFDSiteIsTyped9012 counts five sites and one site's
// mutation cannot leak into another.
func TestBFDLivenessSchemaFactoryFresh17182(t *testing.T) {
	a := bfdLivenessSchema17182()
	b := bfdLivenessSchema17182()
	if a == b {
		t.Fatal("factory returned the same *schemaNode twice; sites would share fate")
	}
	if a.children["minimum-interval"] == b.children["minimum-interval"] {
		t.Fatal("factory shared the minimum-interval child between calls")
	}
	a.children["minimum-interval"].desc = "mutated"
	if b.children["minimum-interval"].desc == "mutated" {
		t.Fatal("mutation of one factory node leaked into another")
	}
}

// TestParseBFDLiveness17182 unit-pins the consolidated reader:
// presence enables, values parse, garbage/unset leaves defaults.
func TestParseBFDLiveness17182(t *testing.T) {
	if got := parseBFDLiveness17182(nil); got.enabled {
		t.Errorf("nil node: enabled=true, want false")
	}
	node := &Node{Keys: []string{"bfd-liveness-detection"}, Children: []*Node{
		{Keys: []string{"minimum-interval", "300"}},
		{Keys: []string{"multiplier", "3"}},
	}}
	got := parseBFDLiveness17182(node)
	if !got.enabled || got.interval != 300 || got.multiplier != 3 || !got.intervalSet || !got.multiplierSet {
		t.Errorf("full node: %+v, want enabled/300/3 with both presence flags set", got)
	}
	bad := &Node{Keys: []string{"bfd-liveness-detection"}, Children: []*Node{
		{Keys: []string{"minimum-interval", "abc"}},
	}}
	got = parseBFDLiveness17182(bad)
	if !got.enabled || got.interval != 0 || got.intervalSet || got.multiplierSet {
		t.Errorf("garbage interval: %+v, want enabled with interval 0 and no presence flags (tolerant drop)", got)
	}
	// Per-field presence (Rev18229 B1): only the named leaf's flag is
	// set, and apply assigns only that field so the target's other
	// field survives.
	onlyMult := &Node{Keys: []string{"bfd-liveness-detection"}, Children: []*Node{
		{Keys: []string{"multiplier", "4"}},
	}}
	got = parseBFDLiveness17182(onlyMult)
	if !got.enabled || got.intervalSet || !got.multiplierSet || got.multiplier != 4 {
		t.Errorf("only-multiplier node: %+v, want enabled with only multiplierSet/4", got)
	}
	enabled, interval, multiplier := false, 200, 5
	got.apply(&enabled, &interval, &multiplier)
	if !enabled || interval != 200 || multiplier != 4 {
		t.Errorf("apply(only-mult) onto (false,200,5): got (%v,%d,%d), want (true,200,4)", enabled, interval, multiplier)
	}
	// An unparseable present leaf must not wipe the inherited value.
	enabled, interval, multiplier = true, 200, 5
	parseBFDLiveness17182(bad).apply(&enabled, &interval, &multiplier)
	if !enabled || interval != 200 || multiplier != 5 {
		t.Errorf("apply(garbage) onto (true,200,5): got (%v,%d,%d), want (true,200,5)", enabled, interval, multiplier)
	}
	// A disabled (nil/absent) result applies nothing.
	enabled, interval, multiplier = false, 200, 5
	parseBFDLiveness17182(nil).apply(&enabled, &interval, &multiplier)
	if enabled || interval != 200 || multiplier != 5 {
		t.Errorf("apply(nil) onto (false,200,5): got (%v,%d,%d), want unchanged", enabled, interval, multiplier)
	}
}
