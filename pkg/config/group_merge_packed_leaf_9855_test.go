package config

import (
	"slices"
	"testing"
)

// Tests for #9855: a group's packed named-instance statement
// (`host 10.0.0.1 any any;`, `vrrp-group 1 priority 200;`) was dropped beside
// an inline leaf naming the same instance. The leaf branch of mergeNodes ran
// the #7648 expansion only against a container peer, so a leaf peer took the
// inline-wins override and the packed tail never compiled. Strict commit
// accepted every row below.
//
// The fix promotes the inline leaf peer to the container its braced spelling
// is and merges the expanded tail into it — one node, never adopt-beside
// (two `host` statements for one address compile two destinations, #9854).
// Same-statement conflicts keep inline-wins (flat-set and braced-merge
// agree, measured at 9603f2a5f); different properties union.
//
// SHAPE NOTE: the defect needs a packed GROUP leaf beside an inline LEAF.
// Flat-set SetPath normalizes packed runs into structured children, so these
// rows are expressible only via the hierarchical / NewParser path.

func compileSyslogHosts9855(t *testing.T, text string) []*SyslogHostConfig {
	t.Helper()
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if err := SchemaValidate(tree, cfg); err != nil {
		t.Fatalf("SchemaValidate rejected the fixture: %v", err)
	}
	if cfg.System.Syslog == nil {
		t.Fatalf("System.Syslog is nil, want hosts to compile (#9855)")
	}
	return cfg.System.Syslog.Hosts
}

func vrrpGroup9855(t *testing.T, text string) *VRRPGroup {
	t.Helper()
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if err := SchemaValidate(tree, cfg); err != nil {
		t.Fatalf("SchemaValidate rejected the fixture: %v", err)
	}
	unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
	for _, vg := range unit.VRRPGroups {
		if vg.ID == 1 {
			return vg
		}
	}
	t.Fatalf("vrrp-group 1 did not compile")
	return nil
}

func facilities9855(hosts []*SyslogHostConfig) []SyslogFacility {
	if len(hosts) != 1 {
		return nil
	}
	return hosts[0].Facilities
}

// TestPackedGroupLeafSyslog9855 pins the issue's syslog row and its merge
// semantics: union into one destination, inline-wins on a same-facility
// conflict, override for a different instance.
func TestPackedGroupLeafSyslog9855(t *testing.T) {
	group := func(inner string) string {
		return `groups { G { system { syslog { ` + inner + ` } } } } apply-groups G; system { syslog { `
	}
	cases := []struct {
		name string
		text string
		want []SyslogFacility
	}{
		{
			"group tail survives beside an inline host leaf",
			group(`host 10.0.0.1 any any;`) + `host 10.0.0.1; } }`,
			[]SyslogFacility{{Facility: "any", Severity: "any"}},
		},
		{
			"both present union into one destination",
			group(`host 10.0.0.1 any any;`) + `host 10.0.0.1 local0 info; } }`,
			[]SyslogFacility{{Facility: "local0", Severity: "info"}, {Facility: "any", Severity: "any"}},
		},
		{
			"same facility keeps the inline severity",
			group(`host 10.0.0.1 any emergency;`) + `host 10.0.0.1 any info; } }`,
			[]SyslogFacility{{Facility: "any", Severity: "info"}},
		},
		{
			"two group leaves merge into one destination",
			group(`host 10.0.0.1 any any; host 10.0.0.1 local0 info;`) + `host 10.0.0.1; } }`,
			[]SyslogFacility{{Facility: "any", Severity: "any"}, {Facility: "local0", Severity: "info"}},
		},
		{
			"packed group leaf merges into a braced inline host",
			group(`host 10.0.0.1 any any;`) + `host 10.0.0.1 { } } }`,
			[]SyslogFacility{{Facility: "any", Severity: "any"}},
		},
		{
			"packed group leaf keeps inline-wins against a braced inline host",
			group(`host 10.0.0.1 any emergency;`) + `host 10.0.0.1 { any info; } } }`,
			[]SyslogFacility{{Facility: "any", Severity: "info"}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hosts := compileSyslogHosts9855(t, c.text)
			if len(hosts) != 1 {
				t.Fatalf("want one destination for 10.0.0.1, got %d (#9854 regression?)", len(hosts))
			}
			if got := facilities9855(hosts); !slices.Equal(got, c.want) {
				t.Fatalf("facilities = %+v, want %+v", got, c.want)
			}
		})
	}
}

// TestPackedGroupLeafDifferentInstanceAdopts9859 pins the #9859 boundary: a
// packed group leaf naming ANOTHER instance is adopted beside an inline leaf,
// while the same-instance promotion behavior remains in the cells above.
func TestPackedGroupLeafDifferentInstanceAdopts9859(t *testing.T) {
	hosts := compileSyslogHosts9855(t,
		`groups { G { system { syslog { host 10.0.0.1 any any; } } } } apply-groups G; system { syslog { host 10.0.0.2; } }`)
	if len(hosts) != 2 {
		t.Fatalf("want both host instances 10.0.0.1 and 10.0.0.2, got %+v", hosts)
	}
	byAddress := map[string]*SyslogHostConfig{}
	for _, host := range hosts {
		byAddress[host.Address] = host
	}
	if byAddress["10.0.0.1"] == nil || !slices.Equal(byAddress["10.0.0.1"].Facilities, []SyslogFacility{{Facility: "any", Severity: "any"}}) {
		t.Fatalf("group host 10.0.0.1 = %+v, want its packed facility", byAddress["10.0.0.1"])
	}
	if byAddress["10.0.0.2"] == nil || len(byAddress["10.0.0.2"].Facilities) != 0 {
		t.Fatalf("inline host 10.0.0.2 = %+v, want no inherited facilities", byAddress["10.0.0.2"])
	}
}

// TestPackedGroupLeafVRRP9855 pins the issue comment's VRRP row: the group's
// packed priority and the inline packed virtual-address both compile into
// group 1. A dropped priority changes mastership (Medium severity).
func TestPackedGroupLeafVRRP9855(t *testing.T) {
	addr := func(inner string) string {
		return `interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { ` + inner + ` } } } } }`
	}
	group := func(inner string) string {
		return `groups { G { ` + addr(inner) + ` } } apply-groups G; `
	}
	t.Run("group priority plus inline virtual-address", func(t *testing.T) {
		vg := vrrpGroup9855(t,
			group(`vrrp-group 1 priority 200;`)+addr(`vrrp-group 1 virtual-address 10.0.61.1/24;`))
		if vg.Priority != 200 {
			t.Fatalf("priority = %d, want 200 (the group tail was dropped)", vg.Priority)
		}
		if !slices.Equal(vg.VirtualAddresses, []string{"10.0.61.1/24"}) {
			t.Fatalf("virtual-addresses = %v, want [10.0.61.1/24]", vg.VirtualAddresses)
		}
	})
	t.Run("same property keeps the inline priority", func(t *testing.T) {
		vg := vrrpGroup9855(t,
			group(`vrrp-group 1 priority 200;`)+addr(`vrrp-group 1 priority 100 virtual-address 10.0.61.1/24;`))
		if vg.Priority != 100 {
			t.Fatalf("priority = %d, want 100 (inline wins)", vg.Priority)
		}
	})
	t.Run("virtual-address unions across group and inline", func(t *testing.T) {
		vg := vrrpGroup9855(t,
			group(`vrrp-group 1 virtual-address 10.0.61.2/24;`)+addr(`vrrp-group 1 virtual-address 10.0.61.1/24;`))
		if !slices.Equal(vg.VirtualAddresses, []string{"10.0.61.1/24", "10.0.61.2/24"}) {
			t.Fatalf("virtual-addresses = %v, want inline first, group appended", vg.VirtualAddresses)
		}
	})
	t.Run("different instance remains distinct", func(t *testing.T) {
		text := group(`vrrp-group 2 priority 200 virtual-address 10.0.61.3/24;`) +
			addr(`vrrp-group 1 virtual-address 10.0.61.1/24;`)
		tree := parseHierarchical(t, text)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		unit := cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0]
		if len(unit.VRRPGroups) != 2 {
			t.Fatalf("VRRP groups = %+v, want distinct IDs 1 and 2", unit.VRRPGroups)
		}
		priority := map[int]int{}
		for _, group := range unit.VRRPGroups {
			priority[group.ID] = group.Priority
		}
		if priority[1] != 100 || priority[2] != 200 {
			t.Fatalf("VRRP priorities = %v, want ID1=100 and ID2=200", priority)
		}
	})
	t.Run("canonical alias never beats inline, either src order", func(t *testing.T) {
		// `vrrp-group 01` canonicalizes to group 1 at compile (Atoi), so a
		// group alias adopted beside the promoted node would hand the group
		// value a last-wins victory over inline. Both src orders must keep
		// the inline priority.
		for _, inner := range []string{
			`vrrp-group 1 priority 200; vrrp-group 01 priority 150;`,
			`vrrp-group 01 priority 150; vrrp-group 1 priority 200;`,
		} {
			vg := vrrpGroup9855(t,
				group(inner)+addr(`vrrp-group 1 priority 100 virtual-address 10.0.61.1/24;`))
			if vg.Priority != 100 {
				t.Fatalf("order %q: priority = %d, want 100 (inline beats the group alias)", inner, vg.Priority)
			}
			if !slices.Equal(vg.VirtualAddresses, []string{"10.0.61.1/24"}) {
				t.Fatalf("order %q: virtual-addresses = %v, want [10.0.61.1/24]", inner, vg.VirtualAddresses)
			}
		}
	})
}

// TestPackedGroupLeafTypoTailKeepsOverride9855 pins the conservative bail:
// an inline peer tail that does not expand under the schema keeps override,
// and the merged tree still carries the tail tokens verbatim so downstream
// gates scanning Keys see exactly what the operator wrote.
func TestPackedGroupLeafTypoTailKeepsOverride9855(t *testing.T) {
	text := `groups { G { interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { vrrp-group 1 priority 200; } } } } } } } apply-groups G; ` +
		`interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { vrrp-group 1 scren edge; } } } } }`
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	var prio int
	for _, vg := range cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].VRRPGroups {
		prio = vg.Priority
	}
	if prio != 100 {
		t.Fatalf("priority = %d, want 100 (the group tail was dropped by override)", prio)
	}
	expanded := parseHierarchical(t, text)
	if err := expanded.ExpandGroups(); err != nil {
		t.Fatalf("expand: %v", err)
	}
	found := false
	var walk func(nodes []*Node)
	walk = func(nodes []*Node) {
		for _, n := range nodes {
			if len(n.Keys) >= 2 && n.Keys[0] == "vrrp-group" && n.Keys[1] == "1" {
				found = true
				if !slices.Equal(n.Keys, []string{"vrrp-group", "1", "scren", "edge"}) {
					t.Fatalf("merged Keys = %q, want the typo tail intact", n.Keys)
				}
			}
			walk(n.Children)
		}
	}
	walk(expanded.Children)
	if !found {
		t.Fatal("merged tree lost the vrrp-group 1 node")
	}
}

// TestPackedGroupLeafSingleHostNode9855 pins the no-adopt-beside invariant at
// the AST level: after expansion exactly one `host` node names the address,
// however many packed leaves fed it. These stay red where #10048's compiler
// coalescing masks the twin: coalescing repairs the destination count, not
// the AST.
func TestPackedGroupLeafSingleHostNode9855(t *testing.T) {
	for _, tc := range []struct{ group, inline string }{
		{`host 10.0.0.1 any any;`, `host 10.0.0.1;`},
		{`host 10.0.0.1 any any; host 10.0.0.1 local0 info;`, `host 10.0.0.1;`},
		{`host 10.0.0.1 any any;`, `host 10.0.0.1 { }`},
		{`host 10.0.0.1 any emergency;`, `host 10.0.0.1 { any info; }`},
	} {
		text := `groups { G { system { syslog { ` + tc.group + ` } } } } apply-groups G; system { syslog { ` + tc.inline + ` } }`
		tree := parseHierarchical(t, text)
		if err := tree.ExpandGroups(); err != nil {
			t.Fatalf("expand: %v", err)
		}
		n := 0
		var walk func(nodes []*Node)
		walk = func(nodes []*Node) {
			for _, node := range nodes {
				if len(node.Keys) >= 2 && node.Keys[0] == "host" && node.Keys[1] == "10.0.0.1" {
					n++
				}
				walk(node.Children)
			}
		}
		walk(tree.Children)
		if n != 1 {
			t.Fatalf("want exactly one host 10.0.0.1 node for group %q inline %q, got %d", tc.group, tc.inline, n)
		}
	}
}

// TestPackedGroupLeafBareTwinSuppressed9855 pins failure 2: a trailing bare
// group leaf (`host A;`) names an instance the merge already promoted and
// adds nothing, so it is suppressed — never adopted beside as a twin. The
// AST assertion is the load-bearing one: #10048 coalesces twins at compile,
// which masks but does not repair the duplicate node.
func TestPackedGroupLeafBareTwinSuppressed9855(t *testing.T) {
	text := `groups { G { system { syslog { host 10.0.0.1 any any; host 10.0.0.1; } } } } apply-groups G; system { syslog { host 10.0.0.1; } }`
	hosts := compileSyslogHosts9855(t, text)
	if len(hosts) != 1 {
		t.Fatalf("want one destination, got %d", len(hosts))
	}
	if got, want := facilities9855(hosts), []SyslogFacility{{Facility: "any", Severity: "any"}}; !slices.Equal(got, want) {
		t.Fatalf("facilities = %+v, want %+v", got, want)
	}
	tree := parseHierarchical(t, text)
	if err := tree.ExpandGroups(); err != nil {
		t.Fatalf("expand: %v", err)
	}
	n := 0
	var walk func(nodes []*Node)
	walk = func(nodes []*Node) {
		for _, node := range nodes {
			if len(node.Keys) >= 2 && node.Keys[0] == "host" && node.Keys[1] == "10.0.0.1" {
				n++
			}
			walk(node.Children)
		}
	}
	walk(tree.Children)
	if n != 1 {
		t.Fatalf("want exactly one host 10.0.0.1 node, got %d (bare twin adopted)", n)
	}
}

// TestPackedGroupLeafHiddenPeerMerges9855 pins failure 3: an unrelated inline
// leaf (`host B;`) must not hide the promoted same-instance peer. The second
// packed leaf still finds the promoted container and merges.
func TestPackedGroupLeafHiddenPeerMerges9855(t *testing.T) {
	hosts := compileSyslogHosts9855(t,
		`groups { G { system { syslog { host 10.0.0.1 any any; host 10.0.0.1 local0 info; } } } } apply-groups G; system { syslog { host 10.0.0.1; host 10.0.0.2; } }`)
	if len(hosts) != 2 {
		t.Fatalf("want two destinations (A and B), got %d", len(hosts))
	}
	if got, want := hosts[0].Facilities, []SyslogFacility{{Facility: "any", Severity: "any"}, {Facility: "local0", Severity: "info"}}; hosts[0].Address != "10.0.0.1" || !slices.Equal(got, want) {
		t.Fatalf("host A = %+v, want both tails", hosts[0])
	}
	if hosts[1].Address != "10.0.0.2" || len(hosts[1].Facilities) != 0 {
		t.Fatalf("host B = %+v, want the bare inline leaf untouched", hosts[1])
	}
}

// TestPackedGroupLeafSuccessiveDifferentInstanceAdopts9859 pins the #9859
// boundary across successive merges. After a promotion, a packed or bare
// group leaf naming another instance is still adopted; #10056 requires this
// result to be independent of source order.
func TestPackedGroupLeafSuccessiveDifferentInstanceAdopts9859(t *testing.T) {
	cases := []struct {
		inner string
		wantB []SyslogFacility
	}{
		{
			inner: `host 10.0.0.1 any any; host 10.0.0.2 local0 info;`,
			wantB: []SyslogFacility{{Facility: "local0", Severity: "info"}},
		},
		{
			inner: `host 10.0.0.1 any any; host 10.0.0.2;`,
			wantB: nil,
		},
	}
	for _, tc := range cases {
		hosts := compileSyslogHosts9855(t,
			`groups { G { system { syslog { `+tc.inner+` } } } } apply-groups G; system { syslog { host 10.0.0.1; } }`)
		if len(hosts) != 2 {
			t.Fatalf("inner %q: want both host instances, got %+v", tc.inner, hosts)
		}
		byAddress := map[string]*SyslogHostConfig{}
		for _, host := range hosts {
			byAddress[host.Address] = host
		}
		if byAddress["10.0.0.1"] == nil || !slices.Equal(byAddress["10.0.0.1"].Facilities, []SyslogFacility{{Facility: "any", Severity: "any"}}) {
			t.Fatalf("inner %q: host A = %+v, want the promoted group facility", tc.inner, byAddress["10.0.0.1"])
		}
		if byAddress["10.0.0.2"] == nil || !slices.Equal(byAddress["10.0.0.2"].Facilities, tc.wantB) {
			t.Fatalf("inner %q: host B = %+v, want facilities %+v", tc.inner, byAddress["10.0.0.2"], tc.wantB)
		}
	}
}

// TestPackedGroupLeafBracketedPeerBails9855 keeps the conservative bail for
// a genuinely unexpandable bracketed tail: the valid multi-value run expands,
// but an unknown trailing property remains outside the schema walk. The
// helper must preserve the whole tail and keep inline-wins override.
func TestPackedGroupLeafBracketedPeerBails9855(t *testing.T) {
	text := `groups { G { interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { vrrp-group 1 priority 200; } } } } } } } apply-groups G; ` +
		`interfaces { ge-0/0/0 { unit 0 { family inet { address 10.0.61.2/24 { vrrp-group 1 virtual-address [ 10.0.61.1/24 10.0.61.3/24 ] scren edge; } } } } }`
	tree := parseHierarchical(t, text)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	var vg *VRRPGroup
	for _, g := range cfg.Interfaces.Interfaces["ge-0/0/0"].Units[0].VRRPGroups {
		vg = g
	}
	if vg == nil {
		t.Fatal("vrrp-group 1 did not compile")
	}
	if vg.Priority != 100 {
		t.Fatalf("priority = %d, want 100 (group tail dropped by bailout override)", vg.Priority)
	}
	if len(vg.VirtualAddresses) < 2 ||
		!slices.Equal(vg.VirtualAddresses[:2], []string{"10.0.61.1/24", "10.0.61.3/24"}) {
		t.Fatalf("virtual-addresses = %v, want the two inline VIPs first", vg.VirtualAddresses)
	}
	expanded := parseHierarchical(t, text)
	if err := expanded.ExpandGroups(); err != nil {
		t.Fatalf("expand: %v", err)
	}
	found := false
	var walk func(nodes []*Node)
	walk = func(nodes []*Node) {
		for _, n := range nodes {
			if len(n.Keys) >= 2 && n.Keys[0] == "vrrp-group" && n.Keys[1] == "1" {
				found = true
				if !slices.Equal(n.Keys, []string{"vrrp-group", "1", "virtual-address", "10.0.61.1/24", "10.0.61.3/24", "scren", "edge"}) {
					t.Fatalf("merged Keys = %q, want the unexpandable bracketed tail intact", n.Keys)
				}
			}
			walk(n.Children)
		}
	}
	walk(expanded.Children)
	if !found {
		t.Fatal("merged tree lost the vrrp-group 1 node")
	}
}
