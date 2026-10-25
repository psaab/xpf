package config

import (
	"strings"
	"testing"
)

// #1387 stale-lease-cleanup slice (Path S): expired-leases-processing
// config-model tests. The dual-AST tests use the production
// ParseSetCommand + SetPath path (buildTree) for flat-set, never NewParser
// for flat-set (the merge gotcha in CLAUDE.md); the hierarchical case uses
// NewParser on real block syntax. They prove dual-AST compile equality, the
// per-family attachment, the empty-block-is-absent guard, the H2 set-vs-0
// distinction, and the schema typed-leaf floors at commit check.

func elpV4(t *testing.T, cfg *Config) *DHCPExpiredLeasesConfig {
	t.Helper()
	if cfg.System.DHCPServer.DHCPLocalServer == nil {
		return nil
	}
	return cfg.System.DHCPServer.DHCPLocalServer.ExpiredLeases
}

func elpV6(t *testing.T, cfg *Config) *DHCPExpiredLeasesConfig {
	t.Helper()
	if cfg.System.DHCPServer.DHCPv6LocalServer == nil {
		return nil
	}
	return cfg.System.DHCPServer.DHCPv6LocalServer.ExpiredLeases
}

// TestDHCPExpiredLeasesHierarchicalAndFlatSetCompileEqually is the dual-AST
// equality proof (invariant H6): the hierarchical block and the flat-set
// spelling must compile to the same typed DHCPExpiredLeasesConfig.
func TestDHCPExpiredLeasesHierarchicalAndFlatSetCompileEqually(t *testing.T) {
	flat := buildTree(t, []string{
		"set system services dhcp-local-server expired-leases-processing enable",
		"set system services dhcp-local-server expired-leases-processing reclaim-timer 10",
		"set system services dhcp-local-server expired-leases-processing flush-timer 25",
		"set system services dhcp-local-server expired-leases-processing hold-time 600",
		"set system services dhcp-local-server expired-leases-processing max-leases 100",
		"set system services dhcp-local-server expired-leases-processing max-time 250",
		"set system services dhcp-local-server expired-leases-processing unwarned-cycles 5",
	})
	cflat, err := CompileConfig(flat)
	if err != nil {
		t.Fatalf("CompileConfig(flat): %v", err)
	}
	cf := elpV4(t, cflat)
	if cf == nil {
		t.Fatal("flat-set expired-leases-processing compiled to nil")
	}

	want := &DHCPExpiredLeasesConfig{
		Enabled:                 true,
		ReclaimTimerWait:        10,
		FlushReclaimedTimerWait: 25,
		HoldReclaimedTime:       600,
		MaxReclaimLeases:        100,
		MaxReclaimLeasesSet:     true,
		MaxReclaimTime:          250,
		MaxReclaimTimeSet:       true,
		UnwarnedReclaimCycles:   5,
	}
	if *cf != *want {
		t.Fatalf("flat-set mismatch:\n got %+v\nwant %+v", *cf, *want)
	}

	hierSrc := `system {
  services {
    dhcp-local-server {
      expired-leases-processing {
        enable;
        reclaim-timer 10;
        flush-timer 25;
        hold-time 600;
        max-leases 100;
        max-time 250;
        unwarned-cycles 5;
      }
    }
  }
}`
	hp := NewParser(hierSrc)
	htree, perrs := hp.Parse()
	if len(perrs) > 0 {
		t.Fatalf("hierarchical Parse: %v", perrs)
	}
	chier, err := CompileConfig(htree)
	if err != nil {
		t.Fatalf("CompileConfig(hier): %v", err)
	}
	ch := elpV4(t, chier)
	if ch == nil {
		t.Fatal("hierarchical expired-leases-processing compiled to nil")
	}
	if *ch != *cf {
		t.Fatalf("hierarchical vs flat-set differ:\n hier %+v\n flat %+v", *ch, *cf)
	}
}

// TestDHCPExpiredLeasesAbsentByDefault: no block => nil => zero behaviour
// change (invariant H1 at the model layer).
func TestDHCPExpiredLeasesAbsentByDefault(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set system services dhcp-local-server group g0 interface ge-0/0/0",
		"set system services dhcp-local-server group g0 pool p0 subnet 10.0.1.0/24",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if elpV4(t, cfg) != nil {
		t.Fatal("absent expired-leases-processing must compile to nil")
	}
}

// TestDHCPExpiredLeasesPerFamilyIndependence: the block attaches to the
// per-family DHCPLocalServerConfig, NOT a shared DHCPServerConfig field, so
// a v4-only block leaves v6 nil and vice-versa (invariant H3).
func TestDHCPExpiredLeasesPerFamilyIndependence(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set system services dhcp-local-server expired-leases-processing enable",
		"set system services dhcp-local-server expired-leases-processing reclaim-timer 11",
		"set system services dhcpv6-local-server expired-leases-processing enable",
		"set system services dhcpv6-local-server expired-leases-processing reclaim-timer 22",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	v4 := elpV4(t, cfg)
	v6 := elpV6(t, cfg)
	if v4 == nil || v4.ReclaimTimerWait != 11 {
		t.Fatalf("v4 block not compiled independently: %+v", v4)
	}
	if v6 == nil || v6.ReclaimTimerWait != 22 {
		t.Fatalf("v6 block not compiled independently: %+v", v6)
	}

	// v4-only: v6 must stay nil.
	cfg4, err := CompileConfig(buildTree(t, []string{
		"set system services dhcp-local-server expired-leases-processing enable",
		"set system services dhcpv6-local-server group g0 pool p0 subnet 2001:db8::/64",
	}))
	if err != nil {
		t.Fatalf("CompileConfig(v4-only): %v", err)
	}
	if elpV4(t, cfg4) == nil {
		t.Fatal("v4 block missing")
	}
	if elpV6(t, cfg4) != nil {
		t.Fatalf("v6 must be nil when only v4 configures the block, got %+v", elpV6(t, cfg4))
	}
}

// TestDHCPExpiredLeasesMaxKnobsSetVsUnset pins the H2 model distinction:
// `max-leases 0` (and `max-time 0`) compile to value 0 WITH the *Set bool
// true (unlimited), distinct from not configuring them (*Set false). A bare
// `if x > 0` model would lose the unlimited intent.
func TestDHCPExpiredLeasesMaxKnobsSetVsUnset(t *testing.T) {
	t.Run("explicit 0 latches Set", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server expired-leases-processing enable",
			"set system services dhcp-local-server expired-leases-processing max-leases 0",
			"set system services dhcp-local-server expired-leases-processing max-time 0",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		c := elpV4(t, cfg)
		if c == nil {
			t.Fatal("compiled to nil")
		}
		if !c.MaxReclaimLeasesSet || c.MaxReclaimLeases != 0 {
			t.Errorf("max-leases 0 must set MaxReclaimLeasesSet=true, value=0; got set=%v val=%d", c.MaxReclaimLeasesSet, c.MaxReclaimLeases)
		}
		if !c.MaxReclaimTimeSet || c.MaxReclaimTime != 0 {
			t.Errorf("max-time 0 must set MaxReclaimTimeSet=true, value=0; got set=%v val=%d", c.MaxReclaimTimeSet, c.MaxReclaimTime)
		}
	})

	t.Run("unset leaves Set false", func(t *testing.T) {
		cfg, err := CompileConfig(buildTree(t, []string{
			"set system services dhcp-local-server expired-leases-processing enable",
			"set system services dhcp-local-server expired-leases-processing reclaim-timer 10",
		}))
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		c := elpV4(t, cfg)
		if c == nil {
			t.Fatal("compiled to nil")
		}
		if c.MaxReclaimLeasesSet || c.MaxReclaimTimeSet {
			t.Errorf("unset cap knobs must keep *Set false; got leasesSet=%v timeSet=%v", c.MaxReclaimLeasesSet, c.MaxReclaimTimeSet)
		}
	})
}

// TestDHCPExpiredLeasesEnableOnlyCompiles: a block with only `enable` is a
// meaningful state (Kea defaults apply / render {}), so it compiles non-nil.
func TestDHCPExpiredLeasesEnableOnlyCompiles(t *testing.T) {
	cfg, err := CompileConfig(buildTree(t, []string{
		"set system services dhcp-local-server expired-leases-processing enable",
	}))
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	c := elpV4(t, cfg)
	if c == nil || !c.Enabled {
		t.Fatalf("enable-only block must compile to a non-nil enabled config, got %+v", c)
	}
}

// TestDHCPExpiredLeasesSchemaCompletes: the new subtree + its six leaves are
// offered by structural completion under both families (setSchema is the
// SSOT; completion and validation read the same node).
func TestDHCPExpiredLeasesSchemaCompletes(t *testing.T) {
	for _, parent := range []string{"dhcp-local-server", "dhcpv6-local-server"} {
		results := CompleteSetPathWithValues(
			[]string{"system", "services", parent}, nil)
		if !containsCompletionName(results, "expired-leases-processing") {
			t.Fatalf("expired-leases-processing not offered under %s: %v", parent, completionNames(results))
		}
		leaves := CompleteSetPathWithValues(
			[]string{"system", "services", parent, "expired-leases-processing"}, nil)
		for _, want := range []string{
			"enable", "reclaim-timer", "flush-timer", "hold-time",
			"max-leases", "max-time", "unwarned-cycles",
		} {
			if !containsCompletionName(leaves, want) {
				t.Errorf("leaf %q not offered under %s expired-leases-processing: %v", want, parent, completionNames(leaves))
			}
		}
	}
}

// TestDHCPExpiredLeasesSchemaValueCompletion: a typed leaf's value slot
// surfaces the placeholder + example values at `?` completion.
func TestDHCPExpiredLeasesSchemaValueCompletion(t *testing.T) {
	results := CompleteSetPathWithValues(
		[]string{"system", "services", "dhcp-local-server", "expired-leases-processing", "max-leases"}, nil)
	// The example values from the schema (100, 0) should appear.
	if !containsCompletionName(results, "0") || !containsCompletionName(results, "100") {
		t.Fatalf("max-leases value-slot completion should offer examples 0/100, got %v", completionNames(results))
	}
}

// TestDHCPExpiredLeasesSchemaRejectsTimerZero pins the SMR MAJOR-3 floor
// split: the three TIMERS use ValidateIntegerMin(1), so a 0 (which some Kea
// versions reject and would take DHCP down on the fail-closed restart) is a
// hard commit-check error.
func TestDHCPExpiredLeasesSchemaRejectsTimerZero(t *testing.T) {
	for _, timer := range []string{"reclaim-timer", "flush-timer", "hold-time"} {
		tree := &ConfigTree{}
		cmd := "set system services dhcp-local-server expired-leases-processing " + timer + " 0"
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
		_, _ = CompileConfig(tree)
		err = SchemaValidate(tree)
		if err == nil || !strings.Contains(err.Error(), timer) {
			t.Fatalf("%s 0 must be rejected (Min(1)), got %v", timer, err)
		}
	}
}

// TestDHCPExpiredLeasesSchemaAcceptsCapZero pins the other half of the floor
// split: the CAP knobs (max-leases, max-time) use ValidateIntegerMin(0), so
// 0 (= unlimited in Kea) is accepted at commit-check. unwarned-cycles is
// also Min(0).
func TestDHCPExpiredLeasesSchemaAcceptsCapZero(t *testing.T) {
	tree := &ConfigTree{}
	cmds := []string{
		"set system services dhcp-local-server expired-leases-processing enable",
		"set system services dhcp-local-server expired-leases-processing max-leases 0",
		"set system services dhcp-local-server expired-leases-processing max-time 0",
		"set system services dhcp-local-server expired-leases-processing unwarned-cycles 0",
	}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	_, _ = CompileConfig(tree)
	if err := SchemaValidate(tree); err != nil {
		t.Fatalf("cap knobs at 0 (unlimited) must pass commit-check, got %v", err)
	}
}

// TestDHCPExpiredLeasesSchemaRejectsNonInteger: a non-integer value for a
// typed leaf is rejected at commit-check.
func TestDHCPExpiredLeasesSchemaRejectsNonInteger(t *testing.T) {
	tree := &ConfigTree{}
	cmd := "set system services dhcp-local-server expired-leases-processing reclaim-timer notanumber"
	path, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath(%q): %v", cmd, err)
	}
	_, _ = CompileConfig(tree)
	err = SchemaValidate(tree)
	if err == nil || !strings.Contains(err.Error(), "reclaim-timer") {
		t.Fatalf("non-integer reclaim-timer must be rejected, got %v", err)
	}
}

// TestDHCPExpiredLeasesLenientCompile: a config carrying the block (even a
// timer value a later range-tightening would reject) must still COMPILE on
// the lenient load / peer-sync path — the model build is the shared
// compileExpanded core, so both the strict and lenient sites land it
// (invariant R4 / H7). The schema gate is separate and runs leniently as a
// warning on those paths (exercised in pkg/configstore).
func TestDHCPExpiredLeasesLenientCompile(t *testing.T) {
	tree := buildTree(t, []string{
		"set system services dhcp-local-server expired-leases-processing enable",
		"set system services dhcp-local-server expired-leases-processing reclaim-timer 10",
		"set system services dhcpv6-local-server expired-leases-processing enable",
		"set system services dhcpv6-local-server expired-leases-processing max-leases 0",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient must compile the block, got %v", err)
	}
	if elpV4(t, cfg) == nil || !elpV4(t, cfg).Enabled {
		t.Fatal("lenient compile dropped the v4 block")
	}
	c6 := elpV6(t, cfg)
	if c6 == nil || !c6.MaxReclaimLeasesSet {
		t.Fatalf("lenient compile dropped the v6 block / max-leases set state: %+v", c6)
	}
}

// validateELPLeaf16691 builds a flat-set tree carrying one
// expired-leases-processing leaf under the given family and returns the
// SchemaValidate error (nil when the leaf commits clean).
func validateELPLeaf16691(t *testing.T, family, leaf, value string) error {
	t.Helper()
	tree := &ConfigTree{}
	cmd := "set system services " + family + " expired-leases-processing " + leaf + " " + value
	path, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath(%q): %v", cmd, err)
	}
	_, _ = CompileConfig(tree)
	return SchemaValidate(tree)
}

// TestDHCPExpiredLeasesSchemaRejectsAboveKeaMax pins #16691: every
// expired-leases-processing leaf refuses a value above the bound the
// deployed Kea parser enforces, naming the leaf, on BOTH families.
// Before the fix the schema was min-only, so each row below committed
// clean and Kea then refused the whole family file.
func TestDHCPExpiredLeasesSchemaRejectsAboveKeaMax(t *testing.T) {
	rows := []struct{ leaf, value string }{
		{"reclaim-timer", "65536"},
		{"flush-timer", "65536"},
		{"unwarned-cycles", "65536"},
		{"max-time", "10001"},
		{"hold-time", "4294967296"},
		{"max-leases", "4294967296"},
	}
	for _, family := range []string{"dhcp-local-server", "dhcpv6-local-server"} {
		for _, r := range rows {
			err := validateELPLeaf16691(t, family, r.leaf, r.value)
			if err == nil || !strings.Contains(err.Error(), r.leaf) {
				t.Errorf("%s %s %s must be refused at commit naming the leaf, got %v", family, r.leaf, r.value, err)
			}
		}
	}
}

// TestDHCPExpiredLeasesSchemaAcceptsKeaBoundary pins the other side of
// #16691: every leaf at its Kea maximum (and the max-time probe from
// the issue just below it) still commits clean on both families, so
// the new maxima do not reject a value Kea accepts.
func TestDHCPExpiredLeasesSchemaAcceptsKeaBoundary(t *testing.T) {
	rows := []struct{ leaf, value string }{
		{"reclaim-timer", "65535"},
		{"reclaim-timer", "1"},
		{"flush-timer", "65535"},
		{"hold-time", "4294967295"},
		{"hold-time", "1"},
		{"max-leases", "4294967295"},
		{"max-leases", "0"},
		{"max-time", "10000"},
		{"max-time", "0"},
		{"unwarned-cycles", "65535"},
		{"unwarned-cycles", "0"},
	}
	for _, family := range []string{"dhcp-local-server", "dhcpv6-local-server"} {
		for _, r := range rows {
			if err := validateELPLeaf16691(t, family, r.leaf, r.value); err != nil {
				t.Errorf("%s %s %s is at Kea's boundary and must commit, got %v", family, r.leaf, r.value, err)
			}
		}
	}
}
