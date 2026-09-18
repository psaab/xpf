package config

import (
	"strings"
	"testing"
)

// parseHier9886 parses hierarchical config text. The control-byte fixtures
// below must be hierarchical: the lexer decodes \n inside quotes (lexer.go),
// which is exactly how a persisted or peer-synced identity key carrying a
// control byte re-enters through the text path.
func parseHier9886(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs[0])
	}
	return tree
}

func warningsJoin9886(w []string) string { return strings.Join(w, "\n") }

// TestLenientDropsControlByteInterfaceMember_9886 is the F-049 vector
// end-to-end: an identity key carrying a control byte is scrubbed to "ge 0" by
// #1798, and the scrubbed multi-pattern member must be DROPPED with a loud
// warning — not compiled (which would render a two-pattern [Match] Name=) and
// not a whole-compile hard error (which would safe-state Load and alarm-loop
// SyncApply for one never-usable member).
func TestLenientDropsControlByteInterfaceMember_9886(t *testing.T) {
	tree := parseHier9886(t, `interfaces {
  "ge\n0" { unit 0 { family inet { address 10.0.0.1/24; } } }
  ge-0-0-0 { unit 0 { family inet { address 10.0.0.2/24; } } }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must drop the poisoned member, not fail: %v", err)
	}
	if _, ok := cfg.Interfaces.Interfaces["ge 0"]; ok {
		t.Fatal(`"ge 0" must be dropped from the compiled interfaces`)
	}
	if _, ok := cfg.Interfaces.Interfaces["ge-0-0-0"]; !ok {
		t.Fatal("the well-formed sibling must survive the drop")
	}
	all := warningsJoin9886(cfg.Warnings)
	for _, want := range []string{"DROPPED", "#9886", "#1798", "[Match] Name="} {
		if !strings.Contains(all, want) {
			t.Errorf("drop warning must mention %q, got warnings:\n%s", want, all)
		}
	}
}

// TestLenientDropsLiteralSpaceInterfaceMember_9886 pins that a literally
// authored multi-pattern name (no control bytes, nothing for #1798 to scrub —
// the pre-#6834 population) is dropped the same way. Manufactured-vs-literal
// tracks no operational difference: the member is unusable either way.
func TestLenientDropsLiteralSpaceInterfaceMember_9886(t *testing.T) {
	tree := parseHier9886(t, `interfaces {
  "ge 0" { unit 0 { family inet { address 10.0.0.1/24; } } }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must drop the poisoned member, not fail: %v", err)
	}
	if _, ok := cfg.Interfaces.Interfaces["ge 0"]; ok {
		t.Fatal(`"ge 0" must be dropped from the compiled interfaces`)
	}
	all := warningsJoin9886(cfg.Warnings)
	if !strings.Contains(all, "DROPPED") || !strings.Contains(all, "#9886") {
		t.Fatalf("want the #9886 drop warning, got:\n%s", all)
	}
	if strings.Contains(all, "sanitized control characters") {
		t.Errorf("no scrub happened, so no #1798 sanitize warning must appear, got:\n%s", all)
	}
}

// TestStrictDirectCompileRejectsMultiPatternMember_9886 pins the strict arm:
// without the schema walk (direct CompileConfig), a multi-pattern member is a
// hard error naming the sink. On the commit path the schema walk rejects first
// with ValidateInterfaceName's message — pinned below as the no-new-behavior
// control.
func TestStrictDirectCompileRejectsMultiPatternMember_9886(t *testing.T) {
	tree := parseHier9886(t, `interfaces {
  "ge 0" { unit 0 { family inet { address 10.0.0.1/24; } } }
}`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("direct strict compile must hard-error on a multi-pattern member, got nil")
	}
	for _, want := range []string{"#9886", "[Match] Name="} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("strict error must mention %q, got %v", want, err)
		}
	}

	// Control: the commit path still rejects via the schema gate first.
	if serr := SchemaValidate(parseHier9886(t, `interfaces {
  "ge 0" { unit 0 { family inet { address 10.0.0.1/24; } } }
}`), nil); serr == nil || !strings.Contains(serr.Error(), "whitespace") {
		t.Fatalf("SchemaValidate must still reject the spaced name first, got %v", serr)
	}
}

// TestLenientDropsWhitespaceBridgeDomain_9886 covers the second identity
// position with the same sink: the dataplane names the bridge "br-"+name, so a
// whitespace bridge-domain name renders a two-pattern [Match] Name= as well.
func TestLenientDropsWhitespaceBridgeDomain_9886(t *testing.T) {
	tree := parseHier9886(t, `bridge-domains {
  "bd x" { vlan-id-list 10; }
  bd0 { vlan-id-list 20; }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must drop the poisoned member, not fail: %v", err)
	}
	for _, bd := range cfg.BridgeDomains {
		if bd != nil && bd.Name == "bd x" {
			t.Fatal(`"bd x" must be dropped from the compiled bridge domains`)
		}
	}
	found := false
	for _, bd := range cfg.BridgeDomains {
		if bd != nil && bd.Name == "bd0" {
			found = true
		}
	}
	if !found {
		t.Fatal("the well-formed sibling bridge domain must survive the drop")
	}
	all := warningsJoin9886(cfg.Warnings)
	for _, want := range []string{"DROPPED", "#9886", "br-"} {
		if !strings.Contains(all, want) {
			t.Errorf("drop warning must mention %q, got warnings:\n%s", want, all)
		}
	}
}

// TestLenientDropOrphansZoneRefToWarning_9886 is the drop-viability pin: refs
// to the dropped member (here a zone member) must WARN via the #4515
// downgrade, not re-fail the compile the drop just saved.
func TestLenientDropOrphansZoneRefToWarning_9886(t *testing.T) {
	tree := setTree(t,
		`set interfaces "ge 0" unit 0 family inet address 10.0.0.1/24`,
		"set interfaces ge-0-0-0 unit 0 family inet address 10.0.0.2/24",
		`set security zones security-zone trust interfaces "ge 0.0"`,
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must survive the orphaned zone ref: %v", err)
	}
	if _, ok := cfg.Interfaces.Interfaces["ge 0"]; ok {
		t.Fatal(`"ge 0" must be dropped from the compiled interfaces`)
	}
	all := warningsJoin9886(cfg.Warnings)
	for _, want := range []string{"#9886", "zone interface defined (downgraded to warning on tolerant path)"} {
		if !strings.Contains(all, want) {
			t.Errorf("warnings must contain %q, got:\n%s", want, all)
		}
	}
}

// TestLenientDropsApplyGroupsInheritedPoisonedMember_9886 pins that the gate
// sees the group-EXPANDED tree: a poisoned member inherited via apply-groups
// is dropped like an inline one.
func TestLenientDropsApplyGroupsInheritedPoisonedMember_9886(t *testing.T) {
	tree := setTree(t,
		`set groups g0 interfaces "ge 0" unit 0 family inet address 10.0.0.1/24`,
		"set apply-groups g0",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must drop the inherited poisoned member, not fail: %v", err)
	}
	if _, ok := cfg.Interfaces.Interfaces["ge 0"]; ok {
		t.Fatal(`inherited "ge 0" must be dropped from the compiled interfaces`)
	}
	if !strings.Contains(warningsJoin9886(cfg.Warnings), "#9886") {
		t.Fatalf("want the #9886 drop warning, got:\n%s", warningsJoin9886(cfg.Warnings))
	}
}

// TestLenientDropsRangeExpandedPoisonedMember_9886 pins that the gate runs
// post-expansion: a poisoned interface-range member materializes as an ordinary
// member before the walk, so it is dropped while its clean sibling compiles.
func TestLenientDropsRangeExpandedPoisonedMember_9886(t *testing.T) {
	tree := setTree(t,
		"set interfaces interface-range uplinks member ge-0/0/1",
		`set interfaces interface-range uplinks member "ge 0"`,
		"set interfaces interface-range uplinks unit 0 family inet address 10.0.0.9/24",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must drop the range-expanded poisoned member, not fail: %v", err)
	}
	if _, ok := cfg.Interfaces.Interfaces["ge 0"]; ok {
		t.Fatal(`range-expanded "ge 0" must be dropped from the compiled interfaces`)
	}
	if _, ok := cfg.Interfaces.Interfaces["ge-0/0/1"]; !ok {
		t.Fatal("the clean range sibling must survive the drop")
	}
	if !strings.Contains(warningsJoin9886(cfg.Warnings), "#9886") {
		t.Fatalf("want the #9886 drop warning, got:\n%s", warningsJoin9886(cfg.Warnings))
	}
}

// TestLenientKeepsWorkingSinglePatternNames_9886 is the anti-over-rejection
// half: a clean config, a UTF-8 name, and a unicode-space name all compile on
// the lenient path with the member PRESENT and no #9886 warning. The glob pins
// the #10089 boundary end-to-end: one pattern, still compiled here — the
// separate #10089 render-stage belt refuses it later, at the unit writers.
func TestLenientKeepsWorkingSinglePatternNames_9886(t *testing.T) {
	// NBSP spelled as an escape: it must be a real non-breaking space, which
	// is invisible in source — a literal would be unreviewable.
	nbspName := "ge\u00a00"
	tree := parseHier9886(t, "interfaces {\n"+
		"  ge-0-0-0 { unit 0 { family inet { address 10.0.0.2/24; } } }\n"+
		"  \"gé0\" { unit 0 { family inet { address 10.0.0.3/24; } } }\n"+
		"  \""+nbspName+"\" { unit 0 { family inet { address 10.0.0.4/24; } } }\n"+
		"  \"ge*\" { unit 0 { family inet { address 10.0.0.5/24; } } }\n"+
		"}")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile of single-pattern names must succeed: %v", err)
	}
	for _, name := range []string{"ge-0-0-0", "gé0", nbspName, "ge*"} {
		if _, ok := cfg.Interfaces.Interfaces[name]; !ok {
			t.Errorf("single-pattern name %q must survive lenient compile", name)
		}
	}
	if strings.Contains(warningsJoin9886(cfg.Warnings), "#9886") {
		t.Errorf("no #9886 warning must fire for single-pattern names, got:\n%s", warningsJoin9886(cfg.Warnings))
	}
}

// TestLenientDropsUnsafeDeviceMapEntry_9886 covers the device-map caller of
// the linksetup .link writer: the logical name becomes a [Link] Name=, a file
// name, and a kernel rename target, so a poisoned entry must be dropped on
// the tolerant path (where the schema validator only warns) rather than reach
// the daemon rename.
func TestLenientDropsUnsafeDeviceMapEntry_9886(t *testing.T) {
	tree := parseHier9886(t, `chassis {
  device-map {
    interface "ge 0" { pci 0000:09:00.0; }
    interface ge-0-0-1 { pci 0000:09:00.1; }
  }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must drop the poisoned entry, not fail: %v", err)
	}
	for _, e := range cfg.Chassis.DeviceMap.Entries {
		if e.LogicalName == "ge 0" {
			t.Fatal(`"ge 0" must be dropped from the compiled device-map entries`)
		}
	}
	found := false
	for _, e := range cfg.Chassis.DeviceMap.Entries {
		if e.LogicalName == "ge-0-0-1" {
			found = true
		}
	}
	if !found {
		t.Fatal("the clean device-map sibling must survive the drop")
	}
	all := warningsJoin9886(cfg.Warnings)
	for _, want := range []string{"DROPPED", "#9886", "device-map", "[Link] Name="} {
		if !strings.Contains(all, want) {
			t.Errorf("drop warning must mention %q, got warnings:\n%s", want, all)
		}
	}
}

// TestLenientDropsDeviceMapControlByteEntry_9886 is the scrub→drop chain for
// device-map: a control-byte logical name is scrubbed to "ge 0" by #1798 and
// the scrubbed entry is dropped with the breadcrumb warning.
func TestLenientDropsDeviceMapControlByteEntry_9886(t *testing.T) {
	tree := parseHier9886(t, `chassis {
  device-map {
    interface "ge\n0" { pci 0000:09:00.0; }
  }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must drop the poisoned entry, not fail: %v", err)
	}
	// Dropping the sole entry deactivates the map (empty block = absent =
	// positional mode), so DeviceMap itself may be nil — either way no
	// poisoned logical name may survive to the daemon rename.
	if dm := cfg.Chassis.DeviceMap; dm != nil {
		for _, e := range dm.Entries {
			if e.LogicalName == "ge 0" {
				t.Fatal(`scrubbed "ge 0" must be dropped from the compiled device-map entries`)
			}
		}
	}
	all := warningsJoin9886(cfg.Warnings)
	for _, want := range []string{"DROPPED", "#9886", "#1798"} {
		if !strings.Contains(all, want) {
			t.Errorf("drop warning must mention %q, got warnings:\n%s", want, all)
		}
	}
}

// TestLenientDropsDeviceMapFanoutAndFlatShapes_9886 pins that the gate mirrors
// the compiler's instance reader on the non-obvious shapes: the bare
// multi-name fan-out (every Keys[1:] token is an instance) and the flat-set
// children shape (each child's Keys[0] is an instance).
func TestLenientDropsDeviceMapFanoutAndFlatShapes_9886(t *testing.T) {
	t.Run("fanout", func(t *testing.T) {
		tree := parseHier9886(t, `chassis {
  device-map {
    interface "ge 0" ge-0-0-1 { pci 0000:09:00.0; }
  }
}`)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile must drop the poisoned instance, not fail: %v", err)
		}
		for _, e := range cfg.Chassis.DeviceMap.Entries {
			if e.LogicalName == "ge 0" {
				t.Fatal(`fan-out "ge 0" must be dropped`)
			}
		}
		found := false
		for _, e := range cfg.Chassis.DeviceMap.Entries {
			if e.LogicalName == "ge-0-0-1" && e.PCIAddr == "0000:09:00.0" {
				found = true
			}
		}
		if !found {
			t.Fatal("the clean fan-out sibling must survive with its shared props")
		}
	})
	t.Run("flat", func(t *testing.T) {
		tree := setTree(t,
			`set chassis device-map interface "ge 0" pci 0000:09:00.0`,
			"set chassis device-map interface ge-0-0-1 pci 0000:09:00.1",
		)
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile must drop the poisoned entry, not fail: %v", err)
		}
		for _, e := range cfg.Chassis.DeviceMap.Entries {
			if e.LogicalName == "ge 0" {
				t.Fatal(`flat-set "ge 0" must be dropped`)
			}
		}
		if !strings.Contains(warningsJoin9886(cfg.Warnings), "#9886") {
			t.Fatalf("want the #9886 drop warning, got:\n%s", warningsJoin9886(cfg.Warnings))
		}
	})
}

// TestStrictDirectCompileRejectsUnsafeDeviceMapEntry_9886 pins the strict arm
// for device-map. On the commit path the schema validator rejects first
// (control below); direct CompileConfig hits this gate instead.
func TestStrictDirectCompileRejectsUnsafeDeviceMapEntry_9886(t *testing.T) {
	tree := parseHier9886(t, `chassis {
  device-map {
    interface "ge 0" { pci 0000:09:00.0; }
  }
}`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("direct strict compile must hard-error on a poisoned device-map entry, got nil")
	}
	for _, want := range []string{"#9886", "device-map"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("strict error must mention %q, got %v", want, err)
		}
	}
	if serr := SchemaValidate(parseHier9886(t, `chassis {
  device-map {
    interface "ge 0" { pci 0000:09:00.0; }
  }
}`), nil); serr == nil {
		t.Fatal("SchemaValidate must still reject the spaced logical name first (control)")
	}
}

// TestLenientStripsUnsafeFabricMemberRefs_9886 pins the reconstruction close:
// surviving members' `member-interfaces` references to render-unsafe names are
// STRIPPED (the dataplane emits bond-member rows without a kernel-existence
// check, so a surviving reference would resurrect the dropped identity as a
// refused-but-partially-applied row). Bracket-list, repeated-statement, and
// nested-block spellings are all covered — the strip mirrors plainListValues.
func TestLenientStripsUnsafeFabricMemberRefs_9886(t *testing.T) {
	tree := parseHier9886(t, `interfaces {
  fab0 {
    fabric-options {
      member-interfaces [ "ge 0" ge-0/0/7 ];
      member-interfaces ge-7/0/7;
    }
    unit 0 { family inet { address 10.99.1.1/30; } }
  }
  fab1 {
    fabric-options {
      member-interfaces { "ge 1"; ge-0/0/8; }
    }
    unit 0 { family inet { address 10.99.2.1/30; } }
  }
  ge-0/0/7 { unit 0 { family inet { address 10.0.0.7/24; } } }
}`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must strip the poisoned refs, not fail: %v", err)
	}
	for _, m := range cfg.Interfaces.Interfaces["fab0"].FabricMembers {
		if m == "ge 0" {
			t.Fatal(`"ge 0" must be stripped from fab0's FabricMembers`)
		}
	}
	if got := cfg.Interfaces.Interfaces["fab0"].FabricMembers; len(got) != 2 {
		t.Fatalf("fab0 must keep its 2 clean members, got %v", got)
	}
	for _, m := range cfg.Interfaces.Interfaces["fab1"].FabricMembers {
		if m == "ge 1" {
			t.Fatal(`"ge 1" must be stripped from fab1's FabricMembers`)
		}
	}
	all := warningsJoin9886(cfg.Warnings)
	for _, want := range []string{"STRIPPED", "#9886", "member-interfaces"} {
		if !strings.Contains(all, want) {
			t.Errorf("strip warning must mention %q, got warnings:\n%s", want, all)
		}
	}
}

// TestLenientStripsUnsafeFabricMemberRefsFlat_9886 covers the flat-set
// spellings: repeated statements (leaf children) and the bracket list (one
// child whose Keys hold every name — the shape plainListValues' descendant
// walk exists for).
func TestLenientStripsUnsafeFabricMemberRefsFlat_9886(t *testing.T) {
	tree := setTree(t,
		`set interfaces fab0 fabric-options member-interfaces "ge 0"`,
		"set interfaces fab0 fabric-options member-interfaces ge-0/0/7",
		`set interfaces fab1 fabric-options member-interfaces [ "ge 1" ge-0/0/8 ]`,
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile must strip the poisoned refs, not fail: %v", err)
	}
	for _, m := range cfg.Interfaces.Interfaces["fab0"].FabricMembers {
		if m == "ge 0" {
			t.Fatal(`"ge 0" must be stripped from fab0's FabricMembers`)
		}
	}
	for _, m := range cfg.Interfaces.Interfaces["fab1"].FabricMembers {
		if m == "ge 1" {
			t.Fatal(`"ge 1" must be stripped from fab1's FabricMembers`)
		}
	}
	if !strings.Contains(warningsJoin9886(cfg.Warnings), "STRIPPED") {
		t.Fatalf("want the strip warning, got:\n%s", warningsJoin9886(cfg.Warnings))
	}
}

// TestStrictDirectCompileRejectsUnsafeFabricRef_9886 pins the strict arm for
// member-interfaces references. The schema does NOT validate these values, so
// on the commit path this gate IS the rejection — a poisoned fabric ref that
// commits today renders a two-pattern bond-member unit.
func TestStrictDirectCompileRejectsUnsafeFabricRef_9886(t *testing.T) {
	text := `interfaces {
  fab0 {
    fabric-options { member-interfaces [ "ge 0" ge-0/0/7 ]; }
    unit 0 { family inet { address 10.99.1.1/30; } }
  }
}`
	if _, err := CompileConfig(parseHier9886(t, text)); err == nil {
		t.Fatal("direct strict compile must hard-error on a poisoned fabric ref, got nil")
	} else {
		for _, want := range []string{"#9886", "member-interfaces"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("strict error must mention %q, got %v", want, err)
			}
		}
	}
	// The schema has no validator on these values, so it passes — documenting
	// the hole this gate closes rather than asserting on it would rot; assert
	// the pass so a future schema validator visibly changes this contract.
	if err := SchemaValidate(parseHier9886(t, text), nil); err != nil {
		t.Fatalf("SchemaValidate unexpectedly rejects member-interfaces values: %v", err)
	}
}
