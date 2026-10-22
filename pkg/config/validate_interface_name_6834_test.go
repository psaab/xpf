package config

import (
	"strings"
	"testing"
)

// #6834. The interface name reaches four render sites in the generated systemd
// units, and one of them — `[Match] Name=` in the .network file — is a
// WHITESPACE-SEPARATED LIST OF SHELL-STYLE GLOBS. An unvalidated name does not
// corrupt the unit file; it makes one .network claim several interfaces.
//
// Before this gate, measured on the real config path: "ge 0", "ge-0-0-0 eth0"
// and "ge*" all committed and reached ifc.Name verbatim.

// TestValidateInterfaceNameAcceptsRealNames_6834 is the OVER-REJECTION half,
// and it is the half that matters most for a narrowing change: a validator
// wrong in the rejecting direction turns a working config into a failed commit
// with no operator workaround. Every form here is one the repo or the docs
// actually use.
func TestValidateInterfaceNameAcceptsRealNames_6834(t *testing.T) {
	for _, name := range []string{
		"ge-0/0/0",     // the documented Junos spelling — slashes REQUIRED
		"ge-0-0-0",     // its canonical kernel form
		"ge-0/0/1.100", // VLAN unit
		"xe-7/0/2",     // node-1 FPC
		"reth0",        // redundant ethernet
		"reth0.50",     // RETH with a VLAN unit
		"fxp0", "em0", "fab0", "ae0", "irb", "lo0",
		"enp5s0", "eno5np0", "enp183s0f0v0", // predictable kernel names
		"st0.1", "gr-0/0/0", "ip-0/0/0.0", // tunnels
		"vlan-100", "wg0", "vrf-mgmt",
		"interface-range",           // a schema keyword at this position
		"ge-0/0/1234567890",         // an existing 17-char fixture: NO length bound
		"a", "A", "0", "x_y", "x.y", // boundary shapes of the allowed class
	} {
		if err := ValidateInterfaceName(name); err != nil {
			t.Errorf("ValidateInterfaceName(%q) must ACCEPT a real interface name, got %v", name, err)
		}
	}
}

// TestValidateInterfaceNameRejectsMultiPattern_6834 is the #6834 vector: a name
// that occupies more than one slot of a whitespace-separated match list.
func TestValidateInterfaceNameRejectsMultiPattern_6834(t *testing.T) {
	for _, tc := range []struct{ name, wantIn string }{
		{"ge 0", "whitespace"},
		{"ge-0-0-0 eth0", "whitespace"}, // the two-pattern payload
		{"ge\t0", "whitespace"},
		{"ge\n0", "whitespace"},
		{" ge0", "whitespace"},
		{"ge0 ", "whitespace"},
	} {
		err := ValidateInterfaceName(tc.name)
		if err == nil {
			t.Errorf("ValidateInterfaceName(%q) must REJECT — it would claim more than one interface", tc.name)
			continue
		}
		// Assert the error EXPLAINS the consequence, not merely that it errored.
		// "invalid character" would not tell an operator their name claims other
		// devices, which is the whole point of rejecting it.
		if !strings.Contains(err.Error(), tc.wantIn) {
			t.Errorf("ValidateInterfaceName(%q) error must mention %q, got %v", tc.name, tc.wantIn, err)
		}
		if !strings.Contains(err.Error(), "[Match] Name=") {
			t.Errorf("ValidateInterfaceName(%q) error must name the sink, got %v", tc.name, err)
		}
	}
}

// TestValidateInterfaceNameRejectsGlobs_6834 covers the other live class. A
// glob is a legal KERNEL name, so nothing downstream would reject it — it just
// silently matches every interface it globs.
func TestValidateInterfaceNameRejectsGlobs_6834(t *testing.T) {
	for _, name := range []string{"ge*", "ge?", "ge[0-9]", "*", "en[p]5s0"} {
		err := ValidateInterfaceName(name)
		if err == nil {
			t.Errorf("ValidateInterfaceName(%q) must REJECT a glob metacharacter", name)
			continue
		}
		if !strings.Contains(err.Error(), "glob") {
			t.Errorf("ValidateInterfaceName(%q) error must say it is a glob, got %v", name, err)
		}
	}
}

// TestValidateInterfaceNameRejectsOtherInvalid_6834 pins the allowlist's tail:
// characters that are neither whitespace nor globs but still have no business
// in an interface name. ':' matters because the kernel itself rejects it.
func TestValidateInterfaceNameRejectsOtherInvalid_6834(t *testing.T) {
	for _, name := range []string{"ge:0", "ge;0", "ge$0", "ge`0", "ge\"0", "ge'0", "gé0", ""} {
		if err := ValidateInterfaceName(name); err == nil {
			t.Errorf("ValidateInterfaceName(%q) must REJECT", name)
		}
	}
}

// TestAcceptedNamesRenderAsExactlyOnePattern_6834 checks the validator against
// systemd's grammar rather than against its own allowlist.
//
// Asserting "the allowlist rejects what the allowlist rejects" would be true by
// construction. The property that actually matters is that anything ACCEPTED
// occupies exactly ONE slot of a whitespace-separated match list — so this
// derives the check from the sink's documented parsing, independently of how
// the validator decides.
func TestAcceptedNamesRenderAsExactlyOnePattern_6834(t *testing.T) {
	for _, name := range []string{
		"ge-0/0/0", "ge-0-0-0", "reth0.50", "enp183s0f0v0", "ge-0/0/1234567890",
	} {
		if err := ValidateInterfaceName(name); err != nil {
			t.Fatalf("fixture %q must be accepted: %v", name, err)
		}
		if !interfaceNameRendersAsOnePattern(name) {
			t.Errorf("accepted name %q does not occupy exactly one match-list slot", name)
		}
	}
	// And the converse, so the helper is not vacuously true for everything.
	for _, name := range []string{"ge 0", "ge-0-0-0 eth0", " ge0"} {
		if interfaceNameRendersAsOnePattern(name) {
			t.Errorf("%q occupies more than one slot; the helper must say so", name)
		}
	}
}

// TestInterfaceNameGateIsWiredIntoTheSchema_6834 binds the WIRING. The
// validator existing proves nothing if the schema does not call it — the shape
// that has repeatedly produced tests which pass while production bypasses the
// code they cover. This drives the real commit path.
func TestInterfaceNameGateIsWiredIntoTheSchema_6834(t *testing.T) {
	commit := func(name string) error {
		tree := &ConfigTree{}
		path, err := ParseSetCommand(`set interfaces "` + name + `" unit 0 family inet address 10.0.0.1/24`)
		if err != nil {
			return err
		}
		if err := tree.SetPath(path); err != nil {
			return err
		}
		return SchemaValidate(tree)
	}

	if err := commit("ge-0/0/0"); err != nil {
		t.Fatalf("a normal interface name must still commit: %v", err)
	}
	err := commit("ge-0-0-0 eth0")
	if err == nil {
		t.Fatal("a multi-pattern interface name must be REFUSED at commit — " +
			"the schema does not reach ValidateInterfaceName")
	}
	if !strings.Contains(err.Error(), "whitespace") {
		t.Errorf("the commit refusal must carry the validator's reason, got %v", err)
	}
	if err := commit("ge*"); err == nil {
		t.Fatal("a glob interface name must be REFUSED at commit")
	}
}

// findChildWildcardAliases returns "<path> <key>" for every schema parent that
// registers the same *schemaNode as both a named child AND its wildcard.
//
// Extracted so the DETECTOR itself can be tested against a schema that really
// contains one. Walking the real schema and finding nothing proves the schema
// is clean; it does not prove the walk would notice if it were not — and a
// tripwire that cannot fire is indistinguishable from one that works.
func findChildWildcardAliases(root *schemaNode) []string {
	var out []string
	seen := map[*schemaNode]bool{}
	var walk func(n *schemaNode, path string)
	walk = func(n *schemaNode, path string) {
		if n == nil || seen[n] {
			return
		}
		seen[n] = true
		if n.wildcard != nil {
			for k, c := range n.children {
				if c == n.wildcard {
					out = append(out, path+" "+k)
				}
			}
		}
		for k, c := range n.children {
			walk(c, path+" "+k)
		}
		walk(n.wildcard, path+" <*>")
	}
	walk(root, "")
	return out
}

// TestAliasDetectorFindsARealAlias_6834 is the positive control for the
// tripwire below. Without it the tripwire passes on a clean schema whether or
// not its comparison works at all — the same vacuity it exists to guard
// against, one level up.
func TestAliasDetectorFindsARealAlias_6834(t *testing.T) {
	shared := &schemaNode{desc: "shared"}
	aliased := &schemaNode{
		desc:     "parent",
		wildcard: shared,
		children: map[string]*schemaNode{"dup": shared},
	}
	if got := findChildWildcardAliases(aliased); len(got) != 1 {
		t.Fatalf("the detector must find a planted alias, got %v", got)
	}
	// And it must not cry alias when the wildcard is a DISTINCT node.
	clean := &schemaNode{
		desc:     "parent",
		wildcard: &schemaNode{desc: "w"},
		children: map[string]*schemaNode{"a": {desc: "a"}},
	}
	if got := findChildWildcardAliases(clean); len(got) != 0 {
		t.Fatalf("a distinct wildcard is not an alias, got %v", got)
	}
}

// TestNoSchemaNodeIsBothChildAndWildcard_6834 keeps the precondition that makes
// the exactness predicate in walkSchemaNode sound.
//
// That predicate is `parent.children[keyword] == childSchema` — POINTER
// equality. If any parent ever registered the same *schemaNode as both a named
// child and as its wildcard, the predicate would report "exact" for a wildcard
// match and the wildcard-identity gate would silently stop running. Nothing
// would fail: the config would simply commit unvalidated again, which is the
// original defect returning with no signal.
//
// Measured at the time of writing: 0 aliases across 1464 schema nodes. This is
// a TRIPWIRE for a future schema edit, so it cannot red today; the detector it
// relies on is bound separately by TestAliasDetectorFindsARealAlias_6834.
func TestNoSchemaNodeIsBothChildAndWildcard_6834(t *testing.T) {
	if got := findChildWildcardAliases(setSchema); len(got) != 0 {
		t.Errorf("schema nodes register a child that IS their wildcard: %v; "+
			"the exactness predicate in walkSchemaNode is pointer-based and would report "+
			"EXACT for a wildcard match there, silently disabling wildcard-identity validation", got)
	}
	seen := map[*schemaNode]bool{}
	var count func(n *schemaNode)
	count = func(n *schemaNode) {
		if n == nil || seen[n] {
			return
		}
		seen[n] = true
		for _, c := range n.children {
			count(c)
		}
		count(n.wildcard)
	}
	count(setSchema)
	if len(seen) < 100 {
		t.Fatalf("the walk visited only %d nodes; it is not reaching the schema and proves nothing", len(seen))
	}
	t.Logf("walked %d schema nodes, no child/wildcard aliasing", len(seen))
}
