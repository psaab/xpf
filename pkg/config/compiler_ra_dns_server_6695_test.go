// #6695: `protocols router-advertisement interface <if> dns-server-address` is
// `multi: true`, but the compiler read it with nodeVal — Keys[1] alone. The
// bracketed spelling kept the FIRST address and dropped the rest; the
// hierarchical BLOCK spelling (`dns-server-address { a; b; }`) has no Keys[1]
// at all, so it compiled NOTHING.
//
// Hosts on the link then learn one RDNSS server while `show configuration`
// renders both, so the missing redundancy is invisible until the primary
// resolver fails — exactly when the fallback was supposed to matter. xpf sends
// RAs from its own embedded sender (pkg/ra), so no external daemon re-reads the
// config and behaves correctly.
//
// Flat-set syntax MUST be built via ParseSetCommand/SetPath, never NewParser.
package config

import (
	"reflect"
	"strings"
	"testing"
)

// raDNSSpellings compiles the same two-address RDNSS list in every spelling the
// grammar admits and returns the compiled DNSServers slice per spelling.
func raDNSSpellings(t *testing.T, v1, v2 string) map[string][]string {
	t.Helper()

	servers := func(name string, cfg *Config) []string {
		t.Helper()
		if len(cfg.Protocols.RouterAdvertisement) != 1 {
			t.Fatalf("%s: compiled %d RA interfaces, want 1",
				name, len(cfg.Protocols.RouterAdvertisement))
		}
		return cfg.Protocols.RouterAdvertisement[0].DNSServers
	}
	compileBrace := func(name, stmt string) []string {
		t.Helper()
		body := "protocols { router-advertisement { interface ge-0-0-0 { " + stmt + " } } }"
		p := NewParser(body)
		tree, errs := p.Parse()
		if len(errs) > 0 {
			t.Fatalf("%s: parse %q: %v", name, body, errs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("%s: CompileConfig(%q): %v", name, body, err)
		}
		return servers(name, cfg)
	}
	compileSet := func(name string, cmds ...string) []string {
		t.Helper()
		tree := &ConfigTree{}
		for _, c := range cmds {
			path, err := ParseSetCommand(c)
			if err != nil {
				t.Fatalf("%s: ParseSetCommand(%q): %v", name, c, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("%s: SetPath(%q): %v", name, c, err)
			}
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("%s: CompileConfig(%v): %v", name, cmds, err)
		}
		return servers(name, cfg)
	}

	flat := "set protocols router-advertisement interface ge-0-0-0 dns-server-address"
	return map[string][]string{
		"A-hier-bracket": compileBrace("A-hier-bracket", "dns-server-address [ "+v1+" "+v2+" ];"),
		"B-hier-block":   compileBrace("B-hier-block", "dns-server-address { "+v1+"; "+v2+"; }"),
		"C-hier-repeat":  compileBrace("C-hier-repeat", "dns-server-address "+v1+"; dns-server-address "+v2+";"),
		"D-set-bracket":  compileSet("D-set-bracket", flat+" [ "+v1+" "+v2+" ]"),
		"E-set-repeat":   compileSet("E-set-repeat", flat+" "+v1, flat+" "+v2),
	}
}

// TestRADNSServerMultiValue_6695 asserts the compiled address SLICE CONTENTS,
// in order, in every spelling — not its length, which a reader installing the
// same address twice would also satisfy.
//
// RED-on-revert (nodeVal): A and D compile ["2001:db8::53"] and B compiles
// nothing at all.
func TestRADNSServerMultiValue_6695(t *testing.T) {
	want := []string{"2001:db8::53", "2001:db8::54"}
	for name, got := range raDNSSpellings(t, "2001:db8::53", "2001:db8::54") {
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: compiled DNSServers %v, want %v "+
				"(RED-on-revert: nodeVal keeps slot 0 alone, and reads the block shape not at all)",
				name, got, want)
		}
	}
}

// TestRADNSServerThreeAddresses_6695 pins that the reader is not a two-slot
// special case: a three-address list compiles all three, in order.
func TestRADNSServerThreeAddresses_6695(t *testing.T) {
	tree := &ConfigTree{}
	cmd := "set protocols router-advertisement interface ge-0-0-0 " +
		"dns-server-address [ 2001:db8::53 2001:db8::54 2001:db8::55 ]"
	path, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	want := []string{"2001:db8::53", "2001:db8::54", "2001:db8::55"}
	got := cfg.Protocols.RouterAdvertisement[0].DNSServers
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("compiled DNSServers %v, want %v", got, want)
	}
}

// TestRADNSServerValidatorCoversEverySlot_6695 is the widened-read/unwidened-
// validator guard. Each address is appended to an RFC 8106 RecursiveDNSServer
// option, which is IPv6-only, and the RA sender does not family-gate — it only
// skips what netip.ParseAddr rejects, so a bare IPv4 literal would go on the
// wire (#2497). validateMultiValueLeaf must run ValidateIPv6Address over EVERY
// authored slot, not slot 0, or widening the compiler's read turns a silent
// truncation into silent propagation of a malformed address.
func TestRADNSServerValidatorCoversEverySlot_6695(t *testing.T) {
	base := "set protocols router-advertisement interface ge-0-0-0 dns-server-address"
	reject := [][]string{
		{base + " [ 2001:db8::53 8.8.8.8 ]"},
		{base + " [ 2001:db8::53 not-an-address ]"},
		{base + " 2001:db8::53", base + " 8.8.8.8"},
	}
	for _, cmds := range reject {
		tree := buildTreeFromSet(t, cmds)
		err := SchemaValidate(tree)
		if err == nil {
			t.Errorf("SchemaValidate accepted %v; a non-IPv6 RDNSS address in a "+
				"non-zero slot must be rejected", cmds)
			continue
		}
		if !strings.Contains(err.Error(), "dns-server-address") {
			t.Errorf("SchemaValidate(%v) error %q does not name the leaf", cmds, err)
		}
	}
	// Over-reject control: a well-formed two-address list in the same shape.
	ok := buildTreeFromSet(t, []string{base + " [ 2001:db8::53 2001:db8::54 ]"})
	if err := SchemaValidate(ok); err != nil {
		t.Errorf("SchemaValidate rejected a well-formed RDNSS list: %v", err)
	}
}
