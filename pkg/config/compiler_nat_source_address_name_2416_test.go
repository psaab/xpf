package config

import (
	"strings"
	"testing"
)

// #2416: NAT `match source-address-name <book-entry>` is an address-book
// reference. The compiler must (1) parse it into NATMatch.SourceAddressName for
// both source and destination NAT, and (2) hard-reject at commit a rule whose
// name is not defined under `security address-book`
// (validateNATSourceAddressNameReferencesStrict) so the typo is operator-
// visible instead of silently failing closed.
//
// All tests use the production ParseSetCommand + SetPath path (buildTree),
// never NewParser (the flat-set gotcha in CLAUDE.md).

func dnatSourceNameSet(matchName string) []string {
	return []string{
		"set security zones security-zone untrust",
		"set security address-book global address corp-a 198.51.100.0/24",
		"set security address-book global address-set corp-net address corp-a",
		"set security nat destination pool dp address 10.0.0.5",
		"set security nat destination rule-set rs1 from zone untrust",
		"set security nat destination rule-set rs1 rule r1 match source-address-name " + matchName,
		"set security nat destination rule-set rs1 rule r1 match destination-address 203.0.113.20",
		"set security nat destination rule-set rs1 rule r1 then destination-nat pool dp",
	}
}

func snatSourceNameSet(matchName string) []string {
	return []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address corp-a 198.51.100.0/24",
		"set security address-book global address-set corp-net address corp-a",
		"set security nat source rule-set rs1 from zone trust",
		"set security nat source rule-set rs1 to zone untrust",
		"set security nat source rule-set rs1 rule r1 match source-address-name " + matchName,
		"set security nat source rule-set rs1 rule r1 then source-nat interface",
	}
}

func TestNATDNATSourceAddressNameParsed(t *testing.T) {
	tree := buildTree(t, dnatSourceNameSet("corp-net"))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("DNAT with a defined source-address-name must compile, got: %v", err)
	}
	if cfg.Security.NAT.Destination == nil || len(cfg.Security.NAT.Destination.RuleSets) == 0 {
		t.Fatal("destination NAT rule-set missing after compile")
	}
	rule := cfg.Security.NAT.Destination.RuleSets[0].Rules[0]
	if rule.Match.SourceAddressName != "corp-net" {
		t.Fatalf("DNAT SourceAddressName = %q, want corp-net (parse dropped)", rule.Match.SourceAddressName)
	}
}

func TestNATSNATSourceAddressNameParsed(t *testing.T) {
	tree := buildTree(t, snatSourceNameSet("corp-net"))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("SNAT with a defined source-address-name must compile, got: %v", err)
	}
	if len(cfg.Security.NAT.Source) == 0 {
		t.Fatal("source NAT rule-set missing after compile")
	}
	rule := cfg.Security.NAT.Source[0].Rules[0]
	if rule.Match.SourceAddressName != "corp-net" {
		t.Fatalf("SNAT SourceAddressName = %q, want corp-net (parse dropped)", rule.Match.SourceAddressName)
	}
}

func TestNATDNATUnknownSourceAddressNameRejected(t *testing.T) {
	tree := buildTree(t, dnatSourceNameSet("does-not-exist"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a DNAT rule naming an undefined source-address-name must be rejected at commit")
	}
	msg := err.Error()
	if !strings.Contains(msg, "destination") ||
		!strings.Contains(msg, "r1") ||
		!strings.Contains(msg, "does-not-exist") {
		t.Fatalf("error must name the rule + the undefined book entry, got: %v", err)
	}
}

func TestNATSNATUnknownSourceAddressNameRejected(t *testing.T) {
	tree := buildTree(t, snatSourceNameSet("does-not-exist"))
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("a SNAT rule naming an undefined source-address-name must be rejected at commit")
	}
	msg := err.Error()
	if !strings.Contains(msg, "source") ||
		!strings.Contains(msg, "r1") ||
		!strings.Contains(msg, "does-not-exist") ||
		!strings.Contains(msg, "unparseable fallback") {
		t.Fatalf("error must name the rule + undefined book entry and describe its unparseable fallback, got: %v", err)
	}
}

// The tolerant load / peer-sync path downgrades the undefined reference to a
// warning so an already-persisted or peer-synced config still boots (#1960).
func TestNATUnknownSourceAddressNameLenientWarns(t *testing.T) {
	tree := buildTree(t, dnatSourceNameSet("does-not-exist"))
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant path must not hard-reject an undefined source-address-name, got: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "source-address-name") &&
			strings.Contains(w, "does-not-exist") &&
			strings.Contains(w, "unparseable fallback") {
			found = true
		}
	}
	if !found {
		t.Fatalf("tolerant path must record a warning for the undefined reference, got warnings: %v", cfg.Warnings)
	}
}
