package config

import (
	"strings"
	"testing"
)

// #14200: a container-shaped `address { h1 10.0.0.1/32; }` /
// `address-set { s1 { address h1; } }` block (name on the child, not on the
// address/address-set node itself) was silently `continue`d by
// parseAddressBookEntries: only unknown keywords reached UnknownBookEntries,
// so strict compile accepted the config with the entry missing, and a
// zone-local policy reference could fall back to a broader same-name global.
//
// FAIL-ON-REVERT: reverting the nameless-container recording in
// parseAddressBookEntries turns every strict case below GREEN (accepted) and
// drops the lenient quarantine, so this file goes RED.

// known keywords kept only for messages; braced names are the dropped entries.
func parseHier14200(t *testing.T, src string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

func unknownHas14200(ab *AddressBook, keyword, name string) bool {
	if ab == nil {
		return false
	}
	for _, e := range ab.UnknownBookEntries {
		if e.Keyword != keyword {
			continue
		}
		for _, n := range e.Names {
			if n == name {
				return true
			}
		}
	}
	return false
}

func TestContainerShapedAddressEntriesStrictRejected14200(t *testing.T) {
	for _, tc := range []struct{ name, src, keyword, entry string }{
		{"global address", `security { address-book { global { address { h1 10.0.0.1/32; } } } }`, "address", "h1"},
		{"global address-set", `security { address-book { global { address-set { s1 { address h1; } } } } }`, "address-set", "s1"},
		{"global address nameless leaf", `security { address-book { global { address; } } }`, "address", ""},
		{"global address-set nameless leaf", `security { address-book { global { address-set; } } }`, "address-set", ""},
		{"zone-local address", `security { zones { security-zone trust { address-book { address { h1 10.0.0.1/32; } } } } }`, "address", "h1"},
		{"zone-local address-set", `security { zones { security-zone trust { address-book { address-set { s1 { address h1; } } } } } }`, "address-set", "s1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHier14200(t, tc.src)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("strict compile accepted container-shaped %s entry %q", tc.keyword, tc.entry)
			}
			if !strings.Contains(err.Error(), tc.keyword) {
				t.Fatalf("strict error %q does not name keyword %q", err, tc.keyword)
			}
			// Lenient path must record the dropped name for quarantine/warning,
			// not silently lose it.
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			var ab *AddressBook
			if strings.HasPrefix(tc.name, "zone-local") {
				if z := cfg.Security.Zones["trust"]; z != nil {
					ab = z.AddressBook
					if !z.DroppedEnforcementChild {
						t.Fatalf("zone-local container entry did not mark zone dropped: %+v", z)
					}
				}
			} else {
				ab = cfg.Security.AddressBook
			}
			if ab == nil || len(ab.UnknownBookEntries) == 0 {
				t.Fatalf("lenient UnknownBookEntries empty for %s: %+v", tc.name, ab)
			}
			if tc.entry != "" && !unknownHas14200(ab, tc.keyword, tc.entry) {
				t.Fatalf("lenient UnknownBookEntries = %+v, want %s %s", ab.UnknownBookEntries, tc.keyword, tc.entry)
			}
			if tc.entry != "" {
				if _, ok := ab.CollidingNames[tc.entry]; !ok {
					t.Fatalf("lenient CollidingNames lacks %q: %v", tc.entry, ab.CollidingNames)
				}
			}
		})
	}
}

// The decisive end-to-end case from the issue: a narrower zone-local
// container-shaped entry is dropped while a broader same-name global exists;
// the policy must not silently resolve to the global twin.
func TestContainerZoneLocalDoesNotFallBackToGlobal14200(t *testing.T) {
	src := `security {
		zones {
			security-zone trust {
				interfaces { eth0.0; }
				address-book { address { h1 10.0.0.1/32; } }
			}
			security-zone untrust;
		}
		address-book { global { address h1 10.9.0.0/24; } }
		policies {
			from-zone trust to-zone untrust {
				policy deny-h1 {
					match { source-address h1; destination-address any; application any; }
					then { deny; }
				}
			}
		}
	}`
	tree := parseHier14200(t, src)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("strict compile accepted dropped zone-local h1 (would fall back to global 10.9.0.0/24)")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	z := cfg.Security.Zones["trust"]
	if z == nil || !z.DroppedEnforcementChild || len(z.Interfaces) != 0 {
		t.Fatalf("zone must be unbound after dropped container entry: %+v", z)
	}
	if !unknownHas14200(z.AddressBook, "address", "h1") {
		t.Fatalf("zone UnknownBookEntries = %+v, want address h1", z.AddressBook.UnknownBookEntries)
	}
	if _, ok := cfg.Security.AddressBook.CollidingNames["zone-local/trust/h1"]; !ok {
		t.Fatalf("qualified h1 not quarantined: %v", cfg.Security.AddressBook.CollidingNames)
	}
	found := false
	for _, pair := range cfg.Security.Policies {
		for _, p := range pair.Policies {
			for _, tok := range p.Match.SourceAddresses {
				if tok == "zone-local/trust/h1" {
					found = true
				}
				if tok == "h1" {
					t.Fatalf("policy source left as bare h1 (global fallback): %+v", p.Match.SourceAddresses)
				}
			}
		}
	}
	if !found {
		t.Fatalf("policy source not rewritten to quarantine name: %+v", cfg.Security.Policies)
	}
	// The global twin itself stays intact; only the zone-local reference is refused.
	if got := cfg.Security.AddressBook.Addresses["h1"]; got == nil || got.Value != "10.9.0.0/24" {
		t.Fatalf("global h1 clobbered: %+v", got)
	}
}

func TestContainerZoneLocalAddressSetDoesNotFallBack14200(t *testing.T) {
	src := `security {
		zones {
			security-zone trust {
				interfaces { eth0.0; }
				address-book { address-set { s1 { address h1; } } }
			}
			security-zone untrust;
		}
		address-book { global { address h1 10.9.0.0/24; address-set s1 { address h1; } } }
		policies {
			from-zone trust to-zone untrust {
				policy deny-s1 {
					match { source-address s1; destination-address any; application any; }
					then { deny; }
				}
			}
		}
	}`
	tree := parseHier14200(t, src)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("strict compile accepted dropped zone-local s1")
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if _, ok := cfg.Security.AddressBook.CollidingNames["zone-local/trust/s1"]; !ok {
		t.Fatalf("qualified s1 not quarantined: %v", cfg.Security.AddressBook.CollidingNames)
	}
}

func TestValidAddressShapesNoUnknown14200(t *testing.T) {
	for _, src := range []string{
		`security { address-book { global { address h1 10.0.0.1/32; address-set s1 { address h1; } } } }`,
		`security { address-book { global { address h1 { 10.0.0.1/32; } } } }`,
		`security { zones { security-zone trust { address-book { address h1 10.0.0.1/32; address-set s1 { address h1; } } } } }`,
	} {
		tree := parseHier14200(t, src)
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("valid config rejected: %v (%s)", err, src)
		}
		if cfg.Security.AddressBook != nil && len(cfg.Security.AddressBook.UnknownBookEntries) != 0 {
			t.Fatalf("valid global flagged: %+v", cfg.Security.AddressBook.UnknownBookEntries)
		}
		if z := cfg.Security.Zones["trust"]; z != nil && z.AddressBook != nil && len(z.AddressBook.UnknownBookEntries) != 0 {
			t.Fatalf("valid zone-local flagged: %+v", z.AddressBook.UnknownBookEntries)
		}
	}
}
