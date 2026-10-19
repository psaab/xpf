package config

import (
	"strings"
	"testing"
)

// #15672: standard Junos named address books
// (`security address-book <book> { address ...; attach { zone <z>; } }`)
// and book-level `description` were schema-rejected on commit
// (`unknown configuration keyword "mybook"`) and silently dropped on
// lenient load (compileAddressBook read only `global`). These tests pin
// the fix: named books compile, attach folds them into the attached zones
// (zone-local semantics), descriptions are stored, and attachment
// conflicts fail closed.

func warningsContaining15672(cfg *Config, subs ...string) bool {
	for _, w := range cfg.Warnings {
		ok := true
		for _, s := range subs {
			if !strings.Contains(w, s) {
				ok = false
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func base15672() []string {
	return []string{
		"set interfaces eth0 unit 0 family inet address 192.0.2.1/24",
		"set interfaces eth1 unit 0 family inet address 192.0.2.2/24",
		"set security zones security-zone trust interfaces eth0.0",
		"set security zones security-zone untrust interfaces eth1.0",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address srv",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
	}
}

func namedBookLines15672() []string {
	lines := base15672()
	lines = append(lines,
		"set security address-book eng-book description engineering",
		"set security address-book eng-book address srv 10.1.0.5/32",
		"set security address-book eng-book address-set grp address srv",
		"set security address-book eng-book attach zone trust",
	)
	return lines
}

// Strict hierarchical spelling: the braced form Junos actually emits.
func TestNamedAddressBookHierarchical15672(t *testing.T) {
	tree, errs := NewParser(`
security {
    zones {
        security-zone trust {
            interfaces { eth0.0; }
        }
        security-zone untrust {
            interfaces { eth1.0; }
        }
    }
    address-book {
        eng-book {
            description engineering;
            address srv 10.1.0.5/32;
            address-set grp { address srv; }
            attach { zone trust; }
        }
    }
    policies {
        from-zone trust to-zone untrust {
            policy p1 {
                match { source-address grp; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
interfaces { eth0 { unit 0 { family inet { address 192.0.2.1/24; } } } eth1 { unit 0 { family inet { address 192.0.2.2/24; } } } }
`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate must accept named book: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile must accept named book: %v", err)
	}
	if cfg.Security.NamedAddressBooks["eng-book"] == nil {
		t.Fatalf("named book not retained: %+v", cfg.Security.NamedAddressBooks)
	}
	nb := cfg.Security.NamedAddressBooks["eng-book"]
	if nb.Description != "engineering" {
		t.Fatalf("book description = %q, want engineering", nb.Description)
	}
	if len(nb.AttachedZones) != 1 || nb.AttachedZones[0] != "trust" {
		t.Fatalf("AttachedZones = %v, want [trust]", nb.AttachedZones)
	}
	// Folded into trust's zone-local namespace: policy token qualified.
	found := false
	for _, pair := range cfg.Security.Policies {
		for _, p := range pair.Policies {
			for _, tok := range p.Match.SourceAddresses {
				if tok == "zone-local/trust/grp" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("attached book set not folded/qualified for trust policy: %+v", cfg.Security.Policies)
	}
	if a := cfg.Security.AddressBook.Addresses["zone-local/trust/srv"]; a == nil || a.UsableValue() != "10.1.0.5/32" {
		t.Fatalf("folded srv = %+v", a)
	}
}

func TestNamedAddressBookFlatSet15672(t *testing.T) {
	tree := buildTree(t, namedBookLines15672())
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate must accept named book (flat): %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("strict compile must accept named book (flat): %v", err)
	}
	nb := cfg.Security.NamedAddressBooks["eng-book"]
	if nb == nil || nb.Description != "engineering" {
		t.Fatalf("named book/description: %+v", nb)
	}
	// Policy references bare `srv`; attached to trust (from-zone) so it
	// must be qualified and resolvable, never silently dropped.
	found := false
	for _, pair := range cfg.Security.Policies {
		for _, p := range pair.Policies {
			for _, tok := range p.Match.SourceAddresses {
				if tok == "zone-local/trust/srv" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("policy srv not qualified to attached book: %+v", cfg.Security.Policies)
	}
	if a := cfg.Security.AddressBook.Addresses["zone-local/trust/srv"]; a == nil || a.UsableValue() != "10.1.0.5/32" {
		t.Fatalf("folded srv = %+v", a)
	}
}

func TestGlobalAndZoneBookDescription15672(t *testing.T) {
	tree := buildTree(t, []string{
		"set security zones security-zone trust",
		"set security address-book global description globalscope",
		"set security address-book global address a 10.0.0.1/32",
		"set security zones security-zone trust address-book description localscope",
		"set security zones security-zone trust address-book address b 10.0.0.2/32",
	})
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate book descriptions: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile book descriptions: %v", err)
	}
	if cfg.Security.AddressBook == nil || cfg.Security.AddressBook.Description != "globalscope" {
		t.Fatalf("global description = %+v", cfg.Security.AddressBook)
	}
	z := cfg.Security.Zones["trust"]
	if z == nil || z.AddressBook == nil || z.AddressBook.Description != "localscope" {
		t.Fatalf("zone-local description = %+v", z)
	}
}

func TestNamedBookAttachmentConflicts15672(t *testing.T) {
	// Two books attached to one zone.
	twoBooks := append(base15672(),
		"set security address-book book-a address srv 10.1.0.5/32",
		"set security address-book book-a attach zone trust",
		"set security address-book book-b address srv 10.2.0.5/32",
		"set security address-book book-b attach zone trust",
	)
	if _, err := CompileConfig(buildTree(t, twoBooks)); err == nil {
		t.Fatalf("strict must reject two books attached to one zone")
	}
	cfg, err := CompileConfigLenient(buildTree(t, twoBooks))
	if err != nil {
		t.Fatalf("lenient must boot: %v", err)
	}
	if !warningsContaining15672(cfg, "address-book") {
		t.Fatalf("lenient must warn naming the attachment conflict: %v", cfg.Warnings)
	}
	// Fail closed: srv must not resolve to either attached prefix for trust.
	for _, pair := range cfg.Security.Policies {
		for _, p := range pair.Policies {
			for _, tok := range p.Match.SourceAddresses {
				if tok == "srv" {
					if _, coll := cfg.Security.AddressBook.CollidingNames[tok]; !coll {
						// Qualified colliding form also acceptable.
						if _, coll2 := cfg.Security.AddressBook.CollidingNames["zone-local/trust/srv"]; !coll2 {
							t.Fatalf("conflicting srv not quarantined: %v", cfg.Security.AddressBook.CollidingNames)
						}
					}
				}
			}
		}
	}

	// Attached book + inline zone address-book on same zone.
	mixed := append(base15672(),
		"set security zones security-zone trust address-book address srv 10.9.0.5/32",
		"set security address-book eng-book address srv 10.1.0.5/32",
		"set security address-book eng-book attach zone trust",
	)
	if _, err := CompileConfig(buildTree(t, mixed)); err == nil {
		t.Fatalf("strict must reject attached+inline on one zone")
	}
	if _, err := CompileConfigLenient(buildTree(t, mixed)); err != nil {
		t.Fatalf("lenient mixed must boot: %v", err)
	}

	// Attach to undefined zone.
	undef := append(base15672(),
		"set security address-book eng-book address srv 10.1.0.5/32",
		"set security address-book eng-book attach zone nosuch",
	)
	if _, err := CompileConfig(buildTree(t, undef)); err == nil {
		t.Fatalf("strict must reject attach to undefined zone")
	}
}

func TestNamedBookUnattachedNotZoneVisible15672(t *testing.T) {
	lines := append(base15672(),
		"set security address-book stray-book address srv 10.1.0.5/32",
	)
	// Policy references srv which exists only in an unattached book:
	// strict must reject the undefined reference (not silently resolve).
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatalf("strict must reject policy ref to unattached book entry")
	}
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("lenient must boot: %v", err)
	}
	if cfg.Security.NamedAddressBooks["stray-book"] == nil {
		t.Fatalf("unattached named book must still be retained on lenient load")
	}
	if cfg.Security.AddressBook != nil {
		if a := cfg.Security.AddressBook.Addresses["srv"]; a != nil && a.UsableValue() == "10.1.0.5/32" {
			t.Fatalf("unattached entry leaked into global book: %+v", a)
		}
	}
}

func TestNamedBookSameNameAsGlobalCoexists15672(t *testing.T) {
	// Same entry name in global and in an attached book: zone-attached
	// wins for that zone's policies (zone-local semantics), global stays
	// intact for other zones.
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security zones security-zone dmz",
		"set security address-book global address srv 10.0.0.1/32",
		"set security address-book eng-book address srv 10.1.0.5/32",
		"set security address-book eng-book attach zone trust",
		"set security policies from-zone trust to-zone untrust policy p1 match source-address srv",
		"set security policies from-zone trust to-zone untrust policy p1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy p1 match application any",
		"set security policies from-zone trust to-zone untrust policy p1 then permit",
		"set security policies from-zone dmz to-zone untrust policy p2 match source-address srv",
		"set security policies from-zone dmz to-zone untrust policy p2 match destination-address any",
		"set security policies from-zone dmz to-zone untrust policy p2 match application any",
		"set security policies from-zone dmz to-zone untrust policy p2 then permit",
	}
	cfg, err := CompileConfig(buildTree(t, lines))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if a := cfg.Security.AddressBook.Addresses["srv"]; a == nil || a.UsableValue() != "10.0.0.1/32" {
		t.Fatalf("global srv overwritten: %+v", a)
	}
	if a := cfg.Security.AddressBook.Addresses["zone-local/trust/srv"]; a == nil || a.UsableValue() != "10.1.0.5/32" {
		t.Fatalf("attached srv: %+v", a)
	}
}

func TestNamedBookMultiZoneAttach15672(t *testing.T) {
	tree, errs := NewParser("security { address-book { eng-book { address srv 10.1.0.5/32; attach { zone trust; zone untrust; } } } zones { security-zone trust { } security-zone untrust { } } }").Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if err := SchemaValidate(tree, nil); err != nil {
		t.Fatalf("schema multi-zone attach: %v", err)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile multi-zone attach: %v", err)
	}
	for _, z := range []string{"trust", "untrust"} {
		q := "zone-local/" + z + "/srv"
		if a := cfg.Security.AddressBook.Addresses[q]; a == nil || a.UsableValue() != "10.1.0.5/32" {
			t.Fatalf("zone %s folded srv = %+v", z, a)
		}
	}
}
