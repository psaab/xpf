package config

import (
	"strings"
	"testing"
)

func warningContaining12622(cfg *Config, subs ...string) bool {
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

func TestZoneLocalTypoEntryStrict12622(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces eth0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces eth0.0",
		"set security zones security-zone untrust",
		"set security address-book global address local 10.0.0.1/32",
		"set security address-book global address-set grp address local",
		"set security zones security-zone trust address-book address local 10.0.0.9/32",
		"set security zones security-zone trust address-book adress-set grp address local",
		"set security policies from-zone trust to-zone untrust policy deny-grp match source-address grp",
		"set security policies from-zone trust to-zone untrust policy deny-grp match destination-address any",
		"set security policies from-zone trust to-zone untrust policy deny-grp match application any",
		"set security policies from-zone trust to-zone untrust policy deny-grp then deny",
	})
	if _, err := CompileConfig(tree); err == nil {
		t.Fatalf("strict must reject typo entry")
	}
}

func TestZoneLocalTypoEntryLenient12622(t *testing.T) {
	tree := buildTree(t, []string{
		"set interfaces eth0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces eth0.0",
		"set security zones security-zone untrust",
		"set security address-book global address local 10.0.0.1/32",
		"set security address-book global address-set grp address local",
		"set security zones security-zone trust address-book address local 10.0.0.9/32",
		"set security zones security-zone trust address-book adress-set grp address local",
		"set security policies from-zone trust to-zone untrust policy deny-grp match source-address grp",
		"set security policies from-zone trust to-zone untrust policy deny-grp match destination-address any",
		"set security policies from-zone trust to-zone untrust policy deny-grp match application any",
		"set security policies from-zone trust to-zone untrust policy deny-grp then deny",
	})
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient must boot: %v", err)
	}
	if !warningContaining12622(cfg, "adress-set", "trust") {
		t.Fatalf("lenient warnings must name typo+zone: %v", cfg.Warnings)
	}
	z := cfg.Security.Zones["trust"]
	if z == nil || !z.DroppedEnforcementChild || len(z.Interfaces) != 0 {
		t.Fatalf("zone must be unbound after typo'd entry: %+v", z)
	}
	found := false
	for _, entry := range z.AddressBook.UnknownBookEntries {
		if entry.Keyword == "adress-set" {
			for _, name := range entry.Names {
				if name == "grp" {
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("UnknownBookEntries = %+v want adress-set grp", z.AddressBook.UnknownBookEntries)
	}
	found = false
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
		t.Fatalf("unknown local name was not qualified to quarantine global fallback")
	}
	if _, ok := cfg.Security.AddressBook.CollidingNames["zone-local/trust/grp"]; !ok {
		t.Fatalf("qualified typo reference not quarantined: %v", cfg.Security.AddressBook.CollidingNames)
	}
	if _, globalTwinQuarantined := cfg.Security.AddressBook.CollidingNames["grp"]; globalTwinQuarantined {
		t.Fatalf("zone-local typo quarantined global grp for unrelated zones: %v", cfg.Security.AddressBook.CollidingNames)
	}
}

func TestGlobalTypoEntryStrictLenient12622(t *testing.T) {
	lines := []string{
		"set security zones security-zone trust",
		"set security zones security-zone untrust",
		"set security address-book global address local 10.0.0.1/32",
		"set security address-book global adress-set grp address local",
		"set security policies from-zone trust to-zone untrust policy deny-grp match source-address grp",
		"set security policies from-zone trust to-zone untrust policy deny-grp match destination-address any",
		"set security policies from-zone trust to-zone untrust policy deny-grp match application any",
		"set security policies from-zone trust to-zone untrust policy deny-grp then deny",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatalf("strict global typo must reject")
	}
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatalf("lenient global: %v", err)
	}
	if !warningContaining12622(cfg, "adress-set", "grp") {
		t.Fatalf("lenient global warnings: %v", cfg.Warnings)
	}
	if len(cfg.Security.AddressBook.UnknownBookEntries) == 0 {
		t.Fatalf("global UnknownBookEntries empty")
	}
	if _, ok := cfg.Security.AddressBook.CollidingNames["grp"]; !ok {
		t.Fatalf("dropped global grp not in CollidingNames: %v", cfg.Security.AddressBook.CollidingNames)
	}
}

func TestValidBooksNoUnknown12622(t *testing.T) {
	for _, lines := range [][]string{
		{
			"set security zones security-zone trust",
			"set security address-book global address a 10.0.0.1/32",
			"set security address-book global address-set s address a",
			"set security address-book global address-set s description hello",
		},
		{
			"set security zones security-zone trust address-book address a 10.0.0.1/32",
		},
	} {
		cfg, err := CompileConfig(buildTree(t, lines))
		if err != nil {
			t.Fatalf("valid rejected: %v", err)
		}
		if len(cfg.Security.AddressBook.UnknownBookEntries) != 0 {
			t.Fatalf("valid flagged unknown: %+v", cfg.Security.AddressBook.UnknownBookEntries)
		}
	}
	tree, errs := NewParser(`security { zones { security-zone A { address-book { apply-macro M { k v; } address H 10.0.0.1/32; } } } }`).Parse()
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("apply-macro book rejected: %v", err)
	}
	if len(cfg.Security.Zones["A"].AddressBook.UnknownBookEntries) != 0 {
		t.Fatalf("apply-macro flagged: %+v", cfg.Security.Zones["A"].AddressBook.UnknownBookEntries)
	}
}

func TestZoneLocalTypoAddressKeyword12622(t *testing.T) {
	lines := []string{
		"set interfaces eth0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces eth0.0",
		"set security zones security-zone untrust",
		"set security address-book global address host 10.0.0.1/32",
		"set security zones security-zone trust address-book adress host 10.0.0.9/32",
		"set security policies from-zone trust to-zone untrust policy deny1 match source-address host",
		"set security policies from-zone trust to-zone untrust policy deny1 match destination-address any",
		"set security policies from-zone trust to-zone untrust policy deny1 match application any",
		"set security policies from-zone trust to-zone untrust policy deny1 then deny",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatalf("strict typo adress must reject")
	}
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatal(err)
	}
	if !warningContaining12622(cfg, "adress") {
		t.Fatalf("warnings %v", cfg.Warnings)
	}
	if cfg.Security.Zones["trust"] == nil || len(cfg.Security.Zones["trust"].Interfaces) != 0 {
		t.Fatalf("zone not unbound")
	}
}

func TestUnknownAddressBookEntryStrictDiagnostic12622(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lines []string
		want  string
	}{
		{
			name:  "zone-local",
			lines: []string{"set security zones security-zone trust", "set security zones security-zone trust address-book adress-set grp address missing"},
			want:  `zone "trust" address-book: unknown entry keyword "adress-set"`,
		},
		{
			name:  "global",
			lines: []string{"set security address-book global adress-set grp address missing"},
			want:  `global address-book: unknown entry keyword "adress-set"`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := CompileConfig(buildTree(t, tc.lines)); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("strict error = %v, want %q", err, tc.want)
			}
		})
	}
}
func TestZoneLocalTypoEntryCapturesAllNames12622(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tree  func() *ConfigTree
		names []string
	}{
		{
			name: "nameless-hierarchical",
			tree: func() *ConfigTree {
				tree, errs := NewParser(`security {
					zones {
						security-zone trust {
							address-book {
								adress-set {
									grp { address local; }
								}
							}
						}
						security-zone untrust;
					}
					address-book { global { address-set grp { address local; } } }
					policies {
						from-zone trust { to-zone untrust { policy deny-grp {
							match { source-address grp; destination-address any; application any; }
							then { deny; }
						} } }
					}
				}`).Parse()
				if len(errs) > 0 {
					t.Fatalf("parse: %v", errs)
				}
				return tree
			},
			names: []string{"grp"},
		},
		{
			name: "flat-tail",
			tree: func() *ConfigTree {
				return buildTree(t, []string{
					"set interfaces eth0 unit 0 family inet address 192.0.2.1/24",
					"set security zones security-zone trust interfaces eth0.0",
					"set security zones security-zone untrust",
					"set security address-book global address-set grp address local",
					"set security zones security-zone trust address-book adress-set grp extra",
					"set security policies from-zone trust to-zone untrust policy deny-grp match source-address grp",
					"set security policies from-zone trust to-zone untrust policy deny-grp match source-address extra",
					"set security policies from-zone trust to-zone untrust policy deny-grp match destination-address any",
					"set security policies from-zone trust to-zone untrust policy deny-grp match application any",
					"set security policies from-zone trust to-zone untrust policy deny-grp then deny",
				})
			},
			names: []string{"grp", "extra"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := tc.tree()
			if _, err := CompileConfig(tree); err == nil {
				t.Fatal("strict compile accepted unknown address-book entry")
			}
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("lenient compile: %v", err)
			}
			zone := cfg.Security.Zones["trust"]
			if zone == nil || !zone.DroppedEnforcementChild || len(zone.Interfaces) != 0 {
				t.Fatalf("zone must be unbound after typo entry: %+v", zone)
			}
			for _, name := range tc.names {
				found := false
				for _, entry := range zone.AddressBook.UnknownBookEntries {
					for _, got := range entry.Names {
						if got == name {
							found = true
						}
					}
				}
				if !found {
					t.Errorf("name %q absent from quarantine entries: %+v", name, zone.AddressBook.UnknownBookEntries)
				}
				if _, ok := cfg.Security.AddressBook.CollidingNames["zone-local/trust/"+name]; !ok {
					t.Errorf("name %q not qualified into collision quarantine: %v", name, cfg.Security.AddressBook.CollidingNames)
				}
			}
			for _, pair := range cfg.Security.Policies {
				for _, policy := range pair.Policies {
					tokens := append(policy.Match.SourceAddresses, policy.Match.DestinationAddresses...)
					for _, name := range tc.names {
						want := "zone-local/trust/" + name
						found := false
						for _, token := range tokens {
							if token == want {
								found = true
							}
						}
						if !found {
							t.Errorf("token %q was not rewritten to quarantine: %v", want, tokens)
						}
					}
				}
			}
		})
	}
}
