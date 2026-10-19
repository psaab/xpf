package config

import (
	"reflect"
	"strings"
	"testing"
)

// #15673 — sole dns-name/range-address/wildcard-address forms must be caught
// at strict commit (not silently warn-only), range-address must expand
// natively, wildcard-address must expand, and mergeAddressNode /
// parseAddressBookEntries must not drop sub-stanzas / leaf names.

func soleFormTree(t *testing.T, body string) *ConfigTree {
	t.Helper()
	return hier9524(t, `security { address-book { global { `+body+` } } zones { security-zone trust; } }`)
}

// Sole unsupported forms: strict must reject deterministically.
func TestSoleAddressFormsRejectedAtCommit15673(t *testing.T) {
	for _, r := range []struct {
		name, body, form string
	}{
		{"sole future form hier", `address partner-api { future-address-form value; }`, "future-address-form"},
		{"sole noncontiguous wildcard hier", `address wc { wildcard-address 10.1.2.3/0.255.0.255; }`, "wildcard-address"},
	} {
		t.Run(r.name, func(t *testing.T) {
			_, err := CompileConfig(soleFormTree(t, r.body))
			if err == nil || !strings.Contains(err.Error(), r.form) {
				t.Fatalf("#15673: strict commit must reject sole %s, got %v", r.form, err)
			}
			cfg, lerr := CompileConfigLenient(soleFormTree(t, r.body))
			if lerr != nil {
				t.Fatalf("lenient must boot (#1960): %v", lerr)
			}
			a := cfg.Security.AddressBook.Addresses[strings.Fields(strings.TrimPrefix(r.body, "address "))[0]]
			_ = a
			warned := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, r.form) {
					warned = true
				}
			}
			if !warned {
				t.Errorf("lenient must warn naming %s; warnings=%v", r.form, cfg.Warnings)
			}
			// ValidateConfig must name the form, not generic "no usable prefix".
			named := false
			for _, w := range ValidateConfig(cfg) {
				if strings.Contains(w, r.form) {
					named = true
				}
			}
			if !named {
				t.Errorf("ValidateConfig must name %s; got %v", r.form, ValidateConfig(cfg))
			}
		})
	}
	// Flat sole forms.
	for _, r := range []struct {
		name, line, form string
	}{
		{"sole future form flat", "set security address-book global address partner-api future-address-form value", "future-address-form"},
		{"unused", "", ""},
	} {
		if r.line == "" {
			continue
		}
		t.Run(r.name, func(t *testing.T) {
			tree := buildTree(t, []string{"set security zones security-zone trust", r.line})
			_, err := CompileConfig(tree)
			if err == nil || !strings.Contains(err.Error(), r.form) {
				t.Fatalf("#15673: strict must reject sole flat %s, got %v", r.form, err)
			}
		})
	}
}

// range-address expands natively to /32 prefixes and is usable.
func TestRangeAddressExpands15673(t *testing.T) {
	for _, tc := range []struct {
		name string
		tree func(t *testing.T) *ConfigTree
		want []string
	}{
		{"hier", func(t *testing.T) *ConfigTree {
			return soleFormTree(t, `address rng { range-address 192.0.2.1 { to { 192.0.2.3; } } }`)
		}, []string{"192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32"}},
		{"flat", func(t *testing.T) *ConfigTree {
			return buildTree(t, []string{
				"set security zones security-zone trust",
				"set security address-book global address rng range-address 192.0.2.1 to 192.0.2.3",
			})
		}, []string{"192.0.2.1/32", "192.0.2.2/32", "192.0.2.3/32"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := CompileConfig(tc.tree(t))
			if err != nil {
				t.Fatalf("#15673: valid range-address must commit: %v", err)
			}
			a := cfg.Security.AddressBook.Addresses["rng"]
			if a == nil {
				t.Fatal("rng missing")
			}
			if got := a.UsableValues(); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("UsableValues = %v, want %v (a=%+v)", got, tc.want, a)
			}
			if a.UsableValue() == "" {
				t.Errorf("range entry must be usable, got Value=%q forms=%v", a.Value, a.UnimplementedForms)
			}
		})
	}
	// Oversized range: strict rejects, lenient boots unusable.
	t.Run("oversized", func(t *testing.T) {
		tree := func() *ConfigTree {
			return buildTree(t, []string{
				"set security zones security-zone trust",
				"set security address-book global address big range-address 10.0.0.0 to 10.0.1.255",
			})
		}
		if _, err := CompileConfig(tree()); err == nil {
			t.Fatal("oversized range-address must reject at strict commit")
		}
		cfg, err := CompileConfigLenient(tree())
		if err != nil {
			t.Fatalf("lenient must boot: %v", err)
		}
		if a := cfg.Security.AddressBook.Addresses["big"]; a == nil || a.UsableValue() != "" || len(a.UsableValues()) != 0 {
			t.Fatalf("oversized lenient entry must be unusable, got %+v", a)
		}
	})
}

// wildcard-address expands to the wildcard-matched prefix.
func TestWildcardAddressExpands15673(t *testing.T) {
	cfg, err := CompileConfig(soleFormTree(t, `address wc { wildcard-address 10.1.2.3/0.0.0.255; }`))
	if err != nil {
		t.Fatalf("wildcard-address must commit: %v", err)
	}
	a := cfg.Security.AddressBook.Addresses["wc"]
	if a == nil || !reflect.DeepEqual(a.UsableValues(), []string{"10.1.2.0/24"}) {
		t.Fatalf("wildcard 10.1.2.3/0.0.0.255 must expand to 10.1.2.0/24, got %+v", a)
	}
	// Flat form.
	cfg2, err := CompileConfig(buildTree(t, []string{
		"set security zones security-zone trust",
		"set security address-book global address wc wildcard-address 10.1.2.3/0.0.0.255",
	}))
	if err != nil {
		t.Fatalf("flat wildcard must commit: %v", err)
	}
	if a := cfg2.Security.AddressBook.Addresses["wc"]; a == nil || !reflect.DeepEqual(a.UsableValues(), []string{"10.1.2.0/24"}) {
		t.Fatalf("flat wildcard wrong: %+v", a)
	}
}

// dns-name is modelled: strict commits, entry carries DNSName, and a resolver
// seam produces usable prefixes (via test resolver, no network).
func TestDNSNameModelled15673(t *testing.T) {
	orig := lookupAddressDNSName
	defer func() { lookupAddressDNSName = orig }()
	lookupAddressDNSName = func(fqdn string) ([]string, error) {
		if fqdn != "api.example.com" {
			return nil, nil
		}
		return []string{"203.0.113.10", "2001:db8::10"}, nil
	}
	cfg, err := CompileConfig(soleFormTree(t, `address partner-api { dns-name api.example.com; }`))
	if err != nil {
		t.Fatalf("dns-name must commit as modelled form: %v", err)
	}
	a := cfg.Security.AddressBook.Addresses["partner-api"]
	if a == nil || a.DNSName != "api.example.com" {
		t.Fatalf("DNSName not modelled: %+v", a)
	}
	want := []string{"2001:db8::10/128", "203.0.113.10/32"}
	if got := a.UsableValues(); !reflect.DeepEqual(got, want) {
		t.Fatalf("dns UsableValues = %v, want %v", got, want)
	}
	// ipv4-only filters v6.
	cfg4, err := CompileConfig(soleFormTree(t, `address partner-api { dns-name api.example.com { ipv4-only; } }`))
	if err != nil {
		t.Fatalf("ipv4-only must commit: %v", err)
	}
	a4 := cfg4.Security.AddressBook.Addresses["partner-api"]
	if a4 == nil || a4.DNSFamily != "ipv4-only" {
		t.Fatalf("DNSFamily not modelled: %+v", a4)
	}
	if got := a4.UsableValues(); !reflect.DeepEqual(got, []string{"203.0.113.10/32"}) {
		t.Fatalf("ipv4-only UsableValues = %v", got)
	}
	// ipv6-only filters v4 (flat).
	cfg6, err := CompileConfig(buildTree(t, []string{
		"set security zones security-zone trust",
		"set security address-book global address partner-api dns-name api.example.com ipv6-only",
	}))
	if err != nil {
		t.Fatalf("flat ipv6-only must commit: %v", err)
	}
	a6 := cfg6.Security.AddressBook.Addresses["partner-api"]
	if a6 == nil || a6.DNSFamily != "ipv6-only" || !reflect.DeepEqual(a6.UsableValues(), []string{"2001:db8::10/128"}) {
		t.Fatalf("ipv6-only flat wrong: %+v values=%v", a6, a6.UsableValues())
	}
	// Unresolvable DNS: usable empty (fail-closed), not an error.
	lookupAddressDNSName = func(string) ([]string, error) { return nil, nil }
	cfgU, err := CompileConfig(soleFormTree(t, `address partner-api { dns-name api.example.com; }`))
	if err != nil {
		t.Fatalf("unresolvable dns-name must still commit (dynamic): %v", err)
	}
	if a := cfgU.Security.AddressBook.Addresses["partner-api"]; a == nil || len(a.UsableValues()) != 0 {
		t.Fatalf("unresolvable dns must be match-none, got %+v", a)
	}
}

// mergeAddressNode: described address node must still inspect children —
// a prefix child under/behind description must not be dropped, and a form
// child after description must be classified.
func TestDescribedAddressKeepsSubStanzas15673(t *testing.T) {
	// Hierarchical: description first, then prefix, then dns-name sibling
	// definitions merged by name.
	cfg, err := CompileConfigLenient(soleFormTree(t, `address mixed { description "web"; 10.10.0.0/24; }`))
	if err != nil {
		t.Fatal(err)
	}
	a := cfg.Security.AddressBook.Addresses["mixed"]
	if a == nil || a.Value != "10.10.0.0/24" || a.Description != "web" {
		t.Fatalf("described hier address lost prefix/desc: %+v", a)
	}
	// Flat: description node carrying a nested form child (legacy split shape
	// is exercised via hierarchical dns-name after description block).
	tree := soleFormTree(t, `address mixed { description "web"; dns-name evil.example; 10.10.0.0/24; }`)
	if _, err := CompileConfig(tree); err == nil {
		t.Fatal("prefix+dns-name after description must still reject at strict (form not dropped)")
	}
}

// parseAddressBookEntries: hierarchical leaf entries inside an unknown book
// stanza must populate Names and quarantine collisions.
func TestUnknownBookLeafNamesQuarantined15673(t *testing.T) {
	tree := hier9524(t, `security { address-book { global { address good 10.0.0.1/32; bogus-book { address leafname 10.9.9.9/32; } } } zones { security-zone trust; } }`)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatal(err)
	}
	ab := cfg.Security.AddressBook
	found := false
	for _, e := range ab.UnknownBookEntries {
		for _, n := range e.Names {
			if n == "leafname" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("leaf name inside unknown stanza not recorded: %+v", ab.UnknownBookEntries)
	}
	if _, ok := ab.CollidingNames["leafname"]; !ok {
		t.Fatalf("leafname not quarantined in CollidingNames: %v", ab.CollidingNames)
	}
	_ = reflect.DeepEqual
}
