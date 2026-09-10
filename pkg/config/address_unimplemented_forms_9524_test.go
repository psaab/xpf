package config

import (
	"reflect"
	"strings"
	"testing"
)

// #9524 — an address carrying a prefix AND an unimplemented value form.
// Channels: CompileConfig (strict; what commit and configstore.CheckText run)
// rejects it; CompileConfigLenient (boot load, HA sync, upgrade) warns and
// keeps the entry, with UsableValue() making it resolve to no usable address.

func hier9524(t *testing.T, text string) *ConfigTree {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture must parse: %v", errs)
	}
	return tree
}

func TestMixedAddressValueFormRejectedAtCommit9524(t *testing.T) {
	const global = "set security address-book global address mixed "
	const zl = "set security zones security-zone trust address-book address mixed "
	type row struct {
		name  string
		tree  func(t *testing.T) *ConfigTree
		form  string
		scope string // "" global, else "zones security-zone trust "
	}
	flat := func(lines ...string) func(t *testing.T) *ConfigTree {
		return func(t *testing.T) *ConfigTree {
			return buildTree(t, append([]string{"set security zones security-zone trust"}, lines...))
		}
	}
	h := func(body string) func(t *testing.T) *ConfigTree {
		return func(t *testing.T) *ConfigTree {
			return hier9524(t, `security { address-book { global { `+body+` } } zones { security-zone trust; } }`)
		}
	}
	for _, r := range []row{
		{"hier prefix then dns-name", h(`address mixed { 10.10.0.0/24; dns-name evil.example; }`), "dns-name", ""},
		{"hier dns-name then prefix", h(`address mixed { dns-name evil.example; 10.10.0.0/24; }`), "dns-name", ""},
		{"hier prefix + wildcard-address", h(`address mixed { 10.10.0.0/24; wildcard-address 10.0.0.1/255.0.255.255; }`), "wildcard-address", ""},
		{"hier prefix + range-address", h(`address mixed { 10.10.0.0/24; range-address 192.0.2.1 { to { 192.0.2.9; } } }`), "range-address", ""},
		{"flat prefix then dns-name", flat(global+"10.10.0.0/24", global+"dns-name evil.example"), "dns-name", ""},
		{"flat dns-name then prefix", flat(global+"dns-name evil.example", global+"10.10.0.0/24"), "dns-name", ""},
		{"flat prefix + wildcard-address", flat(global+"10.10.0.0/24", global+"wildcard-address 10.0.0.1/255.0.255.255"), "wildcard-address", ""},
		{"zone-local flat prefix + dns-name", flat(zl+"10.10.0.0/24", zl+"dns-name evil.example"), "dns-name", "zones security-zone trust "},
	} {
		t.Run(r.name, func(t *testing.T) {
			_, err := CompileConfig(r.tree(t))
			want := `security ` + r.scope + `address-book address "mixed" configures the prefix "10.10.0.0/24" and also ` + r.form
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("#9524: strict commit must reject the mixed entry naming the prefix and the dropped form (%q), got %v", want, err)
			}
			cfg, lerr := CompileConfigLenient(r.tree(t))
			if lerr != nil {
				t.Fatalf("tolerant compile must keep the entry (#1960 no-brick): %v", lerr)
			}
			warned := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "address value form (downgraded") && strings.Contains(w, r.form) {
					warned = true
				}
			}
			if !warned {
				t.Errorf("tolerant compile did not warn; warnings=%v", cfg.Warnings)
			}
			var a *Address
			if r.scope == "" {
				a = cfg.Security.AddressBook.Addresses["mixed"]
			} else {
				a = cfg.Security.Zones["trust"].AddressBook.Addresses["mixed"]
			}
			if a == nil || a.Value != "10.10.0.0/24" || !reflect.DeepEqual(a.UnimplementedForms, []string{r.form}) {
				t.Fatalf("fixture premise: want Value=10.10.0.0/24 and UnimplementedForms=[%s], got %+v", r.form, a)
			}
			if a.UsableValue() != "" {
				t.Errorf("#9524: a mixed entry must resolve to no usable address, got %q", a.UsableValue())
			}
			validated := false
			for _, w := range ValidateConfig(cfg) {
				if strings.Contains(w, `"mixed"`) && strings.Contains(w, r.form+" is not implemented, so this entry resolves to no usable address") {
					validated = true
				}
			}
			if !validated && r.scope == "" {
				t.Errorf("#9524: ValidateConfig does not name the dropped form; warnings=%v", ValidateConfig(cfg))
			}
			if r.scope != "" {
				folded := cfg.Security.AddressBook.Addresses[zoneLocalQualify("trust", "mixed")]
				if folded == nil || folded.UsableValue() != "" {
					t.Errorf("#9524: the zone-local fold dropped the taint: %+v", folded)
				}
			}
		})
	}
}

// The accepting controls. A sole unimplemented form is valid Junos and keeps
// its existing handling (#2229 warning; #3149 only when referenced); a prefix
// with a `description` is a legitimate sub-stanza, not a value form.
func TestMixedAddressValueFormControls9524(t *testing.T) {
	for _, tc := range []struct {
		name       string
		lines      []string
		wantUsable string
	}{
		{"sole prefix", []string{"set security address-book global address mixed 10.10.0.0/24"}, "10.10.0.0/24"},
		{"sole dns-name, unreferenced", []string{"set security address-book global address mixed dns-name evil.example"}, ""},
		{"prefix with description", []string{
			"set security address-book global address mixed 10.10.0.0/24",
			`set security address-book global address mixed description "web tier"`,
		}, "10.10.0.0/24"},
		{"zone-local sole prefix", []string{"set security zones security-zone trust address-book address mixed 10.10.0.0/24"}, "10.10.0.0/24"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := append([]string{"set security zones security-zone trust"}, tc.lines...)
			cfg, err := CompileConfig(buildTree(t, lines))
			if err != nil {
				t.Fatalf("#9524 OVER-REJECTION: a legitimate entry did not commit: %v", err)
			}
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "address value form") {
					t.Errorf("#9524 gate fired for a legitimate entry: %s", w)
				}
			}
			for _, w := range ValidateConfig(cfg) {
				if strings.Contains(w, "is not implemented, so this entry resolves to no usable address") {
					t.Errorf("#9524 warn-validator message fired for a legitimate entry: %s", w)
				}
			}
			a := cfg.Security.AddressBook.Addresses["mixed"]
			if a == nil {
				a = cfg.Security.Zones["trust"].AddressBook.Addresses["mixed"]
			}
			if got := a.UsableValue(); got != tc.wantUsable {
				t.Errorf("UsableValue() = %q, want %q", got, tc.wantUsable)
			}
		})
	}
}

// The junos-host deny projection resolves addresses through the same accessor,
// so a mixed entry is unresolvable there too (ok=false), like the sole-value
// case, instead of projecting the prefix alone.
func TestJunosHostResolverTreatsMixedEntryAsUnresolvable9524(t *testing.T) {
	ab := &AddressBook{Addresses: map[string]*Address{
		"mixed":  {Name: "mixed", Value: "10.10.0.0/24", UnimplementedForms: []string{"dns-name"}},
		"prefix": {Name: "prefix", Value: "10.10.0.0/24"},
	}, AddressSets: map[string]*AddressSet{}}
	cfg := &Config{}
	cfg.Security.AddressBook = ab
	if _, _, _, _, ok := junosHostResolveAddrSet(cfg, []string{"mixed"}, nil); ok {
		t.Error("#9524: the junos-host resolver projected a mixed entry's prefix alone")
	}
	v4, _, _, _, ok := junosHostResolveAddrSet(cfg, []string{"prefix"}, nil)
	if !ok || !reflect.DeepEqual(v4, []string{"10.10.0.0/24"}) {
		t.Errorf("control: a sole prefix must still resolve, got ok=%v v4=%v", ok, v4)
	}
}
