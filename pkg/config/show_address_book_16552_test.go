package config

import (
	"strings"
	"testing"
)

// #16552: AddressDisplayValue / RenderAddressBook must show the
// authored form + enforced set for #15673 forms, an explicit
// unresolved marker for an unresolved dns-name, and NOT ENFORCED for
// tainted entries — never a blank.

func TestAddressDisplayValue16552(t *testing.T) {
	orig := lookupAddressDNSName
	defer func() { lookupAddressDNSName = orig }()
	lookupAddressDNSName = func(fqdn string) ([]string, error) {
		if fqdn == "up.example.com" {
			return []string{"198.51.100.10"}, nil
		}
		return nil, nil
	}
	mk := func(body string) *Address {
		t.Helper()
		cfg, err := CompileConfig(soleFormTree(t, body))
		if err != nil {
			t.Fatalf("compile %q: %v", body, err)
		}
		for _, a := range cfg.Security.AddressBook.Addresses {
			return a
		}
		t.Fatalf("no address in %q", body)
		return nil
	}

	cases := []struct {
		name string
		addr *Address
		want []string
		not  string
	}{
		{"prefix", &Address{Name: "h1", Value: "10.0.0.1/32"}, []string{"10.0.0.1/32"}, ""},
		{"range", mk(`address rng { range-address 192.0.2.1 { to { 192.0.2.3; } } }`),
			[]string{"range-address 192.0.2.1 to 192.0.2.3", "192.0.2.1/32", "192.0.2.2/31"}, ""},
		{"large-range", mk(`address big { range-address 10.0.0.0 { to { 10.0.1.255; } } }`),
			[]string{"range-address 10.0.0.0 to 10.0.1.255", "10.0.0.0/23"}, "NOT ENFORCED"},
		{"wildcard", mk(`address wc { wildcard-address 10.1.2.3/255.255.255.0; }`),
			[]string{"wildcard-address 10.1.2.3/255.255.255.0", "10.1.2.0/24"}, ""},
		{"dns-up", mk(`address up { dns-name up.example.com { ipv4-only; } }`),
			[]string{"dns-name up.example.com", "[ipv4-only]", "198.51.100.10/32"}, "unresolved"},
		{"dns-down", mk(`address down { dns-name down.example.com; }`),
			[]string{"dns-name down.example.com", "unresolved", "matches nothing"}, ""},
		{"invalid-range", &Address{Name: "bad", RangeSpec: "10.0.1.0 to 10.0.0.0", OversizedRange: "10.0.1.0 to 10.0.0.0: low address 10.0.1.0 > high address 10.0.0.0"},
			[]string{"range-address 10.0.1.0 to 10.0.0.0", "NOT ENFORCED", "invalid range-address"}, ""},
		{"unimplemented", &Address{Name: "u", Value: "10.0.0.5/32", UnimplementedForms: []string{"future-form"}},
			[]string{"10.0.0.5/32", "NOT ENFORCED", "future-form"}, ""},
		{"duplicate", &Address{Name: "d", Value: "10.0.0.1/32", DuplicatePrefixes: []string{"10.0.0.2/32"}},
			[]string{"NOT ENFORCED", "duplicate"}, ""},
		{"empty", &Address{Name: "e"}, []string{"unresolved", "matches nothing"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AddressDisplayValue(tc.addr)
			if got == "" {
				t.Fatalf("blank display for %+v", tc.addr)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("display %q missing %q", got, w)
				}
			}
			if tc.not != "" && strings.Contains(got, tc.not) {
				t.Errorf("display %q must not contain %q", got, tc.not)
			}
		})
	}
	if AddressDisplayValue(nil) != "" {
		t.Error("nil must render empty")
	}
	// Resolved vs unresolved dns-name must differ.
	up := AddressDisplayValue(mk(`address up { dns-name up.example.com; }`))
	down := AddressDisplayValue(mk(`address down { dns-name down.example.com; }`))
	if up == down {
		t.Errorf("resolved and unresolved dns-name identical: %q", up)
	}
}

func TestRenderAddressBook16552(t *testing.T) {
	ab := &AddressBook{
		Addresses: map[string]*Address{
			"h1":  {Name: "h1", Value: "10.0.0.1/32"},
			"up":  {Name: "up", DNSName: "up.example.com", DNSFamily: "ipv4-only", DNSAddresses: []string{"198.51.100.10/32"}},
			"bad": nil,
		},
		AddressSets: map[string]*AddressSet{
			"s1": {Name: "s1", Addresses: []string{"h1", "up"}},
		},
	}
	var sb strings.Builder
	RenderAddressBook(&sb, ab)
	out := sb.String()
	for _, want := range []string{"h1", "10.0.0.1/32", "dns-name up.example.com", "198.51.100.10/32", "s1", "members: h1, up"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
	var sb2 strings.Builder
	RenderAddressBook(&sb2, nil)
	if sb2.String() != "No address book configured\n" {
		t.Errorf("nil book: %q", sb2.String())
	}
	// Deterministic.
	var sb3 strings.Builder
	RenderAddressBook(&sb3, ab)
	if sb3.String() != out {
		t.Errorf("non-deterministic render:\n%s\n---\n%s", out, sb3.String())
	}
}
