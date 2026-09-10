package config

import (
	"reflect"
	"testing"
)

// #9574 — the match-all keyword helpers, and the compiled config keeping
// `any-ipv4` / `any-ipv6` as keywords. Channel: CompileConfig (strict); every
// fixture here is a legal, committable config.

func TestPolicyAddressWildcardFamiliesAndLiteral9574(t *testing.T) {
	for _, tc := range []struct {
		tok        string
		v4, v6, ok bool
		lit        string
	}{
		{"any", true, true, true, "any"},
		{"any-ipv4", true, false, true, "0.0.0.0/0"},
		{"any4", true, false, true, "0.0.0.0/0"},
		{"any-ipv6", false, true, true, "::/0"},
		{"any6", false, true, true, "::/0"},
		// Not keywords: a match-all CIDR typed as a token stays a token, so an
		// object of that name is still resolved by name.
		{"0.0.0.0/0", false, false, false, "0.0.0.0/0"},
		{"::/0", false, false, false, "::/0"},
		{"10.0.1.0/24", false, false, false, "10.0.1.0/24"},
		{"ANY", false, false, false, "ANY"},
		{"", false, false, false, ""},
	} {
		v4, v6, ok := PolicyAddressWildcardFamilies(tc.tok)
		if v4 != tc.v4 || v6 != tc.v6 || ok != tc.ok {
			t.Errorf("PolicyAddressWildcardFamilies(%q) = (%v,%v,%v), want (%v,%v,%v)", tc.tok, v4, v6, ok, tc.v4, tc.v6, tc.ok)
		}
		if ok != IsPolicyAddressWildcardKeyword(tc.tok) {
			t.Errorf("IsPolicyAddressWildcardKeyword(%q) disagrees with PolicyAddressWildcardFamilies", tc.tok)
		}
		if got := PolicyAddressKeywordLiteral(tc.tok); got != tc.lit {
			t.Errorf("PolicyAddressKeywordLiteral(%q) = %q, want %q", tc.tok, got, tc.lit)
		}
	}
}

func TestZoneLocalObjectNamedAfterAMatchAllCIDRDoesNotCaptureTheKeyword9574(t *testing.T) {
	pol := "set security policies from-zone trust to-zone untrust policy "
	cfg, err := CompileConfig(buildTree(t, []string{
		"set security zones security-zone trust address-book address 0.0.0.0/0 10.99.0.0/16",
		"set security zones security-zone trust address-book address web 10.0.1.100/32",
		"set security zones security-zone untrust",
		pol + "kw match source-address any-ipv4",
		pol + "kw match destination-address any",
		pol + "kw match application any",
		pol + "kw then deny",
		pol + "named match source-address web",
		pol + "named match destination-address any",
		pol + "named match application any",
		pol + "named then permit",
	}))
	if err != nil {
		t.Fatalf("fixture must commit (a zone-local object named 0.0.0.0/0 is legal): %v", err)
	}
	got := map[string][]string{}
	for _, zpp := range cfg.Security.Policies {
		for _, p := range zpp.Policies {
			got[p.Name] = p.Match.SourceAddresses
		}
	}
	if !reflect.DeepEqual(got["kw"], []string{"any-ipv4"}) {
		t.Errorf("#9574: the keyword was rewritten or zone-local-qualified: %v", got["kw"])
	}
	if !reflect.DeepEqual(got["named"], []string{"zone-local/trust/web"}) {
		t.Errorf("control: a zone-local name must still be qualified: %v", got["named"])
	}
}

// The tolerant-path half of the zone-local skip. A zone-local object named
// `any-ipv4` is rejected at commit since #9523, but a boot load or HA sync keeps
// it with a warning. The zone-local rewrite must still leave the keyword alone:
// qualifying it to `zone-local/trust/any-ipv4` would turn it into a name that the
// snapshot builder then resolves to the object, which is the capture again.
func TestZoneLocalObjectNamedAKeywordDoesNotCaptureItOnTheTolerantPath9574(t *testing.T) {
	pol := "set security policies from-zone trust to-zone untrust policy kw "
	lines := []string{
		"set security zones security-zone trust address-book address any-ipv4 10.99.0.0/16",
		"set security zones security-zone untrust",
		pol + "match source-address any-ipv4",
		pol + "match destination-address any",
		pol + "match application any",
		pol + "then deny",
	}
	if _, err := CompileConfig(buildTree(t, lines)); err == nil {
		t.Fatal("fixture premise broken: strict commit accepted a zone-local object named any-ipv4 (#9523), so this cell no longer measures the tolerant path")
	}
	cfg, err := CompileConfigLenient(buildTree(t, lines))
	if err != nil {
		t.Fatal(err)
	}
	src := cfg.Security.Policies[0].Policies[0].Match.SourceAddresses
	if !reflect.DeepEqual(src, []string{"any-ipv4"}) {
		t.Errorf("#9574: the zone-local rewrite qualified the keyword: %v", src)
	}
}
