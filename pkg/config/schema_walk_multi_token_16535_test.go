package config

// schema_walk_multi_token_16535_test.go — #16535: the parser admits a
// SIXTH spelling of a two-element value list, `leaf { v1 v2; }` (one
// block child carrying both tokens, child Keys=[v1 v2]). The #2419
// spelling differential and the slot-escape sweep enumerated five
// spellings; in the sixth, validateMultiValueLeaf checked only
// c.Keys[:1], so a rejected second value could commit (and reach
// compilers that read every child key, e.g. RA dns-server-address via
// firewallMatchValues), while compilers reading Keys[0] per child
// (proxyARPAddressValues, multiLeafAuthoredValues) silently dropped a
// valid second value.
//
// Fix: the walker REFUSES a multi-token block child — one value per
// statement inside a value block — at every typed multi leaf and at
// untyped multi leaves (proxy-arp `address`, whose values the
// compiler's strict gate checks). Leaves whose compiler reads EVERY
// child key (allChildKeysAreValues) are exempt: every token is a
// value there and every token is validated.
//
// Fail-on-revert: drop the refusal in validateMultiValueLeaf /
// walkSchemaNode and the "refused" cells below go GREEN-on-commit
// again (proxy-arp compiles only the first address; the RA form
// compiles the rejected second address).

import (
	"strings"
	"testing"
)

func commitBrace16535(t *testing.T, body string) error {
	t.Helper()
	return slotEscapeCommitBrace(body)
}

func TestOneChildMultiTokenBlockRefused16535(t *testing.T) {
	cases := []struct {
		name string
		body string
		// wantRefused: the sixth spelling must be refused at commit.
		// wantClean: the same values in a legal spelling must commit.
		legalBody string
	}{
		{
			name:      "proxy-arp good+good refused, block legal",
			body:      "security { nat { proxy-arp { interface ge-0/0/0.0 { address { 10.0.0.1 10.0.0.2; } } } } }",
			legalBody: "security { nat { proxy-arp { interface ge-0/0/0.0 { address { 10.0.0.1; 10.0.0.2; } } } } }",
		},
		{
			name:      "proxy-arp good+bad refused",
			body:      "security { nat { proxy-arp { interface ge-0/0/0.0 { address { 10.0.0.1 999.1.1.1; } } } } }",
			legalBody: "security { nat { proxy-arp { interface ge-0/0/0.0 { address { 10.0.0.1; 10.0.0.2; } } } } }",
		},
		{
			name:      "proxy-ndp good+good refused",
			body:      "security { nat { proxy-ndp { interface ge-0/0/0.0 { address { 2001:db8::1 2001:db8::2; } } } } }",
			legalBody: "security { nat { proxy-ndp { interface ge-0/0/0.0 { address { 2001:db8::1; 2001:db8::2; } } } } }",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := commitBrace16535(t, c.body)
			if err == nil {
				t.Fatalf("sixth spelling %q committed clean; want refusal (#16535)", c.body)
			}
			if !strings.Contains(err.Error(), "only one value per statement") {
				t.Fatalf("refusal %q does not name the one-value-per-statement rule", err)
			}
			if err := commitBrace16535(t, c.legalBody); err != nil {
				t.Fatalf("legal spelling %q must commit clean, got: %v", c.legalBody, err)
			}
		})
	}
}

// The acceptance row from the issue: the one-child proxy-arp spelling
// either compiles BOTH addresses or is refused. It is refused; the
// bracket and one-per-statement spellings compile both.
func TestProxyARPOneChildRowCompilesBothOrRefused16535(t *testing.T) {
	refused := "security { nat { proxy-arp { interface ge-0/0/0.0 { address { 10.0.0.1 10.0.0.2; } } } } }"
	if err := commitBrace16535(t, refused); err == nil {
		// Not refused: then both addresses must be compiled.
		p := NewParser(refused)
		tree, errs := p.Parse()
		if len(errs) > 0 {
			t.Fatalf("parse: %v", errs)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		var got []string
		for _, e := range cfg.Security.NAT.ProxyARP {
			got = append(got, e.Addresses...)
		}
		if len(got) != 2 {
			t.Fatalf("one-child proxy-arp row neither refused nor compiled both addresses: got %v", got)
		}
	}
	for _, body := range []string{
		"security { nat { proxy-arp { interface ge-0/0/0.0 { address [ 10.0.0.1 10.0.0.2 ]; } } } }",
		"security { nat { proxy-arp { interface ge-0/0/0.0 { address { 10.0.0.1; 10.0.0.2; } } } } }",
	} {
		p := NewParser(body)
		tree, errs := p.Parse()
		if len(errs) > 0 {
			t.Fatalf("parse %q: %v", body, errs)
		}
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("validate %q: %v", body, err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("compile %q: %v", body, err)
		}
		var got []string
		for _, e := range cfg.Security.NAT.ProxyARP {
			got = append(got, e.Addresses...)
		}
		if len(got) != 2 {
			t.Fatalf("legal spelling %q compiled %v, want both addresses", body, got)
		}
	}
}

// A typed multi leaf whose compiler reads every child key
// (allChildKeysAreValues, e.g. name-server via firewallMatchValues):
// the sixth spelling is NOT refused, but EVERY token is validated —
// a rejected second token must not commit.
func TestOneChildMultiTokenAllChildKeysValidated16535(t *testing.T) {
	bad := "system { name-server { 8.8.8.8 999.1.1.1; } }"
	if err := commitBrace16535(t, bad); err == nil {
		t.Fatalf("name-server sixth spelling with rejected second value committed clean")
	}
	good := "system { name-server { 8.8.8.8 8.8.4.4; } }"
	if err := commitBrace16535(t, good); err != nil {
		t.Fatalf("name-server sixth spelling with two valid values must commit clean (allChildKeysAreValues), got: %v", err)
	}
}

// A typed multi leaf WITHOUT allChildKeysAreValues whose compiler
// reads every child key (RA dns-server-address via
// firewallMatchValues): pre-fix the rejected second token escaped
// validation and compiled. Now the whole spelling is refused.
func TestOneChildMultiTokenRADNSRefused16535(t *testing.T) {
	body := "protocols { router-advertisement { interface ge-0/0/0.0 { dns-server-address { 2001:db8::53 8.8.8.8; } } } }"
	err := commitBrace16535(t, body)
	if err == nil {
		t.Fatalf("RA dns-server-address sixth spelling with IPv4 second value committed clean; want refusal")
	}
	if !strings.Contains(err.Error(), "only one value per statement") &&
		!strings.Contains(err.Error(), "dns-server-address") {
		t.Fatalf("refusal %q names neither the rule nor the leaf", err)
	}
	legal := "protocols { router-advertisement { interface ge-0/0/0.0 { dns-server-address { 2001:db8::53; 2001:db8::54; } } } }"
	if err := commitBrace16535(t, legal); err != nil {
		t.Fatalf("legal RA spelling must commit clean, got: %v", err)
	}
}

// The slot-escape sweep must carry the sixth form so a future
// regression is caught by the sweep as well as by the rows above.
func TestSlotEscapeFormsIncludeSixth16535(t *testing.T) {
	found := false
	for _, f := range slotEscapeForms() {
		if f.name == "G-hier-one-child-multi-token" {
			found = true
		}
	}
	if !found {
		t.Fatalf("slotEscapeForms missing G-hier-one-child-multi-token (#16535 sixth form)")
	}
}
