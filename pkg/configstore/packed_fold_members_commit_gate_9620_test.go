package configstore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9620: packed one-line spellings that the #8662 fold did not reach, or reached
// and left on one leaf. Each cell compares the elided spelling with the braced
// one through CheckText, the strict commit gate, and through the lenient compile
// that the boot and HA-sync paths use.
//
// Measured at 9f520a5b2, before the admissions and opt-ins this file pins:
//
//	H9   firewall `term t1 then count C1 discard;`       strict ACCEPT, lenient compiled no action
//	H9   policy `term t1 then next-hop self accept;`      strict ACCEPT, lenient differed from braced
//	H10  inet6 `from next-header tcp source-address …;`   strict ACCEPT, lenient compiled a match-all
//	M5   snmp `community public clients … authorization …` strict refused, lenient garbage clients
//	M6   `unit 0 vlan-id 10 inner-vlan-id 20;`            strict refused (unknown modifier), lenient dropped the tag
//
// Two cells pin what was deliberately NOT changed, each for a measured reason:
//   - the firewall `from` container does not opt into packedStatements, so the
//     #9027 refusal of `from { protocol tcp protocol udp; }` still holds;
//   - `term from` is not admitted, so a policy-statement `term t1 from protocol
//     ospf then accept;` that compiles correctly today still commits.
func TestPackedFoldMembersMeetTheBracedCommitGate9620(t *testing.T) {
	fw := func(family, term string) string {
		return `firewall { family ` + family + ` { filter f1 { ` + term + ` } } }`
	}
	pol := func(term string) string { return `policy-options { policy-statement P { ` + term + ` } }` }
	cells := []struct {
		name, elided, braced string
		// mode: "commit" both commit; "elided-refused" only the elided spelling
		// is refused; "both-refused" both are refused.
		mode    string
		refusal string // substring the refusal must name
		// lenientEqual requires the lenient compiles to be identical.
		lenientEqual bool
		// lenientHas are substrings the braced AND elided lenient JSON must contain.
		lenientHas []string
	}{
		{
			name:         "H9 firewall then count discard",
			elided:       fw("inet", `term t1 then count C1 discard;`),
			braced:       fw("inet", `term t1 { then { count C1; discard; } }`),
			mode:         "commit",
			lenientEqual: true,
			lenientHas:   []string{`"Action":"discard"`, `"Count":"C1"`},
		},
		{
			name:         "H9 firewall then discard count",
			elided:       fw("inet", `term t1 then discard count C1;`),
			braced:       fw("inet", `term t1 { then { discard; count C1; } }`),
			mode:         "commit",
			lenientEqual: true,
			lenientHas:   []string{`"Action":"discard"`, `"Count":"C1"`},
		},
		{
			name:         "H9 policy then next-hop self accept",
			elided:       pol(`term t1 then next-hop self accept;`),
			braced:       pol(`term t1 { then { next-hop self; accept; } }`),
			mode:         "elided-refused",
			refusal:      "next-hop",
			lenientEqual: true,
		},
		{
			name:    "H10 inet6 from next-header then source-address",
			elided:  fw("inet6", `term t1 { from next-header tcp source-address 2001:db8::/32; then accept; }`),
			braced:  fw("inet6", `term t1 { from { next-header tcp; source-address 2001:db8::/32; } then accept; }`),
			mode:    "elided-refused",
			refusal: "source-address",
		},
		{
			name:         "M5 snmp community clients then authorization",
			elided:       `snmp { community public clients 10.0.0.0/8 authorization read-only; }`,
			braced:       `snmp { community public { clients 10.0.0.0/8; authorization read-only; } }`,
			mode:         "commit",
			lenientEqual: true,
			lenientHas:   []string{`"Prefix":"10.0.0.0/8"`, `"Authorization":"read-only"`},
		},
		{
			name:         "M5 snmp community authorization then clients",
			elided:       `snmp { community public authorization read-only clients 10.0.0.0/8; }`,
			braced:       `snmp { community public { authorization read-only; clients 10.0.0.0/8; } }`,
			mode:         "commit",
			lenientEqual: true,
			lenientHas:   []string{`"Prefix":"10.0.0.0/8"`, `"Authorization":"read-only"`},
		},
		{
			name:         "M6 unit vlan-id then inner-vlan-id",
			elided:       `interfaces { ge-0/0/0 { flexible-vlan-tagging; unit 0 vlan-id 10 inner-vlan-id 20; } }`,
			braced:       `interfaces { ge-0/0/0 { flexible-vlan-tagging; unit 0 { vlan-id 10; inner-vlan-id 20; } } }`,
			mode:         "both-refused",
			refusal:      "QinQ",
			lenientEqual: true,
			lenientHas:   []string{`"VlanID":10`, `"InnerVlanID":20`},
		},
		{
			// Only this order exercises the `unit inner-vlan-id` admission: with
			// vlan-id first, the run folds through the existing `unit vlan-id` pair.
			name:         "M6 unit inner-vlan-id then vlan-id",
			elided:       `interfaces { ge-0/0/0 { flexible-vlan-tagging; unit 0 inner-vlan-id 20 vlan-id 10; } }`,
			braced:       `interfaces { ge-0/0/0 { flexible-vlan-tagging; unit 0 { inner-vlan-id 20; vlan-id 10; } } }`,
			mode:         "both-refused",
			refusal:      "QinQ",
			lenientEqual: true,
			lenientHas:   []string{`"VlanID":10`, `"InnerVlanID":20`},
		},
		{
			name:    "control: #9027 still refuses a repeated from keyword",
			elided:  fw("inet", `term t1 { from { protocol tcp protocol udp; } then { discard; } }`),
			braced:  fw("inet", `term t1 { from { protocol tcp; protocol udp; } then { discard; } }`),
			mode:    "elided-refused",
			refusal: "repeats its own keyword",
		},
		{
			name:         "control: a policy term from then accept still commits",
			elided:       pol(`term t1 from protocol ospf then accept;`),
			braced:       pol(`term t1 { from protocol ospf; then accept; }`),
			mode:         "commit",
			lenientEqual: true,
		},
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			_, eerr := CheckText(c.elided, -1)
			_, berr := CheckText(c.braced, -1)
			named := func(err error) bool { return err != nil && strings.Contains(err.Error(), c.refusal) }
			switch c.mode {
			case "commit":
				if berr != nil {
					t.Errorf("CONTROL braced %q: want a commit, got %v", c.braced, berr)
				}
				if eerr != nil {
					t.Errorf("elided %q: want a commit, as the braced spelling gets; got %v (#9620)", c.elided, eerr)
				}
			case "elided-refused":
				if berr != nil {
					t.Errorf("CONTROL braced %q: want a commit, got %v", c.braced, berr)
				}
				if !named(eerr) {
					t.Errorf("elided %q: want a strict refusal naming %q, got %v (#9620)", c.elided, c.refusal, eerr)
				}
			case "both-refused":
				if !named(berr) {
					t.Errorf("CONTROL braced %q: want a refusal naming %q, got %v", c.braced, c.refusal, berr)
				}
				if !named(eerr) {
					t.Errorf("elided %q: want the braced spelling's refusal naming %q, got %v (#9620)", c.elided, c.refusal, eerr)
				}
			default:
				t.Fatalf("unknown mode %q", c.mode)
			}
			if !c.lenientEqual && len(c.lenientHas) == 0 {
				return
			}
			ej := lenientJSON9620(t, "elided", c.elided)
			bj := lenientJSON9620(t, "braced", c.braced)
			if ej == "" || bj == "" {
				return
			}
			for _, want := range c.lenientHas {
				if !strings.Contains(bj, want) {
					t.Errorf("CONTROL braced %q: lenient compile lacks %s", c.braced, want)
				}
				if !strings.Contains(ej, want) {
					t.Errorf("elided %q: lenient compile lacks %s, which the braced spelling carries (#9620)", c.elided, want)
				}
			}
			if c.lenientEqual && ej != bj {
				t.Errorf("elided %q and braced %q compile differently on the lenient path (#9620)", c.elided, c.braced)
			}
		})
	}
}

// lenientJSON9620 compiles text on the lenient path the boot and HA-sync
// loaders use, and renders the result without warnings, whose text differs by
// spelling.
func lenientJSON9620(t *testing.T, label, text string) string {
	t.Helper()
	tree, perrs := config.NewParser(text).Parse()
	if len(perrs) > 0 {
		t.Errorf("%s %q: fixture must parse: %v", label, text, perrs)
		return ""
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Errorf("%s %q: lenient compile: %v", label, text, err)
		return ""
	}
	cfg.Warnings = nil
	b, err := json.Marshal(cfg)
	if err != nil {
		t.Errorf("%s %q: marshal: %v", label, text, err)
		return ""
	}
	return string(b)
}
