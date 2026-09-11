package configstore

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9620: packed one-line spellings that the #8662 fold either did not reach or
// reached and left on one leaf. Each cell compares the elided spelling with the
// braced one through CheckText, the strict commit gate. Where a cell sets a
// lenient field, it also compares them through the lenient compile the boot and
// HA-sync loaders use.
//
// Measured at 9f520a5b2, before the admission and opt-ins pinned here:
//
//	H10  inet6 `from next-header tcp source-address …;`      strict accepted a match-all term
//	M5   snmp `community public clients … authorization …;`  strict refused, lenient compiled garbage clients
//	M6   `unit 0 vlan-id 10 inner-vlan-id 20;`               strict refused (unknown modifier), lenient dropped the tag
//	U1   `unit 0 description u0 vlan-id 10;`                 strict refused (trailing token), lenient differed
//
// The controls pin spellings that compile correctly at 9f520a5b2. A broader
// change was measured to break each of them:
//   - `term then` and `term from` break policy-statement terms written as
//     `then accept …` or `from … then …`;
//   - `community authorization` breaks authorization-first snmp communities
//     with `restrict` or a client list;
//   - a firewall `from` opt-in breaks the #9027 refusal of a repeated keyword.
func TestPackedFoldMembersMeetTheBracedCommitGate9620(t *testing.T) {
	fw := func(family, term string) string {
		return `firewall { family ` + family + ` { filter f1 { ` + term + ` } } }`
	}
	pol := func(pre, term string) string {
		return `policy-options { ` + pre + ` policy-statement P { ` + term + ` } }`
	}
	ifu := func(unit string) string {
		return `interfaces { ge-0/0/0 { flexible-vlan-tagging; ` + unit + ` } }`
	}
	cells := []struct {
		name, elided, braced string
		// mode: "commit" both commit; "elided-refused" only the elided spelling
		// is refused; "both-refused" both are refused.
		mode    string
		refusal string // substring the refusal must name
		// lenientCompiles requires both lenient compiles to succeed.
		lenientCompiles bool
		// lenientEqual requires the two lenient compiles to be identical.
		lenientEqual bool
		// lenientHas lists substrings that both lenient JSON renderings must contain.
		lenientHas []string
	}{
		{
			name:            "H10 inet6 from next-header then source-address",
			elided:          fw("inet6", `term t1 { from next-header tcp source-address 2001:db8::/32; then accept; }`),
			braced:          fw("inet6", `term t1 { from { next-header tcp; source-address 2001:db8::/32; } then accept; }`),
			mode:            "elided-refused",
			refusal:         "source-address",
			lenientCompiles: true,
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
			name:         "M6 unit vlan-id then inner-vlan-id",
			elided:       ifu(`unit 0 vlan-id 10 inner-vlan-id 20;`),
			braced:       ifu(`unit 0 { vlan-id 10; inner-vlan-id 20; }`),
			mode:         "both-refused",
			refusal:      "QinQ",
			lenientEqual: true,
			lenientHas:   []string{`"VlanID":10`, `"InnerVlanID":20`},
		},
		{
			name:         "U1 unit description then vlan-id",
			elided:       ifu(`unit 0 description u0 vlan-id 10;`),
			braced:       ifu(`unit 0 { description u0; vlan-id 10; }`),
			mode:         "commit",
			lenientEqual: true,
			lenientHas:   []string{`"Description":"u0"`, `"VlanID":10`},
		},
		{
			name:         "control: snmp authorization then clients",
			elided:       `snmp { community public authorization read-only clients 10.0.0.0/8; }`,
			braced:       `snmp { community public { authorization read-only; clients 10.0.0.0/8; } }`,
			mode:         "commit",
			lenientEqual: true,
			lenientHas:   []string{`"Prefix":"10.0.0.0/8"`, `"Authorization":"read-only"`},
		},
		{
			name:         "control: snmp authorization then clients restrict",
			elided:       `snmp { community public authorization read-only clients 10.0.0.0/8 restrict; }`,
			braced:       `snmp { community public { authorization read-only; clients 10.0.0.0/8 restrict; } }`,
			mode:         "commit",
			lenientEqual: true,
		},
		{
			name:         "control: snmp authorization then a clients list",
			elided:       `snmp { community public authorization read-only clients [ 10.0.0.0/8 192.0.2.0/24 ]; }`,
			braced:       `snmp { community public { authorization read-only; clients [ 10.0.0.0/8 192.0.2.0/24 ]; } }`,
			mode:         "commit",
			lenientEqual: true,
		},
		{
			name:         "control: policy then accept load-balance local-preference",
			elided:       pol("", `term t1 then accept load-balance per-packet local-preference 200;`),
			braced:       pol("", `term t1 { then { accept; load-balance per-packet; local-preference 200; } }`),
			mode:         "commit",
			lenientEqual: true,
		},
		{
			name:         "control: policy then accept community add",
			elided:       pol(`community C members 65000:1;`, `term t1 then accept community add C;`),
			braced:       pol(`community C members 65000:1;`, `term t1 { then { accept; community add C; } }`),
			mode:         "commit",
			lenientEqual: true,
		},
		{
			name:         "control: policy term from then accept",
			elided:       pol("", `term t1 from protocol ospf then accept;`),
			braced:       pol("", `term t1 { from protocol ospf; then accept; }`),
			mode:         "commit",
			lenientEqual: true,
		},
		{
			name:    "control: #9027 still refuses a repeated from keyword",
			elided:  fw("inet", `term t1 { from { protocol tcp protocol udp; } then { discard; } }`),
			braced:  fw("inet", `term t1 { from { protocol tcp; protocol udp; } then { discard; } }`),
			mode:    "elided-refused",
			refusal: "repeats its own keyword",
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
			if !c.lenientCompiles && !c.lenientEqual && len(c.lenientHas) == 0 {
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

// lenientJSON9620 compiles text on the lenient path used by the boot and HA-sync
// loaders. It renders the result without warnings, because warning text differs
// between the two spellings.
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
