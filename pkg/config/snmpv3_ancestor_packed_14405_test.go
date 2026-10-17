package config

import (
	"strings"
	"testing"
)

// snmpv3_ancestor_packed_14405_test.go — #14405 (DR12-H1).
//
// The #9155 gate walked a fixed direct-child chain
// snmp -> v3 -> usm -> local-engine -> user and inspected only a user's
// own Keys tail plus its direct children's Keys. The compiler expands
// packed ancestors with packedBodyChildren and hoists descendant
// flat-chain statements with hoistAndSplitRun8939, so three spellings
// compiled the user while dropping the unknown protocol keyword the
// gate exists to reject:
//
//  1. ancestor-packed `v3 usm { ... }`
//  2. ancestor-packed `usm local-engine { ... }`
//  3. descendant flat-chain protocol keyword nested under the user's
//     first stanza (ordinary `set` form: privacy-* is a grandchild)
//
// Each evasion must strict-reject naming the unknown keyword; the
// fully nested control must still reject; a set form with known auth
// + known privacy must still commit.

func compile14405(t *testing.T, src string) error {
	t.Helper()
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	_, err := CompileConfig(tree)
	return err
}

func TestSNMPv3AncestorPackedEvasions14405(t *testing.T) {
	for _, tc := range []struct {
		name       string
		src        string
		wantReject string
	}{
		{
			name:       "evasion 1: ancestor-packed v3 usm, unknown auth",
			src:        `snmp { v3 usm { local-engine { user alice { authentication-sha512 { authentication-password "s3cretpass"; } } } } }`,
			wantReject: "authentication-sha512",
		},
		{
			name:       "evasion 2: ancestor-packed usm local-engine, unknown auth",
			src:        `snmp { v3 { usm local-engine { user alice { authentication-sha512 { authentication-password "s3cretpass"; } } } } }`,
			wantReject: "authentication-sha512",
		},
		{
			name:       "evasion 1b: ancestor-packed v3 usm, unknown privacy",
			src:        `snmp { v3 usm { local-engine { user alice { authentication-sha256 { authentication-password "s3cretpass"; } privacy-foo { privacy-password "p4ssphrase"; } } } } }`,
			wantReject: "privacy-foo",
		},
		{
			name:       "control A: fully nested unknown auth still rejects",
			src:        `snmp { v3 { usm { local-engine { user alice { authentication-sha512 { authentication-password "s3cretpass"; } } } } } }`,
			wantReject: "authentication-sha512",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := compile14405(t, tc.src)
			if err == nil {
				t.Fatalf("committed clean, want strict rejection naming %q — the unknown protocol is dropped and the user is served below its configured level", tc.wantReject)
			}
			if !strings.Contains(err.Error(), tc.wantReject) {
				t.Errorf("rejected for wrong reason, want naming %q: %v", tc.wantReject, err)
			}
			if !strings.Contains(err.Error(), "unknown") {
				t.Errorf("rejection must be the #9155 unknown-protocol error: %v", err)
			}
		})
	}
}

func TestSNMPv3DescendantFlatChainEvasions14405(t *testing.T) {
	// Evasion 3: unknown privacy keyword is a grandchild of the user.
	err := compile9155Flat(t,
		`set snmp v3 usm local-engine user alice authentication-sha256 authentication-password A14405pass privacy-foo privacy-password P14405pass`)
	if err == nil {
		t.Fatal("evasion 3 committed clean, want strict rejection naming privacy-foo")
	}
	if !strings.Contains(err.Error(), "privacy-foo") || !strings.Contains(err.Error(), "unknown privacy protocol") {
		t.Errorf("evasion 3 rejected for wrong reason: %v", err)
	}

	// Variant 3b: unknown AUTH protocol in the descendant position.
	// The chain after a known privacy stanza nests an unknown auth
	// keyword under the privacy node; gate must still see it.
	err = compile9155Flat(t,
		`set snmp v3 usm local-engine user alice privacy-aes128 privacy-password P14405pass authentication-sha512 authentication-password A14405pass`)
	// This spelling is also Hole B (priv without auth in compiled form
	// if sha512 dropped) — either the unknown-auth rejection or the
	// no-auth rejection proves the gate saw past the first child; the
	// unknown keyword naming is the #14405 criterion.
	if err == nil {
		t.Fatal("variant 3b committed clean, want strict rejection")
	}
	if !strings.Contains(err.Error(), "authentication-sha512") {
		t.Errorf("variant 3b must name authentication-sha512, got: %v", err)
	}

	// Control B: set form with KNOWN auth + KNOWN privacy must commit.
	if err := compile9155Flat(t,
		`set snmp v3 usm local-engine user alice authentication-sha256 authentication-password A14405pass privacy-aes128 privacy-password P14405pass`); err != nil {
		t.Errorf("control B (known auth + known privacy, flat set) was rejected: %v", err)
	}

	// Control B2: ancestor-packed with KNOWN protocols must commit.
	if err := compile14405(t,
		`snmp { v3 usm { local-engine { user alice { authentication-sha256 { authentication-password "s3cretpass"; } privacy-aes128 { privacy-password "p4ssphrase"; } } } } }`); err != nil {
		t.Errorf("control B2 (ancestor-packed, known protocols) was rejected: %v", err)
	}
	if err := compile14405(t,
		`snmp { v3 { usm local-engine { user alice { authentication-sha256 { authentication-password "s3cretpass"; } privacy-aes128 { privacy-password "p4ssphrase"; } } } } }`); err != nil {
		t.Errorf("control B3 (usm-packed, known protocols) was rejected: %v", err)
	}
}

func TestSNMPv3AncestorPackedLenientWarns14405(t *testing.T) {
	src := `snmp { v3 usm { local-engine { user alice { authentication-sha512 { authentication-password "s3cretpass"; } } } } }`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient path rejected ancestor-packed evasion (must warn, #1960): %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "snmpv3 security keyword") && strings.Contains(w, "authentication-sha512") {
			found = true
		}
	}
	if !found {
		t.Errorf("lenient path must warn naming authentication-sha512, warnings: %v", cfg.Warnings)
	}
}
