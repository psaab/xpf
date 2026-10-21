package config

import (
	"strings"
	"testing"
)

// snmpv3_passphrase_floor_16084_test.go — #16084.
//
// The #7530 gate is presence-only: a 1-character SNMPv3 passphrase compiles
// and is then served by an agent that answers authentication challenges
// online with no per-user lockout or backoff, so the credential is recovered
// after a handful of guesses. RFC 3414 section 11.2 recommends pass phrases
// of at least 8 characters. The strict compile must reject shorter
// passphrases; the tolerant path warns and still boots (#1960).

func compileSNMP16084(t *testing.T, body string) (*Config, error) {
	t.Helper()
	src := `snmp { v3 { usm { local-engine { ` + body + ` } } } }`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	return CompileConfig(tree)
}

func compileSNMP16084Lenient(t *testing.T, body string) (*Config, error) {
	t.Helper()
	src := `snmp { v3 { usm { local-engine { ` + body + ` } } } }`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	return CompileConfigLenient(tree)
}

// THE DEFECT (issue's decisive check): a 1-character auth passphrase compiles
// pre-fix and must be rejected by the floor.
func TestOneCharAuthPassphraseIsRejected16084(t *testing.T) {
	_, err := compileSNMP16084(t,
		`user ops { authentication-sha256 { authentication-password "x"; } }`)
	if err == nil {
		t.Fatal("a 1-character authentication-password committed clean. The agent " +
			"answers SNMPv3 HMAC challenges online with no per-user lockout, so this " +
			"credential is recovered after a handful of guesses (#16084)")
	}
	for _, want := range []string{"ops", "authentication-password", "too short", "minimum 8"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the rejection does not mention %q: %v", want, err)
		}
	}
	if strings.Contains(err.Error(), `"x"`) {
		t.Errorf("the rejection leaks the passphrase itself: %v", err)
	}
}

// The privacy passphrase is a credential of the same class and gets the
// same floor.
func TestOneCharPrivPassphraseIsRejected16084(t *testing.T) {
	_, err := compileSNMP16084(t,
		`user ops { authentication-sha256 { authentication-password "longenough"; } privacy-aes128 { privacy-password "p"; } }`)
	if err == nil {
		t.Fatal("a 1-character privacy-password committed clean (#16084)")
	}
	for _, want := range []string{"ops", "privacy-password", "too short", "minimum 8"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the rejection does not mention %q: %v", want, err)
		}
	}
}

// BOUNDARY: 7 characters is below the floor, 8 is at it.
func TestPassphraseFloorBoundary16084(t *testing.T) {
	if _, err := compileSNMP16084(t,
		`user ops { authentication-sha256 { authentication-password "1234567"; } }`); err == nil {
		t.Error("a 7-character authentication-password committed clean; the floor is 8 (#16084)")
	}
	cfg, err := compileSNMP16084(t,
		`user ops { authentication-sha256 { authentication-password "12345678"; } privacy-aes128 { privacy-password "87654321"; } }`)
	if err != nil {
		t.Fatalf("passphrases of exactly 8 characters must commit: %v", err)
	}
	if u := cfg.System.SNMP.V3Users["ops"]; u == nil || string(u.AuthPassword) != "12345678" {
		t.Fatalf("the boundary user did not compile with its credential: %+v", u)
	}
}

// The floor is counted in runes: a passphrase of 7 multibyte characters is
// 14+ bytes but still only 7 characters an operator typed.
func TestPassphraseFloorCountsRunes16084(t *testing.T) {
	if _, err := compileSNMP16084(t,
		`user ops { authentication-sha256 { authentication-password "ééééééé"; } }`); err == nil {
		t.Error("a 7-rune (14-byte) authentication-password committed clean; " +
			"the floor must count characters, not UTF-8 bytes (#16084)")
	}
	if _, err := compileSNMP16084(t,
		`user ops { authentication-sha256 { authentication-password "éééééééé"; } }`); err != nil {
		t.Fatalf("an 8-rune authentication-password must commit: %v", err)
	}
}

// A passphrase carried WITHOUT a named protocol (orphan material on a
// noAuthNoPriv user) is likewise a configured credential and is floored.
func TestShortOrphanPassphraseIsRejected16084(t *testing.T) {
	if _, err := compileSNMP16084(t,
		`user ops { authentication-password "x"; }`); err == nil {
		// The bare-leaf gate (#14401) may reject this shape first; either
		// rejection satisfies the floor. Only a clean commit fails.
		t.Fatal("a 1-character orphan authentication-password committed clean (#16084)")
	}
}

// The tolerant ingress must WARN, not brick (#1960): an already-persisted
// config with a short passphrase still boots, with the floor named.
func TestShortPassphraseIsLenientOnTheTolerantPath16084(t *testing.T) {
	cfg, err := compileSNMP16084Lenient(t,
		`user ops { authentication-sha256 { authentication-password "x"; } }`)
	if err != nil {
		t.Fatalf("the tolerant path must not brick: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "snmpv3 key material") && strings.Contains(w, "too short") {
			found = true
		}
	}
	if !found {
		t.Errorf("the tolerant path accepted a 1-character passphrase and said "+
			"NOTHING about the floor. warnings=%v", cfg.Warnings)
	}
}
