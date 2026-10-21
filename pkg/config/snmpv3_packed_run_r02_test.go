package config

import (
	"strings"
	"testing"
)

// R-02 (found validating the vSRX-parity report, on top of #9155): an SNMPv3
// user configured authPriv on ONE `set` line committed clean as authNoPriv.
//
// `SetPath` builds a flat-set line as a NESTED CHAIN, so the privacy stanza
// landed as a GRANDCHILD of the authentication-password node:
//
//	[user alice] > [authentication-sha256] > [authentication-password A]
//	                                          > [privacy-aes128 privacy-password P]
//
// `compileSNMPv3Users` iterates the user's own children and never reached it.
//
// IT EVADED BOTH #9155 COMMIT GATES, structurally: they read the COMPILED
// config and key on a protocol being NAMED, so "privacy protocol with no
// password" and "privacy without authentication" are both false when the
// privacy protocol was DISCARDED before the gate ran. A gate downstream of a
// dropping compiler is blind to precisely what it drops.
func compileOneLine9155R02(t *testing.T, line string) *Config {
	t.Helper()
	tree := &ConfigTree{}
	path, err := ParseSetCommand(line)
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	cfg, cerr := CompileConfig(tree)
	if cerr != nil {
		t.Fatalf("committed with an error: %v", cerr)
	}
	return cfg
}

func TestOneLineAuthPrivKeepsBothCredentials9155R02(t *testing.T) {
	cfg := compileOneLine9155R02(t,
		`set snmp v3 usm local-engine user alice authentication-sha256 `+
			`authentication-password Auth12345 privacy-aes128 privacy-password Priv12345`)
	u := cfg.System.SNMP.V3Users["alice"]
	if u == nil {
		t.Fatal("user alice did not compile at all")
	}
	if u.AuthProtocol != "sha256" || u.AuthPassword.Reveal() == "" {
		t.Errorf("auth half lost: proto=%q pw_len=%d", u.AuthProtocol, len(u.AuthPassword.Reveal()))
	}
	if u.PrivProtocol != "aes128" {
		t.Fatalf("PRIVACY SILENTLY DROPPED: privProto=%q — the operator configured "+
			"authPriv on one line, the commit succeeded, and the agent serves "+
			"authNoPriv. Both #9155 gates are blind to this because the protocol "+
			"they key on was discarded before they ran", u.PrivProtocol)
	}
	if u.PrivPassword.Reveal() == "" {
		t.Error("privacy protocol survived but its password did not; the derived " +
			"privacy key would be nil and the #9155 runtime floor would refuse the user")
	}
}

// REFERENCE ARM: the braced spelling must still compile identically. Without
// it, the assertion above is satisfied by a change that fixes the flat-set path
// and breaks the canonical one.
func TestBracedAuthPrivStillCompiles9155R02(t *testing.T) {
	src := `snmp { v3 { usm { local-engine { user alice {
		authentication-sha256 { authentication-password "Auth12345"; }
		privacy-aes128 { privacy-password "Priv12345"; }
	} } } } }`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("the braced spelling was rejected: %v", err)
	}
	u := cfg.System.SNMP.V3Users["alice"]
	if u == nil || u.AuthProtocol != "sha256" || u.PrivProtocol != "aes128" {
		t.Fatalf("braced spelling no longer yields authPriv: %+v", u)
	}
}

// NARROWNESS: a one-line AUTH-ONLY user must stay authNoPriv. The hoist must
// lift a genuinely-authored privacy stanza, not invent one.
func TestOneLineAuthOnlyStaysAuthNoPriv9155R02(t *testing.T) {
	cfg := compileOneLine9155R02(t,
		`set snmp v3 usm local-engine user bob authentication-sha256 authentication-password Auth12345`)
	u := cfg.System.SNMP.V3Users["bob"]
	if u == nil {
		t.Fatal("user bob did not compile")
	}
	if u.PrivProtocol != "" || u.PrivPassword.Reveal() != "" {
		t.Errorf("a privacy configuration appeared from nowhere: proto=%q pw_len=%d",
			u.PrivProtocol, len(u.PrivPassword.Reveal()))
	}
}

// The #9155 gates must now SEE the one-line form. Before the hoist they could
// not: a privacy protocol named on one line with no password was discarded, so
// the "protocol named but no key material" gate had nothing to fire on and the
// user committed as a silent authNoPriv.
func TestOneLineGatesNowSeeThePrivacyHalf9155R02(t *testing.T) {
	tree := &ConfigTree{}
	path, err := ParseSetCommand(
		`set snmp v3 usm local-engine user eve authentication-sha256 ` +
			`authentication-password Auth12345 privacy-aes128`)
	if err != nil {
		t.Fatalf("ParseSetCommand: %v", err)
	}
	if err := tree.SetPath(path); err != nil {
		t.Fatalf("SetPath: %v", err)
	}
	_, cerr := CompileConfig(tree)
	if cerr == nil {
		t.Fatal("a privacy protocol with NO privacy-password committed clean on the " +
			"one-line spelling; #9155's gate is reachable only if the compiler " +
			"preserves the protocol it keys on")
	}
	if !strings.Contains(cerr.Error(), "privacy") {
		t.Errorf("rejected for the wrong reason: %v", cerr)
	}
}
