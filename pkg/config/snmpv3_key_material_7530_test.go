package config

import (
	"strings"
	"testing"
)

// snmpv3_key_material_7530_test.go — #7530.
//
// An SNMPv3 user naming an auth or privacy PROTOCOL without the corresponding
// key material committed clean and then served BELOW the configured level.
//
// pkg/snmp/v3.go derives the per-user floor from KEY PRESENCE:
//
//	if user.authKey != nil && msgFlags&msgFlagAuth == 0 { drop }
//	if user.privKey != nil && msgFlags&msgFlagPriv == 0 { drop }
//
// and authKey is derived only when the password is non-empty. So a user naming
// `authentication-sha256` with no password has authKey == nil, no floor
// applies, and a noAuthNoPriv request naming that user is answered
// unauthenticated and in plaintext.
//
// That floor is CORRECT — it is the #4897 bypass gate and must stay keyed on
// what the agent can actually verify. The defect is upstream, so the fix is
// upstream: reject the configuration that produced a protocol with nothing
// behind it, rather than degrading at serve time.

func compileSNMP7530(t *testing.T, body string) (*Config, error) {
	t.Helper()
	src := `snmp { v3 { usm { local-engine { ` + body + ` } } } }`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	return CompileConfig(tree)
}

// THE DEFECT, auth half: a protocol with no password serves noAuthNoPriv.
func TestAuthProtocolWithoutPasswordIsRejected7530(t *testing.T) {
	_, err := compileSNMP7530(t, `user ops { authentication-sha256; }`)
	if err == nil {
		t.Fatal("a user naming authentication-sha256 with NO authentication-password " +
			"committed clean. The agent derives its floor from the key, so this user has " +
			"none: a noAuthNoPriv request naming `ops` is answered unauthenticated and in " +
			"plaintext — the exact level the configuration was written to prevent (#7530)")
	}
	for _, want := range []string{"ops", "sha256", "authentication-password", "unauthenticated"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the rejection does not mention %q: %v", want, err)
		}
	}
}

// THE DEFECT, privacy half: authPriv silently degraded to authNoPriv.
func TestPrivProtocolWithoutPasswordIsRejected7530(t *testing.T) {
	_, err := compileSNMP7530(t,
		`user ops { authentication-sha256 { authentication-password "s3cretpass"; } privacy-aes128; }`)
	if err == nil {
		t.Fatal("a user naming privacy-aes128 with NO privacy-password committed clean. " +
			"With no privacy key there is no privacy floor, so an authNoPriv request is " +
			"answered with an UNENCRYPTED scopedPDU while the configuration says authPriv " +
			"(#7530)")
	}
	for _, want := range []string{"ops", "aes128", "privacy-password", "UNENCRYPTED"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the rejection does not mention %q: %v", want, err)
		}
	}
}

// CONTROL 1 — a COMPLETE auth-only user is legitimate authNoPriv and must
// still commit. Without this, a gate that demanded privacy of everyone would
// satisfy both cells above and break every authNoPriv deployment.
func TestCompleteAuthOnlyUserStillCommits7530(t *testing.T) {
	cfg, err := compileSNMP7530(t,
		`user ops { authentication-sha256 { authentication-password "s3cretpass"; } }`)
	if err != nil {
		t.Fatalf("an auth-only user with its password is legitimate authNoPriv and must "+
			"commit: %v", err)
	}
	u := cfg.System.SNMP.V3Users["ops"]
	if u == nil || u.AuthProtocol != "sha256" || u.AuthPassword.Reveal() == "" {
		t.Fatalf("the control user did not compile with its credential: %+v", u)
	}
	if u.PrivProtocol != "" {
		t.Errorf("the control user acquired a privacy protocol it did not configure: %q",
			u.PrivProtocol)
	}
}

// CONTROL 2 — a COMPLETE authPriv user must still commit.
func TestCompleteAuthPrivUserStillCommits7530(t *testing.T) {
	_, err := compileSNMP7530(t,
		`user ops { authentication-sha256 { authentication-password "s3cretpass"; } privacy-aes128 { privacy-password "p4ssw0rd"; } }`)
	if err != nil {
		t.Fatalf("a complete authPriv user must commit: %v", err)
	}
}

// CONTROL 3 — a user with NO protocols at all is a genuine noAuthNoPriv user
// and must still commit. The gate fires on a NAMED protocol missing its own
// material, never on an absent protocol.
func TestNoAuthNoPrivUserStillCommits7530(t *testing.T) {
	if _, err := compileSNMP7530(t, `user ops;`); err != nil {
		t.Fatalf("a user configuring no protocols is genuinely noAuthNoPriv and must "+
			"commit — rejecting it would make the level unconfigurable: %v", err)
	}
}

// The tolerant ingress must WARN, not brick: such a config served at the lower
// level before this gate and still does, so refusing to boot costs availability
// with no gain in security (#1960).
func TestPartialCredentialIsLenientOnTheTolerantPath7530(t *testing.T) {
	src := `snmp { v3 { usm { local-engine { user ops { authentication-sha256; } } } } }`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("the tolerant path must not brick: %v", err)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "snmpv3 key material") {
			found = true
		}
	}
	if !found {
		t.Errorf("the tolerant path accepted the partial credential and said NOTHING. "+
			"Downgrading to a warning is the no-brick contract; downgrading to silence "+
			"leaves an agent serving below its configured level with no signal. "+
			"warnings=%v", cfg.Warnings)
	}
}
