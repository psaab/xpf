package config

import (
	"strings"
	"testing"
)

// snmpv3_bare_password_leaf_test.go — #14401.
//
// A bare `authentication-password` / `privacy-password` leaf directly under
// an SNMPv3 `user` (no protocol container) was dropped by both compilers:
// the user registered with empty protocols and was served noAuthNoPriv
// (bare auth password) or authNoPriv (bare privacy password beside a valid
// auth stanza) with nothing said at commit.

func compile14401Braced(t *testing.T, body string) (*Config, error) {
	t.Helper()
	src := `snmp { v3 { usm { local-engine { ` + body + ` } } } }`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	return CompileConfig(tree)
}

func compile14401Flat(t *testing.T, lines ...string) (*Config, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, ln := range lines {
		path, err := ParseSetCommand(ln)
		if err != nil {
			t.Fatalf("parse set %q: %v", ln, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath %q: %v", ln, err)
		}
	}
	return CompileConfig(tree)
}

func compile14401LenientBraced(t *testing.T, body string) (*Config, error) {
	t.Helper()
	src := `snmp { v3 { usm { local-engine { ` + body + ` } } } }`
	p := NewParser(src)
	tree, perr := p.Parse()
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	return CompileConfigLenient(tree)
}

func compile14401LenientFlat(t *testing.T, lines ...string) (*Config, error) {
	t.Helper()
	tree := &ConfigTree{}
	for _, ln := range lines {
		path, err := ParseSetCommand(ln)
		if err != nil {
			t.Fatalf("parse set %q: %v", ln, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath %q: %v", ln, err)
		}
	}
	return CompileConfigLenient(tree)
}

func wantBareReject14401(t *testing.T, err error, user, leaf string) {
	t.Helper()
	if err == nil {
		t.Fatalf("committed clean, want rejection naming bare %s under user %q — the password is dropped and the user is served below the configured level (#14401)", leaf, user)
	}
	msg := err.Error()
	for _, sub := range []string{"bare", leaf, user} {
		if !strings.Contains(msg, sub) {
			t.Errorf("rejected for the wrong reason.\n got: %v\nwant substring: %q", err, sub)
		}
	}
}

func TestSNMPv3BarePasswordLeafRejected14401(t *testing.T) {
	t.Run("flat bare authentication-password", func(t *testing.T) {
		_, err := compile14401Flat(t, `set snmp v3 usm local-engine user alice authentication-password s3cret`)
		wantBareReject14401(t, err, "alice", "authentication-password")
	})
	t.Run("flat bare privacy-password beside valid auth", func(t *testing.T) {
		_, err := compile14401Flat(t, `set snmp v3 usm local-engine user bob authentication-sha256 authentication-password s3cret privacy-password p4ss`)
		wantBareReject14401(t, err, "bob", "privacy-password")
	})
	t.Run("braced bare authentication-password", func(t *testing.T) {
		_, err := compile14401Braced(t, `user alice { authentication-password "s3cret"; }`)
		wantBareReject14401(t, err, "alice", "authentication-password")
	})
	t.Run("braced bare privacy-password beside valid auth", func(t *testing.T) {
		_, err := compile14401Braced(t, `user bob { authentication-sha256 { authentication-password "s3cret"; } privacy-password "p4ss"; }`)
		wantBareReject14401(t, err, "bob", "privacy-password")
	})
	t.Run("packed user line bare authentication-password", func(t *testing.T) {
		_, err := compile14401Braced(t, `user alice authentication-password s3cret;`)
		wantBareReject14401(t, err, "alice", "authentication-password")
	})
	t.Run("packed user line bare privacy-password after auth run", func(t *testing.T) {
		_, err := compile14401Braced(t, `user bob authentication-sha256 authentication-password s3cret privacy-password p4ss;`)
		wantBareReject14401(t, err, "bob", "privacy-password")
	})
	// Group-inherited bare leaf: the gate runs on the expanded tree, so an
	// apply-groups fragment must be caught too.
	t.Run("group-inherited bare authentication-password", func(t *testing.T) {
		src := `groups { g1 { snmp { v3 { usm { local-engine { user alice { authentication-password "s3cret"; } } } } } } }
snmp { v3 { usm { local-engine { user alice { } } } } }
apply-groups g1;`
		p := NewParser(src)
		tree, perr := p.Parse()
		if perr != nil {
			t.Fatalf("parse: %v", perr)
		}
		_, err := CompileConfig(tree)
		wantBareReject14401(t, err, "alice", "authentication-password")
	})
}

func TestSNMPv3BarePasswordControlsStillCompile14401(t *testing.T) {
	// The five nested-container spellings still compile, with credentials.
	nested := []struct {
		name string
		body string
	}{
		{"md5", `user carol { authentication-md5 { authentication-password "s3cret"; } }`},
		{"sha", `user carol { authentication-sha { authentication-password "s3cret"; } }`},
		{"sha256", `user carol { authentication-sha256 { authentication-password "s3cret"; } }`},
		{"des", `user carol { authentication-sha256 { authentication-password "s3cret"; } privacy-des { privacy-password "p4ss"; } }`},
		{"aes128", `user carol { authentication-sha256 { authentication-password "s3cret"; } privacy-aes128 { privacy-password "p4ss"; } }`},
	}
	for _, tc := range nested {
		t.Run("nested "+tc.name, func(t *testing.T) {
			cfg, err := compile14401Braced(t, tc.body)
			if err != nil {
				t.Fatalf("nested-container spelling was REJECTED: %v", err)
			}
			u := cfg.System.SNMP.V3Users["carol"]
			if u == nil || string(u.AuthPassword) == "" {
				t.Fatalf("nested user compiled without auth password: %+v", u)
			}
		})
	}
	t.Run("flat nested containers", func(t *testing.T) {
		cfg, err := compile14401Flat(t,
			`set snmp v3 usm local-engine user carol authentication-sha256 authentication-password s3cret`,
			`set snmp v3 usm local-engine user carol privacy-aes128 privacy-password p4ss`)
		if err != nil {
			t.Fatalf("flat nested spelling was REJECTED: %v", err)
		}
		u := cfg.System.SNMP.V3Users["carol"]
		if u == nil || u.AuthProtocol != "sha256" || u.PrivProtocol != "aes128" || string(u.PrivPassword) == "" {
			t.Fatalf("flat nested user wrong: %+v", u)
		}
	})
	t.Run("packed auth-only run on user line stays authNoPriv", func(t *testing.T) {
		cfg, err := compile14401Braced(t, `user carol authentication-sha256 authentication-password s3cret;`)
		if err != nil {
			t.Fatalf("packed auth-only spelling was REJECTED: %v", err)
		}
		u := cfg.System.SNMP.V3Users["carol"]
		if u == nil || u.AuthProtocol != "sha256" || string(u.AuthPassword) == "" {
			t.Fatalf("packed auth-only user wrong: %+v", u)
		}
	})
	t.Run("packed valid authPriv run via one flat line", func(t *testing.T) {
		cfg, err := compile14401Flat(t,
			`set snmp v3 usm local-engine user carol authentication-sha256 authentication-password s3cret privacy-aes128 privacy-password p4ss`)
		if err != nil {
			t.Fatalf("packed valid spelling was REJECTED: %v", err)
		}
		u := cfg.System.SNMP.V3Users["carol"]
		if u == nil || u.AuthProtocol != "sha256" || u.PrivProtocol != "aes128" || string(u.PrivPassword) == "" {
			t.Fatalf("packed valid user wrong: %+v", u)
		}
	})
	t.Run("deliberate noAuthNoPriv with no password leaves", func(t *testing.T) {
		cfg, err := compile14401Braced(t, `user dave { }`)
		if err != nil {
			t.Fatalf("deliberate noAuthNoPriv user was REJECTED: %v", err)
		}
		if cfg.System.SNMP.V3Users["dave"] == nil {
			t.Fatal("deliberate noAuthNoPriv user missing")
		}
	})
	t.Run("deliberate noAuthNoPriv flat (name only)", func(t *testing.T) {
		// A user with no protocol and no password leaf at all must stay legal;
		// only an authored bare password leaf is refused.
		cfg, err := compile14401Braced(t, `user dave;`)
		if err != nil {
			t.Fatalf("bare user statement was REJECTED: %v", err)
		}
		_ = cfg
	})
}

func TestSNMPv3BarePasswordLenientWarns14401(t *testing.T) {
	assertWarn := func(t *testing.T, cfg *Config, err error, user, leaf string) {
		t.Helper()
		if err != nil {
			t.Fatalf("tolerant path REJECTED a persisted config: %v (#1960)", err)
		}
		var found bool
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "bare") && strings.Contains(w, leaf) && strings.Contains(w, user) {
				found = true
			}
		}
		if !found {
			t.Errorf("tolerant path accepted with no bare-password warning naming %s/%s; warnings: %v", user, leaf, cfg.Warnings)
		}
	}
	t.Run("braced bare auth", func(t *testing.T) {
		cfg, err := compile14401LenientBraced(t, `user alice { authentication-password "s3cret"; }`)
		assertWarn(t, cfg, err, "alice", "authentication-password")
	})
	t.Run("flat bare privacy beside auth", func(t *testing.T) {
		cfg, err := compile14401LenientFlat(t, `set snmp v3 usm local-engine user bob authentication-sha256 authentication-password s3cret privacy-password p4ss`)
		assertWarn(t, cfg, err, "bob", "privacy-password")
	})
	t.Run("lenient nested control has no bare warning", func(t *testing.T) {
		cfg, err := compile14401LenientBraced(t, `user carol { authentication-sha256 { authentication-password "s3cret"; } privacy-aes128 { privacy-password "p4ss"; } }`)
		if err != nil {
			t.Fatalf("lenient nested control rejected: %v", err)
		}
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "bare") && (strings.Contains(w, "authentication-password") || strings.Contains(w, "privacy-password")) {
				t.Errorf("nested control got a bare-password warning: %v", w)
			}
		}
	})
}
