package config

import (
	"strings"
	"testing"
)

// TestValidateCryptHash covers the crypt(3)-hash recognizer shared by
// root-authentication and per-user authentication (#1944 §5.5). The
// central guarantee is that plaintext is ABSOLUTELY rejected (legacy DES
// is intentionally not accepted) while deliberate lock sentinels pass.
func TestValidateCryptHash(t *testing.T) {
	const (
		sha512Hash       = "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"
		sha512HighRounds = "$6$rounds=656000$saltsalt$QBvWkidMIWbOshfFz5Mwxc3KCIWWyeVUXV3GSTG3LiicgXdKzNJUczsbxHkDB0EchggCeEhT9bfZcK07sAE5g."
		yescryptHash     = "$y$j9T$saltsaltsaltsalt$Uxvkjnhdr/2B6SINV1mXACdXVbd5kc899ms5aqhxMQD"
		gostYescryptHash = "$gy$j9T$saltsaltsaltsalt$rJwUc/Ira7bf5YaD7oIyqgudtsbNclaiv18Jg66v.j."
		bcryptHash       = "$2b$12$saltsaltsaltsaltsaltsOEpXE0KLxzyVeEtX6R7qbkVGuSGecz6W"
		scryptHash       = "$7$CU..../....wzCyKANN4/9UTyVyuWoQu1$lVUfDsI1kxYFAl5pqAlZ6cS/yB.G.1.M7XEebqH2T41"
	)
	accept := []string{
		sha512Hash,
		sha512HighRounds,
		yescryptHash,     // yescrypt at its default cost (5)
		gostYescryptHash, // gost-yescrypt at its default cost (5)
		bcryptHash,
		strings.Replace(bcryptHash, "$2b$", "$2a$", 1),
		strings.Replace(bcryptHash, "$2b$", "$2y$", 1),
		scryptHash,
		"!" + sha512Hash,  // locked-but-restorable
		"!!" + sha512Hash, // locked-but-restorable (double bang)
		"*",               // bare lock sentinel
		"!",               // bare lock sentinel
		"!!",              // bare lock sentinel
	}
	for _, in := range accept {
		if err := ValidateCryptHash(in, nil); err != nil {
			t.Errorf("ValidateCryptHash(%q) = %v, want accept", in, err)
		}
	}

	reject := []string{
		"plaintext",                          // the real footgun
		"password12345",                      // 13 alnum — DES-looking plaintext
		"",                                   // empty
		"$99$bogus$x",                        // unknown id
		"$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/", // weak md5crypt
		"$5$rounds=5000$saltsalt$gOjOtoMpVhru2uyjeJSEc/JaLQWOXMNmlOnj6T4AtC.", // weak sha256crypt
		"$6$a$b",                                 // structurally impossible
		"$6$saltsalt$",                           // empty checksum
		"$6$$hash",                               // empty salt
		"$6$salt123$" + strings.Repeat("a", 86),  // salt below floor
		"$6$saltsalt$" + strings.Repeat("a", 85), // truncated checksum
		"$6$saltsalt$" + strings.Repeat("a", 87), // overlong checksum
		"$6$rounds=1000$saltsalt$" + strings.Repeat("a", 86),  // too few rounds
		"$6$rounds=05000$saltsalt$" + strings.Repeat("a", 86), // non-canonical rounds
		"$6$rounds=656000$saltsalt$" + strings.Repeat("a", 86) + "$extra",
		"$6$saltsalt$ab:cd",  // colon corrupts chpasswd stdin
		"$6$saltsalt$ab cd",  // space
		"$6$saltsalt$ab\tcd", // control character
		"$6salt$hash",        // missing $ after id
		"$6$saltsalt$$hash",  // empty intermediate field
		"$6$$$hash",          // empty salt and parameter
		"$y$j8T$saltsaltsaltsalt$Uxvkjnhdr/2B6SINV1mXACdXVbd5kc899ms5aqhxMQD", // cost 4
		"$y$j9T$salt$Uxvkjnhdr/2B6SINV1mXACdXVbd5kc899ms5aqhxMQD",             // short salt
		"$y$j9T$saltsaltsaltsalt$" + strings.Repeat("a", 42),                  // truncated checksum
		"$2b$09$saltsaltsaltsaltsaltsOEpXE0KLxzyVeEtX6R7qbkVGuSGecz6W",        // low cost
		"$2b$12$saltsaltsalt", // truncated bcrypt payload
	}
	for _, in := range reject {
		if err := ValidateCryptHash(in, nil); err == nil {
			t.Errorf("ValidateCryptHash(%q) = nil, want reject", in)
		}
	}
}

// TestParseLoginUserEncryptedPasswordHierarchical exercises the
// hierarchical AST shape (#1944 §7.1).
func TestParseLoginUserEncryptedPasswordHierarchical(t *testing.T) {
	input := `system {
    login {
        user op {
            class operator;
            authentication {
                encrypted-password "$6$salt$hash";
                ssh-ed25519 "ssh-ed25519 AAAA op@host";
            }
        }
    }
}`
	parser := NewParser(input)
	tree, errs := parser.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}
	if cfg.System.Login == nil || len(cfg.System.Login.Users) != 1 {
		t.Fatalf("expected 1 user, got %+v", cfg.System.Login)
	}
	u := cfg.System.Login.Users[0]
	if u.EncryptedPassword != "$6$salt$hash" {
		t.Errorf("EncryptedPassword = %q, want %q", u.EncryptedPassword, "$6$salt$hash")
	}
	if len(u.SSHKeys) != 1 || u.SSHKeys[0] != "ssh-ed25519 AAAA op@host" {
		t.Errorf("SSHKeys = %v", u.SSHKeys)
	}
}

// TestParseLoginUserEncryptedPasswordFlatSet exercises the flat-set AST
// shape and asserts it compiles to the same struct as the hierarchical
// shape (Codex M-3, dual-AST pin). Uses ParseSetCommand + SetPath, never
// NewParser, per the project's set-syntax testing rule.
func TestParseLoginUserEncryptedPasswordFlatSet(t *testing.T) {
	cmds := []string{
		"set system login user op class operator",
		`set system login user op authentication encrypted-password "$6$salt$hash"`,
		`set system login user op authentication ssh-ed25519 "ssh-ed25519 AAAA op@host"`,
	}
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	if cfg.System.Login == nil || len(cfg.System.Login.Users) != 1 {
		t.Fatalf("expected 1 user, got %+v", cfg.System.Login)
	}
	u := cfg.System.Login.Users[0]
	if u.Name != "op" || u.Class != "operator" {
		t.Errorf("user = %q/%q", u.Name, u.Class)
	}
	if u.EncryptedPassword != "$6$salt$hash" {
		t.Errorf("flat-set EncryptedPassword = %q, want %q", u.EncryptedPassword, "$6$salt$hash")
	}
	if len(u.SSHKeys) != 1 || u.SSHKeys[0] != "ssh-ed25519 AAAA op@host" {
		t.Errorf("SSHKeys = %v", u.SSHKeys)
	}
}

// TestLoginUserEncryptedPasswordSchemaGate proves the typed-leaf gate
// hard-rejects plaintext and weak or structurally incomplete hashes for both
// root and per-user authentication while accepting strong hashes and the root
// lock sentinel (#1944 §5.6 / #10830).
func TestLoginUserEncryptedPasswordSchemaGate(t *testing.T) {
	mustTree := func(t *testing.T, cmds ...string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		for _, cmd := range cmds {
			path, err := ParseSetCommand(cmd)
			if err != nil {
				t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
			}
			if err := tree.SetPath(path); err != nil {
				t.Fatalf("SetPath(%q): %v", cmd, err)
			}
		}
		return tree
	}

	for _, value := range []string{
		"letmein",
		"$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/",
		"$6$a$b",
	} {
		tree := mustTree(t, `set system login user op authentication encrypted-password "`+value+`"`)
		if err := SchemaValidate(tree, nil); err == nil {
			t.Errorf("SchemaValidate accepted invalid per-user encrypted-password %q, want reject", value)
		}
		rootTree := mustTree(t, `set system root-authentication encrypted-password "`+value+`"`)
		if err := SchemaValidate(rootTree, nil); err == nil {
			t.Errorf("SchemaValidate accepted invalid root encrypted-password %q, want reject", value)
		}
	}

	// Valid sha512crypt per-user → accept.
	good := mustTree(t, `set system login user op authentication encrypted-password "$6$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/"`)
	if err := SchemaValidate(good, nil); err != nil {
		t.Errorf("SchemaValidate rejected a valid per-user hash: %v", err)
	}

	// Valid yescrypt root → accept.
	rootGood := mustTree(t, `set system root-authentication encrypted-password "$y$j9T$saltsaltsaltsalt$Uxvkjnhdr/2B6SINV1mXACdXVbd5kc899ms5aqhxMQD"`)
	if err := SchemaValidate(rootGood, nil); err != nil {
		t.Errorf("SchemaValidate rejected a valid root yescrypt hash: %v", err)
	}

	// Root-auth lock sentinel "*" → accept (the only way to lock root).
	rootLock := mustTree(t, `set system root-authentication encrypted-password "*"`)
	if err := SchemaValidate(rootLock, nil); err != nil {
		t.Errorf("SchemaValidate rejected root lock sentinel: %v", err)
	}
}

// TestLoginUserNoAuthMethodWarning covers the §5.8 commit warning for a
// user with no usable authentication method (no keys, no usable password).
func TestLoginUserNoAuthMethodWarning(t *testing.T) {
	cases := []struct {
		name     string
		user     *LoginUser
		wantWarn bool
	}{
		{"no auth at all", &LoginUser{Name: "op"}, true},
		{"lock sentinel only", &LoginUser{Name: "op", EncryptedPassword: "!"}, true},
		{"double-bang sentinel only", &LoginUser{Name: "op", EncryptedPassword: "!!"}, true},
		{"star sentinel only", &LoginUser{Name: "op", EncryptedPassword: "*"}, true},
		// locked-but-restorable hash: cannot password-login until
		// unlocked, so it is NOT a usable auth method (Codex r1 Low).
		{"locked-restorable hash no ssh", &LoginUser{Name: "op", EncryptedPassword: "!$6$salt$hash"}, true},
		{"double-bang restorable hash no ssh", &LoginUser{Name: "op", EncryptedPassword: "!!$6$salt$hash"}, true},
		// locked-restorable hash + ssh key: ssh path is usable, no warning.
		{"locked-restorable hash with ssh", &LoginUser{Name: "op", EncryptedPassword: "!$6$salt$hash", SSHKeys: []string{"ssh-ed25519 AAAA"}}, false},
		{"usable password", &LoginUser{Name: "op", EncryptedPassword: "$6$salt$hash"}, false},
		{"ssh key only", &LoginUser{Name: "op", SSHKeys: []string{"ssh-ed25519 AAAA"}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.System.Login = &LoginConfig{Users: []*LoginUser{tc.user}}
			warns := ValidateConfig(cfg)
			found := false
			for _, w := range warns {
				if strings.Contains(w, "no usable authentication method") {
					found = true
				}
			}
			if found != tc.wantWarn {
				t.Errorf("warning present = %v, want %v (warns: %v)", found, tc.wantWarn, warns)
			}
		})
	}
}
