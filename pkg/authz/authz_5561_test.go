package authz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// authz_5561_test.go pins the authorization decision itself, independent of any
// transport. pkg/api covers the REST wiring; this covers what the shared layer
// decides, which is the part #5278 will reuse verbatim for gRPC.

func testConfig() *config.Config {
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{
		Users: []*config.LoginUser{
			{Name: "opsuser", Class: "read-only"},
			{Name: "adminuser", Class: "super-user"},
			{Name: "noclass"},
			{Name: "customuser", Class: "netops"},
			{Name: "ghostclass", Class: "does-not-exist"},
		},
		Classes: []*config.LoginClass{
			{Name: "netops", MappedPermissions: []config.LoginClassPermission{
				config.PermView, config.PermClear,
			}},
		},
	}
	return cfg
}

// TestAuthorizeDecisionMatrix_5561 walks the policy: superusers pass, a class
// is evaluated against the required permission, and everything the model does
// not describe is denied.
func TestAuthorizeDecisionMatrix_5561(t *testing.T) {
	cfg := testConfig()
	for _, tc := range []struct {
		name     string
		p        Principal
		required config.LoginClassPermission
		wantDeny bool // require a denial without pinning the reason's wording
	}{
		{
			name:     "root is authorized for the destructive tier",
			p:        Principal{Source: SourcePeerUID, UID: 0, Username: "root", Superuser: true},
			required: config.PermMaint,
		},
		{
			name:     "API credential defaults to read-only",
			p:        CredentialPrincipal("view-key", "read-only"),
			required: config.PermMaint,
			wantDeny: true,
		},
		{
			name:     "API credential can receive explicit maintenance class",
			p:        CredentialPrincipal("maint-key", "super-user"),
			required: config.PermMaint,
		},
		{
			name:     "no identity is denied even for the view tier",
			p:        Unauthenticated("connection carries no local peer identity"),
			required: config.PermView,
			wantDeny: true,
		},
		{
			name:     "read-only holds view",
			p:        Principal{Source: SourcePeerUID, UID: 4242, Username: "opsuser", Class: "read-only"},
			required: config.PermView,
		},
		{
			name:     "read-only does not hold configure",
			p:        Principal{Source: SourcePeerUID, UID: 4242, Username: "opsuser", Class: "read-only"},
			required: config.PermConfig,
			wantDeny: true,
		},
		{
			name:     "operator does not hold maintenance",
			p:        Principal{Source: SourcePeerUID, UID: 4245, Username: "op", Class: "operator"},
			required: config.PermMaint,
			wantDeny: true,
		},
		{
			name:     "operator holds clear",
			p:        Principal{Source: SourcePeerUID, UID: 4245, Username: "op", Class: "operator"},
			required: config.PermClear,
		},
		{
			name:     "super-user class holds configure",
			p:        Principal{Source: SourcePeerUID, UID: 4243, Username: "adminuser", Class: "super-user"},
			required: config.PermConfig,
		},
		{
			name:     "a custom class is evaluated from its mapped permissions",
			p:        Principal{Source: SourcePeerUID, UID: 4246, Username: "customuser", Class: "netops"},
			required: config.PermClear,
		},
		{
			name:     "a custom class is denied a permission it was not mapped",
			p:        Principal{Source: SourcePeerUID, UID: 4246, Username: "customuser", Class: "netops"},
			required: config.PermConfig,
			wantDeny: true,
		},
		{
			name:     "an unknown class is denied rather than treated as empty",
			p:        Principal{Source: SourcePeerUID, UID: 4247, Username: "ghostclass", Class: "does-not-exist"},
			required: config.PermView,
			wantDeny: true,
		},
		{
			name:     "a peer with no class is denied",
			p:        Principal{Source: SourcePeerUID, UID: 4244, Username: "stranger"},
			required: config.PermView,
			wantDeny: true,
		},
		{
			name:     "the unauthorized class holds nothing",
			p:        Principal{Source: SourcePeerUID, UID: 4248, Username: "u", Class: "unauthorized"},
			required: config.PermView,
			wantDeny: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Authorize(cfg, tc.p, tc.required)
			if err == nil && tc.wantDeny {
				t.Fatalf("Authorize admitted %s for %s; want a denial",
					tc.p, PermissionName(tc.required))
			}
			if err != nil && !tc.wantDeny {
				t.Fatalf("Authorize denied an authorized principal: %v", err)
			}
		})
	}
}

// TestAuthorizeDeniesWithoutActiveConfig_5561 covers early boot: before a config
// is active, only root (which does not consult the config) is authorized. A nil
// config must not read as "no restrictions".
func TestAuthorizeDeniesWithoutActiveConfig_5561(t *testing.T) {
	root := Principal{Source: SourcePeerUID, UID: 0, Username: "root", Superuser: true}
	if err := Authorize(nil, root, config.PermConfig); err != nil {
		t.Fatalf("root denied with no active config: %v", err)
	}
	user := Principal{Source: SourcePeerUID, UID: 4242, Username: "opsuser"}
	if err := Authorize(nil, user, config.PermView); err == nil {
		t.Fatal("a non-root caller was authorized against a nil active config — " +
			"an unconfigured box would be wide open on the REST mutation surface")
	}
}

// TestPrincipalForUIDResolution_5561 covers the UID -> account -> class chain,
// including every step that must produce an UNRESOLVED principal rather than a
// default one.
func TestPrincipalForUIDResolution_5561(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte(
		"root:x:0:0:root:/root:/bin/bash\n"+
			"opsuser:x:4242:4242::/home/opsuser:/bin/bash\n"+
			"noclass:x:4249:4249::/home/noclass:/bin/bash\n"+
			"stranger:x:4244:4244::/home/stranger:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer SetPasswdPathForTest(passwd)()
	cfg := testConfig()

	t.Run("root short-circuits without touching passwd or config", func(t *testing.T) {
		p := PrincipalForUID(nil, 0)
		if !p.Superuser || !p.Resolved() {
			t.Fatalf("uid 0 produced %+v, want a resolved superuser", p)
		}
	})

	t.Run("a configured login user resolves to its class", func(t *testing.T) {
		p := PrincipalForUID(cfg, 4242)
		if p.Username != "opsuser" || p.Class != "read-only" || !p.Resolved() {
			t.Fatalf("uid 4242 produced %+v, want opsuser/read-only", p)
		}
		if p.Superuser {
			t.Fatal("a read-only login user was marked superuser")
		}
	})

	t.Run("an account absent from the login model is unresolved", func(t *testing.T) {
		p := PrincipalForUID(cfg, 4244)
		if p.Resolved() {
			t.Fatalf("uid 4244 (a real account, not a login user) resolved to %+v", p)
		}
		if !strings.Contains(p.Detail, "stranger") {
			t.Errorf("detail does not name the account: %q", p.Detail)
		}
	})

	t.Run("a login user with no class is unresolved", func(t *testing.T) {
		p := PrincipalForUID(cfg, 4249)
		if p.Resolved() {
			t.Fatalf("uid 4249 (`system login user noclass` with no class) resolved to %+v", p)
		}
		if !strings.Contains(p.Detail, "no class") {
			t.Errorf("detail does not explain the missing class: %q", p.Detail)
		}
	})

	t.Run("a uid with no passwd entry is unresolved", func(t *testing.T) {
		p := PrincipalForUID(cfg, 65533)
		if p.Resolved() {
			t.Fatalf("uid 65533 resolved to %+v despite having no account", p)
		}
		if !strings.Contains(p.Detail, "/etc/passwd") {
			t.Errorf("detail does not explain the missing account: %q", p.Detail)
		}
	})
}

// TestUsernameForUIDParsesPasswd_5561 covers the account-database reader,
// including the duplicate-UID rule and the unreadable-database denial.
func TestUsernameForUIDParsesPasswd_5561(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte(
		"# a comment\n"+
			"\n"+
			"root:x:0:0:root:/root:/bin/bash\n"+
			"first:x:5000:5000::/home/first:/bin/bash\n"+
			"second:x:5000:5000::/home/second:/bin/bash\n"+
			"truncated:x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	restore := SetPasswdPathForTest(passwd)

	if name, ok := UsernameForUID(0); !ok || name != "root" {
		t.Errorf("uid 0 = (%q, %v), want (root, true)", name, ok)
	}
	// A DUPLICATE uid must not resolve at all (#6645).
	//
	// This asserted the opposite until #6645 — "want the FIRST entry (first,
	// true)" — and that assertion was defending a privilege escalation. With
	// `first` and `second` sharing uid 5000, naming the first row hands
	// `first`'s configured login class to `second`: two legitimate accounts,
	// one of them silently promoted. The kernel gives us 5000 and nothing
	// else, so the two callers are genuinely indistinguishable and there is no
	// correct name to return; the only sound answer is to refuse and let the
	// caller fail closed.
	//
	// The rule itself lives in pkg/osident (see lookupPasswd's comment), which
	// this resolver now delegates to. That is the point: while pkg/authz held
	// a second implementation, REST admitted the first row while the CLI
	// refused — same uid, same passwd file, opposite verdicts, both suites
	// green. TestRESTAndCLIAgreeOnAnAmbiguousUID_6645 (pkg/api) binds the
	// cross-surface property end to end.
	if name, ok := UsernameForUID(5000); ok {
		t.Errorf("duplicate uid 5000 resolved to %q — an ambiguous uid must fail closed, "+
			"never be attributed to whichever passwd row was read first", name)
	}
	if _, ok := UsernameForUID(9999); ok {
		t.Error("an absent uid resolved to a name")
	}
	restore()

	defer SetPasswdPathForTest(filepath.Join(dir, "absent"))()
	if _, ok := UsernameForUID(0); ok {
		t.Error("an unreadable account database still produced an identity — " +
			"the resolver must fail closed")
	}
}

// TestResolveClassPermissionsIsSharedWithTheCLI_5561 pins the factoring: the
// built-in table and the custom-class fallback both resolve here, so pkg/cli
// and this package cannot answer differently for the same class.
func TestResolveClassPermissionsIsSharedWithTheCLI_5561(t *testing.T) {
	cfg := testConfig()
	for class, want := range map[string]bool{
		"super-user": true, "operator": true, "read-only": true,
		"config-viewer": true, "unauthorized": true, "netops": true,
		"nonexistent": false,
	} {
		if _, ok := config.ResolveClassPermissions(cfg, class); ok != want {
			t.Errorf("ResolveClassPermissions(%q) known=%v, want %v", class, ok, want)
		}
	}
	if config.ClassHasPermission(cfg, "read-only", config.PermConfig) {
		t.Error("read-only reported as holding configure")
	}
	if !config.ClassHasPermission(cfg, "super-user", config.PermMaint) {
		t.Error("super-user (PermAll) reported as NOT holding maintenance")
	}
	if _, ok := config.LoginUserClass(cfg, "adminuser"); !ok {
		t.Error("LoginUserClass did not find a configured user")
	}
	if _, ok := config.LoginUserClass(nil, "adminuser"); ok {
		t.Error("LoginUserClass found a user in a nil config")
	}
}

// TestTolerantlyLoadedInvalidUsernameGrantsNoClass_5561 is the round-10
// finding-7 guard.
//
// A STRICT commit rejects an invalid `system login user <name>` at the schema
// (config.ValidateLoginUsername). The TOLERANT load and peer-sync paths do not:
// they warn and keep going (pkg/configstore/store.go), so a legacy on-disk
// config or a divergent peer can make such a stanza ACTIVE. pkg/daemon's account
// reconciliation (applySystemLogin) then refuses to provision the account —
// which is the correct half of the answer, and used to be the only half. The
// class stayed readable, so if an account with that exact name already existed
// in /etc/passwd for any other reason, the caller running as it was handed the
// class the daemon had declined to realize.
//
// `UPPER` is the shape that matters: a plain name with no metacharacters, which
// the validator refuses only because the login-name grammar is lowercase. It is
// the case an operator could plausibly have on disk, and the one that reads as
// harmless.
//
// The control is the same fixture with a VALID name and the same class: it must
// still resolve, or "deny the invalid one" would be indistinguishable from
// "deny everything".
func TestTolerantlyLoadedInvalidUsernameGrantsNoClass_5561(t *testing.T) {
	dir := t.TempDir()
	passwd := filepath.Join(dir, "passwd")
	if err := os.WriteFile(passwd, []byte(
		"UPPER:x:4250:4250::/home/UPPER:/bin/bash\n"+
			"lawful:x:4251:4251::/home/lawful:/bin/bash\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer SetPasswdPathForTest(passwd)()

	// The config a tolerant load leaves active: both users carry super-user.
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{
		Users: []*config.LoginUser{
			{Name: "UPPER", Class: "super-user"},
			{Name: "lawful", Class: "super-user"},
		},
	}

	t.Run("the control resolves", func(t *testing.T) {
		p := PrincipalForUID(cfg, 4251)
		if !p.Resolved() || p.Class != "super-user" {
			t.Fatalf("uid 4251 (a VALID login user name) produced %+v, want a resolved "+
				"super-user — the denial below would otherwise prove nothing", p)
		}
		if err := Authorize(cfg, p, config.PermConfig); err != nil {
			t.Fatalf("the control was denied: %v", err)
		}
	})

	t.Run("a name host provisioning refuses is not a principal", func(t *testing.T) {
		p := PrincipalForUID(cfg, 4250)
		if p.Resolved() {
			t.Fatalf("uid 4250 resolved to %+v. `system login user UPPER` is a name the daemon "+
				"REFUSES to provision (applySystemLogin skips it), so no account with that name "+
				"was created by the login model — yet it was handed that stanza's class over the "+
				"REST control surface", p)
		}
		if err := Authorize(cfg, p, config.PermConfig); err == nil {
			t.Fatal("an unresolved principal was authorized for `configure`")
		}
	})
}
