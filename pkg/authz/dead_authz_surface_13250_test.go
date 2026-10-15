package authz

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13250 (D6-10): Principal.Resolved and UsernameForUID were dead exported
// surface in this security-critical package — no production caller, only
// tests — and their doc comments (plus PrincipalForUID's) coached callers
// to reinstate the outlawed #5561 v2 fall-through. The source guard makes the
// obsolete API and misleading guidance fail the suite if reintroduced.
// Caller placement does not turn an unresolved identity into permission to
// borrow a credential; that fail-closed decision is exercised through
// Authorize below.
func TestDeadAuthzSurfaceAndFallthroughGuidanceRemoved13250(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	src, err := os.ReadFile(filepath.Join(filepath.Dir(file), "authz.go"))
	if err != nil {
		t.Fatal(err)
	}
	authzSource := string(src)
	for _, obsolete := range []string{
		"func (p Principal) Resolved() bool",
		"peer UID with no class falls through to an api-auth credential",
		"The caller may fall through to a weaker identity",
	} {
		if strings.Contains(authzSource, obsolete) {
			t.Errorf("pkg/authz/authz.go retains obsolete API or #5561 v2 fall-through guidance %q", obsolete)
		}
	}
	passwd, err := os.ReadFile(filepath.Join(filepath.Dir(file), "passwd.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(passwd), "func UsernameForUID(") {
		t.Error("pkg/authz/passwd.go retains dead exported UsernameForUID helper")
	}
}

// TestUnresolvedPeerUIDIsTerminal13250 pins the #5561 v2 invariant that
// replaces the deleted helpers' fall-through coaching: a non-root peer UID
// that resolves to no configured login class is terminal — Authorize denies
// it for every permission — while a configured peer keeps its own class.
func TestUnresolvedPeerUIDIsTerminal13250(t *testing.T) {
	cfg := &config.Config{}
	cfg.System.Login = &config.LoginConfig{
		Users: []*config.LoginUser{
			{Name: "bob", UID: 2002, Class: "read-only"},
		},
	}

	bob := Principal{Source: SourcePeerUID, UID: 2002, Username: "bob", Class: "read-only"}
	if err := Authorize(cfg, bob, config.PermView); err != nil {
		t.Fatalf("CONTROL: configured read-only peer denied view (%v) — the "+
			"denials below would prove nothing", err)
	}

	stranger := Principal{Source: SourcePeerUID, UID: 2999, Username: "stranger", Class: ""}
	for _, perm := range []config.LoginClassPermission{
		config.PermView, config.PermClear, config.PermControl,
		config.PermConfig, config.PermMaint, config.PermAll,
	} {
		if err := Authorize(cfg, stranger, perm); err == nil {
			t.Errorf("an unresolved peer UID was AUTHORIZED for %s — a placed "+
				"caller with no login class is terminal (#5561 v2), never a "+
				"candidate to fall through to an api-auth credential",
				PermissionName(perm))
		}
	}
}
