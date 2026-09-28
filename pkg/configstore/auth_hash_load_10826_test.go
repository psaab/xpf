package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
)

const legacyAPIAuthConfig10826 = `system {
 services {
  web-management {
   api-auth {
    expires 2099-01-01;
    user admin { password correct-horse-battery; }
    api-key machine-generated-key-alpha;
   }
  }
 }
}`

func parseAuthMigrationTree10826(t *testing.T, text string) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse auth migration fixture: %v", errs)
	}
	return tree
}

func TestLoadHashesLegacyAPIAuthSecrets10826(t *testing.T) {
	s := newTestStore(t)
	if err := s.db.WriteActive(parseAuthMigrationTree10826(t, legacyAPIAuthConfig10826)); err != nil {
		t.Fatalf("write legacy active config: %v", err)
	}

	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	persisted, _, err := s.db.ReadActiveMeta()
	if err != nil {
		t.Fatalf("read migrated active config: %v", err)
	}
	formatted := persisted.Format()
	for _, cleartext := range []string{"correct-horse-battery", "machine-generated-key-alpha"} {
		if strings.Contains(formatted, cleartext) {
			t.Errorf("active DB still contains cleartext API credential %q", cleartext)
		}
	}
	if !strings.Contains(formatted, "$xpf-bcrypt$") {
		t.Fatalf("active DB does not contain tagged API credential verifiers:\n%s", formatted)
	}
	wm := s.ActiveConfig().System.Services.WebManagement
	if wm == nil || wm.APIAuth == nil || len(wm.APIAuth.Users) != 1 || len(wm.APIAuth.APIKeys) != 1 {
		t.Fatalf("loaded API auth config is incomplete: %+v", wm)
	}
	if !config.VerifyAPIAuthSecret(wm.APIAuth.Users[0].Password.Reveal(), "correct-horse-battery") ||
		!config.VerifyAPIAuthSecret(wm.APIAuth.APIKeys[0].Reveal(), "machine-generated-key-alpha") {
		t.Fatal("migrated API credential verifiers do not accept their original secrets")
	}
}

func TestLoadFailsClosedWhenAPIAuthMigrationCannotPersist10826(t *testing.T) {
	s := newTestStore(t)
	if err := s.db.WriteActive(parseAuthMigrationTree10826(t, legacyAPIAuthConfig10826)); err != nil {
		t.Fatalf("write legacy active config: %v", err)
	}
	s.writeActiveMarkerFn = func(*config.ConfigTree, bool) error {
		return errors.New("injected durable-write failure")
	}

	if err := s.Load(); !errors.Is(err, ErrConfigDBUnreadable) {
		t.Fatalf("Load error = %v, want fail-closed ErrConfigDBUnreadable", err)
	}
	if s.ActiveConfig() != nil {
		t.Fatal("Load published active configuration after failed secret migration")
	}
}

func TestLoadHashesLegacyAPIAuthRollbackSecrets10826(t *testing.T) {
	s := newTestStore(t)
	if err := s.db.WriteActive(&config.ConfigTree{}); err != nil {
		t.Fatalf("write active config: %v", err)
	}
	rollback := `system { services { web-management { api-auth { expires 2099-01-01; api-key rollback-key-alpha-123456; } } } }`
	if err := os.WriteFile(filepath.Join(filepath.Dir(s.filePath), filepath.Base(s.filePath)+".1"), []byte(rollback), 0600); err != nil {
		t.Fatalf("write legacy rollback config: %v", err)
	}

	if err := s.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	persisted, err := os.ReadFile(s.rollbackPath(1))
	if err != nil {
		t.Fatalf("read migrated rollback config: %v", err)
	}
	if strings.Contains(string(persisted), "rollback-key-alpha-123456") {
		t.Fatalf("rollback file still contains cleartext API credential:\n%s", persisted)
	}
	if !strings.Contains(string(persisted), "$xpf-bcrypt$") {
		t.Fatalf("rollback file does not contain a tagged API credential verifier:\n%s", persisted)
	}
}
func TestLoadPreservesPendingConfirmAcrossAPIAuthMigration10826(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	initial := newTestStoreAt(t, path)
	active := parseAuthMigrationTree10826(t, legacyAPIAuthConfig10826)
	previous := parseAuthMigrationTree10826(t, `system {
 services {
  web-management {
   api-auth {
    expires 2099-01-01;
    api-key rollback-key-alpha-123456;
   }
  }
 }
}`)
	if err := initial.db.WriteActive(active); err != nil {
		t.Fatalf("write active config: %v", err)
	}
	if err := initial.db.WriteConfirm(&confirmRecord{
		Deadline:    time.Now().Add(-time.Second),
		PrevTree:    previous,
		GuardedHash: guardedConfigHash(active),
	}); err != nil {
		t.Fatalf("write expired confirm record: %v", err)
	}

	// Simulate a crash after the migration's provisional confirm-record write
	// but before active.json is durably replaced. The next Load must recognize
	// the old active hash alias, complete migration, and still perform rollback.
	initial.writeActiveMarkerFn = func(*config.ConfigTree, bool) error {
		return errors.New("injected active rewrite failure")
	}
	if err := initial.Load(); !errors.Is(err, ErrConfigDBUnreadable) {
		t.Fatalf("first Load error = %v, want fail-closed migration error", err)
	}
	provisional, err := initial.db.ReadConfirm()
	if err != nil {
		t.Fatalf("read provisional confirm record: %v", err)
	}
	if provisional == nil || provisional.GuardedHash == "" || provisional.PreviousHash != guardedConfigHash(active) {
		t.Fatalf("migration did not leave an old-active recovery alias: %+v", provisional)
	}
	if provisional.PrevTree == nil || strings.Contains(provisional.PrevTree.Format(), "rollback-key-alpha-123456") {
		t.Fatal("provisional confirm record still contains a cleartext rollback credential")
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("restart Load: %v", err)
	}
	got := restarted.ActiveConfig().System.Services.WebManagement.APIAuth
	if got == nil || len(got.APIKeys) != 1 ||
		!config.VerifyAPIAuthSecret(got.APIKeys[0].Reveal(), "rollback-key-alpha-123456") {
		t.Fatal("expired pending confirm did not roll back to its migrated credential")
	}
	if rec, err := restarted.db.ReadConfirm(); err != nil || rec != nil {
		t.Fatalf("confirm record after recovery = (%+v, %v), want absent", rec, err)
	}
}
