package configstore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

const (
	rollbackAPIAuthOld10825    = "old-rollback-api-key-10825"
	rollbackAPIAuthRecent10825 = "recent-rollback-api-key-10825"
)

func addLegacyAPIAuthToActive10825(t *testing.T, active *config.ConfigTree) {
	t.Helper()
	legacy := parseAuthMigrationTree10826(t, legacyAPIAuthConfig10826)
	legacySystem := legacy.FindChild("system")
	if legacySystem == nil {
		t.Fatal("PREMISE: api-auth fixture has no system node")
	}
	activeSystem := active.FindChild("system")
	if activeSystem == nil {
		active.Children = append(active.Children, legacySystem)
		return
	}
	legacyServices := legacySystem.FindChild("services")
	activeServices := activeSystem.FindChild("services")
	if activeServices == nil {
		activeSystem.Children = append(activeSystem.Children, legacyServices)
		return
	}
	legacyWeb := legacyServices.FindChild("web-management")
	activeWeb := activeServices.FindChild("web-management")
	if activeWeb == nil {
		activeServices.Children = append(activeServices.Children, legacyWeb)
		return
	}
	activeWeb.Children = append(activeWeb.Children, legacyWeb.FindChild("api-auth"))
}

func prepareBoundAPIAuthMigration10825(t *testing.T) (string, time.Time, time.Time) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config")
	s := newTestStoreAt(t, path)
	commitBaseline(t, s)

	active, err := s.db.ReadActive()
	if err != nil || active == nil {
		t.Fatalf("read active config: tree=%v err=%v", active, err)
	}
	addLegacyAPIAuthToActive10825(t, active)
	s.active = active
	if err := s.db.WriteActive(active); err != nil {
		t.Fatalf("write legacy active config: %v", err)
	}

	maxSize := s.history.MaxSize()
	s.history = NewHistory(maxSize)
	oldTime := time.Date(2022, 3, 4, 5, 6, 7, 0, time.UTC)
	recentTime := time.Date(2023, 7, 8, 9, 10, 11, 0, time.UTC)
	oldTree := parseAuthMigrationTree10826(t, `system { services { web-management { api-auth { expires 2099-01-01; api-key old-rollback-api-key-10825; } } } }`)
	recentTree := parseAuthMigrationTree10826(t, `system { services { web-management { api-auth { expires 2099-01-01; api-key recent-rollback-api-key-10825; } } } }`)
	s.history.Push(&HistoryEntry{Config: oldTree, Timestamp: oldTime, Comment: "old-slot-comment-10825"})
	s.history.Push(&HistoryEntry{Config: recentTree, Timestamp: recentTime, Comment: "recent-slot-comment-10825"})
	s.saveRollbackFiles()
	if s.rollbackPersistDegraded {
		t.Fatal("PREMISE: fixture rollback history failed to persist")
	}
	generation, activeHash, activeIdentity, entries := s.readRollbackMetadataSnapshot()
	if generation == 0 || activeHash == "" || activeIdentity.Inode == 0 || len(entries) != 2 {
		t.Fatalf("PREMISE: expected generation-bound rollback metadata: generation=%d active=%q identity=%+v entries=%d",
			generation, activeHash, activeIdentity, len(entries))
	}
	return path, oldTime, recentTime
}

func checkRollbackAPIAuth10825(t *testing.T, entry *HistoryEntry, raw, comment string, timestamp time.Time) {
	t.Helper()
	if entry == nil || entry.Config == nil {
		t.Fatal("valid rollback target became a tombstone")
	}
	if entry.Comment != comment || !entry.Timestamp.Equal(timestamp) {
		t.Fatalf("rollback metadata changed: timestamp=%s comment=%q; want %s / %q",
			entry.Timestamp, entry.Comment, timestamp, comment)
	}
	formatted := entry.Config.Format()
	if strings.Contains(formatted, raw) {
		t.Fatalf("rollback target still contains cleartext api-auth credential %q", raw)
	}
	auth := entry.Config.FindChild("system").FindChild("services").
		FindChild("web-management").FindChild("api-auth")
	apiKey := auth.FindChild("api-key")
	if apiKey == nil || len(apiKey.Keys) < 2 || !config.VerifyAPIAuthSecret(apiKey.Keys[1], raw) {
		t.Fatal("migrated rollback api-auth verifier does not accept its original secret")
	}
}

func TestLoadPreservesGenerationBoundRollbackDuringAPIAuthMigration10825(t *testing.T) {
	path, oldTime, recentTime := prepareBoundAPIAuthMigration10825(t)
	loaded := newTestStoreAt(t, path)
	if err := loaded.Load(); err != nil {
		t.Fatalf("Load legacy active and rollback configs: %v", err)
	}

	active, err := loaded.db.ReadActive()
	if err != nil {
		t.Fatal(err)
	}
	activeText := active.Format()
	for _, secret := range []string{"correct-horse-battery", "machine-generated-key-alpha", "automation-key-secret-alpha"} {
		if strings.Contains(activeText, secret) {
			t.Fatalf("active config retains cleartext api-auth credential %q", secret)
		}
	}
	apiAuth := loaded.ActiveConfig().System.Services.WebManagement.APIAuth
	if apiAuth == nil || len(apiAuth.Users) != 1 || len(apiAuth.APIKeys) != 1 || len(apiAuth.Keys) != 1 ||
		!config.VerifyAPIAuthSecret(apiAuth.Users[0].Password.Reveal(), "correct-horse-battery") ||
		!config.VerifyAPIAuthSecret(apiAuth.APIKeys[0].Reveal(), "machine-generated-key-alpha") ||
		!config.VerifyAPIAuthSecret(apiAuth.Keys[0].Secret.Reveal(), "automation-key-secret-alpha") {
		t.Fatal("migrated active api-auth credentials are not usable")
	}

	history := loaded.history.List()
	if len(history) != 2 {
		t.Fatalf("loaded rollback history has %d slots, want both generation-bound targets", len(history))
	}
	checkRollbackAPIAuth10825(t, history[0], rollbackAPIAuthRecent10825,
		"recent-slot-comment-10825", recentTime)
	checkRollbackAPIAuth10825(t, history[1], rollbackAPIAuthOld10825,
		"old-slot-comment-10825", oldTime)
	for slot, secret := range map[int]string{1: rollbackAPIAuthRecent10825, 2: rollbackAPIAuthOld10825} {
		data, err := os.ReadFile(loaded.rollbackPath(slot))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), secret) || !strings.Contains(string(data), "$xpf-bcrypt$") {
			t.Fatalf("persisted rollback slot %d did not retain only a tagged verifier", slot)
		}
	}
	if _, err := os.Stat(loaded.apiAuthMigrationStagingPath()); !os.IsNotExist(err) {
		t.Fatalf("migration staging remained after convergence: %v", err)
	}
}

func TestLoadRecoversAfterActiveRewriteBeforeRollbackManifest10825(t *testing.T) {
	path, oldTime, recentTime := prepareBoundAPIAuthMigration10825(t)
	first := newTestStoreAt(t, path)
	crash := errors.New("simulated crash after active rename")
	first.writeActiveMarkerFn = func(tree *config.ConfigTree, committed bool) error {
		if err := first.db.WriteActiveMarker(tree, committed); err != nil {
			return err
		}
		return crash
	}
	if err := first.Load(); !errors.Is(err, ErrConfigDBUnreadable) {
		t.Fatalf("Load after simulated active rewrite crash = %v, want fail-closed persistence error", err)
	}
	if _, err := os.Stat(first.apiAuthMigrationStagingPath()); err != nil {
		t.Fatalf("restart record missing after active rewrite: %v", err)
	}
	generation, oldActiveHash, _, _ := first.readRollbackMetadataSnapshot()
	newActiveHash, _, ok := first.rollbackActiveBindingFromDisk()
	if generation == 0 || !ok || oldActiveHash == newActiveHash {
		t.Fatalf("PREMISE: active rewrite did not leave old manifest/new active: generation=%d old=%q new=%q",
			generation, oldActiveHash, newActiveHash)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("restart did not recover history after active/manifest split: %v", err)
	}
	history := restarted.history.List()
	if len(history) != 2 {
		t.Fatalf("restart retained %d rollback targets, want 2", len(history))
	}
	checkRollbackAPIAuth10825(t, history[0], rollbackAPIAuthRecent10825,
		"recent-slot-comment-10825", recentTime)
	checkRollbackAPIAuth10825(t, history[1], rollbackAPIAuthOld10825,
		"old-slot-comment-10825", oldTime)
}

func TestLoadRecoversAPIAuthRollbackMigrationAfterRestart10825(t *testing.T) {
	path, oldTime, recentTime := prepareBoundAPIAuthMigration10825(t)
	first := newTestStoreAt(t, path)
	originalWrite := rbWriteFileDurable
	injected := errors.New("injected rollback-slot crash boundary")
	failed := false
	t.Cleanup(func() { rbWriteFileDurable = originalWrite })
	rbWriteFileDurable = func(filePath string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if filepath.Clean(filePath) == filepath.Clean(first.rollbackPath(1)) && !failed {
			failed = true
			return injected
		}
		return originalWrite(filePath, data, perm, opts...)
	}
	loadErr := first.Load()
	rbWriteFileDurable = originalWrite
	if !failed {
		t.Fatal("PREMISE: migration did not reach rollback slot write")
	}
	if !errors.Is(loadErr, ErrConfigDBUnreadable) {
		t.Fatalf("first Load error = %v, want staged rollback persistence failure", loadErr)
	}
	if _, err := os.Stat(first.apiAuthMigrationStagingPath()); err != nil {
		t.Fatalf("recoverable migration staging missing after interrupted Load: %v", err)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); err != nil {
		t.Fatalf("restart Load did not finish staged migration: %v", err)
	}
	history := restarted.history.List()
	if len(history) != 2 {
		t.Fatalf("restart retained %d rollback targets, want 2", len(history))
	}
	checkRollbackAPIAuth10825(t, history[0], rollbackAPIAuthRecent10825,
		"recent-slot-comment-10825", recentTime)
	checkRollbackAPIAuth10825(t, history[1], rollbackAPIAuthOld10825,
		"old-slot-comment-10825", oldTime)
	if _, err := os.Stat(restarted.apiAuthMigrationStagingPath()); !os.IsNotExist(err) {
		t.Fatalf("restart failed to retire converged staging record: %v", err)
	}
}

func TestStagedAPIAuthMigrationDoesNotAliasUnrelatedActiveGeneration10825(t *testing.T) {
	path, _, _ := prepareBoundAPIAuthMigration10825(t)
	first := newTestStoreAt(t, path)
	originalWrite := rbWriteFileDurable
	t.Cleanup(func() { rbWriteFileDurable = originalWrite })
	injected := errors.New("injected rollback-slot crash boundary")
	failed := false
	rbWriteFileDurable = func(filePath string, data []byte, perm os.FileMode, opts ...fsatomic.Option) error {
		if filepath.Clean(filePath) == filepath.Clean(first.rollbackPath(1)) && !failed {
			failed = true
			return injected
		}
		return originalWrite(filePath, data, perm, opts...)
	}
	firstErr := first.Load()
	rbWriteFileDurable = originalWrite
	if !failed || !errors.Is(firstErr, ErrConfigDBUnreadable) {
		t.Fatalf("interrupted migration Load = %v, slotWriteFailed=%v; want staged persistence failure", firstErr, failed)
	}
	metadataBefore, err := os.ReadFile(first.rollbackMetadataPath())
	if err != nil {
		t.Fatal(err)
	}
	slotBefore, err := os.ReadFile(first.rollbackPath(1))
	if err != nil {
		t.Fatal(err)
	}
	stagingBefore, err := os.ReadFile(first.apiAuthMigrationStagingPath())
	if err != nil {
		t.Fatal(err)
	}
	unrelated := parseAuthMigrationTree10826(t, `system { host-name unrelated-active-generation-10825; }`)
	if err := first.db.WriteActive(unrelated); err != nil {
		t.Fatalf("inject unrelated active generation: %v", err)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); !errors.Is(err, ErrConfigDBUnreadable) {
		t.Fatalf("Load with unrelated active generation = %v, want fail-closed staging mismatch", err)
	}
	metadataAfter, err := os.ReadFile(restarted.rollbackMetadataPath())
	if err != nil {
		t.Fatal(err)
	}
	slotAfter, err := os.ReadFile(restarted.rollbackPath(1))
	if err != nil {
		t.Fatal(err)
	}
	stagingAfter, err := os.ReadFile(restarted.apiAuthMigrationStagingPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(metadataAfter) != string(metadataBefore) ||
		string(slotAfter) != string(slotBefore) ||
		string(stagingAfter) != string(stagingBefore) {
		t.Fatal("unrelated active-generation mismatch rewrote rollback metadata, slots, or migration staging")
	}
	if err := os.Remove(restarted.rollbackMetadataPath()); err != nil {
		t.Fatal(err)
	}
	withoutManifest := newTestStoreAt(t, path)
	if err := withoutManifest.Load(); !errors.Is(err, ErrConfigDBUnreadable) {
		t.Fatalf("Load with unrelated active and absent rollback manifest = %v, want fail-closed staging mismatch", err)
	}
	if _, err := os.Stat(withoutManifest.rollbackMetadataPath()); !os.IsNotExist(err) {
		t.Fatalf("absent rollback manifest was recreated for an unrelated active generation: %v", err)
	}
	slotWithoutManifest, err := os.ReadFile(withoutManifest.rollbackPath(1))
	if err != nil {
		t.Fatal(err)
	}
	stagingWithoutManifest, err := os.ReadFile(withoutManifest.apiAuthMigrationStagingPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(slotWithoutManifest) != string(slotBefore) ||
		string(stagingWithoutManifest) != string(stagingBefore) {
		t.Fatal("unrelated active without rollback manifest rewrote slots or staging")
	}
}

func verifyAPIAuthText10825(t *testing.T, text string) {
	t.Helper()
	tree, parseErrs := config.NewParser(text).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse retained api-auth config: %v", parseErrs)
	}
	auth := tree.FindChild("system").FindChild("services").
		FindChild("web-management").FindChild("api-auth")
	user := auth.FindChild("user")
	apiKey := auth.FindChild("api-key")
	key := auth.FindChild("key")
	if user == nil || apiKey == nil || key == nil ||
		!config.VerifyAPIAuthSecret(user.FindChild("password").Keys[1], "correct-horse-battery") ||
		!config.VerifyAPIAuthSecret(apiKey.Keys[1], "machine-generated-key-alpha") ||
		!config.VerifyAPIAuthSecret(key.FindChild("secret").Keys[1], "automation-key-secret-alpha") {
		t.Fatal("retained api-auth verifiers do not accept their original secrets")
	}
}

func TestLoadMigratesRescueAndPurgesLegacyLocalArchiveBeforeNewWrites10825(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	store := newTestStoreAt(t, path)
	active := parseAuthMigrationTree10826(t, legacyAPIAuthConfig10826)
	if err := store.db.WriteActive(active); err != nil {
		t.Fatalf("write legacy active: %v", err)
	}
	rescuePath := filepath.Join(filepath.Dir(path), RescueConfigBase)
	if err := os.WriteFile(rescuePath, []byte(legacyAPIAuthConfig10826), 0o600); err != nil {
		t.Fatalf("write legacy rescue: %v", err)
	}
	archiveDir := filepath.Join(t.TempDir(), "archive")
	store.SetAPIAuthArchiveMigrationDir(archiveDir)
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	oldArchive := filepath.Join(archiveDir, "config-20240101-000000.000000000.conf")
	if err := os.WriteFile(oldArchive, []byte(legacyAPIAuthConfig10826), 0o600); err != nil {
		t.Fatalf("write legacy archive: %v", err)
	}

	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	rescueText, err := store.LoadRescueConfig()
	if err != nil {
		t.Fatalf("LoadRescueConfig: %v", err)
	}
	if strings.Contains(rescueText, "correct-horse-battery") ||
		strings.Contains(rescueText, "machine-generated-key-alpha") ||
		strings.Contains(rescueText, "automation-key-secret-alpha") ||
		!strings.Contains(rescueText, "$xpf-bcrypt$") {
		t.Fatalf("parseable rescue config was not migrated to tagged verifiers:\n%s", rescueText)
	}
	verifyAPIAuthText10825(t, rescueText)
	if err := store.SaveRescueConfig(); err != nil {
		t.Fatalf("SaveRescueConfig after migration: %v", err)
	}
	rescueText, err = store.LoadRescueConfig()
	if err != nil || !strings.Contains(rescueText, "$xpf-bcrypt$") ||
		strings.Contains(rescueText, "machine-generated-key-alpha") {
		t.Fatalf("new rescue save contains legacy credential material: err=%v\n%s", err, rescueText)
	}
	verifyAPIAuthText10825(t, rescueText)

	store.SetArchiveConfig(archiveDir, 10)
	if err := store.ArchiveConfig(archiveDir, 10); err != nil {
		t.Fatalf("ArchiveConfig: %v", err)
	}
	if _, err := os.Stat(oldArchive); !os.IsNotExist(err) {
		t.Fatalf("legacy local archive was not purged: %v", err)
	}
	archiveEntries, err := os.ReadDir(archiveDir)
	if err != nil {
		t.Fatal(err)
	}
	foundNew := false
	for _, entry := range archiveEntries {
		if entry.Name() == filepath.Base(oldArchive) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(archiveDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if strings.Contains(text, "correct-horse-battery") ||
			strings.Contains(text, "machine-generated-key-alpha") ||
			strings.Contains(text, "automation-key-secret-alpha") ||
			!strings.Contains(text, "$xpf-bcrypt$") {
			t.Fatalf("new local archive contains legacy api-auth credentials:\n%s", text)
		}
		verifyAPIAuthText10825(t, text)
		foundNew = true
	}
	if !foundNew {
		t.Fatal("ArchiveConfig did not create a new retained archive")
	}
}

func TestLoadLeavesMalformedRescueBytesUntouchedDuringAPIAuthMigration10825(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	store := newTestStoreAt(t, path)
	if err := store.db.WriteActive(parseAuthMigrationTree10826(t, legacyAPIAuthConfig10826)); err != nil {
		t.Fatalf("write legacy active: %v", err)
	}
	rescuePath := filepath.Join(filepath.Dir(path), RescueConfigBase)
	const malformed = "{not valid configuration with secret-looking data\n"
	if err := os.WriteFile(rescuePath, []byte(malformed), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	after, err := os.ReadFile(rescuePath)
	if err != nil || string(after) != malformed {
		t.Fatalf("malformed rescue file was changed: err=%v data=%q", err, after)
	}
}

func TestLoadLeavesMalformedTaggedRescueBytesUntouchedAndContinues10825(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	store := newTestStoreAt(t, path)
	if err := store.db.WriteActive(parseAuthMigrationTree10826(t, legacyAPIAuthConfig10826)); err != nil {
		t.Fatalf("write legacy active: %v", err)
	}
	const malformedTagRescue = `system {
 services {
  web-management {
   api-auth {
    user admin { password "$xpf-bcrypt$malformed"; }
   }
  }
 }
}`
	if tree, parseErrs := config.NewParser(malformedTagRescue).Parse(); len(parseErrs) != 0 || tree == nil {
		t.Fatalf("PREMISE: malformed-tag rescue fixture must be syntactically parseable: %v", parseErrs)
	}
	rescuePath := filepath.Join(filepath.Dir(path), RescueConfigBase)
	if err := os.WriteFile(rescuePath, []byte(malformedTagRescue), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("malformed non-active rescue credential must not block active Load: %v", err)
	}
	after, err := os.ReadFile(rescuePath)
	if err != nil || string(after) != malformedTagRescue {
		t.Fatalf("malformed tagged rescue bytes changed: err=%v data=%q", err, after)
	}
}

func TestLoadMigratesRescueWithoutActiveConfig10825(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	store := newTestStoreAt(t, path)
	rescuePath := filepath.Join(filepath.Dir(path), RescueConfigBase)
	if err := os.WriteFile(rescuePath, []byte(legacyAPIAuthConfig10826), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("fresh-store Load: %v", err)
	}
	rescue, err := os.ReadFile(rescuePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rescue), "correct-horse-battery") ||
		strings.Contains(string(rescue), "machine-generated-key-alpha") ||
		!strings.Contains(string(rescue), "$xpf-bcrypt$") {
		t.Fatalf("fresh-store rescue was not migrated:\n%s", rescue)
	}
	verifyAPIAuthText10825(t, string(rescue))
}

func TestLoadMigratesRescueWhenActiveIsAbsentButHistorySurvives10825(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	store := newTestStoreAt(t, path)
	if err := os.WriteFile(store.rollbackPath(1), []byte(legacyAPIAuthConfig10826), 0o600); err != nil {
		t.Fatal(err)
	}
	rescuePath := filepath.Join(filepath.Dir(path), RescueConfigBase)
	if err := os.WriteFile(rescuePath, []byte(legacyAPIAuthConfig10826), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); !errors.Is(err, ErrConfigAbsentWithHistory) {
		t.Fatalf("Load with missing active and surviving history = %v, want ErrConfigAbsentWithHistory", err)
	}
	rescue, err := os.ReadFile(rescuePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rescue), "correct-horse-battery") ||
		!strings.Contains(string(rescue), "$xpf-bcrypt$") {
		t.Fatalf("rescue was not migrated on missing-active-with-history path:\n%s", rescue)
	}
	verifyAPIAuthText10825(t, string(rescue))
}

func TestAbsentActivePreservesInterruptedAPIAuthMigration10825(t *testing.T) {
	path, _, _ := prepareBoundAPIAuthMigration10825(t)
	first := newTestStoreAt(t, path)
	crash := errors.New("simulated active rewrite boundary")
	first.writeActiveMarkerFn = func(tree *config.ConfigTree, committed bool) error {
		if err := first.db.WriteActiveMarker(tree, committed); err != nil {
			return err
		}
		return crash
	}
	if err := first.Load(); !errors.Is(err, ErrConfigDBUnreadable) {
		t.Fatalf("interrupted migration Load = %v, want fail-closed persistence error", err)
	}

	metadataBefore, err := os.ReadFile(first.rollbackMetadataPath())
	if err != nil {
		t.Fatal(err)
	}
	slotBefore, err := os.ReadFile(first.rollbackPath(1))
	if err != nil {
		t.Fatal(err)
	}
	stagingBefore, err := os.ReadFile(first.apiAuthMigrationStagingPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(filepath.Dir(path), ".configdb", "active.json")); err != nil {
		t.Fatal(err)
	}

	restarted := newTestStoreAt(t, path)
	if err := restarted.Load(); !errors.Is(err, ErrConfigAbsentWithHistory) {
		t.Fatalf("Load with absent active and interrupted migration = %v, want ErrConfigAbsentWithHistory", err)
	}
	metadataAfter, err := os.ReadFile(restarted.rollbackMetadataPath())
	if err != nil {
		t.Fatal(err)
	}
	slotAfter, err := os.ReadFile(restarted.rollbackPath(1))
	if err != nil {
		t.Fatal(err)
	}
	stagingAfter, err := os.ReadFile(restarted.apiAuthMigrationStagingPath())
	if err != nil {
		t.Fatal(err)
	}
	if string(metadataAfter) != string(metadataBefore) ||
		string(slotAfter) != string(slotBefore) ||
		string(stagingAfter) != string(stagingBefore) {
		t.Fatal("absent active config changed rollback metadata, slots, or migration staging")
	}
}

func TestLoadPurgesOnlyOwnedRecognizedLegacyAPIAuthArchives10825(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config")
	store := newTestStoreAt(t, path)
	if err := store.db.WriteActive(parseAuthMigrationTree10826(t, legacyAPIAuthConfig10826)); err != nil {
		t.Fatalf("write legacy active: %v", err)
	}
	ownedArchiveDir := filepath.Join(root, "owned-archive")
	store.SetAPIAuthArchiveMigrationDir(ownedArchiveDir)
	if err := os.MkdirAll(ownedArchiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	customArchiveDir := filepath.Join(root, "custom-archive")
	if err := os.MkdirAll(customArchiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	const legacyName = "config-20240101-000000.000000000.conf"
	const invalidTagName = "config-20240101-000001.000000001.00000000000000000002.conf"
	const validName = "config-20240101-000002.000000002.00000000000000000003.conf"
	const malformedName = "config-20240101-000003.000000003.00000000000000000004.conf"
	const linkedName = "config-20240101-000004.000000004.00000000000000000005.conf"
	const customName = "config-20240101-000005.000000005.00000000000000000006.conf"
	const invalidTag = `system {
 services {
  web-management {
   api-auth {
    user admin { password "$xpf-bcrypt$malformed"; }
   }
  }
 }
}`
	validTree := parseAuthMigrationTree10826(t, legacyAPIAuthConfig10826)
	if _, err := config.HashAPIAuthSecrets(validTree); err != nil {
		t.Fatalf("hash valid archive fixture: %v", err)
	}
	validBytes := []byte(validTree.Format())
	ownedFiles := map[string][]byte{
		legacyName:     []byte(legacyAPIAuthConfig10826),
		invalidTagName: []byte(invalidTag),
		validName:      validBytes,
		malformedName:  []byte("{not valid configuration\n"),
		"notes.conf":   []byte(legacyAPIAuthConfig10826),
	}
	for name, data := range ownedFiles {
		if err := os.WriteFile(filepath.Join(ownedArchiveDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(root, "archive-link-target.conf")
	if err := os.WriteFile(target, []byte(legacyAPIAuthConfig10826), 0o600); err != nil {
		t.Fatal(err)
	}
	linkedPath := filepath.Join(ownedArchiveDir, linkedName)
	if err := os.Symlink(target, linkedPath); err != nil {
		t.Fatal(err)
	}
	customPath := filepath.Join(customArchiveDir, customName)
	if err := os.WriteFile(customPath, []byte(legacyAPIAuthConfig10826), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := store.Load(); err != nil {
		t.Fatalf("Load with local archive cleanup: %v", err)
	}
	for _, name := range []string{legacyName, invalidTagName} {
		if _, err := os.Stat(filepath.Join(ownedArchiveDir, name)); !os.IsNotExist(err) {
			t.Fatalf("legacy/malformed owned snapshot %s was not purged: %v", name, err)
		}
	}
	for name, want := range map[string][]byte{
		validName:     validBytes,
		malformedName: []byte("{not valid configuration\n"),
		"notes.conf":  []byte(legacyAPIAuthConfig10826),
	} {
		got, err := os.ReadFile(filepath.Join(ownedArchiveDir, name))
		if err != nil || string(got) != string(want) {
			t.Fatalf("preserved archive %s changed: err=%v", name, err)
		}
	}
	if fi, err := os.Lstat(linkedPath); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("non-regular archive symlink was not preserved: info=%v err=%v", fi, err)
	}
	gotCustom, err := os.ReadFile(customPath)
	if err != nil || string(gotCustom) != legacyAPIAuthConfig10826 {
		t.Fatalf("custom archive destination was changed: err=%v", err)
	}
}

func TestArchiveCleanupFailureIsNonfatalAndRetriesOnLaterLoad10825(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config")
	store := newTestStoreAt(t, path)
	if err := store.db.WriteActive(parseAuthMigrationTree10826(t, legacyAPIAuthConfig10826)); err != nil {
		t.Fatalf("write legacy active: %v", err)
	}
	archivePath := filepath.Join(root, "archive-is-not-a-directory")
	if err := os.WriteFile(archivePath, []byte("temporary blocker"), 0o600); err != nil {
		t.Fatal(err)
	}
	store.SetAPIAuthArchiveMigrationDir(archivePath)
	if err := store.Load(); err != nil {
		t.Fatalf("archive inspection failure must not block active credential migration: %v", err)
	}

	if err := os.Remove(archivePath); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(archivePath, 0o700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(archivePath, "config-20240101-000000.000000000.conf")
	if err := os.WriteFile(archive, []byte(legacyAPIAuthConfig10826), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("later Load retry after archive path recovery: %v", err)
	}
	if _, err := os.Stat(archive); !os.IsNotExist(err) {
		t.Fatalf("archive cleanup did not retry after the path became accessible: %v", err)
	}
}
