package daemon

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
)

// This is the shape sent by a pre-#10826 primary: credentials are still
// cleartext on the wire, while SyncApply persists tagged verifiers locally.
const legacyAPIAuthConfig10825 = `system {
 host-name legacy-auth;
 services {
  web-management {
   api-auth {
    expires 2099-01-01;
    user admin { password correct-horse-battery; }
    api-key machine-generated-key-alpha;
    key automation { secret automation-key-secret-alpha; }
   }
  }
 }
}`

func TestHandleConfigSync_LegacyAPIAuthDuplicateSkipsRehash10825(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	applyCalls := 0
	d := &Daemon{
		store:    store,
		applySem: semaphore.NewWeighted(1),
		applyBodyForTest: func(*config.Config) {
			applyCalls++
		},
	}

	if err := d.handleConfigSync(legacyAPIAuthConfig10825); err != nil {
		t.Fatalf("first legacy config sync: %v", err)
	}
	if applyCalls != 1 {
		t.Fatalf("first legacy config sync apply calls = %d, want 1", applyCalls)
	}
	activeAfterFirst := store.ShowActive()
	if !strings.Contains(activeAfterFirst, "$xpf-bcrypt$") ||
		strings.Contains(activeAfterFirst, "correct-horse-battery") ||
		strings.Contains(activeAfterFirst, "machine-generated-key-alpha") ||
		strings.Contains(activeAfterFirst, "automation-key-secret-alpha") {
		t.Fatalf("first sync did not persist tagged API-auth verifiers without cleartext:\n%s", activeAfterFirst)
	}

	// The old primary sends the same plaintext again. It is equivalent to the
	// successfully applied active tree, so no apply or fresh bcrypt salt is
	// generated on the receiver.
	if err := d.handleConfigSync(legacyAPIAuthConfig10825); err != nil {
		t.Fatalf("duplicate legacy config sync: %v", err)
	}
	if applyCalls != 1 {
		t.Fatalf("duplicate legacy config sync apply calls = %d, want 1 (must skip)", applyCalls)
	}
	if got := store.ShowActive(); got != activeAfterFirst {
		t.Fatalf("duplicate legacy config sync churned active verifier(s):\nfirst:\n%s\nsecond:\n%s", activeAfterFirst, got)
	}

	// A different cleartext credential does not verify against the active
	// verifier and must take the ordinary sync/apply path.
	changedSecret := strings.ReplaceAll(legacyAPIAuthConfig10825,
		"correct-horse-battery", "different-horse-password")
	if err := d.handleConfigSync(changedSecret); err != nil {
		t.Fatalf("changed-secret config sync: %v", err)
	}
	if applyCalls != 2 {
		t.Fatalf("changed-secret config sync apply calls = %d, want 2", applyCalls)
	}
	activeCfg := store.ActiveConfig()
	if activeCfg == nil || activeCfg.System.Services.WebManagement == nil ||
		activeCfg.System.Services.WebManagement.APIAuth == nil ||
		len(activeCfg.System.Services.WebManagement.APIAuth.Users) != 1 ||
		!config.VerifyAPIAuthSecret(
			activeCfg.System.Services.WebManagement.APIAuth.Users[0].Password.Reveal(),
			"different-horse-password") {
		t.Fatal("changed-secret config was not installed as a usable API-auth verifier")
	}

	// Keep the accepted new credential but change unrelated configuration. This
	// too must not be mistaken for an equivalent credential-only re-push.
	changedNonSecret := strings.ReplaceAll(changedSecret, "legacy-auth", "legacy-auth-updated")
	if err := d.handleConfigSync(changedNonSecret); err != nil {
		t.Fatalf("changed-nonsecret config sync: %v", err)
	}
	if applyCalls != 3 {
		t.Fatalf("changed-nonsecret config sync apply calls = %d, want 3", applyCalls)
	}
	if !strings.Contains(store.ShowActive(), "host-name legacy-auth-updated;") {
		t.Fatalf("changed noncredential content was not installed:\n%s", store.ShowActive())
	}
}

func TestHandleConfigSync_LegacyAPIAuthFailedApplyRetries10825(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	applyCalls := 0
	d := &Daemon{
		store:    store,
		applySem: semaphore.NewWeighted(1),
		applyBodyForTest: func(*config.Config) {
			applyCalls++
		},
	}

	// A failed first apply promotes and hashes the active config, but must not
	// arm ActiveApplied. An identical legacy plaintext delivery therefore has
	// to retry the apply rather than use the equivalence shortcut.
	d.applyErrForTest = errors.New("transient apply failure")
	if err := d.handleConfigSync(legacyAPIAuthConfig10825); err == nil {
		t.Fatal("first legacy config sync: expected the injected apply failure")
	}
	if applyCalls != 1 {
		t.Fatalf("failed first sync apply calls = %d, want 1", applyCalls)
	}
	if store.ActiveApplied() {
		t.Fatal("failed first sync must not report the active config as applied")
	}

	d.applyErrForTest = nil
	if err := d.handleConfigSync(legacyAPIAuthConfig10825); err != nil {
		t.Fatalf("retrying legacy config sync: %v", err)
	}
	if applyCalls != 2 {
		t.Fatalf("same-plaintext retry apply calls = %d, want 2", applyCalls)
	}
	if !store.ActiveApplied() {
		t.Fatal("successful retry must mark the active config applied")
	}
}
