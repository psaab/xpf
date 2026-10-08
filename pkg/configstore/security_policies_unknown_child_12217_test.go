package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const unknownPoliciesChildConfig12217 = `security {
 policies {
  default-policy permit-all;
  global {
   policy g-permit {
    match { source-address any; destination-address any; application any; }
    then { permit; }
   }
  }
  globel {
   policy deny-bad {
    match { source-address any; destination-address any; application any; }
    then { deny; }
   }
  }
 }
}`

func TestLoadQuarantinesUnknownPoliciesChild12217(t *testing.T) {
	tree, errs := config.NewParser(unknownPoliciesChildConfig12217).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: fixture must parse: %v", errs[0])
	}
	path := filepath.Join(t.TempDir(), "config")
	store := newTestStoreAt(t, path)
	schemaErr := store.schemaValidateExpandedTree(tree)
	if schemaErr == nil || !strings.Contains(schemaErr.Error(), "globel") {
		t.Fatalf("strict commit control schema error = %v, want rejection naming globel", schemaErr)
	}
	if !config.IsUnknownSecurityPoliciesChildSchemaError12217(schemaErr) {
		t.Fatalf("strict schema error = %T, want the #12217-specific unknown-policies-child error", schemaErr)
	}
	if err := store.db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("persist fixture: %v", err)
	}
	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("tolerant Store.Load must remain bootable: %v", err)
	}
	cfg := booted.ActiveConfig()
	if cfg == nil {
		t.Fatal("Store.Load returned nil ActiveConfig")
	}
	if got := config.LenientDroppedPolicyLocator(cfg); got == "" {
		t.Fatal("unknown policies child was dropped without a LenientContentDropped poison carrier; with permit-all fallback, the missing deny can fail open")
	}
	joined := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(joined, `"globel"`) || !strings.Contains(joined, "snapshot is refused") {
		t.Fatalf("tolerant Load warning does not durably identify the dropped child and snapshot refusal: %v", cfg.Warnings)
	}
}
