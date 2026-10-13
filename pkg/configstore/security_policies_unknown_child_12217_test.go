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

func TestLoadKeepsPolicySnapshotForJunosValidTraceoptions12628(t *testing.T) {
	text := `security {
 zones {
  security-zone trust;
  security-zone untrust;
 }
 policies {
  default-policy deny-all;
  from-zone trust to-zone untrust {
   policy valid-permit {
    match { source-address any; destination-address any; application any; }
    then { permit; }
   }
  }
  traceoptions { file policies.log; }
 }
}`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse fixture: %v", errs[0])
	}
	path := filepath.Join(t.TempDir(), "config")
	store := newTestStoreAt(t, path)
	if err := store.db.WriteActiveMarker(tree, true); err != nil {
		t.Fatalf("persist fixture: %v", err)
	}
	booted := newTestStoreAt(t, path)
	if err := booted.Load(); err != nil {
		t.Fatalf("tolerant Store.Load: %v", err)
	}
	cfg := booted.ActiveConfig()
	if cfg == nil {
		t.Fatal("Store.Load returned nil ActiveConfig")
	}
	if got := config.LenientDroppedPolicyLocator(cfg); got != "" {
		t.Fatalf("Junos-valid traceoptions blacked out policy snapshot at %q", got)
	}
	if len(cfg.Security.Policies) != 1 || len(cfg.Security.Policies[0].Policies) != 1 {
		t.Fatalf("valid policy snapshot was not retained: %+v", cfg.Security.Policies)
	}
	joined := strings.Join(cfg.Warnings, "\n")
	if !strings.Contains(joined, "traceoptions") || !strings.Contains(joined, "#12628") {
		t.Fatalf("tolerant Load warning does not identify compatibility handling: %v", cfg.Warnings)
	}
}

const unknownPoliciesChildrenSyncApplyConfig12217 = `security {
 policies {
  globel { policy deny-bad { then { deny; } } }
  from-zon { x; }
 }
}`

func TestStoreSyncApplyQuarantinesUnknownPoliciesChildren12217(t *testing.T) {
	store := newTestStore(t)
	compiled, err := store.SyncApply(unknownPoliciesChildrenSyncApplyConfig12217, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected tolerated unknown policy children: %v", err)
	}
	if got := config.LenientDroppedPolicyLocator(compiled); got == "" {
		t.Fatal("SyncApply omitted the unknown-policies poison carrier locator")
	}
	joined := strings.Join(compiled.Warnings, "\n")
	for _, keyword := range []string{"globel", "from-zon"} {
		if !strings.Contains(joined, `"`+keyword+`"`) {
			t.Errorf("SyncApply warnings do not name %q: %v", keyword, compiled.Warnings)
		}
	}

	tree, errs := config.NewParser(unknownPoliciesChildrenSyncApplyConfig12217).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse strict control: %v", errs[0])
	}
	if _, err := store.compileTree(tree); err == nil ||
		!config.IsUnknownSecurityPoliciesChildSchemaError12217(err) ||
		!strings.Contains(err.Error(), "globel") {
		t.Fatalf("strict compileTree error = %v, want typed rejection naming globel", err)
	}
}
