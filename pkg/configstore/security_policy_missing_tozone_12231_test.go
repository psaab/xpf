package configstore

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestStoreLoadRecordsToZoneLessFromZone12231(t *testing.T) {
	const text = `security {
    zones { security-zone A; security-zone B; }
    policies {
        from-zone {
            A {
                policy p1 {
                    match { source-address any; destination-address any; application any; }
                    then { deny; }
                }
            }
        }
        global {
            policy g-permit {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
        default-policy permit-all;
    }
}`
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse persisted config: %v", errs)
	}

	store := newTestStoreAt(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.db.WriteActive(tree); err != nil {
		t.Fatalf("write active config: %v", err)
	}
	if err := store.Load(); err != nil {
		t.Fatalf("Store.Load must remain bootable for the legacy config: %v", err)
	}
	active := store.ActiveConfig()
	if active == nil {
		t.Fatal("ActiveConfig is nil after Store.Load")
	}
	if len(active.Security.Policies) != 0 {
		t.Fatalf("Store.Load installed %d zone pairs from a context with no to-zone", len(active.Security.Policies))
	}
	if len(active.Security.MalformedZonePairs) != 1 {
		t.Fatalf("Store.Load did not record the missing-to-zone context on ActiveConfig: %q", active.Security.MalformedZonePairs)
	}
	if got := config.LenientDroppedPolicyLocator(active); got == "" {
		t.Fatal("Store.Load did not retain the poison carrier for the dropped deny; snapshot may fall through to permit-all")
	}
	if warnings := strings.Join(active.Warnings, "\n"); !strings.Contains(warnings, "not enforced") || !strings.Contains(warnings, "snapshot is refused") {
		t.Fatalf("Store.Load warning does not surface fail-closed handling: %v", active.Warnings)
	}
}
