package configstore

import (
	"strings"
	"testing"
)

func TestStoreSyncApplyWarnsAboutUnknownHostInboundChild12219(t *testing.T) {
	store := newTestStore(t)
	compiled, err := store.SyncApply(`security {
    zones {
        security-zone trust {
            host-inbound-traffic {
                system-service ssh;
            }
        }
    }
}`, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected tolerated unknown host-inbound child: %v", err)
	}
	for _, warning := range compiled.Warnings {
		if strings.Contains(warning, `security zone "trust" host-inbound-traffic`) &&
			strings.Contains(warning, `unknown child keyword "system-service"`) {
			return
		}
	}
	t.Fatalf("SyncApply warnings do not retain the unknown host-inbound child: %v", compiled.Warnings)
}

func TestStoreCompactUnknownHostInboundChild12219(t *testing.T) {
	const content = `security {
    zones {
        security-zone trust {
            host-inbound-traffic system-service ssh;
        }
    }
}`

	t.Run("LoadOverride and Commit reject", func(t *testing.T) {
		store := newTestStore(t)
		if err := store.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := store.LoadOverride(content); err != nil {
			t.Fatalf("LoadOverride: %v", err)
		}
		if _, err := store.Commit(); err == nil ||
			!strings.Contains(err.Error(), `unknown child keyword "system-service"`) {
			t.Fatalf("Commit error = %v, want strict rejection naming system-service", err)
		}
	})

	t.Run("SyncApply warns", func(t *testing.T) {
		store := newTestStore(t)
		compiled, err := store.SyncApply(content, nil)
		if err != nil {
			t.Fatalf("SyncApply rejected tolerated compact unknown child: %v", err)
		}
		for _, warning := range compiled.Warnings {
			if strings.Contains(warning, `security zone "trust" host-inbound-traffic`) &&
				strings.Contains(warning, `unknown child keyword "system-service"`) {
				return
			}
		}
		t.Fatalf("SyncApply warnings do not retain compact unknown child: %v", compiled.Warnings)
	})
}
