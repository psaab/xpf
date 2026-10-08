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
