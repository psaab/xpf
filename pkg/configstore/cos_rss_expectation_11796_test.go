package configstore

import (
	"strings"
	"testing"
)

func TestSyncApplyRSSExpectationMalformedQueueWarns11796(t *testing.T) {
	const peerConfig = `
class-of-service {
    fairness {
        rss-expectation {
            interface ge-0/0/2 {
                queue invalid { balanced; }
                queue 7 { balanced; }
            }
        }
    }
}
system { dataplane-type userspace; }
`
	cfg, err := newTestStore(t).SyncApply(peerConfig, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected a malformed legacy RSS expectation: %v", err)
	}
	if cfg == nil {
		t.Fatal("SyncApply returned nil config")
	}
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "rss-expectation") && strings.Contains(warning, `queue "invalid"`) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("SyncApply produced no malformed RSS queue warning: %v", cfg.Warnings)
	}
	got := cfg.ClassOfService.FairnessExpectations
	if len(got) != 1 || got[0].QueueID != 7 || got[0].RSSExpectation != "balanced" {
		t.Fatalf("SyncApply expectations = %#v, want only the valid queue 7 expectation", got)
	}
}
