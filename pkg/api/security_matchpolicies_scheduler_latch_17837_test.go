package api

import (
	"net/url"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

func schedulerLatchAPIStore17837(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
schedulers {
    scheduler after-hours {
        daily;
    }
}
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy scheduled-deny {
                match { source-address any; destination-address any; application any; }
                then { deny; }
                scheduler-name after-hours;
            }
            policy later-permit {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestMatchPoliciesRESTKeepsLatchedDeny17837 proves REST /security/match uses
// the snapshot-applied scheduler state and fail-closed latch. The runtime keeps
// this scheduled deny eligible and cannot reach the later permit.
func TestMatchPoliciesRESTKeepsLatchedDeny17837(t *testing.T) {
	s := &Server{store: schedulerLatchAPIStore17837(t)}
	s.policySchedAppliedFn = func() (map[string]bool, bool) {
		return map[string]bool{"after-hours": false}, true
	}
	res := matchAction(t, s, url.Values{
		"from_zone": {"trust"},
		"to_zone":   {"untrust"},
		"protocol":  {"tcp"},
		"dst_port":  {"80"},
	})
	if !res.Data.Matched || res.Data.Action != "deny" {
		t.Fatalf("REST match = %+v, want latched scheduled deny (not later permit)", res.Data)
	}
	if res.Data.DefaultUsed {
		t.Fatalf("REST match default_used = true; got %+v", res.Data)
	}
}
