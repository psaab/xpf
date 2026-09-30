package configstore

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/scheduler"
)

const junosSchedulerSyncConfig11305 = `schedulers {
    scheduler permit-window {
        daily {
            start-time 08:30;
            stop-time 09:00;
        }
    }
    scheduler deny-window {
        start-date 2026-10-01.08:30;
        stop-date 2026-10-01.09:00;
    }
}
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy scheduled-permit {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { permit; }
                scheduler-name permit-window;
            }
            policy scheduled-deny {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then { deny; }
                scheduler-name deny-window;
            }
        }
    }
}`

func findPolicy11305(t *testing.T, cfg *config.Config, name string) *config.Policy {
	t.Helper()
	for _, zonePair := range cfg.Security.Policies {
		for _, policy := range zonePair.Policies {
			if policy.Name == name {
				return policy
			}
		}
	}
	t.Fatalf("policy %q was not compiled by SyncApply", name)
	return nil
}

func TestSyncApplyJunosNativeSchedulerWindows11305(t *testing.T) {
	store := newTestStore(t)
	cfg, err := store.SyncApply(junosSchedulerSyncConfig11305, nil)
	if err != nil {
		t.Fatalf("SyncApply rejected Junos-native scheduler values: %v", err)
	}
	for _, tc := range []struct {
		policy    string
		action    config.PolicyAction
		scheduler string
	}{
		{"scheduled-permit", config.PolicyPermit, "permit-window"},
		{"scheduled-deny", config.PolicyDeny, "deny-window"},
	} {
		policy := findPolicy11305(t, cfg, tc.policy)
		if policy.Action != tc.action || policy.SchedulerName != tc.scheduler {
			t.Fatalf("policy %q = action %v, scheduler %q; want action %v, scheduler %q",
				tc.policy, policy.Action, policy.SchedulerName, tc.action, tc.scheduler)
		}
	}

	local := time.FixedZone("JunosLocal", -7*60*60)
	for _, tc := range []struct {
		name   string
		hour   int
		minute int
		second int
		want   bool
	}{
		{"before start", 8, 29, 59, false},
		{"inside window", 8, 45, 0, true},
		{"at exclusive stop", 9, 0, 0, false},
	} {
		now := time.Date(2026, 10, 1, tc.hour, tc.minute, tc.second, 0, local)
		_, active := scheduler.NewPrimedInLocation(cfg.Schedulers, nil, now, local)
		for _, name := range []string{"permit-window", "deny-window"} {
			if got := active[name]; got != tc.want {
				t.Errorf("%s at %s: scheduler %q active=%v, want %v",
					tc.name, now.Format(time.RFC3339), name, got, tc.want)
			}
		}
	}
}
