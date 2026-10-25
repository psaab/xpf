package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #3684: the `show security zones detail` policy summary (#3658) was a
// name+action-only renderer. It omitted the per-rule inventory metadata the
// REST/gRPC surfaces already carry — runtime policy id (M11), scheduler binding
// + runtime-inactive state (H03/#3624), the log/count/address-exclusion
// modifiers (M12), and the default-policy log posture + sentinel id (M13) — so
// a zone-centric audit could not express scheduler state, join a rule to a
// policy_id, or see logging/inversion intent. These tests are the L06
// fail-on-revert guards: reverting the metadata thread in
// policymatch.ZoneDetailPolicySummary back to name+action makes them go RED.

// metadataZoneCLIStore builds a config whose zone `untrust` has a
// scheduler-bound zone-pair policy (rendered inactive here), a zone-pair policy
// carrying log + count + source-address-excluded, and a scheduler-bound global
// policy. default-policy is permit-all with default-policy-log session-init so
// the default catch-all line carries a log posture (M13).
func metadataZoneCLIStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
schedulers {
    scheduler workhours {
        daily;
    }
}
security {
    address-book {
        global {
            address net10 10.0.0.0/8;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy sched-off {
                match { source-address any; destination-address any; application any; }
                then { permit; }
                scheduler-name workhours;
            }
            policy logged-rule {
                match {
                    source-address net10;
                    source-address-excluded;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                    log { session-init; session-close; }
                    count;
                }
            }
        }
        global {
            policy g-sched-off {
                match { source-address any; destination-address any; application any; }
                then { deny; }
                scheduler-name workhours;
            }
        }
        default-policy-log {
            session-init;
        }
        default-policy permit-all;
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

// TestCLIZoneDetailPolicyMetadata is the #3684 fail-on-revert guard for the
// local CLI zone-detail policy summary.
func TestCLIZoneDetailPolicyMetadata(t *testing.T) {
	store := metadataZoneCLIStore(t)
	c := &CLI{
		store: store,
		dp: &schedulerStateDP{
			Manager: dataplane.New(),
			active:  map[string]bool{"workhours": false}, // scheduler runtime-inactive
		},
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}

	out := captureStdout(t, func() {
		if err := c.showZonesDisplay(cfg, true, "untrust"); err != nil {
			t.Fatalf("showZonesDisplay(detail, untrust): %v", err)
		}
	})
	block := zoneDetailBlock(t, out, "untrust")

	// H03: the scheduler-bound zone-pair policy is runtime-inactive — the
	// summary must mark it, not list it as an active participant.
	if !strings.Contains(block, "[zone-pair] trust -> untrust: sched-off (permit) [id 0, scheduler workhours (inactive)]") {
		t.Fatalf("zone-pair scheduler-inactive row missing/incorrect (H03):\n%s", block)
	}
	// M11 + M12: the logged/counted/excluded rule carries its runtime id, log
	// modes, count, and the source-address (except) inversion annotation.
	if !strings.Contains(block, "[zone-pair] trust -> untrust: logged-rule (permit) [id 1, log at-create,at-close, count, source-address (except)]") {
		t.Fatalf("zone-pair log/count/excluded row missing metadata (M11/M12):\n%s", block)
	}
	// H03 on the GLOBAL tier: a scheduler-inactive global is marked too. The
	// global tier's runtime id lives in the policy-set namespace AFTER the
	// zone-pair sets (contiguous id, #16560), matching the
	// span-accumulated id the RT_FLOW/inventory path assigns.
	if !strings.Contains(block, "[global] any -> any: g-sched-off (deny) [id 2, scheduler workhours (inactive)]") {
		t.Fatalf("global scheduler-inactive row missing/incorrect (H03):\n%s", block)
	}
	// M13: the default-policy catch-all carries the reserved sentinel id and
	// the default-policy log posture.
	if !strings.Contains(block, "[default] default-policy: permit [id 4294967295, log at-create]") {
		t.Fatalf("default-policy row missing sentinel id / log posture (M13):\n%s", block)
	}
}

// TestCLIZoneDetailPolicyMetadataActiveScheduler asserts the mirror: when the
// scheduler is runtime-active the (inactive) marker is absent, so the marker
// tracks real runtime state rather than merely the presence of a scheduler.
func TestCLIZoneDetailPolicyMetadataActiveScheduler(t *testing.T) {
	store := metadataZoneCLIStore(t)
	c := &CLI{
		store: store,
		dp: &schedulerStateDP{
			Manager: dataplane.New(),
			active:  map[string]bool{"workhours": true}, // scheduler runtime-active
		},
	}
	cfg := store.ActiveConfig()

	out := captureStdout(t, func() {
		if err := c.showZonesDisplay(cfg, true, "untrust"); err != nil {
			t.Fatalf("showZonesDisplay(detail, untrust): %v", err)
		}
	})
	block := zoneDetailBlock(t, out, "untrust")

	if strings.Contains(block, "(inactive)") {
		t.Fatalf("active scheduler must not render (inactive):\n%s", block)
	}
	// The scheduler binding is still surfaced (just without the inactive tag).
	if !strings.Contains(block, "[zone-pair] trust -> untrust: sched-off (permit) [id 0, scheduler workhours]") {
		t.Fatalf("active scheduler-bound row missing scheduler binding:\n%s", block)
	}
}
