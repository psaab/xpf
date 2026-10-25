package grpcapi

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #3684: the gRPC-text `show security zones detail` policy summary (#3658) was
// a name+action-only renderer, dropping the per-rule inventory metadata the
// structured GetPolicies surface already carries — runtime policy id (M11),
// scheduler binding + runtime-inactive state (H03/#3624), the
// log/count/address-exclusion modifiers (M12), and the default-policy log
// posture + sentinel id (M13). It is now rendered via the shared
// policymatch.ZoneDetailPolicySummary SSOT (L10), so its output is byte-
// identical to the local-CLI peer. This is the gRPC fail-on-revert guard.

// metadataZoneGRPCServer mirrors metadataZoneCLIStore: a scheduler-bound
// zone-pair policy (rendered inactive), a zone-pair policy with
// log+count+source-address-excluded, a scheduler-bound global, and
// default-policy permit-all with default-policy-log session-init.
func metadataZoneGRPCServer(t *testing.T, active map[string]bool) *Server {
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
	s := &Server{store: store}
	s.dp = &schedulerStateDP{Manager: dataplane.New(), active: active}
	return s
}

// TestGRPCZoneDetailPolicyMetadata is the #3684 fail-on-revert guard for the
// gRPC-text zone-detail policy summary. The expected lines are byte-identical
// to the local-CLI TestCLIZoneDetailPolicyMetadata (shared SSOT, L10).
func TestGRPCZoneDetailPolicyMetadata(t *testing.T) {
	s := metadataZoneGRPCServer(t, map[string]bool{"workhours": false})

	var buf strings.Builder
	s.showZonesDetail(s.store.ActiveConfig(), "", &buf)
	out := buf.String()

	for _, want := range []string{
		// H03: scheduler-inactive zone-pair row.
		"[zone-pair] trust -> untrust: sched-off (permit) [id 0, scheduler workhours (inactive)]",
		// M11 + M12: id, log modes, count, source-address (except).
		"[zone-pair] trust -> untrust: logged-rule (permit) [id 1, log at-create,at-close, count, source-address (except)]",
		// H03 on the global tier (id in the post-zone-pair namespace).
		"[global] any -> any: g-sched-off (deny) [id 2, scheduler workhours (inactive)]",
		// M13: default-policy sentinel id + log posture.
		"[default] default-policy: permit [id 4294967295, log at-create]",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("gRPC zone-detail missing %q:\n%s", want, out)
		}
	}
}

// TestGRPCZoneDetailPolicyMetadataActiveScheduler asserts the (inactive) marker
// tracks runtime state, not merely the presence of a scheduler binding.
func TestGRPCZoneDetailPolicyMetadataActiveScheduler(t *testing.T) {
	s := metadataZoneGRPCServer(t, map[string]bool{"workhours": true})

	var buf strings.Builder
	s.showZonesDetail(s.store.ActiveConfig(), "", &buf)
	out := buf.String()

	if strings.Contains(out, "(inactive)") {
		t.Fatalf("active scheduler must not render (inactive):\n%s", out)
	}
	if !strings.Contains(out, "[zone-pair] trust -> untrust: sched-off (permit) [id 0, scheduler workhours]") {
		t.Fatalf("active scheduler-bound row missing scheduler binding:\n%s", out)
	}
}
