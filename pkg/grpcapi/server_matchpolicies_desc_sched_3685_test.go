package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// descSchedGRPCStore commits a trust->untrust PERMIT carrying both a
// `description` (#3685 M05) and a `scheduler-name` binding (#3685 M06), with
// default-policy deny and the scheduler "workhours" defined.
func descSchedGRPCStore(t *testing.T) *configstore.Store {
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
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone untrust {
            policy allow-web {
                description "CHG-4242 web access";
                match { source-address any; destination-address any; application any; }
                then { permit; }
                scheduler-name workhours;
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

// TestMatchPoliciesResponseCarriesDescriptionAndScheduler pins #3685 M05+M06 on
// the gRPC MatchPolicies surface: a positive verdict must carry the matched
// policy's description (M05) and its scheduler binding + effective-active flag
// (M06), mirroring the inventory and the local CLI result over the same
// policymatch.Result.
//
// RED-on-revert: before #3685 MatchPoliciesResponse had no description /
// scheduler_name / scheduler_active fields; dropping the population in
// server_cluster.go (or reverting the proto additions) zeroes them and every
// assertion below fails. Removing the SchedulerName copy in
// policymatch.matchedResult also flips scheduler_name/scheduler_active red.
func TestMatchPoliciesResponseCarriesDescriptionAndScheduler(t *testing.T) {
	s := &Server{store: descSchedGRPCStore(t)}
	// The compatibility fake exposes active state only; the test uses the
	// active scheduler as a positive control for the name-only fallback.
	s.dp = &schedulerStateDP{Manager: dataplane.New(), active: map[string]bool{"workhours": true}}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone:        "trust",
		ToZone:          "untrust",
		Protocol:        "tcp",
		DestinationPort: 80,
	})
	if err != nil {
		t.Fatalf("MatchPolicies error = %v", err)
	}
	if !resp.Matched {
		t.Fatalf("expected match, got %+v", resp)
	}
	if resp.GetDescription() != "CHG-4242 web access" {
		t.Errorf("description = %q, want %q (M05)", resp.GetDescription(), "CHG-4242 web access")
	}
	if resp.GetSchedulerName() != "workhours" {
		t.Errorf("scheduler_name = %q, want %q (M06)", resp.GetSchedulerName(), "workhours")
	}
	if !resp.GetSchedulerActive() {
		t.Errorf("scheduler_active = false, want true (M06 — a matched scheduled policy is currently active)")
	}
}

// globalDescPolicyStore commits a GLOBAL described PERMIT (scoped to
// from-zone trust) with default-policy deny, so a trust->untrust flow matches
// the global rule. Used by the M04 gRPC-text `test policy` global-branch test.
func globalDescPolicyStore(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        global {
            policy g-allow {
                description "CHG-7 global allow";
                match { source-address any; destination-address any; application any; from-zone trust; }
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
	return &Server{store: store}
}

// TestShowTestPolicyGlobalCarriesIDScopeDescription pins #3685 M04: the
// gRPC-text `test policy` renderer (server_show_firewall.go, the remote `cli`
// backend) for a GLOBAL match must print the policy ID, the global match scope,
// and the description — mirroring `show security match-policies` — instead of
// the pre-#3685 name+action-only output.
//
// RED-on-revert: reverting the global branch to the two-line
// "Policy:" / "Action:" form drops the "Policy ID:", "Scope:     global", and
// "Description:" lines, flipping the Contains assertions red.
func TestShowTestPolicyGlobalCarriesIDScopeDescription(t *testing.T) {
	s := globalDescPolicyStore(t)
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{
		Topic: "test-policy:from=trust,to=untrust,proto=tcp,port=80",
	})
	if err != nil {
		t.Fatalf("ShowText error = %v", err)
	}
	out := resp.Output
	if !strings.Contains(out, "Policy match (global):") {
		t.Fatalf("output missing global match header:\n%s", out)
	}
	for _, want := range []string{
		"Policy:    g-allow",
		"Policy ID:",
		"Scope:     global (match from-zone: trust, to-zone: any)",
		"Description: CHG-7 global allow",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q (M04):\n%s", want, out)
		}
	}
}
