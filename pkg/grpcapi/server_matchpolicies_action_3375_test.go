package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
)

// hostInboundStore commits a config with a defined zone but NO `to-zone
// junos-host` policy and a default deny, so a `to-zone junos-host` query
// resolves to the host-inbound (local delivery) verdict — no transit
// global/default fallback (#3285).
func hostInboundStore(t *testing.T) *configstore.Store {
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
        from-zone trust to-zone untrust {
            policy allow {
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
func unzonedEgressStore(t *testing.T) *configstore.Store {
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

// TestMatchPoliciesHostInboundActionNonBlank pins #3375 on the gRPC surface: a
// `to-zone junos-host` query that matched no host-bound policy must return a
// non-blank, self-describing action equal to the SSOT host-inbound string —
// the SAME string the REST surface returns — instead of an empty action that a
// client renders as "no answer".
//
// RED-on-revert: before #3375 the host-inbound branch returned
// MatchPoliciesResponse{Matched:false, HostInboundUnmatched:true} with Action
// empty, so resp.Action != "" fails (and the exact-string assertion fails).
func TestMatchPoliciesHostInboundActionNonBlank(t *testing.T) {
	store := hostInboundStore(t)
	s := &Server{store: store}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "junos-host",
	})
	if err != nil {
		t.Fatalf("MatchPolicies error = %v", err)
	}
	if !resp.HostInboundUnmatched {
		t.Fatalf("HostInboundUnmatched = false, want true; got %+v", resp)
	}
	if resp.Matched {
		t.Errorf("Matched = true, want false")
	}
	if resp.Action == "" {
		t.Fatalf("Action is BLANK for host-inbound (#3375 regression)")
	}
	if resp.Action != policymatch.HostInboundActionString {
		t.Errorf("Action = %q, want %q", resp.Action, policymatch.HostInboundActionString)
	}
	if resp.DefaultUsed {
		t.Errorf("DefaultUsed = true, want false (host path has no default fallback)")
	}
}

// TestMatchPoliciesUnzonedEgress exposes the #11067 cause as a typed gRPC
// field and does not misattribute the deny to permit-all.
func TestMatchPoliciesUnzonedEgress(t *testing.T) {
	s := &Server{store: unzonedEgressStore(t)}
	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "nowhere",
	})
	if err != nil {
		t.Fatalf("MatchPolicies error = %v", err)
	}
	if resp.Matched || resp.Action != policymatch.UnzonedEgressActionString {
		t.Fatalf("unknown ToZone must report the unzoned-egress deny, got %+v", resp)
	}
	if !resp.UnzonedEgress || resp.DefaultUsed {
		t.Fatalf("UnzonedEgress=%v DefaultUsed=%v, want true/false", resp.UnzonedEgress, resp.DefaultUsed)
	}
}

// TestMatchPoliciesNilConfigDefaultDeny pins #3375 on the gRPC surface: with no
// active config the verdict must be the explicit fail-closed default deny with
// a typed default_used bit, not an empty response a client reads as "no answer".
//
// RED-on-revert: before #3375 the nil-config branch returned an empty
// MatchPoliciesResponse{} (Action == "", DefaultUsed == false), so both
// assertions fail.
func TestMatchPoliciesNilConfigDefaultDeny(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	s := &Server{store: store}
	if store.ActiveConfig() != nil {
		t.Skip("active config is not nil; nil-config path not exercised")
	}

	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "untrust",
	})
	if err != nil {
		t.Fatalf("MatchPolicies error = %v", err)
	}
	if resp.Action != "deny (default)" {
		t.Errorf("Action = %q, want %q", resp.Action, "deny (default)")
	}
	if !resp.DefaultUsed {
		t.Errorf("DefaultUsed = false, want true (no-config fail-closed default deny)")
	}
}

// TestMatchPoliciesDefaultUsedTyped pins the typed default_used bit (#3375) for
// a real config whose query falls through to the default-policy: the bit is set
// AND the string still carries the " (default)" suffix.
//
// RED-on-revert: before #3375 MatchPoliciesResponse had no default_used field,
// so DefaultUsed is the zero value and the assertion fails.
func TestMatchPoliciesDefaultUsedTyped(t *testing.T) {
	store := hostInboundStore(t)
	s := &Server{store: store}

	// untrust->trust has no policy; falls through to default deny-all.
	resp, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "untrust", ToZone: "trust",
	})
	if err != nil {
		t.Fatalf("MatchPolicies error = %v", err)
	}
	if resp.Matched {
		t.Fatalf("Matched = true, want false (no rule, default deny)")
	}
	if !resp.DefaultUsed {
		t.Errorf("DefaultUsed = false, want true (default-policy verdict)")
	}
	if resp.Action != "deny (default)" {
		t.Errorf("Action = %q, want %q", resp.Action, "deny (default)")
	}
}
