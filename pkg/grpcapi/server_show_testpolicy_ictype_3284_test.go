package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func icmpTypeTextPolicyStore3284(t *testing.T) *Server {
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
            policy permit-echo-request {
                match { source-address any; destination-address any; application junos-icmp-ping; }
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

// TestShowTestPolicyICMPTypeFlowsToMatcher3284 pins the gRPC-text test-policy
// ictype selector to the shared matcher. The predefined junos-icmp-ping term
// permits only ICMP type 8, so a type-8 query must hit the policy and type 0
// must fall through to the deny-all default.
//
// FAIL-ON-REVERT: removing the ictype ParseICMPValue assignment leaves
// Query.ICMPType nil; the type-8 query then misses the constrained application.
func TestShowTestPolicyICMPTypeFlowsToMatcher3284(t *testing.T) {
	s := icmpTypeTextPolicyStore3284(t)
	for _, tc := range []struct {
		name      string
		topic     string
		wantMatch bool
	}{
		{"echo request", "test-policy:from=trust,to=untrust,src=10.1.2.3,dst=203.0.113.9,proto=icmp,ictype=8", true},
		{"echo reply", "test-policy:from=trust,to=untrust,src=10.1.2.3,dst=203.0.113.9,proto=icmp,ictype=0", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: tc.topic})
			if err != nil {
				t.Fatalf("ShowText(%q) error = %v", tc.topic, err)
			}
			matched := strings.Contains(resp.Output, "Policy match:") &&
				strings.Contains(resp.Output, "permit-echo-request")
			if matched != tc.wantMatch {
				t.Fatalf("ShowText(%q) matched = %v, want %v\noutput: %q", tc.topic, matched, tc.wantMatch, resp.Output)
			}
			if !tc.wantMatch && !strings.Contains(resp.Output, "Default deny") {
				t.Fatalf("non-echo ICMP should fall through to deny-all; output: %q", resp.Output)
			}
		})
	}
}
