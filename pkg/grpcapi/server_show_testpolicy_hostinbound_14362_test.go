package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// hostInboundTextPolicyStore14362 builds a config for the #14362 gRPC-text
// `test policy` surface: `trust` admits only ssh host-inbound, and a
// `trust -> junos-host` permit-all fine policy exists, so a matched permit
// whose coarse gate denies (tcp/23) is the false-permit shape from the issue.
func hostInboundTextPolicyStore14362(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    zones {
        security-zone trust {
            host-inbound-traffic {
                system-services {
                    ssh;
                }
            }
        }
        security-zone untrust;
    }
    policies {
        default-policy deny-all;
        from-zone trust to-zone junos-host {
            policy allow-host {
                match { source-address any; destination-address any; application any; }
                then { permit; }
            }
        }
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
	return &Server{store: store}
}

// TestShowTestPolicyHostInboundVerdict14362 pins #14362 on the gRPC-text
// `test policy` surface: showTestPolicy computed res.HostInbound (the
// ingress-interface selector was wired in by #5579) but never rendered it —
// a matched junos-host permit denied by the coarse gate read as a plain
// permit, the unmatched branch printed only the generic HostInboundShowLine,
// and the RouteDropNote advisory the local surfaces print was dropped.
//
// RED-on-revert: removing the HostInbound Describe() lines makes the
// "host-inbound-traffic (zone trust): DENIED ..." assertions fail; removing
// the RouteDropNote print makes the multicast-destination assertion fail.
func TestShowTestPolicyHostInboundVerdict14362(t *testing.T) {
	s := hostInboundTextPolicyStore14362(t)

	t.Run("matched permit names coarse deny", func(t *testing.T) {
		resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{
			Topic: "test-policy:from=trust,to=junos-host,proto=tcp,port=23",
		})
		if err != nil {
			t.Fatalf("ShowText error = %v", err)
		}
		if !strings.Contains(resp.Output, "allow-host") || !strings.Contains(resp.Output, "permit") {
			t.Fatalf("matched junos-host policy must render; output: %q", resp.Output)
		}
		if !strings.Contains(resp.Output, "host-inbound-traffic (zone trust): DENIED") {
			t.Fatalf("matched permit must name the coarse host-inbound deny (#14362); output: %q", resp.Output)
		}
	})

	t.Run("unmatched names coarse deny", func(t *testing.T) {
		// untrust has no host-inbound stanza and no junos-host policy.
		resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{
			Topic: "test-policy:from=untrust,to=junos-host,proto=tcp,port=22",
		})
		if err != nil {
			t.Fatalf("ShowText error = %v", err)
		}
		if !strings.Contains(resp.Output, "No matching to-zone junos-host policy") {
			t.Fatalf("unmatched host query must render the host header; output: %q", resp.Output)
		}
		if !strings.Contains(resp.Output, "host-inbound-traffic (zone untrust): DENIED") {
			t.Fatalf("unmatched must name the coarse host-inbound deny (#14362); output: %q", resp.Output)
		}
	})

	t.Run("route drop note rendered", func(t *testing.T) {
		resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{
			Topic: "test-policy:from=trust,to=untrust,src=10.0.0.1,dst=224.0.0.1,proto=tcp,port=80",
		})
		if err != nil {
			t.Fatalf("ShowText error = %v", err)
		}
		if !strings.Contains(resp.Output, "route-drop advisory:") {
			t.Fatalf("multicast destination must render the RouteDropNote advisory (#14362); output: %q", resp.Output)
		}
	})
}
