package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
)

// postNAT12246Text renders the #12246 VIP-vs-real fixture: destination NAT
// 203.0.113.10:80 -> 10.0.0.5:8080 from untrust, default-policy deny, and the
// supplied untrust->trust policy stanzas.
func postNAT12246Text(policies string) string {
	return `
security {
    address-book {
        global {
            address vip 203.0.113.10/32;
            address server 10.0.0.5/32;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    nat {
        destination {
            pool srv-pool {
                address 10.0.0.5/32 port 8080;
            }
            rule-set rs-dnat {
                from zone untrust;
                rule vip-http {
                    match {
                        destination-address 203.0.113.10/32;
                        destination-port 80;
                    }
                    then {
                        destination-nat pool srv-pool;
                    }
                }
            }
        }
    }
    policies {
        default-policy deny-all;
        from-zone untrust to-zone trust {` + policies + `
        }
    }
}
`
}

// postNAT12246VIPPolicies permits the pre-NAT VIP and denies the real server,
// so a VIP query and the dataplane's post-DNAT decision disagree.
const postNAT12246VIPPolicies = `
            policy permit-vip {
                match { source-address any; destination-address vip; application any; }
                then { permit; }
            }
            policy deny-server {
                match { source-address any; destination-address server; application any; }
                then { deny; }
            }`

// postNAT12246RejectedPolicies names an undefined application. Only the
// tolerant peer-sync ingress admits it; the userspace builder refuses the
// whole snapshot, so every query takes the content-rejected path.
const postNAT12246RejectedPolicies = `
            policy bad-app {
                match { source-address any; destination-address server; application no-such-app; }
                then { deny; }
            }`

// postNAT12246Server commits the VIP-vs-real fixture through the operator
// commit path.
func postNAT12246Server(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(postNAT12246Text(postNAT12246VIPPolicies)); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &Server{store: store}
}

// postNAT12246RejectedServer installs the DNAT fixture with an unrepresentable
// policy through the tolerant peer-sync ingress.
func postNAT12246RejectedServer(t *testing.T) *Server {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(postNAT12246Text(postNAT12246RejectedPolicies), nil); err != nil {
		t.Fatalf("SyncApply() error = %v", err)
	}
	return &Server{store: store}
}

// TestMatchPoliciesCarriesPostNATInputNote12246 pins #12246 on every gRPC
// MatchPolicies return path. The simulator does not perform inbound
// destination NAT, so whenever DNAT is configured each response must carry
// post_nat_input_note; a client must never read a pre-NAT VIP verdict as the
// dataplane's post-DNAT decision.
//
// RED-on-revert: dropping PostNatInputNote from any MatchPolicies return in
// server_cluster.go (content-rejected, host-inbound, unmatched, matched)
// empties the field on that path and the matching subtest fails.
func TestMatchPoliciesCarriesPostNATInputNote12246(t *testing.T) {
	committed := postNAT12246Server(t)
	rejected := postNAT12246RejectedServer(t)
	cases := []struct {
		name    string
		s       *Server
		req     *pb.MatchPoliciesRequest
		premise func(*pb.MatchPoliciesResponse) bool
	}{
		{
			name: "matched",
			s:    committed,
			req: &pb.MatchPoliciesRequest{
				FromZone: "untrust", ToZone: "trust", Protocol: "tcp",
				DestinationIp: "203.0.113.10", DestinationPort: int32Ptr17081(80),
			},
			premise: func(r *pb.MatchPoliciesResponse) bool {
				return r.GetMatched() && r.GetPolicyName() == "permit-vip"
			},
		},
		{
			name: "unmatched default",
			s:    committed,
			req: &pb.MatchPoliciesRequest{
				FromZone: "trust", ToZone: "untrust", Protocol: "tcp",
				DestinationIp: "203.0.113.10", DestinationPort: int32Ptr17081(80),
			},
			premise: func(r *pb.MatchPoliciesResponse) bool {
				return !r.GetMatched() && r.GetDefaultUsed()
			},
		},
		{
			name: "host-inbound unmatched",
			s:    committed,
			req: &pb.MatchPoliciesRequest{
				FromZone: "untrust", ToZone: "junos-host", Protocol: "tcp",
				DestinationPort: int32Ptr17081(22),
			},
			premise: func(r *pb.MatchPoliciesResponse) bool {
				return r.GetHostInboundUnmatched()
			},
		},
		{
			name: "content rejected",
			s:    rejected,
			req: &pb.MatchPoliciesRequest{
				FromZone: "untrust", ToZone: "trust", Protocol: "tcp",
				DestinationIp: "10.0.0.5", DestinationPort: int32Ptr17081(8080),
			},
			premise: func(r *pb.MatchPoliciesResponse) bool {
				return !r.GetMatched() && r.GetAction() == policymatch.ContentRejectedActionString
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := tc.s.MatchPolicies(context.Background(), tc.req)
			if err != nil {
				t.Fatalf("MatchPolicies error = %v", err)
			}
			if !tc.premise(resp) {
				t.Fatalf("PREMISE: fixture did not reach the %s path: %+v", tc.name, resp)
			}
			if got := resp.GetPostNatInputNote(); got != policymatch.PostNATInputRequirementNote {
				t.Errorf("post_nat_input_note = %q, want %q", got, policymatch.PostNATInputRequirementNote)
			}
		})
	}
}

// TestShowTestPolicyPrintsPostNATInputNote12246 pins #12246 on the gRPC-text
// `test policy` renderer (server_show_firewall.go), the backend of the remote
// `cli test policy`: a VIP query against a DNAT config must print the
// post-DNAT input requirement alongside the literal VIP verdict.
//
// RED-on-revert: removing the NOTE print from the test-policy renderer drops
// the line and the assertion fails.
func TestShowTestPolicyPrintsPostNATInputNote12246(t *testing.T) {
	s := postNAT12246Server(t)
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{
		Topic: "test-policy:from=untrust,to=trust,proto=tcp,dst=203.0.113.10,port=80",
	})
	if err != nil {
		t.Fatalf("ShowText error = %v", err)
	}
	out := resp.GetOutput()
	if !strings.Contains(out, "Policy:    permit-vip") {
		t.Fatalf("PREMISE: VIP query did not reach the literal VIP verdict:\n%s", out)
	}
	if !strings.Contains(out, "NOTE: "+policymatch.PostNATInputRequirementNote) {
		t.Fatalf("test-policy output must print the post-DNAT input requirement:\n%s", out)
	}
}
