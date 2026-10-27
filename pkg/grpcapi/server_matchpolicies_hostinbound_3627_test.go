package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/policymatch"
)

// hostInboundAdmitStore commits a config whose ingress zone `trust` carries a
// host-inbound-traffic stanza (system-services ssh + ping, protocols bgp) and a
// `untrust` zone with NO stanza (post-#3405 default-deny). No `to-zone
// junos-host` policy exists, so a host-bound query resolves to the host-inbound
// verdict and the #3627 B1a classifier names the admitting token.
func hostInboundAdmitStore(t *testing.T) *configstore.Store {
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
                    ping;
                }
                protocols {
                    bgp;
                }
            }
        }
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

// TestMatchPoliciesGRPCHostInboundToken pins #3627 B1a on the gRPC surface: a
// `to-zone junos-host` query returns the structured host_inbound admission
// (WHICH system-service/protocol token admits the tuple, or deny/global-accept),
// mirroring the local CLI `show security match-policies` host-inbound line
// (#4352). An off-host query carries NO host_inbound (nil).
//
// It also proves CLI/gRPC value-parity: the response's host_inbound must carry
// the SAME status/token/kind/description as the shared policymatch.Result.
// HostInbound (the exact object the local CLI renders), because all three read
// the same SSOT-backed classifier (#3375).
//
// RED-on-revert: dropping the HostInbound assignment from the host-inbound
// branch in server_cluster.go leaves resp.HostInbound nil and the token
// assertion fails.
func TestMatchPoliciesGRPCHostInboundToken(t *testing.T) {
	store := hostInboundAdmitStore(t)
	s := &Server{store: store}
	cfg := store.ActiveConfig()

	cases := []struct {
		name       string
		req        *pb.MatchPoliciesRequest
		wantStatus pb.HostInboundAdmissionStatus
		wantToken  string
		wantKind   string
	}{
		{
			name:       "ssh token-admit",
			req:        &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "junos-host", Protocol: "tcp", DestinationPort: int32Ptr17081(22), DestinationIp: "10.0.1.10"},
			wantStatus: pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_TOKEN_ADMIT,
			wantToken:  "ssh",
			wantKind:   "system-services",
		},
		{
			name:       "bgp protocols token-admit",
			req:        &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "junos-host", Protocol: "tcp", DestinationPort: int32Ptr17081(179), DestinationIp: "10.0.1.10"},
			wantStatus: pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_TOKEN_ADMIT,
			wantToken:  "bgp",
			wantKind:   "protocols",
		},
		{
			name:       "esp global-accept",
			req:        &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "junos-host", Protocol: "esp", DestinationIp: "10.0.1.10"},
			wantStatus: pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_GLOBAL_ACCEPT,
		},
		{
			name:       "telnet denied",
			req:        &pb.MatchPoliciesRequest{FromZone: "trust", ToZone: "junos-host", Protocol: "tcp", DestinationPort: int32Ptr17081(23), DestinationIp: "10.0.1.10"},
			wantStatus: pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_DENIED,
		},
		{
			name:       "untrust no-stanza denied",
			req:        &pb.MatchPoliciesRequest{FromZone: "untrust", ToZone: "junos-host", Protocol: "tcp", DestinationPort: int32Ptr17081(22), DestinationIp: "10.0.1.10"},
			wantStatus: pb.HostInboundAdmissionStatus_HOST_INBOUND_ADMISSION_STATUS_DENIED,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, err := s.MatchPolicies(context.Background(), c.req)
			if err != nil {
				t.Fatalf("MatchPolicies error = %v", err)
			}
			if !resp.HostInboundUnmatched {
				t.Fatalf("host_inbound_unmatched = false, want true; got %+v", resp)
			}
			if resp.HostInbound == nil {
				t.Fatalf("host_inbound is nil (#3627 B1a regression); want status %v", c.wantStatus)
			}
			if resp.HostInbound.Status != c.wantStatus {
				t.Errorf("status = %v, want %v", resp.HostInbound.Status, c.wantStatus)
			}
			if resp.HostInbound.Token != c.wantToken || resp.HostInbound.Kind != c.wantKind {
				t.Errorf("token/kind = %q/%q, want %q/%q",
					resp.HostInbound.Token, resp.HostInbound.Kind, c.wantToken, c.wantKind)
			}
			if resp.HostInbound.Description == "" {
				t.Errorf("description is empty; want the CLI explanation line")
			}

			// CLI/gRPC value-parity: the same policymatch.Result the local CLI
			// renders must carry the identical status/token/kind/description.
			ref := policymatch.Match(cfg, queryFromReq(c.req))
			if ref.HostInbound == nil {
				t.Fatalf("policymatch reference HostInbound is nil")
			}
			if resp.HostInbound.Token != ref.HostInbound.Token ||
				resp.HostInbound.Kind != ref.HostInbound.Kind ||
				resp.HostInbound.Description != ref.HostInbound.Describe() {
				t.Errorf("gRPC vs CLI/SSOT drift: gRPC{tok=%q kind=%q desc=%q} vs ref{tok=%q kind=%q desc=%q}",
					resp.HostInbound.Token, resp.HostInbound.Kind, resp.HostInbound.Description,
					ref.HostInbound.Token, ref.HostInbound.Kind, ref.HostInbound.Describe())
			}
			if resp.HostInbound.Status != hostInboundStatusToProto(ref.HostInbound.Status) {
				t.Errorf("gRPC status %v != mapped ref status %v",
					resp.HostInbound.Status, hostInboundStatusToProto(ref.HostInbound.Status))
			}
		})
	}
}

// TestMatchPoliciesGRPCHostInboundOffHostOmitted pins the presence gate: a
// transit (off-host) query has NO host-inbound gate, so host_inbound is nil on
// both a positive match and a no-match/default verdict.
func TestMatchPoliciesGRPCHostInboundOffHostOmitted(t *testing.T) {
	store := hostInboundAdmitStore(t)
	s := &Server{store: store}

	// Positive transit match trust->untrust.
	m, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "trust", ToZone: "untrust", Protocol: "tcp", DestinationPort: int32Ptr17081(22),
	})
	if err != nil {
		t.Fatalf("MatchPolicies(match) error = %v", err)
	}
	if !m.Matched {
		t.Fatalf("matched = false, want true (trust->untrust permit)")
	}
	if m.HostInbound != nil {
		t.Errorf("off-host match carries host_inbound = %+v, want nil", m.HostInbound)
	}

	// No-match / default deny untrust->trust.
	dd, err := s.MatchPolicies(context.Background(), &pb.MatchPoliciesRequest{
		FromZone: "untrust", ToZone: "trust", Protocol: "tcp", DestinationPort: int32Ptr17081(22),
	})
	if err != nil {
		t.Fatalf("MatchPolicies(default) error = %v", err)
	}
	if dd.HostInbound != nil {
		t.Errorf("off-host default carries host_inbound = %+v, want nil", dd.HostInbound)
	}
}

// queryFromReq mirrors the query the MatchPolicies handler builds, so a test can
// recompute the shared policymatch.Result the CLI renders and compare fields.
func queryFromReq(req *pb.MatchPoliciesRequest) policymatch.Query {
	var icmpType, icmpCode *uint8
	if req.IcmpType != nil {
		v := uint8(*req.IcmpType)
		icmpType = &v
	}
	if req.IcmpCode != nil {
		v := uint8(*req.IcmpCode)
		icmpCode = &v
	}
	// #17081: req ports are optional int32 — absent stays omitted.
	var srcPort, dstPort *uint16
	if req.SourcePort != nil {
		srcPort = policymatch.PortPtr(uint16(*req.SourcePort))
	}
	if req.DestinationPort != nil {
		dstPort = policymatch.PortPtr(uint16(*req.DestinationPort))
	}
	return policymatch.Query{
		FromZone: req.FromZone,
		ToZone:   req.ToZone,
		SrcIP:    net.ParseIP(req.SourceIp),
		DstIP:    net.ParseIP(req.DestinationIp),
		Protocol: req.Protocol,
		SrcPort:  srcPort,
		DstPort:  dstPort,
		ICMPType: icmpType,
		ICMPCode: icmpCode,
	}
}
