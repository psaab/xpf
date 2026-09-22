package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/authz"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/nfqueue"
)

func TestGetD11AttestationLedgerAuthorization10484(t *testing.T) {
	s := &Server{d11LedgerFn: func() *nfqueue.D11LedgerSnapshot {
		return &nfqueue.D11LedgerSnapshot{
			NodeID: "node-a", RunID: "attest-0123456789abcdef0123456789abcdef",
			Records: []nfqueue.D11LedgerRecord{{
				Key: nfqueue.D11LedgerKey{
					NodeID: "node-a", RequestID: 3, PermitEpoch: 7,
					QueueEpoch: 2, QueueNumber: 1000,
				},
			}},
		}
	}}
	cases := []struct {
		name      string
		principal authz.Principal
		wantCode  codes.Code
	}{
		{
			name:      "root peer uid",
			principal: authz.Principal{Source: authz.SourcePeerUID, UID: 0, Superuser: true},
			wantCode:  codes.OK,
		},
		{
			name:      "configured super-user class",
			principal: authz.Principal{Source: authz.SourcePeerUID, UID: 1001, Class: "super-user"},
			wantCode:  codes.OK,
		},
		{
			name:      "api credential is not a local uid",
			principal: authz.CredentialPrincipal("operator"),
			wantCode:  codes.PermissionDenied,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), authorizedPrincipalKey{}, tc.principal)
			response, err := s.GetD11AttestationLedger(ctx, &pb.GetD11AttestationLedgerRequest{})
			if got := status.Code(err); got != tc.wantCode {
				t.Fatalf("status code = %s, want %s (err=%v)", got, tc.wantCode, err)
			}
			if tc.wantCode == codes.OK {
				if response == nil || response.GetNodeId() != "node-a" {
					t.Fatalf("response = %v, want node-a snapshot", response)
				}
				if len(response.GetRecords()) != 1 || response.GetRecords()[0].GetQueueNumber() != 1000 {
					t.Fatalf("records = %v, want queue_number 1000", response.GetRecords())
				}
			} else if response != nil {
				t.Fatalf("denied response = %v, want nil", response)
			}
		})
	}
}

func TestD11ArmSystemActionAuthorization10484(t *testing.T) {
	var calls int
	s := &Server{
		d11ArmFn: func(runID string, permitEpoch uint64, markerHex string) error {
			calls++
			return nil
		},
	}
	action := "userspace-attest:arm:attest-0123456789abcdef0123456789abcdef:7:" +
		strings.Repeat("ab", 16)
	cases := []struct {
		name      string
		principal authz.Principal
		wantCode  codes.Code
	}{
		{
			name:      "root peer uid",
			principal: authz.Principal{Source: authz.SourcePeerUID, UID: 0, Superuser: true},
			wantCode:  codes.OK,
		},
		{
			name:      "configured super-user class",
			principal: authz.Principal{Source: authz.SourcePeerUID, UID: 1001, Class: "super-user"},
			wantCode:  codes.OK,
		},
		{
			name:      "api credential denied",
			principal: authz.CredentialPrincipal("super-user"),
			wantCode:  codes.PermissionDenied,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), authorizedPrincipalKey{}, tc.principal)
			response, err := s.SystemAction(ctx, &pb.SystemActionRequest{Action: action})
			if got := status.Code(err); got != tc.wantCode {
				t.Fatalf("status code = %s, want %s (err=%v)", got, tc.wantCode, err)
			}
			if tc.wantCode == codes.OK && response == nil {
				t.Fatal("successful arm returned nil response")
			}
		})
	}
	if calls != 2 {
		t.Fatalf("d11 arm callback calls = %d, want 2 accepted local principals", calls)
	}
}
