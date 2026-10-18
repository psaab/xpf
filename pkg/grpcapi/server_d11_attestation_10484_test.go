package grpcapi

import (
	"context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/authz"
	"github.com/psaab/xpf/pkg/config"
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
			principal: authz.CredentialPrincipal("operator", "read-only"),
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
			principal: authz.CredentialPrincipal("super-user", "super-user"),
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

func TestNewServerWiresPeerLookup10484(t *testing.T) {
	want := authz.PeerIdentity{UID: 1234, OK: true, Local: true}
	s := NewServer("bufnet", Config{
		PeerLookupFn: func(net.Addr, net.Addr) authz.PeerIdentity {
			return want
		},
	})
	if got := s.lookupPeer(nil, nil); got != want {
		t.Fatalf("peer lookup = %+v, want %+v", got, want)
	}
}

func TestD11SystemActionRejectsMalformedAndUnavailableInputs10484(t *testing.T) {
	root := context.WithValue(context.Background(), authorizedPrincipalKey{},
		authz.Principal{Source: authz.SourcePeerUID, UID: 0, Superuser: true})
	s := &Server{d11ArmFn: func(string, uint64, string) error { return nil }}
	if _, err := s.SystemAction(root, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil D11 request code = %s, want InvalidArgument", status.Code(err))
	}
	for _, action := range []string{
		"userspace-attest:arm",
		"userspace-attest:arm:attest-0123456789abcdef0123456789abcdef:0:" + strings.Repeat("ab", 16),
		"userspace-attest:arm:attest-0123456789abcdef0123456789abcdef:not-a-number:" + strings.Repeat("ab", 16),
		"userspace-attest:arm:attest-0123456789abcdef0123456789abcdef:7",
	} {
		_, err := s.SystemAction(root, &pb.SystemActionRequest{Action: action})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("malformed action %q code = %s, want InvalidArgument", action, status.Code(err))
		}
	}
	unavailable := &Server{}
	_, err := unavailable.SystemAction(root, &pb.SystemActionRequest{
		Action: "userspace-attest:arm:attest-0123456789abcdef0123456789abcdef:7:" +
			strings.Repeat("ab", 16),
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("nil D11 arm callback code = %s, want Unavailable", status.Code(err))
	}
}

func TestD11AuthorizationRejectsNonPeerAndReadOnlyPrincipals10484(t *testing.T) {
	s := &Server{d11LedgerFn: func() *nfqueue.D11LedgerSnapshot {
		return &nfqueue.D11LedgerSnapshot{NodeID: "node-a"}
	}}
	cases := []authz.Principal{
		authz.Principal{Source: authz.SourceNone, UID: 0, Superuser: true},
		authz.Principal{Source: authz.SourceCredential, UID: 0, Superuser: true},
		authz.Principal{Source: authz.SourcePeerUID, UID: 1001, Class: "read-only"},
	}
	for _, principal := range cases {
		ctx := context.WithValue(context.Background(), authorizedPrincipalKey{}, principal)
		if _, err := s.GetD11AttestationLedger(ctx, &pb.GetD11AttestationLedgerRequest{}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("principal %+v code = %s, want PermissionDenied", principal, status.Code(err))
		}
	}
}

// TestD11AttestationRejectsNonSuperuserMaintClass is the #14709 regression:
// a custom login class holding only the Junos `maintenance` token (coarse
// PermMaint, not PermAll) must NOT pass either D11 gate. Both handlers
// document "uid 0 or the configured super-user class", so a non-superuser
// maintenance operator reading the ledger or re-arming the attestation
// authority (forged run_id/permit_epoch/marker via d11ArmFn) is a bypass.
//
// FAIL-ON-REVERT: restoring the PermMaint disjunct in
// d11LedgerPrincipalAllowed (or the PermMaint pricing below) makes the
// maint-principal cases return OK and increments the arm counter.
func TestD11AttestationRejectsNonSuperuserMaintClass(t *testing.T) {
	const cfgText = `
system {
    host-name d11-14709;
    login {
        class maint-only {
            permissions maintenance;
        }
        user maintuser {
            class maint-only;
        }
        user adminuser {
            class super-user;
        }
    }
}
`
	store := authzStore5278(t, cfgText)
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("no active config")
	}
	if !config.ClassHasPermission(cfg, "maint-only", config.PermMaint) {
		t.Fatalf("fixture class maint-only does not hold PermMaint; perms resolve failed")
	}
	if config.ClassHasPermission(cfg, "maint-only", config.PermAll) {
		t.Fatalf("fixture class maint-only unexpectedly holds PermAll")
	}

	var armCalls int
	s := &Server{
		store: store,
		d11LedgerFn: func() *nfqueue.D11LedgerSnapshot {
			return &nfqueue.D11LedgerSnapshot{NodeID: "node-a"}
		},
		d11ArmFn: func(string, uint64, string) error {
			armCalls++
			return nil
		},
	}
	maintPrincipal := authz.Principal{Source: authz.SourcePeerUID, UID: 1001, Username: "maintuser", Class: "maint-only"}
	armAction := "userspace-attest:arm:attest-0123456789abcdef0123456789abcdef:7:" +
		strings.Repeat("ab", 16)

	// Handler gates: ledger read and arm must both deny.
	maintCtx := context.WithValue(context.Background(), authorizedPrincipalKey{}, maintPrincipal)
	if _, err := s.GetD11AttestationLedger(maintCtx, &pb.GetD11AttestationLedgerRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("maint-only ledger code = %s, want PermissionDenied (err=%v)", status.Code(err), err)
	}
	if _, err := s.SystemAction(maintCtx, &pb.SystemActionRequest{Action: armAction}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("maint-only arm code = %s, want PermissionDenied (err=%v)", status.Code(err), err)
	}
	if armCalls != 0 {
		t.Fatalf("d11ArmFn called %d times for maint-only principal, want 0", armCalls)
	}

	// Interceptor pricing must not admit the maint-only principal either:
	// the coarse layer is the first gate a real RPC traverses.
	if perm, ok := methodPermission("/"+serviceName+"/GetD11AttestationLedger", &pb.GetD11AttestationLedgerRequest{}); !ok || perm != config.PermAll {
		t.Fatalf("GetD11AttestationLedger pricing = %v,%v, want PermAll,true", perm, ok)
	}
	if perm := systemActionPermission(armAction); perm != config.PermAll {
		t.Fatalf("systemActionPermission(arm) = %v, want PermAll", perm)
	}

	// Controls: root and the configured super-user class still pass both
	// handler gates against the same active config.
	for _, p := range []authz.Principal{
		{Source: authz.SourcePeerUID, UID: 0, Username: "root", Superuser: true},
		{Source: authz.SourcePeerUID, UID: 1002, Username: "adminuser", Class: "super-user"},
	} {
		ctx := context.WithValue(context.Background(), authorizedPrincipalKey{}, p)
		if _, err := s.GetD11AttestationLedger(ctx, &pb.GetD11AttestationLedgerRequest{}); err != nil {
			t.Fatalf("control principal %+v ledger denied: %v", p, err)
		}
		if _, err := s.SystemAction(ctx, &pb.SystemActionRequest{Action: armAction}); err != nil {
			t.Fatalf("control principal %+v arm denied: %v", p, err)
		}
	}
	if armCalls != 2 {
		t.Fatalf("d11ArmFn calls = %d, want 2 (root + super-user controls)", armCalls)
	}
}
