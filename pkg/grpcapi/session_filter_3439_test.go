// #3439 L2: direct gRPC GetSessions must distinguish invalid operator
// input from an empty result set. Before the fix, an unparseable
// protocol token (e.g. "tcpip") iterated to an empty session list and
// returned as a *successful* RPC, and a negative offset (proto field is
// int32) made the first row satisfy `idx >= offset`, silently behaving
// like offset 0. Both now fail with codes.InvalidArgument.
//
// FAIL-ON-REVERT:
//   - Dropping the protocol guard in buildSessionFilter makes
//     TestSessionFilterRejectsInvalidProtocol go RED (validate returns
//     nil for "tcpip").
//   - Dropping the `offset < 0` check in getSessionsLegacy makes
//     TestGetSessionsRejectsNegativeOffset go RED (the RPC succeeds).
package grpcapi

import (
	"context"
	"fmt"
	"testing"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type sessionRowsGRPCDP struct {
	*dataplane.Manager
	v4Sessions map[dataplane.SessionKey]dataplane.SessionValue
	v6Sessions map[dataplane.SessionKeyV6]dataplane.SessionValueV6
}

func (d *sessionRowsGRPCDP) IsLoaded() bool { return true }

func (d *sessionRowsGRPCDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for key, val := range d.v4Sessions {
		if !fn(key, val) {
			break
		}
	}
	return nil
}

func (d *sessionRowsGRPCDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for key, val := range d.v6Sessions {
		if !fn(key, val) {
			break
		}
	}
	return nil
}

func newSessionRowsGRPCDP() *sessionRowsGRPCDP {
	d := &sessionRowsGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: make(map[dataplane.SessionKey]dataplane.SessionValue),
		v6Sessions: make(map[dataplane.SessionKeyV6]dataplane.SessionValueV6),
	}
	for _, proto := range []uint8{6, 132, 41, 7, 0, 17} {
		d.v4Sessions[dataplane.SessionKey{
			SrcIP:    [4]byte{10, 0, 0, proto},
			DstIP:    [4]byte{10, 0, 1, proto},
			Protocol: proto,
		}] = dataplane.SessionValue{}
		d.v6Sessions[dataplane.SessionKeyV6{
			SrcIP:    [16]byte{0x20, 0x01, 0xdb, 0x08, proto},
			DstIP:    [16]byte{0x20, 0x01, 0xdb, 0x09, proto},
			Protocol: proto,
		}] = dataplane.SessionValueV6{}
	}
	return d
}

func TestSessionFilterBuilderWiring(t *testing.T) {
	s := newViewServer(t, newSessionRowsGRPCDP())
	for _, tc := range []struct {
		token string
		proto uint8
	}{
		{"tcp", 6},
		{"6", 6},
		{" tcp ", 6},
		{"sctp", 132},
		{"ipv6", 41},
		{"007", 7},
		{"0", 0},
	} {
		t.Run(tc.token, func(t *testing.T) {
			f := s.buildSessionFilter(&pb.GetSessionsRequest{Protocol: tc.token})
			if err := f.validate(); err != nil {
				t.Fatalf("validate(%q): %v", tc.token, err)
			}
			if !f.hasProto || f.proto != tc.proto || !f.hasFilters {
				t.Fatalf("builder(%q): proto=%d hasProto=%t hasFilters=%t; want %d/true/true",
					tc.token, f.proto, f.hasProto, f.hasFilters, tc.proto)
			}
			resp, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{
				Protocol: tc.token,
				NoEnrich: true,
			})
			if err != nil {
				t.Fatalf("GetSessions(%q): %v", tc.token, err)
			}
			if got := len(resp.Sessions); got != 2 || resp.Total != 2 {
				t.Fatalf("GetSessions(%q): sessions=%d total=%d; want 2/2",
					tc.token, got, resp.Total)
			}
		})
	}
}

func TestSessionFilterRejectsInvalidProtocol(t *testing.T) {
	s := newViewServer(t, &viewFaultGRPCDP{Manager: dataplane.New()})

	// An unparseable protocol token must surface as InvalidArgument,
	// not iterate to an empty success.
	bad := s.buildSessionFilter(&pb.GetSessionsRequest{Protocol: "tcpip"})
	err := bad.validate()
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Protocol=tcpip: validate() = %v (code %v); want InvalidArgument",
			err, status.Code(err))
	}

	// Known names and numeric 0-255 stay valid.
	for _, proto := range []string{"tcp", "udp", "icmpv6", "gre", "sctp", "47", "0", "255", "007", " tcp "} {
		f := s.buildSessionFilter(&pb.GetSessionsRequest{Protocol: proto})
		if err := f.validate(); err != nil {
			t.Errorf("Protocol=%q: validate() = %v; want nil", proto, err)
		}
	}

	// Out-of-range numeric is rejected (not 0-255).
	for _, proto := range []string{"256", "+6", " 6"} {
		f := s.buildSessionFilter(&pb.GetSessionsRequest{Protocol: proto})
		if status.Code(f.validate()) != codes.InvalidArgument {
			t.Errorf("Protocol=%q: want InvalidArgument, got %v", proto, f.validate())
		}
	}

	// Regression guard (#3439 / Refs #3393): "ipv6" is a NAME the system
	// still DISPLAYS (protoName(41)); both the strict and lenient resolvers
	// accept it after #3393, and the shared matcher must match proto 41.
	v6name := s.buildSessionFilter(&pb.GetSessionsRequest{Protocol: "ipv6"})
	if err := v6name.validate(); err != nil {
		t.Errorf("Protocol=ipv6: validate() = %v; want nil (it is a displayed protocol name)", err)
	}
	if !appid.ProtoFilterMatches(41, 41, true) {
		t.Errorf("ProtoFilterMatches(41, 41, true) = false; want true")
	}
	if appid.ProtoFilterMatches(6, 41, true) {
		t.Errorf("ProtoFilterMatches(6, 41, true) = true; want false")
	}
}

func TestGetSessionsRejectsNegativeOffsetCursor(t *testing.T) {
	s := newViewServer(t, &viewFaultGRPCDP{Manager: dataplane.New()})

	// Cursor path: PageSize > 0 routes to getSessionsCursor, which never
	// consulted Offset — a negative offset was silently accepted. The
	// guard now lives in GetSessions before the PageSize branch, so the
	// cursor path rejects it too (#3439 L2, Codex MAJOR fold).
	_, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{PageSize: 1, Offset: -1})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("PageSize=1 Offset=-1: GetSessions err = %v (code %v); want InvalidArgument",
			err, status.Code(err))
	}
}

func TestGetSessionsRejectsNegativeOffset(t *testing.T) {
	s := newViewServer(t, &viewFaultGRPCDP{Manager: dataplane.New()})

	_, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{Offset: -1})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("Offset=-1: GetSessions err = %v (code %v); want InvalidArgument",
			err, status.Code(err))
	}

	// A non-negative offset is not rejected by the offset guard. With
	// nil iterators (no sessions) the legacy path returns a clean,
	// non-error empty response.
	if _, err := s.GetSessions(context.Background(), &pb.GetSessionsRequest{Offset: 0}); err != nil {
		t.Fatalf("Offset=0: unexpected error %v", err)
	}
}

func TestClearSessionsRejectsInvalidProtocol(t *testing.T) {
	dp := &clearFaultGRPCDP{
		Manager:    dataplane.New(),
		v4Sessions: seedGRPCV4(false),
		iterErr:    fmt.Errorf("invalid protocol reached iterator"),
		iterV6Err:  fmt.Errorf("invalid protocol reached v6 iterator"),
	}
	s := newClearServer(t, dp)
	_, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{
		Protocol: "tcpip",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ClearSessions(protocol=tcpip) = %v (code %v); want InvalidArgument",
			err, status.Code(err))
	}
	if dp.iterCalls != 0 || dp.iterV6Calls != 0 ||
		dp.iterFromCalls != 0 || dp.iterV6FromCalls != 0 ||
		dp.deleteCalls != 0 || dp.deleteV6Calls != 0 ||
		dp.dnatCalls != 0 || dp.dnatV6Calls != 0 ||
		dp.clearAllCalls != 0 {
		t.Fatalf("invalid protocol performed dataplane work: %+v", dp)
	}
	if got := len(dp.v4Sessions); got != 1 {
		t.Fatalf("invalid protocol changed the seeded table: %d entries, want 1", got)
	}
}
