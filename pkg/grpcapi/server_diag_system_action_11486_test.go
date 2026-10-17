package grpcapi

import (
	"context"
	"net/netip"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc/metadata"
)

type persistentNatGenerationDataPlane11486 struct {
	*dataplane.Manager
	peerOrigin     string
	peerGeneration uint64
	calls          int
}

func (d *persistentNatGenerationDataPlane11486) ClearPersistentNATLeasesWithGeneration(origin string, generation uint64) (uint64, string, uint64, error) {
	d.GetPersistentNAT().Clear()
	d.calls++
	d.peerOrigin = origin
	d.peerGeneration = generation
	return 2, "0123456789abcdef0123456789abcdef", 5, nil
}

func TestClearPersistentNatCarriesDurableGenerationToPeer11486(t *testing.T) {
	dp := &persistentNatGenerationDataPlane11486{Manager: dataplane.New()}
	dp.GetPersistentNAT().Save(&dataplane.PersistentNATBinding{
		SrcIP: netip.MustParseAddr("10.0.0.10"), SrcPort: 40000,
		NatIP: netip.MustParseAddr("192.0.2.10"), NatPort: 50000, PoolName: "pool-a",
	})
	peerCalls := 0
	s := &Server{
		dp:      dp,
		cluster: cluster.NewManager(0, 0),
		peerSystemActionFn: func(ctx context.Context, req *pb.SystemActionRequest) (*pb.SystemActionResponse, error) {
			peerCalls++
			if req.Action != "clear-persistent-nat" {
				t.Fatalf("peer action = %q, want clear-persistent-nat", req.Action)
			}
			md, ok := metadata.FromOutgoingContext(ctx)
			// #14580: origin/generation ride the signed body, never metadata.
			if !ok || len(md.Get("x-peer-forwarded")) != 1 ||
				len(md.Get("x-peer-persistent-nat-origin")) != 0 ||
				len(md.Get("x-peer-persistent-nat-generation")) != 0 {
				t.Fatalf("peer clear metadata = %v", md)
			}
			if req.PersistentNatOrigin != "0123456789abcdef0123456789abcdef" || req.PersistentNatGeneration != 5 {
				t.Fatalf("peer clear body origin/generation = %q/%d, want 0123456789abcdef0123456789abcdef/5", req.PersistentNatOrigin, req.PersistentNatGeneration)
			}
			return &pb.SystemActionResponse{Message: "peer clear accepted"}, nil
		},
	}
	if _, err := s.SystemAction(context.Background(), &pb.SystemActionRequest{Action: "clear-persistent-nat"}); err != nil {
		t.Fatalf("local clear: %v", err)
	}
	if dp.calls != 1 || dp.peerOrigin != "" || dp.peerGeneration != 0 {
		t.Fatalf("local clear args/calls = %q/%d/%d", dp.peerOrigin, dp.peerGeneration, dp.calls)
	}
	if peerCalls != 1 {
		t.Fatalf("peer clear calls = %d, want 1", peerCalls)
	}

	// A forwarded clear records the original sender's generation (from the
	// signed body) and must not fan back out, otherwise the two peers would
	// loop clears forever.
	incoming := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-peer-forwarded", "1",
	))
	incoming = withPeerMarkers(incoming, peerMarkers{forwarded: true})
	if _, err := s.SystemAction(incoming, &pb.SystemActionRequest{Action: "clear-persistent-nat", PersistentNatOrigin: "fedcba9876543210fedcba9876543210", PersistentNatGeneration: 9}); err != nil {
		t.Fatalf("forwarded clear: %v", err)
	}
	if dp.calls != 2 || dp.peerOrigin != "fedcba9876543210fedcba9876543210" || dp.peerGeneration != 9 {
		t.Fatalf("forwarded clear args/calls = %q/%d/%d", dp.peerOrigin, dp.peerGeneration, dp.calls)
	}
	if peerCalls != 1 {
		t.Fatalf("forwarded clear fanned back out: calls=%d", peerCalls)
	}
}

// #14580: the signed-body extractor. Legacy unsigned metadata is never
// honored; non-forwarded smuggling is rejected; a legacy forwarded clear
// (empty body) clears with no fence.
func TestPersistentNatClearGenerationFromSignedBody14580(t *testing.T) {
	origin := "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		req     *pb.SystemActionRequest
		want    bool
		bad     bool
		wantGen uint64
	}{
		{
			name: "non-forwarded empty ignored",
			ctx:  context.Background(),
			req:  &pb.SystemActionRequest{Action: "clear-persistent-nat"},
		},
		{
			name: "non-forwarded smuggled fence rejected",
			ctx:  context.Background(),
			req:  &pb.SystemActionRequest{Action: "clear-persistent-nat", PersistentNatOrigin: origin, PersistentNatGeneration: 3},
			bad:  true,
		},
		{
			name:    "forwarded signed body accepted",
			ctx:     withPeerMarkers(context.Background(), peerMarkers{forwarded: true}),
			req:     &pb.SystemActionRequest{Action: "clear-persistent-nat", PersistentNatOrigin: origin, PersistentNatGeneration: 3},
			want:    true,
			wantGen: 3,
		},
		{
			name: "forwarded legacy empty body no fence",
			ctx:  withPeerMarkers(context.Background(), peerMarkers{forwarded: true}),
			req:  &pb.SystemActionRequest{Action: "clear-persistent-nat"},
		},
		{
			name: "forwarded generation without origin rejected",
			ctx:  withPeerMarkers(context.Background(), peerMarkers{forwarded: true}),
			req:  &pb.SystemActionRequest{Action: "clear-persistent-nat", PersistentNatGeneration: 3},
			bad:  true,
		},
		{
			name: "forwarded invalid origin rejected",
			ctx:  withPeerMarkers(context.Background(), peerMarkers{forwarded: true}),
			req:  &pb.SystemActionRequest{Action: "clear-persistent-nat", PersistentNatOrigin: "not-hex", PersistentNatGeneration: 3},
			bad:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotOrigin, gotGeneration, got, err := persistentNatClearGenerationFromRequest11486(tc.ctx, tc.req)
			if tc.bad {
				if err == nil {
					t.Fatal("bad signed-body fence was accepted")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("result present=%v err=%v, want present=%v", got, err, tc.want)
			}
			if got && (gotOrigin != origin || gotGeneration != tc.wantGen) {
				t.Fatalf("body = %q/%d, want %q/%d", gotOrigin, gotGeneration, origin, tc.wantGen)
			}
		})
	}
	// Legacy metadata alone (even trusted/forwarded) yields no fence.
	legacyCtx := withPeerMarkers(metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-peer-persistent-nat-origin", origin,
		"x-peer-persistent-nat-generation", "18446744073709551615",
	)), peerMarkers{forwarded: true})
	if _, _, got, err := persistentNatClearGenerationFromRequest11486(legacyCtx, &pb.SystemActionRequest{Action: "clear-persistent-nat"}); err != nil || got {
		t.Fatalf("legacy metadata honored: present=%v err=%v, want no fence", got, err)
	}
}
