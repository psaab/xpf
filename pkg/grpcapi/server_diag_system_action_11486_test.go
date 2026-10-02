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
			origins := md.Get(persistentNatClearOriginMetadata11486)
			generations := md.Get(persistentNatClearGenerationMetadata11486)
			if !ok || len(md.Get("x-peer-forwarded")) != 1 ||
				len(origins) != 1 || origins[0] != "0123456789abcdef0123456789abcdef" ||
				len(generations) != 1 || generations[0] != "5" {
				t.Fatalf("peer clear metadata = %v", md)
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

	// A forwarded clear records the original sender's generation and must not
	// fan back out, otherwise the two peers would loop clears forever.
	incoming := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"x-peer-forwarded", "1",
		persistentNatClearOriginMetadata11486, "fedcba9876543210fedcba9876543210",
		persistentNatClearGenerationMetadata11486, "9",
	))
	incoming = withPeerMarkers(incoming, peerMarkers{forwarded: true})
	if _, err := s.SystemAction(incoming, &pb.SystemActionRequest{Action: "clear-persistent-nat"}); err != nil {
		t.Fatalf("forwarded clear: %v", err)
	}
	if dp.calls != 2 || dp.peerOrigin != "fedcba9876543210fedcba9876543210" || dp.peerGeneration != 9 {
		t.Fatalf("forwarded clear args/calls = %q/%d/%d", dp.peerOrigin, dp.peerGeneration, dp.calls)
	}
	if peerCalls != 1 {
		t.Fatalf("forwarded clear fanned back out: calls=%d", peerCalls)
	}
}

func TestPersistentNatClearGenerationMetadataRequiresTrustedCompleteFrame11486(t *testing.T) {
	origin := "0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name string
		ctx  context.Context
		want bool
		bad  bool
	}{
		{
			name: "untrusted metadata ignored",
			ctx: metadata.NewIncomingContext(context.Background(), metadata.Pairs(
				persistentNatClearOriginMetadata11486, origin,
				persistentNatClearGenerationMetadata11486, "3",
			)),
		},
		{
			name: "trusted complete metadata accepted",
			ctx: withPeerMarkers(metadata.NewIncomingContext(context.Background(), metadata.Pairs(
				persistentNatClearOriginMetadata11486, origin,
				persistentNatClearGenerationMetadata11486, "3",
			)), peerMarkers{forwarded: true}),
			want: true,
		},
		{
			name: "trusted incomplete metadata rejected",
			ctx: withPeerMarkers(metadata.NewIncomingContext(context.Background(), metadata.Pairs(
				persistentNatClearOriginMetadata11486, origin,
			)), peerMarkers{forwarded: true}),
			bad: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotOrigin, gotGeneration, got, err := persistentNatClearGenerationFromContext11486(tc.ctx)
			if tc.bad {
				if err == nil {
					t.Fatal("incomplete trusted metadata was accepted")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("metadata result present=%v err=%v, want present=%v", got, err, tc.want)
			}
			if got && (gotOrigin != origin || gotGeneration != 3) {
				t.Fatalf("metadata = %q/%d, want %q/3", gotOrigin, gotGeneration, origin)
			}
		})
	}
}
