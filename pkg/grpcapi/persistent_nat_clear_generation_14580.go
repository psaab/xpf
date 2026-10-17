package grpcapi

import (
	"context"
	"fmt"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/protobuf/proto"
)

// #14580: the persistent-NAT clear origin/generation used to ride unsigned
// gRPC metadata (x-peer-persistent-nat-{origin,generation}). The #4107 fabric
// token binds only method + protobuf request digest + window — no metadata —
// so anyone holding one captured clear-persistent-nat token inside its window
// could replay it with generation=MaxUint64: the receiver durably persisted
// RemoteGenerations[origin]=MaxUint64, after which every genuine peer lease
// batch (generation < watermark) was silently dropped forever — no expiry,
// no self-heal (the peer refuses to advance at MAX), surviving restart until
// zeroize or manual state-file removal.
//
// The origin/generation now travel INSIDE SystemActionRequest
// (persistent_nat_origin / persistent_nat_generation), so the existing
// request-digest MAC binds them exactly like every other argument: a replay
// whose origin/generation differs from the minted call fails the fabric
// interceptor as Unauthenticated before the handler or watermark runs.
//
// Legacy metadata is never honored. A forwarded clear (peer-marker
// capability present) with both fields empty is a legacy peer that predates
// the signed body: it still clears locally but records no durable generation
// fence — the pre-#11486 behavior — rather than trusting unsigned bytes.

// persistentNatClearGenerationFromRequest11486 extracts the forwarded-clear
// origin/generation from the signed request body. It is meaningful only on a
// forwarded (peer-proxied) call; a non-forwarded call carrying the fields is
// a local/CLI call smuggling a fence for some other origin and is rejected.
func persistentNatClearGenerationFromRequest11486(ctx context.Context, req *pb.SystemActionRequest) (string, uint64, bool, error) {
	if req == nil {
		return "", 0, false, fmt.Errorf("missing system action request")
	}
	origin := req.GetPersistentNatOrigin()
	generation := req.GetPersistentNatGeneration()
	if !peerForwardedFromContext(ctx) {
		if origin != "" || generation != 0 {
			return "", 0, false, fmt.Errorf("persistent-NAT clear generation fields on a non-forwarded call")
		}
		return "", 0, false, nil
	}
	if origin == "" && generation == 0 {
		// Legacy peer: clears locally, records no generation fence.
		return "", 0, false, nil
	}
	if !validPersistentNatClearOrigin11486(origin) {
		return "", 0, false, fmt.Errorf("invalid persistent-NAT clear origin %q", origin)
	}
	return origin, generation, true, nil
}

func validPersistentNatClearOrigin11486(origin string) bool {
	if len(origin) != 32 {
		return false
	}
	for _, char := range origin {
		if char < '0' || (char > '9' && char < 'a') || char > 'f' {
			return false
		}
	}
	return true
}

// persistentNatClearRequestWithGeneration returns the request to forward to
// the peer for a clear-persistent-nat fan-out: a copy carrying the local
// clear's origin/generation in the signed body. The caller's request is
// never mutated — it may be the operator's original request object.
func persistentNatClearRequestWithGeneration(req *pb.SystemActionRequest, origin string, generation uint64) *pb.SystemActionRequest {
	if req == nil {
		return &pb.SystemActionRequest{PersistentNatOrigin: origin, PersistentNatGeneration: generation}
	}
	forwarded := proto.Clone(req).(*pb.SystemActionRequest)
	forwarded.PersistentNatOrigin = origin
	forwarded.PersistentNatGeneration = generation
	return forwarded
}
