package grpcapi

import (
	"context"
	"fmt"
	"strconv"

	"google.golang.org/grpc/metadata"
)

const (
	persistentNatClearOriginMetadata11486     = "x-peer-persistent-nat-origin"
	persistentNatClearGenerationMetadata11486 = "x-peer-persistent-nat-generation"
)

func persistentNatClearGenerationFromContext11486(ctx context.Context) (string, uint64, bool, error) {
	if !peerForwardedFromContext(ctx) {
		return "", 0, false, nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "", 0, false, nil
	}
	origins := md.Get(persistentNatClearOriginMetadata11486)
	generations := md.Get(persistentNatClearGenerationMetadata11486)
	if len(origins) == 0 && len(generations) == 0 {
		return "", 0, false, nil
	}
	if len(origins) != 1 || len(generations) != 1 || len(origins[0]) != 32 {
		return "", 0, false, fmt.Errorf("incomplete persistent-NAT clear generation metadata")
	}
	for _, char := range origins[0] {
		if char < '0' || (char > '9' && char < 'a') || char > 'f' {
			return "", 0, false, fmt.Errorf("invalid persistent-NAT clear origin")
		}
	}
	generation, err := strconv.ParseUint(generations[0], 10, 64)
	if err != nil {
		return "", 0, false, fmt.Errorf("invalid persistent-NAT clear generation: %w", err)
	}
	return origins[0], generation, true, nil
}
