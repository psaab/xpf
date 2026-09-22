package main

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

type clearProtocolRecorder struct {
	pb.BpfrxServiceClient
	calls int
	req   *pb.ClearSessionsRequest
}

func (f *clearProtocolRecorder) ClearSessions(
	_ context.Context, req *pb.ClearSessionsRequest, _ ...grpc.CallOption,
) (*pb.ClearSessionsResponse, error) {
	f.calls++
	f.req = req
	return &pb.ClearSessionsResponse{}, nil
}

// TestClearSessionProtocolTokensForwardVerbatim_10486 covers the command
// parser's serialization boundary only. The remote gRPC endpoint owns protocol
// validation; the CLI must preserve the operator token exactly, including
// numeric, signed, whitespace-padded, and unknown values.
func TestClearSessionProtocolTokensForwardVerbatim_10486(t *testing.T) {
	cases := []string{
		"tcp", "6", "sctp", "ipv6", "+6", " 6", "tcpip", " tcp ", "007", "0",
	}
	for _, token := range cases {
		t.Run(token, func(t *testing.T) {
			fake := &clearProtocolRecorder{}
			c := &ctl{client: fake}
			if err := c.handleClear([]string{
				"security", "flow", "session", "protocol", token,
			}); err != nil {
				t.Fatalf("protocol %q: unexpected client error: %v", token, err)
			}
			if fake.calls != 1 || fake.req == nil {
				t.Fatalf("protocol %q: ClearSessions calls=%d req=%v, want one request", token, fake.calls, fake.req)
			}
			if fake.req.GetProtocol() != token {
				t.Fatalf("protocol %q forwarded as %q", token, fake.req.GetProtocol())
			}
		})
	}
}
