package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

func TestRequestDynamicAddressShrinkAckRejectsMalformedGrammar11059(t *testing.T) {
	hash := strings.Repeat("a", 64)
	baselineHash := strings.Repeat("b", 64)
	valid := []string{
		"security", "dynamic-address", "acknowledge-shrink", "threats",
		"candidate-id", "41", "candidate-hash", hash,
		"baseline-hash", baselineHash,
		"old-count", "100", "new-count", "5", "reason", "reviewed",
	}
	replace := func(index int, value string) []string {
		args := append([]string(nil), valid...)
		args[index] = value
		return args
	}
	overlongReason := append(append([]string(nil), valid[:15]...), strings.Repeat("x", 513))
	missingFeed := append(append([]string(nil), valid[:3]...), valid[4:]...)
	cases := []struct {
		name string
		args []string
	}{
		{name: "missing feed", args: missingFeed},
		{name: "wrong candidate keyword", args: replace(4, "candidate")},
		{name: "non-numeric ID", args: replace(5, "nope")},
		{name: "zero ID", args: replace(5, "0")},
		{name: "signed ID", args: replace(5, "+41")},
		{name: "overflow ID", args: replace(5, "18446744073709551616")},
		{name: "wrong candidate hash keyword", args: replace(6, "hash")},
		{name: "malformed candidate hash", args: replace(7, "not-a-sha256")},
		{name: "wrong baseline hash keyword", args: replace(8, "baseline")},
		{name: "malformed baseline hash", args: replace(9, "not-a-sha256")},
		{name: "wrong old-count keyword", args: replace(10, "old")},
		{name: "zero old count", args: replace(11, "0")},
		{name: "overflow old count", args: replace(11, "4294967296")},
		{name: "wrong new-count keyword", args: replace(12, "new")},
		{name: "signed new count", args: replace(13, "-1")},
		{name: "wrong reason keyword", args: replace(14, "because")},
		{name: "missing reason", args: valid[:15]},
		{name: "empty reason", args: replace(15, "  ")},
		{name: "overlong reason", args: overlongReason},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &ctl{}
			if err := c.handleRequest(tc.args); err == nil {
				t.Fatalf("handleRequest(%v) accepted malformed acknowledgement", tc.args)
			}
		})
	}
}

type shrinkAckRequestRecorder11059 struct {
	pb.BpfrxServiceClient
	request *pb.SystemActionRequest
}

func (r *shrinkAckRequestRecorder11059) SystemAction(
	_ context.Context, request *pb.SystemActionRequest, _ ...grpc.CallOption,
) (*pb.SystemActionResponse, error) {
	r.request = request
	return &pb.SystemActionResponse{Message: "acknowledged"}, nil
}

func TestRequestDynamicAddressShrinkAckSendsExactCandidateTuple11059(t *testing.T) {
	const candidateHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const baselineHash = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	recorder := &shrinkAckRequestRecorder11059{}
	c := &ctl{client: recorder}
	args := []string{
		"security", "dynamic-address", "acknowledge-shrink", "threats",
		"candidate-id", "41", "candidate-hash", candidateHash,
		"baseline-hash", baselineHash,
		"old-count", "100", "new-count", "5", "reason", "reviewed scope",
	}
	if err := c.handleRequest(args); err != nil {
		t.Fatalf("acknowledgement request: %v", err)
	}
	got := recorder.request
	if got == nil || got.Action != "dynamic-address-shrink-ack" ||
		got.Target != "threats" || got.CandidateId != 41 ||
		got.CandidateHash != candidateHash || got.BaselineHash != baselineHash ||
		got.CandidateOldCount != 100 || got.CandidateNewCount != 5 ||
		got.Reason != "reviewed scope" {
		t.Fatalf("SystemAction sent candidate request %+v, want ID/candidate+baseline hash/count tuple and reason", got)
	}
}
