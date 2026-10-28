// #17189: the remote CLI refused `show security flow session summary`
// combined with any filter because "the summary RPC (GetSessionSummary)
// takes no filter". That was true when written; #15236 gave the RPC the
// same selector set as GetSessions, and the on-box CLI has forwarded
// filtered summaries since. The refusal (and its false comment) was
// never revisited, so the remote surface rejected a command the daemon
// and the on-box CLI both serve.
//
// FAIL-ON-REVERT: restoring `p.hasFilter && p.action != flowSessionList`
// in parseFlowSessionArgs makes the filtered parses below error again;
// dropping the selector copy in summaryRequestFromParse makes the
// recorded request lose its filters while still succeeding — the #3439
// silent-drop shape in the summary sub-path.
package main

import (
	"context"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"google.golang.org/grpc"
)

// summary17189Client records the summary request and answers GetZones
// for the zone-name resolution the summary path must still perform.
type summary17189Client struct {
	pb.BpfrxServiceClient
	zones   []*pb.ZoneInfo
	sumReqs []*pb.GetSessionSummaryRequest
}

func (f *summary17189Client) GetZones(context.Context, *pb.GetZonesRequest, ...grpc.CallOption) (*pb.GetZonesResponse, error) {
	return &pb.GetZonesResponse{Zones: f.zones}, nil
}

func (f *summary17189Client) GetSessionSummary(_ context.Context, in *pb.GetSessionSummaryRequest, _ ...grpc.CallOption) (*pb.GetSessionSummaryResponse, error) {
	f.sumReqs = append(f.sumReqs, in)
	return &pb.GetSessionSummaryResponse{ForwardOnly: 3, MaxSessions: 100}, nil
}

func TestRemoteFilteredSummaryAccepted17189(t *testing.T) {
	// Both orders, plus the issue's canonical shape.
	for _, args := range [][]string{
		{"summary", "zone", "trust"},
		{"zone", "trust", "summary"},
		{"summary"},
		{"zone", "trust"},
	} {
		if _, err := parseFlowSessionArgs(args); err != nil {
			t.Errorf("parseFlowSessionArgs(%v) = %v; want accepted (#17189: filtered summary is served since #15236)", args, err)
		}
	}
	// Control: sort-by still rejects a filter — it truly takes none.
	if _, err := parseFlowSessionArgs([]string{"zone", "trust", "sort-by", "bytes"}); err == nil {
		t.Errorf("sort-by with a filter must still be rejected (it walks the whole table)")
	}
	if _, err := parseFlowSessionArgs([]string{"sort-by", "bytes"}); err != nil {
		t.Errorf("unfiltered sort-by must still parse: %v", err)
	}
}

func TestRemoteFilteredSummaryForwardsSelector17189(t *testing.T) {
	fake := &summary17189Client{zones: []*pb.ZoneInfo{{Name: "trust", Id: 7}, {Name: "untrust", Id: 9}}}
	c := &ctl{client: fake}
	out := captureStdout(t, func() {
		if err := c.showFlowSession([]string{
			"summary", "zone", "trust", "protocol", "tcp",
			"source-prefix", "10.0.0.0/8", "destination-port", "443",
			"nat-only", "application", "junos-https",
			"interface", "reth1.0", "source-nat-pool", "pool1",
		}); err != nil {
			t.Fatalf("filtered summary refused: %v", err)
		}
	})
	if len(fake.sumReqs) != 1 {
		t.Fatalf("expected exactly one GetSessionSummary; got %d", len(fake.sumReqs))
	}
	req := fake.sumReqs[0]
	if req.GetZone() != 7 {
		t.Errorf("summary zone = %d, want 7 (name trust resolved, not wildcard 0)", req.GetZone())
	}
	if req.GetProtocol() != "TCP" || req.GetSourcePrefix() != "10.0.0.0/8" ||
		req.GetDestinationPort() != 443 || !req.GetNatOnly() ||
		req.GetApplication() != "junos-https" || req.GetInterfaceFilter() != "reth1.0" ||
		req.GetSourceNatPool() != "pool1" {
		t.Errorf("summary request dropped filters: %+v", req)
	}
	if !req.GetIncludePeer() {
		t.Errorf("summary request must keep include_peer fan-out")
	}
	if !strings.Contains(out, "Unicast-sessions: 3") {
		t.Errorf("summary output missing counts:\n%s", out)
	}

	// Unknown zone on the summary path must refuse and issue NO summary
	// request — zone 0 would widen to every zone (#9065 trap).
	fake2 := &summary17189Client{zones: []*pb.ZoneInfo{{Name: "trust", Id: 7}}}
	c2 := &ctl{client: fake2}
	if err := c2.showFlowSession([]string{"summary", "zone", "nosuchzone"}); err == nil {
		t.Fatal("summary with unknown zone must be refused")
	}
	if len(fake2.sumReqs) != 0 {
		t.Fatalf("no summary request may be issued for an unresolvable zone; got %d", len(fake2.sumReqs))
	}

	// Id-0 trap on the summary path (#9065): a zone that resolves by
	// name but carries Id 0 has no runtime id yet; sending it would
	// put the wildcard (every zone) on GetSessionSummary. It must
	// refuse and issue NO summary request.
	fake3 := &summary17189Client{zones: []*pb.ZoneInfo{{Name: "trust", Id: 0}}}
	c3 := &ctl{client: fake3}
	if err := c3.showFlowSession([]string{"summary", "zone", "trust"}); err == nil {
		t.Fatal("summary with a zone resolving to Id 0 must be refused (Id 0 is the wildcard)")
	}
	if len(fake3.sumReqs) != 0 {
		t.Fatalf("no summary request may be issued for a zone with Id 0; got %d", len(fake3.sumReqs))
	}

	// Protocol 0 (HOPOPT) on the summary path must stay present as
	// "0": dropping it to "" would widen the summary to every
	// protocol (the forwards-selector counterpart of the pkg/cli
	// builder pin in TestSessionSelectorBuildersAgree17189).
	fake4 := &summary17189Client{}
	c4 := &ctl{client: fake4}
	_ = captureStdout(t, func() {
		if err := c4.showFlowSession([]string{"summary", "protocol", "0"}); err != nil {
			t.Fatalf("summary with protocol 0 refused: %v", err)
		}
	})
	if len(fake4.sumReqs) != 1 {
		t.Fatalf("expected exactly one GetSessionSummary for protocol 0; got %d", len(fake4.sumReqs))
	}
	if got := fake4.sumReqs[0].GetProtocol(); got != "0" {
		t.Errorf("summary protocol 0 = %q, want %q (absent would widen to all protocols)", got, "0")
	}
}
