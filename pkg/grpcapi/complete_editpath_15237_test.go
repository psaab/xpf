package grpcapi

import (
	"context"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #15237 A53-06: Complete with edit_path=["system"] completes relative
// to the cursor: `set host` offers host-name, not top-level keywords.
// FAIL-ON-REVERT: ignoring req.EditPath offers `interfaces`-family
// root completions (or nothing for `host`) and this cell goes RED.

func TestCompleteWithEditPathSystem15237(t *testing.T) {
	s := &Server{}
	line := "set host"
	resp, err := s.Complete(context.Background(), &pb.CompleteRequest{
		Line: line, Pos: int32(len(line)), ConfigMode: true, EditPath: []string{"system"},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	found := false
	for _, cand := range resp.Candidates {
		if cand == "host-name" {
			found = true
		}
		if cand == "interfaces" {
			t.Fatalf("edit-cursor completion offered top-level interfaces: %v (#15237 A53-06)", resp.Candidates)
		}
	}
	if !found {
		t.Fatalf("Complete(set host @[edit system]) = %v, want host-name (#15237 A53-06)", resp.Candidates)
	}
	// Control: without edit_path, root-relative completion is unchanged
	// (`set host` at root offers nothing named host-name under system).
	resp2, err := s.Complete(context.Background(), &pb.CompleteRequest{
		Line: "set system host", Pos: int32(len("set system host")), ConfigMode: true,
	})
	if err != nil {
		t.Fatalf("Complete control: %v", err)
	}
	found2 := false
	for _, cand := range resp2.Candidates {
		if cand == "host-name" {
			found2 = true
		}
	}
	if !found2 {
		t.Fatalf("root control Complete(set system host) = %v, want host-name", resp2.Candidates)
	}
}
