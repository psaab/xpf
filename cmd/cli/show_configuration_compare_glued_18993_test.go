package main

// #18993: the remote operational `show configuration` arm split its
// pipe with splitShowPipe, which only recognizes a bare `|` token. A
// compare pipe glued to the scoped path (`system| compare`,
// `system|compare`) or written as `|compare` therefore reached
// ShowConfig as an ordinary path instead of being refused before any
// RPC. handleShow is driven directly here (below the operational gate,
// like the #18667 cells) so the arm's own pre-split refusal is what is
// pinned.

import (
	"reflect"
	"testing"
)

func TestOpShowConfigurationGluedCompareRefused18993(t *testing.T) {
	for _, args := range [][]string{
		{"configuration", "system|", "compare", "rollback", "1"},
		{"configuration", "system|compare", "rollback", "1"},
		{"configuration", "|compare", "rollback", "1"},
	} {
		f := &rec18664{}
		c := &ctl{client: f}
		var err error
		captureStdout(t, func() { err = c.handleShow(args) })
		if err == nil {
			t.Fatalf("handleShow(%q) returned nil; want glued-pipe refusal before any RPC", args)
		}
		if f.calls() != 0 {
			t.Fatalf("handleShow(%q) issued %d RPCs; want refusal before the wire", args, f.calls())
		}
	}
}

// The spaced scoped compare keeps flowing into the landed compare arm:
// exactly one ShowCompare RPC, ACTIVE baseline, path preserved.
func TestOpShowConfigurationSpacedCompareControl18993(t *testing.T) {
	f := &rec18664{}
	c := &ctl{client: f}
	var err error
	out := captureStdout(t, func() {
		err = c.handleShow([]string{"configuration", "system", "|", "compare", "rollback", "1"})
	})
	if err != nil {
		t.Fatalf("handleShow(spaced scoped compare) = %v; want the landed compare arm", err)
	}
	if len(f.compare) != 1 || f.calls() != 1 {
		t.Fatalf("handleShow(spaced scoped compare) issued compare=%d total=%d RPCs; want exactly one ShowCompare", len(f.compare), f.calls())
	}
	req := f.compare[0]
	if !req.GetActiveBaseline() || req.GetRollbackN() != 1 || !reflect.DeepEqual(req.GetPath(), []string{"system"}) {
		t.Fatalf("ShowCompare active=%v n=%d path=%v; want ActiveBaseline/1/[system]",
			req.GetActiveBaseline(), req.GetRollbackN(), req.GetPath())
	}
	if out != "diff\n" {
		t.Fatalf("handleShow(spaced scoped compare) output %q; want diff", out)
	}
}
