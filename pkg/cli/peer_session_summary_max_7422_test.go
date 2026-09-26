// #6565 row 3 / #7422: the CLUSTER-PEER half of `show security flow session
// summary` still printed the hardcoded `Maximum-sessions: 10000000` that #5323
// was written to delete. #5323 fixed the LOCAL branch 45 lines above; the peer
// branch was missed, and its correct value (GetSessionSummaryResponse
// .max_sessions, field 12, populated by the peer from its own helper status in
// grpcapi/server_sessions.go) was already on the wire and discarded.
//
// Before #10836, the peer block was gated on PeerAlive(), so a fixture with
// CLI.cluster nil could not reach it and the local-only summary appeared
// complete. The production path now attempts a peer RPC for every cluster-mode
// summary and prints an explicit unreachable block on failure; the #10836
// regression test exercises that failure path. This file continues to test the
// successful peer render's capacity value directly.
package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestPeerSessionSummaryRendersThePeersOwnMax7422 is the fail-on-revert cell:
// restoring `Maximum-sessions: 10000000` reds it.
func TestPeerSessionSummaryRendersThePeersOwnMax7422(t *testing.T) {
	out := renderPeerSessionSummary(&pb.GetSessionSummaryResponse{
		NodeId:      1,
		ForwardOnly: 42,
		MaxSessions: 786432,
	})
	if !strings.Contains(out, "Maximum-sessions: 786432") {
		t.Fatalf("peer summary does not render the PEER's reported capacity:\n%s", out)
	}
	if strings.Contains(out, "10000000") {
		t.Fatalf("peer summary still prints the retired hardcoded max:\n%s", out)
	}
	// The peer's OTHER fields must keep coming from the peer. A render that
	// dropped them would satisfy the two assertions above while making the
	// node1 block meaningless.
	if !strings.Contains(out, "node1:") || !strings.Contains(out, "Unicast-sessions: 42") {
		t.Fatalf("peer summary lost the peer's own identity/counts:\n%s", out)
	}
	for _, state := range []string{
		"Valid sessions: unknown",
		"Pending sessions: unknown",
		"Invalidated sessions: unknown",
		"Sessions in other states: unknown",
	} {
		if !strings.Contains(out, state) {
			t.Errorf("peer summary must mark unmeasured %q as unknown:\n%s", state, out)
		}
	}
	if strings.Contains(out, "Valid sessions: 42") ||
		strings.Contains(out, "Pending sessions: 0") ||
		strings.Contains(out, "Invalidated sessions: 0") {
		t.Fatalf("peer summary fabricates session-state distribution:\n%s", out)
	}
}

// TestPeerSessionSummaryUnknownMax7422 pins the honest answer for a peer that
// returned no capacity.
//
// MaxSessions == 0 is not "zero sessions allowed" — it is the wire's absence
// sentinel (the peer's userspaceDataplaneStatus() errored, so server_sessions
// .go left the field unset). Rendering `Maximum-sessions: 0` would answer "is
// the peer near its bound?" with a definite and wrong YES; the local branch
// answers "unknown" for exactly this input and the two halves of one command
// must not disagree about it.
func TestPeerSessionSummaryUnknownMax7422(t *testing.T) {
	out := renderPeerSessionSummary(&pb.GetSessionSummaryResponse{NodeId: 1})
	if !strings.Contains(out, "Maximum-sessions: unknown") {
		t.Fatalf("peer summary fabricates a bound for a peer that reported none:\n%s", out)
	}
	if strings.Contains(out, "Maximum-sessions: 0") {
		t.Fatalf("peer summary renders the absence sentinel as a real bound:\n%s", out)
	}
}

// TestShowFlowSessionDelegatesThePeerSummaryRender7422 is the WIRING cell.
//
// The two cells above test a function; this one ensures production continues
// to use it. Re-inlining the peer render into showFlowSession would leave those
// value assertions green while bypassing them on successful cluster fetches.
// The #10836 regression test drives the cluster-mode failure path end to end;
// this wiring assertion protects the successful render delegation.
func TestShowFlowSessionDelegatesThePeerSummaryRender7422(t *testing.T) {
	const src = "cli_show_flow.go"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, src, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", src, err)
	}
	var found, scanned bool
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil || fd.Name.Name != "showFlowSession" {
			continue
		}
		scanned = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := ce.Fun.(*ast.Ident); ok && id.Name == "renderPeerSessionSummary" {
				found = true
			}
			return true
		})
	}
	// Non-vacuity: a renamed or moved showFlowSession would otherwise leave
	// this cell asserting nothing while reporting green.
	if !scanned {
		t.Fatalf("showFlowSession not found in %s — this cell is scanning the "+
			"wrong subject and would pass over an empty set", src)
	}
	if !found {
		t.Fatal("showFlowSession no longer calls renderPeerSessionSummary. If the " +
			"peer render was inlined again, the unit cells in this file still " +
			"pass while `show security flow session summary` can once more print " +
			"a fabricated peer capacity.")
	}
}
