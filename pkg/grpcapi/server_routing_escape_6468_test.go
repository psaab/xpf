package grpcapi

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/frr"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #6468 D2, remote-cli half. The routing show RPCs return captured `vtysh`
// stdout and the remote `cli` prints resp.Output VERBATIM
// (cmd/cli/show_protocols.go, cmd/cli/show.go: fmt.Print(resp.Output)) — the
// same operator terminal the in-process CLI writes to, reached over gRPC
// instead of in-process. That stdout carries text a REMOTE PEER advertised:
// the BGP hostname capability, IS-IS dynamic hostname TLVs, OSPF router IDs.
//
// These are the fail-on-revert guards for that surface. Dropping a
// termsafe.SanitizeBlockForDisplay call in server_routing.go /
// server_show_routes_text.go makes the raw ESC reappear in the emitted text,
// and swapping in the single-line termsafe.SanitizeForDisplay collapses the
// table — each assertion below binds one of those two failure modes.
//
// hasRawTermControl6468 is shared with server_show_dhcp_escape_6468_test.go.

// evilVtyshBlock6468 is a realistic multi-line vtysh table with a CSI
// erase-line escape buried in the peer-advertised hostname cell. The
// surrounding rows are clean so a test can assert BOTH that the escape was
// neutralized AND that the block's line structure survived.
const evilVtyshBlock6468 = "BGP neighbor is 10.0.0.1, remote AS 65001\n" +
	"  Hostname: rtr1\x1b[2Kforged-peer\n" +
	"  BGP state = Established, up for 00:12:34\n"

// evilISISNeighborTable6468 is a `show isis neighbor` table whose FIRST column
// carries a CSI erase-line escape. That column is not a numeric system ID: FRR
// substitutes the hostname the peer advertised in its Dynamic Hostname TLV
// (RFC 5301), so it is peer-controlled text — and GetISISAdjacency reaches it
// through strings.Fields, which splits on whitespace and leaves ESC/DEL/C1
// inside the token untouched. Tokenizing is not sanitizing.
//
// The header row must survive the parser's own skips: it drops lines starting
// with "Area" and rows whose first field is "System".
const evilISISNeighborTable6468 = "Area 1:\n" +
	" System Id           Interface   L  State        Holdtime SNPA\n" +
	" rtr1\x1b[2Kforged     ge-0-0-1    2  Up           27       2020.2020.2020\n"

// evilBGPSummaryJSON6468 is a `show bgp summary json` reply whose peer "state"
// string carries an embedded NEWLINE plus a complete fake peer row. It is the
// case that ISOLATES the per-cell row guard from the response-boundary block
// guard: SanitizeBlockForDisplay PRESERVES LF by design (that is what keeps a
// vtysh table from collapsing), so it cannot catch this — only the single-line
// cell guard escapes the newline and stops the forged row.
//
// This cell is reachable in a way a strings.Fields-scraped cell is not: JSON
// decoding turns \n into a real newline, and the split that would have
// consumed it never happens.
const evilBGPSummaryJSON6468 = `{"ipv4Unicast":{"peers":{"10.0.0.1":{` +
	`"remoteAs":65001,"msgRcvd":10,"msgSent":11,"peerUptime":"00:12:34",` +
	`"state":"Established\n  10.0.0.99             ipv4-unicast  65099    0         0         never       Idle         0",` +
	`"pfxRcd":5,"pfxSnt":5}}}}`

// vtyshEscapeExecutor6468 is an frr executor double that returns hostile
// stdout. It satisfies pkg/frr's package-private frrExecutor (all four methods
// are exported names, so an out-of-package type can implement it) and is handed
// to frr.NewForTest, which is the seam that lets a show RPC run its real wiring
// without shelling out to vtysh.
//
// `show isis neighbor` gets a PARSED-table fixture because that command feeds
// GetISISAdjacency rather than being printed verbatim; every other command gets
// the raw block.
type vtyshEscapeExecutor6468 struct{}

func (vtyshEscapeExecutor6468) Vtysh(_ context.Context, cmd string) (string, error) {
	switch cmd {
	case "show isis neighbor":
		return evilISISNeighborTable6468, nil
	case "show bgp summary json":
		return evilBGPSummaryJSON6468, nil
	}
	return evilVtyshBlock6468, nil
}

func (vtyshEscapeExecutor6468) FrrReloadPy(context.Context, string) error { return nil }

func (vtyshEscapeExecutor6468) VtyshLoad(context.Context, string) ([]byte, error) {
	return nil, nil
}

func (vtyshEscapeExecutor6468) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	return io.NopCloser(strings.NewReader("")), func() error { return nil }, nil
}

func (vtyshEscapeExecutor6468) VtyshDaemon(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

func (vtyshEscapeExecutor6468) VtyshLoadDaemon(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

// escapeVtyshServer6468 wires a Server whose FRR manager returns the hostile
// block from every vtysh call.
func escapeVtyshServer6468(t *testing.T) *Server {
	t.Helper()
	m := frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), vtyshEscapeExecutor6468{})
	return &Server{frr: m}
}

// assertVtyshOutputSanitized6468 is the shared verdict for a rendered block.
// It binds THREE distinct failure modes:
//
//	(1) non-vacuous — the fixture actually rendered, so the guard is not being
//	    asserted against an empty string;
//	(2) no raw terminal control byte survived — the revert signal for dropping
//	    the sanitize call entirely;
//	(3) the escape is VISIBLE and the LINE COUNT is unchanged — the revert
//	    signal for swapping in the single-line sanitizer, which would escape
//	    every LF and collapse the table into one \x0a-laden row.
func assertVtyshOutputSanitized6468(t *testing.T, surface, out string) {
	t.Helper()
	if !strings.Contains(out, "BGP neighbor is 10.0.0.1") {
		t.Fatalf("%s: the vtysh block must render (else the guard is vacuous):\n%q", surface, out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("%s: emitted raw terminal control bytes — unsanitized vtysh stdout reaches "+
			"the remote cli's verbatim fmt.Print(resp.Output) (#6468 D2):\n%q", surface, out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatalf("%s: expected the escaped ESC (\\x1b) to render, proving the peer hostname was "+
			"sanitized rather than dropped:\n%q", surface, out)
	}
	if want, have := strings.Count(evilVtyshBlock6468, "\n"), strings.Count(out, "\n"); want != have {
		t.Fatalf("%s: the block's line structure must survive — want %d newlines, got %d. "+
			"The single-line termsafe.SanitizeForDisplay escapes LF and would collapse this "+
			"table; these surfaces need SanitizeBlockForDisplay:\n%q", surface, want, have, out)
	}
}

func TestGetOSPFStatus_RemoteCLIEscapesVtyshOutput_6468(t *testing.T) {
	// Every raw-vtysh req.Type of the OSPF handler. "" (the structured
	// neighbor-summary default) is excluded: it does not return vtysh stdout.
	for _, typ := range []string{"neighbor-detail", "database", "interface", "routes"} {
		s := escapeVtyshServer6468(t)
		resp, err := s.GetOSPFStatus(context.Background(), &pb.GetOSPFStatusRequest{Type: typ})
		if err != nil {
			t.Fatalf("GetOSPFStatus(%q): %v", typ, err)
		}
		assertVtyshOutputSanitized6468(t, "GetOSPFStatus type="+typ, resp.Output)
	}
}

func TestGetBGPStatus_RemoteCLIEscapesVtyshOutput_6468(t *testing.T) {
	// The three neighbor sub-selectors that return raw vtysh stdout. "routes",
	// "groups" and the bare summary build structured tables instead.
	for _, typ := range []string{
		"received-routes:10.0.0.1",
		"advertised-routes:10.0.0.1",
		"neighbor:10.0.0.1",
		"neighbor",
	} {
		s := escapeVtyshServer6468(t)
		resp, err := s.GetBGPStatus(context.Background(), &pb.GetBGPStatusRequest{Type: typ})
		if err != nil {
			t.Fatalf("GetBGPStatus(%q): %v", typ, err)
		}
		assertVtyshOutputSanitized6468(t, "GetBGPStatus type="+typ, resp.Output)
	}
}

func TestGetISISStatus_RemoteCLIEscapesVtyshOutput_6468(t *testing.T) {
	for _, typ := range []string{"adjacency-detail", "routes", "database"} {
		s := escapeVtyshServer6468(t)
		resp, err := s.GetISISStatus(context.Background(), &pb.GetISISStatusRequest{Type: typ})
		if err != nil {
			t.Fatalf("GetISISStatus(%q): %v", typ, err)
		}
		assertVtyshOutputSanitized6468(t, "GetISISStatus type="+typ, resp.Output)
	}
}

// TestGetISISStatus_RemoteCLIEscapesParsedAdjacencyRow_6468 covers the surface
// the "raw vtysh output" sweep could not see: a PARSED field (the peer's IS-IS
// dynamic hostname) reprinted into a caller-formatted row.
//
// On THIS renderer the row is covered TWICE — by the per-cell row guard and by
// the response-boundary block guard — so reverting either one alone still
// produces safe output HERE. This test is therefore the end-to-end
// defense-in-depth assertion, not the binder for the per-cell call.
//
// The per-cell call IS bound, by
// TestGetISISStatus_RemoteCLICellGuardPrecedesWidthFormat_6579 in
// server_row_escape_6579_test.go: the guard must run BEFORE the %-20s width
// format, so dropping it pads the RAW cell and shifts every later column right
// by the escape expansion. That discriminator survives the outer block guard,
// which the raw-control-byte assertion below does not. The LF shape that
// isolates BGP summary is unreachable for this row because strings.Fields
// consumed every whitespace rune before the cell existed.
func TestGetISISStatus_RemoteCLIEscapesParsedAdjacencyRow_6468(t *testing.T) {
	s := escapeVtyshServer6468(t)
	resp, err := s.GetISISStatus(context.Background(), &pb.GetISISStatusRequest{Type: ""})
	if err != nil {
		t.Fatalf("GetISISStatus(adjacency): %v", err)
	}
	out := resp.Output

	if !strings.Contains(out, "ge-0-0-1") {
		t.Fatalf("the adjacency row must render (else the guard is vacuous):\n%q", out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("emitted raw terminal control bytes — the peer-advertised IS-IS dynamic "+
			"hostname reaches the remote cli through the PARSED SystemID field, which the "+
			"raw-output sweep does not cover (#6468):\n%q", out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatalf("expected the escaped ESC (\\x1b) to render, proving the parsed cell was "+
			"sanitized rather than dropped:\n%q", out)
	}
}

// assertBGPSummaryRowSanitized6468 is the shared verdict for the rendered BGP
// summary. hasRawTermControl6468 deliberately tolerates \n and \t (a rendered
// table needs them), so a surviving newline would slip past it — the line-count
// and \x0a assertions are what actually bind this case.
func assertBGPSummaryRowSanitized6468(t *testing.T, surface, out string) {
	t.Helper()
	if !strings.Contains(out, "10.0.0.1") {
		t.Fatalf("%s: the peer row must render (else the guard is vacuous):\n%q", surface, out)
	}
	if !strings.Contains(out, `\x0a`) {
		t.Fatalf("%s: the newline embedded in the peer's state cell must render as \\x0a. "+
			"The response-boundary block sanitizer PRESERVES LF by design, so only the "+
			"per-cell row guard catches this (#6468):\n%q", surface, out)
	}
	// Header + exactly one peer row. A third line means the JSON cell forged one.
	if n := strings.Count(strings.TrimRight(out, "\n"), "\n"); n != 1 {
		t.Fatalf("%s: want header + exactly 1 peer row (1 interior newline), got %d — "+
			"the provider-controlled cell forged a table row:\n%q", surface, n, out)
	}
	if strings.Contains(out, "\n  10.0.0.99") {
		t.Fatalf("%s: a forged peer row reached the terminal:\n%q", surface, out)
	}
}

func TestGetBGPStatus_RemoteCLIEscapesParsedSummaryRow_6468(t *testing.T) {
	s := escapeVtyshServer6468(t)
	resp, err := s.GetBGPStatus(context.Background(), &pb.GetBGPStatusRequest{Type: ""})
	if err != nil {
		t.Fatalf("GetBGPStatus(summary): %v", err)
	}
	assertBGPSummaryRowSanitized6468(t, "GetBGPStatus summary", resp.Output)
}

func TestShowBFDPeers_RemoteCLIEscapesVtyshOutput_6468(t *testing.T) {
	s := escapeVtyshServer6468(t)
	var buf strings.Builder
	if err := s.showBFDPeers(context.Background(), &buf); err != nil {
		t.Fatalf("showBFDPeers: %v", err)
	}
	assertVtyshOutputSanitized6468(t, "showBFDPeers", buf.String())
}

func TestShowRouteMap_RemoteCLIEscapesVtyshOutput_6468(t *testing.T) {
	s := escapeVtyshServer6468(t)
	var buf strings.Builder
	if err := s.showRouteMap(context.Background(), nil, &buf); err != nil {
		t.Fatalf("showRouteMap: %v", err)
	}
	assertVtyshOutputSanitized6468(t, "showRouteMap", buf.String())
}
