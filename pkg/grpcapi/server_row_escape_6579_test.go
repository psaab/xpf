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

// #6579 fold. The first pass bound the raw-vtysh sweep on both renderers and
// the PARSED row on two of the five sites. These are the remaining three
// production row sites — OSPF neighbors, BGP routes, RIP routes — plus the
// isolation the first pass could not reach.
//
// # Why the parsed-row sites need their own binders
//
// A parsed row is not covered by a raw-output test: frr.Get*() scrapes vtysh
// stdout with strings.Fields and the handler REPRINTS the cells into its own
// format string, so the block guard on the response never sees the cell as the
// peer wrote it. Dropping termsafe.SanitizeRowForDisplay at one of these five
// sites is invisible to every test in server_routing_escape_6468_test.go.
//
// # Isolating the inner guard from the outer one
//
// GetOSPFStatus / GetBGPStatus / GetISISStatus sanitize the whole RESPONSE with
// SanitizeBlockForDisplay as a fail-safe, which MASKS a dropped per-cell guard
// for the raw-ESC assertion: the escape gets neutralized either way. Two shapes
// see through that mask, and every test below uses one of them:
//
//   - COLUMN ALIGNMENT (assertCellGuardRanBeforeWidthFormat6579). `%-20s` pads
//     whatever it is handed. Guarding the CELL pads the 17-character escaped
//     text to 20. Guarding only the response pads the 14-byte RAW text to 20 and
//     THEN expands the escape, so the column runs 3 characters long and every
//     later column shifts right. Same bytes, different layout — and the layout
//     is the operator-visible difference.
//   - A REAL LF in a cell, which the block variant preserves by design. Only
//     reachable for a JSON-decoded cell; already covered for BGP summary by
//     TestGetBGPStatus_RemoteCLIEscapesParsedSummaryRow_6468.
//
// GetRIPStatus has NO response-boundary guard (it has no raw-vtysh branch for
// one to protect), so its per-cell guard is isolated by construction and the
// plain raw-ESC assertion binds it.

// The hostile token shared by the row fixtures below: a CSI erase-line escape
// inside the cell. 14 bytes raw ("rtr1" + ESC + "[2Kforged"), 17 characters
// once escaped ("rtr1" + `\x1b` + "[2Kforged") — the 3-character difference the
// alignment assertion keys on.
const evilRowCell6579 = "rtr1\x1b[2Kforged"

const (
	// evilRowCellRawLen is len(evilRowCell6579).
	evilRowCellRawLen = 14
	// evilRowCellEscapedLen is its length after termsafe escaping.
	evilRowCellEscapedLen = 17
)

// evilOSPFNeighborTable6579 puts the escape in the Neighbor ID column of
// `show ip ospf neighbor`. GetOSPFNeighbors needs >= 5 fields and skips the
// header (fields[0] == "Neighbor"); it takes Address/Interface from the LAST
// two fields.
//
// An OSPF router ID is a dotted quad today, so this is a CALL-SITE BINDER, not
// a claim that FRR emits free text here now. That is exactly the documented
// reason the guard is uniform: "this column is numeric" is a property of the
// current upstream, not of the protocol.
const evilOSPFNeighborTable6579 = "Neighbor ID     Pri State    Dead Time Address    Interface\n" +
	evilRowCell6579 + " 128 Full/DR 32.100s 10.0.1.2 ge-0-0-0\n"

// evilRIPTable6579 puts the escape in the Network column of `show ip rip`.
// GetRIPRoutes needs >= 3 fields and skips the header (fields[0] == "Network")
// and the "Codes" legend.
const evilRIPTable6579 = "Codes: R - RIP, C - connected\n" +
	"     Network            Next Hop         Metric From\n" +
	evilRowCell6579 + " 10.0.1.2 2 ge-0-0-1\n"

// evilBGPRouteTable6579 puts the escape in the NEXT-HOP column of
// `show bgp ipv4 unicast`. parseBGPRouteLine requires the line to start with
// "*" or " " and to carry >= 3 fields; Network is fields[1], NextHop fields[2],
// Path the join of fields[4:].
//
// Next-hop is the realistic taint here: with `bgp default show-nexthop-hostname`
// FRR renders a peer-supplied hostname in this column.
const evilBGPRouteTable6579 = "   Network          Next Hop            Metric LocPrf Weight Path\n" +
	"*> 10.0.0.0/8       " + evilRowCell6579 + "         0    100      0 65001 65002 i\n"

// rowEscapeExecutor6579 answers the three PARSED-table commands with hostile
// rows. It deliberately does NOT reuse vtyshEscapeExecutor6468: that double
// returns a raw BGP-neighbor block for every unmatched command, which these
// parsers would scrape into nonsense rows and make the assertions unreadable.
type rowEscapeExecutor6579 struct{}

func (rowEscapeExecutor6579) Vtysh(_ context.Context, cmd string) (string, error) {
	switch cmd {
	case "show ip ospf neighbor":
		return evilOSPFNeighborTable6579, nil
	case "show ip rip":
		return evilRIPTable6579, nil
	case "show bgp ipv4 unicast":
		return evilBGPRouteTable6579, nil
	case "show isis neighbor":
		return evilISISNeighborTable6468, nil
	}
	return "", nil
}

func (rowEscapeExecutor6579) FrrReloadPy(context.Context, string) error { return nil }

func (rowEscapeExecutor6579) VtyshLoad(context.Context, string) ([]byte, error) { return nil, nil }

func (rowEscapeExecutor6579) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	return io.NopCloser(strings.NewReader(evilBGPRouteTable6579)), func() error { return nil }, nil
}

func rowEscapeServer6579(t *testing.T) *Server {
	t.Helper()
	m := frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), rowEscapeExecutor6579{})
	return &Server{frr: m}
}

// assertRowCellSanitized6579 is the call-site binder: the hostile cell rendered,
// no raw control byte survived, and the escape is visible rather than dropped.
func assertRowCellSanitized6579(t *testing.T, surface, out string) {
	t.Helper()
	if !strings.Contains(out, "forged") {
		t.Fatalf("%s: the hostile row must render, else this binder is vacuous:\n%q", surface, out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("%s: a raw terminal control byte reached the remote cli's verbatim "+
			"fmt.Print(resp.Output). This row site lost its termsafe.SanitizeRowForDisplay "+
			"guard (#6468):\n%q", surface, out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatalf("%s: expected the escaped ESC (\\x1b), proving the cell was sanitized rather "+
			"than dropped:\n%q", surface, out)
	}
}

// assertCellGuardRanBeforeWidthFormat6579 proves the guard runs on the CELL and
// not merely on the finished response.
//
// nextCol is a clean value from the column immediately after the hostile one,
// and wantStart is the byte offset the handler's format string puts it at
// (leading literal + the hostile column's declared width + the separator).
// Sanitizing per cell pads the escaped text, so nextCol lands exactly there.
// Sanitizing only at the response boundary pads the RAW text and then expands
// the escape, pushing nextCol right by (escaped - raw) bytes.
func assertCellGuardRanBeforeWidthFormat6579(t *testing.T, surface, out, nextCol string, wantStart int) {
	t.Helper()
	line := ""
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "forged") {
			line = l
			break
		}
	}
	if line == "" {
		t.Fatalf("%s: no rendered row carried the hostile cell:\n%q", surface, out)
	}
	got := strings.Index(line, nextCol)
	if got == wantStart {
		return
	}
	drift := evilRowCellEscapedLen - evilRowCellRawLen
	if got == wantStart+drift {
		t.Fatalf("%s: the next column starts at %d instead of %d — exactly the %d bytes the ESC "+
			"grows by when escaped. The width format padded the RAW cell and the escaping "+
			"happened afterwards, at the response boundary. termsafe.SanitizeRowForDisplay must "+
			"run on the CELLS, before %%-Ns, or every column after a hostile one shifts right:\n%q",
			surface, got, wantStart, drift, line)
	}
	t.Fatalf("%s: the next column starts at %d, want %d (the hostile cell must occupy exactly its "+
		"declared width once escaped):\n%q", surface, got, wantStart, line)
}

// --- OSPF neighbors: "%-18s %-10s %-16s %-18s %s" -----------------------------

func TestGetOSPFStatus_RemoteCLIEscapesParsedNeighborRow_6579(t *testing.T) {
	s := rowEscapeServer6579(t)
	resp, err := s.GetOSPFStatus(context.Background(), &pb.GetOSPFStatusRequest{Type: ""})
	if err != nil {
		t.Fatalf("GetOSPFStatus(neighbors): %v", err)
	}
	assertRowCellSanitized6579(t, "GetOSPFStatus neighbors", resp.Output)
	// No leading literal; column 0 is %-18s, then one space -> col 1 at 19.
	assertCellGuardRanBeforeWidthFormat6579(t, "GetOSPFStatus neighbors", resp.Output, "128", 19)
}

// --- BGP routes: "%-24s %-20s %s" ---------------------------------------------

func TestGetBGPStatus_RemoteCLIEscapesParsedRouteRow_6579(t *testing.T) {
	s := rowEscapeServer6579(t)
	resp, err := s.GetBGPStatus(context.Background(), &pb.GetBGPStatusRequest{Type: "routes"})
	if err != nil {
		t.Fatalf("GetBGPStatus(routes): %v", err)
	}
	assertRowCellSanitized6579(t, "GetBGPStatus routes", resp.Output)
	// The hostile cell is the NEXT-HOP (column 1, %-20s). Column 0 is %-24s
	// holding the clean "10.0.0.0/8", then a space -> the hostile cell starts
	// at 25 and the path column at 25+20+1 = 46.
	assertCellGuardRanBeforeWidthFormat6579(t, "GetBGPStatus routes", resp.Output, "100 0 65001", 46)
}

// --- RIP routes: "  %-20s %-18s %-8s %s" --------------------------------------

func TestGetRIPStatus_RemoteCLIEscapesParsedRouteRow_6579(t *testing.T) {
	s := rowEscapeServer6579(t)
	resp, err := s.GetRIPStatus(context.Background(), &pb.GetRIPStatusRequest{})
	if err != nil {
		t.Fatalf("GetRIPStatus: %v", err)
	}
	// GetRIPStatus has no response-boundary block guard, so the raw-ESC
	// assertion alone isolates the per-cell guard here: reverting
	// SanitizeRowForDisplay at this site puts a raw ESC on the wire.
	assertRowCellSanitized6579(t, "GetRIPStatus", resp.Output)
	// "  " + %-20s + " " -> next column at 23.
	assertCellGuardRanBeforeWidthFormat6579(t, "GetRIPStatus", resp.Output, "10.0.1.2", 23)
}

// --- IS-IS adjacency: "  %-20s %-14s %-10s %-10s %s" --------------------------

// TestGetISISStatus_RemoteCLICellGuardPrecedesWidthFormat_6579 closes the gap
// the first pass documented but could not bind: on this handler the outer block
// guard masks a dropped per-cell guard for any raw-ESC assertion, and the LF
// shape that isolates BGP summary is unreachable here because strings.Fields
// consumed every whitespace rune before the cell existed. Column alignment is
// the discriminator that survives the mask.
func TestGetISISStatus_RemoteCLICellGuardPrecedesWidthFormat_6579(t *testing.T) {
	s := rowEscapeServer6579(t)
	resp, err := s.GetISISStatus(context.Background(), &pb.GetISISStatusRequest{Type: ""})
	if err != nil {
		t.Fatalf("GetISISStatus(adjacency): %v", err)
	}
	assertRowCellSanitized6579(t, "GetISISStatus adjacency", resp.Output)
	// "  " + %-20s + " " -> the Interface column at 23.
	assertCellGuardRanBeforeWidthFormat6579(t, "GetISISStatus adjacency", resp.Output, "ge-0-0-1", 23)
}
