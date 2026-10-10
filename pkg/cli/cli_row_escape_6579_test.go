package cli

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/frr"
)

// #6579 fold, local-CLI half. Mirrors server_row_escape_6579_test.go: the three
// PARSED row sites the first pass left without a call-site binder — OSPF
// neighbors, BGP routes, RIP routes.
//
// A parsed row is not covered by the raw-vtysh sweep. frr.Get*() scrapes vtysh
// stdout with strings.Fields and showOSPF/showBGP/showRIP REPRINT the cells into
// their own format strings, so dropping termsafe.SanitizeRowForDisplay at one of
// these sites is invisible to every test in cli_residual_escape_6468_test.go.
//
// Unlike the gRPC handlers, the local CLI has NO response boundary: these row
// paths call fmt.Printf directly, with no SanitizeBlockForDisplay downstream to
// mask a dropped per-cell guard. The raw-ESC assertion therefore isolates the
// guard here by construction, which is why the alignment discriminator the gRPC
// mirror needs is not repeated.

// evilRowCell6579 is the hostile token: a CSI erase-line escape inside the cell.
const evilRowCell6579 = "rtr1\x1b[2Kforged"

// evilOSPFNeighborTable6579 puts the escape in the Neighbor ID column of
// `show ip ospf neighbor`. GetOSPFNeighbors needs >= 5 fields and skips the
// header (fields[0] == "Neighbor").
//
// An OSPF router ID is a dotted quad today, so this is a CALL-SITE BINDER, not
// a claim that FRR emits free text here now — exactly the documented reason the
// guard is uniform: "this column is numeric" is a property of the current
// upstream, not of the protocol.
const evilOSPFNeighborTable6579 = "Neighbor ID     Pri State    Dead Time Address    Interface\n" +
	evilRowCell6579 + " 128 Full/DR 32.100s 10.0.1.2 ge-0-0-0\n"

// evilRIPTable6579 puts the escape in the Network column of `show ip rip`.
const evilRIPTable6579 = "Codes: R - RIP, C - connected\n" +
	"     Network            Next Hop         Metric From\n" +
	evilRowCell6579 + " 10.0.1.2 2 ge-0-0-1\n"

// evilBGPRouteTable6579 puts the escape in the NEXT-HOP column of
// `show bgp ipv4 unicast` — the realistic taint, since `bgp default
// show-nexthop-hostname` renders a peer-supplied hostname in that column.
const evilBGPRouteTable6579 = "   Network          Next Hop            Metric LocPrf Weight Path\n" +
	"*> 10.0.0.0/8       " + evilRowCell6579 + "         0    100      0 65001 65002 i\n"

// rowEscapeExecutor6579 answers the parsed-table commands with hostile rows. It
// deliberately does not reuse vtyshEscapeExecutor6468, whose catch-all returns a
// raw BGP-neighbor block that these parsers would scrape into nonsense rows.
type rowEscapeExecutor6579 struct{}

func (rowEscapeExecutor6579) Vtysh(_ context.Context, cmd string) (string, error) {
	switch cmd {
	case "show ip ospf neighbor":
		return evilOSPFNeighborTable6579, nil
	case "show ip rip":
		return evilRIPTable6579, nil
	case "show bgp ipv4 unicast":
		return evilBGPRouteTable6579, nil
	}
	return "", nil
}

func (rowEscapeExecutor6579) FrrReloadPy(context.Context, string) error { return nil }

func (rowEscapeExecutor6579) VtyshLoad(context.Context, string) ([]byte, error) { return nil, nil }

func (rowEscapeExecutor6579) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	return io.NopCloser(strings.NewReader("")), func() error { return nil }, nil
}

func (rowEscapeExecutor6579) VtyshDaemon(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

func (rowEscapeExecutor6579) VtyshLoadDaemon(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

func rowEscapeCLI6579(t *testing.T) *CLI {
	t.Helper()
	m := frr.NewForTest(filepath.Join(t.TempDir(), "frr.conf"), rowEscapeExecutor6579{})
	return &CLI{frr: m}
}

// assertRowCellSanitized6579 is the call-site binder: the hostile cell rendered,
// no raw control byte reached stdout, and the escape is visible rather than the
// value silently dropped.
func assertRowCellSanitized6579(t *testing.T, surface, out string) {
	t.Helper()
	if !strings.Contains(out, "forged") {
		t.Fatalf("%s: the hostile row must render, else this binder is vacuous:\n%q", surface, out)
	}
	if hasRawTermControl6468(out) {
		t.Fatalf("%s: a raw terminal control byte reached the operator's terminal. This row site "+
			"lost its termsafe.SanitizeRowForDisplay guard, and a parsed FRR cell is peer-"+
			"controlled text that the raw-vtysh sweep does not cover (#6468):\n%q", surface, out)
	}
	if !strings.Contains(out, `\x1b`) {
		t.Fatalf("%s: expected the escaped ESC (\\x1b), proving the cell was sanitized rather "+
			"than dropped:\n%q", surface, out)
	}
}

func TestShowOSPF_LocalCLIEscapesParsedNeighborRow_6579(t *testing.T) {
	c := rowEscapeCLI6579(t)
	out := captureStdout(t, func() {
		if err := c.showOSPF([]string{"neighbor"}); err != nil {
			t.Fatalf("showOSPF(neighbor): %v", err)
		}
	})
	assertRowCellSanitized6579(t, "show ospf neighbor", out)
}

func TestShowBGP_LocalCLIEscapesParsedRouteRow_6579(t *testing.T) {
	c := rowEscapeCLI6579(t)
	out := captureStdout(t, func() {
		if err := c.showBGP([]string{"routes"}); err != nil {
			t.Fatalf("showBGP(routes): %v", err)
		}
	})
	assertRowCellSanitized6579(t, "show bgp routes", out)
}

func TestShowRIP_LocalCLIEscapesParsedRouteRow_6579(t *testing.T) {
	c := rowEscapeCLI6579(t)
	out := captureStdout(t, func() {
		if err := c.showRIP(); err != nil {
			t.Fatalf("showRIP: %v", err)
		}
	})
	assertRowCellSanitized6579(t, "show rip", out)
}
