package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/frr"
)

// #4708: the BGP routes REST endpoint must stream its response instead of
// rendering the entire routing table into one strings.Builder (and then a
// second full copy while json-encoding it). A full internet table (900k+
// routes) otherwise materializes as a multi-hundred-MB string on a
// RAM-constrained firewall. These tests pin two invariants:
//
//  1. Wire-format equivalence — the streamed bytes are byte-for-byte identical
//     to the previous buffered writeOK(TextResponse{Output: <joined lines>})
//     form, for a representative table AND the empty table. A regression that
//     drops/reorders routes or corrupts the JSON array/object framing fails.
//  2. Non-buffering — even a large table is written to the ResponseWriter in
//     bounded chunks (never one giant Write) and is flushed incrementally.

// fakeBGPExecutor satisfies frr's unexported frrExecutor interface (all methods
// are exported, so a value of this type is assignable to it) and lets the test
// drive GetBGPRoutes deterministically via a canned `show bgp ipv4 unicast`
// output.
type fakeBGPExecutor struct {
	vtyshOut string
}

func (f fakeBGPExecutor) Vtysh(context.Context, string) (string, error)     { return f.vtyshOut, nil }
func (f fakeBGPExecutor) FrrReloadPy(context.Context, string) error         { return nil }
func (f fakeBGPExecutor) VtyshLoad(context.Context, string) ([]byte, error) { return nil, nil }

// VtyshStream serves the canned table as an incremental reader so the streaming
// StreamBGPRoutes path (and therefore bgpHandler) is exercised end-to-end.
func (f fakeBGPExecutor) VtyshStream(context.Context, string) (io.ReadCloser, func() error, error) {
	return io.NopCloser(strings.NewReader(f.vtyshOut)), func() error { return nil }, nil
}

func (f fakeBGPExecutor) VtyshDaemon(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

func (f fakeBGPExecutor) VtyshLoadDaemon(context.Context, string, string) ([]byte, error) {
	return nil, nil
}

// makeFRRBGPOutput renders route tuples into an FRR `show bgp ipv4 unicast`-
// style block. GetBGPRoutes keeps lines starting with "*"/" " that have >=3
// fields, taking Network=fields[1], NextHop=fields[2], Path=join(fields[4:]).
func makeFRRBGPOutput(routes [][3]string) string {
	var b strings.Builder
	// A header line that starts with neither "*" nor " " is ignored by the parser.
	b.WriteString("BGP table version is 1, local router ID is 10.0.0.1\n")
	for _, r := range routes {
		// "*> <network> <nexthop> <metric> <path...>" — field[3] (metric) is
		// dropped by the parser; everything from field[4] on is the Path.
		fmt.Fprintf(&b, "*> %s %s 0 %s\n", r[0], r[1], r[2])
	}
	return b.String()
}

func newBGPServer(t *testing.T, vtyshOut string) *Server {
	t.Helper()
	mgr := frr.NewForTest(t.TempDir()+"/frr.conf", fakeBGPExecutor{vtyshOut: vtyshOut})
	return &Server{frr: mgr}
}

// bufferedBGPResponse reproduces the exact bytes the pre-#4708 buffered handler
// produced: writeOK(TextResponse{Output: <lines>}), i.e. json.Encoder over the
// Response envelope (HTML-escaping on, trailing newline). This is the golden
// the streamed output must match byte-for-byte.
func bufferedBGPResponse(t *testing.T, routes []frr.BGPRoute) []byte {
	t.Helper()
	var lines strings.Builder
	for _, route := range routes {
		fmt.Fprintf(&lines, "%-24s %-20s %s\n", route.Network, route.NextHop, route.Path)
	}
	var out bytes.Buffer
	if err := json.NewEncoder(&out).Encode(Response{Success: true, Data: TextResponse{Output: lines.String()}}); err != nil {
		t.Fatalf("encode golden: %v", err)
	}
	return out.Bytes()
}

func TestBGPRoutesStreamWireFormat(t *testing.T) {
	cases := []struct {
		name   string
		routes [][3]string
	}{
		{
			name: "representative",
			routes: [][3]string{
				{"10.0.0.0/24", "192.168.1.1", "65001 65002 i"},
				{"10.1.0.0/16", "192.168.1.2", "65003 i"},
				{"2001:db8::/32", "fe80::1", "65004 65005 65006 i"},
				// A path containing every character encoding/json escapes
				// specially (<, >, &, ", \) proves the streamed per-line
				// escaper is byte-identical to escaping the joined string.
				{"172.16.0.0/12", "10.9.8.7", `x<y>&"z\w`},
			},
		},
		{
			name:   "empty",
			routes: nil, // no routes -> {"output":""}, must not panic
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newBGPServer(t, makeFRRBGPOutput(tc.routes))

			// Golden: parse via the real code path, then render the buffered form.
			parsed, err := s.frr.GetBGPRoutes(context.Background())
			if err != nil {
				t.Fatalf("GetBGPRoutes: %v", err)
			}
			if len(parsed) != len(tc.routes) {
				t.Fatalf("parsed %d routes, want %d", len(parsed), len(tc.routes))
			}
			golden := bufferedBGPResponse(t, parsed)

			req := httptest.NewRequest(http.MethodGet, "/api/routing/bgp?type=routes", nil)
			rec := httptest.NewRecorder()
			s.bgpHandler(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}

			// Byte-for-byte equivalence with the buffered form.
			if got := rec.Body.Bytes(); !bytes.Equal(got, golden) {
				t.Fatalf("streamed body != buffered golden\n got: %q\nwant: %q", got, golden)
			}

			// Schema + content: decodes cleanly, all routes present in order.
			var resp struct {
				Success bool         `json:"success"`
				Data    TextResponse `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatalf("unmarshal streamed response: %v", err)
			}
			if !resp.Success {
				t.Errorf("success = false, want true")
			}
			assertRoutesInOrder(t, resp.Data.Output, parsed)
		})
	}
}

// flushRecorder is a ResponseWriter that records how the handler writes: the
// number of Write calls, the largest single Write, and the number of Flush
// calls. It proves the response is streamed in bounded chunks rather than
// materialized as one payload.
type flushRecorder struct {
	hdr      http.Header
	buf      bytes.Buffer
	status   int
	writes   int
	maxWrite int
	flushes  int
}

func (r *flushRecorder) Header() http.Header {
	if r.hdr == nil {
		r.hdr = http.Header{}
	}
	return r.hdr
}
func (r *flushRecorder) WriteHeader(s int) { r.status = s }
func (r *flushRecorder) Write(p []byte) (int, error) {
	r.writes++
	if len(p) > r.maxWrite {
		r.maxWrite = len(p)
	}
	return r.buf.Write(p)
}
func (r *flushRecorder) Flush() { r.flushes++ }

var _ http.ResponseWriter = (*flushRecorder)(nil)
var _ http.Flusher = (*flushRecorder)(nil)

func TestBGPRoutesStreamNonBuffering(t *testing.T) {
	const n = 3000
	routes := make([][3]string, n)
	for i := 0; i < n; i++ {
		routes[i] = [3]string{
			fmt.Sprintf("10.%d.%d.0/24", i/256, i%256),
			fmt.Sprintf("192.168.%d.%d", i/256, i%256),
			fmt.Sprintf("65000 %d i", i),
		}
	}
	s := newBGPServer(t, makeFRRBGPOutput(routes))
	parsed, err := s.frr.GetBGPRoutes(context.Background())
	if err != nil {
		t.Fatalf("GetBGPRoutes: %v", err)
	}
	if len(parsed) != n {
		t.Fatalf("parsed %d routes, want %d", len(parsed), n)
	}

	rec := &flushRecorder{}
	req := httptest.NewRequest(http.MethodGet, "/api/routing/bgp?type=routes", nil)
	s.bgpHandler(rec, req)

	if rec.status != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.status)
	}
	// Non-buffering: the largest single Write to the ResponseWriter is bounded
	// by the internal bufio buffer (4096), NOT the ~200KB full table. This is
	// the memory-bounding guarantee (#4708).
	const bufioCap = 4096
	if rec.maxWrite > bufioCap {
		t.Errorf("largest single Write = %d bytes, want <= %d (table not streamed in bounded chunks)", rec.maxWrite, bufioCap)
	}
	if rec.writes <= 1 {
		t.Errorf("Write called %d times, want > 1 (response was buffered into one payload)", rec.writes)
	}
	if rec.flushes < 1 {
		t.Errorf("Flush called %d times, want >= 1 (response not flushed incrementally)", rec.flushes)
	}

	// Correctness still holds for the large table: byte-equivalent + all routes.
	golden := bufferedBGPResponse(t, parsed)
	if !bytes.Equal(rec.buf.Bytes(), golden) {
		t.Fatalf("large streamed body != buffered golden (len got=%d want=%d)", rec.buf.Len(), len(golden))
	}
	var resp struct {
		Success bool         `json:"success"`
		Data    TextResponse `json:"data"`
	}
	if err := json.Unmarshal(rec.buf.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal large streamed response: %v", err)
	}
	assertRoutesInOrder(t, resp.Data.Output, parsed)
}

// assertRoutesInOrder verifies every route appears, in order, as its rendered
// line inside the decoded output field.
func assertRoutesInOrder(t *testing.T, output string, routes []frr.BGPRoute) {
	t.Helper()
	if len(routes) == 0 {
		if output != "" {
			t.Errorf("empty table output = %q, want \"\"", output)
		}
		return
	}
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	if len(lines) != len(routes) {
		t.Fatalf("output line count = %d, want %d", len(lines), len(routes))
	}
	for i, route := range routes {
		want := fmt.Sprintf("%-24s %-20s %s", route.Network, route.NextHop, route.Path)
		if lines[i] != want {
			t.Fatalf("line %d = %q, want %q (routes dropped/reordered)", i, lines[i], want)
		}
	}
}
