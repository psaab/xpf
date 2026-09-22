package api

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// multiSessionDP yields a deterministic set of forward sessions for
// filter/pagination tests. It implements both the offset iterators
// (IterateSessions/V6) and the cursor iterators (IterateSessionsFrom/V6From)
// so it can drive both REST pagination paths.
type multiSessionDP struct {
	*dataplane.Manager
	v4 []struct {
		key dataplane.SessionKey
		val dataplane.SessionValue
	}
	v6 []struct {
		key dataplane.SessionKeyV6
		val dataplane.SessionValueV6
	}
}

func (d *multiSessionDP) IsLoaded() bool { return true }

func newMultiSessionDP() *multiSessionDP {
	d := &multiSessionDP{Manager: dataplane.New()}
	// Three TCP v4 sessions, distinct dst ports, with non-zero counters so
	// the cursor==offset COUNTER parity assertion is meaningful.
	for i, dport := range []uint16{80, 443, 8080} {
		d.v4 = append(d.v4, struct {
			key dataplane.SessionKey
			val dataplane.SessionValue
		}{
			key: dataplane.SessionKey{
				SrcIP:    [4]byte{10, 0, 1, byte(5 + i)},
				DstIP:    [4]byte{10, 0, 2, 7},
				SrcPort:  ntohs(uint16(10000 + i)),
				DstPort:  ntohs(dport),
				Protocol: 6,
			},
			val: dataplane.SessionValue{
				State:       dataplane.SessStateEstablished,
				IngressZone: 2,
				EgressZone:  3,
				FwdPackets:  uint64(10 + i),
				FwdBytes:    uint64(1000 + i),
				RevPackets:  uint64(5 + i),
				RevBytes:    uint64(500 + i),
			},
		})
	}
	// One v6 UDP session.
	d.v6 = append(d.v6, struct {
		key dataplane.SessionKeyV6
		val dataplane.SessionValueV6
	}{
		key: dataplane.SessionKeyV6{
			SrcIP:    [16]byte{0x20, 0x01, 0x05, 0x59},
			DstIP:    [16]byte{0x20, 0x01, 0x05, 0x60},
			SrcPort:  ntohs(20000),
			DstPort:  ntohs(53),
			Protocol: 17,
		},
		val: dataplane.SessionValueV6{
			State:       dataplane.SessStateEstablished,
			IngressZone: 2,
			EgressZone:  3,
			FwdPackets:  77,
			FwdBytes:    7777,
		},
	})
	return d
}

// GetSessionV4/V6 return a fixed reverse-counter delta for ANY key, so the
// reverse-counter merge in enrichSessionV4/V6 actually changes the rendered
// counters. This makes the cursor==offset COUNTER parity test able to detect
// a cursor path that bypasses the merge (e.g. calling sessionEntryV4 directly
// instead of the shared enrichSessionV4).
func (d *multiSessionDP) GetSessionV4(dataplane.SessionKey) (dataplane.SessionValue, error) {
	return dataplane.SessionValue{RevPackets: 100, RevBytes: 9000, FwdPackets: 1, FwdBytes: 2}, nil
}

func (d *multiSessionDP) GetSessionV6(dataplane.SessionKeyV6) (dataplane.SessionValueV6, error) {
	return dataplane.SessionValueV6{RevPackets: 100, RevBytes: 9000, FwdPackets: 1, FwdBytes: 2}, nil
}

func (d *multiSessionDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for _, e := range d.v4 {
		if !fn(e.key, e.val) {
			return nil
		}
	}
	return nil
}

func (d *multiSessionDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for _, e := range d.v6 {
		if !fn(e.key, e.val) {
			return nil
		}
	}
	return nil
}

// IterateSessionsFrom resumes AFTER cursor (matching the dataplane Manager
// contract). A nil cursor starts at the beginning.
func (d *multiSessionDP) IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	started := cursor == nil
	for _, e := range d.v4 {
		if !started {
			if e.key == *cursor {
				started = true
			}
			continue
		}
		if !fn(e.key, e.val) {
			return nil
		}
	}
	return nil
}

func (d *multiSessionDP) IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	started := cursor == nil
	for _, e := range d.v6 {
		if !started {
			if e.key == *cursor {
				started = true
			}
			continue
		}
		if !fn(e.key, e.val) {
			return nil
		}
	}
	return nil
}

func newProtocolMatrixDP() *multiSessionDP {
	d := &multiSessionDP{Manager: dataplane.New()}
	for i, proto := range []uint8{6, 6, 17, 47, 132, 0, 7, 41, 255} {
		d.v4 = append(d.v4, struct {
			key dataplane.SessionKey
			val dataplane.SessionValue
		}{
			key: dataplane.SessionKey{
				SrcIP:    [4]byte{10, 0, 3, byte(i + 1)},
				DstIP:    [4]byte{10, 0, 4, byte(i + 1)},
				SrcPort:  ntohs(uint16(30000 + i)),
				DstPort:  ntohs(uint16(1000 + i)),
				Protocol: proto,
			},
			val: dataplane.SessionValue{
				State:       dataplane.SessStateEstablished,
				IngressZone: 2,
				EgressZone:  3,
				FwdPackets:  uint64(i + 1),
				FwdBytes:    uint64(100 + i),
			},
		})
	}
	for i, proto := range []uint8{17, dataplane.ProtoICMPv6} {
		d.v6 = append(d.v6, struct {
			key dataplane.SessionKeyV6
			val dataplane.SessionValueV6
		}{
			key: dataplane.SessionKeyV6{
				SrcIP:    [16]byte{0x20, 0x01, 0xdb, 0x08, byte(i + 1)},
				DstIP:    [16]byte{0x20, 0x01, 0xdb, 0x09, byte(i + 1)},
				SrcPort:  ntohs(uint16(40000 + i)),
				DstPort:  ntohs(uint16(2000 + i)),
				Protocol: proto,
			},
			val: dataplane.SessionValueV6{
				State:       dataplane.SessStateEstablished,
				IngressZone: 2,
				EgressZone:  3,
				FwdPackets:  uint64(i + 1),
				FwdBytes:    uint64(200 + i),
			},
		})
	}
	return d
}

// TestRESTSessionPrefixPortFilters asserts the #3421 M2 contract: REST
// session list accepts source/destination prefix and source/destination
// port filters with gRPC-parity semantics.
//
// FAIL-ON-REVERT: removing the srcNet/dstNet/srcPort/dstPort predicates from
// sessionQuery.matchV4 (or dropping their parse in buildSessionQuery) makes
// every filtered case return all three v4 rows, flipping the narrowed want
// counts red.
func TestRESTSessionPrefixPortFilters(t *testing.T) {
	s := &Server{dp: newMultiSessionDP()}

	cases := []struct {
		name string
		q    string
		want int
	}{
		{"no filter", "", 4}, // 3 v4 + 1 v6
		{"source_prefix matches one", "source_prefix=10.0.1.5/32", 1},
		{"source_prefix subnet matches all v4", "source_prefix=10.0.1.0/24", 3},
		{"destination_port 443", "destination_port=443", 1},
		{"destination_port none", "destination_port=22", 0},
		{"source_port 10000", "source_port=10000", 1},
		{"dest_prefix v6", "destination_prefix=2001:560::/32", 1},
		{"combined src+dport", "source_prefix=10.0.1.0/24&destination_port=80", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			url := "/api/v1/security/sessions"
			if tc.q != "" {
				url += "?" + tc.q
			}
			rr := httptest.NewRecorder()
			s.sessionsHandler(rr, httptest.NewRequest("GET", url, nil))
			if rr.Code != 200 {
				t.Fatalf("status %d, want 200; body: %s", rr.Code, rr.Body.String())
			}
			got := len(decodeSessions(t, rr.Body.Bytes()).Sessions)
			if got != tc.want {
				t.Fatalf("%s: %d sessions, want %d", tc.name, got, tc.want)
			}
		})
	}
}

// TestRESTSessionFilterFailsClosed asserts the #3421 M2/M8 contract: a
// malformed prefix/port/page_size/limit/offset must return HTTP 400, not
// silently zero the predicate (widening the query) or default the page.
//
// FAIL-ON-REVERT: reverting parseRESTSessionFilter to silently drop a bad
// value, or restoring queryInt for limit/offset/page_size, makes these
// requests return HTTP 200, flipping every want-400 case red.
func TestRESTSessionFilterFailsClosed(t *testing.T) {
	s := &Server{dp: newMultiSessionDP()}

	cases := []struct {
		name   string
		q      string
		want   int
		reason string
	}{
		{"bad source_prefix", "source_prefix=10.0.0.300/24", 400, ""},
		{"bad destination_prefix", "destination_prefix=notanip", 400, ""},
		{"bad source_port", "source_port=abc", 400, ""},
		{"out-of-range destination_port", "destination_port=70000", 400, ""},
		{"bad limit", "limit=abc", 400, ""},
		{"negative offset", "offset=-5", 400, ""},
		{"bad page_size", "page_size=abc", 400, ""},
		{"negative page_size", "page_size=-1", 400, ""},
		{"bad protocol", "protocol=tcpip", 400, "invalid protocol filter: tcpip"},
		{"bogus protocol", "protocol=bogus", 400, "invalid protocol filter: bogus"},
		{"out-of-range protocol", "protocol=256", 400, "invalid protocol filter: 256"},
		{"negative protocol", "protocol=-1", 400, "invalid protocol filter: -1"},
		{"bad signed protocol", "protocol=%2B6", 400, "invalid protocol filter: +6"},
		{"bad space-padded protocol", "protocol=%206", 400, "invalid protocol filter:  6"},
		{"valid", "source_prefix=10.0.1.0/24&destination_port=443", 200, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			s.sessionsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions?"+tc.q, nil))
			if rr.Code != tc.want {
				t.Fatalf("%s: status %d, want %d; body: %s", tc.name, rr.Code, tc.want, rr.Body.String())
			}
			if tc.reason != "" && !strings.Contains(rr.Body.String(), tc.reason) {
				t.Fatalf("%s: body %q does not contain reason %q", tc.name, rr.Body.String(), tc.reason)
			}
		})
	}
}
func TestRESTSessionProtocolErrorPreservesEncodedPlus(t *testing.T) {
	s := &Server{dp: newMultiSessionDP()}
	rr := httptest.NewRecorder()
	s.sessionsHandler(rr, httptest.NewRequest(
		"GET", "/api/v1/security/sessions?protocol=%2B6", nil,
	))
	if rr.Code != 400 {
		t.Fatalf("protocol=%%2B6: status %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "invalid protocol filter: +6") {
		t.Fatalf("protocol=%%2B6: body %q does not preserve decoded +6", rr.Body.String())
	}
}

func TestRESTInvalidProtocolIncludePeerStopsFanout(t *testing.T) {
	fake := &fakeClusterSessionService{}
	s := &Server{
		dp:               newMultiSessionDP(),
		clusterSessionFn: func() ClusterSessionService { return fake },
	}
	rr := httptest.NewRecorder()
	s.sessionsHandler(rr, httptest.NewRequest(
		"GET", "/api/v1/security/sessions?protocol=tcpip&include_peer=true", nil,
	))
	if rr.Code != 400 {
		t.Fatalf("status %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
	if fake.peerGetCalled || fake.getCalled {
		t.Fatal("invalid protocol reached peer fan-out")
	}
}

func TestRESTProtocolFilterMatrix(t *testing.T) {
	cases := []struct {
		name   string
		query  string
		status int
		count  int
	}{
		{"tcp", "protocol=tcp", 200, 2},
		{"TCP", "protocol=TCP", 200, 2},
		{"numeric tcp", "protocol=6", 200, 2},
		{"numeric GRE", "protocol=47", 200, 1},
		{"gre", "protocol=gre", 200, 1},
		{"GRE", "protocol=GRE", 200, 1},
		{"ipv6", "protocol=ipv6", 200, 1},
		{"zero", "protocol=0", 200, 1},
		{"255", "protocol=255", 200, 1},
		{"007", "protocol=007", 200, 1},
		{"sctp", "protocol=sctp", 200, 1},
		{"space-padded name", "protocol=%20tcp%20", 200, 2},
		{"tcpip", "protocol=tcpip", 400, 0},
		{"bogus", "protocol=bogus", 400, 0},
		{"256", "protocol=256", 400, 0},
		{"negative", "protocol=-1", 400, 0},
		{"space-padded numeric", "protocol=%206", 400, 0},
		{"signed numeric", "protocol=%2B6", 400, 0},
		{"absent", "", 200, 11},
		{"explicit empty", "protocol=", 200, 11},
	}
	for _, mode := range []struct {
		name  string
		query string
	}{
		{"offset", "limit=100"},
		{"cursor", "page_size=100"},
	} {
		for _, tc := range cases {
			t.Run(mode.name+"/"+tc.name, func(t *testing.T) {
				query := mode.query
				if tc.query != "" {
					query += "&" + tc.query
				}
				rr := httptest.NewRecorder()
				s := &Server{dp: newProtocolMatrixDP()}
				s.sessionsHandler(rr, httptest.NewRequest(
					"GET", "/api/v1/security/sessions?"+query, nil,
				))
				if rr.Code != tc.status {
					t.Fatalf("status %d, want %d; body: %s", rr.Code, tc.status, rr.Body.String())
				}
				if rr.Code == 200 {
					if got := len(decodeSessions(t, rr.Body.Bytes()).Sessions); got != tc.count {
						t.Fatalf("sessions=%d, want %d; body: %s", got, tc.count, rr.Body.String())
					}
				}
			})
		}
	}
}

// TestRESTSessionCursorPagination asserts the #3421 H4 contract: with
// page_size>0 REST paginates over a stable cursor, returning a
// next_page_token that resumes exactly after the last row with no skips or
// duplicates, and an empty token on the final page.
//
// FAIL-ON-REVERT: removing the page_size>0 cursor branch (so page_size is
// ignored and the offset path runs) makes the first request return all 4
// sessions with no next_page_token, flipping the page-boundary assertions.
func TestRESTSessionCursorPagination(t *testing.T) {
	s := &Server{dp: newMultiSessionDP()}

	var seen []string
	token := ""
	pages := 0
	for {
		url := "/api/v1/security/sessions?page_size=2"
		if token != "" {
			url += "&page_token=" + token
		}
		rr := httptest.NewRecorder()
		s.sessionsHandler(rr, httptest.NewRequest("GET", url, nil))
		if rr.Code != 200 {
			t.Fatalf("page %d: status %d, want 200; body: %s", pages, rr.Code, rr.Body.String())
		}
		resp := decodeSessions(t, rr.Body.Bytes())
		if len(resp.Sessions) > 2 {
			t.Fatalf("page %d returned %d rows, want <= page_size 2", pages, len(resp.Sessions))
		}
		for _, se := range resp.Sessions {
			seen = append(seen, se.SrcAddr+":"+se.DstAddr)
		}
		pages++
		if resp.NextPageToken == "" {
			break
		}
		token = resp.NextPageToken
		if pages > 10 {
			t.Fatal("pagination did not terminate")
		}
	}

	// All 4 sessions returned exactly once across pages.
	if len(seen) != 4 {
		t.Fatalf("cursor pagination returned %d total rows, want 4 (rows: %v)", len(seen), seen)
	}
	uniq := map[string]bool{}
	for _, k := range seen {
		if uniq[k] {
			t.Fatalf("duplicate row across pages: %s", k)
		}
		uniq[k] = true
	}
}

// TestRESTSessionCursorOffsetParity asserts the #3421 rework contract: the
// cursor path and the offset path report IDENTICAL rows and counters for the
// same dataset, because both share #3419's sessionQuery + sessionView +
// enriched sessionEntryV4/V6 + reverse-counter merge.
//
// FAIL-ON-REVERT: wiring the cursor path to a parallel filter/entry builder
// (the pre-rework restSessionFilter that dropped #3419's enrichment) makes
// the cursor rows diverge from the offset rows (missing fields/counters),
// flipping this assertion red.
func TestRESTSessionCursorOffsetParity(t *testing.T) {
	s := &Server{dp: newMultiSessionDP()}

	// Offset path: one big page.
	rr := httptest.NewRecorder()
	s.sessionsHandler(rr, httptest.NewRequest("GET", "/api/v1/security/sessions?limit=100", nil))
	if rr.Code != 200 {
		t.Fatalf("offset: status %d; body: %s", rr.Code, rr.Body.String())
	}
	offsetRows := decodeSessions(t, rr.Body.Bytes()).Sessions

	// Cursor path: walk all pages and concatenate.
	var cursorRows []SessionEntry
	token := ""
	for i := 0; ; i++ {
		url := "/api/v1/security/sessions?page_size=2"
		if token != "" {
			url += "&page_token=" + token
		}
		crr := httptest.NewRecorder()
		s.sessionsHandler(crr, httptest.NewRequest("GET", url, nil))
		if crr.Code != 200 {
			t.Fatalf("cursor page %d: status %d; body: %s", i, crr.Code, crr.Body.String())
		}
		resp := decodeSessions(t, crr.Body.Bytes())
		cursorRows = append(cursorRows, resp.Sessions...)
		if resp.NextPageToken == "" {
			break
		}
		token = resp.NextPageToken
		if i > 10 {
			t.Fatal("pagination did not terminate")
		}
	}

	if len(offsetRows) != len(cursorRows) {
		t.Fatalf("row count differs: offset=%d cursor=%d", len(offsetRows), len(cursorRows))
	}
	// Index both by 5-tuple identity, then assert per-row field+counter equality.
	idx := func(se SessionEntry) string {
		return fmt.Sprintf("%s:%d-%s:%d/%s", se.SrcAddr, se.SrcPort, se.DstAddr, se.DstPort, se.Protocol)
	}
	om := map[string]SessionEntry{}
	for _, se := range offsetRows {
		om[idx(se)] = se
	}
	for _, c := range cursorRows {
		o, ok := om[idx(c)]
		if !ok {
			t.Fatalf("cursor row %s not present in offset rows", idx(c))
		}
		if c != o {
			t.Fatalf("cursor row %s differs from offset row:\n cursor=%+v\n offset=%+v", idx(c), c, o)
		}
	}
}

// TestRESTSessionCursorBadToken asserts a malformed page_token returns 400.
func TestRESTSessionCursorBadToken(t *testing.T) {
	s := &Server{dp: newMultiSessionDP()}
	rr := httptest.NewRecorder()
	s.sessionsHandler(rr, httptest.NewRequest("GET",
		"/api/v1/security/sessions?page_size=2&page_token=!!!notbase64", nil))
	if rr.Code != 400 {
		t.Fatalf("bad page_token: status %d, want 400; body: %s", rr.Code, rr.Body.String())
	}
}

// clearAllDP records ClearAllSessions calls.
type clearAllDP struct {
	*dataplane.Manager
	cleared bool
}

func (d *clearAllDP) IsLoaded() bool { return true }
func (d *clearAllDP) ClearAllSessions() (int, int, error) {
	d.cleared = true
	return 1, 0, nil
}

// TestRESTClearRejectsFilters asserts the #3421 H6 contract: the REST
// clear endpoint clears ALL local sessions and must reject any query string
// or request body with HTTP 400 rather than silently ignoring filter
// parameters and wiping the whole table. A parameterless clear proceeds.
//
// FAIL-ON-REVERT: removing the query/body guard makes the filtered request
// reach ClearAllSessions and return 200, flipping the want-400 case (and the
// cleared-flag assertion) red.
//
// The "malformed query" and "empty-value param" sub-cases specifically pin
// why the guard tests r.URL.RawQuery rather than len(r.URL.Query()) > 0:
//   - `?%zz` is an un-decodable percent-escape. url.Query() swallows the
//     parse error and yields an EMPTY map (len 0), so a Query()-based guard
//     would let it through and clear the whole table. RawQuery != "" rejects.
//   - `?zone=` is a present-but-empty-value param. Both url.Query() (len 1)
//     and RawQuery != "" reject it, but this case proves RawQuery does not
//     under-reject a syntactically valid empty-value filter request.
func TestRESTClearRejectsFilters(t *testing.T) {
	t.Run("filtered clear rejected", func(t *testing.T) {
		dp := &clearAllDP{Manager: dataplane.New()}
		s := &Server{dp: dp}
		rr := httptest.NewRecorder()
		s.clearSessionsHandler(rr, httptest.NewRequest("POST",
			"/api/v1/security/sessions/clear?zone=trust", nil))
		if rr.Code != 400 {
			t.Fatalf("filtered clear: status %d, want 400; body: %s", rr.Code, rr.Body.String())
		}
		if dp.cleared {
			t.Fatal("filtered clear wiped the table; want no ClearAllSessions call")
		}
	})

	t.Run("malformed query rejected", func(t *testing.T) {
		dp := &clearAllDP{Manager: dataplane.New()}
		s := &Server{dp: dp}
		req := httptest.NewRequest("POST",
			"/api/v1/security/sessions/clear", nil)
		// Carry an un-decodable percent-escape verbatim in RawQuery.
		// url.Query() would parse this to an empty map (len 0) and a
		// Query()-based guard would wrongly proceed to clear-all.
		req.URL.RawQuery = "%zz"
		if got := req.URL.Query(); len(got) != 0 {
			t.Fatalf("precondition: url.Query() of %q = %v (len %d), want empty map",
				req.URL.RawQuery, got, len(got))
		}
		rr := httptest.NewRecorder()
		s.clearSessionsHandler(rr, req)
		if rr.Code != 400 {
			t.Fatalf("malformed query: status %d, want 400; body: %s", rr.Code, rr.Body.String())
		}
		if dp.cleared {
			t.Fatal("malformed query wiped the table; want no ClearAllSessions call")
		}
	})

	t.Run("empty-value param rejected", func(t *testing.T) {
		dp := &clearAllDP{Manager: dataplane.New()}
		s := &Server{dp: dp}
		req := httptest.NewRequest("POST",
			"/api/v1/security/sessions/clear", nil)
		// Present-but-empty value: `?zone=`. RawQuery != "" must still reject.
		req.URL.RawQuery = "zone="
		rr := httptest.NewRecorder()
		s.clearSessionsHandler(rr, req)
		if rr.Code != 400 {
			t.Fatalf("empty-value param: status %d, want 400; body: %s", rr.Code, rr.Body.String())
		}
		if dp.cleared {
			t.Fatal("empty-value param wiped the table; want no ClearAllSessions call")
		}
	})

	t.Run("parameterless clear proceeds", func(t *testing.T) {
		dp := &clearAllDP{Manager: dataplane.New()}
		s := &Server{dp: dp}
		rr := httptest.NewRecorder()
		s.clearSessionsHandler(rr, httptest.NewRequest("POST",
			"/api/v1/security/sessions/clear", nil))
		if rr.Code != 200 {
			t.Fatalf("clear-all: status %d, want 200; body: %s", rr.Code, rr.Body.String())
		}
		if !dp.cleared {
			t.Fatal("parameterless clear did not call ClearAllSessions")
		}
	})
}
