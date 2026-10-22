// #5319: `show ... sessions-top:{bytes,packets}` must (a) select the top-K
// (20) sessions with a bounded min-heap over a CHEAP metric and enrich only
// the <=K survivors — not full-sort + full-enrich all N — and (b) surface a
// backend iterator error instead of returning a partial ranking as success.
//
// FAIL-ON-REVERT:
//   - TestSessionsTopBoundedSelectionMatchesFullSort pins that the bounded
//     heap yields the SAME top-20 rows in the SAME order a full sort would.
//   - TestSessionsTopSurfacesIteratorError pins the error surfacing: restoring
//     `_ = s.dp.IterateSessions(...)` makes ShowText return a non-error partial
//     result and the want-Internal assertion goes RED.
//   - TestSessionsTopEnrichesOnlySurvivors pins the deferral: enriching inside
//     the iteration loop (the pre-#5319 shape) calls resolveSessionName N times
//     instead of <=K, turning the count assertion RED.
package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// topFakeSession is a family-tagged synthetic session with a distinct metric.
type topFakeSession struct {
	isV6   bool
	metric uint64
	port   uint16
}

// topSessionsDP feeds a fixed set of forward sessions across the v4 and v6
// iterators and reports the dataplane as loaded. FwdBytes == FwdPackets ==
// metric and rev counters are 0, so the bytes and packets sort keys both
// equal metric — the top-K is uniquely determined by the distinct metrics.
type topSessionsDP struct {
	*dataplane.Manager
	sessions []topFakeSession
}

func (d *topSessionsDP) IsLoaded() bool { return true }

func (d *topSessionsDP) IterateSessions(cb func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	for i, s := range d.sessions {
		if s.isV6 {
			continue
		}
		key := dataplane.SessionKey{
			SrcIP:    [4]byte{10, 0, byte(i >> 8), byte(i)},
			DstIP:    [4]byte{172, 16, 80, 8},
			SrcPort:  hostToNetwork16(s.port),
			DstPort:  hostToNetwork16(443),
			Protocol: 6,
		}
		val := dataplane.SessionValue{
			FwdBytes:   s.metric,
			FwdPackets: s.metric,
		}
		if !cb(key, val) {
			return nil
		}
	}
	return nil
}

func (d *topSessionsDP) IterateSessionsV6(cb func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	for i, s := range d.sessions {
		if !s.isV6 {
			continue
		}
		key := dataplane.SessionKeyV6{
			SrcIP:    [16]byte{0x20, 0x01, 0x05, 0x59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 8), byte(i)},
			DstIP:    [16]byte{0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00},
			SrcPort:  hostToNetwork16(s.port),
			DstPort:  hostToNetwork16(443),
			Protocol: 6,
		}
		val := dataplane.SessionValueV6{
			FwdBytes:   s.metric,
			FwdPackets: s.metric,
		}
		if !cb(key, val) {
			return nil
		}
	}
	return nil
}

// buildTopSessions returns 30 sessions (6 v6, 24 v4) with 30 distinct metrics
// scrambled out of insertion order so the min-heap actually has to reorder,
// and with high-metric v6 sessions interleaved so the top-20 crosses BOTH
// families (matching the current cross-family ranking).
func buildTopSessions() []topFakeSession {
	const n = 30
	out := make([]topFakeSession, 0, n)
	for i := 0; i < n; i++ {
		// perm is a bijection over [0,n) since gcd(7,30)==1 -> distinct metrics.
		perm := (i*7 + 11) % n
		out = append(out, topFakeSession{
			isV6:   i%5 == 0, // 6 v6 sessions at i = 0,5,10,15,20,25
			metric: uint64(perm)*1000 + 500,
			port:   uint16(10000 + i),
		})
	}
	return out
}

// parseTopMetrics extracts the per-row forward byte/packet counter (== metric)
// from `sessions-top` output, in row order, plus the "of N total" count.
func parseTopMetrics(t *testing.T, out string) (metrics []uint64, total int) {
	t.Helper()
	seenHeader := false
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "sessions by") {
			// "Top 20 sessions by bytes (of 30 total):"
			for _, f := range strings.Fields(line) {
				if v, err := strconv.Atoi(f); err == nil {
					total = v // last integer on the line is the total
				}
			}
			continue
		}
		if strings.Contains(line, "Source") && strings.Contains(line, "Destination") {
			seenHeader = true
			continue
		}
		if !seenHeader {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		// field[5] == "fwdBytes/revBytes"
		fwd := fields[5]
		if slash := strings.IndexByte(fwd, '/'); slash >= 0 {
			fwd = fwd[:slash]
		}
		v, err := strconv.ParseUint(fwd, 10, 64)
		if err != nil {
			continue
		}
		metrics = append(metrics, v)
	}
	return metrics, total
}

func TestSessionsTopRendersCandidateAddresses(t *testing.T) {
	sessions := buildTopSessions()
	want := make(map[uint64][2]string, len(sessions))
	for i, se := range sessions {
		var src, dst string
		if se.isV6 {
			srcIP := net.IP([]byte{0x20, 0x01, 0x05, 0x59, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i >> 8), byte(i)})
			dstIP := net.IP([]byte{0x20, 0x01, 0x05, 0x59, 0x85, 0x85, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x00})
			src = fmt.Sprintf("[%s]:%d", srcIP, se.port)
			dst = fmt.Sprintf("[%s]:443", dstIP)
		} else {
			src = fmt.Sprintf("10.0.%d.%d:%d", byte(i>>8), byte(i), se.port)
			dst = "172.16.80.8:443"
		}
		want[se.metric] = [2]string{src, dst}
	}

	dp := &topSessionsDP{Manager: dataplane.New(), sessions: sessions}
	s := newViewServer(t, dp)
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "sessions-top:bytes"})
	if err != nil {
		t.Fatalf("ShowText(sessions-top:bytes) error = %v", err)
	}

	seenHeader := false
	rows := 0
	for _, line := range strings.Split(resp.GetOutput(), "\n") {
		if strings.Contains(line, "Source") && strings.Contains(line, "Destination") {
			seenHeader = true
			continue
		}
		if !seenHeader {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		metricText := strings.SplitN(fields[5], "/", 2)[0]
		metric, err := strconv.ParseUint(metricText, 10, 64)
		if err != nil {
			continue
		}
		addresses, ok := want[metric]
		if !ok {
			t.Fatalf("row with unknown metric %d: %q", metric, line)
		}
		if fields[1] != addresses[0] || fields[2] != addresses[1] {
			t.Errorf("metric %d: src/dst = %s %s, want %s %s",
				metric, fields[1], fields[2], addresses[0], addresses[1])
		}
		rows++
	}
	if rows != topSessionsK {
		t.Fatalf("rendered %d address rows, want %d\n%s", rows, topSessionsK, resp.GetOutput())
	}
}

func TestSessionsTopBoundedSelectionMatchesFullSort(t *testing.T) {
	sessions := buildTopSessions()

	// Reference: full descending sort by metric, top 20.
	ref := make([]topFakeSession, len(sessions))
	copy(ref, sessions)
	sort.Slice(ref, func(i, j int) bool { return ref[i].metric > ref[j].metric })
	want := make([]uint64, 0, topSessionsK)
	for i := 0; i < topSessionsK && i < len(ref); i++ {
		want = append(want, ref[i].metric)
	}

	dp := &topSessionsDP{Manager: dataplane.New(), sessions: sessions}
	s := newViewServer(t, dp)

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "sessions-top:bytes"})
	if err != nil {
		t.Fatalf("ShowText(sessions-top:bytes) error = %v", err)
	}
	got, total := parseTopMetrics(t, resp.GetOutput())

	if total != len(sessions) {
		t.Errorf("total = %d, want %d", total, len(sessions))
	}
	if len(got) != len(want) {
		t.Fatalf("returned %d rows, want %d\noutput:\n%s", len(got), len(want), resp.GetOutput())
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("row %d metric = %d, want %d (bounded top-K must match full sort)\ngot:  %v\nwant: %v",
				i, got[i], want[i], got, want)
		}
	}

	// Sanity: the top-20 must include at least one v6 session, proving the
	// ranking is across BOTH families (not v4-only). The v6 metrics are
	// derived from i in {0,5,10,15,20,25}.
	v6InTop := false
	for _, se := range ref[:topSessionsK] {
		if se.isV6 {
			v6InTop = true
			break
		}
	}
	if !v6InTop {
		t.Fatal("test fixture bug: expected at least one v6 session in the top-20")
	}
}

func TestSessionsTopSurfacesIteratorError(t *testing.T) {
	// v4 iterator error.
	dpV4 := &viewFaultGRPCDP{
		Manager: dataplane.New(),
		iterErr: errors.New("helper restart: session map closed"),
	}
	sV4 := newViewServer(t, dpV4)
	if _, err := sV4.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "sessions-top:bytes"}); err == nil {
		t.Fatal("ShowText returned nil error on v4 iterator failure; want codes.Internal")
	} else if status.Code(err) != codes.Internal {
		t.Fatalf("v4 error code = %v, want Internal; err: %v", status.Code(err), err)
	}

	// v6 iterator error (v4 clean).
	dpV6 := &viewFaultGRPCDP{
		Manager:   dataplane.New(),
		iterV6Err: errors.New("helper restart: v6 session map closed"),
	}
	sV6 := newViewServer(t, dpV6)
	if _, err := sV6.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "sessions-top:packets"}); err == nil {
		t.Fatal("ShowText returned nil error on v6 iterator failure; want codes.Internal")
	} else if status.Code(err) != codes.Internal {
		t.Fatalf("v6 error code = %v, want Internal; err: %v", status.Code(err), err)
	}
}

func TestSessionsTopEnrichesOnlySurvivors(t *testing.T) {
	sessions := buildTopSessions() // 30 sessions

	var calls int
	orig := resolveSessionName
	resolveSessionName = func(appNames map[config.AssignedAppID]string, cfg *config.Config, fallback *appid.FallbackIndex, proto uint8, srcPort, dstPort uint16, appID config.AssignedAppID) string {
		calls++
		return appid.ResolveSessionNameWithIndex(appNames, cfg, fallback, proto, srcPort, dstPort, appID)
	}
	defer func() { resolveSessionName = orig }()

	dp := &topSessionsDP{Manager: dataplane.New(), sessions: sessions}
	s := newViewServer(t, dp)

	if _, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "sessions-top:bytes"}); err != nil {
		t.Fatalf("ShowText error = %v", err)
	}

	// Deferral contract: enrich only the <=K survivors, never all N. If the
	// enrichment moves back into the iteration loop (pre-#5319), calls == 30.
	if calls != topSessionsK {
		t.Fatalf("resolveSessionName called %d times, want %d (enrichment must be deferred to the <=K survivors, not run for all %d sessions)",
			calls, topSessionsK, len(sessions))
	}
}
