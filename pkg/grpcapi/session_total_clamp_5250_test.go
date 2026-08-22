// #5250 (A8-b2 F3): the session/NAT totals published over gRPC are int32
// protobuf fields fed from 64-bit accumulators. A bare `int32(v)` conversion
// WRAPS NEGATIVE past MaxInt32 — an operator reading `show security flow
// session summary` on a very large table would see a negative session count
// rather than a saturated one. A clampInt32 helper (server_nat.go, #2282)
// already existed in this package and simply was not applied at these sites.
//
// FAIL-ON-REVERT: restore `resp.Total = int32(v4 + v6)` in setSessionsTotal
// and TestSessionsTotalSaturates_5250 goes RED with a negative Total. Restore
// the int32 fields on natSessionCounts and TestNATSessionCountsAre64Bit_5250
// goes RED — that accumulator now cannot silently wrap while being built.
//
// Scope note (honest): the FILTERED count path (setSessionsTotal's iterator
// scan) and countNATSessions' per-rule-set map are only reachable past
// MaxInt32 by iterating >2^31 sessions, which no unit test can drive. Those
// two sites share the clamp helper asserted here and the 64-bit accumulator
// asserted below; neither is independently drivable in a unit test.
package grpcapi

import (
	"math"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// hugeCountDP reports a v4+v6 session total past MaxInt32.
type hugeCountDP struct {
	*dataplane.Manager
	v4, v6 int
}

func (*hugeCountDP) IsLoaded() bool { return true }

func (d *hugeCountDP) SessionCount() (int, int) { return d.v4, d.v6 }

func TestSessionsTotalSaturates_5250(t *testing.T) {
	dp := &hugeCountDP{Manager: dataplane.New(), v4: math.MaxInt32 - 1, v6: 10}
	s := &Server{dp: dp, store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))}

	resp := &pb.GetSessionsResponse{}
	if err := s.setSessionsTotal(resp, &sessionFilter{}); err != nil {
		t.Fatalf("setSessionsTotal: %v", err)
	}
	if resp.Total < 0 {
		t.Fatalf("Total = %d, want a saturated non-negative count (int32 conversion wrapped)", resp.Total)
	}
	if resp.Total != math.MaxInt32 {
		t.Fatalf("Total = %d, want %d (saturate at the int32 ceiling)", resp.Total, int32(math.MaxInt32))
	}
}

func TestNATSessionCountsAre64Bit_5250(t *testing.T) {
	ty := reflect.TypeOf(natSessionCounts{})
	f, ok := ty.FieldByName("total")
	if !ok {
		t.Fatal("natSessionCounts has no field total")
	}
	if f.Type.Kind() != reflect.Int64 {
		t.Fatalf("natSessionCounts.total is %s, want int64 — a 32-bit accumulator wraps NEGATIVE while counting, before any clamp can run", f.Type)
	}
	m, ok := ty.FieldByName("ruleSetSessions")
	if !ok {
		t.Fatal("natSessionCounts has no field ruleSetSessions")
	}
	if m.Type.Elem().Kind() != reflect.Int64 {
		t.Fatalf("natSessionCounts.ruleSetSessions value type is %s, want int64", m.Type.Elem())
	}
}

// The clamp itself: the boundary the two undrivable sites rely on.
func TestClampInt32Saturates_5250(t *testing.T) {
	for _, tc := range []struct {
		in   int64
		want int32
	}{
		{math.MaxInt32, math.MaxInt32},
		{math.MaxInt32 + 1, math.MaxInt32},
		{int64(math.MaxInt32) * 4, math.MaxInt32},
		{0, 0},
		{7, 7},
	} {
		if got := clampInt32(tc.in); got != tc.want {
			t.Errorf("clampInt32(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
