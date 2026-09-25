package grpcapi

import (
	"context"
	"fmt"
	"math"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestCompleteRejectsNegativePos guards the #2282 negative-Pos slice panic.
// CompleteRequest.pos is an int32 on the wire; before the fix a crafted
// negative value made the upper-bound guard pass (int(-1) < len(text)) and
// slice text[:-1], panicking the handler goroutine. The handler must reject
// any negative position with InvalidArgument and must not panic for any
// position (negative, zero, len, len+1, MinInt32).
//
// Fail-on-revert: removing the `if req.Pos < 0` guard makes the MinInt32 and
// Pos=-1 cases panic (slice bounds out of range), failing this test rather
// than crashing silently in production.
func TestCompleteRejectsNegativePos(t *testing.T) {
	s := &Server{}
	const line = "show security"

	cases := []struct {
		name      string
		pos       int32
		wantError bool
	}{
		{name: "min-int32", pos: math.MinInt32, wantError: true},
		{name: "negative-one", pos: -1, wantError: true},
		{name: "zero", pos: 0, wantError: false},
		{name: "mid", pos: 4, wantError: false},
		{name: "len", pos: int32(len(line)), wantError: false},
		{name: "len-plus-one", pos: int32(len(line)) + 1, wantError: false},
		{name: "far-beyond-len", pos: math.MaxInt32, wantError: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A panic here (e.g. if the guard is reverted) fails the test.
			resp, err := s.Complete(context.Background(), &pb.CompleteRequest{
				Line: line,
				Pos:  tc.pos,
			})
			if tc.wantError {
				if err == nil {
					t.Fatalf("Complete(pos=%d) error = nil, want InvalidArgument", tc.pos)
				}
				if status.Code(err) != codes.InvalidArgument {
					t.Fatalf("Complete(pos=%d) code = %v, want InvalidArgument", tc.pos, status.Code(err))
				}
				if resp != nil {
					t.Fatalf("Complete(pos=%d) resp = %v, want nil on error", tc.pos, resp)
				}
				return
			}
			if err != nil {
				t.Fatalf("Complete(pos=%d) unexpected error = %v", tc.pos, err)
			}
			if resp == nil {
				t.Fatalf("Complete(pos=%d) resp = nil, want non-nil", tc.pos)
			}
		})
	}
}

// TestCompleteValidPosCompletes confirms a valid position still produces the
// expected completions after the negative-Pos guard was added — the guard must
// reject only negatives, not perturb normal completion. With Pos truncating
// "show sec" the operational completer should offer "security".
func TestCompleteValidPosCompletes(t *testing.T) {
	s := &Server{}
	const line = "show secdropme"
	// Pos=8 truncates to "show sec" so "security" is the expected candidate.
	resp, err := s.Complete(context.Background(), &pb.CompleteRequest{
		Line: line,
		Pos:  8,
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	found := false
	for _, c := range resp.Candidates {
		if c == "security" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Complete(pos=8) candidates = %v, want to contain %q", resp.Candidates, "security")
	}
}

// newNATPoolStatsStore commits a single named source NAT pool so the active
// config exposes one entry in Security.NAT.SourcePools that the test can then
// grow to provoke the #2282 int32 overflow without pushing tens of thousands
// of addresses through the address-range-capped compiler.
func newNATPoolStatsStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if _, err := store.LoadSet(`set security nat source pool bigpool address 10.0.0.0/24
set security nat source rule-set rs from zone trust
set security nat source rule-set rs to zone untrust
set security nat source rule-set rs rule r1 match source-address 10.0.0.0/8
set security nat source rule-set rs rule r1 then source-nat pool bigpool`); err != nil {
		t.Fatalf("LoadSet() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestGetNATPoolStatsClampsInt32Overflow guards the #2282 int32 port-pool
// overflow. The port-pool size (portHigh-portLow+1)*(unique expanded
// addresses) is computed in int64 and clamped to int32 max for the int32
// proto fields; a bare int32() cast would wrap negative for a large pool and
// corrupt the avail=total-used display.
//
// Fail-on-revert: reverting the int64 computation + clampInt32 back to the
// bare int32() cast makes TotalPorts wrap negative, failing the
// non-negative + clamped-to-max assertions below.
func TestGetNATPoolStatsClampsInt32Overflow(t *testing.T) {
	store := newNATPoolStatsStore(t)

	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	pool := cfg.Security.NAT.SourcePools["bigpool"]
	if pool == nil {
		t.Fatalf("SourcePools[bigpool] missing; pools = %v", cfg.Security.NAT.SourcePools)
	}

	// Force a large pool: default port window is 1024..65535 (64512 ports).
	// 64512 * 40000 ≈ 2.58e9 > math.MaxInt32 (~2.147e9), so the int64
	// product overflows int32 and must be clamped to MaxInt32. The members
	// must be DISTINCT: capacity counts the union of expanded addresses
	// (#10700), so 40000 copies of one /32 would count as 1 address and
	// never reach the clamp.
	pool.PortLow = 0
	pool.PortHigh = 0 // handler defaults these to 1024/65535
	pool.Addresses = make([]string, 40000)
	for i := range pool.Addresses {
		pool.Addresses[i] = fmt.Sprintf("10.%d.%d.%d/32", (i>>16)&0xff, (i>>8)&0xff, i&0xff)
	}
	const portWindow = 65535 - 1024 + 1
	wantTotal64 := int64(portWindow) * int64(len(pool.Addresses))
	if wantTotal64 <= math.MaxInt32 {
		t.Fatalf("test precondition: pool size %d does not overflow int32", wantTotal64)
	}

	s := &Server{store: store}
	resp, err := s.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATPoolStats() error = %v", err)
	}

	var got *pb.NATPoolStats
	for _, p := range resp.Pools {
		if p.Name == "bigpool" {
			got = p
			break
		}
	}
	if got == nil {
		t.Fatalf("bigpool not in response pools = %v", resp.Pools)
	}
	if got.TotalPorts < 0 {
		t.Fatalf("TotalPorts = %d, want non-negative (int32 overflow not clamped)", got.TotalPorts)
	}
	if got.TotalPorts != math.MaxInt32 {
		t.Fatalf("TotalPorts = %d, want clamped to MaxInt32 (%d)", got.TotalPorts, int32(math.MaxInt32))
	}
	if got.AvailablePorts < 0 {
		t.Fatalf("AvailablePorts = %d, want non-negative", got.AvailablePorts)
	}
	// avail = total - used, used is 0 here (no dataplane apply result), so
	// avail must equal the clamped total.
	if got.AvailablePorts != got.TotalPorts {
		t.Fatalf("AvailablePorts = %d, want = TotalPorts %d (used=0)", got.AvailablePorts, got.TotalPorts)
	}
}

// TestGetNATPoolStatsSmallPoolExact confirms the int64+clamp path leaves a
// normal pool size exactly correct (no clamping for in-range values).
func TestGetNATPoolStatsSmallPoolExact(t *testing.T) {
	store := newNATPoolStatsStore(t)
	cfg := store.ActiveConfig()
	pool := cfg.Security.NAT.SourcePools["bigpool"]
	if pool == nil {
		t.Fatalf("SourcePools[bigpool] missing")
	}
	pool.PortLow = 1024
	pool.PortHigh = 2023 // 1000-port window
	pool.Addresses = []string{"10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32"}
	wantTotal := int32((2023 - 1024 + 1) * 3) // 3000

	s := &Server{store: store}
	resp, err := s.GetNATPoolStats(context.Background(), &pb.GetNATPoolStatsRequest{})
	if err != nil {
		t.Fatalf("GetNATPoolStats() error = %v", err)
	}
	var got *pb.NATPoolStats
	for _, p := range resp.Pools {
		if p.Name == "bigpool" {
			got = p
			break
		}
	}
	if got == nil {
		t.Fatalf("bigpool not in response")
	}
	if got.TotalPorts != wantTotal {
		t.Fatalf("TotalPorts = %d, want %d", got.TotalPorts, wantTotal)
	}
	if got.AvailablePorts != wantTotal {
		t.Fatalf("AvailablePorts = %d, want %d (used=0)", got.AvailablePorts, wantTotal)
	}
}
