// #5454: the FILTERED ClearSessions gRPC path must bound its handler-goroutine
// working set to O(batch), not O(matches). The pre-#5454 path materialized
// every matching forward key and reverse companion into
// unbounded slices before the first delete — an O(N) allocation (N up to the
// full multi-million-entry session table) a fabric-reachable PSK peer could
// weaponize into a control-plane OOM/GC-stall DoS.
//
// These tests drive the clear through a cursor-capable in-memory dataplane
// (modelling the production LegacyDataPlaneAdapter, which implements
// sessionCursorIterator) and assert (a) every matching session plus its reverse
// is deleted, (b) the collected-key chunk never exceeds
// clearFilteredBatch (bounded working set), and (c) a mid-clear context cancel
// stops promptly. RED-on-revert: reverting clearFilteredSessionsV4 to the
// collect-all-then-delete path reports a single len==matches chunk, so the
// bounded-chunk assertion fails.
package grpcapi

import (
	"context"
	"encoding/binary"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// v4KeyOrder returns a deterministic ordering token for a v4 session key so a
// map-backed fake can present a STABLE iteration order with resume-after-cursor
// semantics (modelling the kernel hash map's BPF_MAP_GET_NEXT_KEY, which the
// real IterateSessionsFrom walks).
func v4KeyOrder(k dataplane.SessionKey) string {
	var b [13]byte
	copy(b[0:4], k.SrcIP[:])
	copy(b[4:8], k.DstIP[:])
	binary.BigEndian.PutUint16(b[8:10], k.SrcPort)
	binary.BigEndian.PutUint16(b[10:12], k.DstPort)
	b[12] = k.Protocol
	return string(b[:])
}

func v6KeyOrder(k dataplane.SessionKeyV6) string {
	var b [37]byte
	copy(b[0:16], k.SrcIP[:])
	copy(b[16:32], k.DstIP[:])
	binary.BigEndian.PutUint16(b[32:34], k.SrcPort)
	binary.BigEndian.PutUint16(b[34:36], k.DstPort)
	b[36] = k.Protocol
	return string(b[:])
}

// iterateV4From iterates sessions in a stable order, resuming strictly after
// cursor (or from the start when cursor is nil), mirroring the real cursor
// iterator. Shared by the fakes in this package.
func iterateV4From(sessions map[dataplane.SessionKey]dataplane.SessionValue, cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) {
	keys := make([]dataplane.SessionKey, 0, len(sessions))
	for k := range sessions {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return v4KeyOrder(keys[i]) < v4KeyOrder(keys[j]) })
	started := cursor == nil
	for _, k := range keys {
		if !started {
			if k == *cursor {
				started = true
			}
			continue
		}
		if !fn(k, sessions[k]) {
			return
		}
	}
}

func iterateV6From(sessions map[dataplane.SessionKeyV6]dataplane.SessionValueV6, cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) {
	keys := make([]dataplane.SessionKeyV6, 0, len(sessions))
	for k := range sessions {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return v6KeyOrder(keys[i]) < v6KeyOrder(keys[j]) })
	started := cursor == nil
	for _, k := range keys {
		if !started {
			if k == *cursor {
				started = true
			}
			continue
		}
		if !fn(k, sessions[k]) {
			return
		}
	}
}

// boundedClearDP is a cursor-capable in-memory dataplane fake. DeleteSession
// actually removes the key (modelling the real map), so the cursor advances and
// the clear converges.
type boundedClearDP struct {
	*dataplane.Manager

	v4 map[dataplane.SessionKey]dataplane.SessionValue
	v6 map[dataplane.SessionKeyV6]dataplane.SessionValueV6

	// fwdNotFound models a GC race: a forward key collected during iteration
	// returns ErrKeyNotExist by delete time (it is left in the map so the
	// cursor still advances, mimicking "reaped just before deleteAll").
	fwdNotFound bool
}

func (d *boundedClearDP) IsLoaded() bool { return true }

func (d *boundedClearDP) IterateSessions(fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	iterateV4From(d.v4, nil, fn)
	return nil
}

func (d *boundedClearDP) IterateSessionsV6(fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	iterateV6From(d.v6, nil, fn)
	return nil
}

func (d *boundedClearDP) IterateSessionsFrom(cursor *dataplane.SessionKey, fn func(dataplane.SessionKey, dataplane.SessionValue) bool) error {
	iterateV4From(d.v4, cursor, fn)
	return nil
}

func (d *boundedClearDP) IterateSessionsV6From(cursor *dataplane.SessionKeyV6, fn func(dataplane.SessionKeyV6, dataplane.SessionValueV6) bool) error {
	iterateV6From(d.v6, cursor, fn)
	return nil
}

func (d *boundedClearDP) DeleteSession(key dataplane.SessionKey) error {
	val, ok := d.v4[key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	if d.fwdNotFound && val.IsReverse == 0 {
		return ebpf.ErrKeyNotExist // forward key reaped by GC before delete
	}
	delete(d.v4, key)
	return nil
}

func (d *boundedClearDP) DeleteSessionV6(key dataplane.SessionKeyV6) error {
	val, ok := d.v6[key]
	if !ok {
		return ebpf.ErrKeyNotExist
	}
	if d.fwdNotFound && val.IsReverse == 0 {
		return ebpf.ErrKeyNotExist
	}
	delete(d.v6, key)
	return nil
}

func newBoundedClearServer(t *testing.T, dp grpcRuntime) *Server {
	t.Helper()
	return &Server{
		store: newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
		dp:    dp,
	}
}

// seedBoundedClearDP seeds n matching TCP forward sessions plus each
// session's reverse conntrack entry.
func seedBoundedClearDP(n int) *boundedClearDP {
	d := &boundedClearDP{
		Manager: dataplane.New(),
		v4:      make(map[dataplane.SessionKey]dataplane.SessionValue),
		v6:      make(map[dataplane.SessionKeyV6]dataplane.SessionValueV6),
	}
	for i := 0; i < n; i++ {
		// Distinct v4 forward key.
		fwd := dataplane.SessionKey{
			Protocol: 6,
			SrcIP:    [4]byte{10, 0, byte(i >> 8), byte(i)},
			DstIP:    [4]byte{8, 8, 8, 8},
			SrcPort:  uint16(0x1000 + i),
			DstPort:  0x0050,
		}
		rev := dataplane.SessionKey{
			Protocol: 6,
			SrcIP:    [4]byte{8, 8, 8, 8},
			DstIP:    [4]byte{203, 0, 113, byte(i)},
			SrcPort:  0x0050,
			DstPort:  uint16(0x2000 + i),
		}
		val := dataplane.SessionValue{ReverseKey: rev}
		if i%2 == 0 {
			val.Flags = dataplane.SessFlagSNAT
		}
		d.v4[fwd] = val
		d.v4[rev] = dataplane.SessionValue{IsReverse: 1} // reverse conntrack entry

		// Distinct v6 forward key + reverse.
		fwd6 := dataplane.SessionKeyV6{Protocol: 6, SrcPort: uint16(0x3000 + i), DstPort: 0x0050}
		fwd6.SrcIP[0] = 0x20
		fwd6.SrcIP[15] = byte(i)
		fwd6.SrcIP[14] = byte(i >> 8)
		rev6 := dataplane.SessionKeyV6{Protocol: 6, SrcPort: 0x0050, DstPort: uint16(0x4000 + i)}
		rev6.DstIP[0] = 0x20
		rev6.DstIP[15] = byte(i)
		rev6.DstIP[14] = byte(i >> 8)
		val6 := dataplane.SessionValueV6{ReverseKey: rev6}
		if i%2 == 0 {
			val6.Flags = dataplane.SessFlagSNAT
		}
		d.v6[fwd6] = val6
		d.v6[rev6] = dataplane.SessionValueV6{IsReverse: 1}
	}
	return d
}

func TestClearSessionsFilteredBoundedWorkingSet(t *testing.T) {
	const n = 50
	const batch = 8

	// Shrink the batch and install the chunk observer for this test only.
	origBatch := clearFilteredBatch
	origObs := clearFilteredBatchObserver
	clearFilteredBatch = batch
	var maxChunk, chunkCalls int
	clearFilteredBatchObserver = func(chunkLen int) {
		chunkCalls++
		if chunkLen > maxChunk {
			maxChunk = chunkLen
		}
	}
	t.Cleanup(func() {
		clearFilteredBatch = origBatch
		clearFilteredBatchObserver = origObs
	})

	dp := seedBoundedClearDP(n)
	s := newBoundedClearServer(t, dp)

	resp, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{Protocol: "tcp"})
	if err != nil {
		t.Fatalf("ClearSessions RPC error: %v", err)
	}

	// (a) Every matching forward session cleared, count accurate.
	if resp.Ipv4Cleared != n {
		t.Fatalf("Ipv4Cleared=%d, want %d", resp.Ipv4Cleared, n)
	}
	if resp.Ipv6Cleared != n {
		t.Fatalf("Ipv6Cleared=%d, want %d", resp.Ipv6Cleared, n)
	}
	// Forward AND reverse conntrack entries all removed from the table.
	if len(dp.v4) != 0 {
		t.Fatalf("v4 sessions remaining after clear: %d, want 0 (forward+reverse leak)", len(dp.v4))
	}
	if len(dp.v6) != 0 {
		t.Fatalf("v6 sessions remaining after clear: %d, want 0", len(dp.v6))
	}
	if resp.Failures != 0 {
		t.Fatalf("Failures=%d summary=%q, want 0", resp.Failures, resp.FailureSummary)
	}

	// (b) Bounded working set: no collected chunk exceeded the batch bound, and
	// the clear was actually chunked (proving it did NOT collect all matches
	// into one slice — the #5454 bug). RED-on-revert: the collect-all path
	// reports a single len==n chunk, so maxChunk==n>batch here.
	if maxChunk > batch {
		t.Fatalf("collected chunk length %d exceeded batch bound %d — working set not bounded (#5454)", maxChunk, batch)
	}
	if chunkCalls < 2 {
		t.Fatalf("clear used %d chunk(s) for %d v4 + %d v6 matches with batch %d — not chunked (collect-all regression #5454)", chunkCalls, n, n, batch)
	}
}

func TestClearSessionsFilteredContextCancel(t *testing.T) {
	const n = 50
	const batch = 8

	origBatch := clearFilteredBatch
	origObs := clearFilteredBatchObserver
	clearFilteredBatch = batch
	t.Cleanup(func() {
		clearFilteredBatch = origBatch
		clearFilteredBatchObserver = origObs
	})

	dp := seedBoundedClearDP(n)
	s := newBoundedClearServer(t, dp)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel the RPC as soon as the first chunk is collected so the clear must
	// stop promptly instead of draining all n matches.
	clearFilteredBatchObserver = func(int) { cancel() }

	resp, err := s.ClearSessions(ctx, &pb.ClearSessionsRequest{Protocol: "tcp"})
	if err != nil {
		t.Fatalf("ClearSessions RPC error: %v", err)
	}

	// Prompt stop: far fewer than all n sessions cleared, and the cancellation
	// is surfaced in the failure summary.
	if resp.Ipv4Cleared >= n {
		t.Fatalf("Ipv4Cleared=%d, want < %d (clear did not stop promptly on cancel)", resp.Ipv4Cleared, n)
	}
	if resp.Failures == 0 || !strings.Contains(resp.FailureSummary, "canceled") {
		t.Fatalf("cancellation not surfaced: Failures=%d summary=%q", resp.Failures, resp.FailureSummary)
	}
	// Some v4 sessions remain (the clear was interrupted), proving it did not
	// run to completion.
	if len(dp.v4) == 0 {
		t.Fatalf("all v4 sessions cleared despite mid-clear cancel — not prompt")
	}
}

// TestClearSessionsFilteredForwardNotFoundBenign covers the #5531 review MINOR:
// a forward key that is already gone at delete time (GC reaped it, or a
// restart-from-bucket-0 after a GC-deleted anchor re-collected a prior chunk's
// key) must be BENIGN — not a spurious Failure, and not a re-delete that
// regrows the failure-string buffer this fix bounds. RED-on-revert: routing the
// forward delete back through add() (instead of addExceptNotFound) reports
// Failures>0 for the reaped keys.
func TestClearSessionsFilteredForwardNotFoundBenign(t *testing.T) {
	const n = 50
	origBatch := clearFilteredBatch
	clearFilteredBatch = 8
	t.Cleanup(func() { clearFilteredBatch = origBatch })

	dp := seedBoundedClearDP(n)
	dp.fwdNotFound = true // every collected forward key is already gone at delete time
	s := newBoundedClearServer(t, dp)

	resp, err := s.ClearSessions(context.Background(), &pb.ClearSessionsRequest{Protocol: "tcp"})
	if err != nil {
		t.Fatalf("ClearSessions RPC error: %v", err)
	}
	if resp.Failures != 0 {
		t.Fatalf("forward ErrKeyNotExist inflated Failures=%d summary=%q, want 0 (benign #5531)", resp.Failures, resp.FailureSummary)
	}
	// The forward keys were reaped by GC, not by us -> not counted as cleared.
	if resp.Ipv4Cleared != 0 || resp.Ipv6Cleared != 0 {
		t.Fatalf("Ipv4Cleared=%d Ipv6Cleared=%d, want 0/0 (forward keys already gone)", resp.Ipv4Cleared, resp.Ipv6Cleared)
	}
	if resp.FailureSummary != "" {
		t.Fatalf("FailureSummary=%q, want empty (no failures)", resp.FailureSummary)
	}
}

// TestClearErrorsPartsBounded proves the failure-string buffer stays O(cap)
// regardless of how many failures accumulate (#5531 review): count is exact but
// parts is capped with a trailing overflow summary. RED-on-revert: without the
// cap, parts grows to the full failure count.
func TestClearErrorsPartsBounded(t *testing.T) {
	var e clearErrors
	const total = 500
	for i := 0; i < total; i++ {
		e.add("v4 forward delete", fmt.Errorf("EBUSY inst %d", i))
	}
	if e.count != total {
		t.Fatalf("count=%d, want %d (honest total must stay exact)", e.count, total)
	}
	if len(e.parts) > clearErrorsPartsCap {
		t.Fatalf("failure-string buffer grew to %d entries, want <= %d (unbounded regrowth #5531)", len(e.parts), clearErrorsPartsCap)
	}
	if want := total - clearErrorsPartsCap; !strings.Contains(e.summary(), fmt.Sprintf("…and %d more", want)) {
		t.Fatalf("summary missing bounded-overflow marker: %q", e.summary())
	}
}
