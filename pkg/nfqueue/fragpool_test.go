package nfqueue

import (
	"errors"
	"testing"
	"time"
)

func testFragmentKey(version uint8, id uint32) FragmentKey {
	return FragmentKey{Version: version, Tunnel: 7, VRF: 3, Generation: 11, ID: id}
}

func TestFragPoolIPv4FirstWinsCompletesRetainedSet(t *testing.T) {
	pool, err := NewFragPool(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	key := testFragmentKey(4, 1)
	if complete, err := pool.Insert(key, Fragment{Offset: 0, More: true, Data: []byte("abcd")}); complete || err != nil {
		t.Fatalf("first fragment: complete=%t err=%v", complete, err)
	}
	// The later fragment overlaps bytes 2..3. First-wins keeps "ab" and
	// retains only the new bytes at offsets 4..5, so the releasable set is
	// "abcdZZ", not bytes copied from a discarded overlap.
	if complete, err := pool.Insert(key, Fragment{Offset: 2, More: false, Data: []byte("ZZZZ")}); !complete || err != nil {
		t.Fatalf("overlapping terminal fragment: complete=%t err=%v", complete, err)
	}
	got, ok := pool.PopCompleted()
	if !ok {
		t.Fatal("completed datagram missing")
	}
	if string(got.Payload) != "abcdZZ" {
		t.Fatalf("first-wins payload = %q, want %q", got.Payload, "abcdZZ")
	}
	if got.Fragments != 2 {
		t.Fatalf("retained fragment count = %d, want 2", got.Fragments)
	}
}

func TestFragPoolIPv6OverlapDropsWholeDatagram(t *testing.T) {
	pool, err := NewFragPool(8, 8)
	if err != nil {
		t.Fatal(err)
	}
	key := testFragmentKey(6, 2)
	_, _ = pool.Insert(key, Fragment{Offset: 0, More: true, Data: []byte("abcd")})
	complete, err := pool.Insert(key, Fragment{Offset: 2, More: false, Data: []byte("WXYZ")})
	if complete || !errors.Is(err, ErrFragmentOverlap) {
		t.Fatalf("IPv6 overlap: complete=%t err=%v", complete, err)
	}
	if got := pool.Stats(); got.Flows != 0 || got.OverlapDrops != 1 {
		t.Fatalf("overlap stats = %+v, want no flow and one drop", got)
	}
}

func TestFragPoolExactIPv6DuplicateDoesNotConsumePieceCap(t *testing.T) {
	pool, err := NewFragPool(2, 2)
	if err != nil {
		t.Fatal(err)
	}
	key := testFragmentKey(6, 3)
	first := Fragment{Offset: 0, More: true, Data: []byte("ab")}
	if _, err := pool.Insert(key, first); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Insert(key, first); err != nil {
		t.Fatalf("exact duplicate: %v", err)
	}
	if complete, err := pool.Insert(key, Fragment{Offset: 2, More: false, Data: []byte("cd")}); !complete || err != nil {
		t.Fatalf("terminal after duplicate: complete=%t err=%v", complete, err)
	}
	if got := pool.Stats(); got.DuplicateDrops != 1 || got.Completed != 1 {
		t.Fatalf("duplicate stats = %+v", got)
	}
}

func TestFragPoolCapacityDropsFlowAndBoundsCompletionQueue(t *testing.T) {
	pool, err := NewFragPool(2, 1)
	if err != nil {
		t.Fatal(err)
	}
	stalled := testFragmentKey(4, 10)
	for i := uint32(0); i < 2; i++ {
		if complete, err := pool.Insert(stalled, Fragment{Offset: i * 2, More: true, Data: []byte("ab")}); complete || err != nil {
			t.Fatalf("stalled fragment %d: complete=%t err=%v", i, complete, err)
		}
	}
	if complete, err := pool.Insert(stalled, Fragment{Offset: 4, More: true, Data: []byte("cd")}); complete || !errors.Is(err, ErrFragmentCapacity) {
		t.Fatalf("per-flow cap: complete=%t err=%v", complete, err)
	}
	if got := pool.Stats(); got.Flows != 0 || got.CapacityDrops != 1 {
		t.Fatalf("capacity stats = %+v", got)
	}
	first := testFragmentKey(4, 11)
	if complete, err := pool.Insert(first, Fragment{More: false, Data: []byte("one")}); !complete || err != nil {
		t.Fatalf("first completion: complete=%t err=%v", complete, err)
	}
	second := testFragmentKey(4, 12)
	if complete, err := pool.Insert(second, Fragment{More: false, Data: []byte("two")}); complete || !errors.Is(err, ErrFragmentCapacity) {
		t.Fatalf("completion queue bound: complete=%t err=%v", complete, err)
	}
	if _, ok := pool.PopCompleted(); !ok {
		t.Fatal("first completion missing")
	}
	if complete, err := pool.Insert(second, Fragment{More: false, Data: []byte("two")}); !complete || err != nil {
		t.Fatalf("completion after drain: complete=%t err=%v", complete, err)
	}
}

func TestFragPoolExpireReclaimsStalledFlows(t *testing.T) {
	pool, err := NewFragPool(8, 2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Insert(testFragmentKey(4, 20), Fragment{More: true, Data: []byte("stalled")}); err != nil {
		t.Fatal(err)
	}
	if removed := pool.Expire(time.Now().Add(time.Second)); removed != 1 {
		t.Fatalf("expired sets = %d, want 1", removed)
	}
	if got := pool.Stats(); got.Flows != 0 || got.Expired != 1 {
		t.Fatalf("expiry stats = %+v", got)
	}
}
func TestFragPoolConflictingTerminalPreservesOtherFragmentCounts(t *testing.T) {
	pool, err := NewFragPool(8, 4)
	if err != nil {
		t.Fatal(err)
	}
	survivor := testFragmentKey(6, 30)
	if _, err := pool.Insert(survivor, Fragment{Offset: 0, More: true, Data: []byte("ab")}); err != nil {
		t.Fatal(err)
	}
	conflict := testFragmentKey(6, 31)
	for _, frag := range []Fragment{
		{Offset: 0, More: true, Data: []byte("ab")},
		{Offset: 4, More: false, Data: []byte("ef")},
	} {
		if _, err := pool.Insert(conflict, frag); err != nil {
			t.Fatal(err)
		}
	}
	if complete, err := pool.Insert(conflict, Fragment{Offset: 6, More: false, Data: []byte("gh")}); complete || !errors.Is(err, ErrFragmentOverlap) {
		t.Fatalf("conflicting terminal: complete=%t err=%v, want overlap error", complete, err)
	}
	if got := pool.Stats(); got.Flows != 1 || got.Fragments != 1 {
		t.Fatalf("stats after dropping one of two sets = %+v, want one surviving flow and fragment", got)
	}
}
