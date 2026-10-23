package cluster

import (
	"encoding/binary"
	"runtime"
	"testing"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #16036: decodeDHCPLeaseChunkHeader bounded the chunk count `total` to
// [1, 1<<20] but checked the lease count `totalLeases` only for != 0, and
// dhcpChunkState.addChunk executed make([]SyncLease, 0, totalLeases) at
// assembly completion BEFORE the len(complete) != totalLeases refusal.
// One chunk header with total=1, totalLeases=0xFFFFFFFF therefore asked
// the runtime for ~4.29e9-record capacity (~721 GiB virtual at the
// documented ~168 B SyncLease) before any check refused the set.
//
// WHAT THIS ASSERTS, AND WHY IT IS NOT "THE PROCESS DIED" (the #8792
// posture). Whether the oversized make() is fatal is a property of the
// HOST (GOMEMLIMIT / overcommit), not of the code — NV-1 in the issue is
// exactly that unrun host check, so no cell here asserts a crash. The
// INVARIANT holds everywhere: a totalLeases the wire cannot justify is
// refused before it sizes any allocation, and nothing commits.

// TestDHCPChunkTotalLeasesBound16036 is the decisive header cell: the
// issue's exact fixture (total=1, totalLeases=0xFFFFFFFF) and every
// value past the [1, 1<<20] bound must be refused by
// decodeDHCPLeaseChunkHeader, with the boundary values still admitted
// (a guard that rejects everything passes trivially and is useless).
func TestDHCPChunkTotalLeasesBound16036(t *testing.T) {
	header := func(totalLeases uint32) []byte {
		p := make([]byte, dhcpChunkHeaderLen)
		binary.LittleEndian.PutUint64(p[0:8], 1)   // generation
		binary.LittleEndian.PutUint32(p[8:12], 0)  // index
		binary.LittleEndian.PutUint32(p[12:16], 1) // total
		binary.LittleEndian.PutUint32(p[16:20], totalLeases)
		return p
	}
	for _, tl := range []uint32{0, (1 << 20) + 1, 0xFFFFFFFF} {
		if _, _, _, _, _, ok := decodeDHCPLeaseChunkHeader(header(tl)); ok {
			t.Errorf("totalLeases=%#x: header accepted; want refused by the [1,1<<20] bound (#16036)", tl)
		}
	}
	for _, tl := range []uint32{1, 1 << 20} {
		if _, _, _, got, _, ok := decodeDHCPLeaseChunkHeader(header(tl)); !ok || got != tl {
			t.Errorf("totalLeases=%#x: header refused (ok=%v got=%d); want admitted at the bound boundary", tl, ok, got)
		}
	}
}

// TestDHCPChunkForgedTotalLeasesNeverCommits16036 drives the issue's
// one-chunk fixture through the receiver exactly as receiveLoop would:
// total=1, totalLeases=0xFFFFFFFF, one real lease in the body. The held
// set must survive untouched and no assembly may linger. Before the fix
// this frame reached addChunk's make(0, 0xFFFFFFFF) before refusal —
// on hosts where that request is fatal the suite dies here, which is
// the regression signal; the assertion below is the host-independent
// half (nothing committed, prior set retained).
func TestDHCPChunkForgedTotalLeasesNeverCommits16036(t *testing.T) {
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	prior := []dhcpserver.SyncLease{dhcpChunkLease15160(4242)}
	recv.SetPeerDHCPLeasesForTesting(4, prior)

	body := encodeDHCPLeasePayload([]dhcpserver.SyncLease{dhcpChunkLease15160(7)})
	forged := encodeDHCPLeaseChunkPayload(body, 1, 0, 1, 0xFFFFFFFF)
	recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, appendFullSetSeq(forged, 77, 1))

	if held := recv.PeerDHCPLeases4(); len(held) != 1 || held[0].Address != prior[0].Address {
		t.Fatalf("forged totalLeases=0xFFFFFFFF chunk disturbed the held set: %v", held)
	}
	if n := len(recv.dhcpChunkState4.pending); n != 0 {
		t.Fatalf("forged chunk left %d pending assemblies; want 0", n)
	}
	if got := recv.stats.MalformedRecordsDropped.Load(); got == 0 {
		t.Fatalf("forged chunk was not counted as malformed (MalformedRecordsDropped=0)")
	}
}

// TestDHCPChunkReceivedOverTotalRefused16036 pins the second half of the
// acceptance: received > totalLeases is refused before allocating. A
// generation announcing totalLeases=1 across total=2 chunks but carrying
// one lease per chunk must never commit, and its assembly must be
// dropped — even though each individual header is inside the bound, so
// only the addChunk early refusal stops it.
func TestDHCPChunkReceivedOverTotalRefused16036(t *testing.T) {
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	prior := []dhcpserver.SyncLease{dhcpChunkLease15160(4242)}
	recv.SetPeerDHCPLeasesForTesting(4, prior)

	one := encodeDHCPLeasePayload([]dhcpserver.SyncLease{dhcpChunkLease15160(7)})
	c0 := encodeDHCPLeaseChunkPayload(one, 5, 0, 2, 1)
	c1 := encodeDHCPLeaseChunkPayload(one, 5, 1, 2, 1)
	recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, appendFullSetSeq(c0, 77, 1))
	recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, appendFullSetSeq(c1, 77, 2))

	if held := recv.PeerDHCPLeases4(); len(held) != 1 || held[0].Address != prior[0].Address {
		t.Fatalf("over-total generation (received 2 > totalLeases 1) committed over the held set: %v", held)
	}
	if n := len(recv.dhcpChunkState4.pending); n != 0 {
		t.Fatalf("over-total generation left %d pending assemblies; want 0 (refused and dropped)", n)
	}
}

// TestDHCPChunkCompletionAllocationBounded16036 measures the ordering
// directly (the #8792 idiom): at the admitted boundary totalLeases=1<<20
// with only one real lease in the sole chunk, completion must size its
// slice by the leases actually received, never by the announced total.
// Without the fix this allocates 1<<20 SyncLeases (~176 MiB at the
// measured size) before the count check discards the set; with it, it
// allocates ~nothing. 1<<20 is chosen to be unmistakable against GC
// noise while staying survivable if the guard is ever removed.
func TestDHCPChunkCompletionAllocationBounded16036(t *testing.T) {
	st := &dhcpChunkState{}
	key := dhcpChunkGeneration{incarnation: 1, generation: 9}
	one := []dhcpserver.SyncLease{dhcpChunkLease15160(7)}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	complete, closed := st.addChunk(key, 0, 1, 1<<20, one)
	runtime.ReadMemStats(&after)

	if closed || complete != nil {
		t.Fatalf("under-total generation (1 of 1<<20 leases) closed=%v with %d leases; want refused", closed, len(complete))
	}
	const budget = 1 << 20 // 1 MiB; the defect costs ~176 MiB
	if grew := after.TotalAlloc - before.TotalAlloc; grew > budget {
		t.Errorf("completing a 1-lease generation announcing totalLeases=1<<20 allocated %d bytes "+
			"(budget %d): the announced total sized the completion allocation before the count "+
			"check refused it — the #16036 ordering defect", grew, budget)
	}
	if n := len(st.pending); n != 0 {
		t.Fatalf("refused generation left %d pending assemblies; want 0", n)
	}
}
