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
// the runtime for ~4.29e9-record capacity (~672 GiB virtual at the
// documented ~168 B SyncLease; 721 GB decimal) before any check refused
// the set.
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
	c0 := encodeDHCPLeaseChunkPayload(one, 1, 0, 2, 1)
	c1 := encodeDHCPLeaseChunkPayload(one, 1, 1, 2, 1)
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
	complete, closed, _ := st.addChunk(key, 0, 1, 1<<20, one)
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

// TestDHCPChunkSenderRefusesOverCapSet16036 is the sender twin of the
// receiver bound (fold): queueDHCPLeaseSnapshot stamps totalLeases=kept
// on every chunk, so with only a receiver guard a conforming-but-huge
// local set (the memfile fallback and direct QueueDHCPLeaseSnapshot
// callers have no 64 MiB Kea-response bound) would emit frames a new
// receiver counts malformed — and the daemon re-pushes every 30s. The
// sender must refuse before writing ANY frame.
//
// Fixture: (1<<20)+10 minimal leases. Each record is ~40 wire bytes
// (min record 36 + 4-byte length prefix), so the encoded set is ~40 MiB
// — provably over the 16 MiB cap, hence into the chunk branch — while
// staying cheap to build. If the fixture ever fit one frame the fast
// path would emit a legacy frame and this cell would be void, so the
// cell asserts over-cap first.
func TestDHCPChunkSenderRefusesOverCapSet16036(t *testing.T) {
	leases := make([]dhcpserver.SyncLease, 0, dhcpChunkMaxTotalLeases+10)
	for range dhcpChunkMaxTotalLeases + 10 {
		leases = append(leases, dhcpserver.SyncLease{
			Family: 4, Address: "10.0.0.1", HWAddress: "aa", LeaseType: "IA_NA",
		})
	}
	if got := len(encodeDHCPLeasePayload(leases)); got <= maxSyncPayload {
		t.Fatalf("FIXTURE: %d minimal leases encode to %d bytes, must exceed maxSyncPayload %d to reach the chunk branch",
			len(leases), got, maxSyncPayload)
	}
	// Precondition: this count is over-cap for the chunk splitter too,
	// one frame-budget chunk holds <1<<20 records, so rejecting chunks
	// wholesale cannot strand a valid set: kept must exceed the cap.
	if _, kept, _ := encodeDHCPLeaseChunkFrames(leases); kept <= dhcpChunkMaxTotalLeases {
		t.Fatalf("FIXTURE: chunk splitter kept %d, want > cap %d (else the sender refusal would not trigger)", kept, dhcpChunkMaxTotalLeases)
	}

	sender := NewSessionSync(":0", "10.0.0.2:4785", nil)
	cc := &captureConn{}
	sender.mu.Lock()
	sender.conn0 = cc
	sender.mu.Unlock()

	before := sender.stats.MalformedRecordsDropped.Load()
	sender.QueueDHCPLeases(4, leases)
	if frames := cc.frames(); len(frames) != 0 {
		t.Fatalf("over-cap sender emitted %d frame(s) announcing totalLeases>%d; want 0 frames — a conforming sender never announces a value the receiver must refuse (#16036 fold)", len(frames), dhcpChunkMaxTotalLeases)
	}
	if got := sender.stats.MalformedRecordsDropped.Load(); got <= before {
		t.Fatalf("over-cap sender refusal not counted: MalformedRecordsDropped %d -> %d", before, got)
	}
}

// TestDHCPChunkSenderWithinCapSetStillChunks16036 is the positive control:
// the refusal must not break the normal chunk path — a large-but-within-cap
// set still chunks and commits whole at the receiver. 260k realistic
// leases are the existing #15160 overset (over the frame cap, far under
// the lease-count cap).
func TestDHCPChunkSenderWithinCapSetStillChunks16036(t *testing.T) {
	leases := dhcpOverset15160(t, 260_000)
	sender := NewSessionSync(":0", "10.0.0.2:4785", nil)
	cc := &captureConn{}
	sender.mu.Lock()
	sender.conn0 = cc
	sender.mu.Unlock()
	sender.QueueDHCPLeases(4, leases)
	frames := cc.frames()
	if len(frames) < 2 {
		t.Fatalf("within-cap overset emitted %d frame(s), want chunked >=2", len(frames))
	}
	for i, f := range frames {
		if f.msgType != syncMsgDHCPLeaseV4Chunk {
			t.Fatalf("frame %d type=%d, want chunk type %d", i, f.msgType, syncMsgDHCPLeaseV4Chunk)
		}
		_, _, _, tl, _, ok := decodeDHCPLeaseChunkHeader(f.payload[:len(f.payload)-fullSetSeqTrailerLen])
		if !ok || int(tl) != len(leases) {
			t.Fatalf("frame %d totalLeases=%d ok=%v, want %d admitted within cap", i, tl, ok, len(leases))
		}
	}
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	feedCaptured15160(t, recv, frames)
	if got := len(recv.PeerDHCPLeases4()); got != len(leases) {
		t.Fatalf("within-cap chunked set committed %d leases, want %d", got, len(leases))
	}
}
