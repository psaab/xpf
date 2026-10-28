package cluster

import (
	"fmt"
	"math"
	"testing"

	"github.com/psaab/xpf/pkg/dhcpserver"
)

// #15160 (B03-01): queueDHCPLeaseSnapshot encoded the entire Kea lease set
// as ONE session-sync frame with no size check. A set over the receiver's
// maxSyncPayload (16 MiB) makes receiveLoop log "payload too large" and
// RETURN, tearing down the HA connection (sessions, IPsec SAs, config all
// ride it), and the forced re-push on reconnect repeats the cycle forever:
// DHCP lease protection for takeover silently stops. Roughly 165k ordinary
// v4 leases suffice. The fix chunks the full set generation-tagged across
// sub-cap frames (the #14607 precedent for persistent-NAT batches) that the
// receiver assembles and commits atomically with #7175 replace semantics.

// dhcpChunkLease15160 builds one realistic v4 lease whose encoding is ~70-90
// bytes, so exceeding the 16 MiB cap needs a large but plausible population.
func dhcpChunkLease15160(i int) dhcpserver.SyncLease {
	return dhcpserver.SyncLease{
		Family:             4,
		Address:            fmt.Sprintf("10.%d.%d.%d", (i>>16)&0xff, (i>>8)&0xff, i&0xff),
		SubnetID:           1,
		ValidLife:          7200,
		Remaining:          3600,
		PreferredRemaining: 1800,
		HWAddress:          fmt.Sprintf("52:54:00:%02x:%02x:%02x", (i>>16)&0xff, (i>>8)&0xff, i&0xff),
		ClientID:           fmt.Sprintf("01:52:54:00:%02x:%02x:%02x", (i>>16)&0xff, (i>>8)&0xff, i&0xff),
		LeaseType:          "IA_NA",
	}
}

// dhcpOverset15160 returns a lease population whose single-frame encoding
// provably exceeds maxSyncPayload, so it can only ever arrive chunked.
func dhcpOverset15160(t *testing.T, n int) []dhcpserver.SyncLease {
	t.Helper()
	leases := make([]dhcpserver.SyncLease, 0, n)
	for i := range n {
		leases = append(leases, dhcpChunkLease15160(i))
	}
	if got := len(encodeDHCPLeasePayload(leases)); got <= maxSyncPayload {
		t.Fatalf("FIXTURE: %d leases encode to %d bytes, must exceed maxSyncPayload %d to exercise #15160",
			n, got, maxSyncPayload)
	}
	return leases
}

// feedCaptured15160 plays captured wire frames through the receiver's
// handleMessage in order, exactly as its receiveLoop would after stripping
// the 12-byte sync header (captureConn.frames already did that).
func feedCaptured15160(t *testing.T, recv *SessionSync, frames []captureFrame) {
	t.Helper()
	for _, f := range frames {
		recv.handleMessage(nil, f.msgType, f.payload)
	}
}

// TestDHCPLeaseOversetChunked15160 is the acceptance cell: an over-cap set
// must cross as multiple frames, every one <= maxSyncPayload, and the
// receiver must hold ALL leases afterwards with its replace semantics and
// authority metadata intact.
func TestDHCPLeaseOversetChunked15160(t *testing.T) {
	leases := dhcpOverset15160(t, 260_000)

	sender := NewSessionSync(":0", "10.0.0.2:4785", nil)
	cc := &captureConn{}
	sender.mu.Lock()
	sender.conn0 = cc
	sender.mu.Unlock()

	snap := dhcpserver.LeaseSyncSnapshot{
		Leases:     leases,
		Generation: 7,
		Received:   true,
		Scopes: []dhcpserver.LeaseScopeAuthority{
			{Family: 4, CIDR: "10.0.0.0/8", RGID: 1, Generation: 7, Served: true, Applied: true},
		},
	}
	sender.QueueDHCPLeaseSnapshot(4, snap)

	frames := cc.frames()
	if len(frames) < 2 {
		t.Fatalf("over-cap DHCP set emitted %d frame(s); every frame over maxSyncPayload "+
			"makes the receiver's receiveLoop return and tear down HA sync (#15160)", len(frames))
	}
	for i, f := range frames {
		if len(f.payload) > maxSyncPayload {
			t.Fatalf("frame %d payload = %d bytes, exceeds maxSyncPayload %d (the receiveLoop "+
				"refuses the header and disconnects; #15160)", i, len(f.payload), maxSyncPayload)
		}
		if f.msgType != syncMsgDHCPLeaseV4Chunk && f.msgType != syncMsgDHCPLeaseV4 {
			t.Fatalf("frame %d type = %d, want the DHCP v4 chunk/legacy family", i, f.msgType)
		}
	}

	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var callbackSets [][]dhcpserver.SyncLease
	recv.OnDHCPLeasesReceived = func(_ int, got []dhcpserver.SyncLease) {
		callbackSets = append(callbackSets, append([]dhcpserver.SyncLease(nil), got...))
	}
	feedCaptured15160(t, recv, frames)

	held := recv.PeerDHCPLeaseSnapshot4()
	if !held.Received {
		t.Fatal("receiver never committed the chunked set (Received=false); DHCP takeover protection is down")
	}
	if held.Generation != 7 || len(held.Scopes) != 1 || !held.Scopes[0].Applied {
		t.Fatalf("chunked commit lost authority metadata: generation=%d scopes=%+v", held.Generation, held.Scopes)
	}
	if len(held.Leases) != len(leases) {
		t.Fatalf("receiver holds %d leases, want all %d from the over-cap set (a truncated commit "+
			"silently deletes leases past the cut; #7175)", len(held.Leases), len(leases))
	}
	// Spot-check identity at the chunk seams: first, middle and last lease.
	for _, idx := range []int{0, len(leases) / 2, len(leases) - 1} {
		if held.Leases[idx].Address != leases[idx].Address || held.Leases[idx].HWAddress != leases[idx].HWAddress {
			t.Fatalf("lease %d mismatch: held %+v, want address/hw %s/%s", idx, held.Leases[idx], leases[idx].Address, leases[idx].HWAddress)
		}
	}
	// The consumer callback fires exactly once, with the complete set.
	if len(callbackSets) != 1 || len(callbackSets[0]) != len(leases) {
		t.Fatalf("OnDHCPLeasesReceived fired %d time(s) with sizes summing wrong; want exactly one complete-set callback", len(callbackSets))
	}
}

// TestDHCPLeaseChunkOpenTrailingNeverCommits15160 pins atomicity: an
// incomplete chunk generation (the final chunk never arrives, e.g. the
// connection dropped mid-set) must NOT replace the held set — the receiver
// keeps the previous complete set, the #7175 posture.
func TestDHCPLeaseChunkOpenTrailingNeverCommits15160(t *testing.T) {
	leases := dhcpOverset15160(t, 260_000)

	sender := NewSessionSync(":0", "10.0.0.2:4785", nil)
	cc := &captureConn{}
	sender.mu.Lock()
	sender.conn0 = cc
	sender.mu.Unlock()
	sender.QueueDHCPLeaseSnapshot(4, dhcpserver.LeaseSyncSnapshot{Leases: leases, Generation: 3, Received: true})
	frames := cc.frames()
	if len(frames) < 2 {
		t.Fatalf("FIXTURE: need >=2 frames to withhold the final chunk, got %d", len(frames))
	}

	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	prior := []dhcpserver.SyncLease{dhcpChunkLease15160(999_999)}
	recv.SetPeerDHCPLeasesForTesting(4, prior)

	// Feed every chunk EXCEPT the last: the set is announced but never closes.
	feedCaptured15160(t, recv, frames[:len(frames)-1])
	held := recv.PeerDHCPLeases4()
	if len(held) != 1 || held[0].Address != prior[0].Address {
		t.Fatalf("an unclosed chunk generation replaced the held set with %d leases; "+
			"partial assembly must never commit (#7175/#15160)", len(held))
	}
	// Feeding the final chunk now completes and replaces atomically.
	feedCaptured15160(t, recv, frames[len(frames)-1:])
	if got := len(recv.PeerDHCPLeases4()); got != len(leases) {
		t.Fatalf("after the closing chunk the receiver holds %d leases, want %d", got, len(leases))
	}
}

// TestDHCPLeaseChunkStaleGenerationIgnored15160: a chunk generation whose
// (incarnation, seq) is not strictly newer than the last committed set is
// dropped whole — its chunks must not resurrect or regress the held set,
// and a LATER fresh set must still apply (the stale generation must not
// wedge the stream).
func TestDHCPLeaseChunkStaleGenerationIgnored15160(t *testing.T) {
	mk := func(base, n int) []dhcpserver.SyncLease {
		out := make([]dhcpserver.SyncLease, 0, n)
		for i := range n {
			out = append(out, dhcpChunkLease15160(base+i))
		}
		return out
	}
	capture := func(ss *SessionSync, leases []dhcpserver.SyncLease) []captureFrame {
		cc := &captureConn{}
		ss.mu.Lock()
		ss.conn0 = cc
		ss.mu.Unlock()
		ss.mu.Lock()
		ss.conn0 = cc
		ss.mu.Unlock()
		ss.QueueDHCPLeases(4, leases)
		return cc.frames()
	}

	sender := NewSessionSync(":0", "10.0.0.2:4785", nil)

	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	good := capture(sender, dhcpOverset15160(t, 260_000))
	feedCaptured15160(t, recv, good)
	if got := len(recv.PeerDHCPLeases4()); got != 260_000 {
		t.Fatalf("FIXTURE: fresh overset must commit, holds %d", got)
	}
	// Replay the SAME frames (same incarnation/seq): strictly-older-or-equal,
	// so the generation admits nothing and the held set is untouched. Replay
	// with mutated content would need re-encoding; equality of (inc,seq) is
	// what the guard keys on, so a verbatim replay is the honest probe.
	feedCaptured15160(t, recv, good)
	if got := len(recv.PeerDHCPLeases4()); got != 260_000 {
		t.Fatalf("replayed chunk generation changed the held set to %d leases", got)
	}
	// A genuinely newer push (single-frame, legacy type) still applies.
	small := capture(sender, mk(500_000, 3))
	feedCaptured15160(t, recv, small)
	if got := recv.PeerDHCPLeases4(); len(got) != 3 || got[0].Address != dhcpChunkLease15160(500_000).Address {
		t.Fatalf("newer legacy set after chunk commits = %v, want the 3-lease set", got)
	}
}

// TestDHCPLeaseSingleFrameStaysLegacy15160 is the named control: a set that
// fits one frame keeps the pre-#15160 wire shape (single legacy-typed frame,
// no chunk envelope) so a pre-#15160 peer decodes it exactly as before.
func TestDHCPLeaseSingleFrameStaysLegacy15160(t *testing.T) {
	sender := NewSessionSync(":0", "10.0.0.2:4785", nil)
	cc := &captureConn{}
	sender.mu.Lock()
	sender.conn0 = cc
	sender.mu.Unlock()

	leases := []dhcpserver.SyncLease{dhcpChunkLease15160(1), dhcpChunkLease15160(2)}
	sender.QueueDHCPLeaseSnapshot(4, dhcpserver.LeaseSyncSnapshot{
		Leases: leases, Generation: 5, Received: true,
		Scopes: []dhcpserver.LeaseScopeAuthority{{Family: 4, CIDR: "10.0.0.0/8", RGID: 1, Generation: 5, Served: true, Applied: true}},
	})
	frames := cc.frames()
	if len(frames) != 1 {
		t.Fatalf("small set emitted %d frames, want exactly 1 (no chunking tax on the common path)", len(frames))
	}
	if frames[0].msgType != syncMsgDHCPLeaseV4 {
		t.Fatalf("small set frame type = %d, want legacy syncMsgDHCPLeaseV4 %d so old peers decode it", frames[0].msgType, syncMsgDHCPLeaseV4)
	}
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	feedCaptured15160(t, recv, frames)
	held := recv.PeerDHCPLeaseSnapshot4()
	if !held.Received || held.Generation != 5 || len(held.Leases) != 2 {
		t.Fatalf("small legacy commit wrong: %+v", held)
	}
}

// TestDHCPLeaseV6OversetChunked15160 mirrors the acceptance cell on v6:
// the fix must cover both families (queueDHCPLeaseSnapshot is shared).
func TestDHCPLeaseV6OversetChunked15160(t *testing.T) {
	mk6 := func(i int) dhcpserver.SyncLease {
		return dhcpserver.SyncLease{
			Family:             6,
			Address:            fmt.Sprintf("2001:db8:%x:%x::%x", (i>>16)&0xffff, (i>>8)&0xff, i&0xff),
			SubnetID:           2,
			ValidLife:          7200,
			Remaining:          3600,
			PreferredRemaining: 1800,
			DUID:               fmt.Sprintf("00:03:00:01:52:54:00:%02x:%02x:%02x", (i>>16)&0xff, (i>>8)&0xff, i&0xff),
			IAID:               uint32(i),
			LeaseType:          "IA_NA",
		}
	}
	leases := make([]dhcpserver.SyncLease, 0, 260_000)
	for i := range 260_000 {
		leases = append(leases, mk6(i))
	}
	if got := len(encodeDHCPLeasePayload(leases)); got <= maxSyncPayload {
		t.Fatalf("FIXTURE: v6 set encodes to %d bytes, must exceed %d", got, maxSyncPayload)
	}
	sender := NewSessionSync(":0", "10.0.0.2:4785", nil)
	cc := &captureConn{}
	sender.mu.Lock()
	sender.conn0 = cc
	sender.mu.Unlock()
	sender.QueueDHCPLeases(6, leases)
	frames := cc.frames()
	if len(frames) < 2 {
		t.Fatalf("v6 over-cap set emitted %d frame(s) (#15160)", len(frames))
	}
	for i, f := range frames {
		if len(f.payload) > maxSyncPayload || f.msgType != syncMsgDHCPLeaseV6Chunk {
			t.Fatalf("v6 frame %d: %d bytes type %d, want <= %d chunk type", i, len(f.payload), f.msgType, maxSyncPayload)
		}
	}
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	feedCaptured15160(t, recv, frames)
	if got := len(recv.PeerDHCPLeases6()); got != len(leases) {
		t.Fatalf("v6 receiver holds %d leases, want %d", got, len(leases))
	}
}

// TestDHCPLeaseChunkFramingGuards15160 pins the receiver's fail-closed
// edges: a chunk frame whose chunk-count header lies about the record
// count, or whose records are cut, must be refused without committing
// anything and without disturbing a previously held set.
func TestDHCPLeaseChunkFramingGuards15160(t *testing.T) {
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	prior := []dhcpserver.SyncLease{dhcpChunkLease15160(4242)}
	recv.SetPeerDHCPLeasesForTesting(4, prior)

	// A chunk envelope claiming 9 records while carrying none, as the sole
	// chunk of its generation: undecodable, so nothing may commit.
	bogus := encodeDHCPLeaseChunkPayload(nil, 1, 0, 1, 9)
	recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, appendFullSetSeq(bogus, 77, 1))
	if held := recv.PeerDHCPLeases4(); len(held) != 1 || held[0].Address != prior[0].Address {
		t.Fatalf("malformed chunk frame disturbed the held set: %v", held)
	}
	// A chunk whose generation never closes with a mismatched total:
	// chunk 0 of 2, then chunk 1 claiming total 3 — inconsistent assembly,
	// must never commit.
	small := encodeDHCPLeasePayload([]dhcpserver.SyncLease{dhcpChunkLease15160(7)})
	c0 := encodeDHCPLeaseChunkPayload(small, 1, 0, 2, 1)
	c1bad := encodeDHCPLeaseChunkPayload(small, 1, 1, 3, 1)
	recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, appendFullSetSeq(c0, 77, 1))
	recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, appendFullSetSeq(c1bad, 77, 2))
	if held := recv.PeerDHCPLeases4(); len(held) != 1 || held[0].Address != prior[0].Address {
		t.Fatalf("inconsistent chunk generation committed over the held set: %v", held)
	}
}

// TestDHCPLeaseChunkInterleavedGenerationsSurvive17956 pins #17956: opening
// a sixth pending generation evicts only the oldest, so an interleaved
// generation that still has a chunk in flight can complete and commit.
func TestDHCPLeaseChunkInterleavedGenerationsSurvive17956(t *testing.T) {
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	prior := []dhcpserver.SyncLease{dhcpChunkLease15160(999)}
	if !recv.handleMessage(nil, syncMsgDHCPLeaseV4, appendFullSetSeq(encodeDHCPLeasePayload(prior), 1000, 1)) {
		t.Fatal("CONTROL: prior legacy set must commit")
	}

	chunk := func(generation uint64, index int, seq uint64) []byte {
		lease := dhcpChunkLease15160(int(generation*10) + index)
		body := encodeDHCPLeasePayload([]dhcpserver.SyncLease{lease})
		base := encodeDHCPLeaseChunkPayload(body, generation, uint32(index), 2, 2)
		return appendFullSetSeq(base, 1000, seq)
	}
	seq := uint64(100)
	nextSeq := func() uint64 {
		seq++
		return seq
	}

	// Open generations 101..105 with their first chunk, filling the cap.
	for generation := uint64(101); generation <= 105; generation++ {
		if !recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, chunk(generation, 0, nextSeq())) {
			t.Fatalf("CONTROL: first chunk of generation %d must be accepted", generation)
		}
	}
	// Opening generation 106 evicts only oldest generation 101.
	if !recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, chunk(106, 0, nextSeq())) {
		t.Fatal("CONTROL: first chunk of generation 106 must be accepted")
	}
	if n := len(recv.dhcpChunkState4.pending); n != 5 {
		t.Fatalf("opening generation 106 left %d pending assemblies, want 5", n)
	}
	if _, ok := recv.dhcpChunkState4.pending[dhcpChunkGeneration{incarnation: 1000, generation: 101}]; ok {
		t.Fatal("oldest generation 101 must be evicted")
	}
	for generation := uint64(102); generation <= 106; generation++ {
		if _, ok := recv.dhcpChunkState4.pending[dhcpChunkGeneration{incarnation: 1000, generation: generation}]; !ok {
			t.Fatalf("generation %d must survive opening generation 106", generation)
		}
	}
	if held := recv.PeerDHCPLeases4(); len(held) != 1 || held[0].Address != prior[0].Address {
		t.Fatalf("no incomplete generation may commit: held %v, want prior set", held)
	}

	// Generation 102 predates the sixth arrival but survives and completes.
	if !recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, chunk(102, 1, nextSeq())) {
		t.Fatal("final chunk of surviving generation 102 must be accepted")
	}
	held := recv.PeerDHCPLeases4()
	want := []dhcpserver.SyncLease{dhcpChunkLease15160(1020), dhcpChunkLease15160(1021)}
	if len(held) != len(want) || held[0].Address != want[0].Address || held[1].Address != want[1].Address {
		t.Fatalf("completed generation 102 must commit: held %v, want %v", held, want)
	}
}

// TestDHCPLeaseChunkOlderGenerationCannotOverwriteNewerCommit18369 pins
// #18369: a chunk generation whose final chunk is refused downstream of
// seq admission (here: its only lease is filtered to empty before
// addChunk, leaving the pending assembly untouched) must not commit when
// its valid later-sequenced retry completes after a newer chunked
// generation has committed. The per-frame seq guard admits the retry
// (its frame seq is fresh); only the per-incarnation committed-generation
// watermark fences it. Mirrors the executed #18353 interleaving for IPsec.
func TestDHCPLeaseChunkOlderGenerationCannotOverwriteNewerCommit18369(t *testing.T) {
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var callbacks [][]dhcpserver.SyncLease
	recv.OnDHCPLeasesReceived = func(family int, leases []dhcpserver.SyncLease) {
		if family != 4 {
			t.Errorf("callback family = %d, want 4", family)
		}
		callbacks = append(callbacks, append([]dhcpserver.SyncLease(nil), leases...))
	}
	chunk := func(generation uint64, index uint32, seq uint64, lease dhcpserver.SyncLease) []byte {
		body := encodeDHCPLeasePayload([]dhcpserver.SyncLease{lease})
		return appendFullSetSeq(encodeDHCPLeaseChunkPayload(body, generation, index, 2, 2), 1000, seq)
	}
	g0 := dhcpChunkLease15160(200)
	g1 := dhcpChunkLease15160(201)
	h0 := dhcpChunkLease15160(400)
	h1 := dhcpChunkLease15160(401)

	if !recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, chunk(2, 0, 2, g0)) {
		t.Fatal("G index 0 must be admitted into its pending assembly")
	}
	// G's final chunk carries a lease with no v4 identity: it is filtered
	// to empty and refused before addChunk, so G's assembly stays pending
	// and nothing commits.
	bad := g1
	bad.HWAddress = ""
	bad.ClientID = ""
	if recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, chunk(2, 1, 3, bad)) {
		t.Fatal("G's identity-less final chunk must be refused")
	}
	if n := len(recv.dhcpChunkState4.pending); n != 1 {
		t.Fatalf("refused G chunk must leave its existing assembly pending, got %d assemblies", n)
	}

	for _, f := range [][]byte{
		chunk(4, 0, 4, h0),
		chunk(4, 1, 5, h1),
	} {
		if !recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, f) {
			t.Fatal("H chunks must be accepted")
		}
	}
	held := recv.PeerDHCPLeases4()
	if len(held) != 2 || held[0].Address != h0.Address || held[1].Address != h1.Address {
		t.Fatalf("H must publish before G's retry: held %v", held)
	}
	if len(callbacks) != 1 || len(callbacks[0]) != 2 || callbacks[0][0].Address != h0.Address || callbacks[0][1].Address != h1.Address {
		t.Fatalf("only H's completed set should have fired a callback, got %v", callbacks)
	}

	// G's valid retry arrives with a fresh frame seq, so the per-frame
	// guard admits it and the assembly closes — but generation 2 is older
	// than committed generation 4, so the completion must be fenced.
	if recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, chunk(2, 1, 6, g1)) {
		t.Fatal("G's now-complete older generation must be dropped")
	}
	held = recv.PeerDHCPLeases4()
	if len(held) != 2 || held[0].Address != h0.Address || held[1].Address != h1.Address {
		t.Fatalf("stale G completion overwrote H: held %v", held)
	}
	if len(callbacks) != 1 {
		t.Fatalf("stale G completion must not fire OnDHCPLeasesReceived, got %v", callbacks)
	}
	if n := recv.Stats().DHCPLeasesStaleIgnored; n != 1 {
		t.Fatalf("DHCPLeasesStaleIgnored = %d, want 1 for stale completed G", n)
	}

}

// TestDHCPLeaseChunkGenerationCannotExceedFrameSequence18371 pins the
// sender invariant that a chunk set's generation is its first frame
// sequence: a forged generation ahead of its sequence must not poison the
// committed-generation watermark and suppress a later legitimate set.
func TestDHCPLeaseChunkGenerationCannotExceedFrameSequence18371(t *testing.T) {
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var callbacks [][]dhcpserver.SyncLease
	recv.OnDHCPLeasesReceived = func(_ int, leases []dhcpserver.SyncLease) {
		callbacks = append(callbacks, append([]dhcpserver.SyncLease(nil), leases...))
	}
	chunk := func(generation, seq uint64, lease dhcpserver.SyncLease) []byte {
		body := encodeDHCPLeasePayload([]dhcpserver.SyncLease{lease})
		return appendFullSetSeq(encodeDHCPLeaseChunkPayload(body, generation, 0, 1, 1), 1000, seq)
	}
	forged := chunk(math.MaxUint64, 1, dhcpChunkLease15160(700))
	if recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, forged) {
		t.Fatal("generation ahead of frame sequence must be rejected")
	}
	if held := recv.PeerDHCPLeases4(); len(held) != 0 {
		t.Fatalf("inconsistent generation committed before valid set: %v", held)
	}
	valid := dhcpChunkLease15160(701)
	if !recv.handleMessage(nil, syncMsgDHCPLeaseV4Chunk, chunk(2, 2, valid)) {
		t.Fatal("valid generation 2 / sequence 2 must be accepted after malformed frame")
	}
	if held := recv.PeerDHCPLeases4(); len(held) != 1 || held[0].Address != valid.Address {
		t.Fatalf("valid generation 2 was suppressed by inconsistent frame: %v", held)
	}
	if len(callbacks) != 1 || len(callbacks[0]) != 1 || callbacks[0][0].Address != valid.Address {
		t.Fatalf("only valid generation should notify callback, got %v", callbacks)
	}
}
