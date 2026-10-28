package cluster

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// #16758: an IPsec SA full set over maxIPsecSANames was refused whole by
// the standby decoder, and the sender neither fitted the bound nor
// alarmed, so the standby kept a stale set and would re-initiate it on
// takeover. The fix chunks over-bound sets (the #15160 precedent), counts
// receiver refusals, and latches an operator-visible alarm on the sender.

func ipsecNames16758(n int) []string {
	names := make([]string, 0, n)
	for i := range n {
		names = append(names, fmt.Sprintf("vpn-%d", i))
	}
	return names
}

// TestIPsecSAOversizeAlarmRendered16758 pins the operator-visible half:
// after an over-cap push, FormatStatus carries the latched Warning and
// both statistics surfaces carry the malformed/over-cap row; before any
// over-cap push, neither appears.
func TestIPsecSAOversizeAlarmRendered16758(t *testing.T) {
	sender, _ := captureIPsecSender16758(t)
	manager := NewManager(0, 22)
	manager.SetSyncStats(sender)
	if s := manager.FormatStatus(); strings.Contains(s, "IPsec SA set exceeded") {
		t.Fatalf("clean sender must not raise the oversize alarm:\n%s", s)
	}
	if s := manager.FormatStatistics(); strings.Contains(s, "IPsec SA malformed/over-cap") {
		t.Fatalf("clean sender must not render the over-cap row:\n%s", s)
	}
	if !sender.QueueIPsecSA(ipsecNames16758(5000)) {
		t.Fatal("over-cap push must confirm")
	}
	if s := manager.FormatStatus(); !strings.Contains(s, "IPsec SA set exceeded the single-frame bound") || !strings.Contains(s, "Over-cap IPsec SA pushes: 1") {
		t.Fatalf("FormatStatus must render the latched oversize alarm:\n%s", s)
	}
	for name, s := range map[string]string{
		"statistics": manager.FormatStatistics(),
		"data-plane": manager.FormatDataPlaneStatistics(),
	} {
		if !strings.Contains(s, "IPsec SA malformed/over-cap") {
			t.Fatalf("%s must render the malformed/over-cap row:\n%s", name, s)
		}
	}
}

func captureIPsecSender16758(t *testing.T) (*SessionSync, *captureConn) {
	t.Helper()
	sender := NewSessionSync(":0", "10.0.0.2:4785", nil)
	cc := &captureConn{}
	sender.mu.Lock()
	sender.conn0 = cc
	sender.mu.Unlock()
	return sender, cc
}

// TestIPsecSA5000NamesRoundTrip16758 is the acceptance cell: a 5000-name
// set crosses as chunk frames (never one legacy frame), every frame fits
// the global cap, and the receiver holds all 5000 names afterwards with
// the callback fired exactly once. Pre-fix QueueIPsecSA emitted one
// legacy frame and the receiver held its prior set.
func TestIPsecSA5000NamesRoundTrip16758(t *testing.T) {
	names := ipsecNames16758(5000)
	sender, cc := captureIPsecSender16758(t)
	if !sender.QueueIPsecSA(names) {
		t.Fatal("QueueIPsecSA(5000 names) must confirm the chunked send")
	}
	frames := cc.frames()
	if len(frames) < 2 {
		t.Fatalf("5000-name set emitted %d frame(s), want multiple chunk frames", len(frames))
	}
	for i, f := range frames {
		if f.msgType != syncMsgIPsecSAChunk {
			t.Fatalf("frame %d type = %d, want syncMsgIPsecSAChunk (%d)", i, f.msgType, syncMsgIPsecSAChunk)
		}
		if len(f.payload) > maxSyncPayload {
			t.Fatalf("frame %d payload = %d, exceeds maxSyncPayload %d", i, len(f.payload), maxSyncPayload)
		}
	}
	if got := sender.Stats(); got.IPsecSAOverCapSets != 1 || !got.IPsecSAOversizeAlarmLatched {
		t.Fatalf("sender alarm/counter not raised for over-cap set: %+v", got)
	}

	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var applied [][]string
	recv.OnIPsecSAReceived = func(n []string) { applied = append(applied, append([]string(nil), n...)) }
	// Seed a prior set so a partial commit would be visible.
	recv.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(encodeIPsecSAPayload([]string{"vpn-old-0"}), 1000, 1))
	for _, f := range frames {
		recv.handleMessage(nil, f.msgType, f.payload)
	}
	held := recv.PeerIPsecSAs()
	if len(held) != 5000 {
		t.Fatalf("receiver held %d names after chunked 5000-name push, want 5000 (first=%v)", len(held), held[:min(3, len(held))])
	}
	if held[0] != "vpn-0" || held[4999] != "vpn-4999" {
		t.Fatalf("chunked set order/content wrong: first=%q last=%q", held[0], held[4999])
	}
	if len(applied) != 2 || len(applied[1]) != 5000 {
		t.Fatalf("OnIPsecSAReceived must fire once for the completed chunked set (plus setup), got %d callbacks", len(applied))
	}
}

// TestIPsecSAAtBoundKeepsLegacyShape16758 pins the boundary: exactly
// maxIPsecSANames names keep the legacy single-frame shape (so a mixed
// pair behaves as before), and maxIPsecSANames+1 switches to chunked.
func TestIPsecSAAtBoundKeepsLegacyShape16758(t *testing.T) {
	sender, cc := captureIPsecSender16758(t)
	if !sender.QueueIPsecSA(ipsecNames16758(maxIPsecSANames)) {
		t.Fatal("at-bound QueueIPsecSA must confirm")
	}
	frames := cc.frames()
	if len(frames) != 1 || frames[0].msgType != syncMsgIPsecSA {
		t.Fatalf("at-bound set must emit one legacy frame, got %d frames type=%v", len(frames), frames)
	}
	if got := sender.Stats(); got.IPsecSAOverCapSets != 0 || got.IPsecSAOversizeAlarmLatched {
		t.Fatalf("at-bound set must not raise the over-cap alarm: %+v", got)
	}

	sender2, cc2 := captureIPsecSender16758(t)
	if !sender2.QueueIPsecSA(ipsecNames16758(maxIPsecSANames + 1)) {
		t.Fatal("over-bound QueueIPsecSA must confirm chunked send")
	}
	frames2 := cc2.frames()
	if len(frames2) != 2 {
		t.Fatalf("4097-name set must emit 2 chunk frames, got %d", len(frames2))
	}
	for _, f := range frames2 {
		if f.msgType != syncMsgIPsecSAChunk {
			t.Fatalf("over-bound frame type = %d, want chunk", f.msgType)
		}
	}
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	for _, f := range frames2 {
		recv.handleMessage(nil, f.msgType, f.payload)
	}
	if got := len(recv.PeerIPsecSAs()); got != maxIPsecSANames+1 {
		t.Fatalf("4097-name chunked set held %d names, want %d", got, maxIPsecSANames+1)
	}
}

// TestIPsecSAChunkIncompleteNeverCommits16758 pins atomicity: an
// incomplete generation (final chunk never arrives) must not replace the
// held set.
func TestIPsecSAChunkIncompleteNeverCommits16758(t *testing.T) {
	sender, cc := captureIPsecSender16758(t)
	if !sender.QueueIPsecSA(ipsecNames16758(5000)) {
		t.Fatal("setup chunked send must confirm")
	}
	frames := cc.frames()
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	recv.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(encodeIPsecSAPayload([]string{"vpn-prior"}), 1000, 1))
	for _, f := range frames[:len(frames)-1] {
		if !recv.handleMessage(nil, f.msgType, f.payload) {
			t.Fatal("non-final chunk must be accepted into the assembly")
		}
	}
	if held := recv.PeerIPsecSAs(); len(held) != 1 || held[0] != "vpn-prior" {
		t.Fatalf("incomplete chunk generation committed: held %v, want [vpn-prior]", held)
	}
	if n := len(recv.ipsecChunkState.pending); n != 1 {
		t.Fatalf("incomplete generation left %d pending assemblies, want 1", n)
	}
}

// TestIPsecSAChunkOlderGenerationCannotOverwriteNewerCommit17826 reproduces
// a generation whose oversized final chunk is refused, then completes with
// a valid later-sequenced retry after a newer generation has committed. The
// frame sequence admits that retry, but its original generation must remain
// fenced by the newer committed set.
func TestIPsecSAChunkOlderGenerationCannotOverwriteNewerCommit17826(t *testing.T) {
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	var callbacks [][]string
	recv.OnIPsecSAReceived = func(names []string) {
		callbacks = append(callbacks, append([]string(nil), names...))
	}
	chunk := func(generation uint64, index uint32, seq uint64, name string) []byte {
		body := encodeIPsecSAPayload([]string{name})
		return appendFullSetSeq(encodeIPsecSAChunkPayload(body, generation, index, 2, 2), 1000, seq)
	}

	if !recv.handleMessage(nil, syncMsgIPsecSAChunk, chunk(2, 0, 2, "vpn-g0")) {
		t.Fatal("G index 0 must be admitted into its pending assembly")
	}
	overlong := []byte(strings.Repeat("x", maxIPsecSANameLen+1))
	refused := appendFullSetSeq(encodeIPsecSAChunkPayload(overlong, 2, 1, 2, 2), 1000, 3)
	if recv.handleMessage(nil, syncMsgIPsecSAChunk, refused) {
		t.Fatal("G's over-limit index 1 must be refused")
	}
	if n := len(recv.ipsecChunkState.pending); n != 1 {
		t.Fatalf("refused G chunk must leave its existing assembly pending, got %d assemblies", n)
	}

	for _, f := range [][]byte{
		chunk(4, 0, 4, "vpn-h0"),
		chunk(4, 1, 5, "vpn-h1"),
	} {
		if !recv.handleMessage(nil, syncMsgIPsecSAChunk, f) {
			t.Fatal("H chunks must be accepted")
		}
	}
	if held := recv.PeerIPsecSAs(); len(held) != 2 || held[0] != "vpn-h0" || held[1] != "vpn-h1" {
		t.Fatalf("H must publish before G's retry: held %v", held)
	}
	if len(callbacks) != 1 || len(callbacks[0]) != 2 || callbacks[0][0] != "vpn-h0" || callbacks[0][1] != "vpn-h1" {
		t.Fatalf("only H's completed set should have fired a callback, got %v", callbacks)
	}

	if recv.handleMessage(nil, syncMsgIPsecSAChunk, chunk(2, 1, 6, "vpn-g1")) {
		t.Fatal("G's now-complete older generation must be dropped")
	}
	if held := recv.PeerIPsecSAs(); len(held) != 2 || held[0] != "vpn-h0" || held[1] != "vpn-h1" {
		t.Fatalf("stale G completion overwrote H: held %v", held)
	}
	if len(callbacks) != 1 {
		t.Fatalf("stale G completion must not fire OnIPsecSAReceived, got %v", callbacks)
	}
	if n := recv.Stats().IPsecSAStaleIgnored; n != 1 {
		t.Fatalf("IPsecSAStaleIgnored = %d, want 1 for stale completed G", n)
	}
}

// TestIPsecSAChunkInterleavedGenerationsSurvive17846 pins #17846: opening
// more generations than the pending-assembly cap must evict only the
// oldest assembly. The flush-all budget replaced every pending generation
// when a 6th generation appeared, so an older generation whose remaining
// chunks then arrived could never complete and its set was silently lost
// (the receiver kept the prior set; no stale/partial commit, just liveness
// loss on interleaved pushes/reconnect replays).
func TestIPsecSAChunkInterleavedGenerationsSurvive17846(t *testing.T) {
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	recv.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(encodeIPsecSAPayload([]string{"vpn-prior"}), 1000, 1))

	// Each generation carries two one-name chunks (total=2, totalNames=2).
	// Generation identity is its first full-set seq; every chunk frame
	// also carries its own strictly increasing seq.
	chunk := func(generation, index, seq uint64) []byte {
		body := encodeIPsecSAPayload([]string{fmt.Sprintf("vpn-g%d-c%d", generation, index)})
		return appendFullSetSeq(encodeIPsecSAChunkPayload(body, generation, uint32(index), 2, 2), 1000, seq)
	}

	seq := uint64(1)
	next := func() uint64 { seq++; return seq }

	// Open generations 101..105 with their first chunk only, filling
	// the pending cap of five. Opening generation 106 below evicts the
	// oldest one (101) and leaves the other four plus 106 pending.
	for g := uint64(101); g <= 105; g++ {
		if !recv.handleMessage(nil, syncMsgIPsecSAChunk, chunk(g, 0, next())) {
			t.Fatalf("CONTROL: first chunk of generation %d must be accepted", g)
		}
	}
	// Opening the 6th generation over the cap evicts only the oldest
	// (101); generations 102..106 must all still be pending.
	if !recv.handleMessage(nil, syncMsgIPsecSAChunk, chunk(106, 0, next())) {
		t.Fatal("CONTROL: first chunk of generation 106 must be accepted")
	}
	if n := len(recv.ipsecChunkState.pending); n != 5 {
		t.Fatalf("over-cap opening left %d pending assemblies, want 5 (only generation 101 evicted)", n)
	}
	if _, ok := recv.ipsecChunkState.pending[ipsecSAChunkGeneration{incarnation: 1000, generation: 101}]; ok {
		t.Fatal("oldest generation 101 must be the one evicted")
	}
	for g := uint64(102); g <= 106; g++ {
		if _, ok := recv.ipsecChunkState.pending[ipsecSAChunkGeneration{incarnation: 1000, generation: g}]; !ok {
			t.Fatalf("generation %d must survive the over-cap opening (flush-all discarded it)", g)
		}
	}
	if held := recv.PeerIPsecSAs(); len(held) != 1 || held[0] != "vpn-prior" {
		t.Fatalf("no incomplete generation may commit: held %v, want [vpn-prior]", held)
	}

	// The surviving generation 106 completes and commits atomically.
	if !recv.handleMessage(nil, syncMsgIPsecSAChunk, chunk(106, 1, next())) {
		t.Fatal("final chunk of surviving generation 106 must be accepted")
	}
	held := recv.PeerIPsecSAs()
	if len(held) != 2 || held[0] != "vpn-g106-c0" || held[1] != "vpn-g106-c1" {
		t.Fatalf("completed generation 106 must commit: held %v, want [vpn-g106-c0 vpn-g106-c1]", held)
	}

	// The evicted generation 101 can never complete: its remaining chunk
	// starts a fresh assembly that stays incomplete, so the committed set
	// is undisturbed and no stale/partial set ever commits.
	if !recv.handleMessage(nil, syncMsgIPsecSAChunk, chunk(101, 1, next())) {
		t.Fatal("CONTROL: lone chunk of evicted generation 101 is accepted as a fresh incomplete assembly")
	}
	if held := recv.PeerIPsecSAs(); len(held) != 2 || held[0] != "vpn-g106-c0" || held[1] != "vpn-g106-c1" {
		t.Fatalf("evicted generation's lone chunk must not commit: held %v, want generation 106 set", held)
	}
	if n := len(recv.ipsecChunkState.pending); n > 5 {
		t.Fatalf("pending assemblies exceed the cap: %d, want <= 5", n)
	}
}

// TestIPsecSAMalformedRefusalCounted16758 pins the receiver counter: a
// malformed legacy frame and a malformed chunk header each increment
// IPsecSAMalformedIgnored and retain the held set.
func TestIPsecSAMalformedRefusalCounted16758(t *testing.T) {
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	recv.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(encodeIPsecSAPayload([]string{"vpn-a"}), 1000, 1))
	// Malformed legacy: over element bound.
	huge := strings.Repeat("a\n", maxIPsecSANames+1)
	recv.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq([]byte(huge), 1000, 2))
	if got := recv.Stats().IPsecSAMalformedIgnored; got != 1 {
		t.Fatalf("malformed legacy refusal not counted: IPsecSAMalformedIgnored=%d want 1", got)
	}
	if held := recv.PeerIPsecSAs(); len(held) != 1 || held[0] != "vpn-a" {
		t.Fatalf("malformed legacy frame disturbed held set: %v", held)
	}
	// The malformed seq was not consumed: a well-formed twin at seq=2 applies.
	recv.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(encodeIPsecSAPayload([]string{"vpn-b"}), 1000, 2))
	if held := recv.PeerIPsecSAs(); len(held) != 1 || held[0] != "vpn-b" {
		t.Fatalf("well-formed twin after malformed must apply: %v", held)
	}
	// Malformed chunk header: truncated.
	if recv.handleMessage(nil, syncMsgIPsecSAChunk, appendFullSetSeq([]byte{1, 2, 3}, 1000, 3)) {
		t.Fatal("truncated chunk header must be rejected")
	}
	if got := recv.Stats().IPsecSAMalformedIgnored; got != 2 {
		t.Fatalf("malformed chunk refusal not counted: IPsecSAMalformedIgnored=%d want 2", got)
	}
}

// TestIPsecSAChunkForgedTotalNamesRefused16758: a chunk header announcing
// totalNames past the cap, or a chunk carrying more names than the
// per-chunk bound, is refused and counted before any allocation sized by
// the announced total.
func TestIPsecSAChunkForgedTotalNamesRefused16758(t *testing.T) {
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	recv.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(encodeIPsecSAPayload([]string{"vpn-a"}), 1000, 1))
	body := encodeIPsecSAPayload([]string{"vpn-x"})
	forged := encodeIPsecSAChunkPayload(body, 1, 0, 1, 0xFFFFFFFF)
	if recv.handleMessage(nil, syncMsgIPsecSAChunk, appendFullSetSeq(forged, 1000, 2)) {
		t.Fatal("forged totalNames=0xFFFFFFFF chunk must be rejected")
	}
	if got := recv.Stats().IPsecSAMalformedIgnored; got != 1 {
		t.Fatalf("forged header not counted malformed: %d", got)
	}
	if held := recv.PeerIPsecSAs(); len(held) != 1 || held[0] != "vpn-a" {
		t.Fatalf("forged chunk disturbed held set: %v", held)
	}
	// Over per-chunk bound: one chunk carrying maxIPsecSANames+1 names.
	bigBody := encodeIPsecSAPayload(ipsecNames16758(maxIPsecSANames + 1))
	over := encodeIPsecSAChunkPayload(bigBody, 7, 0, 1, uint32(maxIPsecSANames+1))
	if recv.handleMessage(nil, syncMsgIPsecSAChunk, appendFullSetSeq(over, 1000, 3)) {
		t.Fatal("chunk over per-chunk name bound must be rejected")
	}
	if got := recv.Stats().IPsecSAMalformedIgnored; got != 2 {
		t.Fatalf("over-bound chunk not counted malformed: %d", got)
	}
}

// TestIPsecSAChunkInconsistentAssemblyRefused16758: chunks disagreeing on
// total/totalNames, or pushing the assembly past totalNames, invalidate
// the generation and never commit.
func TestIPsecSAChunkInconsistentAssemblyRefused16758(t *testing.T) {
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	recv.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(encodeIPsecSAPayload([]string{"vpn-a"}), 1000, 1))
	one := encodeIPsecSAPayload([]string{"vpn-x"})
	if !recv.handleMessage(nil, syncMsgIPsecSAChunk, appendFullSetSeq(encodeIPsecSAChunkPayload(one, 5, 0, 2, 2), 1000, 2)) {
		t.Fatal("CONTROL: first consistent chunk must be accepted")
	}
	if recv.handleMessage(nil, syncMsgIPsecSAChunk, appendFullSetSeq(encodeIPsecSAChunkPayload(one, 5, 1, 3, 2), 1000, 3)) {
		t.Fatal("chunk disagreeing on total must be rejected")
	}
	if n := len(recv.ipsecChunkState.pending); n != 0 {
		t.Fatalf("inconsistent generation left %d pending assemblies, want 0", n)
	}
	if held := recv.PeerIPsecSAs(); len(held) != 1 || held[0] != "vpn-a" {
		t.Fatalf("inconsistent assembly disturbed held set: %v", held)
	}
	// Over-total: totalNames=1 across two chunks carrying one name each.
	recv2 := NewSessionSync(":0", "10.0.0.2:4785", nil)
	if !recv2.handleMessage(nil, syncMsgIPsecSAChunk, appendFullSetSeq(encodeIPsecSAChunkPayload(one, 6, 0, 2, 1), 1000, 1)) {
		t.Fatal("CONTROL: first chunk of over-total fixture must be accepted")
	}
	if recv2.handleMessage(nil, syncMsgIPsecSAChunk, appendFullSetSeq(encodeIPsecSAChunkPayload(one, 6, 1, 2, 1), 1000, 2)) {
		t.Fatal("chunk pushing assembly past totalNames must be rejected")
	}
	if n := len(recv2.ipsecChunkState.pending); n != 0 {
		t.Fatalf("over-total generation left %d pending assemblies, want 0", n)
	}
}

// TestIPsecSAOverlongNameRefusedBySender16758: a set containing a name
// over maxIPsecSANameLen is refused by the sender (counted, no frames),
// even when chunking would otherwise apply.
func TestIPsecSAOverlongNameRefusedBySender16758(t *testing.T) {
	sender, cc := captureIPsecSender16758(t)
	names := ipsecNames16758(5000)
	names[123] = strings.Repeat("n", maxIPsecSANameLen+1)
	if sender.QueueIPsecSA(names) {
		t.Fatal("sender must refuse a set containing an over-long name")
	}
	if frames := cc.frames(); len(frames) != 0 {
		t.Fatalf("refused set emitted %d frames, want 0", len(frames))
	}
	if got := sender.Stats(); got.IPsecSAMalformedIgnored != 1 {
		t.Fatalf("over-long refusal not counted: IPsecSAMalformedIgnored=%d want 1", got.IPsecSAMalformedIgnored)
	}
}

// TestIPsecSAChunkHeaderBounds16758 pins the header decoder boundaries.
func TestIPsecSAChunkHeaderBounds16758(t *testing.T) {
	header := func(totalNames uint32) []byte {
		return encodeIPsecSAChunkPayload([]byte("vpn-a"), 1, 0, 1, totalNames)
	}
	for _, tl := range []uint32{0, ipsecChunkMaxTotalNames + 1, 0xFFFFFFFF} {
		if _, _, _, _, _, ok := decodeIPsecSAChunkHeader(header(tl)); ok {
			t.Errorf("totalNames=%#x: header accepted; want refused", tl)
		}
	}
	for _, tl := range []uint32{1, ipsecChunkMaxTotalNames} {
		if _, _, _, got, _, ok := decodeIPsecSAChunkHeader(header(tl)); !ok || got != tl {
			t.Errorf("totalNames=%#x: header refused (ok=%v got=%d); want admitted", tl, ok, got)
		}
	}
	if _, _, _, _, _, ok := decodeIPsecSAChunkHeader([]byte{1, 2, 3}); ok {
		t.Error("truncated header accepted; want refused")
	}
	// Sender-side total cap: a set over ipsecChunkMaxTotalNames is refused
	// before any frame. (Only the guard is exercised here via a fake count
	// check — building 1M names is cheap enough.)
	sender, cc := captureIPsecSender16758(t)
	big := make([]string, ipsecChunkMaxTotalNames+1)
	for i := range big {
		big[i] = "v"
	}
	if sender.QueueIPsecSA(big) {
		t.Fatal("sender must refuse a set over the chunked-set name cap")
	}
	if frames := cc.frames(); len(frames) != 0 {
		t.Fatalf("over-cap set emitted %d frames, want 0", len(frames))
	}
}

// TestIPsecSAChunkBodyNameBoundAtDecode17826 pins the named decoder errors
// and the exact per-chunk name-count boundary from #17826.
func TestIPsecSAChunkBodyNameBoundAtDecode17826(t *testing.T) {
	tests := []struct {
		name      string
		body      []byte
		wantNames int
		wantErr   error
	}{
		{
			name:      "at limit accepted",
			body:      bytes.Repeat([]byte("a\n"), ipsecChunkNamesPerChunk),
			wantNames: ipsecChunkNamesPerChunk,
		},
		{
			name:    "one over limit returns named error",
			body:    bytes.Repeat([]byte("a\n"), ipsecChunkNamesPerChunk+1),
			wantErr: errIPsecSAChunkTooManyNames,
		},
		{
			name:    "over limit with valid tail is rejected whole",
			body:    append(bytes.Repeat([]byte("a\n"), ipsecChunkNamesPerChunk+1), []byte("vpn-tail")...),
			wantErr: errIPsecSAChunkTooManyNames,
		},
		{
			name:    "overlong name returns named error",
			body:    bytes.Repeat([]byte("n"), maxIPsecSANameLen+1),
			wantErr: errIPsecSAChunkNameTooLong,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeIPsecSAChunkBody(tc.body)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("decode error = %v, want named error %v", err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("refused chunk returned names %v; want nil", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decode error = %v, want success", err)
			}
			if len(got) != tc.wantNames {
				t.Fatalf("decoded %d names, want %d", len(got), tc.wantNames)
			}
		})
	}
}

// TestIPsecSAChunkHugeBodyRefusedAtDecode17826 is the receiver-level
// companion: a chunk frame whose body carries ~8M minimal names (the
// 16MiB-frame admission shape) is refused and counted
// IPsecSAMalformedIgnored with the held set retained — the same outcome
// the caller's post-decode bound produced, now reached inside the
// decoder before the names are materialized.
func TestIPsecSAChunkHugeBodyRefusedAtDecode17826(t *testing.T) {
	recv := NewSessionSync(":0", "10.0.0.2:4785", nil)
	recv.handleMessage(nil, syncMsgIPsecSA, appendFullSetSeq(encodeIPsecSAPayload([]string{"vpn-a"}), 1000, 1))
	if held := recv.PeerIPsecSAs(); len(held) != 1 || held[0] != "vpn-a" {
		t.Fatalf("fixture held set = %v, want [vpn-a]", held)
	}
	hugeBody := bytes.Repeat([]byte("a\n"), 8_000_000)
	forged := encodeIPsecSAChunkPayload(hugeBody, 9, 0, 1, uint32(ipsecChunkMaxTotalNames))
	if recv.handleMessage(nil, syncMsgIPsecSAChunk, appendFullSetSeq(forged, 1000, 2)) {
		t.Fatal("chunk carrying ~8M names in one body must be rejected")
	}
	if got := recv.Stats().IPsecSAMalformedIgnored; got != 1 {
		t.Fatalf("huge-body chunk refusal not counted: IPsecSAMalformedIgnored=%d want 1", got)
	}
	if held := recv.PeerIPsecSAs(); len(held) != 1 || held[0] != "vpn-a" {
		t.Fatalf("huge-body chunk disturbed held set: %v", held)
	}
}
