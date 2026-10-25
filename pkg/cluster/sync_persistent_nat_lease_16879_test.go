package cluster

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #16879: the #14638 record layout must be chosen per record, not per
// batch. One deterministic NAPT64 idle lease in a mixed push must not
// move the dynamic SNAT leases to type 43: a pre-#14638 peer has no case
// for 43 and drops every frame, so during a rolling upgrade no idle
// lease reaches it. The deterministic lease rides 43; the dynamic leases
// keep generation type 41 under the same origin/generation.

func mixedBatch16879() userspace.PersistentNatLeaseBatch {
	det := sampleIdleLease()
	det.Pool = "nat64-deterministic-0"
	det.SrcIP = "2001:db8::1"
	det.Deterministic = true
	det.DeterministicMode = 2
	det.DeterministicBlockSize = 32
	det.DeterministicBlocksPerIP = 2
	det.DeterministicHostPrefixLen = 32
	det.DeterministicHostBase = "2001:db8::"
	det.DeterministicHostCount = 2

	dyn1 := sampleIdleLease()
	dyn2 := sampleIdleLease()
	dyn2.Pool = "P2"
	dyn2.SrcIP = "10.0.61.51"

	return userspace.PersistentNatLeaseBatch{
		OriginID:   "0123456789abcdef0123456789abcdef",
		Generation: 4,
		Leases:     []userspace.IdleLeaseWire{dyn1, det, dyn2},
	}
}

// Queue a mixed batch through a capture conn: the dynamic leases must
// arrive in at least one type-41 frame decodable by the legacy decoder
// and the deterministic lease in a type-43 frame decodable only by the
// deterministic decoder, all under the same origin/generation, and a
// new receiver fed every frame in order must deliver all three leases.
func TestPersistentNatLeaseMixedBatchPerRecordLayout16879(t *testing.T) {
	batch := mixedBatch16879()

	sender := NewSessionSync(":0", "10.0.0.2:4785", nil)
	cc := &captureConn{}
	sender.mu.Lock()
	sender.conn0 = cc
	sender.mu.Unlock()
	sender.QueuePersistentNatLeaseBatch(batch)

	frames := cc.frames()
	if len(frames) < 2 {
		t.Fatalf("mixed batch frames = %d, want >= 2 (split by layout)", len(frames))
	}
	var legacyLeases, detLeases []userspace.IdleLeaseWire
	for i, f := range frames {
		base := stripPayload14607(f.payload)
		switch f.msgType {
		case syncMsgPersistentNatLeaseGeneration:
			b, ok := decodePersistentNatLeaseBatchPayload(base)
			if !ok {
				t.Fatalf("frame %d (type 41) not legacy-decodable", i)
			}
			if b.OriginID != batch.OriginID || b.Generation != batch.Generation {
				t.Fatalf("frame %d origin/gen = %q/%d, want %q/%d", i, b.OriginID, b.Generation, batch.OriginID, batch.Generation)
			}
			legacyLeases = append(legacyLeases, b.Leases...)
		case syncMsgPersistentNatLeaseDeterministic:
			b, ok := decodePersistentNatLeaseBatchPayloadDeterministic(base)
			if !ok {
				t.Fatalf("frame %d (type 43) not deterministic-decodable", i)
			}
			if b.OriginID != batch.OriginID || b.Generation != batch.Generation {
				t.Fatalf("frame %d origin/gen = %q/%d, want %q/%d", i, b.OriginID, b.Generation, batch.OriginID, batch.Generation)
			}
			detLeases = append(detLeases, b.Leases...)
		default:
			t.Fatalf("frame %d type = %d, want 41 or 43", i, f.msgType)
		}
	}
	if len(legacyLeases) != 2 {
		t.Fatalf("legacy-decodable leases = %d, want 2 dynamic SNAT leases under type 41", len(legacyLeases))
	}
	for _, l := range legacyLeases {
		if l.Deterministic {
			t.Fatalf("deterministic lease %q rode the legacy type", l.Pool)
		}
	}
	if len(detLeases) != 1 || !detLeases[0].Deterministic {
		t.Fatalf("deterministic-decodable leases = %+v, want the 1 deterministic NAPT64 lease under type 43", detLeases)
	}

	receiver := NewSessionSync(":0", "10.0.0.1:4785", nil)
	var got []userspace.IdleLeaseWire
	receiver.OnPersistentNatLeasesReceived = func(b userspace.PersistentNatLeaseBatch) {
		if b.OriginID != batch.OriginID || b.Generation != batch.Generation {
			t.Fatalf("callback origin/gen = %q/%d, want %q/%d", b.OriginID, b.Generation, batch.OriginID, batch.Generation)
		}
		got = append(got, b.Leases...)
	}
	for _, f := range frames {
		receiver.handleMessage(nil, f.msgType, f.payload)
	}
	if len(got) != 3 {
		t.Fatalf("receiver got %d leases, want 3 (2 dynamic + 1 deterministic)", len(got))
	}
}

func TestPersistentNatLeaseSingleLayoutAndEmptyTypes16879(t *testing.T) {
	mixed := mixedBatch16879()
	allInvalid := mixedBatch16879()
	for i := range allInvalid.Leases {
		allInvalid.Leases[i].Pool = strings.Repeat("x", 70_000)
	}
	for _, tc := range []struct {
		name        string
		batch       userspace.PersistentNatLeaseBatch
		msgType     uint8
		wantSize    int
		wantDropped uint64
	}{
		{
			name:     "dynamic-only",
			batch:    sampleIdleLeaseBatch11486(mixed.Leases[0]),
			msgType:  syncMsgPersistentNatLeaseGeneration,
			wantSize: 1,
		},
		{
			name:     "deterministic-only",
			batch:    sampleIdleLeaseBatch11486(mixed.Leases[1]),
			msgType:  syncMsgPersistentNatLeaseDeterministic,
			wantSize: 1,
		},
		{
			name:    "empty-generation-barrier",
			batch:   sampleIdleLeaseBatch11486(),
			msgType: syncMsgPersistentNatLeaseGeneration,
		},
		{
			name:        "all-dropped-keeps-one-generation-barrier",
			batch:       allInvalid,
			msgType:     syncMsgPersistentNatLeaseDeterministic,
			wantDropped: 3,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender := NewSessionSync(":0", "10.0.0.2:4785", nil)
			cc := &captureConn{}
			sender.mu.Lock()
			sender.conn0 = cc
			sender.mu.Unlock()
			sender.QueuePersistentNatLeaseBatch(tc.batch)

			frames := cc.frames()
			if len(frames) != 1 {
				t.Fatalf("frames = %d, want one layout/barrier frame", len(frames))
			}
			if frames[0].msgType != tc.msgType {
				t.Fatalf("message type = %d, want %d", frames[0].msgType, tc.msgType)
			}
			base := stripPayload14607(frames[0].payload)
			var got userspace.PersistentNatLeaseBatch
			var ok bool
			if tc.msgType == syncMsgPersistentNatLeaseDeterministic {
				got, ok = decodePersistentNatLeaseBatchPayloadDeterministic(base)
			} else {
				got, ok = decodePersistentNatLeaseBatchPayload(base)
			}
			if !ok {
				t.Fatalf("frame not decodable for message type %d", tc.msgType)
			}
			if got.OriginID != tc.batch.OriginID || got.Generation != tc.batch.Generation ||
				len(got.Leases) != tc.wantSize {
				t.Fatalf("decoded batch = %+v, want origin/gen %q/%d with %d leases",
					got, tc.batch.OriginID, tc.batch.Generation, tc.wantSize)
			}
			if got := sender.stats.MalformedRecordsDropped.Load(); got != tc.wantDropped {
				t.Fatalf("malformed/drop count = %d, want %d", got, tc.wantDropped)
			}
		})
	}
}

func TestPersistentNatLeaseChunkedMixedLayoutsAndDropAccounting16879(t *testing.T) {
	batch := mixedBatch16879()
	dynamic := batch.Leases[0]
	dynamic.Pool = strings.Repeat("p", 65_000)
	batch.Leases = make([]userspace.IdleLeaseWire, 0, 262)
	for range 260 {
		batch.Leases = append(batch.Leases, dynamic)
	}
	invalid := dynamic
	invalid.Pool = strings.Repeat("x", 70_000)
	batch.Leases = append(batch.Leases, invalid, mixedBatch16879().Leases[1])

	sender := NewSessionSync(":0", "10.0.0.2:4785", nil)
	cc := &captureConn{}
	sender.mu.Lock()
	sender.conn0 = cc
	sender.mu.Unlock()
	sender.QueuePersistentNatLeaseBatch(batch)

	frames := cc.frames()
	if len(frames) < 3 {
		t.Fatalf("mixed chunked frames = %d, want >1 legacy chunk plus deterministic frame", len(frames))
	}
	if got := sender.stats.MalformedRecordsDropped.Load(); got != 1 {
		t.Fatalf("malformed/drop count = %d, want 1 unencodable dynamic lease", got)
	}
	dynamicFrames, dynamicLeases := 0, 0
	deterministicFrames, deterministicLeases := 0, 0
	var prevSeq uint64
	for i, frame := range frames {
		if len(frame.payload) > maxSyncPayload {
			t.Fatalf("frame %d size = %d, exceeds %d", i, len(frame.payload), maxSyncPayload)
		}
		base, incarnation, seq := stripFullSetSeq(frame.payload)
		if incarnation != sender.syncEpoch || seq != uint64(i+1) || seq <= prevSeq {
			t.Fatalf("frame %d sequence = (%d, %d), want incarnation %d and increasing seq",
				i, incarnation, seq, sender.syncEpoch)
		}
		prevSeq = seq
		switch frame.msgType {
		case syncMsgPersistentNatLeaseGeneration:
			if deterministicFrames != 0 {
				t.Fatalf("legacy frame %d came after deterministic group began", i)
			}
			decoded, ok := decodePersistentNatLeaseBatchPayload(base)
			if !ok {
				t.Fatalf("legacy frame %d not decodable by type-41 reader", i)
			}
			if decoded.OriginID != batch.OriginID || decoded.Generation != batch.Generation {
				t.Fatalf("legacy frame %d origin/gen = %q/%d, want %q/%d",
					i, decoded.OriginID, decoded.Generation, batch.OriginID, batch.Generation)
			}
			dynamicFrames++
			dynamicLeases += len(decoded.Leases)
		case syncMsgPersistentNatLeaseDeterministic:
			decoded, ok := decodePersistentNatLeaseBatchPayloadDeterministic(base)
			if !ok {
				t.Fatalf("deterministic frame %d not decodable by type-43 reader", i)
			}
			if decoded.OriginID != batch.OriginID || decoded.Generation != batch.Generation {
				t.Fatalf("deterministic frame %d origin/gen = %q/%d, want %q/%d",
					i, decoded.OriginID, decoded.Generation, batch.OriginID, batch.Generation)
			}
			deterministicFrames++
			deterministicLeases += len(decoded.Leases)
		default:
			t.Fatalf("frame %d type = %d, want type 41 or 43", i, frame.msgType)
		}
	}
	if dynamicFrames < 2 || dynamicLeases != 260 {
		t.Fatalf("legacy group frames/leases = %d/%d, want >1 frame and 260 leases",
			dynamicFrames, dynamicLeases)
	}
	if deterministicFrames != 1 || deterministicLeases != 1 {
		t.Fatalf("deterministic group frames/leases = %d/%d, want 1/1",
			deterministicFrames, deterministicLeases)
	}
	if len(frames) != dynamicFrames+deterministicFrames {
		t.Fatalf("total frames = %d, group frames sum to %d+%d",
			len(frames), dynamicFrames, deterministicFrames)
	}
}
