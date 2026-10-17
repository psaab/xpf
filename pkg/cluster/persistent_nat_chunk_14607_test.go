package cluster

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #14607: an unchunked persistent-NAT idle-lease batch over the 16 MiB
// receive cap tears down HA session sync on every 30 s push. The sender
// must split the batch into sub-cap frames of the same generation, the
// peer must receive every lease, and the connection must stay up.

func chunkLease14607(i int, remotes int) userspace.IdleLeaseWire {
	l := userspace.IdleLeaseWire{
		Pool:           "pool-a",
		Protocol:       6,
		SrcIP:          fmt.Sprintf("10.0.%d.%d", (i>>8)&0xff, i&0xff),
		SrcPort:        uint16(1024 + i%60000),
		RoutingScope:   persistentNatLeaseScope(0),
		EgressScope:    persistentNatLeaseScope(0),
		RemoteIP:       "198.51.100.1",
		RemotePort:     443,
		TranslatedIP:   "203.0.113.1",
		TranslatedPort: uint16(2048 + i%60000),
		RemainingNs:    270_000_000_000,
		TimeoutNs:      300_000_000_000,
	}
	for r := 0; r < remotes; r++ {
		l.PermittedRemotes = append(l.PermittedRemotes, userspace.PersistentNatRemote{
			IP:   fmt.Sprintf("2001:db8::%x", r+1),
			Port: uint16(r),
		})
	}
	return l
}

func chunkBatch14607(n, remotes int) userspace.PersistentNatLeaseBatch {
	leases := make([]userspace.IdleLeaseWire, 0, n)
	for i := range n {
		leases = append(leases, chunkLease14607(i, remotes))
	}
	return userspace.PersistentNatLeaseBatch{
		OriginID:   "0123456789abcdef0123456789abcdef",
		Generation: 7,
		Leases:     leases,
	}
}

// TestPersistentNatLeaseChunkedFrames14607 drives QueuePersistentNatLeaseBatch
// over a capture conn for populations that exceed one frame: every emitted
// frame must be <= maxSyncPayload, there must be >1 frame, and feeding all
// frames in order through a receiver must deliver every lease exactly once
// under the same origin/generation.
func TestPersistentNatLeaseChunkedFrames14607(t *testing.T) {
	for _, tc := range []struct {
		name    string
		n       int
		remotes int
	}{
		{"262144_remote_less", 262144, 0},
		{"1300x1024_remotes", 1300, 1024},
		{"300k_remote_less", 300000, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			batch := chunkBatch14607(tc.n, tc.remotes)

			sender := NewSessionSync(":0", "10.0.0.2:4785", nil)
			cc := &captureConn{}
			sender.mu.Lock()
			sender.conn0 = cc
			sender.mu.Unlock()
			sender.QueuePersistentNatLeaseBatch(batch)

			frames := cc.frames()
			if len(frames) <= 1 {
				t.Fatalf("frames = %d, want >1 chunked frames for %d leases", len(frames), tc.n)
			}
			for i, f := range frames {
				if f.msgType != syncMsgPersistentNatLeaseGeneration {
					t.Fatalf("frame %d type = %d, want %d", i, f.msgType, syncMsgPersistentNatLeaseGeneration)
				}
				if len(f.payload) > maxSyncPayload {
					t.Fatalf("frame %d payload = %d bytes, exceeds maxSyncPayload %d", i, len(f.payload), maxSyncPayload)
				}
			}

			receiver := NewSessionSync(":0", "10.0.0.1:4785", nil)
			var got []userspace.IdleLeaseWire
			var origins []string
			var gens []uint64
			receiver.OnPersistentNatLeasesReceived = func(b userspace.PersistentNatLeaseBatch) {
				got = append(got, b.Leases...)
				origins = append(origins, b.OriginID)
				gens = append(gens, b.Generation)
			}
			for _, f := range frames {
				receiver.handleMessage(nil, f.msgType, f.payload)
			}
			if len(got) != tc.n {
				t.Fatalf("receiver got %d leases, want %d (all chunks delivered)", len(got), tc.n)
			}
			for i, o := range origins {
				if o != batch.OriginID || gens[i] != batch.Generation {
					t.Fatalf("callback %d origin/gen = %q/%d, want %q/%d", i, o, gens[i], batch.OriginID, batch.Generation)
				}
			}
			// Spot-check first and last lease identity survived.
			if got[0].SrcIP != batch.Leases[0].SrcIP || got[len(got)-1].SrcIP != batch.Leases[len(batch.Leases)-1].SrcIP {
				t.Fatalf("lease identity drift: first %q last %q", got[0].SrcIP, got[len(got)-1].SrcIP)
			}
			if tc.remotes > 0 && len(got[0].PermittedRemotes) != tc.remotes {
				t.Fatalf("first lease remotes = %d, want %d", len(got[0].PermittedRemotes), tc.remotes)
			}
		})
	}
}

// TestPersistentNatLeaseSingleRecordExceedsCap14607: a single lease whose
// encoded record alone exceeds the frame budget must be refused (counted),
// never written as an over-cap frame.
func TestPersistentNatLeaseSingleRecordExceedsCap14607(t *testing.T) {
	// A lease with 1024 IPv6 remotes is ~19 KiB — well under cap. To exceed
	// the budget with one record we use an oversized pool string that the
	// record encoder rejects; the sender must emit zero frames and count it.
	batch := chunkBatch14607(1, 0)
	batch.Leases[0].Pool = strings.Repeat("p", 70000)
	sender := NewSessionSync(":0", "10.0.0.2:4785", nil)
	cc := &captureConn{}
	sender.mu.Lock()
	sender.conn0 = cc
	sender.mu.Unlock()
	before := sender.stats.MalformedRecordsDropped.Load()
	sender.QueuePersistentNatLeaseBatch(batch)
	if frames := cc.frames(); len(frames) != 0 {
		// An empty-set frame carrying only the generation barrier is also
		// acceptable (count 0); an over-cap frame is not.
		for i, f := range frames {
			if len(f.payload) > maxSyncPayload {
				t.Fatalf("frame %d payload %d exceeds cap", i, len(f.payload))
			}
			b, ok := decodePersistentNatLeaseBatchPayload(stripPayload14607(f.payload))
			if !ok || len(b.Leases) != 0 {
				t.Fatalf("frame %d should carry zero leases, got ok=%v n=%d", i, ok, len(b.Leases))
			}
		}
	}
	if sender.stats.MalformedRecordsDropped.Load() <= before {
		t.Fatal("unencodable oversize lease was not counted")
	}
}

func stripPayload14607(payload []byte) []byte {
	base, _, _ := stripFullSetSeq(payload)
	return base
}

// TestPersistentNatLeaseChunkEncoderBound14607: the chunk encoder itself
// must never produce a frame above the cap, regardless of input size.
func TestPersistentNatLeaseChunkEncoderBound14607(t *testing.T) {
	batch := chunkBatch14607(5000, 10)
	frames, err := encodePersistentNatLeaseBatchFrames(batch)
	if err != nil {
		t.Fatalf("encode frames: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("no frames encoded")
	}
	total := 0
	for i, f := range frames {
		if len(f) > maxSyncPayload {
			t.Fatalf("frame %d = %d > maxSyncPayload %d", i, len(f), maxSyncPayload)
		}
		b, ok := decodePersistentNatLeaseBatchPayload(f)
		if !ok {
			t.Fatalf("frame %d does not decode", i)
		}
		if b.OriginID != batch.OriginID || b.Generation != batch.Generation {
			t.Fatalf("frame %d origin/gen drift", i)
		}
		total += len(b.Leases)
	}
	if total != len(batch.Leases) {
		t.Fatalf("decoded %d leases across frames, want %d", total, len(batch.Leases))
	}
	// Empty batch still yields exactly one barrier frame.
	empty, err := encodePersistentNatLeaseBatchFrames(chunkBatch14607(0, 0))
	if err != nil || len(empty) != 1 {
		t.Fatalf("empty batch frames = %d err=%v, want 1", len(empty), err)
	}
}
