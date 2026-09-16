package cluster

import (
	"encoding/binary"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// TestQueueSessionWhileDisconnectedStamps9631 pins the load-bearing mechanism
// of the #9631 peer-down fall-through: QueueSessionV4 stamps a fresh #2170
// install generation BEFORE its disconnected send no-op, so a later close of
// the same key draws a fresh #2221 delete generation (never gen-0
// unconditional) and journals for replay. Nothing reaches the wire while down.
func TestQueueSessionWhileDisconnectedStamps9631(t *testing.T) {
	ss := NewSessionSync("127.0.0.1:0", "127.0.0.1:0", nil)
	if ss.IsConnected() {
		t.Fatal("test setup: fresh sync must be disconnected")
	}
	key := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 1, 102}, DstIP: [4]byte{172, 16, 80, 200}, Protocol: 6, SrcPort: 12345, DstPort: 443}
	ss.QueueSessionV4(key, dataplane.SessionValue{})
	ss.genSentMu.Lock()
	stamp := ss.genSentV4[key]
	ss.genSentMu.Unlock()
	if stamp == 0 {
		t.Fatal("QueueSessionV4 while disconnected must stamp a nonzero install generation (the stamp precedes the send no-op)")
	}
	if n := len(ss.sendCh); n != 0 {
		t.Fatalf("sendCh holds %d frames while disconnected, want 0 (silent no-op)", n)
	}
	// Ordinary delete: forwardOnly=false. Purge-retirement closes keep
	// forward-only propagation via the delete sinks (#9752); this pin covers
	// the plain close path.
	ss.QueueDeleteV4(key, false)
	ss.deleteJournalMu.Lock()
	defer ss.deleteJournalMu.Unlock()
	if len(ss.deleteJournal) != 1 {
		t.Fatalf("journal holds %d entries, want 1 (the close journals while down)", len(ss.deleteJournal))
	}
	// encodeDeleteV4 lays the #2170 generation out after the 16-byte 5-tuple;
	// #9752 appends one forwardOnly byte after it, so the gen is no longer
	// the trailing uint64 — parse at the fixed offset.
	raw := ss.deleteJournal[0]
	if len(raw) != syncHeaderSize+25 {
		t.Fatalf("journaled delete len = %d, want %d (header + 16-byte tuple + gen + forwardOnly)", len(raw), syncHeaderSize+25)
	}
	gen := binary.LittleEndian.Uint64(raw[syncHeaderSize+16 : syncHeaderSize+24])
	if gen == 0 {
		t.Fatal("journaled delete drew gen 0 (unconditional): the open's stamp was lost — #9631 fall-through broken")
	}
	if gen <= stamp {
		t.Fatalf("journaled delete gen %d not above install stamp %d (#2221 ordering)", gen, stamp)
	}
	stats := ss.Stats()
	if stats.SessionsSent != 0 || stats.DeletesSent != 0 {
		t.Fatalf("wire counters moved while down: SessionsSent=%d DeletesSent=%d, want 0/0", stats.SessionsSent, stats.DeletesSent)
	}
}
