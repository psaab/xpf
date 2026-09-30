package logging

import "testing"

// #11072: ring overwrite must be observable — eviction counter, oldest-live
// seq, and an in-band Overrun mark on the oldest Latest record — so a
// forensic reader cannot mistake truncation for complete history.
func TestRingEvictionObservable11072(t *testing.T) {
	eb := NewEventBuffer(3)
	for i := 0; i < 5; i++ {
		eb.Add(EventRecord{Type: "T"})
	}
	if got := eb.EvictedTotal(); got != 2 {
		t.Fatalf("EvictedTotal() = %d, want 2", got)
	}
	if got := eb.OldestLiveSeq(); got != 3 {
		t.Fatalf("OldestLiveSeq() = %d, want 3 (seqs 1-2 evicted)", got)
	}
	got := eb.Latest(3)
	if len(got) != 3 {
		t.Fatalf("Latest(3) returned %d records", len(got))
	}
	if !got[2].Overrun {
		t.Errorf("oldest Latest record must carry Overrun once the ring overwrote")
	}
	if got[0].Overrun || got[1].Overrun {
		t.Errorf("only the oldest record may carry the eviction mark: %+v", got)
	}
	// No-overwrite control: fresh ring reads clean.
	eb2 := NewEventBuffer(10)
	eb2.Add(EventRecord{Type: "T"})
	if eb2.EvictedTotal() != 0 {
		t.Fatalf("fresh ring EvictedTotal = %d", eb2.EvictedTotal())
	}
	if r := eb2.Latest(1); len(r) != 1 || r[0].Overrun {
		t.Fatalf("fresh ring must read unmarked: %+v", r)
	}
}
