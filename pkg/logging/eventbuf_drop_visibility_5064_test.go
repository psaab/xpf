package logging

import (
	"sync"
	"testing"
)

// TestEventBufferDropVisibility pins #5064: the EventBuffer fan-out is
// intentionally lossy (a subscriber whose channel is full is skipped rather
// than blocking Add), but the loss must be OBSERVABLE. A dropped security /
// audit record must surface three independent signals so a forensic consumer
// cannot mistake a gapped stream for a complete one:
//
//  1. the per-subscriber Dropped() counter and the aggregate DroppedTotal()
//     both increment by exactly the number of shed records;
//  2. every delivered record carries the buffer's monotonic BufSeq, so a
//     gap in the delivered sequence pinpoints which records were lost;
//  3. the first record delivered after a drop carries Overrun=true.
//
// RED on revert: restore the old `default: // drop if subscriber is slow`
// no-op branch (no counters, no overrun) and drop the BufSeq stamp, and every
// assertion below fails — Dropped()/DroppedTotal() stay 0, the delivered
// records have BufSeq==0 with no detectable gap, and Overrun is never set.
func TestEventBufferDropVisibility(t *testing.T) {
	eb := NewEventBuffer(64)

	// bufSize 2, and we deliberately do NOT drain until after the Adds, so
	// records 3..5 hit a full channel and are dropped.
	sub := eb.Subscribe(2)
	defer sub.Close()

	const total = 5
	for i := 0; i < total; i++ {
		eb.Add(EventRecord{Type: "POLICY_DENY"})
	}

	// Exactly (total - bufSize) records were shed for this subscriber.
	const wantDropped = total - 2
	if got := sub.Dropped(); got != wantDropped {
		t.Fatalf("sub.Dropped() = %d, want %d", got, wantDropped)
	}
	if got := eb.DroppedTotal(); got != wantDropped {
		t.Fatalf("eb.DroppedTotal() = %d, want %d", got, wantDropped)
	}

	// Drain the two buffered records. They are the FIRST two published
	// (BufSeq 1 and 2), strictly increasing, and NOT overrun-flagged (no drop
	// preceded them).
	var tracker EventGapTracker
	var gapLines []string
	r1 := <-sub.C
	r2 := <-sub.C
	for _, rec := range []EventRecord{r1, r2} {
		if lost, gap := tracker.Observe(sub, rec); gap {
			gapLines = append(gapLines, OverrunLine(lost))
		}
	}
	if r1.BufSeq != 1 || r2.BufSeq != 2 {
		t.Fatalf("delivered BufSeq = %d,%d want 1,2 (buffer publish sequence not attached)", r1.BufSeq, r2.BufSeq)
	}
	if r1.Overrun || r2.Overrun {
		t.Fatalf("records delivered before any drop must not be Overrun (got %v,%v)", r1.Overrun, r2.Overrun)
	}

	// Recovery: the channel now has room, so the next Add is delivered. It
	// must (a) carry Overrun=true because records were shed since the last
	// successful delivery, and (b) expose the gap via BufSeq — it is the 6th
	// published record, so BufSeq==6 while the last delivered was 2. The
	// missing 3,4,5 are exactly the wantDropped shed records.
	eb.Add(EventRecord{Type: "POLICY_DENY"})
	r6 := <-sub.C
	if r6.BufSeq != total+1 {
		t.Fatalf("recovery record BufSeq = %d, want %d", r6.BufSeq, total+1)
	}
	if !r6.Overrun {
		t.Fatalf("first record after a drop must carry Overrun=true (in-band loss signal)")
	}
	if lost, gap := tracker.Observe(sub, r6); gap {
		gapLines = append(gapLines, OverrunLine(lost))
	}
	if gap := r6.BufSeq - r2.BufSeq - 1; gap != wantDropped {
		t.Fatalf("BufSeq gap = %d, want %d shed records between the two deliveries", gap, wantDropped)
	}

	// Overrun is one-shot: after the flagged record is delivered, a further
	// in-window delivery (no new drops) is clean.
	eb.Add(EventRecord{Type: "POLICY_DENY"})
	r7 := <-sub.C
	if r7.Overrun {
		t.Fatalf("Overrun must clear after the flagged record is delivered")
	}
	if r7.BufSeq != total+2 {
		t.Fatalf("post-recovery record BufSeq = %d, want %d", r7.BufSeq, total+2)
	}
	if lost, gap := tracker.Observe(sub, r7); gap {
		gapLines = append(gapLines, OverrunLine(lost))
	}
	if len(gapLines) != 1 || gapLines[0] != OverrunLine(wantDropped) {
		t.Fatalf("operator gap lines = %v, want exactly %q", gapLines, OverrunLine(wantDropped))
	}
	if got, want := uint64(4)+sub.Dropped(), uint64(total+2); got != want {
		t.Fatalf("published accounting: received + dropped = %d, want %d", got, want)
	}

	// Counters are monotonic: no further drops occurred during recovery.
	if got := sub.Dropped(); got != wantDropped {
		t.Fatalf("sub.Dropped() after recovery = %d, want %d (no new drops)", got, wantDropped)
	}
}

// TestEventBufferDropCountersRaceFree asserts the drop counters are safe under
// concurrent Add fan-out (run with -race). Multiple producers slam a
// never-drained subscriber; the aggregate must equal the per-subscriber count
// and both must be strictly positive, with no data race on the atomics.
func TestEventBufferDropCountersRaceFree(t *testing.T) {
	eb := NewEventBuffer(64)
	sub := eb.Subscribe(1) // tiny channel, never drained -> most Adds drop
	defer sub.Close()

	const producers = 8
	const perProducer = 200
	var wg sync.WaitGroup
	for p := 0; p < producers; p++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perProducer; i++ {
				eb.Add(EventRecord{Type: "SESSION_CLOSE"})
			}
		}()
	}
	wg.Wait()

	if eb.DroppedTotal() != sub.Dropped() {
		t.Fatalf("aggregate DroppedTotal()=%d != single-subscriber Dropped()=%d", eb.DroppedTotal(), sub.Dropped())
	}
	// With one subscriber and a 1-deep channel that is never drained, all but
	// at most the one buffered record are dropped.
	if got, min := sub.Dropped(), uint64(producers*perProducer-1); got < min {
		t.Fatalf("sub.Dropped()=%d, want >= %d", got, min)
	}
}
