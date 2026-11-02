package fabricsegment

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestRetiredTrackerIgnoresLateObserve18719(t *testing.T) {
	var mu sync.Mutex
	var edges []bool
	tr := NewTracker(testLink(t), func(_ Link, raised bool, _ string) {
		mu.Lock()
		edges = append(edges, raised)
		mu.Unlock()
	})
	src, err := net.ParseMAC("18:e8:29:2c:13:7a")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tr.Observe(src, now)
	tr.Retire("fabric link removed")
	tr.Observe(src, now.Add(time.Second))

	mu.Lock()
	got := append([]bool(nil), edges...)
	mu.Unlock()
	if len(got) != 2 || !got[0] || got[1] {
		t.Fatalf("transitions after retire = %v, want exactly [raise clear]", got)
	}
	if alarm := tr.Alarm(now.Add(time.Second)); alarm != "" {
		t.Fatalf("retired tracker re-raised alarm: %s", alarm)
	}
}

func TestRetireRacingObserveDoesNotLeaveTrackerRaised18719(t *testing.T) {
	src, err := net.ParseMAC("18:e8:29:2c:13:7a")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var edges []bool
	raiseEntered := make(chan struct{})
	releaseRaise := make(chan struct{})
	clearEmitted := make(chan struct{})
	tr := NewTracker(testLink(t), func(_ Link, raised bool, _ string) {
		if raised {
			close(raiseEntered)
			<-releaseRaise
		}
		mu.Lock()
		edges = append(edges, raised)
		mu.Unlock()
		if !raised {
			close(clearEmitted)
		}
	})

	go tr.Observe(src, time.Now())
	<-raiseEntered
	retired := make(chan struct{})
	retireStarted := make(chan struct{})
	go func() {
		close(retireStarted)
		tr.Retire("fabric link removed")
		close(retired)
	}()
	<-retireStarted

	// The raise callback is deliberately delayed after the state transition.
	// Retire must not publish its clear until that raise callback is emitted.
	clearBeforeRaise := false
	select {
	case <-clearEmitted:
		clearBeforeRaise = true
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseRaise)
	<-retired

	mu.Lock()
	got := append([]bool(nil), edges...)
	mu.Unlock()
	if clearBeforeRaise || len(got) != 2 || !got[0] || got[1] {
		t.Fatalf("concurrent callbacks = %v (clear before raise callback: %v), want [raise clear]", got, clearBeforeRaise)
	}
	if alarm := tr.Alarm(time.Now()); alarm != "" {
		t.Fatalf("concurrent retire left tracker raised: %s", alarm)
	}
}
