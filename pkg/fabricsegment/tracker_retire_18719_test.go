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
	for i := range 64 {
		tr := NewTracker(testLink(t), nil)
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			tr.Observe(src, time.Now())
		}()
		go func() {
			defer wg.Done()
			<-start
			tr.Retire("fabric link removed")
		}()
		close(start)
		wg.Wait()
		tr.Observe(src, time.Now())
		if alarm := tr.Alarm(time.Now()); alarm != "" {
			t.Fatalf("iteration %d: concurrent retire left a late observation active: %s", i, alarm)
		}
	}
}
