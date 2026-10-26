package nfqueue

import (
	"bytes"
	"runtime"
	"testing"
	"time"
)

// TestEOFCompletionFixturesJoinServerGoroutines invokes each EOF fixture as
// a regression check: the fixture's server goroutine must be gone when the
// assertion returns, not merely left behind until the test process exits.
func TestEOFCompletionFixturesJoinServerGoroutines(t *testing.T) {
	fixtures := []struct {
		name   string
		marker string
		run    func(*testing.T)
	}{
		{
			name:   "partial-frame-timeout",
			marker: "TestDrainReinjectCompletionsPartialFrameTimeoutIsError",
			run:    TestDrainReinjectCompletionsPartialFrameTimeoutIsError,
		},
		{
			name:   "bad-length",
			marker: "TestDrainReinjectCompletionsBadLengthClosesConn16863",
			run:    TestDrainReinjectCompletionsBadLengthClosesConn16863,
		},
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			fixture.run(t)
			marker := []byte(fixture.marker)
			stacks := make([]byte, 1<<20)
			deadline := time.Now().Add(time.Second)
			for {
				n := runtime.Stack(stacks, true)
				if !bytes.Contains(stacks[:n], marker) {
					return
				}
				if time.Now().After(deadline) {
					t.Fatalf("EOF fixture left a goroutine blocked after cleanup:\n%s", stacks[:n])
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	}
}
