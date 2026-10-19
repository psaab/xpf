package diagcmd

import (
	"testing"
	"time"
)

// TestPingClientTimeoutCoversServerBudget15235 is the A51-02 regression:
// the remote-CLI deadline must cover the server budget for count 100.
func TestPingClientTimeoutCoversServerBudget15235(t *testing.T) {
	if got := PingExecTimeout(100); got != 115*time.Second {
		t.Fatalf("PingExecTimeout(100) = %v, want 115s", got)
	}
	if got := PingClientTimeout(100); got < 115*time.Second {
		t.Fatalf("PingClientTimeout(100) = %v, want >= server budget 115s (pre-fix cli used 60s)", got)
	}
	if got := PingClientTimeout(100); got != 130*time.Second {
		t.Fatalf("PingClientTimeout(100) = %v, want 130s", got)
	}
	if got := PingClientTimeout(5); got != 45*time.Second {
		t.Fatalf("PingClientTimeout(5) = %v, want 45s (30s floor + slack)", got)
	}
	if got := PingClientTimeout(1); got != 45*time.Second {
		t.Fatalf("PingClientTimeout(1) = %v, want 45s", got)
	}
}
