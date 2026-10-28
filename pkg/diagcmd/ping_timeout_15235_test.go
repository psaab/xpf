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

// TestPingExecTimeoutTable17203 pins the request-sized ping budget
// table (#1819) against the sole implementation (#17203). Counts above
// the 100 clamp cannot reach the handlers today, but PingExecTimeout
// clamps internally and the ceiling must hold anyway. A mutant of
// PingExecSlack / PingFloor / DiagExecCeiling reds this table and —
// because both servers now call this function — the servers' budget
// with it.
func TestPingExecTimeoutTable17203(t *testing.T) {
	cases := []struct {
		count int
		want  time.Duration
	}{
		{1, 30 * time.Second},    // 16s formula, floored at the old bound
		{5, 30 * time.Second},    // default count, floored
		{15, 30 * time.Second},   // 30s formula == floor
		{16, 31 * time.Second},   // first count past the floor
		{60, 75 * time.Second},   // the count>~30 case the 30s bound killed
		{100, 115 * time.Second}, // clamp maximum
		{135, 115 * time.Second}, // count clamped to 100 first
		{200, 115 * time.Second}, // ceiling via clamp, not formula
		{1 << 30, 115 * time.Second},
	}
	for _, c := range cases {
		if got := PingExecTimeout(c.count); got != c.want {
			t.Errorf("PingExecTimeout(%d) = %v, want %v", c.count, got, c.want)
		}
	}
	if TracerouteTimeout != 60*time.Second {
		t.Fatalf("TracerouteTimeout = %v, want 60s (pre-#1819 HTTP bound)", TracerouteTimeout)
	}
	if TracerouteTimeout > DiagExecCeiling {
		t.Fatalf("TracerouteTimeout = %v exceeds DiagExecCeiling %v", TracerouteTimeout, DiagExecCeiling)
	}
	for _, c := range []struct{ in, want time.Duration }{
		{time.Second, time.Second},
		{DiagExecCeiling - 1, DiagExecCeiling - 1},
		{DiagExecCeiling, DiagExecCeiling},
		{DiagExecCeiling + 1, DiagExecCeiling},
		{24 * time.Hour, DiagExecCeiling},
	} {
		if got := ClampDiagTimeout(c.in); got != c.want {
			t.Errorf("ClampDiagTimeout(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}
