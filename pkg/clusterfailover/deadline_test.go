package clusterfailover_test

import (
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/clusterfailover"
)

// #15081: the forwarded-failover proxy budget must cover the peer's
// RequestPeerFailover sequence: two failoverAckTimeout-bounded
// round-trips (20s each) plus the commit settle. 46s at the defaults.
func TestProxyFailoverTimeoutBudget15081(t *testing.T) {
	if clusterfailover.FailoverAckTimeout != 20*time.Second {
		t.Fatalf("FailoverAckTimeout = %v, want 20s (pkg/cluster failoverAckTimeout)", clusterfailover.FailoverAckTimeout)
	}
	want := 2*clusterfailover.FailoverAckTimeout + 2*clusterfailover.DefaultCommitSettle
	if clusterfailover.ProxyFailoverTimeout != want {
		t.Fatalf("ProxyFailoverTimeout = %v, want %v", clusterfailover.ProxyFailoverTimeout, want)
	}
	if clusterfailover.ProxyFailoverTimeout <= 5*time.Second {
		t.Fatalf("ProxyFailoverTimeout = %v must exceed the old flat 5s proxy deadline", clusterfailover.ProxyFailoverTimeout)
	}
}

func TestIsFailoverActionString15081(t *testing.T) {
	for _, tc := range []struct {
		action string
		want   bool
	}{
		{"cluster-failover:1:node1", true},
		{"cluster-failover:0:node0", true},
		{"cluster-failover-data:node1", true},
		{"cluster-failover-data:node0", true},
		// Never proxied: untargeted, reset, malformed, unrelated.
		{"cluster-failover:1", false},
		{"cluster-failover-reset:1", false},
		{"cluster-failover:1:node", false},
		{"cluster-failover:1:node2", false},
		{"cluster-failover:bogus", false},
		{"clear-persistent-nat", false},
		{"reboot", false},
		{"", false},
	} {
		if got := clusterfailover.IsFailoverActionString(tc.action); got != tc.want {
			t.Errorf("IsFailoverActionString(%q) = %v, want %v", tc.action, got, tc.want)
		}
	}
}
