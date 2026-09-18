package upgrade

import (
	"fmt"
	"testing"
	"time"
)

func TestSystemActionContextAllowsUserspaceDemotionBarrier10261(t *testing.T) {
	g := &grpcCluster{dialTimeout: 5 * time.Second}

	ctx, cancel := g.actionCtx("in-service-upgrade", 1)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("in-service-upgrade action must have a bounded deadline")
	}
	remaining := time.Until(deadline)
	want := rollingForceSecondaryActionTimeoutForRGs(1)
	if remaining < want-time.Second || remaining > want {
		t.Fatalf("in-service-upgrade RPC deadline has %v remaining, want approximately %v", remaining, want)
	}

	ctx, cancel = g.actionCtx("reset-failover", 0)
	defer cancel()
	deadline, ok = ctx.Deadline()
	if !ok {
		t.Fatal("ordinary system action must have a bounded deadline")
	}
	remaining = time.Until(deadline)
	if remaining < 4*time.Second || remaining > 5*time.Second {
		t.Fatalf("ordinary system action deadline has %v remaining, want approximately 5s", remaining)
	}
}

func TestSystemActionContextCoversSequentialMultiRGBarriers10261(t *testing.T) {
	const activeRGs = 2
	g := &grpcCluster{dialTimeout: 5 * time.Second}
	ctx, cancel := g.actionCtx("in-service-upgrade", activeRGs)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("in-service-upgrade action must have a bounded deadline")
	}
	remaining := time.Until(deadline)
	want := rollingForceSecondaryActionTimeoutForRGs(activeRGs)
	minimum := time.Duration(activeRGs) *
		(rollingForceSecondaryBarrierTimeout + rollingForceSecondaryRetrySlack)
	minimum += rollingForceSecondaryHandoffTimeout
	if want < minimum {
		t.Fatalf("multi-RG deadline %v covers less than sequential barriers, retry slack, and handoff %v", want, minimum)
	}
	if remaining < want-time.Second || remaining > want {
		t.Fatalf("two-RG in-service-upgrade RPC deadline has %v remaining, want approximately %v", remaining, want)
	}
}

func TestParseSessionSyncBulkPrimedFailsClosed10261(t *testing.T) {
	const base = `Remote node: healthy (node1)
Fabric link statistics:
  Status: Up
  Bulk sync primed: %s

Cold synchronization:
`
	for _, tc := range []struct {
		name string
		line string
		want bool
	}{
		{name: "primed", line: "yes", want: true},
		{name: "pending", line: "no", want: false},
		{name: "malformed", line: "yes (timeout released)", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseSessionSyncBulkPrimed(fmt.Sprintf(base, tc.line)); got != tc.want {
				t.Fatalf("parseSessionSyncBulkPrimed(%q) = %v, want %v", tc.line, got, tc.want)
			}
		})
	}
	if parseSessionSyncBulkPrimed("Remote node: healthy (node1)\nBulk sync primed: yes\n") {
		t.Fatal("an unscoped bulk-prime line must not satisfy the rejoin gate")
	}
}
