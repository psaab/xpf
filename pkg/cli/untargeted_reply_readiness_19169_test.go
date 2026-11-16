package cli

import (
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/clusterfailover"
)

// #19169 (codex-e P2-1): an untargeted failover that finds the group already
// gone from this node replies with its state. That reply reads only the state,
// so it must not run the transfer-readiness callback (routing discovery, then
// FRR under a 2 s timeout) before the operator gets the answer.
func TestCLIUntargetedNoLongerPrimaryReplyRunsNoReadiness19169(t *testing.T) {
	c, mgr := untargetedCLI18559(t, true, nil)
	c.fabricPeerAddrFn = func() []string {
		mgr.SetGroupStateForTesting(1, cluster.StateSecondary)
		mgr.SetPeerGroupStateForTesting(1, cluster.StatePrimary)
		return nil
	}
	var calls atomic.Int32
	mgr.SetTransferReadinessFunc(func(rg int) (bool, []string) {
		calls.Add(1)
		t.Errorf("the failover reply ran the transfer-readiness callback for RG%d:\n%s", rg, debug.Stack())
		return true, nil
	})
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleRequestChassisClusterFailover([]string{"redundancy-group", "1"})
	})
	if callErr != nil {
		t.Fatalf("the group already left this node; want success, got %v", callErr)
	}
	if want := clusterfailover.UntargetedNoLongerPrimaryMessage(1, "secondary", 1); strings.TrimSpace(out) != want {
		t.Fatalf("stdout = %q, want %q", out, want)
	}
	if calls.Load() != 0 {
		t.Fatalf("the reply path ran readiness %d times", calls.Load())
	}
}

// #19169: the CLI prompt prefix reads only RG0's state, on every prompt.
func TestCLIPromptPrefixRunsNoReadiness19169(t *testing.T) {
	c, mgr := untargetedCLI18559(t, true, nil)
	var calls atomic.Int32
	mgr.SetTransferReadinessFunc(func(int) (bool, []string) { calls.Add(1); return true, nil })
	if got := c.clusterPrefix(); got == "" {
		t.Fatal("setup: no cluster prefix rendered, so this cell observed nothing")
	}
	if calls.Load() != 0 {
		t.Fatalf("rendering the prompt prefix ran readiness %d times", calls.Load())
	}
}
