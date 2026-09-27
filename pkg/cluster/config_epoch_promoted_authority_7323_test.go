package cluster

import (
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// #11055 regression: a promoted RG0 authority may retain a
// lastAppliedConfigGen from its prior non-authority tenure. Reverse-direction
// tagged epochs must be judged against the promoted node's own config
// generation, not that retained mark. Untagged frames are role mismatches and
// remain fail-open during the handover.
func TestPromotedAuthorityUsesOwnConfigEpoch11055(t *testing.T) {
	newSync := func() *SessionSync {
		dp := &mockSweepDP{v4sessions: map[dataplane.SessionKey]dataplane.SessionValue{}}
		s := NewSessionSync(":0", "10.0.0.2:4785", dp)
		s.IsPrimaryFn = func() bool { return true }
		setConfigEpochPeerTagCapability11055(s, true)
		s.configGenCounter.Store(100)
		return s
	}

	always := newSync()
	if always.configEpochStale(configEpochReverseTag | 100) {
		t.Fatal("authority falsely rejected a tagged current-generation session against its own send counter")
	}
	if !always.configEpochStale(configEpochReverseTag | 3) {
		t.Fatal("authority must reject a tagged reverse session older than its committed generation")
	}

	promoted := newSync()
	promoted.recordAppliedConfigGen(10)
	if got := promoted.lastAppliedConfigGen.Load(); got != 10 {
		t.Fatalf("setup: retained applied high-water = %d, want 10", got)
	}
	if got := promoted.stampConfigEpoch(); got != 100 {
		t.Fatalf("promoted authority outgoing stamp = %d, want its own untagged send generation 100", got)
	}
	if !promoted.configEpochStale(configEpochReverseTag | 99) {
		t.Fatal("promoted authority must reject reverse epoch 99 against its own generation 100, not retained applied mark 10")
	}
	if promoted.configEpochStale(configEpochReverseTag | 100) {
		t.Fatal("promoted authority falsely rejected a reverse session at its current generation")
	}
	if promoted.configEpochStale(3) {
		t.Fatal("promoted authority falsely rejected an untagged handover frame from a sender that still believes it is authority")
	}

	promoted.resetRecvGen()
	if got := promoted.lastAppliedConfigGen.Load(); got != 0 {
		t.Fatalf("resetRecvGen must clear the applied high-water, got %d", got)
	}
	if !promoted.configEpochStale(configEpochReverseTag | 99) {
		t.Fatal("re-prime reset must not make the authority compare tagged reverse epochs against a zero receive mark")
	}
}
