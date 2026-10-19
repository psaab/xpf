package upgrade

import "testing"

// #15181: a promoted roll must clear the kernel-roll lease (the PROMOTE
// path previously left it; only REVERT/discard cleared it), so the lease
// cannot later be misread as a crashed-roll fingerprint.

func TestKernelPromoteClearsRollLease15181(t *testing.T) {
	f := newFakeKernelSystem()
	r := newKernelRunner(t, f)
	if err := r.Arm("6.18.5-12-generic"); err != nil {
		t.Fatalf("Arm: %v", err)
	}
	f.running = "6.18.5-12-generic"
	f.bootCurrent = "0004"
	f.verifyPass = true
	f.beaconPass = true
	outcome, err := r.Promote()
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if outcome.Outcome != RollOutcomePromoted {
		t.Fatalf("outcome = %q, want promoted", outcome.Outcome)
	}
	if f.clearRollLease != 1 {
		t.Fatalf("#15181: ClearRollLease calls = %d, want 1 on promote", f.clearRollLease)
	}
}
