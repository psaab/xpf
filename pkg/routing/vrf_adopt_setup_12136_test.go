package routing

import (
	"net"
	"strings"
	"testing"
)

// TestReconcileVRFs_AdoptLinkSetUpFailureIsHard_12136: an adopted
// (already-present, correct-table) VRF whose LinkSetUp fails must fail
// the reconcile — mirroring the create path (createLinkedVRF returns
// "set VRF %s up") — instead of logging at Debug and returning nil
// while the down VRF sits tracked (and IsManaged-gated consumers treat
// it as ready after a green commit).
//
// FAIL-ON-REVERT: pre-#12136 the adopt branch swallowed the LinkSetUp
// error — RED at the "want non-nil" assertion.
func TestReconcileVRFs_AdoptLinkSetUpFailureIsHard_12136(t *testing.T) {
	ops := newInjectable()
	// Present in kernel with the desired table: the adopt branch.
	ops.seed("vrf-a", 100)
	if ops.links["vrf-a"].Flags&net.FlagUp != 0 {
		t.Fatal("test precondition failed: seeded VRF should be down")
	}
	ops.failSetUpFor = "vrf-a"
	manager := &vrfManager{ops: ops}

	err := manager.Reconcile([]VRFSpec{{Name: "a", TableID: 100}})
	if err == nil {
		t.Fatal("Reconcile() = nil error, want non-nil after an injected LinkSetUp failure on an adopted VRF")
	}
	if !strings.Contains(err.Error(), "set VRF vrf-a up: injected LinkSetUp failure") {
		t.Errorf("error %q does not preserve the VRF bring-up failure context", err)
	}
	// Ownership is retained so a future reconcile can retry (the
	// partial-failure contract); only the swallowed error is fixed.
	if !manager.IsManaged("a") {
		t.Error("adopted VRF must remain tracked after LinkSetUp failure")
	}
	if ops.dels != 0 || ops.adds != 0 {
		t.Errorf("adopt path must not delete+recreate: adds=%d dels=%d", ops.adds, ops.dels)
	}
}

// TestReconcileVRFs_AdoptLinkSetUpRecoversNextCycle_12136: the retained
// ownership from the failed adopt converges on the next healthy
// reconcile (self-heals on retry; the failure is not sticky).
func TestReconcileVRFs_AdoptLinkSetUpRecoversNextCycle_12136(t *testing.T) {
	ops := newInjectable()
	ops.seed("vrf-a", 100)
	ops.failSetUpFor = "vrf-a"
	manager := &vrfManager{ops: ops}

	if err := manager.Reconcile([]VRFSpec{{Name: "a", TableID: 100}}); err == nil {
		t.Fatal("first Reconcile() = nil error, want non-nil (precondition for the retry check)")
	}

	// The transient failure clears; the next apply retries the LinkSetUp.
	ops.failSetUpFor = ""
	if err := manager.Reconcile([]VRFSpec{{Name: "a", TableID: 100}}); err != nil {
		t.Fatalf("second Reconcile() = %v, want nil after the LinkSetUp failure clears", err)
	}
	if !manager.IsManaged("a") {
		t.Error("VRF must remain managed after recovery")
	}
	if ops.setUps != 2 {
		t.Errorf("LinkSetUp attempts = %d after failed and healthy reconciles, want 2", ops.setUps)
	}
	if ops.adds != 0 || ops.dels != 0 {
		t.Errorf("recovery must re-up in place: adds=%d dels=%d", ops.adds, ops.dels)
	}
}
