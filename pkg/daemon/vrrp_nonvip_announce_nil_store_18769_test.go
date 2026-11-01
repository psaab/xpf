package daemon

import "testing"

// #18769: the legacy-VRRP non-VIP announce path (#17052) read
// d.store.ActiveConfig() without the nil-store guard every other HA path
// has, so a store-less daemon (the reconcile fixtures) panicked inside
// reconcileRGState and aborted the whole pkg/daemon test binary. With no
// store there are no targets to announce, and the activation must stay
// UNCLAIMED so a later pass with a store still owns the announce.
func TestNonVIPAnnounceWithoutStoreNeitherPanicsNorClaims18769(t *testing.T) {
	d := &Daemon{rgStates: make(map[int]*rgStateMachine)}
	d.getOrCreateRGState(0).SetVRRP("reth0", true)
	active, generation := d.rgStates[0].CurrentActivation()
	if !active {
		t.Fatal("precondition: RG 0 must be active, or the announce path is never reached and this cell proves nothing")
	}

	d.convergeLegacyNonVIPAnnounce(0) // panicked before #18769

	d.nonVIPAnnounceMu.Lock()
	claimed, ok := d.nonVIPAnnounced[0]
	d.nonVIPAnnounceMu.Unlock()
	if ok {
		t.Errorf("store-less converge claimed activation generation %d for RG 0; a later pass with a store would then skip the announce", claimed)
	}
	if res := d.sendVRRPModeNonVIPAnnounce(0, generation); res.Sent != 0 || res.FirstErr != nil {
		t.Errorf("store-less send = %+v, want an empty result", res)
	}
}
