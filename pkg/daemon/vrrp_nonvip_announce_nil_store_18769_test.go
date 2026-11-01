package daemon

import (
	"path/filepath"
	"testing"
)

// #18769: the legacy-VRRP non-VIP announce path (#17052) read
// d.store.ActiveConfig() without the nil-store guard every other HA path
// has, so a store-less daemon (the reconcile fixtures) panicked inside
// reconcileRGState and aborted the whole pkg/daemon test binary. With no
// store, or a store with no active config yet, there are no targets to
// announce, and the activation must stay UNCLAIMED so a later pass with an
// active config still owns the announce.
func TestNonVIPAnnounceWithoutStoreNeitherPanicsNorClaims18769(t *testing.T) {
	for name, mk := range map[string]func(t *testing.T) *Daemon{
		"nil store": func(*testing.T) *Daemon {
			return &Daemon{rgStates: make(map[int]*rgStateMachine)}
		},
		"store with no active config": func(t *testing.T) *Daemon {
			return &Daemon{
				rgStates: make(map[int]*rgStateMachine),
				store:    newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf")),
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			d := mk(t)
			if d.store != nil && d.store.ActiveConfig() != nil {
				t.Fatal("precondition: the store must have no active config")
			}
			if d.isNoRethVRRP() {
				t.Fatal("precondition: legacy RETH-VRRP mode, or the announce path returns before the claim and this cell proves nothing")
			}
			d.getOrCreateRGState(0).SetVRRP("reth0", true)
			active, generation := d.rgStates[0].CurrentActivation()
			if !active {
				t.Fatal("precondition: RG 0 must be active, or the announce path is never reached")
			}
			// A regression must red THIS cell by name, not abort the whole
			// pkg/daemon binary (that abort is #18769's harm).
			call := func(what string, f func()) {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("%s panicked: %v", what, r)
					}
				}()
				f()
			}
			call("convergeLegacyNonVIPAnnounce", func() { d.convergeLegacyNonVIPAnnounce(0) })
			d.nonVIPAnnounceMu.Lock()
			claimed, ok := d.nonVIPAnnounced[0]
			d.nonVIPAnnounceMu.Unlock()
			if ok {
				t.Errorf("converge claimed activation generation %d for RG 0 with no active config; a later pass would then skip the announce", claimed)
			}
			call("sendVRRPModeNonVIPAnnounce", func() {
				if res := d.sendVRRPModeNonVIPAnnounce(0, generation); res.Sent != 0 || res.FirstErr != nil {
					t.Errorf("send = %+v, want an empty result", res)
				}
			})
		})
	}
}
