package daemon

import (
	"errors"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

type fallbackDemotionFixture18426 struct {
	d          *Daemon
	cm         *cluster.Manager
	ss         *cluster.SessionSync
	live       []string
	activeErr  error
	initiated  []string
	terminated []string
}

func newFallbackDemotionFixture18426(t *testing.T) *fallbackDemotionFixture18426 {
	t.Helper()
	store := testStoreWithSetConfig(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster node 0",
		"set chassis cluster authentication-key test-cluster-psk-18426",
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces reth1 redundant-ether-options redundancy-group 1",
		"set interfaces reth1 unit 0 family inet address 10.0.1.1/24",
		"set interfaces ge-0/0/0 gigether-options redundant-parent reth1",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.3.1/24",
		"set security ike gateway gw-plain address 198.51.100.3",
		"set security ike gateway gw-plain external-interface ge-0/0/3.0",
		"set security ike gateway gw-trap address 198.51.100.4",
		"set security ike gateway gw-trap external-interface ge-0/0/3.0",
		"set security ipsec vpn vpn-plain ike gateway gw-plain",
		"set security ipsec vpn vpn-plain pre-shared-key fixture-secret",
		"set security ipsec vpn vpn-plain bind-interface st0",
		"set security ipsec vpn vpn-trap ike gateway gw-trap",
		"set security ipsec vpn vpn-trap pre-shared-key fixture-secret",
		"set security ipsec vpn vpn-trap bind-interface st1",
	})
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(store.ActiveConfig().Chassis.Cluster)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	if _, known := cm.LocalGroupPrimary(0); known {
		t.Fatal("FIXTURE: RG0 must be undeclared for the sole-data-RG fallback")
	}
	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-plain"})
	f := &fallbackDemotionFixture18426{cm: cm, ss: ss}
	f.d = &Daemon{
		cluster:     cm,
		store:       store,
		sessionSync: ss,
		ipsecActiveNamesFn: func() ([]string, error) {
			if f.activeErr != nil {
				return nil, f.activeErr
			}
			return append([]string(nil), f.live...), nil
		},
		ipsecTerminateFn: func(name string) error {
			f.terminated = append(f.terminated, name)
			return nil
		},
		ipsecInitiateFn: func(name string) error {
			f.initiated = append(f.initiated, name)
			f.live = append(f.live, name)
			return nil
		},
	}
	return f
}

func (f *fallbackDemotionFixture18426) initiateFallback(t *testing.T) {
	t.Helper()
	f.d.bumpIPsecRGOwnershipEpoch(1)
	f.d.reinitiateIPsecSAsForRG(1)
	if len(f.initiated) != 1 || f.initiated[0] != "vpn-plain" {
		t.Fatalf("fallback initiation = %v, want [vpn-plain]", f.initiated)
	}
}

func TestFallbackInitiatedUnanchoredSAIsTerminatedOnSoleRGDemotion18426(t *testing.T) {
	f := newFallbackDemotionFixture18426(t)
	f.initiateFallback(t)

	// Retry bookkeeping may prune a successful name absent from the peer's
	// latest set; its fallback provenance must still reach the demotion sweep.
	f.ss.SetPeerIPsecSAsForTesting(nil)
	f.d.retryOwedIPsecFallback()
	f.live = append(f.live, "vpn-trap") // live, unanchored, but not fallback-initiated

	f.cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	demotionEpoch := f.d.bumpIPsecRGOwnershipEpoch(1)
	f.d.terminateDemotedRGIPsecSAs(1, demotionEpoch)
	if len(f.terminated) != 1 || f.terminated[0] != "vpn-plain" {
		t.Fatalf("sole-RG demotion terminated %v, want only fallback-initiated [vpn-plain] (not trap-initiated vpn-trap)", f.terminated)
	}

	// A later trap-established SA with the same connection name has no
	// fallback provenance after the successful cleanup above.
	f.cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	f.d.bumpIPsecRGOwnershipEpoch(1)
	f.live = []string{"vpn-plain", "vpn-trap"}
	f.cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	demotionEpoch = f.d.bumpIPsecRGOwnershipEpoch(1)
	f.d.terminateDemotedRGIPsecSAs(1, demotionEpoch)
	if len(f.terminated) != 1 || f.terminated[0] != "vpn-plain" {
		t.Fatalf("later sole-RG demotion swept non-fallback names: %v", f.terminated)
	}
}

func TestFallbackProvenanceExpiresAfterObservedSADisappearance18426(t *testing.T) {
	f := newFallbackDemotionFixture18426(t)
	f.initiateFallback(t)

	if _, err := f.d.ipsecActiveNames(); err != nil {
		t.Fatalf("observe fallback SA live: %v", err)
	}
	f.live = nil
	if _, err := f.d.ipsecActiveNames(); err != nil {
		t.Fatalf("observe fallback SA disappearance: %v", err)
	}
	// A trap-established SA later reuses the same name; it must not inherit
	// the earlier fallback initiation's provenance.
	f.live = []string{"vpn-plain"}
	f.cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	demotionEpoch := f.d.bumpIPsecRGOwnershipEpoch(1)
	f.d.terminateDemotedRGIPsecSAs(1, demotionEpoch)
	if len(f.terminated) != 0 {
		t.Fatalf("demotion swept same-name SA after observed fallback loss: %v", f.terminated)
	}
}

func TestFallbackProvenanceDoesNotCrossSoleRGTenure18426(t *testing.T) {
	f := newFallbackDemotionFixture18426(t)
	f.initiateFallback(t)
	if _, err := f.d.ipsecActiveNames(); err != nil {
		t.Fatalf("observe fallback SA live: %v", err)
	}

	f.activeErr = errors.New("charon down")
	f.cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	firstDemotionEpoch := f.d.bumpIPsecRGOwnershipEpoch(1)
	f.d.terminateDemotedRGIPsecSAs(1, firstDemotionEpoch)
	if len(f.terminated) != 0 {
		t.Fatalf("failed active-SA read terminated names: %v", f.terminated)
	}

	// A later tenure cannot reuse the old provenance, even if the same name
	// is live again without a new successful fallback initiation.
	f.activeErr = nil
	f.cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	f.d.bumpIPsecRGOwnershipEpoch(1)
	f.live = []string{"vpn-plain"}
	f.cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	nextDemotionEpoch := f.d.bumpIPsecRGOwnershipEpoch(1)
	f.d.terminateDemotedRGIPsecSAs(1, nextDemotionEpoch)
	if len(f.terminated) != 0 {
		t.Fatalf("later sole-RG demotion swept a prior-tenure fallback name: %v", f.terminated)
	}
}

func TestFallbackProvenanceClearIsEpochScoped18426(t *testing.T) {
	d := &Daemon{
		ipsecFallbacks: map[string]ipsecFallbackRetryState{
			"vpn-plain": {
				fallbackInitiated:         true,
				fallbackInitiatedEpoch:    3,
				fallbackInitiatedSeenLive: true,
			},
		},
	}

	d.clearIPsecFallbackInitiated("vpn-plain", 1)
	d.ipsecFallbackMu.Lock()
	state := d.ipsecFallbacks["vpn-plain"]
	d.ipsecFallbackMu.Unlock()
	if !state.fallbackInitiated || state.fallbackInitiatedEpoch != 3 {
		t.Fatalf("old demotion clear changed new provenance: %+v", state)
	}

	d.clearIPsecFallbackInitiated("vpn-plain", 3)
	d.ipsecFallbackMu.Lock()
	state = d.ipsecFallbacks["vpn-plain"]
	d.ipsecFallbackMu.Unlock()
	if state.fallbackInitiated || state.fallbackInitiatedEpoch != 0 {
		t.Fatalf("matching demotion clear retained provenance: %+v", state)
	}
}
