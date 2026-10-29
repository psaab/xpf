package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
)

func TestFallbackInitiatedUnanchoredSAIsTerminatedOnSoleRGDemotion18426(t *testing.T) {
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
	cfg := store.ActiveConfig()
	cm := cluster.NewManager(0, 1)
	cm.UpdateConfig(cfg.Chassis.Cluster)
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	if _, known := cm.LocalGroupPrimary(0); known {
		t.Fatal("FIXTURE: RG0 must be undeclared for the sole-data-RG fallback")
	}

	ss := cluster.NewSessionSync(":0", "", nil)
	ss.SetPeerIPsecSAsForTesting([]string{"vpn-plain"})
	var live, initiated, terminated []string
	d := &Daemon{
		cluster:     cm,
		store:       store,
		sessionSync: ss,
		ipsecActiveNamesFn: func() ([]string, error) {
			return append([]string(nil), live...), nil
		},
		ipsecTerminateFn: func(name string) error {
			terminated = append(terminated, name)
			return nil
		},
		ipsecInitiateFn: func(name string) error {
			initiated = append(initiated, name)
			live = append(live, name)
			return nil
		},
	}

	// Model the promotion edge's epoch bump, then exercise the real scoped
	// fallback path. Only vpn-plain is peer-advertised and initiated here.
	d.bumpIPsecRGOwnershipEpoch(1)
	d.reinitiateIPsecSAsForRG(1)
	if len(initiated) != 1 || initiated[0] != "vpn-plain" {
		t.Fatalf("fallback initiation = %v, want [vpn-plain]", initiated)
	}

	// Retry bookkeeping may prune a successful name absent from the peer's
	// latest set; its fallback provenance must still reach the demotion sweep.
	ss.SetPeerIPsecSAsForTesting(nil)
	d.retryOwedIPsecFallback()
	live = append(live, "vpn-trap") // live, unanchored, but not fallback-initiated

	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	demotionEpoch := d.bumpIPsecRGOwnershipEpoch(1)
	d.terminateDemotedRGIPsecSAs(1, demotionEpoch)
	if len(terminated) != 1 || terminated[0] != "vpn-plain" {
		t.Fatalf("sole-RG demotion terminated %v, want only fallback-initiated [vpn-plain] (not trap-initiated vpn-trap)", terminated)
	}
	// A later trap-established SA with the same connection name has no
	// fallback provenance after the successful cleanup above.
	cm.SetGroupStateForTesting(1, cluster.StatePrimary)
	d.bumpIPsecRGOwnershipEpoch(1)
	live = []string{"vpn-plain", "vpn-trap"}
	cm.SetGroupStateForTesting(1, cluster.StateSecondary)
	demotionEpoch = d.bumpIPsecRGOwnershipEpoch(1)
	d.terminateDemotedRGIPsecSAs(1, demotionEpoch)
	if len(terminated) != 1 || terminated[0] != "vpn-plain" {
		t.Fatalf("later sole-RG demotion swept non-fallback names: %v", terminated)
	}
}
