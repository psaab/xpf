package config

import (
	"strings"
	"testing"
)

// #16746 (R3-A22-02): a cluster with redundancy groups under the default
// private-RG election but without a complete control link committed
// cleanly, yet no heartbeat could ever start (daemon startClusterComms
// gates on ControlInterface != "" && PeerAddress != ""), so the cluster
// had no peer detector: control-interface absent -> both nodes elect
// PRIMARY (dual-primary, RETH VRRP suppressed); control-interface set but
// peer-address absent -> peerConfirmedAbsent never set, non-preempt RGs
// stay SECONDARY forever (permanent no-primary).
//
// Fix: validateChassisClusterStrict rejects RGs + PrivateRGElection with
// an incomplete pair on the strict path; the tolerant load/peer-sync
// path warns instead (#1960 no-brick, via lenientChassisRG).
//
// FAIL-ON-REVERT: remove the #16746 block in validateChassisClusterStrict
// and the three reject subtests below compile clean again — exactly the
// silent dual-/no-primary regression this file exists to catch. The
// accept controls pin that the gate does not over-reject: complete pair,
// no-private-rg-election opt-out (VRRP arbitrates), and RG-less clusters.

// controlLinkLines16746 builds a cluster with RG0+RG1. control carries the
// control-link leaves under test; extra appends cluster leaves (e.g. the
// no-private-rg-election opt-out).
func controlLinkLines16746(control []string, extra ...string) []string {
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster node 0",
		"set interfaces em0 unit 0 family inet address 10.99.0.1/24",
		"set chassis cluster redundancy-group 0 node 0 priority 200",
		"set chassis cluster redundancy-group 0 node 1 priority 100",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set chassis cluster redundancy-group 1 node 1 priority 100",
	}
	lines = append(lines, control...)
	return append(lines, extra...)
}

func TestIncompleteControlLinkFailsCommit16746(t *testing.T) {
	cases := []struct {
		name    string
		control []string
		want    []string
	}{
		{
			name:    "neither leaf (fabric-transport shape)",
			control: nil,
			want:    []string{"control-interface", "peer-address", "dual-primary", "no-private-rg-election"},
		},
		{
			name:    "peer-address only",
			control: []string{"set chassis cluster peer-address 10.99.0.2"},
			want:    []string{"peer-address is set but control-interface", "dual-primary", "no-private-rg-election"},
		},
		{
			name: "control-interface only",
			control: []string{
				"set chassis cluster control-interface em0",
			},
			want: []string{"control-interface is set but peer-address", "stay secondary", "no-private-rg-election"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, controlLinkLines16746(tc.control))
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("expected commit to reject RGs under private-rg-election with %s "+
					"(no heartbeat can start, so no peer detector exists), got nil error", tc.name)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not name %q", err.Error(), w)
				}
			}
		})
	}
}

func TestIncompleteControlLinkTolerantWarns16746(t *testing.T) {
	for _, control := range [][]string{
		nil,
		{"set chassis cluster peer-address 10.99.0.2"},
		{"set chassis cluster control-interface em0"},
	} {
		tree := buildTree(t, controlLinkLines16746(control))
		cfg, err := CompileConfigLenient(tree)
		if err != nil {
			t.Fatalf("lenient compile must not brick a persisted incomplete-control-link config: %v", err)
		}
		found := false
		for _, w := range cfg.Warnings {
			if strings.Contains(w, "control-interface") && strings.Contains(w, "peer-address") {
				found = true
			}
		}
		if !found {
			t.Fatalf("lenient compile should warn about the incomplete control link; warnings=%v", cfg.Warnings)
		}
	}
}

func TestCompleteControlLinkControlsCommit16746(t *testing.T) {
	// Control: complete pair under default private-RG election commits.
	tree := buildTree(t, controlLinkLines16746([]string{
		"set chassis cluster control-interface em0",
		"set chassis cluster peer-address 10.99.0.2",
	}))
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("commit rejected a complete control link: %v", err)
	}
	if cfg.Chassis.Cluster == nil || !cfg.Chassis.Cluster.PrivateRGElection {
		t.Fatalf("fixture must exercise default private-RG election, got %+v", cfg.Chassis.Cluster)
	}

	// Control: no control link but no-private-rg-election — RETH VRRP
	// arbitrates, so the shape is legitimate and must commit. This is
	// also the documented fabric-transport migration path.
	for _, control := range [][]string{
		nil,
		{"set chassis cluster peer-address 10.99.0.2"},
		{"set chassis cluster control-interface em0"},
	} {
		tree = buildTree(t, controlLinkLines16746(control,
			"set chassis cluster no-private-rg-election"))
		cfg, err = CompileConfig(tree)
		if err != nil {
			t.Fatalf("commit rejected no-private-rg-election cluster with control=%v: %v", control, err)
		}
		if cfg.Chassis.Cluster.PrivateRGElection {
			t.Fatal("fixture must compile to PrivateRGElection=false")
		}
	}

	// Control: RG-less cluster under private-RG election has no RG to
	// mis-elect and must commit without a control link.
	tree = buildTree(t, []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-6611",
		"set chassis cluster node 0",
	})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("commit rejected RG-less cluster: %v", err)
	}

	// Control: no cluster stanza at all is unaffected.
	tree = buildTree(t, []string{"set system host-name solo"})
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("commit rejected standalone config: %v", err)
	}
}
