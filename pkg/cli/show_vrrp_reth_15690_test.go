package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/cluster"
	"github.com/psaab/xpf/pkg/configstore"
)

// #15690: the local CLI's showVRRP collected only the generic per-interface
// vrrp-group instances and dropped every RETH instance, while the gRPC
// GetVRRPStatus and REST /vrrp handlers append them. On a chassis cluster
// whose RG 1 is carried by reth0 the console printed "No VRRP groups
// configured" for exactly the deployments that have VRRP.
//
// The cells drive the real showVRRP / handleShow dispatchers, not
// CollectRethInstances directly — a cell that called the collector would
// pass against the defective handler, because the collector was never
// what was broken.

func newRethClusterStore15690(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	lines := []string{
		"set chassis cluster cluster-id 1",
		"set chassis cluster authentication-key test-cluster-psk-15690",
		"set chassis cluster reth-count 2",
		"set chassis cluster no-private-rg-election",
		"set chassis cluster redundancy-group 1 node 0 priority 200",
		"set interfaces ge-0/0/1 gigether-options redundant-parent reth0",
		"set interfaces reth0 redundant-ether-options redundancy-group 1",
		"set interfaces reth0 unit 0 family inet address 10.0.61.1/24",
	}
	if _, err := store.LoadSet(strings.Join(lines, "\n")); err != nil {
		t.Fatalf("LoadSet: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return store
}

func TestShowVRRPReportsRethInstances15690(t *testing.T) {
	c := &CLI{
		store:   newRethClusterStore15690(t),
		cluster: cluster.NewManager(0, 1),
	}

	out := captureStdout(t, func() {
		if err := c.showVRRP(); err != nil {
			t.Fatalf("showVRRP: %v", err)
		}
	})
	if strings.Contains(out, "No VRRP groups configured") {
		t.Fatalf("#15690: show security vrrp reported no groups on a chassis cluster "+
			"whose RG 1 is carried by reth0; the RETH instance (group 101) was dropped:\n%s", out)
	}
	// The RETH instance's group id is 100+rgID (101), it carries reth0's
	// address, and it renders under the resolved physical member name
	// (ge-0-0-1, as CollectRethInstances resolves reth -> member). With no
	// RG state registered the priority defaults to the secondary 100.
	if !strings.Contains(out, "ge-0-0-1") || !strings.Contains(out, "101") ||
		!strings.Contains(out, "10.0.61.1/24") || !strings.Contains(out, "100") {
		t.Fatalf("#15690: RETH instance row (ge-0-0-1 / group 101 / 10.0.61.1/24 / priority 100) missing:\n%s", out)
	}
}

// The top-level Junos spelling must reach the same rendering.
func TestShowVRRPTopLevelDispatch15690(t *testing.T) {
	c := &CLI{
		store:   newRethClusterStore15690(t),
		cluster: cluster.NewManager(0, 1),
	}
	out := captureStdout(t, func() {
		if err := c.handleShow([]string{"vrrp"}); err != nil {
			t.Fatalf("handleShow(show vrrp): %v", err)
		}
	})
	if !strings.Contains(out, "101") || !strings.Contains(out, "10.0.61.1/24") {
		t.Fatalf("#15690: top-level `show vrrp` must render the RETH instance:\n%s", out)
	}
}

// Control: a node with no cluster manager must keep the pre-fix behaviour
// (generic instances only, no panic on the nil cluster).
func TestShowVRRPWithoutClusterIsUnchanged15690(t *testing.T) {
	c := &CLI{store: newRethClusterStore15690(t)}

	out := captureStdout(t, func() {
		if err := c.showVRRP(); err != nil {
			t.Fatalf("showVRRP: %v", err)
		}
	})
	if !strings.Contains(out, "No VRRP groups configured") {
		t.Fatalf("#15690: with no cluster manager the RETH instances must not be "+
			"synthesised; got:\n%s", out)
	}
}
