package daemon

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #6611 review follow-up. The original PR claimed the strict cluster-auth gate
// only affected the operator commit, and that "a rejected commit is inert for
// traffic". That is true for Store.Commit / CommitCheck / CommitConfirmed and
// FALSE for bootstrapFromFile, which strict-compiles /etc/xpf/xpf.conf
// UNATTENDED at first boot whenever the config DB has no active config
// (daemon_run_bringup.go). A node that takes that path with an unkeyed cluster
// config comes up with NO active config — reimage / node replacement / DR
// restore from archived text, and this repo's own `make cluster-deploy`, which
// wipes /etc/xpf/.configdb before restarting (test/incus/cluster-setup.sh).
//
// Refusing to provision an unkeyed cluster is the intended posture — a NEW
// provision should fail closed. These tests exist so that verdict is a pinned,
// deliberate choice with a documented migration order (key the RUNNING cluster
// first, then re-provision), and cannot silently drift again.

// bootstrapDaemon builds the minimal Daemon bootstrapFromFile needs: a real
// store over a temp DB and a config file path.
//
// nodeID selects the compile the store performs, and it matters:
// configstore.New defaults to -1 (standalone -> CompileConfig), whereas a real
// cluster node's first boot has a /etc/xpf/node-id and runs
// CompileConfigForNode. A guard that only ever ran at -1 would not measure the
// verdict it claims to pin, so every case below is exercised at the cluster
// node ids too.
func bootstrapDaemon(t *testing.T, conf string, nodeID int) (*Daemon, func() bool) {
	t.Helper()
	dir := t.TempDir()
	confPath := filepath.Join(dir, "xpf.conf")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	store := newConfigStore(t, filepath.Join(dir, "config.db"))
	if nodeID >= 0 {
		store.SetNodeID(nodeID)
	}
	d := &Daemon{store: store, opts: Options{NoDataplane: true, ConfigFile: confPath}}
	return d, func() bool { return store.ActiveConfig() != nil }
}

// clusterBootstrapConf renders a cluster config for a given node, optionally
// keyed. The `node` leaf tracks nodeID so the #4185 identity cross-check is
// satisfied and the #6611 verdict is what decides these tests.
func clusterBootstrapConf(nodeID int, key string) string {
	leaf := ""
	if key != "" {
		leaf = "        authentication-key \"" + key + "\";\n"
	}
	node := nodeID
	if node < 0 {
		node = 0
	}
	return fmt.Sprintf(`chassis {
    cluster {
        cluster-id 1;
        node %d;
        reth-count 2;
%s        redundancy-group 1 {
            node 0 priority 200;
            node 1 priority 100;
        }
    }
}
`, node, leaf)
}

// TestBootstrapFromFileRejectsUnkeyedCluster_6611 pins the UNATTENDED verdict:
// a fresh node handed an unkeyed cluster config refuses to bootstrap, and — the
// part that makes this different from a rejected operator commit — is left with
// NO active config rather than a warning.
//
// RED on revert: with the #6611 gate call site removed, bootstrapFromFile
// succeeds and the node comes up active with an unauthenticated control channel.
func TestBootstrapFromFileRejectsUnkeyedCluster_6611(t *testing.T) {
	for _, nodeID := range []int{-1, 0, 1} {
		d, hasActive := bootstrapDaemon(t, clusterBootstrapConf(nodeID, ""), nodeID)
		err := d.bootstrapFromFile()
		if err == nil {
			t.Fatalf("node %d: bootstrapFromFile ACCEPTED an unkeyed chassis "+
				"cluster: a freshly provisioned node would come up running an "+
				"unauthenticated cluster control channel", nodeID)
		}
		if !strings.Contains(err.Error(), "authentication-key") {
			t.Fatalf("node %d: bootstrap rejection does not name the missing leaf: %v",
				nodeID, err)
		}
		// The consequence the operator doc must state: no active config, not a
		// warning.
		if hasActive() {
			t.Fatalf("node %d: a rejected bootstrap must leave NO active config", nodeID)
		}
	}
}

// TestBootstrapFromFileRejectsEmptyConfig_10735 ensures a torn day-0 config
// cannot be committed as an empty configuration and mark a fresh store
// configured.
//
// RED on revert: without the empty-file guard, the store commits an empty tree
// and EverCommitted becomes true.
func TestBootstrapFromFileRejectsEmptyConfig_10735(t *testing.T) {
	d, hasActive := bootstrapDaemon(t, "", -1)
	err := d.bootstrapFromFile()
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("bootstrapFromFile(empty config) error = %v, want empty-config rejection", err)
	}
	if hasActive() {
		t.Fatal("empty config was committed as an active configuration")
	}
	if d.store.EverCommitted() {
		t.Fatal("empty config marked the fresh store ever-committed")
	}
}

// TestBootstrapFromFileAcceptsKeyedCluster_6611 is the NEGATIVE CONTROL: the
// same unattended path accepts a keyed cluster and promotes it, so the guard
// above cannot be passing by rejecting every bootstrap. It is also the
// mechanical proof of the documented migration order — key the running cluster
// FIRST, then re-provision, and the provision succeeds.
func TestBootstrapFromFileAcceptsKeyedCluster_6611(t *testing.T) {
	for _, nodeID := range []int{-1, 0, 1} {
		conf := clusterBootstrapConf(nodeID, "bootstrap-psk-6611-long-enough")
		d, hasActive := bootstrapDaemon(t, conf, nodeID)
		if err := d.bootstrapFromFile(); err != nil {
			t.Fatalf("node %d: bootstrapFromFile rejected a KEYED cluster config: %v",
				nodeID, err)
		}
		if !hasActive() {
			t.Fatalf("node %d: keyed bootstrap did not promote an active config", nodeID)
		}
		active := d.store.ActiveConfig()
		if active.Chassis.Cluster == nil {
			t.Fatalf("node %d: keyed bootstrap promoted a config with no cluster stanza",
				nodeID)
		}
		if got := active.Chassis.Cluster.ControlLinkAuthKey.Reveal(); got == "" {
			t.Fatalf("node %d: keyed bootstrap promoted a config whose control-link "+
				"key is empty", nodeID)
		}
	}
}

// TestBootstrapFromFileStandaloneUnaffected_6611 is the second NEGATIVE
// CONTROL: a non-clustered node has no control channel to authenticate and must
// still bootstrap unattended. A gate that broke standalone first boot would
// brick every non-HA appliance.
func TestBootstrapFromFileStandaloneUnaffected_6611(t *testing.T) {
	d, hasActive := bootstrapDaemon(t, `system {
    host-name standalone-6611;
}
`, -1)
	if err := d.bootstrapFromFile(); err != nil {
		t.Fatalf("bootstrapFromFile rejected a standalone config: %v", err)
	}
	if !hasActive() {
		t.Fatal("standalone bootstrap did not promote an active config")
	}
}

// TestBootstrapStoreIsInClusterMode_6611 proves the node-id plumbing in
// bootstrapDaemon actually takes effect, so the node coverage the guards above
// claim is real rather than three repetitions of the standalone compile.
//
// It works by feeding a KEYED config whose `node` leaf disagrees with the
// store's node id. That clears the #6611 gate and is then refused by the #4185
// node-identity cross-check — a verdict only reachable when nodeID >= 0, i.e.
// only when compileTreeStrict took the CompileConfigForNode branch.
// crossCheckNodeID returns nil for nodeID < 0, so if SetNodeID had not taken
// effect this config would commit clean.
func TestBootstrapStoreIsInClusterMode_6611(t *testing.T) {
	// Store is node 1; the config says node 0.
	conf := clusterBootstrapConf(0, "bootstrap-psk-6611-long-enough")
	d, hasActive := bootstrapDaemon(t, conf, 1)
	err := d.bootstrapFromFile()
	if err == nil {
		t.Fatal("store node-id never took effect: a keyed config whose node leaf " +
			"disagrees with the store node-id committed clean, which means the " +
			"cluster-mode (CompileConfigForNode) branch was not taken")
	}
	if !strings.Contains(err.Error(), "node identity mismatch") {
		t.Fatalf("expected the #4185 identity cross-check (proving cluster-mode "+
			"compile), got: %v", err)
	}
	if hasActive() {
		t.Fatal("a rejected bootstrap must leave NO active config")
	}
}
