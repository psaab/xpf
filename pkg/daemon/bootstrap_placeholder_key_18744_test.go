package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #18744: the bootstrap import is the one committer the placeholder gate does
// not judge on a never-committed store, so a reimaged node bootstrapping a
// placeholder conf still gets an active config, with the warning.
func TestBootstrapFromFileAcceptsPlaceholderKeyWithWarning18744(t *testing.T) {
	for _, nodeID := range []int{-1, 0, 1} {
		conf := clusterBootstrapConf(nodeID, "xpf-lab-ha-psk-cluster-22-CHANGE-ME")
		d, hasActive := bootstrapDaemon(t, conf, nodeID)
		if err := d.bootstrapFromFile(); err != nil {
			t.Fatalf("node %d: bootstrapFromFile refused a placeholder-keyed conf: %v", nodeID, err)
		}
		if !hasActive() {
			t.Fatalf("node %d: no active config after the bootstrap import", nodeID)
		}
		warned := false
		for _, w := range d.store.ActiveConfig().Warnings {
			if strings.Contains(w, "matches a published placeholder") {
				warned = true
			}
		}
		if !warned {
			t.Fatalf("node %d: the bootstrap import dropped the placeholder warning", nodeID)
		}
	}
}

// The bootstrap pre-flight must compile as the bootstrap authority. If it ran
// as an ordinary committer, a placeholder would fail the pre-flight compile,
// bootstrapFromFile would skip its device-map strand check (it only checks a
// compiled candidate), and the unjudged commit would then promote a stranding
// config. The cell pairs a placeholder key with a stranding device-map and
// requires the device-map refusal.
func TestBootstrapPreflightRunsWithAPlaceholderKey18744(t *testing.T) {
	withInjectedNICs(t, strandNICs)
	conf := strings.Replace(strandDeviceMapConfig, "chassis {\n",
		"chassis {\n    cluster {\n        cluster-id 1;\n        authentication-key \"xpf-lab-ha-psk-cluster-22-CHANGE-ME\";\n    }\n", 1)
	dir := t.TempDir()
	path := filepath.Join(dir, "xpf.conf")
	if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := configstore.New(filepath.Join(dir, "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	d := &Daemon{opts: Options{ConfigFile: path}, store: s}
	err = d.bootstrapFromFile()
	if err == nil || !strings.Contains(err.Error(), "preflight") {
		t.Fatalf("bootstrapFromFile = %v, want the device-map preflight refusal; a placeholder "+
			"key must not switch the pre-flight off", err)
	}
	if d.store.ActiveConfig() != nil {
		t.Fatal("a stranding bootstrap config was committed")
	}
}
