package daemon

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// TestRescueGuidanceNamesConfiguredPaths12129 is the #12129 F1 regression: a
// daemon started with -config on a nondefault directory AND basename must
// have its offline-recovery guidance name the configured config file and its
// adjacent rescue.conf — not the default appliance paths. RED-before: both
// rescue-fallback warnings prescribed /etc/xpf/xpf.conf +
// /etc/xpf/rescue.conf unconditionally, so following them left the real
// rescue.conf in place and never populated the real config file; the next
// restart selected rescue-fallback again.
func TestRescueGuidanceNamesConfiguredPaths12129(t *testing.T) {
	isolateRescueBootState11802(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "custom-site.conf")
	rescuePath := filepath.Join(dir, configstore.RescueConfigBase)
	writeRescue11802Daemon(t, rescuePath, "system { host-name guided-rescue-12129; }\n")

	buf, restore := captureSlog(t)
	defer restore()

	store := newConfigStore(t, path)
	d := &Daemon{store: store, opts: Options{ConfigFile: path}}
	failClosed, err := d.loadAndBootstrapConfig()
	if err != nil || !failClosed || !d.inBootstrap() {
		t.Fatalf("custom-root rescue fallback: failClosed=%v bootstrap=%v err=%v; want true/true/nil",
			failClosed, d.inBootstrap(), err)
	}

	logs := buf.String()
	if got := strings.Count(logs, path); got < 3 {
		t.Errorf("both warnings must name configured config file %q (including structured field); count=%d:\n%s",
			path, got, logs)
	}
	if got := strings.Count(logs, rescuePath); got < 2 {
		t.Errorf("both warnings must name adjacent rescue file %q; count=%d:\n%s",
			rescuePath, got, logs)
	}
	for _, stale := range []string{"/etc/xpf/xpf.conf", "/etc/xpf/rescue.conf"} {
		if strings.Contains(logs, stale) {
			t.Errorf("rescue guidance prescribed default path %q for configured root %q:\n%s",
				stale, path, logs)
		}
	}
}
