package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #15679: show security flow traceoptions must render proto= for a filter.
func TestShowFlowTraceoptionsProto15679(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride("security { flow { traceoptions { file rt.log; packet-filter pf1 { protocol ospf; } } } }"); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	c := &CLI{store: store}
	out := captureStdout(t, func() {
		if err := c.showFlowTraceoptions(); err != nil {
			t.Fatalf("show: %v", err)
		}
	})
	if !strings.Contains(out, "proto=ospf") {
		t.Fatalf("CLI show missing proto=ospf:\n%s", out)
	}
}
