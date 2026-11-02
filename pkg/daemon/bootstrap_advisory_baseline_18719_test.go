package daemon

import (
	"strings"
	"testing"
)

const fabricStampBootstrapConfig18719 = `set chassis cluster cluster-id 1
set chassis cluster node 0
set chassis cluster authentication-key aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
set chassis cluster fabric-interface fab0
`

func TestBootstrapDoesNotHideFabricReminder18719(t *testing.T) {
	d, _ := bootstrapDaemon(t, fabricStampBootstrapConfig18719, 0)
	if err := d.bootstrapFromFile(); err != nil {
		t.Fatalf("bootstrapFromFile: %v", err)
	}
	if active := d.store.ActiveConfig(); active == nil || !hasWarningText18719(active.Warnings) {
		t.Fatalf("premise: bootstrap compiled the fabric reminder; active=%v", active)
	}
	if err := d.store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if _, err := d.store.LoadSet("set system host-name after-bootstrap"); err != nil {
		t.Fatalf("stage unrelated operator change: %v", err)
	}
	compiled, err := d.store.Commit()
	if err != nil {
		t.Fatalf("first operator commit after bootstrap: %v", err)
	}
	if !hasWarningText18719(compiled.Warnings) {
		t.Fatalf("first operator commit hid the bootstrap reminder: %v", compiled.Warnings)
	}
}

func hasWarningText18719(warnings []string) bool {
	for _, warning := range warnings {
		if strings.Contains(warning, "fabric zone stamp (#10105)") {
			return true
		}
	}
	return false
}
