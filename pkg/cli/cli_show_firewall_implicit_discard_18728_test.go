package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #18728: the local CLI raw views (all-filters and single-filter) render the
// synthetic implicit-discard term after the authored ones, with its helper
// counter read at the ordinal after the last authored term. The fixture's
// filter has a lenient suppressed-member clone (#16464), so the clone's
// implicit-discard hits must fold into the source's as authored terms do.
func TestCLIShowFirewallImplicitDiscardCounter18728(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(clone16464TreeCLI, nil); err != nil {
		t.Fatalf("SyncApply (lenient): %v", err)
	}
	cfg := store.ActiveConfig()
	cloneName := ""
	for name, f := range cfg.Firewall.FiltersInet {
		if src, _ := f.SuppressedMemberFBF11321(); src == "shared-fbf" {
			cloneName = name
		}
	}
	if cloneName == "" {
		t.Fatalf("premise: no clone in %+v", cfg.Firewall.FiltersInet)
	}
	c := &CLI{store: store, dp: &firewallFilterUserspaceDP{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "shared-fbf", TermName: "steer", TermOrdinal: 0, Packets: 40, Bytes: 4000},
			{Family: "inet", FilterName: "shared-fbf", TermName: "implicit-discard", TermOrdinal: 1, Packets: 5, Bytes: 500},
			{Family: "inet", FilterName: cloneName, TermName: "implicit-discard", TermOrdinal: 1, Packets: 6, Bytes: 600},
		}},
	}}
	const term = "Term: implicit-discard (Junos implicit final discard: no term above matched)"
	check := func(view, out string) {
		t.Helper()
		i := strings.Index(out, term)
		if i < 0 {
			t.Fatalf("%s view lacks the implicit-discard term: %q", view, out)
		}
		if j := strings.Index(out, "Term: steer"); j < 0 || j > i {
			t.Fatalf("%s view must list the implicit-discard term AFTER the authored term: %q", view, out)
		}
		if !strings.Contains(out[i:], "then discard\n    Hit count: 11 packets, 1100 bytes") {
			t.Fatalf("%s view: implicit-discard hit count must fold source+clone to 11/1100: %q", view, out)
		}
	}
	check("all-filters", captureStdout(t, func() {
		if err := c.showFirewallFilters(); err != nil {
			t.Fatalf("showFirewallFilters: %v", err)
		}
	}))
	check("single-filter", captureStdout(t, func() {
		if err := c.showFirewallFilter("shared-fbf", ""); err != nil {
			t.Fatalf("showFirewallFilter: %v", err)
		}
	}))
}
