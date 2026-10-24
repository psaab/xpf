package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #16454: an uncounted term must never render a numeric Hit count, even
// when a (legacy / pre-fix) helper publishes a row for it, while a
// counted-but-idle term still renders 0. This binds the config-side
// `then count` gate on the raw CLI views; the Rust producer-side gate is
// pinned in userspace-dp status_tests.rs.
//
// FAIL-ON-REVERT: dropping `term.Count != ""` from the Hit-count
// conditions in cli_show_security_filters.go re-renders the uncounted
// term's published 0 (and, on the all-filters view, the counted-idle 0
// assertion still passes, so the count==1 / not-contains checks are the
// ones that go RED).
func newUncounted16454Store(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"firewall family inet filter edge term block from destination-port 22",
		"firewall family inet filter edge term block then discard",
		"firewall family inet filter edge term counted-idle from destination-port 80",
		"firewall family inet filter edge term counted-idle then count hits",
		"firewall family inet filter edge term counted-idle then accept",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func uncounted16454CLI(store *configstore.Store) *CLI {
	return &CLI{
		store: store,
		dp: &firewallFilterUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
					// Legacy-helper row for the UNCOUNTED term: must be ignored.
					{Family: "inet", FilterName: "edge", TermName: "block", TermOrdinal: 0, Packets: 0, Bytes: 0},
					{Family: "inet", FilterName: "edge", TermName: "counted-idle", TermOrdinal: 1, Packets: 0, Bytes: 0},
				},
			},
		},
	}
}

func assertUncounted16454(t *testing.T, out string) {
	t.Helper()
	if strings.Count(out, "Hit count:") != 1 {
		t.Fatalf("output = %q, want exactly one Hit count (counted-idle only)", out)
	}
	if !strings.Contains(out, "Hit count: 0 packets, 0 bytes") {
		t.Fatalf("output = %q, want counted-but-idle term to render 0", out)
	}
	// The uncounted term's block must not be followed by a Hit count line:
	// split on term headings and check the block segment.
	idx := strings.Index(out, "Term: block")
	if idx < 0 {
		t.Fatalf("output = %q, want block term rendered", out)
	}
	seg := out[idx:]
	if next := strings.Index(seg, "Term: counted-idle"); next >= 0 {
		seg = seg[:next]
	}
	if strings.Contains(seg, "Hit count:") {
		t.Fatalf("output = %q, uncounted term rendered a numeric Hit count (#16454)", out)
	}
}

func TestShowFirewallUncountedTermNoHitCount16454(t *testing.T) {
	store := newUncounted16454Store(t)
	c := uncounted16454CLI(store)
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleShow([]string{"firewall"})
	})
	if callErr != nil {
		t.Fatalf("handleShow(firewall) error = %v", callErr)
	}
	assertUncounted16454(t, out)
}

func TestShowFirewallFilterUncountedTermNoHitCount16454(t *testing.T) {
	store := newUncounted16454Store(t)
	c := uncounted16454CLI(store)
	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleShow([]string{"firewall", "filter", "edge"})
	})
	if callErr != nil {
		t.Fatalf("handleShow(firewall filter edge) error = %v", callErr)
	}
	assertUncounted16454(t, out)
}
