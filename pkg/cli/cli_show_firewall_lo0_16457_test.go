package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

// #16457: `show firewall filter <lo0-filter>` (and `show firewall`) render
// the kernel inet xpf_lo0 count beside the helper count; non-lo0 filters
// are unchanged and never trigger the kernel read.
func newLo0ShowStore16457(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, cmd := range []string{
		"firewall family inet filter protect-re term ssh from protocol tcp",
		"firewall family inet filter protect-re term ssh from destination-port 22",
		"firewall family inet filter protect-re term ssh then count ssh-deny",
		"firewall family inet filter protect-re term ssh then discard",
		"firewall family inet filter edge term t1 then accept",
		"interfaces lo0 unit 0 family inet filter input protect-re",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q): %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return store
}

func TestShowFirewallFilterLo0KernelCounter16457(t *testing.T) {
	orig := readLo0CountersCLI
	defer func() { readLo0CountersCLI = orig }()
	calls := 0
	readLo0CountersCLI = func() ([]xnft.Lo0Count, error) {
		calls++
		return []xnft.Lo0Count{{Counter: "ssh-deny", Packets: 42, Bytes: 4200}}, nil
	}

	c := &CLI{store: newLo0ShowStore16457(t), dp: &firewallFilterUserspaceDP{Manager: dataplane.New()}}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleShow([]string{"firewall", "filter", "protect-re"})
	})
	if callErr != nil {
		t.Fatalf("handleShow: %v", callErr)
	}
	if !strings.Contains(out, "Kernel lo0 counter ssh-deny: 42 packets, 4200 bytes") {
		t.Fatalf("output = %q, want kernel lo0 ssh-deny 42", out)
	}
	if calls == 0 {
		t.Fatal("kernel lo0 lookup never invoked for lo0 filter")
	}

	// All-filters view carries it too.
	out = captureStdout(t, func() {
		callErr = c.handleShow([]string{"firewall"})
	})
	if callErr != nil {
		t.Fatalf("handleShow all: %v", callErr)
	}
	if !strings.Contains(out, "Kernel lo0 counter ssh-deny: 42 packets, 4200 bytes") {
		t.Fatalf("all-filters output = %q, want kernel lo0 ssh-deny 42", out)
	}

	// Non-lo0 filter: unchanged (no kernel line, no lookup).
	before := calls
	var edgeOut string
	edgeOut = captureStdout(t, func() {
		callErr = c.handleShow([]string{"firewall", "filter", "edge"})
	})
	if callErr != nil {
		t.Fatalf("handleShow edge: %v", callErr)
	}
	if strings.Contains(edgeOut, "Kernel lo0 counter") {
		t.Fatalf("edge output = %q, non-lo0 filter must not render kernel line", edgeOut)
	}
	if calls != before {
		t.Fatalf("lookup calls for non-lo0 = %d, want %d (unchanged)", calls, before)
	}
}
