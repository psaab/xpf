package cli

import (
	"path/filepath"
	"testing"
)

func TestShowDHCPRelayRendersTrustOption82Override11695(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	for _, line := range []string{
		"set forwarding-options dhcp-relay server-group sg 10.1.1.1",
		"set forwarding-options dhcp-relay group lan active-server-group sg",
		"set forwarding-options dhcp-relay group lan interface ge-0/0/0.0",
		"set forwarding-options dhcp-relay group lan overrides always-broadcast",
		"set forwarding-options dhcp-relay group lan overrides maximum-hop-count 4",
		"set forwarding-options dhcp-relay group lan overrides maximum-packet-rate 20",
		"set forwarding-options dhcp-relay group lan overrides forward-only",
		"set forwarding-options dhcp-relay group lan overrides relay-agent-option",
		"set forwarding-options dhcp-relay group lan overrides trust-option-82",
	} {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q): %v", line, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	c := &CLI{store: store}
	got := captureStdout(t, func() {
		if err := c.showDHCPRelay(); err != nil {
			t.Fatalf("showDHCPRelay: %v", err)
		}
	})
	want := "Server groups:\n" +
		"  sg: 10.1.1.1\n" +
		"Relay groups:\n" +
		"  lan:\n" +
		"    Interfaces: ge-0/0/0.0\n" +
		"    Active server group: sg\n" +
		"    Overrides: always-broadcast, maximum-hop-count 4, maximum-packet-rate 20, forward-only (accepted-only), relay-agent-option (accepted-only), trust-option-82\n"
	if got != want {
		t.Fatalf("showDHCPRelay output mismatch\n got: %q\nwant: %q", got, want)
	}
}
