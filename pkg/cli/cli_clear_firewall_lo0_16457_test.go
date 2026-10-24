package cli

import (
	"errors"
	"strings"
	"testing"
)

// #16457: `clear firewall all` also resets the kernel lo0 named counters
// (previously they reset only on table rebuild).
func TestClearFirewallAllResetsLo0Counters16457(t *testing.T) {
	orig := resetLo0CountersCLI
	defer func() { resetLo0CountersCLI = orig }()
	resets := 0
	resetLo0CountersCLI = func() error { resets++; return nil }

	dp := newArityDP()
	c := &CLI{dp: dp}
	var err error
	out := captureStdout(t, func() { err = c.handleClearFirewall([]string{"all"}) })
	if err != nil {
		t.Fatalf("handleClearFirewall: %v", err)
	}
	if dp.filterCounters != 1 {
		t.Fatalf("filterCounters = %d, want 1", dp.filterCounters)
	}
	if resets != 1 {
		t.Fatalf("lo0 resets = %d, want 1", resets)
	}
	if !strings.Contains(out, "Firewall filter counters cleared") {
		t.Fatalf("output = %q, want cleared message", out)
	}

	// A lo0 reset failure surfaces instead of an unqualified success.
	resetLo0CountersCLI = func() error { return errors.New("netlink: denied") }
	err = nil
	_ = captureStdout(t, func() { err = c.handleClearFirewall([]string{"all"}) })
	if err == nil || !strings.Contains(err.Error(), "clear lo0 filter counters") {
		t.Fatalf("err = %v, want lo0 reset failure surfaced", err)
	}
}
