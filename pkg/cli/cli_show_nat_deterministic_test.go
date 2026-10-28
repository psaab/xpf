// FAIL-ON-REVERT: the local CLI `show security nat source deterministic-nat`
// command must resolve the deterministic source-NAT forward (subscriber ->
// translated IPv4 + port block) AND reverse (translated IPv4 + port ->
// subscriber) mapping from the LAST-APPLIED NAT generation (#5794). Reverting
// the dispatch (so it no longer calls pkg/nat against the applied view) makes
// the assertions below go RED. Golden values match the Rust dataplane
// allocator vectors (userspace-dp/src/nat/tests_pool.rs).
package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// appliedViewCLIDP is a loaded DP returning a fixed applied NAT view.
type appliedViewCLIDP struct {
	*dataplane.Manager
	view dpuserspace.AppliedNATView
}

func (d *appliedViewCLIDP) IsLoaded() bool                             { return true }
func (d *appliedViewCLIDP) AppliedNATView() dpuserspace.AppliedNATView { return d.view }

func deterministicV4CLIView(gen uint64) dpuserspace.AppliedNATView {
	pool := &config.NATPool{
		Name:      "cgn-pool",
		Addresses: []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"},
		PortLow:   1024,
		PortHigh:  65535,
		Deterministic: &config.DeterministicNATConfig{
			BlockSize:   512,
			HostAddress: "100.64.0.0/22",
		},
	}
	cfg := &config.Config{}
	cfg.Security.NAT.SourcePools = map[string]*config.NATPool{"cgn-pool": pool}
	return dpuserspace.AppliedNATView{Config: cfg, AppliedGeneration: gen, Available: true}
}

func TestCLIShowNATDeterministicForwardReverse(t *testing.T) {
	c := &CLI{dp: &appliedViewCLIDP{Manager: dataplane.New(), view: deterministicV4CLIView(21)}}

	// Forward: 100.64.0.5 -> 203.0.113.1, block 3584-4095.
	out := captureStdout(t, func() {
		if err := c.showNATDeterministic([]string{"internal-host", "100.64.0.5", "pool", "cgn-pool"}); err != nil {
			t.Fatalf("forward: %v", err)
		}
	})
	for _, want := range []string{"203.0.113.1", "3584-4095", "100.64.0.5", "generation: 21"} {
		if !strings.Contains(out, want) {
			t.Fatalf("forward output missing %q:\n%s", want, out)
		}
	}

	// Reverse: 203.0.113.1:3900 -> 100.64.0.5.
	out = captureStdout(t, func() {
		if err := c.showNATDeterministic([]string{"nat-ip", "203.0.113.1", "nat-port", "3900", "pool", "cgn-pool"}); err != nil {
			t.Fatalf("reverse: %v", err)
		}
	})
	for _, want := range []string{"100.64.0.5", "3584-4095", "generation: 21"} {
		if !strings.Contains(out, want) {
			t.Fatalf("reverse output missing %q:\n%s", want, out)
		}
	}
}

func TestCLIShowNATDeterministicErrors(t *testing.T) {
	c := &CLI{dp: &appliedViewCLIDP{Manager: dataplane.New(), view: deterministicV4CLIView(1)}}

	// Out-of-range subscriber surfaces the stable code in the output.
	out := captureStdout(t, func() {
		if err := c.showNATDeterministic([]string{"internal-host", "100.64.4.0", "pool", "cgn-pool"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "out-of-range") {
		t.Fatalf("expected out-of-range in output:\n%s", out)
	}

	// No applied view fails closed.
	cNone := &CLI{dp: &appliedViewCLIDP{Manager: dataplane.New(), view: dpuserspace.AppliedNATView{Available: false}}}
	out = captureStdout(t, func() {
		if err := cNone.showNATDeterministic([]string{"internal-host", "100.64.0.5"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "no-applied-view") {
		t.Fatalf("expected no-applied-view in output:\n%s", out)
	}

	// Bad port is a usage error.
	if err := c.showNATDeterministic([]string{"nat-ip", "203.0.113.1", "nat-port", "70000"}); err == nil {
		t.Fatalf("expected error for out-of-range port")
	}
}

// #17225: the local copy used to accept `pool`, `bogus`, `poo web` and
// `pool web extra` and silently drop the selector (the remote copy was
// made strict by #13199). Both now use cliterm.ParseNATPoolSelector.
func TestCLIShowNATDeterministicRejectsMalformedPool17225(t *testing.T) {
	c := &CLI{dp: &appliedViewCLIDP{Manager: dataplane.New(), view: deterministicV4CLIView(1)}}
	for _, args := range [][]string{
		{"internal-host", "100.64.0.5", "pool"},
		{"internal-host", "100.64.0.5", "bogus"},
		{"internal-host", "100.64.0.5", "poo", "web"},
		{"internal-host", "100.64.0.5", "pool", "web", "extra"},
		{"nat-ip", "203.0.113.1", "nat-port", "3900", "pool"},
		{"nat-ip", "203.0.113.1", "nat-port", "3900", "pool", "web", "extra"},
	} {
		if err := c.showNATDeterministic(args); err == nil {
			t.Errorf("showNATDeterministic(%v): expected usage error for malformed pool suffix", args)
		}
	}
	// Control: a well-formed selector still resolves.
	out := captureStdout(t, func() {
		if err := c.showNATDeterministic([]string{"internal-host", "100.64.0.5", "pool", "cgn-pool"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "203.0.113.1") {
		t.Fatalf("expected mapped address in output:\n%s", out)
	}
}
