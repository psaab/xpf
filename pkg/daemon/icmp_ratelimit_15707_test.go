package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #15707: applyKernelTuning must never leave the kernel ICMPv6 error
// rate-limit knob at 0. The pre-fix code wrote "0" (rate limiting
// DISABLED — 0 is unlimited in icmpv6_xrlim_allow) when
// `no-ipv6-reject-zero-hop-limit` was set and never restored it, so the
// knob stayed disabled after the stanza was deleted. The fix never
// writes 0 and reconciles a previously-zeroed knob back to the kernel
// default (1000 ms) on every apply.

func withRatelimitPath15707(t *testing.T, initial string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ratelimit")
	if err := os.WriteFile(p, []byte(initial+"\n"), 0o644); err != nil {
		t.Fatalf("seed ratelimit: %v", err)
	}
	orig := icmpv6RatelimitPath
	icmpv6RatelimitPath = p
	origRoot := redirectSysctlRoot
	redirectSysctlRoot = filepath.Join(t.TempDir(), "net")
	origNoRedirects := noRedirectsActive.Load()
	noRedirectsActive.Store(false)
	t.Cleanup(func() {
		icmpv6RatelimitPath = orig
		redirectSysctlRoot = origRoot
		noRedirectsActive.Store(origNoRedirects)
	})
	return p
}

func readRatelimit15707(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read ratelimit: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func TestApplyKernelTuningNeverDisablesICMPv6Ratelimit15707(t *testing.T) {
	p := withRatelimitPath15707(t, "1000")
	d := &Daemon{}
	cfg := &config.Config{System: config.SystemConfig{
		InternetOptions: &config.InternetOptionsConfig{NoIPv6RejectZeroHopLimit: true},
	}}
	d.applyKernelTuning(cfg)
	if got := readRatelimit15707(t, p); got == "0" {
		t.Errorf("ratelimit = 0 after apply with the knob set; rate limiting must never be disabled")
	}
	if got := readRatelimit15707(t, p); got != "1000" {
		t.Errorf("ratelimit = %q, want untouched 1000", got)
	}
}

func TestApplyKernelTuningRestoresZeroedRatelimit15707(t *testing.T) {
	// Simulate the state the pre-fix binary left behind: knob at 0.
	p := withRatelimitPath15707(t, "0")
	d := &Daemon{}
	// Even with the stanza now deleted, the apply must repair it.
	d.applyKernelTuning(&config.Config{})
	if got := readRatelimit15707(t, p); got != defaultICMPv6Ratelimit {
		t.Errorf("ratelimit = %q after apply, want restored %q", got, defaultICMPv6Ratelimit)
	}
}

func TestReconcileLeavesOperatorRatelimit15707(t *testing.T) {
	p := withRatelimitPath15707(t, "500")
	reconcileICMPv6Ratelimit()
	if got := readRatelimit15707(t, p); got != "500" {
		t.Errorf("ratelimit = %q, want operator value 500 untouched", got)
	}
}
