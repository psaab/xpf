package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #13982 regression tests for the no-redirects posture.
//
// The defect (deep-review H26-03): `system no-redirects` wrote only the
// three conf/all sysctls. For IPv6 the kernel ignores conf/all for
// accept_redirects entirely, so the per-interface value (default 1 on
// every managed netdev) kept accepting ICMPv6 Redirects; for IPv4,
// all+default only seed interfaces created AFTER the write. Worse, every
// transit-gate close writes ip_forward=0, which resets conf/all
// accept_redirects back to 1 — so the gate-closed windows (boot before
// arm, helper crash loop, failed XDP census) were exactly the windows in
// which an on-link attacker spoofing the current first hop could install
// route exceptions steering box-originated traffic.
//
// The fix asserts the posture at conf/default + every netdev enumerated
// under the sysctl roots, and re-asserts it inside the gate writer after
// every actual ip_forward write, so the gate itself repairs the clobber
// its own write causes. These tests drive the production writers against
// temp-dir stand-ins for /proc/sys, matching the withTempTransitForward-
// Sysctls seam style; none may run t.Parallel (package-level path vars).

// withRedirectSysctlRoot builds a temp /proc/sys/net stand-in:
//
//	ipv4/conf/{all,default,r0}/send_redirects, accept_redirects
//	ipv6/conf/{all,default,r0}/accept_redirects
//
// all seeded with `initial`, points the production seams at it, and
// returns the root plus the transit-forwarding knob paths.
func withRedirectSysctlRoot(t *testing.T, initial string) (root, v4Fwd, v6Fwd string) {
	t.Helper()
	dir := t.TempDir()
	root = filepath.Join(dir, "net")
	for _, knobs := range []struct {
		dir   string
		names []string
	}{
		{filepath.Join(root, "ipv4", "conf"), []string{"send_redirects", "accept_redirects"}},
		{filepath.Join(root, "ipv6", "conf"), []string{"accept_redirects"}},
	} {
		for _, ifc := range []string{"all", "default", "r0"} {
			for _, name := range knobs.names {
				p := filepath.Join(knobs.dir, ifc, name)
				if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
					t.Fatalf("mkdir %s: %v", p, err)
				}
				if err := os.WriteFile(p, []byte(initial+"\n"), 0o644); err != nil {
					t.Fatalf("seed %s: %v", p, err)
				}
			}
		}
	}
	v4Fwd = filepath.Join(dir, "ip_forward")
	v6Fwd = filepath.Join(dir, "all_forwarding")
	for _, p := range []string{v4Fwd, v6Fwd} {
		if err := os.WriteFile(p, []byte(initial+"\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	origNoRedirects := noRedirectsActive.Load()
	noRedirectsActive.Store(false)
	origRoot, origV4, origV6 := redirectSysctlRoot, ipv4ForwardSysctlPath, ipv6ForwardSysctlPath
	origMarker := applianceMarkerFile
	redirectSysctlRoot = root
	ipv4ForwardSysctlPath, ipv6ForwardSysctlPath = v4Fwd, v6Fwd
	applianceMarkerFile = filepath.Join(dir, "appliance")
	if err := os.WriteFile(applianceMarkerFile, []byte("appliance\n"), 0o644); err != nil {
		t.Fatalf("seed appliance marker: %v", err)
	}
	t.Cleanup(func() {
		redirectSysctlRoot, ipv4ForwardSysctlPath, ipv6ForwardSysctlPath = origRoot, origV4, origV6
		applianceMarkerFile = origMarker
		noRedirectsActive.Store(origNoRedirects)
		redirectCaptureMu.Lock()
		capturedRedirects = nil
		redirectCaptureMu.Unlock()
	})
	return root, v4Fwd, v6Fwd
}
func assertKnobs(t *testing.T, paths []string, want, when string) {
	t.Helper()
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		if got := strings.TrimSpace(string(b)); got != want {
			t.Errorf("%s = %q %s, want %q", p, got, when, want)
		}
	}
}

// noRedirectKnobPaths enumerates the knob files the posture must cover
// under a withRedirectSysctlRoot root: all, default, and the r0 netdev
// (the kernel ignores IPv6 conf/all for accept_redirects, so the
// per-interface leaves are the load-bearing ones).
func noRedirectKnobPaths(root string) []string {
	var out []string
	for _, f := range []struct {
		fam   string
		names []string
	}{
		{"ipv4", []string{"send_redirects", "accept_redirects"}},
		{"ipv6", []string{"accept_redirects"}},
	} {
		for _, ifc := range []string{"all", "default", "r0"} {
			for _, name := range f.names {
				out = append(out, filepath.Join(root, f.fam, "conf", ifc, name))
			}
		}
	}
	return out
}

// TestNoRedirectsPostureTouchesEveryInterface13982 binds the apply-tail
// writer: with system no-redirects set, applyKernelTuning must drive the
// posture to 0 at conf/default and every enumerated netdev, not only
// conf/all (which IPv6 ignores and which seeds no already-existing
// interface). Control: without the knob the same apply leaves every
// knob untouched, and an armed re-apply does not clobber the posture.
func TestNoRedirectsPostureTouchesEveryInterface13982(t *testing.T) {
	root, v4Fwd, v6Fwd := withRedirectSysctlRoot(t, "1")

	d := &Daemon{}
	// Control: no knob -> no redirect knob is touched.
	d.applyKernelTuning(&config.Config{})
	assertKnobs(t, noRedirectKnobPaths(root), "1",
		"after applyKernelTuning without no-redirects (control)")
	_ = v6Fwd

	// Knob set: every knob at all/default/r0 goes to 0, including the
	// per-interface IPv6 accept_redirects conf/all never reaches.
	d.applyKernelTuning(&config.Config{System: config.SystemConfig{NoRedirects: true}})
	assertKnobs(t, noRedirectKnobPaths(root), "0",
		"after applyKernelTuning with no-redirects")
	// Gate still closed on this never-armed daemon (existing behaviour).
	assertKnobs(t, []string{v4Fwd}, "0", "after applyKernelTuning (gate closed)")
}

// TestTransitGateCloseReassertsNoRedirects13982 binds the gate writer:
// flipping the transit gate (ip_forward write) resets conf/all
// accept_redirects in the kernel, so after a close that actually wrote
// ip_forward the daemon must leave the no-redirects posture at 0 again.
// Simulates the kernel reset by re-seeding the conf knobs to 1 after the
// first apply, then re-asserting the gate closed.
func TestTransitGateCloseReassertsNoRedirects13982(t *testing.T) {
	root, _, _ := withRedirectSysctlRoot(t, "1")

	knobs := noRedirectKnobPaths(root)
	d := &Daemon{}
	cfg := &config.Config{System: config.SystemConfig{NoRedirects: true}}
	d.applyKernelTuning(cfg)
	assertKnobs(t, knobs, "0", "after initial no-redirects apply")

	// Simulate the kernel side effect of the ip_forward=0 write plus an
	// interface appearing after the apply: posture knocked back to 1.
	for _, p := range knobs {
		if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
			t.Fatalf("re-seed %s: %v", p, err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "ipv6", "conf", "reth0.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	late := filepath.Join(root, "ipv6", "conf", "reth0.0", "accept_redirects")
	if err := os.WriteFile(late, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// The gate close re-asserts the posture (holding transitGateMu, as
	// the production reassert does).
	d.transitGateMu.Lock()
	d.writeTransitGateLocked("test", false)
	d.transitGateMu.Unlock()
	assertKnobs(t, append(knobs, late), "0",
		"after transit gate close following the ip_forward reset")
}

// TestTransitGateOpenCloseCycleKeepsNoRedirects13982 is the end-to-end
// sequence: raise the gate (which writes ip_forward), knock the
// posture back to 1 as the kernel does, then close — the close must
// restore 0 everywhere, so no gate state ever leaves the own-routing
// redirect surface open once the operator set no-redirects.
func TestTransitGateOpenCloseCycleKeepsNoRedirects13982(t *testing.T) {
	root, v4Fwd, _ := withRedirectSysctlRoot(t, "0")
	knobs := noRedirectKnobPaths(root)

	d := &Daemon{}
	noRedirectsActive.Store(true)

	d.transitGateMu.Lock()
	writeTransitForwardSysctls(true)
	d.transitGateMu.Unlock()
	assertKnobs(t, []string{v4Fwd}, "1", "after gate open")

	for _, p := range knobs {
		if err := os.WriteFile(p, []byte("1\n"), 0o644); err != nil {
			t.Fatalf("re-seed %s: %v", p, err)
		}
	}
	d.transitGateMu.Lock()
	writeTransitForwardSysctls(false)
	d.transitGateMu.Unlock()
	assertKnobs(t, knobs, "0", "after gate close in an open/close cycle")
	assertKnobs(t, []string{v4Fwd}, "0", "after gate close")
}

// TestNoRedirectsNeverAssertedWithoutKnob13982 is the negative control
// for the gate re-assertion: a daemon that never applied no-redirects
// must not touch the redirect knobs at all when the gate flips (the
// posture belongs to the operator's config, not to the gate).
func TestNoRedirectsNeverAssertedWithoutKnob13982(t *testing.T) {
	root, _, _ := withRedirectSysctlRoot(t, "1")
	d := &Daemon{}
	d.transitGateMu.Lock()
	writeTransitForwardSysctls(false)
	writeTransitForwardSysctls(true)
	d.transitGateMu.Unlock()
	assertKnobs(t, noRedirectKnobPaths(root), "1",
		"after gate flips on a daemon that never applied no-redirects")
}

// TestNoRedirectsDeleteRestoresKernel15710: deleting `system
// no-redirects` (applying a config without it after one with it) must
// restore the values captured when the posture was asserted, not a
// constant 1 (#16779). Pre-#16779 the restore wrote 1 everywhere,
// which under ip_forward=1 left ipv4 accept_redirects above the
// kernel router default of 0. Control: a daemon that never set the
// knob must not write over an operator's own 0s on a no-knob apply.
func TestNoRedirectsDeleteRestoresKernel15710(t *testing.T) {
	root, v4Fwd, _ := withRedirectSysctlRoot(t, "1")
	knobs := noRedirectKnobPaths(root)
	d := &Daemon{}
	d.applyKernelTuning(&config.Config{System: config.SystemConfig{NoRedirects: true}})
	assertKnobs(t, knobs, "0", "after apply with no-redirects")
	// Production steady state at delete time: the transit gate is
	// open, so ip_forward=1. The apply tail closes the gate on this
	// never-armed test daemon, so re-open it by hand to simulate
	// the gate-open moment the restore must read.
	if err := os.WriteFile(v4Fwd, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Delete the stanza: next apply has NoRedirects=false.
	// Captured values were all 1, but ipv4 accept_redirects must be
	// capped at the router default !ip_forward = 0 (#16779); the
	// other knobs restore their captured 1.
	d.applyKernelTuning(&config.Config{})
	for _, p := range knobs {
		want := "1"
		if isIPv4AcceptRedirects(p) {
			want = "0"
		}
		assertKnobs(t, []string{p}, want, "after deleting no-redirects (captured restore, ipv4 accept capped)")
	}
	// A second no-knob apply is a no-op (restore fires once, on transition).
	d.applyKernelTuning(&config.Config{})
	for _, p := range knobs {
		want := "1"
		if isIPv4AcceptRedirects(p) {
			want = "0"
		}
		assertKnobs(t, []string{p}, want, "after second no-knob apply")
	}

	// Control: never-active daemon leaves pre-existing 0s untouched.
	root2, _, _ := withRedirectSysctlRoot(t, "0")
	// withRedirectSysctlRoot resets noRedirectsActive to false.
	d2 := &Daemon{}
	d2.applyKernelTuning(&config.Config{})
	assertKnobs(t, noRedirectKnobPaths(root2), "0",
		"never-active daemon must not restore knobs it never asserted")
}

// TestR3A36NoRedirectsRestoreVsRouterDefault is the #16779 acceptance
// probe: with ip_forward=1 the set-then-delete sequence must leave
// ipv4/conf/all/accept_redirects at 0 (the kernel router default
// !ip_forward), not the constant 1 the #15710 restore wrote. A
// captured operator 0 must survive, and with ip_forward=0 a captured
// 1 is faithfully restored.
func TestR3A36NoRedirectsRestoreVsRouterDefault(t *testing.T) {
	root, v4Fwd, _ := withRedirectSysctlRoot(t, "1")
	allAccept := filepath.Join(root, "ipv4", "conf", "all", "accept_redirects")
	d := &Daemon{}
	d.applyKernelTuning(&config.Config{System: config.SystemConfig{NoRedirects: true}})
	assertKnobs(t, []string{allAccept}, "0", "after set no-redirects")
	if err := os.WriteFile(v4Fwd, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.applyKernelTuning(&config.Config{})
	assertKnobs(t, []string{allAccept}, "0",
		"after delete no-redirects under ip_forward=1 (router default)")

	// Captured operator hardening (0) is restored as 0, not raised.
	root2, v4Fwd2, _ := withRedirectSysctlRoot(t, "0")
	allAccept2 := filepath.Join(root2, "ipv4", "conf", "all", "accept_redirects")
	d2 := &Daemon{}
	d2.applyKernelTuning(&config.Config{System: config.SystemConfig{NoRedirects: true}})
	if err := os.WriteFile(v4Fwd2, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d2.applyKernelTuning(&config.Config{})
	assertKnobs(t, []string{allAccept2}, "0",
		"captured operator 0 restored under ip_forward=1")

	// With ip_forward=0 a captured 1 restores faithfully to 1.
	root3, v4Fwd3, _ := withRedirectSysctlRoot(t, "1")
	if err := os.WriteFile(v4Fwd3, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	allAccept3 := filepath.Join(root3, "ipv4", "conf", "all", "accept_redirects")
	d3 := &Daemon{}
	d3.applyKernelTuning(&config.Config{System: config.SystemConfig{NoRedirects: true}})
	// Gate tail already leaves ip_forward=0 on this never-armed daemon.
	d3.applyKernelTuning(&config.Config{})
	assertKnobs(t, []string{allAccept3}, "1",
		"captured 1 restored when ip_forward=0")

}

// TestNoRedirectsRestorePreservesForeignHardening16779 pins the
// capture half of #16779: per-path values that differ (foreign
// sysctl.d hardening, e.g. send_redirects=0 on one interface only)
// are restored per path, not flattened to a constant.
func TestNoRedirectsRestorePreservesForeignHardening16779(t *testing.T) {
	root, v4Fwd, _ := withRedirectSysctlRoot(t, "1")
	// Foreign hardening: ipv4 send on r0 = 0, ipv6 accept on r0 = 0,
	// everything else 1. ip_forward is re-opened by hand before the
	// delete apply (the tail closes it on this never-armed daemon).
	seed := func(p, v string) {
		if err := os.WriteFile(p, []byte(v+"\n"), 0o644); err != nil {
			t.Fatalf("seed %s: %v", p, err)
		}
	}
	r0Send := filepath.Join(root, "ipv4", "conf", "r0", "send_redirects")
	r0V6Accept := filepath.Join(root, "ipv6", "conf", "r0", "accept_redirects")
	seed(r0Send, "0")
	seed(r0V6Accept, "0")
	d := &Daemon{}
	d.applyKernelTuning(&config.Config{System: config.SystemConfig{NoRedirects: true}})
	assertKnobs(t, noRedirectKnobPaths(root), "0", "after set no-redirects")
	if err := os.WriteFile(v4Fwd, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d.applyKernelTuning(&config.Config{})
	assertKnobs(t, []string{r0Send}, "0", "foreign send_redirects=0 preserved")
	assertKnobs(t, []string{r0V6Accept}, "0", "foreign ipv6 accept=0 preserved")
	// Untouched-by-foreign paths restore captured 1 except ipv4
	// accept_redirects, capped at 0 under ip_forward=1.
	assertKnobs(t, []string{filepath.Join(root, "ipv4", "conf", "r0", "send_redirects")}, "0", "r0 send")
	assertKnobs(t, []string{filepath.Join(root, "ipv6", "conf", "all", "accept_redirects")}, "1", "ipv6 all restored to captured 1")
	assertKnobs(t, []string{filepath.Join(root, "ipv4", "conf", "all", "send_redirects")}, "1", "ipv4 send restored to captured 1")
}
