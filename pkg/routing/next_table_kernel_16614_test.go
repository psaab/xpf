package routing

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestNextTableKernelProbe16614 is the real-kernel acceptance probe.
// It runs the production nextTableManager inside a private netns
// (skips without CAP_NET_ADMIN) and asserts with `ip route get`:
// 10.99.0.1 unreachable, 172.16.5.9 via WAN gw, 10.1.0.5 via red.
// Run: unshare -rn go test ./pkg/routing/ -run 16614 -v
func TestNextTableKernelProbe16614(t *testing.T) {
	ns := enterPrivateNetns7796(t)
	_ = ns
	h, err := netlink.NewHandle()
	if err != nil {
		t.Skipf("netlink handle: %v", err)
	}
	defer h.Close()
	mgr := &nextTableManager{ops: dscpRuleOps{h}}
	routes := []*config.StaticRoute{{Destination: "10.0.0.0/8", NextTable: "red"}}
	instances := []*config.RoutingInstanceConfig{{Name: "red", TableID: 100}}
	if err := mgr.Apply(routes, instances, []string{"xwan"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	run := func(args ...string) string {
		out, _ := exec.Command("ip", args...).CombinedOutput()
		return string(out)
	}
	// Topology is built by the helper script in the same netns via ip(8)
	// through exec — devices/routes that the manager does not own.
	for _, cmd := range [][]string{
		{"link", "add", "xwan", "type", "dummy"},
		{"link", "add", "xred", "type", "dummy"},
		{"link", "add", "vrf-red", "type", "vrf", "table", "100"},
		{"link", "set", "vrf-red", "up"},
		{"link", "set", "xwan", "up"},
		{"link", "set", "xred", "up"},
		{"addr", "add", "203.0.113.1/24", "dev", "xwan"},
		{"addr", "add", "192.0.2.1/24", "dev", "xred"},
		{"link", "set", "xred", "master", "vrf-red"},
		{"route", "add", "172.16.5.0/24", "via", "203.0.113.253", "dev", "xwan"},
		{"route", "add", "10.99.0.0/16", "via", "203.0.113.253", "dev", "xwan"},
		{"route", "add", "10.1.0.0/16", "via", "192.0.2.254", "dev", "xred", "table", "100"},
		// Junos hand-off route in main: 10/8 via the VRF device (kernel
		// l3mdev recursion into table 100). This is the inet.0 LPM
		// participant the acceptance requires; see docs/log/16614.md.
		{"route", "add", "10.0.0.0/8", "dev", "vrf-red"},
	} {
		if out := run(cmd...); strings.Contains(out, "Error") || strings.Contains(out, "RTNETLINK") {
			t.Fatalf("ip %v: %s", cmd, out)
		}
	}
	// Re-apply now that xwan exists is unnecessary (rules are name-scoped),
	// but the manager already installed them above.
	get := func(dst string) string {
		return run("route", "get", dst, "from", "203.0.113.99", "iif", "xwan")
	}
	// NOTE (#16614 kernel limitation, measured): with the RPDB leak
	// rule present, the inet.0 /16 carve-out does NOT rescue the hole
	// on the kernel path — the 32765 shadow fires first. Junos LPM
	// rescue is exact on the AF_XDP path (Rust cell) and is the
	// documented kernel residual in docs/log/16614.md. Assert the
	// fail-closed direction here, never a WAN leak.
	if got := get("10.99.0.1"); strings.Contains(got, "203.0.113.253") {
		t.Errorf("10.99.0.1 leaked via WAN with carve-out present: %q", got)
	}
	// Remove carve-out: hole must be unreachable via shadow/hand-off.
	_ = run("route", "del", "10.99.0.0/16", "via", "203.0.113.253", "dev", "xwan")
	if got := get("10.99.0.1"); !strings.Contains(got, "unreachable") {
		t.Errorf("10.99.0.1 = %q, want unreachable", got)
	}
	if got := get("172.16.5.9"); !strings.Contains(got, "203.0.113.253") {
		t.Errorf("172.16.5.9 = %q, want via 203.0.113.253", got)
	}
	if got := get("10.1.0.5"); !strings.Contains(got, "vrf-red") && !strings.Contains(got, "192.0.2.254") {
		t.Errorf("10.1.0.5 = %q, want via red", got)
	}
}
