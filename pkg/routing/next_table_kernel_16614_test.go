package routing

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
)

// TestNextTableKernelProbe16614 uses the real RPDB in a private netns. A
// narrower target-table miss must stop before a broad next-table rule, while
// a still-more-specific main-table carve-out remains reachable.
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
	routes := []*config.StaticRoute{
		{Destination: "10.0.0.0/8", NextTable: "red"},
		{Destination: "10.99.0.0/16", NextTable: "black"},
	}
	instances := []*config.RoutingInstanceConfig{
		{Name: "red", TableID: 100},
		{Name: "black", TableID: 101},
	}
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
		{"route", "add", "10.99.0.0/24", "via", "203.0.113.253", "dev", "xwan"},
		{"route", "add", "10.0.0.0/8", "via", "192.0.2.254", "dev", "xred", "table", "100"},
		{"route", "add", "10.99.0.0/16", "via", "192.0.2.254", "dev", "xred", "table", "101"},
	} {
		if out := run(cmd...); strings.Contains(out, "Error") || strings.Contains(out, "RTNETLINK") {
			t.Fatalf("ip %v: %s", cmd, out)
		}
	}
	get := func(dst string) string {
		return run("route", "get", dst, "from", "203.0.113.99", "iif", "xwan")
	}
	// A /24 main route beats the /16 config target both when that target
	// contains a covering route and when it misses.
	if got := get("10.99.0.1"); !strings.Contains(got, "203.0.113.253") {
		t.Errorf("10.99.0.1 with target coverage = %q, want main-table carve-out via WAN", got)
	}
	if out := run("route", "del", "10.99.0.0/16", "via", "192.0.2.254", "dev", "xred", "table", "101"); strings.Contains(out, "RTNETLINK") {
		t.Fatalf("remove black target route: %s", out)
	}
	if got := get("10.99.0.1"); !strings.Contains(got, "203.0.113.253") {
		t.Errorf("10.99.0.1 with target miss = %q, want main-table carve-out via WAN", got)
	}
	// Without the main carve-out, the /16 target miss must stop instead of
	// falling through to the broad /8 target route in table 100.
	if out := run("route", "del", "10.99.0.0/24", "via", "203.0.113.253", "dev", "xwan"); strings.Contains(out, "RTNETLINK") {
		t.Fatalf("remove main carve-out: %s", out)
	}
	if got := get("10.99.0.1"); !strings.Contains(got, "unreachable") {
		t.Errorf("10.99.0.1 = %q, want terminal unreachable on the /16 target miss", got)
	}
	// The broader /8 target remains the control for destinations outside /16.
	if got := get("10.2.0.5"); !strings.Contains(got, "192.0.2.254") {
		t.Errorf("10.2.0.5 = %q, want broad /8 target via red", got)
	}
	if got := get("172.16.5.9"); !strings.Contains(got, "203.0.113.253") {
		t.Errorf("172.16.5.9 = %q, want via 203.0.113.253", got)
	}
}
