package routing

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestNextTableDynamicCarveoutKernel17971 is the real-RPDB evidence for
// #17971 acceptance cases (a)-(d): a learned (non-configured) main route
// more specific than the leak must win over a target hit, a broad terminal
// main default must not shadow the target, a target miss must end at the
// unreachable shadow, and plain main destinations stay in main. The learned
// row exists ONLY in the kernel main table; the manager learns about it
// through the same ImportLearnedRoutes dump production uses.
// Run: unshare -rn go test ./pkg/routing/ -run 17971 -v
func TestNextTableDynamicCarveoutKernel17971(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "ipv4"
		if ipv6 {
			name = "ipv6"
		}
		t.Run(name, func(t *testing.T) {
			runNextTableDynamicCarveoutKernelCell17971(t, ipv6)
		})
	}
}

func runNextTableDynamicCarveoutKernelCell17971(t *testing.T, ipv6 bool) {
	t.Helper()
	_ = enterPrivateNetns7796(t)
	h, err := netlink.NewHandle()
	if err != nil {
		t.Skipf("netlink handle: %v", err)
	}
	defer h.Close()

	leakPrefix, learnedPrefix, targetHit, learnedHit, controlDst, source, address := "198.19.0.0/16", "198.19.0.0/24", "198.19.1.1", "198.19.0.1", "172.16.5.9", "203.0.113.99", "203.0.113.1/24"
	learnedGateway, controlPrefix := "203.0.113.2", "172.16.0.0/16"
	if ipv6 {
		leakPrefix, learnedPrefix, targetHit, learnedHit, controlDst, source, address = "2001:db8:19::/48", "2001:db8:19::/64", "2001:db8:19:1::1", "2001:db8:19::1", "2001:db8:172::5", "2001:db8:ffff::99", "2001:db8:ffff::1/64"
		learnedGateway, controlPrefix = "2001:db8:ffff::2", "2001:db8:172::/48"
	}
	routes := []*config.StaticRoute{{Destination: leakPrefix, NextTable: "red"}}
	instances := []*config.RoutingInstanceConfig{{Name: "red", TableID: 100}}
	mgr := &nextTableManager{ops: dscpRuleOps{h}, mainRoutes: importMainLearnedRoutes}
	if err := mgr.Apply(routes, instances, []string{"xwan"}); err != nil {
		t.Fatalf("Apply before learned route exists: %v", err)
	}

	run := func(args ...string) (string, error) {
		if ipv6 {
			args = append([]string{"-6"}, args...)
		}
		out, err := exec.Command("ip", args...).CombinedOutput()
		return string(out), err
	}
	for _, cmd := range [][]string{
		{"link", "add", "xwan", "type", "dummy"},
		{"link", "add", "xred", "type", "dummy"},
		{"link", "set", "xwan", "up"},
		{"link", "set", "xred", "up"},
		{"addr", "add", address, "dev", "xwan"},
		{"route", "add", "blackhole", "default"},
		{"route", "add", leakPrefix, "dev", "xred", "table", "100"},
		{"route", "add", controlPrefix, "dev", "xwan"},
	} {
		if out, err := run(cmd...); err != nil {
			t.Fatalf("ip %v: %s: %v", cmd, out, err)
		}
	}
	// The learned main route: installed directly in the kernel (as BGP or
	// an operator would), never present in the config route list.
	if out, err := run("route", "add", learnedPrefix, "via", learnedGateway, "dev", "xwan", "proto", "bgp"); err != nil {
		t.Fatalf("add learned main route: %s: %v", out, err)
	}
	// Churn refresh: the route listener's actuation path.
	if err := mgr.RefreshCarveouts(routes, instances, []string{"xwan"}); err != nil {
		t.Fatalf("RefreshCarveouts: %v", err)
	}
	rules, err := h.RuleList(map[bool]int{false: unix.AF_INET, true: unix.AF_INET6}[ipv6])
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	found := false
	for _, rule := range rules {
		if isNextTableMainCarveoutShape(rule) && rule.Dst.String() == learnedPrefix {
			found = true
		}
	}
	if !found {
		t.Fatalf("no dynamic carve-out rule for learned prefix %s in %+v", learnedPrefix, rules)
	}

	get := func(destination string) string {
		out, _ := run("route", "get", destination, "from", source, "iif", "xwan")
		return out
	}
	// (a) Broad terminal main default + target hit outside the learned
	// prefix: the target still wins.
	if got := get(targetHit); !strings.Contains(got, "dev xred") {
		t.Errorf("broad-terminal target hit = %q, want target table via xred", got)
	}
	// (b) More-specific learned main route + target hit: main wins.
	if got := get(learnedHit); !strings.Contains(got, "dev xwan") || strings.Contains(got, "dev xred") {
		t.Errorf("learned carve-out hit = %q, want main route via xwan", got)
	}
	// (d) Plain main destination outside the leak: main, untouched.
	if got := get(controlDst); !strings.Contains(got, "dev xwan") {
		t.Errorf("no-leak control = %q, want main route via xwan", got)
	}
	// Withdraw the learned route and refresh: the exception must go, and
	// the destination falls back to the target hit.
	if out, err := run("route", "del", learnedPrefix, "via", learnedGateway, "dev", "xwan"); err != nil {
		t.Fatalf("withdraw learned route: %s: %v", out, err)
	}
	if err := mgr.RefreshCarveouts(routes, instances, []string{"xwan"}); err != nil {
		t.Fatalf("RefreshCarveouts after withdrawal: %v", err)
	}
	if got := get(learnedHit); !strings.Contains(got, "dev xred") {
		t.Errorf("withdrawn learned route = %q, want target table via xred again", got)
	}
	// (c) Target miss + broad terminal main: the unreachable shadow ends
	// the walk instead of the main default or a fall-through.
	if out, err := run("route", "del", leakPrefix, "dev", "xred", "table", "100"); err != nil {
		t.Fatalf("remove target route: %s: %v", out, err)
	}
	if got := strings.ToLower(get(targetHit)); !strings.Contains(got, "unreachable") {
		t.Errorf("target miss with broad terminal = %q, want terminal unreachable shadow", got)
	}
}
