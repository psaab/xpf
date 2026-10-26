package routing

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// TestNextTableKernelProbe16614 uses the real RPDB in a private netns. A
// narrower target-table miss must stop before a broad next-table rule, while
// the configured /24 main-table exception remains reachable.
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
		{Destination: "10.99.0.0/24", NextHops: []config.NextHopEntry{{Interface: "xwan"}}},
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

func TestNextTableTerminalDefaultsAndCarveouts17970(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, terminal := range []string{"blackhole", "unreachable"} {
			t.Run(family+"/"+terminal, func(t *testing.T) {
				runNextTableTerminalDefaultCell17970(t, family == "ipv6", terminal)
			})
		}
	}
}

func runNextTableTerminalDefaultCell17970(t *testing.T, ipv6 bool, terminal string) {
	t.Helper()
	_ = enterPrivateNetns7796(t)
	h, err := netlink.NewHandle()
	if err != nil {
		t.Skipf("netlink handle: %v", err)
	}
	defer h.Close()

	var routes []*config.StaticRoute
	var leakPrefix, carveoutPrefix, controlPrefix, target, controlDst, source string
	if ipv6 {
		leakPrefix = "2001:db8:16::/48"
		carveoutPrefix = "2001:db8:16::/64"
		controlPrefix = "2001:db8:172::/48"
		target = "2001:db8:16::/48"
		controlDst = "2001:db8:172::5"
		source = "2001:db8:ffff::99"
		routes = []*config.StaticRoute{
			{Destination: leakPrefix, NextTable: "red"},
			{Destination: carveoutPrefix, NextHops: []config.NextHopEntry{{Interface: "xwan"}}},
			{Destination: "::/0", Reject: terminal == "unreachable", Discard: terminal == "blackhole"},
			{Destination: controlPrefix},
		}
	} else {
		leakPrefix = "198.18.0.0/16"
		carveoutPrefix = "198.18.0.0/24"
		controlPrefix = "172.16.0.0/16"
		target = "198.18.0.0/16"
		controlDst = "172.16.5.9"
		source = "203.0.113.99"
		routes = []*config.StaticRoute{
			{Destination: leakPrefix, NextTable: "red"},
			{Destination: carveoutPrefix, NextHops: []config.NextHopEntry{{Interface: "xwan"}}},
			{Destination: "0.0.0.0/0", Reject: terminal == "unreachable", Discard: terminal == "blackhole"},
			{Destination: controlPrefix},
		}
	}
	mgr := &nextTableManager{ops: dscpRuleOps{h}}
	if err := mgr.Apply(routes, []*config.RoutingInstanceConfig{{Name: "red", TableID: 100}}, []string{"xwan"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}

	run := func(args ...string) (string, error) {
		out, err := exec.Command("ip", args...).CombinedOutput()
		return string(out), err
	}
	runFamily := func(args ...string) (string, error) {
		if ipv6 {
			args = append([]string{"-6"}, args...)
		}
		return run(args...)
	}
	for _, cmd := range [][]string{
		{"link", "add", "xwan", "type", "dummy"},
		{"link", "add", "xred", "type", "dummy"},
		{"link", "set", "xwan", "up"},
		{"link", "set", "xred", "up"},
	} {
		if out, err := run(cmd...); err != nil {
			t.Fatalf("ip %v: %s: %v", cmd, out, err)
		}
	}
	address := "203.0.113.1/24"
	if ipv6 {
		address = "2001:db8:ffff::1/64"
	}
	if out, err := runFamily("addr", "add", address, "dev", "xwan"); err != nil {
		t.Fatalf("ip addr add %s: %s: %v", address, out, err)
	}
	if out, err := runFamily("route", "add", terminal, "default"); err != nil {
		t.Fatalf("ip route add %s default: %s: %v", terminal, out, err)
	}
	for _, cmd := range [][]string{
		{"route", "add", target, "dev", "xred", "table", "100"},
		{"route", "add", carveoutPrefix, "dev", "xwan"},
		{"route", "add", controlPrefix, "dev", "xwan"},
	} {
		if out, err := runFamily(cmd...); err != nil {
			t.Fatalf("ip %v: %s: %v", cmd, out, err)
		}
	}

	get := func(destination string) string {
		args := []string{"route", "get", destination, "from", source, "iif", "xwan"}
		out, _ := runFamily(args...)
		return out
	}
	// Broad blackhole/unreachable defaults must not shadow a more-specific
	// target-table hit. The destination is inside the leak but outside its /24
	// main-table exception.
	targetHit := "198.18.1.1"
	carveoutHit := "198.18.0.1"
	if ipv6 {
		targetHit = "2001:db8:16:1::1"
		carveoutHit = "2001:db8:16::1"
	}
	if got := get(targetHit); !strings.Contains(got, "dev xred") {
		t.Errorf("%s broad-terminal target hit = %q, want target table via xred", familyName17970(ipv6), got)
	}
	if got := get(carveoutHit); !strings.Contains(got, "dev xwan") {
		t.Errorf("%s carve-out with target hit = %q, want main route via xwan", familyName17970(ipv6), got)
	}
	if out, err := runFamily("route", "del", carveoutPrefix, "dev", "xwan"); err != nil {
		t.Fatalf("withdraw main carve-out route: %s: %v", out, err)
	}
	// The config exception remains while an external runtime withdrawal
	// removes its main route. The main lookup then returns the broad terminal
	// default; fail closed instead of letting the leak resurrect that dst.
	if got := get(carveoutHit); !strings.Contains(got, "RTNETLINK answers:") || strings.Contains(got, "dev xred") {
		t.Errorf("%s withdrawn main carve-out = %q, want the main-table terminal error (no target rescue)",
			familyName17970(ipv6), got)
	}
	if out, err := runFamily("route", "add", carveoutPrefix, "dev", "xwan"); err != nil {
		t.Fatalf("restore main carve-out route: %s: %v", out, err)
	}
	if out, err := runFamily("route", "del", target, "dev", "xred", "table", "100"); err != nil {
		t.Fatalf("remove target route: %s: %v", out, err)
	}
	if got := get(carveoutHit); !strings.Contains(got, "dev xwan") {
		t.Errorf("%s carve-out with target miss = %q, want main route via xwan", familyName17970(ipv6), got)
	}
	if got := strings.ToLower(get(targetHit)); !strings.Contains(got, "unreachable") {
		t.Errorf("%s target miss without carve-out = %q, want terminal unreachable shadow", familyName17970(ipv6), got)
	}
	if got := get(controlDst); !strings.Contains(got, "dev xwan") {
		t.Errorf("%s no-leak control = %q, want main route via xwan", familyName17970(ipv6), got)
	}
}

func familyName17970(ipv6 bool) string {
	if ipv6 {
		return "IPv6"
	}
	return "IPv4"
}

func TestNextTableFRROmittedStaticDoesNotCreateCarveout17970(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		t.Run(familyName17970(ipv6), func(t *testing.T) {
			runNextTableExcludedStaticCell17970(t, ipv6)
		})
	}
}

func runNextTableExcludedStaticCell17970(t *testing.T, ipv6 bool) {
	t.Helper()
	_ = enterPrivateNetns7796(t)
	h, err := netlink.NewHandle()
	if err != nil {
		t.Skipf("netlink handle: %v", err)
	}
	defer h.Close()

	leakPrefix, malformedPrefix, validPrefix := "198.20.0.0/16", "198.20.1.0/24", "198.20.2.0/24"
	source, malformedDestination, validDestination, address := "203.0.113.99", "198.20.1.5", "198.20.2.5", "203.0.113.1/24"
	malformedGateway, validGateway := "192.0.2.999", "203.0.113.2"
	family := unix.AF_INET
	if ipv6 {
		leakPrefix, malformedPrefix, validPrefix = "2001:db8:20::/48", "2001:db8:20:1::/64", "2001:db8:20:2::/64"
		source, malformedDestination, validDestination, address = "2001:db8:ffff::99", "2001:db8:20:1::5", "2001:db8:20:2::5", "2001:db8:ffff::1/64"
		malformedGateway, validGateway = "2001:db8::gg", "2001:db8:ffff::2"
		family = unix.AF_INET6
	}
	mgr := &nextTableManager{ops: dscpRuleOps{h}}
	routes := []*config.StaticRoute{
		{Destination: leakPrefix, NextTable: "red"},
		{Destination: malformedPrefix, NextHops: []config.NextHopEntry{{Address: malformedGateway}}},
		{Destination: validPrefix, NextHops: []config.NextHopEntry{
			{Address: malformedGateway},
			{Address: validGateway},
		}},
		{Destination: "0.0.0.0/0", Discard: true},
	}
	if ipv6 {
		routes[3] = &config.StaticRoute{Destination: "::/0", Discard: true}
	}
	if err := mgr.Apply(routes, []*config.RoutingInstanceConfig{{Name: "red", TableID: 100}}, []string{"xwan"}); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	rules, err := h.RuleList(family)
	if err != nil {
		t.Fatalf("list rules: %v", err)
	}
	malformedException, validECMPException := false, false
	for _, rule := range rules {
		if !isNextTableMainCarveoutShape(rule) {
			continue
		}
		switch rule.Dst.String() {
		case malformedPrefix:
			malformedException = true
		case validPrefix:
			validECMPException = true
		}
	}
	if malformedException {
		t.Fatalf("FRR-omitted static %s created a main exception", malformedPrefix)
	}
	if !validECMPException {
		t.Fatalf("valid ECMP member did not keep main exception for %s", validPrefix)
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
	} {
		if out, err := run(cmd...); err != nil {
			t.Fatalf("ip %v: %s: %v", cmd, out, err)
		}
	}
	if out, err := run("addr", "add", address, "dev", "xwan"); err != nil {
		t.Fatalf("add source address: %s: %v", out, err)
	}
	if out, err := run("route", "add", "blackhole", "default"); err != nil {
		t.Fatalf("add broad blackhole default: %s: %v", out, err)
	}
	if out, err := run("route", "add", leakPrefix, "dev", "xred", "table", "100"); err != nil {
		t.Fatalf("add target-table route: %s: %v", out, err)
	}
	if out, err := run("route", "add", validPrefix, "via", validGateway, "dev", "xwan"); err != nil {
		t.Fatalf("add valid ECMP main route: %s: %v", out, err)
	}
	get := func(destination string) string {
		out, _ := run("route", "get", destination, "from", source, "iif", "xwan")
		return out
	}
	if got := get(malformedDestination); !strings.Contains(got, "dev xred") {
		t.Errorf("FRR-omitted static with target hit = %q, want target table via xred", got)
	}
	if got := get(validDestination); !strings.Contains(got, "dev xwan") {
		t.Errorf("valid ECMP static with target hit = %q, want main route via xwan", got)
	}
	if out, err := run("route", "del", leakPrefix, "dev", "xred", "table", "100"); err != nil {
		t.Fatalf("remove target-table route: %s: %v", out, err)
	}
	if got := strings.ToLower(get(malformedDestination)); !strings.Contains(got, "unreachable") {
		t.Errorf("FRR-omitted static with target miss = %q, want the next-table unreachable shadow", got)
	}
}
