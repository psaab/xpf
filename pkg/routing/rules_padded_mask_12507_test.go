package routing

import (
	"fmt"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
)

// #12507 (B5): padded next-table destinations must not split the kernel
// ip-rule applier from the userspace FIB. Helper-supported padding ("/08") is
// written canonically at compile, so both install 10.0.0.0/8. Helper-refused
// padding ("/008") stays in config.StaticRouteExclusions' window count, as the
// applier counts it, so the two agree on which tail leak falls outside the
// 100-rule window. (The userspace helper then refuses the "/008" snapshot as a
// whole; see pkg/dataplane/userspace.)
func TestNextTableApplierAgreesWithExclusionsForPaddedMasks12507(t *testing.T) {
	cmds := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set routing-instances blue instance-type virtual-router",
		"set routing-options static route 10.0.0.0/08 next-table blue.inet.0",
		"set routing-options static route 11.0.0.0/008 next-table blue.inet.0",
	}
	// 2 padded + 99 canonical leaks = 101 against a 100-rule window with one
	// ingress interface: exactly the last leak is dropped.
	for i := range config.NextTableRuleWindow - 1 {
		cmds = append(cmds, fmt.Sprintf(
			"set routing-options static route 10.100.%d.0/24 next-table blue.inet.0", i))
	}
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("tolerant compile: %v", err)
	}
	if ingress := DefaultInstanceIngressIfaces(cfg); len(ingress) != 1 {
		t.Fatalf("fixture needs exactly one default-instance ingress interface, got %v", ingress)
	}

	routes := append(append([]*config.StaticRoute(nil), cfg.RoutingOptions.StaticRoutes...),
		cfg.RoutingOptions.Inet6StaticRoutes...)
	ops := newFakeRuleOps()
	nt := &nextTableManager{ops: ops}
	if err := nt.Apply(routes, cfg.RoutingInstances, DefaultInstanceIngressIfaces(cfg)); err == nil {
		t.Fatal("101 leaks over one ingress interface must overflow the 100-entry window")
	}
	installed := map[string]bool{}
	for _, rule := range ops.rules[unix.AF_INET] {
		if rule.Dst != nil {
			installed[rule.Dst.String()] = true
		}
	}

	excluded := config.StaticRouteExclusions(cfg)
	published := map[string]bool{}
	for _, route := range routes {
		if route.NextTable == "" || excluded[route] != "" {
			continue
		}
		_, dst, err := net.ParseCIDR(route.Destination)
		if err != nil {
			t.Fatalf("published leak %q does not parse: %v", route.Destination, err)
		}
		published[dst.String()] = true
	}

	for _, dst := range []string{"10.0.0.0/8", "11.0.0.0/8"} {
		if !installed[dst] || !published[dst] {
			t.Fatalf("padded leak %s: installed=%v published=%v", dst, installed[dst], published[dst])
		}
	}
	const tail = "10.100.98.0/24"
	if installed[tail] || published[tail] {
		t.Fatalf("window tail %s: installed=%v published=%v, want dropped by both", tail, installed[tail], published[tail])
	}
	if len(installed) != len(published) {
		t.Fatalf("kernel installed %d leaks, FIB publishes %d: split", len(installed), len(published))
	}
	for dst := range installed {
		if !published[dst] {
			t.Fatalf("installed leak %s is not published", dst)
		}
	}
	// The helper-supported spelling reached both layers canonically.
	for _, route := range routes {
		if route.Destination == "10.0.0.0/08" {
			t.Fatalf("compiled route kept the padded spelling %q", route.Destination)
		}
	}
}
