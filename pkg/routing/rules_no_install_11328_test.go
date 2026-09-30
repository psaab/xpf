package routing

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sys/unix"
)

func TestNoInstallNextTableDoesNotInstallPolicyRule11328(t *testing.T) {
	ops := newFakeRuleOps()
	manager := &nextTableManager{ops: ops}
	routes := []*config.StaticRoute{{
		Destination: "10.99.0.0/16",
		NextTable:   "blue",
		NoInstall:   true,
	}}
	instances := []*config.RoutingInstanceConfig{{Name: "blue", TableID: 101}}

	if err := manager.Apply(routes, instances, nil); err != nil {
		t.Fatalf("Apply without an installable route should succeed: %v", err)
	}
	if got := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); got != 0 {
		t.Fatalf("installed %d next-table rules for a no-install route", got)
	}

	// A normal next-table route remains installable and still uses the same
	// fail-closed ingress requirement as before.
	routes[0].NoInstall = false
	if err := manager.Apply(routes, instances, nil); err == nil {
		t.Fatal("ordinary next-table route with no ingress interface must retain the fail-closed error")
	}
	if got := ops.count(unix.AF_INET) + ops.count(unix.AF_INET6); got != 0 {
		t.Fatalf("no-ingress control unexpectedly installed %d rules", got)
	}
}
