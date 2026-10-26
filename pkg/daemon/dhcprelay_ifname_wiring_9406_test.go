package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcprelay"
)

// #9406 wiring. pkg/dhcprelay can resolve bind names perfectly and the box
// still relays nothing if the daemon never installs the resolver: a nil
// resolver is deliberately IDENTITY so this package's ~50 direct Apply callers
// keep working, and identity is exactly the defect — `ge-0/0/0.0` handed
// straight to SO_BINDTODEVICE, which finds no device, forever, silently.

func relayCfgText9406() string {
	return `
interfaces {
    ge-0/0/0 {
        vlan-tagging;
        unit 80 { vlan-id 180; family inet { address 10.0.80.1/24; } }
    }
}
forwarding-options {
    dhcp-relay {
        server-group isp { 192.0.2.1; }
        group g1 { active-server-group isp; interface ge-0/0/0.80; }
    }
}
`
}

// TestReconcileDHCPRelayWiresIfNameResolver9406 asserts what the relay ACTUALLY
// BOUND, read back off the exported Stats surface, rather than that some setter
// was called. `ge-0/0/0.80` must reach the kernel as `ge-0-0-0.180`: unit 80
// carries `vlan-id 180`, so a resolver missing that arm (#5107) names the wrong
// VLAN device while looking entirely plausible.
func TestReconcileDHCPRelayWiresIfNameResolver9406(t *testing.T) {
	tree, perrs := config.NewParser(relayCfgText9406()).Parse()
	if len(perrs) > 0 {
		t.Fatalf("fixture must parse: %v", perrs)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("fixture must compile: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d := &Daemon{daemonCtx: ctx}
	d.dhcpRelay = dhcprelay.NewManager()
	defer d.dhcpRelay.Stop()

	d.reconcileDHCPRelay(cfg)

	stats := d.dhcpRelay.Stats()
	if len(stats) != 1 {
		t.Fatalf("Stats() = %+v, want one relay row", stats)
	}
	if stats[0].Interface != "ge-0/0/0.80" {
		t.Errorf("Interface = %q, want the authored reference — that identity is "+
			"what relayInterfaceRG parses to find the owning redundancy group",
			stats[0].Interface)
	}
	if got, want := stats[0].KernelInterface, "ge-0-0-0.180"; got != want {
		t.Fatalf("bound device = %q, want %q. reconcileDHCPRelay must install "+
			"cfg.ResolveKernelIfName before Apply; without it the relay binds the "+
			"authored reference, which is not a device — no listener, no giaddr, "+
			"nothing relayed, on a green commit (#9406).", got, want)
	}
}

// TestDHCPRelayApplyHasOneProductionCallSite9406 pins the collapse that makes
// the wire above sufficient.
//
// Before #9406 the boot path (daemon_run.go) called Manager.Apply directly and
// the day-2 path called it through reconcileDHCPRelay — two places to remember
// the resolver, and the BOOT one is the one that matters, because a box that
// boots with a relay already configured never sees a commit. Boot now routes
// through reconcileDHCPRelay, so there is one site. A second one reintroduces
// exactly the class of bug this issue is.
func TestDHCPRelayApplyHasOneProductionCallSite9406(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join("..", "..")
	var sites []string
	err := filepath.WalkDir(filepath.Join(repoRoot, "pkg"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		// pkg/dhcprelay defines Apply; only its CALLERS are in scope.
		rel, rerr := filepath.Rel(repoRoot, path)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if strings.HasPrefix(rel, "pkg/dhcprelay/") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.Contains(line, "dhcpRelay.Apply(") {
				sites = append(sites, rel+":"+itoa(i+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// Non-vacuity: zero sites would satisfy "at most one" while measuring
	// nothing — which is how a guard keyed on a renamed symbol goes green.
	if len(sites) != 1 {
		t.Fatalf("dhcpRelay.Apply called from %d production sites: %v\n"+
			"There must be exactly ONE, inside reconcileDHCPRelay, which installs "+
			"the #9406 interface-name resolver immediately before Apply. A second "+
			"call site is a second place to forget it, and the relay then binds "+
			"the authored Junos reference — which is not a kernel device.",
			len(sites), sites)
	}
	if !strings.HasPrefix(sites[0], "pkg/daemon/daemon_apply_tail.go:") {
		t.Fatalf("the sole dhcpRelay.Apply call site is %s, want it inside "+
			"reconcileDHCPRelay (pkg/daemon/daemon_apply_tail.go)", sites[0])
	}
}
