package daemon

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/lldp"
)

// #14617 daemon-level cells: `interface all` (+ per-interface disable)
// reaches Apply expanded at the manager; `all disable` is refused
// before Apply; a NIC appearing later under an unchanged `all` config
// re-applies via inventory comparison.

func lldpCfgIfaces14617(ifaces ...config.LLDPInterface) *config.Config {
	cfg := &config.Config{}
	cfg.Protocols.LLDP = &config.LLDPConfig{Interfaces: append([]config.LLDPInterface(nil), ifaces...)}
	return cfg
}

func installAllSeams14617(t *testing.T, present map[string]bool, inventory *[]string) {
	t.Helper()
	lldp.SetInterfaceByNameForTesting(func(name string) (*net.Interface, error) {
		if present[name] {
			return &net.Interface{Name: name}, nil
		}
		return nil, errors.New("no such interface: " + name)
	})
	lldp.SetInterfacesForTesting(func() ([]net.Interface, error) {
		var out []net.Interface
		for _, n := range *inventory {
			out = append(out, net.Interface{Name: n})
		}
		return out, nil
	})
	lldp.FailIfSessionForTesting(errors.New("injected: no CAP_NET_RAW in test"))
	t.Cleanup(func() {
		lldp.SetInterfaceByNameForTesting(nil)
		lldp.SetInterfacesForTesting(nil)
		lldp.FailIfSessionForTesting(nil)
	})
}

func TestReconcileLLDPAllExpandsMinusDisable14617(t *testing.T) {
	present := map[string]bool{"ge-0-0-0": true, "ge-0-0-1": true, "fxp0": true}
	inventory := []string{"ge-0-0-0", "ge-0-0-1", "fxp0"}
	installAllSeams14617(t, present, &inventory)
	d, _ := lldpDaemonFor14617(t)
	cfg := lldpCfgIfaces14617(
		config.LLDPInterface{Name: "all"},
		config.LLDPInterface{Name: "fxp0", Disable: true},
	)
	d.reconcileLLDP(cfg)
	if len(d.lldpUnresolved) != 0 {
		t.Fatalf("all-minus-disable must converge, unresolved=%v", d.lldpUnresolved)
	}
	if got := d.lldpMgr.ApplyCount(); got != 1 {
		t.Fatalf("ApplyCount=%d want 1", got)
	}
	// Unchanged commit must not bounce (inventory unchanged).
	d.reconcileLLDP(cfg)
	if got := d.lldpMgr.ApplyCount(); got != 1 {
		t.Fatalf("unchanged all commit re-applied: ApplyCount=%d want 1", got)
	}
	// A NIC appears: unchanged config must re-apply once.
	present["ge-0-0-2"] = true
	inventory = append(inventory, "ge-0-0-2")
	d.reconcileLLDP(cfg)
	if got := d.lldpMgr.ApplyCount(); got != 2 {
		t.Fatalf("late NIC under all must re-apply: ApplyCount=%d want 2", got)
	}
}

func TestReconcileLLDPAllDisableRefused14617(t *testing.T) {
	present := map[string]bool{"ge-0-0-0": true}
	inventory := []string{"ge-0-0-0"}
	installAllSeams14617(t, present, &inventory)
	d, _ := lldpDaemonFor14617(t)
	if got, ok := effectiveLLDPConfigChecked(lldpCfgIfaces14617(config.LLDPInterface{Name: "all", Disable: true})); ok || got != nil {
		t.Fatalf("all+disable must be refused, got=%v ok=%v", got, ok)
	}
	d.reconcileLLDP(lldpCfgIfaces14617(config.LLDPInterface{Name: "all", Disable: true}))
	if got := d.lldpMgr.ApplyCount(); got != 0 {
		t.Fatalf("refused all-disable must never Apply, ApplyCount=%d", got)
	}
}

func lldpDaemonFor14617(t *testing.T) (*Daemon, map[string]bool) {
	t.Helper()
	// Reuse the #6794 harness shape but with our own seams installed by caller.
	mgr := lldp.New()
	t.Cleanup(mgr.Stop)
	return &Daemon{lldpMgr: mgr, daemonCtx: context.Background()}, nil
}
