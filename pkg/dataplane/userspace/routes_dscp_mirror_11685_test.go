package userspace

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"syscall"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

// TestBuildRouteSnapshotsDoesNotWidenForeignDSCPRule11685 is the fast-path
// half of the slow/fast parity cell. The slow kernel rule has FRA_DSCP=46,
// which matches only packets whose DiffServ code point is 46; netlink.RuleList
// hides FRA_DSCP and returns a destination-only Rule. The userspace FIB must
// not turn that incomplete readback into an unconditional NextTable leak.
func TestBuildRouteSnapshotsDoesNotWidenForeignDSCPRule11685(t *testing.T) {
	oldRules, oldDSCPSelectors := ruleListFn, ruleDSCPSelectorsFn
	t.Cleanup(func() {
		ruleListFn, ruleDSCPSelectorsFn = oldRules, oldDSCPSelectors
	})

	const tableID = 100
	const priority = 30016 // Outside both the current and legacy PBR bands.
	_, dst, err := net.ParseCIDR("198.51.100.0/24")
	if err != nil {
		t.Fatal(err)
	}
	ruleListFn = func(family int) ([]netlink.Rule, error) {
		if family == syscall.AF_INET {
			// This is exactly what netlink.RuleList reports for a kernel rule
			// carrying FRA_DSCP: Tos remains zero and no DSCP field exists.
			return []netlink.Rule{{Priority: priority, Dst: dst, Table: tableID}}, nil
		}
		return nil, nil
	}
	ruleDSCPSelectorsFn = func(family int) ([]routing.RuleDSCPSelector, error) {
		if family == syscall.AF_INET {
			return []routing.RuleDSCPSelector{{
				Priority: priority,
				Table:    tableID,
				Dst:      dst.String(),
				DSCP:     46,
			}}, nil
		}
		return nil, nil
	}

	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	cfg := &config.Config{}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "blue", TableID: tableID}}
	routes, _, err := buildRouteSnapshots(cfg, nil, nil)
	if err != nil {
		t.Fatalf("buildRouteSnapshots: %v", err)
	}
	for _, route := range routes {
		if route.Table == "inet.0" && route.Destination == dst.String() && route.NextTable == "blue.inet.0" {
			t.Fatalf("foreign DSCP-scoped kernel rule was widened into an unconditional NextTable leak: %+v", route)
		}
	}
	if output := logs.String(); !strings.Contains(output, "11685") ||
		!strings.Contains(output, "dscp=46") ||
		!strings.Contains(output, "priority=30016") {
		t.Fatalf("skipped DSCP-scoped rule lacks a diagnostic naming its scope: %q", output)
	}
}
