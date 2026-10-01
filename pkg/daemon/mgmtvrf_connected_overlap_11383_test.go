package daemon

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
)

func TestMgmtVRFClasslessMgmtConnectedOverlapSuppressed11383(t *testing.T) {
	fake := &fakeMgmtProgrammer{
		links: map[string]int{"fxp0": 7},
		v4:    []netlink.Route{connectedRoute11362(t, "192.0.2.0/24", 7)},
	}
	lease := classlessLease9943("192.0.2.42/32", "192.0.2.128/25", "198.51.100.0/24")
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	t.Setenv(dhcpClasslessTrustOverrideEnv, "")

	if err := (&Daemon{}).applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	got := replacedDestinations9943(fake.replaced)
	for _, dst := range []string{"192.0.2.42/32", "192.0.2.128/25"} {
		if got[dst] != 0 {
			t.Errorf("classless route %s inside management connected prefix reached RouteReplace: %v", dst, got)
		}
	}
	if got["198.51.100.0/24"] != 1 {
		t.Errorf("unrelated classless route must install exactly once: %v", got)
	}
	for _, want := range []string{
		"SECURITY: suppressing management-VRF DHCP classless route inside a connected subnet (#11383)",
		"connected_prefix=192.0.2.0/24",
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("connected-overlap alarm missing %q: %s", want, logs.String())
		}
	}
}

func TestMgmtVRFClasslessMgmtConnectedTrustOverrideWarns11383(t *testing.T) {
	fake := &fakeMgmtProgrammer{
		links: map[string]int{"fxp0": 7},
		v4:    []netlink.Route{connectedRoute11362(t, "192.0.2.0/24", 7)},
	}
	lease := classlessLease9943("192.0.2.42/32", "198.51.100.0/24")
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	t.Setenv(dhcpClasslessTrustOverrideEnv, "1")

	if err := (&Daemon{}).applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	got := replacedDestinations9943(fake.replaced)
	for _, dst := range []string{"192.0.2.42/32", "198.51.100.0/24"} {
		if got[dst] != 1 {
			t.Errorf("trust override must install classless route %s exactly once: %v", dst, got)
		}
	}
	for _, want := range []string{
		"SECURITY: DHCP classless trust override allows a route inside a connected subnet (#11383)",
		"env=" + dhcpClasslessTrustOverrideEnv,
		"connected_prefix=192.0.2.0/24",
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("trust-override alarm missing %q: %s", want, logs.String())
		}
	}
}
