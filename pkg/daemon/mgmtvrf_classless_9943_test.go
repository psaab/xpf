package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func operatorRouteWithProtocol9943(t *testing.T, cidr string, protocol netlink.RouteProtocol) netlink.Route {
	t.Helper()
	_, dst, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return netlink.Route{
		Dst:      dst,
		Family:   netlink.FAMILY_V4,
		Protocol: protocol,
		Table:    mgmtVRFTableID,
	}
}

func operatorRoute9943(t *testing.T, cidr string) netlink.Route {
	return operatorRouteWithProtocol9943(t, cidr, unix.RTPROT_STATIC)
}

func classlessLease9943(routes ...string) *dhcp.Lease {
	classless := make([]dhcp.LeaseRoute, 0, len(routes))
	for _, route := range routes {
		classless = append(classless, dhcp.LeaseRoute{
			Destination: netip.MustParsePrefix(route),
			Gateway:     netip.MustParseAddr("192.0.2.1"),
		})
	}
	return &dhcp.Lease{
		Interface:       "fxp0",
		Family:          dhcp.AFInet,
		ClasslessRoutes: classless,
	}
}

func replacedDestinations9943(replaced []*netlink.Route) map[string]int {
	got := make(map[string]int)
	for _, route := range replaced {
		if route.Dst == nil {
			got["0.0.0.0/0"]++
			continue
		}
		got[route.Dst.String()]++
	}
	return got
}

// The filed attack in the management-VRF twin: an operator static default
// covers both halves of a rogue option-121 /1 pair, so neither learned route
// may reach RouteReplace.
func TestMgmtVRFClasslessCoveredByStaticDefaultSuppressed_9943(t *testing.T) {
	fake := &fakeMgmtProgrammer{
		v4:      []netlink.Route{operatorRoute9943(t, "0.0.0.0/0")},
		linkIdx: 7,
	}
	lease := classlessLease9943("0.0.0.0/1", "128.0.0.0/1")
	lease.Gateway = netip.MustParseAddr("192.0.2.254")
	var d Daemon
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "")
	if err := d.applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	got := replacedDestinations9943(fake.replaced)
	if got["0.0.0.0/0"] != 0 {
		t.Fatalf("static default must suppress the learned DHCP default: %v", got)
	}
	if got["0.0.0.0/1"] != 0 || got["128.0.0.0/1"] != 0 {
		t.Fatalf("rogue /1 pair reached RouteReplace despite static default: %v", got)
	}
	if len(got) != 0 {
		t.Fatalf("all learned classless routes must be suppressed by static default: %v", got)
	}
}

// General containment, not a /1 special case: a learned /9 over an operator
// /8 is suppressed while a route outside that /8 remains installable.
func TestMgmtVRFClasslessCoveredByStaticPrefixSuppressed_9943(t *testing.T) {
	fake := &fakeMgmtProgrammer{
		v4:      []netlink.Route{operatorRoute9943(t, "10.0.0.0/8")},
		linkIdx: 7,
	}
	lease := classlessLease9943("10.0.0.0/9", "10.128.0.0/9", "10.0.0.0/8", "192.168.0.0/16")
	var d Daemon
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "")
	if err := d.applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	got := replacedDestinations9943(fake.replaced)
	if got["10.0.0.0/9"] != 0 || got["10.128.0.0/9"] != 0 || got["10.0.0.0/8"] != 0 {
		t.Fatalf("learned routes covered/equal to operator /8 reached RouteReplace: %v", got)
	}
	if got["192.168.0.0/16"] != 1 {
		t.Fatalf("uncovered route did not install exactly once: %v", got)
	}
	if !strings.Contains(logs.String(), "suppressing management-VRF DHCP classless route") ||
		!strings.Contains(logs.String(), "operator_destination=10.0.0.0/8") {
		t.Fatalf("suppression WARN missing covering operator destination: %s", logs.String())
	}
}

// A learned route broader than an operator static is still needed for the
// uncovered portion of its address space and must install.
func TestMgmtVRFClasslessCoveringStaticStillInstalls_9943(t *testing.T) {
	fake := &fakeMgmtProgrammer{
		v4:      []netlink.Route{operatorRoute9943(t, "10.20.0.0/16")},
		linkIdx: 7,
	}
	lease := classlessLease9943("10.0.0.0/8")
	var d Daemon
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "")
	if err := d.applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	if got := replacedDestinations9943(fake.replaced); got["10.0.0.0/8"] != 1 {
		t.Fatalf("learned route covering operator static must install: %v", got)
	}
}

// Connected/kernel routes and xpf-owned DHCP routes are not configured statics
// and remain silent; an unexpected BOOT route is warned and ignored.
func TestMgmtVRFClasslessAlternateProtocolHandling_9943(t *testing.T) {
	fake := &fakeMgmtProgrammer{
		v4: []netlink.Route{
			operatorRouteWithProtocol9943(t, "0.0.0.0/0", unix.RTPROT_BOOT),
			operatorRouteWithProtocol9943(t, "10.0.0.0/8", unix.RTPROT_DHCP),
			operatorRouteWithProtocol9943(t, "192.168.0.0/16", unix.RTPROT_KERNEL),
		},
		linkIdx: 7,
	}
	lease := classlessLease9943("172.16.0.0/12")
	var d Daemon
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "")
	if err := d.applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	got := replacedDestinations9943(fake.replaced)
	if got["172.16.0.0/12"] != 1 {
		t.Fatalf("alternate-protocol routes incorrectly suppressed legitimate DHCP route: %v", got)
	}
	logText := logs.String()
	if !strings.Contains(logText, "ignoring non-static management-VRF route") ||
		!strings.Contains(logText, "destination=0.0.0.0/0") {
		t.Fatalf("unexpected BOOT route was not warned: %s", logText)
	}
	for _, silentDestination := range []string{"10.0.0.0/8", "192.168.0.0/16"} {
		if strings.Contains(logText, "destination="+silentDestination) {
			t.Fatalf("owned/connected route generated a skip warning: %s", logText)
		}
	}
}

func TestMgmtVRFClasslessBroadPrefixRefused_9943(t *testing.T) {
	fake := &fakeMgmtProgrammer{linkIdx: 7}
	lease := classlessLease9943("0.0.0.0/1", "128.0.0.0/1", "0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4")
	var d Daemon
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "")
	if err := d.applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	if len(fake.replaced) != 0 {
		t.Fatalf("broad /1 classless routes must be refused by default: %v", replacedDestinations9943(fake.replaced))
	}
}

func TestMgmtVRFClasslessInventoryFailureFailsClosed_9943(t *testing.T) {
	fake := &fakeMgmtProgrammer{
		linkIdx: 7,
		listErr: errors.New("injected route inventory failure"),
	}
	lease := classlessLease9943("10.0.0.0/8")
	var d Daemon
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "")
	err := d.applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true})
	if err == nil {
		t.Fatal("operator-route inventory failure must be returned")
	}
	if len(fake.replaced) != 0 {
		t.Fatalf("inventory failure must prevent every classless RouteReplace: %v", replacedDestinations9943(fake.replaced))
	}
}

// The explicit operator escape hatch restores learned-wins in the twin and
// emits the production warning from applyMgmtVRFRoutesTo.
func TestMgmtVRFClasslessTrustOverrideRestoresCovered_9943(t *testing.T) {
	fake := &fakeMgmtProgrammer{
		v4:      []netlink.Route{operatorRoute9943(t, "10.0.0.0/8")},
		linkIdx: 7,
	}
	lease := classlessLease9943("10.0.0.0/9", "10.128.0.0/9")
	var d Daemon
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "1")
	if err := d.applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	got := replacedDestinations9943(fake.replaced)
	if got["10.0.0.0/9"] != 1 || got["10.128.0.0/9"] != 1 {
		t.Fatalf("trust override did not restore both covered learned /9 routes: %v", got)
	}
	logText := logs.String()
	for _, field := range []string{
		"level=WARN",
		"env=XPF_DHCP_TRUST_CLASSLESS_OVERRIDE",
		"destination=10.0.0.0/9",
		"destination=10.128.0.0/9",
		"operator_destination=10.0.0.0/8",
	} {
		if !strings.Contains(logText, field) {
			t.Errorf("trust override warning missing %q: %s", field, logText)
		}
	}
	if got := strings.Count(logText, "msg=\"SECURITY: DHCP classless trust override allows a route covered"); got != 2 {
		t.Errorf("expected one covered-route WARN per trusted /9, got %d: %s", got, logText)
	}
}

func TestMgmtVRFClasslessBroadTrustOverrideAllows_9943(t *testing.T) {
	fake := &fakeMgmtProgrammer{
		v4:      []netlink.Route{operatorRoute9943(t, "0.0.0.0/0")},
		linkIdx: 7,
	}
	lease := classlessLease9943("0.0.0.0/1")
	var d Daemon
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "1")
	if err := d.applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	if got := replacedDestinations9943(fake.replaced); got["0.0.0.0/1"] != 1 {
		t.Fatalf("trust override must permit broad classless route: %v", got)
	}
	for _, field := range []string{
		"level=WARN",
		"env=XPF_DHCP_TRUST_CLASSLESS_OVERRIDE",
		"destination=0.0.0.0/1",
		"operator_destination=0.0.0.0/0",
	} {
		if !strings.Contains(logs.String(), field) {
			t.Errorf("broad trust warning missing %q: %s", field, logs.String())
		}
	}
	if got := strings.Count(logs.String(), "msg=\"SECURITY: DHCP classless trust override allows an unsafe"); got != 1 {
		t.Errorf("expected one unsafe WARN for trusted broad route, got %d: %s", got, logs.String())
	}
	if got := strings.Count(logs.String(), "msg=\"SECURITY: DHCP classless trust override allows a route covered"); got != 1 {
		t.Errorf("expected covering-static WARN alongside unsafe WARN, got %d: %s", got, logs.String())
	}
}

func TestMgmtVRFClasslessMartianTrustOverrideAllows_9943(t *testing.T) {
	fake := &fakeMgmtProgrammer{linkIdx: 7}
	lease := classlessLease9943("127.0.0.0/8", "169.254.0.0/16", "240.0.0.0/4")
	var d Daemon
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)
	t.Setenv("XPF_DHCP_TRUST_CLASSLESS_OVERRIDE", "1")
	if err := d.applyMgmtVRFRoutesTo(fake, []*dhcp.Lease{lease}, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	got := replacedDestinations9943(fake.replaced)
	for _, destination := range []string{"127.0.0.0/8", "169.254.0.0/16", "240.0.0.0/4"} {
		if got[destination] != 1 || !strings.Contains(logs.String(), "destination="+destination) {
			t.Errorf("trust override did not install and warn for %s: routes=%v logs=%s", destination, got, logs.String())
		}
	}
	if count := strings.Count(logs.String(), "msg=\"SECURITY: DHCP classless trust override allows an unsafe"); count != 3 {
		t.Errorf("expected one unsafe WARN per trusted martian route, got %d: %s", count, logs.String())
	}
}
