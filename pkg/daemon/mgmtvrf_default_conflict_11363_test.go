package daemon

import (
	"bytes"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dhcp"
)

func TestMgmtVRFCompetingDefaultsChooseFirstInterfaceAndWarn11363(t *testing.T) {
	oldLogger := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	mgmtSet := map[string]bool{"em0": true, "fxp0": true}
	cases := []struct {
		name   string
		leases []*dhcp.Lease
	}{
		{
			name: "map-order-fxp-first",
			leases: []*dhcp.Lease{
				gwLease("fxp0", "192.0.2.1"),
				gwLease("em0", "192.0.2.2"),
			},
		},
		{
			name: "map-order-em-first",
			leases: []*dhcp.Lease{
				gwLease("em0", "192.0.2.2"),
				gwLease("fxp0", "192.0.2.1"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs.Reset()
			fake := &fakeMgmtProgrammer{linkIdx: 7}
			if err := (&Daemon{}).applyMgmtVRFRoutesTo(fake, tc.leases, mgmtSet); err != nil {
				t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
			}
			if len(fake.v4) != 1 {
				t.Fatalf("got %d IPv4 defaults, want exactly one: %+v", len(fake.v4), fake.v4)
			}
			if got := fake.v4[0].Gw.String(); got != "192.0.2.2" {
				t.Fatalf("selected default gateway = %s, want first interface em0 gateway 192.0.2.2", got)
			}
			for _, want := range []string{"#11363", "em0", "192.0.2.2", "fxp0", "192.0.2.1"} {
				if !strings.Contains(logs.String(), want) {
					t.Errorf("competing-default warning does not include %q: %s", want, logs.String())
				}
			}
		})
	}
}

func TestMgmtVRFCompetingDefaultsAreSelectedPerFamily11363(t *testing.T) {
	oldLogger := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	leases := []*dhcp.Lease{
		gwLease("fxp0", "192.0.2.1"),
		gwLease("em0", "192.0.2.2"),
		{Interface: "fxp0", Family: dhcp.AFInet6, Gateway: netip.MustParseAddr("2001:db8::1")},
	}
	fake := &fakeMgmtProgrammer{linkIdx: 7}
	mgmtSet := map[string]bool{"em0": true, "fxp0": true}
	if err := (&Daemon{}).applyMgmtVRFRoutesTo(fake, leases, mgmtSet); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	if len(fake.v4) != 1 || fake.v4[0].Gw.String() != "192.0.2.2" {
		t.Fatalf("IPv4 selection = %+v, want only em0 via 192.0.2.2", fake.v4)
	}
	if len(fake.v6) != 1 || fake.v6[0].Gw.String() != "2001:db8::1" {
		t.Fatalf("IPv6 default = %+v, want the independent fxp0 route", fake.v6)
	}
	if got := strings.Count(logs.String(), "#11363"); got != 1 {
		t.Fatalf("conflict warning count = %d, want one IPv4-only warning: %s", got, logs.String())
	}
}

func TestMgmtVRFSingleDefaultHasNoConflictWarning11363(t *testing.T) {
	oldLogger := slog.Default()
	var logs bytes.Buffer
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(oldLogger) })

	fake := &fakeMgmtProgrammer{linkIdx: 7}
	leases := []*dhcp.Lease{gwLease("fxp0", "192.0.2.1")}
	if err := (&Daemon{}).applyMgmtVRFRoutesTo(fake, leases, map[string]bool{"fxp0": true}); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}
	if len(fake.v4) != 1 || fake.v4[0].Gw.String() != "192.0.2.1" {
		t.Fatalf("single default = %+v, want fxp0 via 192.0.2.1", fake.v4)
	}
	if strings.Contains(logs.String(), "#11363") {
		t.Fatalf("single management default must not report a conflict: %s", logs.String())
	}
}

func TestMgmtVRFCompetingDefaultKeepsClasslessRoutes11363(t *testing.T) {
	nonselected := gwLease("fxp0", "192.0.2.1")
	nonselected.ClasslessRoutes = []dhcp.LeaseRoute{{
		Destination: netip.MustParsePrefix("198.51.100.0/24"),
		Gateway:     netip.MustParseAddr("192.0.2.254"),
	}}
	fake := &fakeMgmtProgrammer{linkIdx: 7}
	leases := []*dhcp.Lease{gwLease("em0", "192.0.2.2"), nonselected}
	mgmtSet := map[string]bool{"em0": true, "fxp0": true}
	if err := (&Daemon{}).applyMgmtVRFRoutesTo(fake, leases, mgmtSet); err != nil {
		t.Fatalf("applyMgmtVRFRoutesTo: %v", err)
	}

	routes := make(map[string]string, len(fake.v4))
	for _, route := range fake.v4 {
		destination := "<default>"
		if route.Dst != nil {
			destination = route.Dst.String()
		}
		routes[destination] = route.Gw.String()
	}
	if len(routes) != 2 || routes["0.0.0.0/0"] != "192.0.2.2" ||
		routes["198.51.100.0/24"] != "192.0.2.254" {
		t.Fatalf("routes after competing defaults = %v, want selected default and nonselected classless route", routes)
	}
}
