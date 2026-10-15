package daemon

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
)

func TestHostInboundGapDropsIngressDeniedSharedAddressOnNewDHCPInterface13174(t *testing.T) {
	origInstaller := nftInstaller
	t.Cleanup(func() { nftInstaller = origInstaller })
	origSample := sampleHostInboundSnapshots
	t.Cleanup(func() { sampleHostInboundSnapshots = origSample })

	cfg1 := lifelineDenyAllConfig12229()
	cfg2 := lifelineDenyAllConfig12229()
	cfg2.Interfaces.Interfaces["ge-0/0/9"] = &config.InterfaceConfig{
		Name: "ge-0/0/9", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true}},
	}
	cfg2.Security.Zones["untrust"].Interfaces = append(cfg2.Security.Zones["untrust"].Interfaces, "ge-0/0/9.0")
	s1 := lifelineDenyAllSnapshot12229()
	s2 := append(append([]dpuserspace.InterfaceSnapshot(nil), s1...), dpuserspace.InterfaceSnapshot{
		Name: "ge-0/0/9.0", Zone: "untrust", LinuxName: "ge-0-0-9", IsUnit: true,
	})
	sampleHostInboundSnapshots = func(c *config.Config) []dpuserspace.InterfaceSnapshot {
		if c == cfg1 {
			return s1
		}
		return s2
	}

	views := dpuserspace.BuildZoneHostInboundViewsFromSnapshots(cfg1, s1)
	var denyView *dpuserspace.ZoneHostInboundView
	for i := range views {
		if views[i].Zone == "untrust" {
			denyView = &views[i]
			break
		}
	}
	if denyView == nil || !sliceContains(denyView.IngressDenyV4, lifelineSharedAddr12229) {
		t.Fatalf("fixture must put shared address only in ingress-deny scope: %+v", views)
	}

	nftInstaller = &fakeNftInstaller{}
	d := &Daemon{}
	if err := d.applyHostInboundFilter(cfg1); err != nil {
		t.Fatalf("initial real host-inbound install: %v", err)
	}
	installErr := errors.New("injected real host-inbound install failure")
	var gapSpec xnft.GapFenceSpec
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return installErr },
		gapFence: func(spec xnft.GapFenceSpec) error {
			gapSpec = spec
			return nil
		},
	}
	if err := d.applyHostInboundFilter(cfg2); !errors.Is(err, installErr) {
		t.Fatalf("failed day-2 apply error = %v, want injected install failure", err)
	}

	if sliceContains(gapSpec.RetainedV4, lifelineSharedAddr12229) {
		t.Fatalf("ingress-only retained destination incorrectly exempts new DHCP backstop: %v", gapSpec.RetainedV4)
	}
	gapPayload := buildHostInboundGapFencePayload(
		views, gapSpec.UncoveredV4, gapSpec.UncoveredV6, gapSpec.WGListenPorts, gapSpec.WGZonePorts,
		gapSpec.UnleasedV4, gapSpec.UnleasedV6, gapSpec.SharedV4, gapSpec.SharedV6,
		gapSpec.LifelineNetdevs,
		dhcpBackstopLists{v4: gapSpec.UnleasedVRFSlavesV4, v6: gapSpec.UnleasedVRFSlavesV6},
		gapSpec.RetainedV4, gapSpec.RetainedV6,
	)
	wantPrefix := "iifname " + nftIifnameSet([]string{"ge-0-0-9"}) + " meta nfproto ipv4 fib daddr type { local, anycast }"
	for _, line := range strings.Split(gapPayload, "\n") {
		if strings.Contains(line, wantPrefix) && strings.HasSuffix(line, " drop") &&
			!strings.Contains(line, lifelineSharedAddr12229) {
			return
		}
	}
	t.Fatalf("new DHCP interface must retain the shared local-IP drop without excluding it; gap payload:\\n%s", gapPayload)
}
