package userspace

import (
	"reflect"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func compile13151(t *testing.T, cmds []string) *config.Config {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, cmd := range cmds {
		p, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(p); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

// #13151 (D3-05): a zoned unit sharing one kernel netdev with an unzoned
// sibling must not get an uncontested bare-netdev ingress claim (fail-open),
// and in VRF mode the unzoned builder must not emit that slave as a blanket
// sdifname drop ahead of the zoned unit (fail-closed blackhole).
func TestSharedNetdevZonedUnzoned13151(t *testing.T) {
	t.Run("main table contested not claimed", func(t *testing.T) {
		cfg := compile13151(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set interfaces ge-0/0/0 unit 1 family inet address 10.0.1.1/24",
			"set security zones security-zone trust interfaces ge-0/0/0.0",
			"set security zones security-zone trust host-inbound-traffic system-services ssh",
		})
		snaps := buildInterfaceSnapshots(cfg)
		for i := range snaps {
			if snaps[i].Name == "ge-0/0/0.1" {
				snaps[i].LinuxName = "ge-0-0-0"
			}
		}
		views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
		if len(views) != 1 {
			t.Fatalf("views=%+v want 1 trust view", views)
		}
		for _, nd := range views[0].IngressNetdevs {
			if nd == "ge-0-0-0" {
				t.Fatalf("fail-open: trust claimed shared netdev ge-0-0-0 uncontested: %+v", views[0])
			}
		}
		if !reflect.DeepEqual(views[0].IngressDenyNetdevs, []string{"ge-0-0-0"}) {
			t.Fatalf("IngressDenyNetdevs=%v want [ge-0-0-0] (contested fail-closed)", views[0].IngressDenyNetdevs)
		}
		if !reflect.DeepEqual(views[0].V4Addrs, []string{"10.0.0.1"}) {
			t.Fatalf("V4Addrs=%v want [10.0.0.1]", views[0].V4Addrs)
		}
	})

	t.Run("vrf slave not blanket-dropped", func(t *testing.T) {
		cfg := compile13151(t, []string{
			"set interfaces ge-0/0/0 unit 0 family inet address 10.0.0.1/24",
			"set interfaces ge-0/0/0 unit 1 family inet address 10.0.1.1/24",
			"set routing-instances blue instance-type vrf",
			"set routing-instances blue interface ge-0/0/0.0",
			"set routing-instances blue interface ge-0/0/0.1",
			"set security zones security-zone trust interfaces ge-0/0/0.0",
			"set security zones security-zone trust host-inbound-traffic system-services ssh",
		})
		snaps := buildInterfaceSnapshots(cfg)
		for i := range snaps {
			if snaps[i].Name == "ge-0/0/0.1" {
				snaps[i].LinuxName = "ge-0-0-0"
			}
		}
		views := BuildZoneHostInboundViewsFromSnapshots(cfg, snaps)
		_, unzonedVRFSlaves := BuildUnzonedHostInboundIngressNetdevsFromSnapshots(cfg, snaps, views)
		for _, s := range unzonedVRFSlaves {
			if s == "ge-0-0-0" {
				t.Fatalf("fail-closed blackhole: unzonedVRFSlaves contains zoned slave ge-0-0-0 (views=%+v slaves=%v)", views, unzonedVRFSlaves)
			}
		}
	})
}
