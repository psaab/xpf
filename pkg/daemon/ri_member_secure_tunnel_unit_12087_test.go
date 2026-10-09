package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
)

const riMemberSecureTunnelNetnsChild12087 = "XPF_12087_ST0_NETNS_CHILD"

// #12087: bind both a bare-member fanout key and an explicit unit to the
// authored xfrmi names, then inspect the kernel's real MasterIndex. The second
// read uses the stale-member ownership map: neither correctly-bound xfrmi may
// be queued for unbind.
func TestRIMemberSecureTunnelUnitBindsToVRF12087(t *testing.T) {
	if os.Getenv(riMemberSecureTunnelNetnsChild12087) == "1" {
		runRIMemberSecureTunnelUnitNetnsChild12087(t)
		return
	}
	unshare, err := exec.LookPath("unshare")
	if err != nil {
		t.Skipf("cannot run the isolated MasterIndex cell: unshare not found: %v", err)
	}
	cmd := exec.Command(unshare, "-rn", os.Args[0], "-test.run", "^TestRIMemberSecureTunnelUnitBindsToVRF12087$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), riMemberSecureTunnelNetnsChild12087+"=1")
	out, err := cmd.CombinedOutput()
	if !strings.Contains(string(out), "NETNS-CHILD-STARTED-12087") {
		if os.Getenv("XPF_REQUIRE_NETNS") == "" {
			t.Skipf("cannot create an isolated network namespace (%v): %s", err, out)
		}
		t.Fatalf("netns child never started (%v): %s", err, out)
	}
	if err != nil || !strings.Contains(string(out), "NETNS-CHILD-PASSED-12087") {
		t.Fatalf("real-kernel #12087 MasterIndex cell failed (%v):\n%s", err, out)
	}
}

func runRIMemberSecureTunnelUnitNetnsChild12087(t *testing.T) {
	fmt.Println("NETNS-CHILD-STARTED-12087")
	vrfIndexes := make(map[string]int)
	for _, spec := range []struct {
		name  string
		table uint32
	}{
		{name: "vrf-blue", table: 12087},
		{name: "vrf-red", table: 12088},
	} {
		vrf := &netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: spec.name}, Table: spec.table}
		if err := netlink.LinkAdd(vrf); err != nil {
			t.Fatalf("create %s in private netns: %v", spec.name, err)
		}
		if err := netlink.LinkSetUp(vrf); err != nil {
			t.Fatalf("bring %s up: %v", spec.name, err)
		}
		link, err := netlink.LinkByName(spec.name)
		if err != nil {
			t.Fatalf("read %s: %v", spec.name, err)
		}
		vrfIndexes[spec.name] = link.Attrs().Index
	}

	cfg := &config.Config{}
	cfg.Security.IPsec.VPNs = map[string]*config.IPsecVPN{
		"vpn0": {Name: "vpn0", BindInterface: "st0.0"},
		"vpn1": {Name: "vpn1", BindInterface: "st1.0"},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"st0": {Name: "st0", Units: map[int]*config.InterfaceUnit{
			0: {Number: 0},
			1: {Number: 1},
		}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{
		{
			Name: "blue", InstanceType: "vrf", TableID: 12087,
			Interfaces: []string{"st0"},
		},
		{
			Name: "red", InstanceType: "vrf", TableID: 12088,
			Interfaces: []string{"st1.0"},
		},
	}
	rt, err := routing.New()
	if err != nil {
		t.Fatalf("routing.New: %v", err)
	}
	defer func() { _ = rt.Close() }()
	if err := rt.ApplyXfrmi(cfg.Security.IPsec.VPNs); err != nil {
		t.Fatalf("create xfrmi from authored bind-interface: %v", err)
	}
	d := &Daemon{routing: rt, linkByNameFn: netlink.LinkByName}
	d.bindRoutingInstanceMembers(cfg)

	wantVRF := map[string]string{"st0.0": "vrf-blue", "st1.0": "vrf-red"}
	assertMaster := func(stage string) {
		t.Helper()
		for device, vrfName := range wantVRF {
			link, err := netlink.LinkByName(device)
			if err != nil {
				t.Fatalf("%s: xfrmi %s absent: %v", stage, device, err)
			}
			if got, want := link.Attrs().MasterIndex, vrfIndexes[vrfName]; got != want {
				t.Fatalf("%s: %s master index = %d, want %s (%d)",
					stage, device, got, vrfName, want)
			}
		}
	}
	assertMaster("after bind")

	for _, member := range d.riMembersOutsideTheirVRF(cfg) {
		if member.unbind && wantVRF[member.linuxName] != "" {
			t.Fatalf("#12087: stale-member cleanup queued %s for unbind from %s despite current RI ownership",
				member.linuxName, member.instance)
		}
	}
	d.rebindRIMembersOutsideTheirVRF(cfg)
	assertMaster("after stale-member cleanup")
	fmt.Println("NETNS-CHILD-PASSED-12087")
}
