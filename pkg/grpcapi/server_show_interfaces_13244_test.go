package grpcapi

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #13244 (D6-04): gRPC show-interfaces drifted from the fixed CLI twins.
// The regression cases pin VLAN address lookup, malformed unit handling, and
// filtered extensive RETH output.
func interfaces13244Server(t *testing.T, body string) *Server {
	t.Helper()
	store, err := configstore.New(filepath.Join(t.TempDir(), "xpf.conf"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(body); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return &Server{store: store}
}

func TestShowInterfacesExtensiveFilterHonoursReth13244(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"lo":       {Name: "lo", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
			"ge-0/0/0": {Name: "ge-0/0/0", RedundantParent: "reth0"},
			"reth0":    {Name: "reth0", RedundancyGroup: 1, Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		}},
	}
	s := &Server{}
	var buf strings.Builder
	if err := s.showInterfacesExtensive(cfg, "lo", &buf); err != nil {
		t.Fatalf("showInterfacesExtensive: %v", err)
	}
	if strings.Contains(buf.String(), "Physical interface: reth0") {
		t.Fatalf("filtered extensive (filter=lo) leaked reth0:\n%s", buf.String())
	}
	buf.Reset()
	if err := s.showInterfacesExtensive(cfg, "", &buf); err != nil {
		t.Fatalf("showInterfacesExtensive unfiltered: %v", err)
	}
	if !strings.Contains(buf.String(), "Physical interface: reth0") {
		t.Fatalf("unfiltered extensive omitted reth0:\n%s", buf.String())
	}
}

func TestShowInterfacesDetailNonNumericUnit13244(t *testing.T) {
	junos, _, ok := dashNamedKernelIface(t)
	if !ok {
		t.Skip("no dash-named host interface available")
	}
	s := interfaces13244Server(t, `interfaces {
  `+junos+` {
    vlan-tagging;
    unit 0 { vlan-id 99; description unit-zero-desc; }
  }
}
security { zones { security-zone trust { interfaces { `+junos+`.0; } } } }
`)
	s.store.ActiveConfig().Security.Zones["trust"].Interfaces = []string{junos + ".abc", junos + ".0"}
	resp, err := s.ShowInterfacesDetail(context.Background(), &pb.ShowInterfacesDetailRequest{Filter: junos})
	if err != nil {
		t.Fatalf("ShowInterfacesDetail: %v", err)
	}
	out := resp.GetOutput()
	if n := strings.Count(out, "Logical interface "+junos+".0"); n != 1 {
		t.Fatalf("non-numeric unit must not collapse to unit 0; got %d unit-0 blocks:\n%s", n, out)
	}
	if n := strings.Count(out, "unit-zero-desc"); n != 1 {
		t.Fatalf("unit-zero description should appear only on unit 0, got %d:\n%s", n, out)
	}
	if strings.Contains(out, "0x8100.99") && strings.Count(out, "0x8100.99") != 1 {
		t.Fatalf("unit-zero VLAN metadata was borrowed by malformed unit:\n%s", out)
	}
}

func TestShowInterfacesDetailVLANLookupUsesLinuxName13244(t *testing.T) {
	junos, _, ok := dashNamedKernelIface(t)
	if !ok {
		t.Skip("no dash-named host interface available")
	}
	iface, err := net.InterfaceByName(config.LinuxIfName(junos))
	if err != nil || iface == nil {
		t.Skip("host interface vanished")
	}
	parentAddrs, _ := iface.Addrs()
	if len(parentAddrs) == 0 {
		t.Skip("host interface has no addresses to misattribute")
	}
	vlanIface, err := net.InterfaceByName(config.LinuxIfName(junos) + ".50")
	if err != nil || vlanIface == nil {
		t.Skip("host has no VLAN sub-interface to exercise kernel-name lookup")
	}
	vlanAddrs, _ := vlanIface.Addrs()
	if len(vlanAddrs) == 0 {
		t.Skip("host VLAN sub-interface has no addresses")
	}
	s := interfaces13244Server(t, `interfaces {
  `+junos+` {
    vlan-tagging;
    unit 0 { family inet { dhcp; } }
    unit 50 { vlan-id 50; }
  }
}
security { zones { security-zone trust { interfaces { `+junos+`.0; `+junos+`.50; } } } }
`)
	resp, err := s.ShowInterfacesDetail(context.Background(), &pb.ShowInterfacesDetailRequest{Filter: junos})
	if err != nil {
		t.Fatalf("ShowInterfacesDetail: %v", err)
	}
	out := resp.GetOutput()
	idx := strings.Index(out, "Logical interface "+junos+".50")
	if idx < 0 {
		t.Fatalf("VLAN unit .50 not rendered:\n%s", out)
	}
	// The VLAN sub-device exists under the Linux dash name, with distinct
	// addresses from its parent. The authored slash-form lookup used to fail
	// and fall back to the parent.
	end := strings.Index(out[idx+1:], "Logical interface ")
	if end < 0 {
		end = len(out)
	} else {
		end += idx + 1
	}
	vlanBlock := out[idx:end]
	for _, addr := range parentAddrs {
		if strings.Contains(vlanBlock, addr.String()) {
			t.Fatalf("VLAN unit inherited parent address %q:\n%s", addr, vlanBlock)
		}
	}
	for _, addr := range vlanAddrs {
		if !strings.Contains(vlanBlock, addr.String()) {
			t.Fatalf("VLAN unit omitted child address %q:\n%s", addr, vlanBlock)
		}
	}
}
