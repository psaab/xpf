package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// Regression #13155 (D3-09): classifier must match dataplane for lifeline-only
// zones, quarantined multi-zone conflict interfaces, and Shape B bare st0.

func compile13155(t *testing.T, cmds []string, lenient bool) *config.Config {
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
	var cfg *config.Config
	var err error
	if lenient {
		cfg, err = config.CompileConfigLenient(tree)
	} else {
		cfg, err = config.CompileConfig(tree)
	}
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	return cfg
}

func Test13155_LifelineOnlyZoneNotDenied(t *testing.T) {
	cfg := compile13155(t, []string{
		"set interfaces fxp0 unit 0 family inet address 10.0.0.1/24",
		"set security zones security-zone mgmt interfaces fxp0.0",
	}, false)
	got := ClassifyHostInbound(cfg, "mgmt", config.HostInboundProtoTCP, true, 22, nil, "ip")
	if got.Status != HostInboundNotComputed {
		t.Fatalf("lifeline-only mgmt tcp/22 status = %v (%+v), want NotComputed", got.Status, got)
	}
	gotIface := ClassifyHostInboundForInterface(cfg, "mgmt", "fxp0.0", config.HostInboundProtoTCP, true, 22, nil, "ip")
	if gotIface.Status != HostInboundNotComputed {
		t.Fatalf("lifeline interface status = %v (%+v), want NotComputed", gotIface.Status, gotIface)
	}
	if err := ResolveHostInboundIngressInterface(cfg, "mgmt", "fxp0.0"); err == nil {
		t.Fatalf("Resolve lifeline fxp0.0 = nil, want lifeline error")
	}
}

func Test13155_QuarantinedConflictInterfaceDenied(t *testing.T) {
	cfg := compile13155(t, []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone a interfaces ge-0/0/0.0",
		"set security zones security-zone a host-inbound-traffic system-services ssh",
		"set security zones security-zone b interfaces ge-0/0/0.0",
	}, true)
	if _, ok := config.QuarantinedZoneInterfaceKeys(cfg)["ge-0/0/0.0"]; !ok {
		t.Fatalf("positive control: ge-0/0/0.0 not quarantined")
	}
	got := ClassifyHostInboundForInterface(cfg, "a", "ge-0/0/0.0", config.HostInboundProtoTCP, true, 22, nil, "ip")
	if got.Status != HostInboundDenied {
		t.Fatalf("quarantined conflict iface status = %v (%+v), want Denied", got.Status, got)
	}
	if err := ResolveHostInboundIngressInterface(cfg, "a", "ge-0/0/0.0"); err == nil {
		t.Fatalf("Resolve quarantined conflict iface = nil, want error")
	}
}

func Test13155_ShapeBBareSt0Rejected(t *testing.T) {
	cfg := compile13155(t, []string{
		"set security ipsec vpn v1 bind-interface st0.0",
		"set security zones security-zone vpn host-inbound-traffic system-services all",
		"set security zones security-zone vpn interfaces st0.0",
		"set security zones security-zone vpn interfaces st0.0 host-inbound-traffic system-services ssh",
	}, false)
	got := ClassifyHostInboundForInterface(cfg, "vpn", "st0", config.HostInboundProtoTCP, true, 22, nil, "")
	if got.Status == HostInboundTokenAdmit {
		t.Fatalf("bare st0 returned TokenAdmit %+v, want not admitted (unit override bypass)", got)
	}
	if err := ResolveHostInboundIngressInterface(cfg, "vpn", "st0"); err == nil {
		t.Fatalf("Resolve bare st0 = nil, want bare-interface error")
	}
	gotU := ClassifyHostInboundForInterface(cfg, "vpn", "st0.0", config.HostInboundProtoTCP, true, 22, nil, "")
	if gotU.Status != HostInboundTokenAdmit {
		t.Fatalf("st0.0 tcp/22 status = %v (%+v), want TokenAdmit", gotU.Status, gotU)
	}
	if err := ResolveHostInboundIngressInterface(cfg, "vpn", "st0.0"); err != nil {
		t.Fatalf("Resolve st0.0 err = %v, want nil", err)
	}
}
