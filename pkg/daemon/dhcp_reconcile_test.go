package daemon

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dhcp"
)

func dhcpTestConfig() *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/3": {
					Name: "ge-0/0/3",
					Units: map[int]*config.InterfaceUnit{
						0: {
							DHCP:        true,
							DHCPOptions: &config.DHCPInetOptions{LeaseTime: 300},
						},
						50: {
							VlanID: 50,
							DHCPv6: true,
							DHCPv6Client: &config.DHCPv6ClientConfig{
								ClientType: "stateless",
								DUIDType:   "duid-llt",
								ReqOptions: []string{"dns-server"},
							},
						},
					},
				},
				"ge-0/0/1": {
					Name: "ge-0/0/1",
					Units: map[int]*config.InterfaceUnit{
						0: {Addresses: []string{"10.0.61.1/24"}},
					},
				},
			},
		},
	}
}

func TestBuildDHCPClientSpecs(t *testing.T) {
	specs := buildDHCPClientSpecs(dhcpTestConfig())
	if len(specs) != 2 {
		t.Fatalf("got %d specs, want 2: %+v", len(specs), specs)
	}
	byKey := make(map[string]dhcp.ClientSpec)
	for _, s := range specs {
		byKey[s.Iface] = s
	}

	v4, ok := byKey["ge-0-0-3"]
	if !ok {
		t.Fatalf("no spec for ge-0-0-3: %+v", specs)
	}
	if v4.Family != dhcp.AFInet || v4.V4 == nil || v4.V4.LeaseTime != 300 {
		t.Errorf("v4 spec wrong: %+v", v4)
	}

	v6, ok := byKey["ge-0-0-3.50"]
	if !ok {
		t.Fatalf("no spec for VLAN sub-interface ge-0-0-3.50: %+v", specs)
	}
	if v6.Family != dhcp.AFInet6 || v6.DUIDType != "duid-llt" ||
		v6.V6 == nil || !v6.V6.Stateless {
		t.Errorf("v6 spec wrong: %+v", v6)
	}
}

func TestBuildDHCPClientSpecsDefaults(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"fxp0": {
					Name: "fxp0",
					Units: map[int]*config.InterfaceUnit{
						0: {DHCPv6: true},
					},
				},
			},
		},
	}
	specs := buildDHCPClientSpecs(cfg)
	if len(specs) != 1 {
		t.Fatalf("got %d specs, want 1", len(specs))
	}
	if specs[0].DUIDType != "duid-ll" {
		t.Errorf("DUIDType = %q, want default duid-ll", specs[0].DUIDType)
	}
	if specs[0].V6 != nil {
		t.Errorf("V6 opts = %+v, want nil for bare dhcpv6", specs[0].V6)
	}
}

// #16476: the consumed axis of the three-arm probe at the daemon
// consumer. Compiling `family inet6 { dhcpv6; }` must yield exactly one
// AFInet6 spec with no #10707 advisory; `dhcpv6-client` the same;
// `dhcpv6x` no spec and the advisory retained.
func TestDHCPv6ShorthandConsumedNotAdvised16476(t *testing.T) {
	cases := []struct {
		leaf        string
		wantSpecs   int
		wantAdvised bool
	}{
		{"dhcpv6", 1, false},
		{"dhcpv6-client", 1, false},
		{"dhcpv6x", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.leaf, func(t *testing.T) {
			tree, perrs := config.NewParser("interfaces { ge-0/0/0 { unit 0 { family inet6 { " + tc.leaf + "; } } } }").Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse: %v", perrs)
			}
			cfg, err := config.CompileConfig(tree)
			if err != nil {
				t.Fatalf("CompileConfig: %v", err)
			}
			var v6 int
			for _, s := range buildDHCPClientSpecs(cfg) {
				if s.Family == dhcp.AFInet6 {
					v6++
				}
			}
			if v6 != tc.wantSpecs {
				t.Fatalf("leaf=%s AFInet6 specs=%d, want %d (all=%+v)", tc.leaf, v6, tc.wantSpecs, buildDHCPClientSpecs(cfg))
			}
			advised := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "#10707") && strings.Contains(w, `"`+tc.leaf+`"`) {
					advised = true
				}
			}
			if advised != tc.wantAdvised {
				t.Fatalf("leaf=%s advisory=%v, want %v; warnings=%v", tc.leaf, advised, tc.wantAdvised, cfg.Warnings)
			}
		})
	}
}

// TestReconcileDHCPClientsNoDHCPNoManager: a config without DHCP units
// must not lazily create the manager (nothing desired, nothing running).
func TestReconcileDHCPClientsNoDHCPNoManager(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{}
	d.reconcileDHCPClients(cfg)
	if d.dhcp != nil {
		t.Fatal("DHCP manager created for a config without DHCP units")
	}
}

func TestReconcileDHCPClientsNoDataplaneGate(t *testing.T) {
	d := &Daemon{opts: Options{NoDataplane: true}}
	d.reconcileDHCPClients(dhcpTestConfig())
	if d.dhcp != nil {
		t.Fatal("DHCP manager created in NoDataplane mode")
	}
}

// TestReconcileDHCPClientsCommitLifecycle covers #1793 defects 1 and 2
// at the daemon level: a commit that enables dhcp/dhcpv6 starts clients
// on a running daemon, and a commit that deletes them stops the clients.
func TestReconcileDHCPClientsCommitLifecycle(t *testing.T) {
	mgr := dhcp.NewManagerForTesting(
		func(ctx context.Context, iface string, af dhcp.AddressFamily) {
			<-ctx.Done()
		})
	defer mgr.StopAll()
	d := &Daemon{dhcp: mgr}

	// Commit 1: no DHCP anywhere — nothing starts.
	d.reconcileDHCPClients(&config.Config{})
	if h := mgr.RunningClientHandlesForTesting(); len(h) != 0 {
		t.Fatalf("clients running before DHCP enabled: %v", h)
	}

	// Commit 2: enable dhcp + dhcpv6 — clients must start (previously a
	// silent no-op until daemon restart).
	d.reconcileDHCPClients(dhcpTestConfig())
	handles := mgr.RunningClientHandlesForTesting()
	if len(handles) != 2 {
		t.Fatalf("got %d running clients after enable commit, want 2: %v",
			len(handles), handles)
	}

	// Commit 3: delete DHCP from the config — clients must stop
	// (previously kept renewing forever).
	d.reconcileDHCPClients(&config.Config{})
	if h := mgr.RunningClientHandlesForTesting(); len(h) != 0 {
		t.Fatalf("clients still running after DHCP deleted: %v", h)
	}
}

// TestReconcileDHCPClientsLeaseChangeNoRestart models the lease-change
// callback path: onDHCPAddressChange re-enters applyConfig with the SAME
// active config but NEW lease state. The reconcile must not restart any
// client (config identity unchanged) or the daemon would loop:
// lease change -> callback -> applyConfig -> restart -> lease change.
func TestReconcileDHCPClientsLeaseChangeNoRestart(t *testing.T) {
	mgr := dhcp.NewManagerForTesting(
		func(ctx context.Context, iface string, af dhcp.AddressFamily) {
			<-ctx.Done()
		})
	defer mgr.StopAll()
	d := &Daemon{dhcp: mgr}
	cfg := dhcpTestConfig()

	d.reconcileDHCPClients(cfg)
	before := mgr.RunningClientHandlesForTesting()
	if len(before) != 2 {
		t.Fatalf("got %d running clients, want 2", len(before))
	}

	// New lease lands (this is what fires the callback).
	mgr.SeedLeaseForTesting("ge-0-0-3", dhcp.AFInet, &dhcp.Lease{
		Interface: "ge-0-0-3",
		Family:    dhcp.AFInet,
		Address:   netip.MustParsePrefix("172.16.50.5/24"),
		Obtained:  time.Now(),
	})
	d.reconcileDHCPClients(cfg)

	after := mgr.RunningClientHandlesForTesting()
	if len(after) != 2 {
		t.Fatalf("got %d running clients after lease change, want 2", len(after))
	}
	for k := range before {
		if before[k] != after[k] {
			t.Errorf("client %s restarted by lease-change reconcile", k)
		}
	}
}
