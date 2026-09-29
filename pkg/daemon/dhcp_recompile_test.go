package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestDHCPLeaseChangeRequiresRecompile_ManagementOnlyDHCP(t *testing.T) {
	d := &Daemon{}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"fxp0": {
					Name: "fxp0",
					Units: map[int]*config.InterfaceUnit{
						0: {DHCP: true},
					},
				},
			},
		},
	}

	if d.dhcpLeaseChangeRequiresRecompile(cfg, false) {
		t.Fatal("management-only DHCP lease refresh should not require dataplane recompile")
	}
}

func TestDHCPLeaseChangeRequiresRecompile_NonManagementDHCP(t *testing.T) {
	d := &Daemon{}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/2": {
					Name: "ge-0/0/2",
					Units: map[int]*config.InterfaceUnit{
						80: {VlanID: 80, DHCP: true},
					},
				},
			},
		},
	}

	if !d.dhcpLeaseChangeRequiresRecompile(cfg, false) {
		t.Fatal("dataplane-facing DHCP lease refresh should require dataplane recompile")
	}
}

func TestDHCPLeaseChangeRequiresRecompile_RequiresMgmtMap(t *testing.T) {
	d := &Daemon{}
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"fxp0": {
					Name: "fxp0",
					Units: map[int]*config.InterfaceUnit{
						0: {DHCP: true},
					},
				},
			},
		},
	}

	if !d.dhcpLeaseChangeRequiresRecompile(cfg, false) {
		t.Fatal("missing management VRF map should keep recompile path conservative")
	}
}

// TestDHCPLeaseChangeRequiresRecompile_ZonedNonLifelineFxp1 is the #5791
// fail-on-revert gate. A zoned, standalone (non-cluster) fxp1 DHCP client is in
// the BROAD management-VRF name class (fxp*) but is NOT a host-inbound LIFELINE
// (only fxp0 is fixed; cluster control/fabric roles must be explicitly configured).
// Its learned address needs an address-scoped host-inbound fence, so a lease
// recompile that (re)builds that fence — it must NOT take the lightweight
// management-only skip path. Neutralizing the fix (gating the skip on the broad
// mgmt-VRF class again, i.e. `mgmtSet[config.DHCPLeaseIfName(ifName, unit)]`)
// makes this return false → RED.
func TestDHCPLeaseChangeRequiresRecompile_ZonedNonLifelineFxp1(t *testing.T) {
	d := &Daemon{}
	// fxp1 is bound to the management VRF by the broad name class, so it IS in
	// the published mgmt set — exactly the condition the old proxy exempted.
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true, "fxp1": true})
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"fxp1": {
					Name: "fxp1",
					Units: map[int]*config.InterfaceUnit{
						0: {DHCP: true},
					},
				},
			},
		},
	}

	if !d.dhcpLeaseChangeRequiresRecompile(cfg, false) {
		t.Fatal("zoned non-lifeline fxp1 DHCP lease change must require the full " +
			"recompile so its address-scoped host-inbound fence is (re)built")
	}
}

// TestDHCPLeaseChangeRequiresRecompile_LifelineFastPathPreserved guards the
// lifeline fast-path (#5791): fxp0 is the only implicit lifeline. Bare em0/fab0
// names are ordinary interfaces, while configured control/fabric roles are
// covered by TestDHCPLeaseChangeRequiresRecompile_ClusterControlFxp1.
func TestDHCPLeaseChangeRequiresRecompile_LifelineFastPathPreserved(t *testing.T) {
	for _, tc := range []struct {
		ifName        string
		wantRecompile bool
	}{
		{"fxp0", false},
		{"em0", true},
		{"fab0", true},
	} {
		t.Run(tc.ifName, func(t *testing.T) {
			d := &Daemon{}
			d.publishMgmtVRFIfaces(map[string]bool{tc.ifName: true})
			cfg := &config.Config{
				Interfaces: config.InterfacesConfig{
					Interfaces: map[string]*config.InterfaceConfig{
						tc.ifName: {
							Name: tc.ifName,
							Units: map[int]*config.InterfaceUnit{
								0: {DHCP: true},
							},
						},
					},
				},
			}

			if got := d.dhcpLeaseChangeRequiresRecompile(cfg, false); got != tc.wantRecompile {
				t.Fatalf("lease change recompile = %v, want %v for unconfigured %s",
					got, tc.wantRecompile, tc.ifName)
			}
		})
	}
}

// TestDHCPLeaseChangeRequiresRecompile_ClusterControlFxp1 covers the
// chassis-cluster case (#5791 regression guard ii): when fxp1 is configured as
// the cluster control-interface it BECOMES a host-inbound lifeline
// (HostInboundLifelineSet adds the configured control-interface, #3277), so its
// lease change retains the management-only skip — no needless recompile on a
// clustered control-interface lease.
func TestDHCPLeaseChangeRequiresRecompile_ClusterControlFxp1(t *testing.T) {
	d := &Daemon{}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp1": true})
	cfg := &config.Config{
		Chassis: config.ChassisConfig{
			Cluster: &config.ClusterConfig{
				ControlInterface: "fxp1",
			},
		},
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"fxp1": {
					Name: "fxp1",
					Units: map[int]*config.InterfaceUnit{
						0: {DHCP: true},
					},
				},
			},
		},
	}

	if d.dhcpLeaseChangeRequiresRecompile(cfg, false) {
		t.Fatal("fxp1 configured as cluster control-interface is a lifeline and " +
			"should retain the management-only fast path")
	}
}

// TestDHCPLeaseChangeRequiresRecompile_ZonedDataInterfaceUnchanged is #5791
// regression guard iii: a normal zoned data-interface DHCP lease already forced
// the recompile under the old proxy and must keep doing so under the lifeline
// gate (it is neither in the mgmt class nor a lifeline).
func TestDHCPLeaseChangeRequiresRecompile_ZonedDataInterfaceUnchanged(t *testing.T) {
	d := &Daemon{}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/3": {
					Name: "ge-0/0/3",
					Units: map[int]*config.InterfaceUnit{
						0: {DHCP: true},
					},
				},
			},
		},
	}

	if !d.dhcpLeaseChangeRequiresRecompile(cfg, false) {
		t.Fatal("zoned data-interface DHCP lease change must require the full recompile")
	}
}

// TestDHCPLeaseChangeRequiresRecompile_VRFEnslavedNonLifeline10751 pins the
// convergence the #10751 R7-B backstop relies on for VRF-enslaved units:
// the backstop SKIPS them (their LOCAL_IN identity is the shared master,
// where an iifname DROP would shadow addressed siblings), so a VRF-enslaved
// lease MUST force the full recompile that installs destination DROPs. A
// future VRF-membership fast-path skip would strand VRF leases unprotected
// with no backstop to catch them — this test makes that RED.
func TestDHCPLeaseChangeRequiresRecompile_VRFEnslavedNonLifeline10751(t *testing.T) {
	d := &Daemon{}
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{
			Interfaces: map[string]*config.InterfaceConfig{
				"ge-0/0/9": {
					Name: "ge-0/0/9",
					Units: map[int]*config.InterfaceUnit{
						0: {DHCP: true, DHCPv6: true},
					},
				},
			},
		},
		RoutingInstances: []*config.RoutingInstanceConfig{
			{Name: "vrf-data", Interfaces: []string{"ge-0/0/9.0"}},
		},
	}

	if !d.dhcpLeaseChangeRequiresRecompile(cfg, false) {
		t.Fatal("VRF-enslaved non-lifeline DHCP lease change must require the full recompile (no backstop covers it)")
	}
}
