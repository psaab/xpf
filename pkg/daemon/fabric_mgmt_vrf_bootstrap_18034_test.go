package daemon

import (
	"net"
	"os"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/routing"
	"github.com/vishvananda/netlink"
)

type fabricBootstrapLinkOps18034 struct {
	*reconcileFakeLinkOps
	binds []string
}

func (o *fabricBootstrapLinkOps18034) LinkSetMaster(link, master netlink.Link) error {
	link.Attrs().MasterIndex = master.Attrs().Index
	o.binds = append(o.binds, link.Attrs().Name+"->"+master.Attrs().Name)
	return nil
}

func canonicalStandbyConfig18034(t *testing.T) *config.Config {
	t.Helper()
	raw, err := os.ReadFile("../../docs/ha-cluster-userspace.conf")
	if err != nil {
		t.Fatalf("read canonical HA config: %v", err)
	}
	tree, parseErrs := config.NewParser(string(raw)).Parse()
	if len(parseErrs) != 0 {
		t.Fatalf("parse canonical HA config: %v", parseErrs)
	}
	cfg, err := config.CompileConfigForNode(tree, 1)
	if err != nil {
		t.Fatalf("compile canonical HA config for standby node 1: %v", err)
	}
	return cfg
}

// TestEmptyDatabaseStandbyFabricInterfacesConverge18034 drives the bootstrap
// ordering that deadlocked an empty-DB standby: fab0/fab1 are in the canonical
// chassis config, but the local fabric overlay is absent when the authoritative
// post-networkd management-VRF rebind runs. The rebind must succeed, then the
// deferred fabric creation path must create and bind the local overlay.
func TestEmptyDatabaseStandbyFabricInterfacesConverge18034(t *testing.T) {
	cfg := canonicalStandbyConfig18034(t)
	if cfg.Chassis.Cluster == nil || cfg.Interfaces.Interfaces["fab0"] == nil || cfg.Interfaces.Interfaces["fab1"] == nil {
		t.Fatalf("canonical standby config does not contain the chassis and fab0/fab1 stanzas")
	}
	fabricSet := chassisClusterFabricInterfaces(cfg)
	if len(fabricSet) == 0 {
		t.Fatal("canonical standby config produced no chassis-cluster fabric interfaces")
	}
	mgmtSet := managementVRFIfaceSet(cfg)
	for name := range fabricSet {
		if !mgmtSet[name] {
			t.Fatalf("fabric interface %q is missing from the management-VRF set %v", name, mgmtSet)
		}
	}

	ops := &fabricBootstrapLinkOps18034{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	ops.links[config.ManagementVRFDeviceName] = &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 77},
		Table:     config.ManagementVRFTableID,
	}
	// Management/control NICs are present in hardware on the empty-DB standby;
	// only the software-created fabric overlays are absent.
	for i, name := range []string{"fxp0", "em0"} {
		ops.links[name] = &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: i + 2}}
	}
	d := &Daemon{
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
	}
	d.publishMgmtVRFIfaces(mgmtSet)

	// Empty DB means no fabric overlay exists at the first rebind boundary.
	for name := range fabricSet {
		if _, exists := ops.links[name]; exists {
			t.Fatalf("fixture unexpectedly created %s before the first rebind", name)
		}
	}
	if err := d.rebindManagementVRFIfaces(cfg); err != nil {
		t.Fatalf("standby bootstrap rebind failed on a not-yet-created fabric interface: %v", err)
	}
	for _, bind := range ops.binds {
		if strings.HasPrefix(bind, "fab") {
			t.Fatalf("absent fabric interface was bound before creation: %v", ops.binds)
		}
	}

	var overlays []deferredIPVLAN
	for name, ifc := range cfg.Interfaces.Interfaces {
		if ifc == nil || !strings.HasPrefix(name, "fab") || ifc.LocalFabricMember == "" {
			continue
		}
		var addrs []string
		if unit := ifc.Units[0]; unit != nil {
			addrs = unit.Addresses
		}
		overlays = append(overlays, deferredIPVLAN{
			parent: config.LinuxIfName(ifc.LocalFabricMember),
			name:   config.LinuxIfName(name),
			addrs:  addrs,
			mtu:    ifc.MTU,
		})
	}
	if len(overlays) == 0 {
		t.Fatal("canonical standby config has no local fabric overlay to create")
	}
	prevEnsure := fabricEnsureFn
	fabricEnsureFn = func(_, name string, _ []string, _ int) error {
		ops.links[name] = &netlink.IPVlan{LinkAttrs: netlink.LinkAttrs{
			Name: name, Index: 100 + len(ops.links), Flags: net.FlagUp,
		}}
		return nil
	}
	t.Cleanup(func() { fabricEnsureFn = prevEnsure })

	// This is the deferred OnXSKBound creation owner: it creates the overlay
	// after the apply's rebind point and binds it immediately to vrf-mgmt.
	d.createDeferredFabricOverlays(overlays)
	for _, overlay := range overlays {
		link, exists := ops.links[overlay.name]
		if !exists {
			t.Fatalf("deferred apply did not create %s", overlay.name)
		}
		if got := link.Attrs().MasterIndex; got != 77 {
			t.Errorf("deferred fabric %s MasterIndex = %d, want vrf-mgmt index 77", overlay.name, got)
		}
	}
	fabricBinds := 0
	for _, bind := range ops.binds {
		if strings.HasPrefix(bind, "fab") {
			fabricBinds++
		}
	}
	if fabricBinds != len(overlays) {
		t.Fatalf("deferred fabric creation made %d fabric binds, want %d: %v", fabricBinds, len(overlays), ops.binds)
	}
}

// TestMissingNonFabricManagementInterfaceStillFails18034 is the negative
// control: the fabric-specific absence tolerance must not mask a real missing
// management-interface error or report a successful apply.
func TestMissingNonFabricManagementInterfaceStillFails18034(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"fxp0": {Name: "fxp0"},
	}
	ops := &fabricBootstrapLinkOps18034{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	ops.links[config.ManagementVRFDeviceName] = &netlink.Vrf{
		LinkAttrs: netlink.LinkAttrs{Name: config.ManagementVRFDeviceName, Index: 77},
		Table:     config.ManagementVRFTableID,
	}
	d := &Daemon{
		routing:      routing.NewManagerWithLinkOpsForTest(ops),
		linkByNameFn: ops.LinkByName,
	}
	d.publishMgmtVRFIfaces(managementVRFIfaceSet(cfg))

	err := d.rebindManagementVRFIfaces(cfg)
	if err == nil || !strings.Contains(err.Error(), "re-bind fxp0 to management VRF") || !strings.Contains(err.Error(), "interface fxp0 not found") {
		t.Fatalf("missing non-fabric management interface error = %v, want the original fxp0 not-found failure", err)
	}
}
