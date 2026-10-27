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

// TestEmptyDatabaseStandbyFabricInterfacesConverge18034 drives the actual
// apply ordering that deadlocked an empty-DB standby: applyFabricIPVLAN creates
// this node's fab1 before the authoritative post-networkd management-VRF
// rebind, while the remote fab0 remains absent. Apply must not fail on that
// chassis fabric member, and the local fab1 must be bound to vrf-mgmt.
func TestEmptyDatabaseStandbyFabricInterfacesConverge18034(t *testing.T) {
	cfg := canonicalStandbyConfig18034(t)
	if cfg.Chassis.Cluster == nil || cfg.Interfaces.Interfaces["fab0"] == nil || cfg.Interfaces.Interfaces["fab1"] == nil {
		t.Fatalf("canonical standby config does not contain the chassis and fab0/fab1 stanzas")
	}
	if cfg.Interfaces.Interfaces["fab0"].LocalFabricMember != "" {
		t.Fatalf("standby fab0 unexpectedly has local member %q", cfg.Interfaces.Interfaces["fab0"].LocalFabricMember)
	}
	if cfg.Interfaces.Interfaces["fab1"].LocalFabricMember == "" {
		t.Fatal("standby fab1 has no local member to create")
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

	for name := range fabricSet {
		if _, exists := ops.links[name]; exists {
			t.Fatalf("empty-DB fixture unexpectedly created %s before apply", name)
		}
	}
	var created []string
	prevEnsure := fabricEnsureFn
	fabricEnsureFn = func(_, name string, _ []string, _ int) error {
		created = append(created, name)
		ops.links[name] = &netlink.IPVlan{LinkAttrs: netlink.LinkAttrs{
			Name: name, Index: 100 + len(ops.links), Flags: net.FlagUp,
		}}
		return nil
	}
	t.Cleanup(func() { fabricEnsureFn = prevEnsure })

	if err := d.applyFabricIPVLAN(cfg); err != nil {
		t.Fatalf("applyFabricIPVLAN: %v", err)
	}
	if len(created) != 1 || created[0] != "fab1" {
		t.Fatalf("standby fabric creation = %v, want only local fab1", created)
	}
	if _, exists := ops.links["fab0"]; exists {
		t.Fatal("apply fabricated the remote fab0 instead of leaving it absent")
	}
	if _, exists := ops.links["fab1"]; !exists {
		t.Fatal("apply did not create local fab1 before the management-VRF rebind")
	}

	if err := d.rebindManagementVRFIfaces(cfg); err != nil {
		t.Fatalf("standby bootstrap rebind failed with remote fab0 absent: %v", err)
	}
	if got := ops.links["fab1"].Attrs().MasterIndex; got != 77 {
		t.Fatalf("local fab1 MasterIndex = %d, want vrf-mgmt index 77", got)
	}
	fabricBinds := 0
	for _, bind := range ops.binds {
		if strings.HasPrefix(bind, "fab") {
			fabricBinds++
			if bind != "fab1->vrf-mgmt" {
				t.Errorf("unexpected fabric bind %q, want local fab1 only", bind)
			}
		}
	}
	if fabricBinds != 1 {
		t.Fatalf("management-VRF rebind made %d fabric binds, want one for fab1: %v", fabricBinds, ops.binds)
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
