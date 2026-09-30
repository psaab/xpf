package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sync/semaphore"
)

func mgmtRIMemberConfig11392(name string) *config.Config {
	return &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			name: {Name: name, Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		}},
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name: "blue", InstanceType: "vrf", TableID: 100, Interfaces: []string{name + ".0"},
		}},
	}
}

func mgmtRIMemberOps11392(name string, master int) *bindRecorderOps {
	ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	linkWithMaster9813(ops, "vrf-mgmt", 70, 0)
	linkWithMaster9813(ops, "vrf-blue", 77, 0)
	linkWithMaster9813(ops, name, 10, master)
	return ops
}

func TestManagementClassRIMemberApplyDoesNotBindTenant11392(t *testing.T) {
	for _, name := range []string{"fxp0", "fab0", "em0"} {
		t.Run(name, func(t *testing.T) {
			ops := mgmtRIMemberOps11392(name, 70)
			d := riVRFDaemon9813(ops)

			d.bindRoutingInstanceMembers(mgmtRIMemberConfig11392(name))

			if got := ops.recorded(); len(got) != 0 {
				t.Fatalf("management-class member bound to tenant VRF: %v", got)
			}
			if got := ops.unboundRecorded(); len(got) != 0 {
				t.Fatalf("management-class member detached from vrf-mgmt: %v", got)
			}
			if got := ops.links[name].Attrs().MasterIndex; got != 70 {
				t.Fatalf("%s master index = %d, want vrf-mgmt index 70", name, got)
			}
		})
	}
}

func TestManagementClassRIMemberReassertDoesNotBindTenant11392(t *testing.T) {
	for _, name := range []string{"fxp0", "fab0", "em0"} {
		t.Run(name, func(t *testing.T) {
			ops := mgmtRIMemberOps11392(name, 70)
			d := riVRFDaemon9813(ops)

			d.rebindRIMembersOutsideTheirVRF(mgmtRIMemberConfig11392(name))

			if got := ops.recorded(); len(got) != 0 {
				t.Fatalf("management-class member re-bound to tenant VRF: %v", got)
			}
			if got := ops.unboundRecorded(); len(got) != 0 {
				t.Fatalf("management-class member detached from vrf-mgmt: %v", got)
			}
			if got := ops.links[name].Attrs().MasterIndex; got != 70 {
				t.Fatalf("%s master index = %d, want vrf-mgmt index 70", name, got)
			}
		})
	}
}

func TestManagementClassRIMemberIsNotDetachedByStaleReassertCleanup11392(t *testing.T) {
	ops := mgmtRIMemberOps11392("fxp0", 77)
	d := riVRFDaemon9813(ops)
	cfg := &config.Config{RoutingInstances: []*config.RoutingInstanceConfig{{
		Name: "blue", InstanceType: "vrf", TableID: 100,
	}}}

	d.rebindRIMembersOutsideTheirVRF(cfg)

	if got := ops.unboundRecorded(); len(got) != 0 {
		t.Fatalf("stale tenant cleanup detached management-class fxp0: %v", got)
	}
}

func TestFxp0StaysInManagementVRFAcrossReassertTicks11392(t *testing.T) {
	ops := mgmtRIMemberOps11392("fxp0", 70)
	d := riVRFDaemon9813(ops)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	const configText = "routing-instances {\n    blue {\n        instance-type virtual-router;\n        interface fxp0.0;\n    }\n}\n"
	if _, err := store.SyncApply(configText, nil); err != nil {
		t.Fatalf("SyncApply management-member config: %v", err)
	}
	d.store = store
	d.applySem = semaphore.NewWeighted(1)
	d.publishMgmtVRFIfaces(map[string]bool{"fxp0": true})

	for tick := 0; tick < 3; tick++ {
		d.reassertRIMemberVRFOnce(context.Background())
	}
	if got := ops.recorded(); len(got) != 0 {
		t.Fatalf("periodic reassert stole fxp0 from vrf-mgmt: %v", got)
	}
	if got := ops.unboundRecorded(); len(got) != 0 {
		t.Fatalf("periodic reassert detached fxp0 from vrf-mgmt: %v", got)
	}
	if got := ops.links["fxp0"].Attrs().MasterIndex; got != 70 {
		t.Fatalf("fxp0 master index after three ticks = %d, want vrf-mgmt index 70", got)
	}
}

func TestOrdinaryRIMemberStillBindsToTenant11392(t *testing.T) {
	cfg := &config.Config{
		Interfaces: config.InterfacesConfig{Interfaces: map[string]*config.InterfaceConfig{
			"ge-0/0/5": {Name: "ge-0/0/5", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		}},
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name: "blue", InstanceType: "vrf", TableID: 100, Interfaces: []string{"ge-0/0/5.0"},
		}},
	}
	ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	linkWithMaster9813(ops, "vrf-blue", 77, 0)
	linkWithMaster9813(ops, "ge-0-0-5", 10, 0)
	d := riVRFDaemon9813(ops)

	d.bindRoutingInstanceMembers(cfg)

	if got := ops.recorded(); len(got) != 1 || got[0] != "ge-0-0-5->vrf-blue" {
		t.Fatalf("ordinary member bind = %v, want [ge-0-0-5->vrf-blue]", got)
	}
}
