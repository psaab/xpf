package daemon

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"golang.org/x/sync/semaphore"
)

func configWithoutRIMembers11390() *config.Config {
	return &config.Config{
		RoutingInstances: []*config.RoutingInstanceConfig{{
			Name: "blue", InstanceType: "vrf", TableID: 100,
		}},
	}
}

func TestRemovedRIMemberIsDetachedOnApply11390(t *testing.T) {
	ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	linkWithMaster9813(ops, "vrf-blue", 77, 0)
	linkWithMaster9813(ops, "ge-0-0-5", 10, 77)
	d := riVRFDaemon9813(ops)

	d.bindRoutingInstanceMembers(configWithoutRIMembers11390())

	if got := ops.unboundRecorded(); len(got) != 1 || got[0] != "ge-0-0-5" {
		t.Fatalf("removed member detach calls = %v, want [ge-0-0-5]", got)
	}
	if got := ops.links["ge-0-0-5"].Attrs().MasterIndex; got != 0 {
		t.Fatalf("removed member master index = %d, want default routing context", got)
	}
	if got := ops.recorded(); len(got) != 0 {
		t.Fatalf("removed member was re-bound: %v", got)
	}
}

func TestRemovedRIMemberReassertTickDetachesWithoutRebinding11390(t *testing.T) {
	ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	linkWithMaster9813(ops, "vrf-blue", 77, 0)
	linkWithMaster9813(ops, "ge-0-0-5", 10, 77)
	d := riVRFDaemon9813(ops)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "config.db"))
	const removedMemberConfig = "routing-instances {\n    blue {\n        instance-type virtual-router;\n    }\n}\n"
	if _, err := store.SyncApply(removedMemberConfig, nil); err != nil {
		t.Fatalf("SyncApply removed-member config: %v", err)
	}
	d.store = store
	d.applySem = semaphore.NewWeighted(1)

	// The production tick reads the active post-removal snapshot and acquires
	// applySem before reconciling the surviving VRF's kernel slaves.
	d.reassertRIMemberVRFOnce(context.Background())
	if got := ops.unboundRecorded(); len(got) != 1 || got[0] != "ge-0-0-5" {
		t.Fatalf("reassert detach calls = %v, want [ge-0-0-5]", got)
	}
	if got := ops.recorded(); len(got) != 0 {
		t.Fatalf("reassert rebound a removed member: %v", got)
	}

	// A later no-drift tick must not resurrect the removed membership or
	// issue another detach after the kernel master is already clear.
	d.reassertRIMemberVRFOnce(context.Background())
	if got := ops.unboundRecorded(); len(got) != 1 {
		t.Fatalf("later tick repeated detach or rebound the member: %v", got)
	}
	if got := ops.recorded(); len(got) != 0 {
		t.Fatalf("later tick rebound a removed member: %v", got)
	}
}

func TestRemovedRIMemberDoesNotDetachAnUnrelatedMaster11390(t *testing.T) {
	ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	linkWithMaster9813(ops, "vrf-blue", 77, 0)
	linkWithMaster9813(ops, "ge-0-0-5", 10, 99)
	d := riVRFDaemon9813(ops)

	d.bindRoutingInstanceMembers(configWithoutRIMembers11390())

	if got := ops.unboundRecorded(); len(got) != 0 {
		t.Fatalf("removed member cleanup detached unrelated master 99: %v", got)
	}
	if got := ops.links["ge-0-0-5"].Attrs().MasterIndex; got != 99 {
		t.Fatalf("unrelated master changed to %d, want 99", got)
	}
}

func TestRIMemberMovedToAnotherInstanceIsNotDetached11390(t *testing.T) {
	cfg := &config.Config{RoutingInstances: []*config.RoutingInstanceConfig{
		{Name: "blue", InstanceType: "vrf", TableID: 100},
		{Name: "red", InstanceType: "vrf", TableID: 101, Interfaces: []string{"ge-0/0/5"}},
	}}
	ops := &bindRecorderOps{reconcileFakeLinkOps: newReconcileFakeLinkOps()}
	linkWithMaster9813(ops, "vrf-blue", 77, 0)
	linkWithMaster9813(ops, "vrf-red", 78, 0)
	linkWithMaster9813(ops, "ge-0-0-5", 10, 77)
	d := riVRFDaemon9813(ops)

	d.bindRoutingInstanceMembers(cfg)

	if got := ops.unboundRecorded(); len(got) != 0 {
		t.Fatalf("member still claimed by red was detached: %v", got)
	}
	if got := ops.recorded(); len(got) != 1 || got[0] != "ge-0-0-5->vrf-red" {
		t.Fatalf("move to still-desired red instance = %v, want [ge-0-0-5->vrf-red]", got)
	}
}
