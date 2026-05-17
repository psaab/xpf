package userspace

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/dataplane"
	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

func TestRuntimeSessionDeltaSnapshotAdaptsUserspaceDTOs(t *testing.T) {
	startedAt := time.Unix(123, 456)
	status := ProcessStatus{
		StartedAt:              startedAt,
		Enabled:                true,
		ForwardingArmed:        true,
		LastSnapshotGeneration: 77,
		LastFIBGeneration:      9,
		Capabilities: UserspaceCapabilities{
			ForwardingSupported: true,
			UnsupportedReasons:  []string{"example"},
		},
	}
	deltas := []SessionDeltaInfo{{
		Timestamp:        time.Unix(200, 0),
		Slot:             1,
		QueueID:          2,
		WorkerID:         3,
		Interface:        "xe-0/0/0",
		Ifindex:          10,
		Event:            "close",
		AddrFamily:       10,
		Protocol:         17,
		SrcIP:            "2001:db8::1",
		DstIP:            "2001:db8::2",
		SrcPort:          1234,
		DstPort:          53,
		IngressZone:      "trust",
		EgressZone:       "untrust",
		IngressZoneID:    1,
		EgressZoneID:     2,
		OwnerRGID:        4,
		Disposition:      "expired",
		Origin:           "helper",
		EgressIfindex:    11,
		TXIfindex:        12,
		TunnelEndpointID: 13,
		TXVLANID:         14,
		NextHop:          "2001:db8::ff",
		NeighborMAC:      "00:11:22:33:44:55",
		SrcMAC:           "00:11:22:33:44:66",
		NATSrcIP:         "2001:db8::10",
		NATDstIP:         "2001:db8::20",
		NATSrcPort:       40000,
		NATDstPort:       53000,
		FabricRedirect:   true,
		FabricIngress:    true,
	}}

	snapshot := runtimeSessionDeltaSnapshot(deltas, status, 1)
	if !snapshot.Truncated {
		t.Fatal("Truncated = false, want true when max equals returned deltas")
	}
	if snapshot.BackendEpoch != uint64(startedAt.UnixNano()) {
		t.Fatalf("BackendEpoch = %d, want %d", snapshot.BackendEpoch, startedAt.UnixNano())
	}
	if snapshot.Status.LastSnapshotGeneration != 77 {
		t.Fatalf("LastSnapshotGeneration = %d, want 77", snapshot.Status.LastSnapshotGeneration)
	}
	if len(snapshot.Status.UnsupportedReasons) != 1 || snapshot.Status.UnsupportedReasons[0] != "example" {
		t.Fatalf("UnsupportedReasons = %+v", snapshot.Status.UnsupportedReasons)
	}
	if got := len(snapshot.Deltas); got != 1 {
		t.Fatalf("len(Deltas) = %d, want 1", got)
	}
	delta := snapshot.Deltas[0]
	if delta.Family != dpruntime.SessionFamilyInet6 {
		t.Fatalf("Family = %q, want inet6", delta.Family)
	}
	if delta.Reason != dpruntime.SessionDeltaReasonClose {
		t.Fatalf("Reason = %q, want close", delta.Reason)
	}
	if delta.Generation != 77 {
		t.Fatalf("Generation = %d, want 77", delta.Generation)
	}
	if delta.Key.IngressZoneID != 1 || delta.Key.EgressZoneID != 2 {
		t.Fatalf("zone IDs = %d/%d, want 1/2", delta.Key.IngressZoneID, delta.Key.EgressZoneID)
	}
	if !delta.Value.FabricRedirect || !delta.Value.FabricIngress {
		t.Fatalf("fabric flags = redirect:%t ingress:%t, want true/true", delta.Value.FabricRedirect, delta.Value.FabricIngress)
	}
}

func TestRuntimeSessionDeltaSourceAdapterSatisfiesNeutralInterface(t *testing.T) {
	var _ dpruntime.SessionDeltaSource = (&Manager{}).RuntimeSessionDeltaSource()
}

func TestRuntimeSessionsExposeUserspaceDeltaSource(t *testing.T) {
	store := New().Sessions()
	if store.SessionDeltas() == nil {
		t.Fatal("Sessions().SessionDeltas() = nil, want userspace runtime delta source")
	}
}

type fakeUserspaceHAOps struct {
	fabric0Updates int
	fabric1Updates int
	syncs          int
	updateErr      error
	events         []string
}

func (f *fakeUserspaceHAOps) UpdateRGActive(int, bool) error {
	return nil
}

func (f *fakeUserspaceHAOps) UpdateHAWatchdog(int, uint64) error {
	return nil
}

func (f *fakeUserspaceHAOps) UpdateFabricFwd(dataplane.FabricFwdInfo) error {
	f.fabric0Updates++
	f.events = append(f.events, "fabric0")
	return f.updateErr
}

func (f *fakeUserspaceHAOps) UpdateFabricFwd1(dataplane.FabricFwdInfo) error {
	f.fabric1Updates++
	f.events = append(f.events, "fabric1")
	return f.updateErr
}

func (f *fakeUserspaceHAOps) SyncFabricState() {
	f.syncs++
	f.events = append(f.events, "sync")
}

func TestRuntimeManagerHAUsesUserspaceController(t *testing.T) {
	controller, ok := New().HA().(userspaceHAController)
	if !ok {
		t.Fatalf("Manager.HA() = %T, want userspaceHAController", New().HA())
	}
	if _, ok := controller.manager.(*Manager); !ok {
		t.Fatalf("Manager.HA() controller manager = %T, want *Manager", controller.manager)
	}
}

func TestRuntimeUserspaceHAControllerSyncsFabricStateAfterForwardingUpdate(t *testing.T) {
	fake := &fakeUserspaceHAOps{}
	controller := userspaceHAController{manager: fake}

	if err := controller.SetFabricForwarding(context.Background(), 0, dataplane.FabricFwdInfo{}); err != nil {
		t.Fatalf("SetFabricForwarding fabric0: %v", err)
	}
	if fake.fabric0Updates != 1 || fake.fabric1Updates != 0 || fake.syncs != 1 {
		t.Fatalf("fabric0 path updates/syncs = %d/%d/%d, want 1/0/1",
			fake.fabric0Updates, fake.fabric1Updates, fake.syncs)
	}
	if want := []string{"fabric0", "sync"}; !reflect.DeepEqual(fake.events, want) {
		t.Fatalf("fabric0 event order = %#v, want %#v", fake.events, want)
	}

	if err := controller.SetFabricForwarding(context.Background(), 1, dataplane.FabricFwdInfo{}); err != nil {
		t.Fatalf("SetFabricForwarding fabric1: %v", err)
	}
	if fake.fabric0Updates != 1 || fake.fabric1Updates != 1 || fake.syncs != 2 {
		t.Fatalf("fabric1 path updates/syncs = %d/%d/%d, want 1/1/2",
			fake.fabric0Updates, fake.fabric1Updates, fake.syncs)
	}
	if want := []string{"fabric0", "sync", "fabric1", "sync"}; !reflect.DeepEqual(fake.events, want) {
		t.Fatalf("fabric1 event order = %#v, want %#v", fake.events, want)
	}
}

func TestRuntimeUserspaceHAControllerDoesNotSyncFabricStateAfterUpdateError(t *testing.T) {
	fake := &fakeUserspaceHAOps{updateErr: errors.New("update failed")}
	controller := userspaceHAController{manager: fake}

	if err := controller.SetFabricForwarding(context.Background(), 0, dataplane.FabricFwdInfo{}); err == nil {
		t.Fatal("SetFabricForwarding succeeded, want update error")
	}
	if fake.syncs != 0 {
		t.Fatalf("SyncFabricState calls = %d, want 0 after update error", fake.syncs)
	}
}

func TestRuntimeUserspaceHAControllerSyncsAfterSuccessfulUpdateDespiteCanceledContext(t *testing.T) {
	fake := &fakeUserspaceHAOps{}
	controller := userspaceHAController{manager: fake}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := controller.SetFabricForwarding(ctx, 0, dataplane.FabricFwdInfo{}); err == nil {
		t.Fatal("SetFabricForwarding with initially canceled context succeeded, want context error")
	}
	if len(fake.events) != 0 {
		t.Fatalf("events after initially canceled context = %#v, want none", fake.events)
	}

	ctx = context.Background()
	if err := controller.SetFabricForwarding(ctx, 0, dataplane.FabricFwdInfo{}); err != nil {
		t.Fatalf("SetFabricForwarding after successful update: %v", err)
	}
	if want := []string{"fabric0", "sync"}; !reflect.DeepEqual(fake.events, want) {
		t.Fatalf("event order after successful update = %#v, want %#v", fake.events, want)
	}
}
