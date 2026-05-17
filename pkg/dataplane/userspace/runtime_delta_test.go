package userspace

import (
	"testing"
	"time"

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
