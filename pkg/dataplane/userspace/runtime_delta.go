package userspace

import (
	"strings"
	"time"

	dpruntime "github.com/psaab/xpf/pkg/dataplane/runtime"
)

var _ dpruntime.SessionDeltaSource = runtimeSessionDeltaSource{}

type runtimeSessionDeltaSource struct {
	manager *Manager
}

func (s runtimeSessionDeltaSource) DrainSessionDeltas(max uint32) (dpruntime.SessionDeltaSnapshot, error) {
	deltas, status, err := s.manager.DrainSessionDeltas(max)
	if err != nil {
		return runtimeSessionDeltaSnapshot(deltas, status, max), err
	}
	return runtimeSessionDeltaSnapshot(deltas, status, max), nil
}

func (s runtimeSessionDeltaSource) ExportOwnerRGSessions(rgIDs []int, max uint32) (dpruntime.SessionDeltaSnapshot, error) {
	deltas, status, err := s.manager.ExportOwnerRGSessions(rgIDs, max)
	if err != nil {
		return runtimeSessionDeltaSnapshot(deltas, status, max), err
	}
	return runtimeSessionDeltaSnapshot(deltas, status, max), nil
}

func (s runtimeSessionDeltaSource) SessionSyncSweepProfile() (bool, time.Duration, time.Duration) {
	return s.manager.SessionSyncSweepProfile()
}

func runtimeSessionDeltaSnapshot(deltas []SessionDeltaInfo, status ProcessStatus, max uint32) dpruntime.SessionDeltaSnapshot {
	out := dpruntime.SessionDeltaSnapshot{
		Deltas:       make([]dpruntime.SessionDelta, 0, len(deltas)),
		Status:       runtimeStatus(status),
		BackendEpoch: runtimeBackendEpoch(status),
		Truncated:    max > 0 && uint32(len(deltas)) >= max,
	}
	for _, delta := range deltas {
		out.Deltas = append(out.Deltas, runtimeSessionDelta(delta, status.LastSnapshotGeneration))
	}
	return out
}

func runtimeStatus(status ProcessStatus) dpruntime.RuntimeStatus {
	return dpruntime.RuntimeStatus{
		Enabled:                status.Enabled,
		ForwardingArmed:        status.ForwardingArmed,
		ForwardingSupported:    status.Capabilities.ForwardingSupported,
		UnsupportedReasons:     append([]string(nil), status.Capabilities.UnsupportedReasons...),
		LastSnapshotGeneration: status.LastSnapshotGeneration,
		LastFIBGeneration:      status.LastFIBGeneration,
	}
}

func runtimeBackendEpoch(status ProcessStatus) uint64 {
	if status.StartedAt.IsZero() {
		return 0
	}
	return uint64(status.StartedAt.UnixNano())
}

func runtimeSessionDelta(delta SessionDeltaInfo, generation uint64) dpruntime.SessionDelta {
	return dpruntime.SessionDelta{
		Timestamp: delta.Timestamp,
		Slot:      delta.Slot,
		QueueID:   delta.QueueID,
		WorkerID:  delta.WorkerID,
		Interface: delta.Interface,
		Ifindex:   delta.Ifindex,
		Family:    runtimeSessionFamily(delta.AddrFamily),
		Key: dpruntime.SessionIdentity{
			Protocol:      delta.Protocol,
			SrcIP:         delta.SrcIP,
			DstIP:         delta.DstIP,
			SrcPort:       delta.SrcPort,
			DstPort:       delta.DstPort,
			IngressZone:   delta.IngressZone,
			EgressZone:    delta.EgressZone,
			IngressZoneID: delta.IngressZoneID,
			EgressZoneID:  delta.EgressZoneID,
		},
		Value: dpruntime.SessionState{
			Disposition:      delta.Disposition,
			Origin:           delta.Origin,
			EgressIfindex:    delta.EgressIfindex,
			TXIfindex:        delta.TXIfindex,
			TunnelEndpointID: delta.TunnelEndpointID,
			TXVLANID:         delta.TXVLANID,
			NextHop:          delta.NextHop,
			NeighborMAC:      delta.NeighborMAC,
			SrcMAC:           delta.SrcMAC,
			NATSrcIP:         delta.NATSrcIP,
			NATDstIP:         delta.NATDstIP,
			NATSrcPort:       delta.NATSrcPort,
			NATDstPort:       delta.NATDstPort,
			FabricRedirect:   delta.FabricRedirect,
			FabricIngress:    delta.FabricIngress,
		},
		OwnerRGID:  delta.OwnerRGID,
		Reason:     runtimeSessionDeltaReason(delta.Event),
		Generation: generation,
	}
}

func runtimeSessionFamily(family uint8) dpruntime.SessionFamily {
	switch family {
	case 6, 10:
		return dpruntime.SessionFamilyInet6
	default:
		return dpruntime.SessionFamilyInet
	}
}

func runtimeSessionDeltaReason(event string) dpruntime.SessionDeltaReason {
	switch strings.ToLower(event) {
	case "close", "closed", "delete", "deleted":
		return dpruntime.SessionDeltaReasonClose
	case "update", "updated":
		return dpruntime.SessionDeltaReasonUpdate
	default:
		return dpruntime.SessionDeltaReasonOpen
	}
}
