package grpcapi

import (
	"context"
	"time"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
)

func (s *Server) GetEvents(_ context.Context, req *pb.GetEventsRequest) (*pb.GetEventsResponse, error) {
	if s.eventBuf == nil {
		return &pb.GetEventsResponse{}, nil
	}

	limit := int(req.Limit)
	if limit <= 0 {
		limit = 50
	}
	if limit > 10000 {
		limit = 10000
	}

	filter := logging.EventFilter{
		Zone:     uint16(req.Zone),
		Action:   req.Action,
		Protocol: req.Protocol,
	}

	var events []logging.EventRecord
	if filter.IsEmpty() {
		events = s.eventBuf.Latest(limit)
	} else {
		events = s.eventBuf.LatestFiltered(limit, filter)
	}

	// Build reverse zone ID → name map
	evZoneNames := make(map[uint16]string)
	if cr := s.applyResult(); cr != nil {
		for name, id := range cr.ZoneIDs {
			evZoneNames[id] = name
		}
	}

	resp := &pb.GetEventsResponse{}
	for _, ev := range events {
		resp.Events = append(resp.Events, &pb.EventEntry{
			Time:            ev.Time.Format(time.RFC3339),
			Type:            ev.Type,
			SrcAddr:         ev.SrcAddr,
			DstAddr:         ev.DstAddr,
			Protocol:        ev.Protocol,
			Action:          ev.Action,
			PolicyId:        ev.PolicyID,
			IngressZone:     uint32(ev.InZone),
			EgressZone:      uint32(ev.OutZone),
			IngressZoneName: evZoneNames[ev.InZone],
			EgressZoneName:  evZoneNames[ev.OutZone],
			ScreenCheck:     ev.ScreenCheck,
			SessionPackets:  ev.SessionPkts,
			SessionBytes:    ev.SessionBytes,
			PolicyName:      ev.PolicyName,
			RevSessionPkts:  ev.RevSessionPkts,
			RevSessionBytes: ev.RevSessionBytes,
			AppName:         ev.AppName,
			IngressIface:    ev.IngressIface,
			CloseReason:     ev.CloseReason,
		})
	}
	return resp, nil
}
