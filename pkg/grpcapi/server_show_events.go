package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/config"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
	"github.com/psaab/xpf/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (s *Server) GetEvents(_ context.Context, req *pb.GetEventsRequest) (*pb.GetEventsResponse, error) {
	if s.eventBuf == nil {
		return &pb.GetEventsResponse{}, nil
	}

	// Zone IDs are uint16 internally; the request value is uint32. A value
	// above 65535 used to be narrowed by an unchecked uint16() cast, which
	// silently WRAPS (65536 -> 0 = no filter, 65537 -> zone 1) and returns
	// the wrong events or hides the intended ones. Reject out-of-range input
	// up front, matching the sessions path (buildSessionFilter) and the REST
	// events guard (queryUint16Strict) which both fail-closed (#3334).
	if req.Zone > 65535 {
		return nil, status.Errorf(codes.InvalidArgument, "invalid zone id %d", req.Zone)
	}

	limit := int(req.Limit)
	if limit <= 0 {
		limit = 50
	}
	if limit > 10000 {
		limit = 10000
	}

	// Zone-filter presence: an explicit has_zone selects the zone filter even
	// for zone 0 (the "unknown" / unassigned zone carried by pre-classification
	// and host-inbound events), which #3338 makes selectable. For backward
	// compatibility a non-zero zone still filters when has_zone is unset, so a
	// pre-#3338 client passing only zone=N is unaffected; only the new
	// has_zone=true + zone=0 combination isolates the unknown-zone events. A
	// bare zone=0 with has_zone=false stays "no filter" (match-all), preserving
	// the #3334 sentinel.
	filter := logging.EventFilter{
		Zone:     uint16(req.Zone),
		HasZone:  req.GetHasZone() || req.Zone != 0,
		Action:   req.Action,
		Protocol: req.Protocol,
	}

	var events []logging.EventRecord
	if filter.IsEmpty() {
		events = s.eventBuf.Latest(limit)
	} else {
		events = s.eventBuf.LatestFiltered(limit, filter)
	}

	// Build reverse zone ID → name map from the CURRENT config. This is only a
	// fallback for legacy records that predate the resolved-at-event-time zone
	// names (#3335): each EventRecord already stores InZoneName/OutZoneName as
	// resolved when the event fired, so a later zone rename / delete / ID reuse
	// (#3075) must NOT retroactively rewrite an old event's zone name from the
	// live config. Prefer the stored name; only consult this map when the
	// record carries no resolved name.
	var cfg *config.Config
	if s.store != nil {
		cfg = s.store.ActiveConfig()
	}
	evZoneNames := make(map[uint16]string)
	if cr := s.applyResult(); cr != nil {
		evZoneNames = config.SurvivorZoneNames(cr.ZoneIDs, cfg)
	}
	zoneName := func(stored string, id uint16) string {
		if stored != "" {
			return stored
		}
		return evZoneNames[id]
	}

	resp := &pb.GetEventsResponse{}
	for _, ev := range events {
		resp.Events = append(resp.Events, &pb.EventEntry{
			Time:            ev.Time.Format(time.RFC3339Nano),
			Type:            ev.Type,
			SrcAddr:         ev.SrcAddr,
			DstAddr:         ev.DstAddr,
			Protocol:        ev.Protocol,
			Action:          ev.Action,
			PolicyId:        ev.PolicyID,
			IngressZone:     uint32(ev.InZone),
			EgressZone:      uint32(ev.OutZone),
			IngressZoneName: zoneName(ev.InZoneName, ev.InZone),
			EgressZoneName:  zoneName(ev.OutZoneName, ev.OutZone),
			ScreenCheck:     ev.ScreenCheck,
			SessionPackets:  ev.SessionPkts,
			SessionBytes:    ev.SessionBytes,
			PolicyName:      ev.PolicyName,
			RevSessionPkts:  ev.RevSessionPkts,
			RevSessionBytes: ev.RevSessionBytes,
			AppName:         ev.AppName,
			IngressIface:    ev.IngressIface,
			CloseReason:     ev.CloseReason,
			NatSrcAddr:      ev.NATSrcAddr,
			NatDstAddr:      ev.NATDstAddr,
			SessionId:       ev.SessionID,
			ElapsedTime:     ev.ElapsedTime,
			Created:         ev.Created,
			CreatedNanos:    ev.CreatedNanos,
			EgressIfindex:   ev.EgressIfindex,
			IngressIfindex:  ev.IngressIfindex,
			Tos:             uint32(ev.TOS),
			TcpControlBits:  uint32(ev.TCPControlBits),
			Reason:          ev.Reason,
		})
	}
	return resp, nil
}

// --- #1700: residual ShowText branches ---

func (s *Server) showEventOptions(cfg *config.Config, buf *strings.Builder) {
	if cfg == nil || len(cfg.EventOptions) == 0 {
		buf.WriteString("No event-options configured\n")
	} else {
		for _, ep := range cfg.EventOptions {
			fmt.Fprintf(buf, "Policy: %s\n", ep.Name)
			if len(ep.Events) > 0 {
				fmt.Fprintf(buf, "  Events: %s\n", strings.Join(ep.Events, ", "))
			}
			for _, w := range ep.WithinClauses {
				if w == nil {
					continue // #9916 F-135: never panic display on a corrupt clause
				}
				fmt.Fprintf(buf, "  Within: %d seconds", w.Seconds)
				if w.TriggerOn > 0 {
					fmt.Fprintf(buf, ", trigger on %d", w.TriggerOn)
				}
				if w.TriggerUntil > 0 {
					fmt.Fprintf(buf, ", trigger until %d", w.TriggerUntil)
				}
				buf.WriteString("\n")
			}
			if len(ep.AttributesMatch) > 0 {
				buf.WriteString("  Attributes match:\n")
				for _, am := range ep.AttributesMatch {
					fmt.Fprintf(buf, "    %s\n", am)
				}
			}
			if len(ep.ThenCommands) > 0 {
				buf.WriteString("  Then commands:\n")
				for _, cmd := range ep.ThenCommands {
					fmt.Fprintf(buf, "    %s\n", cmd)
				}
			}
			buf.WriteString("\n")
		}
	}
}
