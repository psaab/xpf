package grpcapi

import (
	"context"
	"sort"

	"github.com/psaab/xpf/pkg/dataplane"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (s *Server) GetZones(_ context.Context, _ *pb.GetZonesRequest) (*pb.GetZonesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetZonesResponse{}, nil
	}

	cr := s.applyResult()

	resp := &pb.GetZonesResponse{}
	for zoneName, zone := range cfg.Security.Zones {
		zi := &pb.ZoneInfo{
			Name:        zoneName,
			Description: zone.Description,
			Interfaces:  zone.Interfaces,
			TcpRst:      zone.TCPRst,
		}
		if zone.ScreenProfile != "" {
			zi.ScreenProfile = zone.ScreenProfile
		}
		if zone.HostInboundTraffic != nil {
			zi.HostInboundServices = append(zi.HostInboundServices, zone.HostInboundTraffic.SystemServices...)
			zi.HostInboundServices = append(zi.HostInboundServices, zone.HostInboundTraffic.Protocols...)
		}
		if zi.Interfaces == nil {
			zi.Interfaces = []string{}
		}
		if zi.HostInboundServices == nil {
			zi.HostInboundServices = []string{}
		}

		if cr != nil {
			if id, ok := cr.ZoneIDs[zoneName]; ok {
				zi.Id = uint32(id)
				if s.dp != nil && s.dp.IsLoaded() {
					if ing, err := s.dp.ReadZoneCounters(id, 0); err == nil {
						zi.IngressPackets = ing.Packets
						zi.IngressBytes = ing.Bytes
					}
					if eg, err := s.dp.ReadZoneCounters(id, 1); err == nil {
						zi.EgressPackets = eg.Packets
						zi.EgressBytes = eg.Bytes
					}
				}
			}
		}
		resp.Zones = append(resp.Zones, zi)
	}
	sort.Slice(resp.Zones, func(i, j int) bool { return resp.Zones[i].Name < resp.Zones[j].Name })
	return resp, nil
}

func (s *Server) GetPolicies(_ context.Context, _ *pb.GetPoliciesRequest) (*pb.GetPoliciesResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetPoliciesResponse{}, nil
	}

	resp := &pb.GetPoliciesResponse{}
	var policySetID uint32
	for _, zpp := range cfg.Security.Policies {
		pi := &pb.PolicyInfo{
			FromZone: zpp.FromZone,
			ToZone:   zpp.ToZone,
		}
		for i, rule := range zpp.Policies {
			pr := &pb.PolicyRule{
				Name:         rule.Name,
				Description:  rule.Description,
				Action:       policyActionStr(rule.Action),
				SrcAddresses: rule.Match.SourceAddresses,
				DstAddresses: rule.Match.DestinationAddresses,
				Applications: rule.Match.Applications,
				Log:          rule.Log != nil,
				Count:        rule.Count,
			}
			if pr.SrcAddresses == nil {
				pr.SrcAddresses = []string{}
			}
			if pr.DstAddresses == nil {
				pr.DstAddresses = []string{}
			}
			if pr.Applications == nil {
				pr.Applications = []string{}
			}
			if s.dp != nil && s.dp.IsLoaded() {
				policyID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
				if ctrs, err := s.dp.ReadPolicyCounters(policyID); err == nil {
					pr.HitPackets = ctrs.Packets
					pr.HitBytes = ctrs.Bytes
				}
			}
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []*pb.PolicyRule{}
		}
		resp.Policies = append(resp.Policies, pi)
		policySetID++
	}

	// Global policies
	if len(cfg.Security.GlobalPolicies) > 0 {
		pi := &pb.PolicyInfo{
			FromZone: "*",
			ToZone:   "*",
		}
		for i, rule := range cfg.Security.GlobalPolicies {
			pr := &pb.PolicyRule{
				Name:         rule.Name,
				Description:  rule.Description,
				Action:       policyActionStr(rule.Action),
				SrcAddresses: rule.Match.SourceAddresses,
				DstAddresses: rule.Match.DestinationAddresses,
				Applications: rule.Match.Applications,
				Log:          rule.Log != nil,
				Count:        rule.Count,
			}
			if pr.SrcAddresses == nil {
				pr.SrcAddresses = []string{}
			}
			if pr.DstAddresses == nil {
				pr.DstAddresses = []string{}
			}
			if pr.Applications == nil {
				pr.Applications = []string{}
			}
			if s.dp != nil && s.dp.IsLoaded() {
				policyID := policySetID*dataplane.MaxRulesPerPolicy + uint32(i)
				if ctrs, err := s.dp.ReadPolicyCounters(policyID); err == nil {
					pr.HitPackets = ctrs.Packets
					pr.HitBytes = ctrs.Bytes
				}
			}
			pi.Rules = append(pi.Rules, pr)
		}
		if pi.Rules == nil {
			pi.Rules = []*pb.PolicyRule{}
		}
		resp.Policies = append(resp.Policies, pi)
	}

	return resp, nil
}

func (s *Server) GetScreen(_ context.Context, _ *pb.GetScreenRequest) (*pb.GetScreenResponse, error) {
	cfg := s.store.ActiveConfig()
	if cfg == nil {
		return &pb.GetScreenResponse{}, nil
	}

	resp := &pb.GetScreenResponse{}
	for name, profile := range cfg.Security.Screen {
		si := &pb.ScreenInfo{
			Name:   name,
			Checks: screenChecks(profile),
		}
		if si.Checks == nil {
			si.Checks = []string{}
		}
		resp.Screens = append(resp.Screens, si)
	}
	sort.Slice(resp.Screens, func(i, j int) bool { return resp.Screens[i].Name < resp.Screens[j].Name })
	return resp, nil
}
