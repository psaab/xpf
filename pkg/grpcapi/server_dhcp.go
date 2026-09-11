package grpcapi

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"time"

	"github.com/psaab/xpf/pkg/dhcp"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

func (s *Server) GetDHCPLeases(_ context.Context, _ *pb.GetDHCPLeasesRequest) (*pb.GetDHCPLeasesResponse, error) {
	if s.dhcp == nil {
		return &pb.GetDHCPLeasesResponse{}, nil
	}
	return BuildDHCPLeasesResponse(s.dhcp.Leases(), s.dhcp.DelegatedPrefixes()), nil
}

// BuildDHCPLeasesResponse aggregates DHCP address leases (IA_NA) and IPv6
// delegated prefixes (IA_PD) into the GetDHCPLeases response. A delegated
// prefix is attached to the matching inet6 address lease when one exists;
// otherwise it is surfaced as a standalone PD-only lease entry so a
// prefix-delegation-only interface (IA_PD present, no IA_NA address) still
// reports its delegated prefix (#5382). Extracted as a pure function so the
// aggregation is unit-testable without a live dhcp.Manager.
//
// #9413: it is the SINGLE lease aggregation behind both surfaces. The REST
// GET /api/v1/dhcp/leases handler maps this response rather than keeping its own
// loop, because that separate loop is how REST came to omit delegated prefixes
// (and the PD-only row) while gRPC reported them.
func BuildDHCPLeasesResponse(leases []*dhcp.Lease, pds []dhcp.DelegatedPrefix) *pb.GetDHCPLeasesResponse {
	resp := &pb.GetDHCPLeasesResponse{}
	for _, l := range leases {
		family := "inet"
		if l.Family == dhcp.AFInet6 {
			family = "inet6"
		}
		info := &pb.DHCPLeaseInfo{
			Interface: l.Interface,
			Family:    family,
			Address:   l.Address.String(),
			LeaseTime: l.LeaseTime.String(),
			Obtained:  l.Obtained.Format(time.RFC3339),
		}
		if l.Gateway.IsValid() {
			info.Gateway = l.Gateway.String()
		}
		for _, dns := range l.DNS {
			info.Dns = append(info.Dns, dns.String())
		}
		if info.Dns == nil {
			info.Dns = []string{}
		}
		resp.Leases = append(resp.Leases, info)
	}

	// Add delegated prefixes
	for _, dp := range pds {
		pdInfo := &pb.DHCPDelegatedPrefix{
			Interface:         dp.Interface,
			Prefix:            dp.Prefix.String(),
			PreferredLifetime: dp.PreferredLifetime.String(),
			ValidLifetime:     dp.ValidLifetime.String(),
			Obtained:          dp.Obtained.Format(time.RFC3339),
		}
		// Attach PD to the matching inet6 lease if one exists.
		attached := false
		for _, lease := range resp.Leases {
			if lease.Interface == dp.Interface && lease.Family == "inet6" {
				lease.DelegatedPrefixes = append(lease.DelegatedPrefixes, pdInfo)
				attached = true
				break
			}
		}
		if !attached {
			// No inet6 address lease to attach to — surface the prefix as a
			// standalone PD-only lease entry. This must fire even when there
			// are no IA_NA leases at all (resp.Leases empty), otherwise a
			// prefix-delegation-only interface reports an empty lease table
			// (#5382). A subsequent PD for the same interface attaches to the
			// standalone entry created here (it now matches the inner loop).
			resp.Leases = append(resp.Leases, &pb.DHCPLeaseInfo{
				Interface:         dp.Interface,
				Family:            "inet6",
				Dns:               []string{},
				DelegatedPrefixes: []*pb.DHCPDelegatedPrefix{pdInfo},
			})
		}
	}

	return resp
}

func (s *Server) GetDHCPClientIdentifiers(_ context.Context, _ *pb.GetDHCPClientIdentifiersRequest) (*pb.GetDHCPClientIdentifiersResponse, error) {
	if s.dhcp == nil {
		return &pb.GetDHCPClientIdentifiersResponse{}, nil
	}

	resp := &pb.GetDHCPClientIdentifiersResponse{}
	for _, d := range s.dhcp.DUIDs() {
		resp.Identifiers = append(resp.Identifiers, &pb.DHCPClientIdentifierInfo{
			Interface: d.Interface,
			Type:      d.Type,
			Display:   d.Display,
			Hex:       d.HexBytes,
		})
	}
	return resp, nil
}

func (s *Server) ClearDHCPClientIdentifier(_ context.Context, req *pb.ClearDHCPClientIdentifierRequest) (*pb.ClearDHCPClientIdentifierResponse, error) {
	if s.dhcp == nil {
		return &pb.ClearDHCPClientIdentifierResponse{Message: "No DHCP clients running"}, nil
	}

	if req.Interface != "" {
		if err := s.dhcp.ClearDUID(req.Interface); err != nil {
			// #8629 (K94, the finding this issue was split from). Bare, this
			// surfaced as codes.Unknown, so a caller could not tell a rejected
			// interface name from a filesystem fault.
			//
			// RESIDUAL, stated rather than guessed at: ClearDUID has two error
			// paths wanting different codes. `duidPath` refuses a crafted
			// interface name (#4857) -- caller error, ideally InvalidArgument --
			// while os.Remove failing is a server fault. Both arrive here as a
			// plain fmt.Errorf string, so they are not distinguishable at this
			// boundary without string-matching (fragile) or a typed error from
			// pkg/dhcp (another package). Replicating the path-traversal
			// validation here would put a second copy of a security check in a
			// different package, free to drift. Internal is the honest answer
			// for what is knowable at this boundary.
			return nil, status.Errorf(codes.Internal, "clear DUID: %v", err)
		}
		return &pb.ClearDHCPClientIdentifierResponse{
			Message: fmt.Sprintf("DHCPv6 DUID cleared for %s", req.Interface),
		}, nil
	}

	if err := s.dhcp.ClearAllDUIDs(); err != nil {
		// #8629: takes no caller input, so an error here is unambiguously a
		// server fault.
		return nil, status.Errorf(codes.Internal, "clear all DUIDs: %v", err)
	}
	return &pb.ClearDHCPClientIdentifierResponse{Message: "All DHCPv6 DUIDs cleared"}, nil
}
