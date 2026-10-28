// #17189: the session selector set (zone, protocol, prefixes, ports,
// nat-only, application, interface, source-NAT-pool) is declared on three
// proto requests — GetSessionsRequest, GetSessionSummaryRequest and, under
// renamed/retyped fields, ClearSessionsRequest. Before this file every
// consumer hand-projected it struct-to-struct, and each selector change
// (#15236) had to be replayed at every site; the sites that were missed
// produced a remote-CLI parity gap and an authz under-deny (#16067).
//
// This file is the single Go-side projection for grpcapi: summary and
// clear requests are copied into a GetSessionsRequest here, peer forwards
// are built here, and the authz argument reconstruction consumes the same
// copies. The wire format is unchanged; the reflection guard in
// session_selector_17189_test.go fails if a selector is ever added to one
// request without reaching the helper.
package grpcapi

import (
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// selectorFromSessions copies the selector fields of a GetSessionsRequest
// into a fresh request carrying no list/presentation state (limit, offset,
// pagination, include_peer). A nil input yields an empty (unfiltered)
// selector. Non-selector fields never travel through here, so a peer
// forward cannot inherit a local page token or recursion flag by accident.
func selectorFromSessions(req *pb.GetSessionsRequest) *pb.GetSessionsRequest {
	out := &pb.GetSessionsRequest{}
	if req == nil {
		return out
	}
	out.Zone = req.GetZone()
	out.Protocol = req.GetProtocol()
	out.SourcePrefix = req.GetSourcePrefix()
	out.DestinationPrefix = req.GetDestinationPrefix()
	out.SourcePort = req.GetSourcePort()
	out.DestinationPort = req.GetDestinationPort()
	out.NatOnly = req.GetNatOnly()
	out.Application = req.GetApplication()
	out.InterfaceFilter = req.GetInterfaceFilter()
	out.SourceNatPool = req.GetSourceNatPool()
	return out
}

// selectorFromSummary copies the selector fields of a
// GetSessionSummaryRequest (#15236) into the GetSessionsRequest shape the
// shared filter builder and authz reconstruction consume. include_peer is
// fan-out state, not a selector, and is deliberately dropped.
func selectorFromSummary(req *pb.GetSessionSummaryRequest) *pb.GetSessionsRequest {
	out := &pb.GetSessionsRequest{}
	if req == nil {
		return out
	}
	out.Zone = req.GetZone()
	out.Protocol = req.GetProtocol()
	out.SourcePrefix = req.GetSourcePrefix()
	out.DestinationPrefix = req.GetDestinationPrefix()
	out.SourcePort = req.GetSourcePort()
	out.DestinationPort = req.GetDestinationPort()
	out.NatOnly = req.GetNatOnly()
	out.Application = req.GetApplication()
	out.InterfaceFilter = req.GetInterfaceFilter()
	out.SourceNatPool = req.GetSourceNatPool()
	return out
}

// selectorFromClear copies the selector fields of a ClearSessionsRequest
// into the GetSessionsRequest shape. ClearSessions renames two fields
// (zone carries the zone NAME as a string, interface_filter is `interface`)
// and types zone differently, so the copy is field-wise rather than
// mechanical: the zone name is returned separately for the caller to
// resolve to the numeric ID GetSessions filters on, because leaving it at
// the zero wildcard on an unresolvable name would silently widen a clear
// to every zone.
func selectorFromClear(req *pb.ClearSessionsRequest) (out *pb.GetSessionsRequest, zoneName string) {
	out = &pb.GetSessionsRequest{}
	if req == nil {
		return out, ""
	}
	out.Protocol = req.GetProtocol()
	out.SourcePrefix = req.GetSourcePrefix()
	out.DestinationPrefix = req.GetDestinationPrefix()
	out.SourcePort = req.GetSourcePort()
	out.DestinationPort = req.GetDestinationPort()
	out.NatOnly = req.GetNatOnly()
	out.Application = req.GetApplication()
	out.InterfaceFilter = req.GetInterface()
	out.SourceNatPool = req.GetSourceNatPool()
	return out, req.GetZone()
}

// forwardSelector builds the GetSessionSummaryRequest forwarded to the
// cluster peer for the include_peer fan-out: the selector verbatim, with
// include_peer forced off so the peer answers from its local table without
// recursing back (the one-hop bound). A nil input forwards an unfiltered
// summary, matching the standalone/dead-peer call sites.
func forwardSelector(req *pb.GetSessionSummaryRequest) *pb.GetSessionSummaryRequest {
	out := &pb.GetSessionSummaryRequest{}
	if req == nil {
		return out
	}
	sel := selectorFromSummary(req)
	out.Zone = sel.Zone
	out.Protocol = sel.Protocol
	out.SourcePrefix = sel.SourcePrefix
	out.DestinationPrefix = sel.DestinationPrefix
	out.SourcePort = sel.SourcePort
	out.DestinationPort = sel.DestinationPort
	out.NatOnly = sel.NatOnly
	out.Application = sel.Application
	out.InterfaceFilter = sel.InterfaceFilter
	out.SourceNatPool = sel.SourceNatPool
	return out
}
