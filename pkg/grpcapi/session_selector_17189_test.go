// #17189: the protoreflect guard for the session selector contract.
// The selector set is declared on GetSessionsRequest and re-declared on
// GetSessionSummaryRequest (#15236); ClearSessionsRequest carries it
// renamed/retyped. Before the shared session_selector.go helper, every
// consumer hand-projected the set and a missed site produced a live
// parity gap (remote CLI) and an authz under-deny.
//
// FAIL-ON-DRIFT: adding a selector field to GetSessionSummaryRequest
// without copying it in selectorFromSummary — or renaming one so the
// name/kind match against GetSessionsRequest breaks — makes these tests
// fail at the field that drifted, instead of silently dropping the new
// selector at every consumer the way #15236's initial pass dropped the
// summary leg.
package grpcapi

import (
	"testing"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// TestSessionSelectorSummaryFieldsMatchSessions17189 asserts the issue's
// acceptance shape directly: every field of GetSessionSummaryRequest
// except include_peer exists by name and kind in GetSessionsRequest, and
// selectorFromSummary copies each one. A future selector added to only
// one request (the #15236 omission) fails here naming the field.
func TestSessionSelectorSummaryFieldsMatchSessions17189(t *testing.T) {
	sumMD := (&pb.GetSessionSummaryRequest{}).ProtoReflect().Descriptor()
	sessMD := (&pb.GetSessionsRequest{}).ProtoReflect().Descriptor()

	typed := &pb.GetSessionSummaryRequest{
		IncludePeer:       true, // fan-out state; must NOT travel as a selector
		Zone:              4242,
		Protocol:          "sentinel-protocol",
		SourcePrefix:      "sentinel-source_prefix",
		DestinationPrefix: "sentinel-destination_prefix",
		SourcePort:        4242,
		DestinationPort:   4243,
		NatOnly:           true,
		Application:       "sentinel-application",
		InterfaceFilter:   "sentinel-interface_filter",
		SourceNatPool:     "sentinel-source_nat_pool",
	}
	got := selectorFromSummary(typed)
	gotMsg := got.ProtoReflect()
	sumMsg := typed.ProtoReflect()

	for i := range sumMD.Fields().Len() {
		fd := sumMD.Fields().Get(i)
		name := string(fd.Name())
		if name == "include_peer" {
			continue
		}
		sessFD := sessMD.Fields().ByName(fd.Name())
		if sessFD == nil {
			t.Errorf("GetSessionSummaryRequest.%s has no same-name field in GetSessionsRequest — the selector sets have drifted (#17189)", name)
			continue
		}
		if sessFD.Kind() != fd.Kind() {
			t.Errorf("field %s: kind drift, summary=%v sessions=%v", name, fd.Kind(), sessFD.Kind())
			continue
		}
		if gotV, want := gotMsg.Get(sessFD), sumMsg.Get(fd); gotV.String() != want.String() {
			t.Errorf("selectorFromSummary dropped/mismatched %s: got %v, want %v", name, gotV, want)
		}
	}
	// include_peer is fan-out state, not a selector: the projection must
	// not smuggle it into the sessions shape (which would re-enable peer
	// recursion through a forwarded request).
	if got.GetIncludePeer() {
		t.Errorf("selectorFromSummary carried include_peer; fan-out state must not travel as a selector")
	}
	// Nil input stays an empty (unfiltered) selector.
	if empty := selectorFromSummary(nil); empty == nil || empty.GetZone() != 0 || empty.GetProtocol() != "" {
		t.Errorf("selectorFromSummary(nil) = %v, want empty selector", empty)
	}
	if empty := selectorFromSessions(nil); empty == nil || empty.GetZone() != 0 {
		t.Errorf("selectorFromSessions(nil) = %v, want empty selector", empty)
	}
	// selectorFromSessions must not carry list/presentation state.
	listy := selectorFromSessions(&pb.GetSessionsRequest{
		Zone: 7, Protocol: "TCP", SourceNatPool: "pool1",
		Limit: 100, Offset: 5, IncludePeer: true, PageToken: "tok", PageSize: 50, NoEnrich: true,
	})
	if listy.GetZone() != 7 || listy.GetProtocol() != "TCP" || listy.GetSourceNatPool() != "pool1" {
		t.Errorf("selectorFromSessions dropped selector fields: %v", listy)
	}
	if listy.GetLimit() != 0 || listy.GetOffset() != 0 || listy.GetIncludePeer() ||
		listy.GetPageToken() != "" || listy.GetPageSize() != 0 || listy.GetNoEnrich() {
		t.Errorf("selectorFromSessions carried list state (limit/offset/include_peer/page/no_enrich): %v", listy)
	}
}

// TestSessionSelectorClearFieldsCopied17189 covers the renamed/retyped
// third declaration: every ClearSessionsRequest selector must be copied
// by selectorFromClear under its GetSessionsRequest name, with zone
// returned by name for the caller to resolve (never pre-resolved to the
// numeric wildcard).
func TestSessionSelectorClearFieldsCopied17189(t *testing.T) {
	clearReq := &pb.ClearSessionsRequest{
		SourcePrefix:      "sentinel-source_prefix",
		DestinationPrefix: "sentinel-destination_prefix",
		Protocol:          "sentinel-protocol",
		Zone:              "trust",
		SourcePort:        4242,
		DestinationPort:   4243,
		Application:       "sentinel-application",
		Interface:         "sentinel-interface",
		NatOnly:           true,
		SourceNatPool:     "sentinel-source_nat_pool",
	}
	got, zoneName := selectorFromClear(clearReq)
	if zoneName != "trust" {
		t.Errorf("selectorFromClear zoneName = %q, want %q (zone travels by name for caller resolution)", zoneName, "trust")
	}
	if got.GetZone() != 0 {
		t.Errorf("selectorFromClear set numeric Zone=%d from a zone NAME; resolution is the caller's job or the wildcard widens", got.GetZone())
	}
	for k, w := range map[string]string{
		"Protocol":          "sentinel-protocol",
		"SourcePrefix":      "sentinel-source_prefix",
		"DestinationPrefix": "sentinel-destination_prefix",
		"Application":       "sentinel-application",
		"InterfaceFilter":   "sentinel-interface", // ClearSessions `interface` rename
		"SourceNatPool":     "sentinel-source_nat_pool",
	} {
		var gv string
		switch k {
		case "Protocol":
			gv = got.GetProtocol()
		case "SourcePrefix":
			gv = got.GetSourcePrefix()
		case "DestinationPrefix":
			gv = got.GetDestinationPrefix()
		case "Application":
			gv = got.GetApplication()
		case "InterfaceFilter":
			gv = got.GetInterfaceFilter()
		case "SourceNatPool":
			gv = got.GetSourceNatPool()
		}
		if gv != w {
			t.Errorf("selectorFromClear %s = %q, want %q", k, gv, w)
		}
	}
	if got.GetSourcePort() != 4242 || got.GetDestinationPort() != 4243 {
		t.Errorf("selectorFromClear ports = %d/%d, want 4242/4243", got.GetSourcePort(), got.GetDestinationPort())
	}
	if !got.GetNatOnly() {
		t.Errorf("selectorFromClear dropped nat_only")
	}
	if empty, zn := selectorFromClear(nil); empty == nil || zn != "" || empty.GetProtocol() != "" {
		t.Errorf("selectorFromClear(nil) = (%v, %q), want empty selector and empty zone name", empty, zn)
	}
}

// TestSessionSelectorForwardDropsIncludePeer17189 pins the one-hop bound:
// forwardSelector must carry the selector verbatim but never propagate
// include_peer, or the peer would fan out again.
func TestSessionSelectorForwardDropsIncludePeer17189(t *testing.T) {
	in := &pb.GetSessionSummaryRequest{
		IncludePeer:       true,
		Zone:              7,
		Protocol:          "TCP",
		SourcePrefix:      "10.0.0.0/8",
		DestinationPrefix: "192.0.2.0/24",
		SourcePort:        1024,
		DestinationPort:   443,
		NatOnly:           true,
		Application:       "junos-https",
		InterfaceFilter:   "reth1.0",
		SourceNatPool:     "pool1",
	}
	fwd := forwardSelector(in)
	if fwd.GetIncludePeer() {
		t.Errorf("forwardSelector propagated include_peer — peer would recurse")
	}
	if got, want := selectorFromSummary(fwd), selectorFromSummary(in); got.String() != want.String() {
		t.Errorf("forwardSelector selector drift:\n got %v\nwant %v", got, want)
	}
	if fwd := forwardSelector(nil); fwd == nil || fwd.GetIncludePeer() {
		t.Errorf("forwardSelector(nil) = %v, want non-nil unfiltered forward with include_peer off", fwd)
	}
}
