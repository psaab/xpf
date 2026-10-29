package userspace

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

// #17142 (acceptance 2): the populated session_delta_info specimen,
// decoded field-by-value.
//
// The #16132 default specimen carries ingress_ifindex ==
// nat_scope_ifindex == 0, so no key-set cell can see those two keys
// SWAPPED — a swap preserves the set. The Go #11070 cell was named for
// exactly that per-field identity, but it resolved the key through a
// file-wide first-match regex and read ExceptionStatus's rename instead
// of SessionDeltaInfo's (mutant C in the issue: swap the two renames in
// binding.rs and every Go cell stayed green).
//
// This cell reads no Rust source at all. The Rust golden
// (wire_invariant_default_specimens) serializes a SessionDeltaInfo with
// a DISTINCT sentinel in every field into
// tests/fixtures/protocol_wire_v1.json as `session_delta_info_populated`;
// this decodes those BYTES into the Go struct and asserts every field
// carries its own sentinel. A rename swap on either side transposes two
// sentinels and reds here with both values visible; a one-sided rename
// that reaches a regenerated fixture decodes the sentinel into the wrong
// field (or drops it) and reds the same way. The sentinels are restated
// here deliberately: they are the fixture's published values, and the
// Rust golden will red on regeneration drift if they move there without
// moving here — that two-sided restatement is what makes this an
// agreement check rather than a self-consistency check.
//
// FAIL-ON-REVERT (mutant C): swap `ingress_ifindex`/`nat_scope_ifindex`
// renames in binding.rs, regenerate the fixture, and IngressIfindex /
// NatScopeIfindex below read each other's sentinel — RED. Mutant B
// (pub -> pub(crate) on a SessionDeltaInfo field) touches no wire bytes
// and stays GREEN here and in every cell routed through rustwire_test.go.
func TestSessionDeltaPopulatedSpecimenValues17142(t *testing.T) {
	fixture := loadWireFixture16132(t)
	raw, ok := fixture["session_delta_info_populated"]
	if !ok {
		t.Fatalf("fixture has no session_delta_info_populated specimen — the populated " +
			"golden in wire_invariant_default_specimens was deleted, and with it the only " +
			"value-level guard against a SessionDeltaInfo rename swap (#17142)")
	}
	var delta SessionDeltaInfo
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&delta); err != nil {
		t.Fatalf("strict decode of session_delta_info_populated into SessionDeltaInfo: %v "+
			"(a Rust rename with no Go counterpart, or a width the Go field cannot hold)", err)
	}

	// Every field, its own sentinel. The numeric sentinels are unique
	// across the struct so ANY transposition — not just the ingress /
	// NAT-scope pair the issue measured — is caught and named.
	checks := []struct {
		field string
		got   any
		want  any
	}{
		{"Slot", delta.Slot, uint32(17142001)},
		{"QueueID", delta.QueueID, uint32(17142002)},
		{"WorkerID", delta.WorkerID, uint32(17142003)},
		{"Interface", delta.Interface, "ge-0/0/0.17142"},
		{"Ifindex", delta.Ifindex, 17142004},
		{"Event", delta.Event, "open-17142"},
		{"AddrFamily", delta.AddrFamily, uint8(42)},
		{"Protocol", delta.Protocol, uint8(43)},
		{"SrcIP", delta.SrcIP, "10.171.42.1"},
		{"DstIP", delta.DstIP, "10.171.42.2"},
		{"SrcPort", delta.SrcPort, uint16(4201)},
		{"DstPort", delta.DstPort, uint16(4202)},
		{"IngressZone", delta.IngressZone, "ingress-zone-17142"},
		{"EgressZone", delta.EgressZone, "egress-zone-17142"},
		{"IngressZoneID", delta.IngressZoneID, uint32(17142005)},
		{"EgressZoneID", delta.EgressZoneID, uint32(17142006)},
		// The measured mutant-C pair: distinct, so a swap reds by name.
		{"IngressIfindex", delta.IngressIfindex, 17142007},
		{"IngressVLANID", delta.IngressVLANID, uint16(4203)},
		{"NatScopeIfindex", delta.NatScopeIfindex, int32(17142008)},
		{"OwnerRGID", delta.OwnerRGID, 17142009},
		{"Disposition", delta.Disposition, "disposition-17142"},
		{"Origin", delta.Origin, "origin-17142"},
		{"EgressIfindex", delta.EgressIfindex, 17142010},
		{"TXIfindex", delta.TXIfindex, 17142011},
		{"TunnelEndpointID", delta.TunnelEndpointID, uint16(4204)},
		{"TXVLANID", delta.TXVLANID, uint16(4205)},
		{"NextHop", delta.NextHop, "10.171.42.3"},
		{"NeighborMAC", delta.NeighborMAC, "02:17:14:20:00:01"},
		{"SrcMAC", delta.SrcMAC, "02:17:14:20:00:02"},
		{"NATSrcIP", delta.NATSrcIP, "10.171.42.4"},
		{"NATDstIP", delta.NATDstIP, "10.171.42.5"},
		{"NATSrcPort", delta.NATSrcPort, uint16(4206)},
		{"NATDstPort", delta.NATDstPort, uint16(4207)},
		{"SourceNatProvenance", delta.SourceNatProvenance, uint8(44)},
		{"FabricRedirect", delta.FabricRedirect, true},
		{"FabricIngress", delta.FabricIngress, true},
		{"LogSessionInit", delta.LogSessionInit, true},
		{"LogSessionClose", delta.LogSessionClose, true},
		{"RTFlowSessionID", delta.RTFlowSessionID, uint64(17142012)},
		{"RoutingDomain", delta.RoutingDomain, uint32(17142013)},
		{"PolicyID", delta.PolicyID, uint32(17142014)},
		{"PolicyCounterIdx", delta.PolicyCounterIdx, uint32(17142015)},
		{"PolicyRuleID", delta.PolicyRuleID, "policy-rule-17142"},
		{"AppTimeout", delta.AppTimeout, uint32(17142016)},
		{"AppTimeoutLogStated", delta.AppTimeoutLogStated, true},
		{"Nat64", delta.Nat64, true},
		{"Nat64SnatV4", delta.Nat64SnatV4, "10.171.42.6"},
		{"SourceNatICMPValid", delta.SourceNatICMPValid, true},
		{"SourceNatICMPType", delta.SourceNatICMPType, uint8(45)},
		{"SourceNatICMPCode", delta.SourceNatICMPCode, uint8(46)},
		{"TunnelDiscriminator", delta.TunnelDiscriminator, uint64(17142017)},
		{"PptpCallIDs", delta.PptpCallIDs, uint64(17142018)},
		{"TCPCloseClass", delta.TCPCloseClass, uint8(47)},
		{"TCPHandshakeState", delta.TCPHandshakeState, uint8(48)},
		{"InstallTableDomain", delta.InstallTableDomain, uint32(17142019)},
		{"InstallTableCheck", delta.InstallTableCheck, uint32(17142020)},
		{"PurgeRetirement", delta.PurgeRetirement, true},
		{"FwdPackets", delta.FwdPackets, uint64(17142021)},
		{"RevPackets", delta.RevPackets, uint64(17142022)},
		{"StreamSeq", delta.StreamSeq, uint64(17142023)},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.got, c.want) {
			t.Errorf("SessionDeltaInfo.%s = %v, want %v — the populated fixture specimen's "+
				"sentinel did not land on this field. A rename swap or one-sided rename "+
				"transposed/dropped it (#17142 mutant C class)", c.field, c.got, c.want)
		}
	}
	if want := time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC); !delta.Timestamp.Equal(want) {
		t.Errorf("SessionDeltaInfo.Timestamp = %v, want %v (the specimen's sentinel instant)", delta.Timestamp, want)
	}

	// The binary-leg-only fields must stay OFF this JSON specimen: they
	// are json:"-" and a populated JSON decode must not invent them.
	if delta.BinAddrLen != 0 || delta.SrcAddr != [16]byte{} || delta.SrcMACBin != [6]byte{} {
		t.Errorf("binary-leg-only fields populated by JSON decode: %+v — the legs must not mix (#9905)", delta)
	}
}
