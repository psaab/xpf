package userspace

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/psaab/xpf/pkg/dataplane"
)

func TestSessionSyncEgressLockedDerivesOwnerAndTxPath(t *testing.T) {
	m := &Manager{
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{
				{
					Name:            "reth0.80",
					Ifindex:         12,
					ParentIfindex:   6,
					VLANID:          80,
					RedundancyGroup: 1,
				},
			},
		},
	}
	egress, tx, owner := m.sessionSyncEgressLocked(6, 80, "")
	if egress != 12 {
		t.Fatalf("egress = %d, want 12", egress)
	}
	if tx != 6 {
		t.Fatalf("tx = %d, want 6", tx)
	}
	if owner != 1 {
		t.Fatalf("owner = %d, want 1", owner)
	}
}

func TestSessionSyncEgressLockedResolvesOwnerRGFromZone(t *testing.T) {
	m := &Manager{
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{
				{
					Name:            "reth0",
					Zone:            "trust",
					Ifindex:         10,
					RedundancyGroup: 1,
				},
				{
					Name:            "ge-0-0-1",
					Zone:            "untrust",
					Ifindex:         20,
					RedundancyGroup: 0,
				},
			},
		},
	}
	// FibIfindex=0: should resolve owner_rg_id from zone.
	egress, tx, owner := m.sessionSyncEgressLocked(0, 0, "trust")
	if egress != 0 {
		t.Fatalf("egress = %d, want 0", egress)
	}
	if tx != 0 {
		t.Fatalf("tx = %d, want 0", tx)
	}
	if owner != 1 {
		t.Fatalf("owner = %d, want 1 (from trust zone)", owner)
	}
	// Zone with no RG: should return 0.
	_, _, owner = m.sessionSyncEgressLocked(0, 0, "untrust")
	if owner != 0 {
		t.Fatalf("owner = %d, want 0 (untrust has no RG)", owner)
	}
	// Empty zone: should return 0.
	_, _, owner = m.sessionSyncEgressLocked(0, 0, "")
	if owner != 0 {
		t.Fatalf("owner = %d, want 0 (empty zone)", owner)
	}
}

func TestSessionSyncTunnelEndpointIDLockedMatchesLogicalTunnelIfindex(t *testing.T) {
	m := &Manager{
		lastSnapshot: &ConfigSnapshot{
			TunnelEndpoints: []TunnelEndpointSnapshot{{
				ID:      3,
				Ifindex: 586,
			}},
		},
	}
	if got := m.sessionSyncTunnelEndpointIDLocked(586); got != 3 {
		t.Fatalf("tunnel endpoint id = %d, want 3", got)
	}
	if got := m.sessionSyncTunnelEndpointIDLocked(24); got != 0 {
		t.Fatalf("tunnel endpoint id for non-tunnel ifindex = %d, want 0", got)
	}
}

func TestBuildSessionSyncRequestV4ConvertsPortsToHostOrder(t *testing.T) {
	m := &Manager{
		bpfShim: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{{
				Name:            "reth0.80",
				Ifindex:         12,
				ParentIfindex:   6,
				VLANID:          80,
				RedundancyGroup: 1,
			}},
		},
	}
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(50952),
		DstPort:  hostToNetwork16(5201),
		Protocol: 6,
	}
	val := &dataplane.SessionValue{
		IngressZone: 1,
		EgressZone:  2,
		Flags:       dataplane.SessFlagSNAT,
		LogFlags:    dataplane.LogFlagUserspaceFabricIngress,
		FibIfindex:  6,
		FibVlanID:   80,
		NATSrcIP:    binary.NativeEndian.Uint32([]byte{172, 16, 80, 8}),
		NATSrcPort:  hostToNetwork16(40000),
	}
	req := m.buildSessionSyncRequestV4("upsert", key, val)
	if req.SrcPort != 50952 || req.DstPort != 5201 {
		t.Fatalf("unexpected host-order request ports: %+v", req)
	}
	if req.NATSrcPort != 40000 {
		t.Fatalf("unexpected nat src port: %d", req.NATSrcPort)
	}
	if !req.FabricIngress {
		t.Fatalf("expected fabric_ingress to be preserved: %+v", req)
	}
}

// #2785: the per-policy `then log` selection must ride the session-sync
// request so a session synced to the peer logs identically after failover.
// Reverting the manager_ha.go mapping drops the flags and this fails RED.
func TestBuildSessionSyncRequestCarriesLogFlags(t *testing.T) {
	m := &Manager{bpfShim: dataplane.New()}
	keyV4 := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(50952),
		DstPort:  hostToNetwork16(5201),
		Protocol: 6,
	}
	valV4 := &dataplane.SessionValue{
		IngressZone: 1,
		EgressZone:  2,
		LogFlags:    dataplane.LogFlagSessionInit | dataplane.LogFlagSessionClose,
	}
	reqV4 := m.buildSessionSyncRequestV4("upsert", keyV4, valV4)
	if !reqV4.LogSessionInit || !reqV4.LogSessionClose {
		t.Fatalf("v4: expected log flags carried, got init=%t close=%t",
			reqV4.LogSessionInit, reqV4.LogSessionClose)
	}

	// Only session-close set: init must NOT leak true.
	valCloseOnly := &dataplane.SessionValue{
		IngressZone: 1, EgressZone: 2,
		LogFlags: dataplane.LogFlagSessionClose,
	}
	reqCloseOnly := m.buildSessionSyncRequestV4("upsert", keyV4, valCloseOnly)
	if reqCloseOnly.LogSessionInit || !reqCloseOnly.LogSessionClose {
		t.Fatalf("v4 close-only: init=%t close=%t, want false/true",
			reqCloseOnly.LogSessionInit, reqCloseOnly.LogSessionClose)
	}

	// Neither set: both false.
	reqNone := m.buildSessionSyncRequestV4("upsert", keyV4,
		&dataplane.SessionValue{IngressZone: 1, EgressZone: 2})
	if reqNone.LogSessionInit || reqNone.LogSessionClose {
		t.Fatalf("v4 none: expected both false, got init=%t close=%t",
			reqNone.LogSessionInit, reqNone.LogSessionClose)
	}

	keyV6 := dataplane.SessionKeyV6{Protocol: 6}
	valV6 := &dataplane.SessionValueV6{
		IngressZone: 1, EgressZone: 2,
		LogFlags: dataplane.LogFlagSessionInit | dataplane.LogFlagSessionClose,
	}
	reqV6 := m.buildSessionSyncRequestV6("upsert", keyV6, valV6)
	if !reqV6.LogSessionInit || !reqV6.LogSessionClose {
		t.Fatalf("v6: expected log flags carried, got init=%t close=%t",
			reqV6.LogSessionInit, reqV6.LogSessionClose)
	}
}

// Stable policy rule identity travels with policy attribution so the receiver
// can bind a counter against its current rule ordering.
func TestBuildSessionSyncRequestCarriesPolicyFields3301(t *testing.T) {
	m := &Manager{bpfShim: dataplane.New()}
	keyV4 := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{172, 16, 80, 200},
		SrcPort: hostToNetwork16(40000), DstPort: hostToNetwork16(5201), Protocol: 6,
	}
	valV4 := &dataplane.SessionValue{
		IngressZone: 1, EgressZone: 2,
		PolicyID: 42, PolicyCounterIdx: 7, PolicyRuleID: "lan->wan/allow-web", AppTimeout: 30,
	}
	reqV4 := m.buildSessionSyncRequestV4("upsert", keyV4, valV4)
	if reqV4.PolicyID != 42 || reqV4.PolicyCounterIdx != 7 || reqV4.PolicyRuleID != "lan->wan/allow-web" || reqV4.InactivityTimeout != 30 {
		t.Fatalf("v4: policy=%d counter=%d rule=%q inact=%d", reqV4.PolicyID, reqV4.PolicyCounterIdx, reqV4.PolicyRuleID, reqV4.InactivityTimeout)
	}

	// JSON wire keys must match the Rust SessionSyncRequest serde(rename).
	js, err := json.Marshal(reqV4)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{`"policy_id":42`, `"policy_counter_idx":7`, `"inactivity_timeout":30`} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("wire JSON missing %s: %s", want, js)
		}
	}
	var wireFields map[string]json.RawMessage
	if err := json.Unmarshal(js, &wireFields); err != nil {
		t.Fatalf("unmarshal request JSON: %v", err)
	}
	var gotRuleID string
	if err := json.Unmarshal(wireFields["policy_rule_id"], &gotRuleID); err != nil {
		t.Fatalf("decode policy_rule_id: %v", err)
	}
	if gotRuleID != "lan->wan/allow-web" {
		t.Fatalf("wire policy_rule_id = %q, want %q", gotRuleID, "lan->wan/allow-web")
	}

	keyV6 := dataplane.SessionKeyV6{Protocol: 6}
	valV6 := &dataplane.SessionValueV6{
		IngressZone: 1, EgressZone: 2,
		PolicyID: 99, PolicyCounterIdx: 11, PolicyRuleID: "lan->wan/allow-web", AppTimeout: 45,
	}
	reqV6 := m.buildSessionSyncRequestV6("upsert", keyV6, valV6)
	if reqV6.PolicyID != 99 || reqV6.PolicyCounterIdx != 11 || reqV6.PolicyRuleID != "lan->wan/allow-web" || reqV6.InactivityTimeout != 45 {
		t.Fatalf("v6: policy=%d counter=%d rule=%q inact=%d", reqV6.PolicyID, reqV6.PolicyCounterIdx, reqV6.PolicyRuleID, reqV6.InactivityTimeout)
	}
}

// #4565: buildSessionSyncRequestV6 must copy the NAT64 translated pool source
// (SessionValueV6.Nat64SnatV4) onto the wire as a dotted-quad so the peer helper
// rebuilds the reverse (v4->v6) BIB after promotion. The JSON key must match the
// Rust SessionSyncRequest serde(rename = "nat64_snat_v4"). RED-on-revert:
// dropping the manager_ha.go population leaves req.Nat64SnatV4 empty.
func TestBuildSessionSyncRequestV6CarriesNat64SnatV4_4565(t *testing.T) {
	m := &Manager{bpfShim: dataplane.New()}
	keyV6 := dataplane.SessionKeyV6{Protocol: 6}
	valV6 := &dataplane.SessionValueV6{
		IngressZone: 1, EgressZone: 2,
		Nat64SnatV4: [4]byte{203, 0, 113, 5},
	}
	reqV6 := m.buildSessionSyncRequestV6("upsert", keyV6, valV6)
	if reqV6.Nat64SnatV4 != "203.0.113.5" {
		t.Fatalf("v6 Nat64SnatV4 = %q, want 203.0.113.5", reqV6.Nat64SnatV4)
	}
	js, err := json.Marshal(reqV6)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(js), `"nat64_snat_v4":"203.0.113.5"`) {
		t.Fatalf("wire JSON missing nat64_snat_v4: %s", js)
	}

	// A non-NAT64 session leaves the field zero -> omitted from the wire.
	valPlain := &dataplane.SessionValueV6{IngressZone: 1, EgressZone: 2}
	reqPlain := m.buildSessionSyncRequestV6("upsert", keyV6, valPlain)
	if reqPlain.Nat64SnatV4 != "" {
		t.Fatalf("non-nat64 Nat64SnatV4 = %q, want empty", reqPlain.Nat64SnatV4)
	}
	jsPlain, _ := json.Marshal(reqPlain)
	if strings.Contains(string(jsPlain), "nat64_snat_v4") {
		t.Fatalf("non-nat64 wire JSON must omit nat64_snat_v4: %s", jsPlain)
	}
}

// TestBuildSessionSyncRequestCarriesRTFlowSessionID5212 verifies the manager
// forwards the originating node's stable RT_FLOW session id (SessionValue{,V6}.
// RTFlowSessionID) onto the SessionSyncRequest (JSON session_id) for both
// families so the peer helper adopts it on import. Reverting the copy leaves the
// field 0 (omitted) and this fails RED.
func TestBuildSessionSyncRequestCarriesRTFlowSessionID5212(t *testing.T) {
	m := &Manager{bpfShim: dataplane.New()}
	wantID := uint64(7)<<48 | 0x1234_5678

	key := dataplane.SessionKey{Protocol: 6}
	val := &dataplane.SessionValue{IngressZone: 1, EgressZone: 2, RTFlowSessionID: wantID}
	req := m.buildSessionSyncRequestV4("upsert", key, val)
	if req.RTFlowSessionID != wantID {
		t.Fatalf("v4 req.RTFlowSessionID = %#x, want %#x", req.RTFlowSessionID, wantID)
	}
	if js, _ := json.Marshal(req); !strings.Contains(string(js), `"session_id":`) {
		t.Fatalf("v4 wire JSON missing session_id: %s", js)
	}

	keyV6 := dataplane.SessionKeyV6{Protocol: 6}
	valV6 := &dataplane.SessionValueV6{IngressZone: 1, EgressZone: 2, RTFlowSessionID: wantID}
	reqV6 := m.buildSessionSyncRequestV6("upsert", keyV6, valV6)
	if reqV6.RTFlowSessionID != wantID {
		t.Fatalf("v6 req.RTFlowSessionID = %#x, want %#x", reqV6.RTFlowSessionID, wantID)
	}

	// A session with no id (0) omits the key from the wire (rolling-upgrade safe).
	reqPlain := m.buildSessionSyncRequestV4("upsert", key, &dataplane.SessionValue{IngressZone: 1, EgressZone: 2})
	if reqPlain.RTFlowSessionID != 0 {
		t.Fatalf("plain req.RTFlowSessionID = %#x, want 0", reqPlain.RTFlowSessionID)
	}
	if js, _ := json.Marshal(reqPlain); strings.Contains(string(js), "session_id") {
		t.Fatalf("zero-id wire JSON must omit session_id: %s", js)
	}
}

func TestBuildSessionSyncRequestV4PreservesBothNatLegs(t *testing.T) {
	m := &Manager{bpfShim: dataplane.New()}
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{198, 51, 100, 10},
		DstIP:    [4]byte{172, 16, 80, 8},
		SrcPort:  hostToNetwork16(54321),
		DstPort:  hostToNetwork16(443),
		Protocol: 6,
	}
	val := &dataplane.SessionValue{
		Flags:      dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
		NATSrcIP:   binary.NativeEndian.Uint32([]byte{10, 0, 61, 1}),
		NATDstIP:   binary.NativeEndian.Uint32([]byte{10, 0, 61, 102}),
		NATSrcPort: hostToNetwork16(54321),
		NATDstPort: hostToNetwork16(8443),
	}
	req := m.buildSessionSyncRequestV4("upsert", key, val)
	if req.NATSrcIP != "10.0.61.1" || req.NATDstIP != "10.0.61.102" {
		t.Fatalf("unexpected nat ips: %+v", req)
	}
	if req.NATSrcPort != 54321 || req.NATDstPort != 8443 {
		t.Fatalf("unexpected nat ports: %+v", req)
	}
}

func TestBuildSessionSyncRequestV4PreservesTunnelEndpointIdentity(t *testing.T) {
	m := &Manager{
		bpfShim: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{{
				Name:            "gr-0/0/0.0",
				Ifindex:         586,
				RedundancyGroup: 1,
			}},
			TunnelEndpoints: []TunnelEndpointSnapshot{{
				ID:              3,
				Ifindex:         586,
				RedundancyGroup: 1,
			}},
		},
	}
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{10, 255, 192, 41},
		SrcPort:  hostToNetwork16(4459),
		DstPort:  hostToNetwork16(4459),
		Protocol: 1,
	}
	val := &dataplane.SessionValue{
		IngressZone: 1,
		EgressZone:  2,
		LogFlags:    dataplane.LogFlagUserspaceTunnelEndpoint,
		FibIfindex:  894,
		FibGen:      3,
		FibVlanID:   80,
		FibDmac:     [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		FibSmac:     [6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08},
	}
	req := m.buildSessionSyncRequestV4("upsert", key, val)
	if req.TunnelEndpointID != 3 {
		t.Fatalf("unexpected tunnel endpoint id: %d", req.TunnelEndpointID)
	}
	if req.EgressIfindex != 586 {
		t.Fatalf("unexpected egress ifindex: %d", req.EgressIfindex)
	}
	if req.TXIfindex != 0 {
		t.Fatalf("unexpected tx ifindex: %d", req.TXIfindex)
	}
	if req.OwnerRGID != 1 {
		t.Fatalf("unexpected owner rg: %d", req.OwnerRGID)
	}
	if req.TXVLANID != 0 {
		t.Fatalf("unexpected tx vlan id: %d", req.TXVLANID)
	}
	if req.NeighborMAC != "" || req.SrcMAC != "" {
		t.Fatalf("unexpected tunnel L2 metadata: %+v", req)
	}
}

func TestBuildSessionSyncRequestV6PreservesTunnelEndpointIdentity(t *testing.T) {
	m := &Manager{
		bpfShim: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{{
				Name:            "gr-0/0/0.0",
				Ifindex:         586,
				RedundancyGroup: 1,
			}},
			TunnelEndpoints: []TunnelEndpointSnapshot{{
				ID:              7,
				Ifindex:         586,
				RedundancyGroup: 1,
			}},
		},
	}
	var srcIP, dstIP [16]byte
	copy(srcIP[:], net.ParseIP("2001:559:8585:ef00::100").To16())
	copy(dstIP[:], net.ParseIP("2001:db8::1").To16())
	val := &dataplane.SessionValueV6{
		IngressZone: 1,
		EgressZone:  2,
		LogFlags:    dataplane.LogFlagUserspaceTunnelEndpoint,
		FibIfindex:  1133,
		FibGen:      7,
		FibVlanID:   80,
	}
	req := m.buildSessionSyncRequestV6("upsert", dataplane.SessionKeyV6{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  hostToNetwork16(5555),
		DstPort:  hostToNetwork16(53),
		Protocol: 17,
	}, val)
	if req.TunnelEndpointID != 7 {
		t.Fatalf("unexpected tunnel endpoint id: %d", req.TunnelEndpointID)
	}
	if req.EgressIfindex != 586 {
		t.Fatalf("unexpected egress ifindex: %d", req.EgressIfindex)
	}
	if req.OwnerRGID != 1 {
		t.Fatalf("unexpected owner rg: %d", req.OwnerRGID)
	}
	if req.TXIfindex != 0 || req.TXVLANID != 0 {
		t.Fatalf("unexpected tx path for tunnel sync: %+v", req)
	}
}

func TestBuildSessionSyncRequestV6ConvertsPortsToHostOrder(t *testing.T) {
	m := &Manager{
		bpfShim: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{{
				Name:            "reth0.80",
				Ifindex:         12,
				ParentIfindex:   6,
				VLANID:          80,
				RedundancyGroup: 1,
			}},
		},
	}
	var srcIP, dstIP [16]byte
	copy(srcIP[:], net.ParseIP("2001:559:8585:ef00::100").To16())
	copy(dstIP[:], net.ParseIP("2001:559:8585:80::200").To16())
	var natSrc [16]byte
	copy(natSrc[:], net.ParseIP("2001:559:8585:80::8").To16())
	key := dataplane.SessionKeyV6{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  hostToNetwork16(50952),
		DstPort:  hostToNetwork16(5201),
		Protocol: 6,
	}
	val := &dataplane.SessionValueV6{
		IngressZone: 1,
		EgressZone:  2,
		Flags:       dataplane.SessFlagSNAT,
		LogFlags:    dataplane.LogFlagUserspaceFabricIngress,
		FibIfindex:  6,
		FibVlanID:   80,
		NATSrcIP:    natSrc,
		NATSrcPort:  hostToNetwork16(40000),
	}
	req := m.buildSessionSyncRequestV6("upsert", key, val)
	if req.SrcPort != 50952 || req.DstPort != 5201 {
		t.Fatalf("unexpected host-order request ports: %+v", req)
	}
	if req.NATSrcPort != 40000 {
		t.Fatalf("unexpected nat src port: %d", req.NATSrcPort)
	}
	if !req.FabricIngress {
		t.Fatalf("expected fabric_ingress to be preserved: %+v", req)
	}
}

func TestBuildSessionSyncRequestV6PreservesBothNatLegs(t *testing.T) {
	m := &Manager{bpfShim: dataplane.New()}
	var srcIP, dstIP, natSrc, natDst [16]byte
	copy(srcIP[:], net.ParseIP("2001:db8::10").To16())
	copy(dstIP[:], net.ParseIP("2001:db8:80::8").To16())
	copy(natSrc[:], net.ParseIP("2001:db8:61::1").To16())
	copy(natDst[:], net.ParseIP("2001:db8:61::102").To16())
	key := dataplane.SessionKeyV6{
		SrcIP:    srcIP,
		DstIP:    dstIP,
		SrcPort:  hostToNetwork16(54321),
		DstPort:  hostToNetwork16(443),
		Protocol: 6,
	}
	val := &dataplane.SessionValueV6{
		Flags:      dataplane.SessFlagSNAT | dataplane.SessFlagDNAT,
		NATSrcIP:   natSrc,
		NATDstIP:   natDst,
		NATSrcPort: hostToNetwork16(54321),
		NATDstPort: hostToNetwork16(8443),
	}
	req := m.buildSessionSyncRequestV6("upsert", key, val)
	if req.NATSrcIP != "2001:db8:61::1" || req.NATDstIP != "2001:db8:61::102" {
		t.Fatalf("unexpected nat ips: %+v", req)
	}
	if req.NATSrcPort != 54321 || req.NATDstPort != 8443 {
		t.Fatalf("unexpected nat ports: %+v", req)
	}
}

func TestShouldMirrorUserspaceSessionSkipsReverseEntries(t *testing.T) {
	if !shouldMirrorUserspaceSession(0) {
		t.Fatal("expected forward sessions to be mirrored")
	}
	if shouldMirrorUserspaceSession(1) {
		t.Fatal("expected reverse sessions to be skipped")
	}
}

// TestBuildSessionSyncRequestForwardsGeneration verifies the #2170 install
// generation is mirrored from SessionValue.Generation into the Go→Rust
// SessionSyncRequest for both address families.
func TestBuildSessionSyncRequestForwardsGeneration(t *testing.T) {
	m := &Manager{bpfShim: dataplane.New()}
	keyV4 := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(80), Protocol: 6}
	valV4 := &dataplane.SessionValue{IngressZone: 1, EgressZone: 2, Generation: 0xABCDEF}
	if req := m.buildSessionSyncRequestV4("upsert", keyV4, valV4); req.Generation != 0xABCDEF {
		t.Fatalf("v4 request Generation = %#x, want %#x", req.Generation, uint64(0xABCDEF))
	}

	var srcIP, dstIP [16]byte
	copy(srcIP[:], net.ParseIP("2001:db8::1").To16())
	copy(dstIP[:], net.ParseIP("2001:db8::2").To16())
	keyV6 := dataplane.SessionKeyV6{SrcIP: srcIP, DstIP: dstIP, SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(80), Protocol: 6}
	valV6 := &dataplane.SessionValueV6{IngressZone: 1, EgressZone: 2, Generation: 0x123456}
	if req := m.buildSessionSyncRequestV6("upsert", keyV6, valV6); req.Generation != 0x123456 {
		t.Fatalf("v6 request Generation = %#x, want %#x", req.Generation, uint64(0x123456))
	}
}

// TestSessionSyncRequestGenerationJSONWireType is the #1961-class wire-type
// guard: the Generation field MUST serialize as an explicit numeric value
// (NO omitempty), so a 0 round-trips as 0 rather than being dropped. An old
// helper without the field decodes via serde(default); a new helper sees an
// explicit number.
func TestSessionSyncRequestGenerationJSONWireType(t *testing.T) {
	// Non-zero must serialize and decode losslessly.
	req := SessionSyncRequest{Operation: "upsert", Generation: 0x1122334455667788}
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), "\"generation\":1234605616436508552") {
		t.Fatalf("generation not serialized as a number: %s", b)
	}
	var back SessionSyncRequest
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Generation != req.Generation {
		t.Fatalf("Generation round-trip mismatch: got %#x", back.Generation)
	}

	// Zero MUST serialize as an explicit 0 (no omitempty drop) so the wire is
	// unambiguous to a new decoder.
	zero := SessionSyncRequest{Operation: "delete"}
	zb, err := json.Marshal(zero)
	if err != nil {
		t.Fatalf("marshal zero: %v", err)
	}
	if !strings.Contains(string(zb), "\"generation\":0") {
		t.Fatalf("zero generation must serialize explicitly as 0, got: %s", zb)
	}

	// A legacy payload with NO generation key decodes to 0.
	var legacy SessionSyncRequest
	if err := json.Unmarshal([]byte(`{"operation":"upsert","src_ip":"10.0.0.1"}`), &legacy); err != nil {
		t.Fatalf("unmarshal legacy: %v", err)
	}
	if legacy.Generation != 0 {
		t.Fatalf("legacy payload Generation = %d, want 0", legacy.Generation)
	}
}

func TestSetClusterSyncedSessionV4SkipsReverseHelperMirror(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	controlSock := filepath.Join(dir, "control.sock")
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	ln, err := net.Listen("unix", sessionSock)
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	defer ln.Close()

	unexpectedConn := make(chan string, 4)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			select {
			case unexpectedConn <- "unexpected helper session socket connection for reverse cluster session":
			default:
			}
			go func() {
				defer conn.Close()
				var req ControlRequest
				if err := json.NewDecoder(conn).Decode(&req); err == nil {
					select {
					case unexpectedConn <- fmt.Sprintf("unexpected helper mirror request for reverse cluster session: %+v", req):
					default:
					}
				}
				_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true})
			}()
		}
	}()

	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = controlSock
	sessionsMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:    ebpf.Hash,
		KeySize: uint32(unsafe.Sizeof(dataplane.SessionKey{})),
		// On-map conntrack ABI size (excludes sync-only Generation) — must
		// match the production registration, else the Manager's lookup copies
		// the registered value_size into the smaller bpfSessionValue buffer
		// (the #2360 OOB). Derive from the shared SSOT constant.
		ValueSize:  dataplane.ConntrackSessionValueSize,
		MaxEntries: 1024,
	})
	if err != nil {
		t.Fatalf("new sessions map: %v", err)
	}
	defer sessionsMap.Close()
	injectShimMap(t, m.bpfShim, "sessions", sessionsMap)
	sessionsMapV6, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.Hash,
		KeySize:    uint32(unsafe.Sizeof(dataplane.SessionKeyV6{})),
		ValueSize:  dataplane.ConntrackSessionValueSizeV6,
		MaxEntries: 1024,
	})
	if err != nil {
		t.Fatalf("new sessions_v6 map: %v", err)
	}
	defer sessionsMapV6.Close()
	injectShimMap(t, m.bpfShim, "sessions_v6", sessionsMapV6)

	key := dataplane.SessionKey{
		SrcIP:    [4]byte{172, 16, 80, 200},
		DstIP:    [4]byte{172, 16, 80, 8},
		SrcPort:  hostToNetwork16(5201),
		DstPort:  hostToNetwork16(55340),
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		IsReverse:   1,
		IngressZone: 2,
		EgressZone:  1,
		Flags:       dataplane.SessFlagSNAT,
		FibIfindex:  6,
		FibVlanID:   80,
		NATSrcIP:    binary.NativeEndian.Uint32([]byte{172, 16, 80, 8}),
		NATSrcPort:  hostToNetwork16(55340),
	}

	if err := m.SetClusterSyncedSessionV4(key, val); err != nil {
		t.Fatalf("SetClusterSyncedSessionV4: %v", err)
	}

	select {
	case msg := <-unexpectedConn:
		t.Fatal(msg)
	case <-time.After(200 * time.Millisecond):
	}

	var srcIPv6, dstIPv6, natSrcIPv6 [16]byte
	copy(srcIPv6[:], net.ParseIP("2001:db8:1::200").To16())
	copy(dstIPv6[:], net.ParseIP("2001:db8:2::8").To16())
	copy(natSrcIPv6[:], net.ParseIP("2001:db8:2::8").To16())
	keyV6 := dataplane.SessionKeyV6{
		SrcIP:    srcIPv6,
		DstIP:    dstIPv6,
		SrcPort:  hostToNetwork16(5201),
		DstPort:  hostToNetwork16(55340),
		Protocol: 6,
	}
	valV6 := dataplane.SessionValueV6{
		IsReverse:   1,
		IngressZone: 2,
		EgressZone:  1,
		Flags:       dataplane.SessFlagSNAT,
		FibIfindex:  6,
		FibVlanID:   80,
		NATSrcIP:    natSrcIPv6,
		NATSrcPort:  hostToNetwork16(55340),
	}

	if err := m.SetClusterSyncedSessionV6(keyV6, valV6); err != nil {
		t.Fatalf("SetClusterSyncedSessionV6: %v", err)
	}

	select {
	case msg := <-unexpectedConn:
		t.Fatal(msg)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestSetClusterSyncedSessionV4MirrorFailureMarksHelperUnhealthy(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	injectSessionMaps(t, m)

	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(5201),
		DstPort:  hostToNetwork16(55340),
		Protocol: 6,
	}
	val := dataplane.SessionValue{
		IsReverse: 0,
	}

	err := m.SetClusterSyncedSessionV4(key, val)
	if err == nil {
		t.Fatal("SetClusterSyncedSessionV4() = nil, want mirror failure")
	}
	if !m.sessionMirrorFailed {
		t.Fatal("sessionMirrorFailed = false, want true")
	}
	if m.sessionMirrorErr == "" {
		t.Fatal("sessionMirrorErr is empty")
	}
}

func TestSetClusterSyncedSessionV6MirrorFailureMarksHelperUnhealthy(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	m := New()
	m.proc = &exec.Cmd{}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	injectSessionMaps(t, m)

	var srcIPv6, dstIPv6 [16]byte
	copy(srcIPv6[:], net.ParseIP("2001:db8:61::102").To16())
	copy(dstIPv6[:], net.ParseIP("2001:db8:80::200").To16())
	key := dataplane.SessionKeyV6{
		SrcIP:    srcIPv6,
		DstIP:    dstIPv6,
		SrcPort:  hostToNetwork16(5201),
		DstPort:  hostToNetwork16(55340),
		Protocol: 6,
	}
	val := dataplane.SessionValueV6{
		IsReverse: 0,
	}

	err := m.SetClusterSyncedSessionV6(key, val)
	if err == nil {
		t.Fatal("SetClusterSyncedSessionV6() = nil, want mirror failure")
	}
	if !m.sessionMirrorFailed {
		t.Fatal("sessionMirrorFailed = false, want true")
	}
	if m.sessionMirrorErr == "" {
		t.Fatal("sessionMirrorErr is empty")
	}
}

// TestSetClusterSyncedSessionV4MirrorSuccessClearsStickyFailure asserts the
// #5247 self-heal: a transient session-mirror failure latches
// sessionMirrorFailed (and blocks HA takeover-readiness), but a subsequent
// SUCCESSFUL mirror through a healthy helper socket clears it without a helper
// process restart. If the clear-on-success is reverted, the flag stays set,
// takeoverReadyLocked never becomes ready, and this test fails.
func TestSetClusterSyncedSessionV4MirrorSuccessClearsStickyFailure(t *testing.T) {
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Skipf("RemoveMemlock: %v", err)
	}
	dir := t.TempDir()
	sessionSock := filepath.Join(dir, "userspace-dp-sessions.sock")
	ln, err := net.Listen("unix", sessionSock)
	if err != nil {
		t.Fatalf("listen session socket: %v", err)
	}
	defer ln.Close()
	// A healthy session helper that acknowledges every mirror request.
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var req ControlRequest
				_ = json.NewDecoder(conn).Decode(&req)
				_ = json.NewEncoder(conn).Encode(ControlResponse{OK: true})
			}()
		}
	}()

	m := New()
	m.proc = &exec.Cmd{Process: &os.Process{Pid: 1}}
	m.cfg.ControlSocket = filepath.Join(dir, "control.sock")
	injectSessionMaps(t, m)

	// Every takeover-readiness gate other than the session-mirror flag is
	// satisfied, so the sticky flag is the sole thing keeping the standby
	// not-ready.
	m.lastStatus = ProcessStatus{
		Enabled:         true,
		ForwardingArmed: true,
		Capabilities:    UserspaceCapabilities{ForwardingSupported: true},
	}
	m.mode = ModeUserspaceCompat
	m.xskLivenessProven = true
	// #5273: takeover-readiness now also gates on a bound event-stream listener.
	m.eventStream = boundEventStream(t)

	// A prior transient control-socket failure latched the sticky flag.
	m.recordSessionMirrorFailureLocked(errors.New("transient control-socket failure"))
	if ready, reasons := m.TakeoverReady(); ready {
		t.Fatalf("TakeoverReady() = true while mirror failed, want false; reasons=%v", reasons)
	}

	// Drive a genuinely successful forward-session mirror through the live
	// helper socket — no helper restart.
	key := dataplane.SessionKey{
		SrcIP:    [4]byte{10, 0, 61, 102},
		DstIP:    [4]byte{172, 16, 80, 200},
		SrcPort:  hostToNetwork16(5201),
		DstPort:  hostToNetwork16(55340),
		Protocol: 6,
	}
	val := dataplane.SessionValue{IsReverse: 0}
	if err := m.SetClusterSyncedSessionV4(key, val); err != nil {
		t.Fatalf("SetClusterSyncedSessionV4: %v", err)
	}

	if m.sessionMirrorFailed {
		t.Fatal("sessionMirrorFailed = true after successful mirror, want false (#5247)")
	}
	if m.sessionMirrorErr != "" {
		t.Fatalf("sessionMirrorErr = %q after successful mirror, want empty", m.sessionMirrorErr)
	}
	if ready, reasons := m.TakeoverReady(); !ready {
		t.Fatalf("TakeoverReady() = false after successful mirror, want true; reasons=%v", reasons)
	}
}

func TestSessionSocketPathDerivation(t *testing.T) {
	m := &Manager{}
	m.cfg.ControlSocket = "/run/xpf/userspace-dp.sock"
	got := m.sessionSocketPath()
	want := "/run/xpf/userspace-dp-sessions.sock"
	if got != want {
		t.Fatalf("sessionSocketPath() = %q, want %q", got, want)
	}
}

func TestSessionSocketPathEmpty(t *testing.T) {
	m := &Manager{}
	m.cfg.ControlSocket = ""
	if got := m.sessionSocketPath(); got != "" {
		t.Fatalf("sessionSocketPath() = %q, want empty", got)
	}
}
