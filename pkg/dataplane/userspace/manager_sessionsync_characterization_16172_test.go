package userspace

// #16172 characterization: dual-family byte goldens for
// buildSessionSyncRequest{V4,V6}. These pin the FULL JSON output BEFORE the
// V4/V6 twins are collapsed behind a family-neutral view, and must stay
// byte-identical after the collapse. They are the seam: any hidden family
// difference (NAT64, NAT rendering, fold resolution, tunnel override,
// stale-generation / order variants) reds here before it ships.
//
// Coverage:
//   - representative V4 and V6 upserts with every shared field populated
//   - NAT64-on-V6 (V6-only field) and its zero control
//   - NAT-off (SNAT/DNAT flags clear => NAT fields scrubbed)
//   - missing map / nil snapshot (val == nil delete, and val with no snapshot)
//   - stale generation: the generation value rides verbatim (no clamping)
//   - order variants: RTFlowSessionID vs SessionID fallback, tunnel-endpoint
//     FibGen override vs egress-derived endpoint, peer-egress MAC suppression

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// goldenManager16172 returns a manager whose snapshot exercises egress
// resolution (reth0.80: ifindex 12 via parent 6 vlan 80, RG 1), an egress
// zone fallback interface, and a tunnel endpoint (id 3 at ifindex 586).
// bpfShim is a fresh dataplane.Manager with no compile result, so zone IDs
// resolve to "" — exactly the missing-map case for zone names.
func goldenManager16172() *Manager {
	return &Manager{
		bpfShim: dataplane.New(),
		lastSnapshot: &ConfigSnapshot{
			Interfaces: []InterfaceSnapshot{
				{Name: "reth0.80", Zone: "wan", Ifindex: 12, ParentIfindex: 6, VLANID: 80, RedundancyGroup: 1},
				{Name: "reth0.50", Zone: "lan", Ifindex: 11, ParentIfindex: 5, VLANID: 50, RedundancyGroup: 2},
				// Fold-resolution targets (#15263 presence check): the
				// resolvers in the goldens return these local identities.
				{Name: "reth1.50", Zone: "lan", Ifindex: 99, ParentIfindex: 42, VLANID: 50, RedundancyGroup: 2},
				{Name: "reth2", Zone: "lan", Ifindex: 43, RedundancyGroup: 2},
				{Name: "reth3.80", Zone: "wan", Ifindex: 98, ParentIfindex: 7, VLANID: 80, RedundancyGroup: 1},
			},
			TunnelEndpoints: []TunnelEndpointSnapshot{
				{ID: 3, Ifindex: 586, RedundancyGroup: 1},
			},
		},
	}
}

func mustJSON16172(t *testing.T, req SessionSyncRequest) string {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

func ip16(s string) [16]byte {
	var out [16]byte
	copy(out[:], net.ParseIP(s).To16())
	return out
}

func natU32(s string) uint32 {
	ip := net.ParseIP(s).To4()
	return binary.NativeEndian.Uint32(ip)
}

// TestSessionSyncGoldenV4Representative16172 pins a fully-populated V4
// upsert: NAT both legs, policy/log/generation fields, MACs via the local
// egress path, and the RTFlow-present identity.
func TestSessionSyncGoldenV4Representative16172(t *testing.T) {
	m := goldenManager16172()
	m.SetIngressFoldResolver(func(fold uint32) (uint32, uint16, bool) {
		switch fold {
		case 0xAAAA:
			return 42, 50, true
		case 0xBBBB:
			return 43, 0, true
		}
		return 0, 0, false
	})
	key := dataplane.SessionKey{
		SrcIP: [4]byte{10, 0, 61, 102}, DstIP: [4]byte{172, 16, 80, 200},
		SrcPort: hostToNetwork16(50952), DstPort: hostToNetwork16(5201), Protocol: 6,
	}
	val := &dataplane.SessionValue{
		IngressZone: 1, EgressZone: 2,
		IngressIfaceFold: 0xAAAA, NatScopeFold: 0xBBBB, RoutingDomain: 100007,
		FibIfindex: 6, FibVlanID: 80,
		FibDmac:  [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		FibSmac:  [6]byte{0x02, 0xbf, 0x72, 0x00, 0x50, 0x08},
		Flags:    dataplane.SessFlagSNAT | dataplane.SessFlagDNAT | dataplane.WithSourceNatProvenance(0, dataplane.SourceNatProvenanceDynamic),
		NATSrcIP: natU32("10.0.61.1"), NATDstIP: natU32("10.0.61.102"),
		NATSrcPort: hostToNetwork16(40000), NATDstPort: hostToNetwork16(8443),
		LogFlags:   dataplane.LogFlagSessionInit | dataplane.LogFlagSessionClose | dataplane.LogFlagUserspaceFabricIngress,
		IsReverse:  1,
		Generation: 0xABCDEF, PolicyID: 42, PolicyCounterIdx: 7,
		PolicyRuleID: "lan-wan/allow-web", AppTimeout: 30,
		RTFlowSessionID: 0x1122334455667788, SessionID: 99,
		TunnelDiscriminator: 0xDEADBEEF, PptpCallIDs: 0x11112222,
		TCPCloseClass: 1, TCPHandshakeState: 3,
		InstallTableDomain: 525590, InstallTableCheck: 77,
		SourceNatICMPValid: true, SourceNatICMPType: 8, SourceNatICMPCode: 3,
	}
	got := mustJSON16172(t, m.buildSessionSyncRequestV4("upsert", key, val))
	want := `{"operation":"upsert","addr_family":2,"protocol":6,"src_ip":"10.0.61.102","dst_ip":"172.16.80.200","src_port":50952,"dst_port":5201,"ingress_zone_id":1,"egress_zone_id":2,"ingress_ifindex":42,"ingress_vlan_id":50,"nat_scope_ifindex":43,"owner_rg_id":1,"egress_ifindex":12,"tx_ifindex":6,"tx_vlan_id":80,"neighbor_mac":"aa:bb:cc:dd:ee:ff","src_mac":"02:bf:72:00:50:08","nat_src_ip":"10.0.61.1","nat_dst_ip":"10.0.61.102","nat_src_port":40000,"nat_dst_port":8443,"source_nat_icmp_valid":true,"source_nat_icmp_type":8,"source_nat_icmp_code":3,"source_nat_provenance":1,"fabric_ingress":true,"is_reverse":true,"log_session_init":true,"log_session_close":true,"generation":11259375,"policy_id":42,"policy_counter_idx":7,"policy_rule_id":"lan-wan/allow-web","inactivity_timeout":30,"session_id":1234605616436508552,"tunnel_discriminator":3735928559,"pptp_call_ids":286335522,"routing_domain":100007,"tcp_close_class":1,"tcp_handshake_state":3,"install_table_domain":525590,"install_table_check":77}`
	if got != want {
		t.Fatalf("V4 golden mismatch:\n got: %s\nwant: %s", got, want)
	}
}

// TestSessionSyncGoldenV6RepresentativeNat64_16172 pins a fully-populated V6
// upsert WITH the V6-only NAT64 pool source.
func TestSessionSyncGoldenV6RepresentativeNat64_16172(t *testing.T) {
	m := goldenManager16172()
	m.SetIngressFoldResolver(func(fold uint32) (uint32, uint16, bool) {
		switch fold {
		case 0xCCCC:
			return 7, 80, true
		case 0xDDDD:
			return 43, 0, true
		}
		return 0, 0, false
	})
	key := dataplane.SessionKeyV6{
		SrcIP: ip16("2001:db8::10"), DstIP: ip16("2001:db8:80::8"),
		SrcPort: hostToNetwork16(54321), DstPort: hostToNetwork16(443), Protocol: 6,
	}
	val := &dataplane.SessionValueV6{
		IngressZone: 1, EgressZone: 2, IngressIfaceFold: 0xCCCC, NatScopeFold: 0xDDDD, RoutingDomain: 100008,
		FibIfindex: 6, FibVlanID: 80,
		FibDmac: [6]byte{1, 2, 3, 4, 5, 6}, FibSmac: [6]byte{6, 5, 4, 3, 2, 1},
		Flags:    dataplane.SessFlagSNAT | dataplane.SessFlagDNAT | dataplane.WithSourceNatProvenance(0, dataplane.SourceNatProvenanceStatic),
		NATSrcIP: ip16("2001:db8:61::1"), NATDstIP: ip16("2001:db8:61::102"),
		NATSrcPort: hostToNetwork16(54321), NATDstPort: hostToNetwork16(8443),
		LogFlags:   dataplane.LogFlagSessionInit | dataplane.LogFlagSessionClose | dataplane.LogFlagUserspaceFabricIngress,
		IsReverse:  1,
		Generation: 0x123456, PolicyID: 99, PolicyCounterIdx: 11,
		PolicyRuleID: "lan-wan/allow-web", AppTimeout: 45,
		Nat64SnatV4:     [4]byte{203, 0, 113, 5},
		RTFlowSessionID: 0x99, SessionID: 55,
		TunnelDiscriminator: 7, PptpCallIDs: 0x11112222, TCPCloseClass: 2, TCPHandshakeState: 99, // 99 normalizes to 4
		InstallTableDomain: 525590, InstallTableCheck: 88,
		SourceNatICMPValid: true, SourceNatICMPType: 128, SourceNatICMPCode: 3,
	}
	got := mustJSON16172(t, m.buildSessionSyncRequestV6("upsert", key, val))
	want := `{"operation":"upsert","addr_family":10,"protocol":6,"src_ip":"2001:db8::10","dst_ip":"2001:db8:80::8","src_port":54321,"dst_port":443,"ingress_zone_id":1,"egress_zone_id":2,"ingress_ifindex":7,"ingress_vlan_id":80,"nat_scope_ifindex":43,"owner_rg_id":1,"egress_ifindex":12,"tx_ifindex":6,"tx_vlan_id":80,"neighbor_mac":"01:02:03:04:05:06","src_mac":"06:05:04:03:02:01","nat_src_ip":"2001:db8:61::1","nat_dst_ip":"2001:db8:61::102","nat_src_port":54321,"nat_dst_port":8443,"source_nat_icmp_valid":true,"source_nat_icmp_type":128,"source_nat_icmp_code":3,"source_nat_provenance":2,"fabric_ingress":true,"is_reverse":true,"log_session_init":true,"log_session_close":true,"generation":1193046,"policy_id":99,"policy_counter_idx":11,"policy_rule_id":"lan-wan/allow-web","inactivity_timeout":45,"nat64_snat_v4":"203.0.113.5","session_id":153,"tunnel_discriminator":7,"pptp_call_ids":286335522,"routing_domain":100008,"tcp_close_class":2,"tcp_handshake_state":4,"install_table_domain":525590,"install_table_check":88}`
	if got != want {
		t.Fatalf("V6 NAT64 golden mismatch:\n got: %s\nwant: %s", got, want)
	}
}

// TestSessionSyncGoldenNATOff16172: NAT values present in the value but the
// SNAT/DNAT flags clear => both legs scrubbed, for both families. Also the
// V6 non-NAT64 control (Nat64SnatV4 zero omits the key).
func TestSessionSyncGoldenNATOff16172(t *testing.T) {
	m := goldenManager16172()
	v4 := m.buildSessionSyncRequestV4("upsert",
		dataplane.SessionKey{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(80), Protocol: 6},
		&dataplane.SessionValue{IngressZone: 1, EgressZone: 2, NATSrcIP: natU32("10.0.61.1"), NATDstIP: natU32("10.0.61.102"), NATSrcPort: hostToNetwork16(40000), NATDstPort: hostToNetwork16(8443)})
	gotV4 := mustJSON16172(t, v4)
	wantV4 := `{"operation":"upsert","addr_family":2,"protocol":6,"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1234,"dst_port":80,"ingress_zone_id":1,"egress_zone_id":2,"generation":0,"tunnel_discriminator":0}`
	if gotV4 != wantV4 {
		t.Fatalf("V4 NAT-off golden mismatch:\n got: %s\nwant: %s", gotV4, wantV4)
	}

	v6 := m.buildSessionSyncRequestV6("upsert",
		dataplane.SessionKeyV6{SrcIP: ip16("2001:db8::1"), DstIP: ip16("2001:db8::2"), SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(80), Protocol: 6},
		&dataplane.SessionValueV6{IngressZone: 1, EgressZone: 2, NATSrcIP: ip16("2001:db8:61::1"), NATDstIP: ip16("2001:db8:61::102"), NATSrcPort: hostToNetwork16(40000), NATDstPort: hostToNetwork16(8443)})
	gotV6 := mustJSON16172(t, v6)
	wantV6 := `{"operation":"upsert","addr_family":10,"protocol":6,"src_ip":"2001:db8::1","dst_ip":"2001:db8::2","src_port":1234,"dst_port":80,"ingress_zone_id":1,"egress_zone_id":2,"generation":0,"tunnel_discriminator":0}`
	if gotV6 != wantV6 {
		t.Fatalf("V6 NAT-off golden mismatch:\n got: %s\nwant: %s", gotV6, wantV6)
	}
	if strings.Contains(gotV6, "nat64") {
		t.Fatalf("non-NAT64 V6 request carries nat64 key: %s", gotV6)
	}
}

// TestSessionSyncGoldenNilValueAndMissingSnapshot16172 pins the missing-map
// variants: val == nil (delete shape: key-only request) for both families,
// and a valued request on a manager with NO snapshot at all (egress falls
// back to the raw FibIfindex, zone names empty).
func TestSessionSyncGoldenNilValueAndMissingSnapshot16172(t *testing.T) {
	m := goldenManager16172()
	gotV4 := mustJSON16172(t, m.buildSessionSyncRequestV4("delete",
		dataplane.SessionKey{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(80), Protocol: 6}, nil))
	wantV4 := `{"operation":"delete","addr_family":2,"protocol":6,"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","src_port":1234,"dst_port":80,"generation":0,"tunnel_discriminator":0}`
	if gotV4 != wantV4 {
		t.Fatalf("V4 nil-value golden mismatch:\n got: %s\nwant: %s", gotV4, wantV4)
	}
	gotV6 := mustJSON16172(t, m.buildSessionSyncRequestV6("delete",
		dataplane.SessionKeyV6{SrcIP: ip16("2001:db8::1"), DstIP: ip16("2001:db8::2"), SrcPort: hostToNetwork16(1234), DstPort: hostToNetwork16(80), Protocol: 17}, nil))
	wantV6 := `{"operation":"delete","addr_family":10,"protocol":17,"src_ip":"2001:db8::1","dst_ip":"2001:db8::2","src_port":1234,"dst_port":80,"generation":0,"tunnel_discriminator":0}`
	if gotV6 != wantV6 {
		t.Fatalf("V6 nil-value golden mismatch:\n got: %s\nwant: %s", gotV6, wantV6)
	}

	// Missing map: no snapshot, no bpfShim compile result.
	bare := &Manager{bpfShim: dataplane.New()}
	got := mustJSON16172(t, bare.buildSessionSyncRequestV4("upsert",
		dataplane.SessionKey{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, Protocol: 6},
		&dataplane.SessionValue{IngressZone: 1, EgressZone: 2, FibIfindex: 9, Generation: 5}))
	want := `{"operation":"upsert","addr_family":2,"protocol":6,"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","ingress_zone_id":1,"egress_zone_id":2,"egress_ifindex":9,"tx_ifindex":9,"generation":5,"tunnel_discriminator":0}`
	if got != want {
		t.Fatalf("missing-snapshot golden mismatch:\n got: %s\nwant: %s", got, want)
	}
	got6 := mustJSON16172(t, bare.buildSessionSyncRequestV6("upsert",
		dataplane.SessionKeyV6{SrcIP: ip16("2001:db8::1"), DstIP: ip16("2001:db8::2"), Protocol: 6},
		&dataplane.SessionValueV6{IngressZone: 1, EgressZone: 2, FibIfindex: 9, Generation: 6}))
	want6 := `{"operation":"upsert","addr_family":10,"protocol":6,"src_ip":"2001:db8::1","dst_ip":"2001:db8::2","ingress_zone_id":1,"egress_zone_id":2,"egress_ifindex":9,"tx_ifindex":9,"generation":6,"tunnel_discriminator":0}`
	if got6 != want6 {
		t.Fatalf("missing-snapshot V6 golden mismatch:\n got: %s\nwant: %s", got6, want6)
	}
}

// TestSessionSyncGoldenOrderVariants16172 pins the stale/order variants
// as FULL-BYTE JSON for BOTH families (no substrings, no field picks):
//   - stale generation rides verbatim (a large/old generation is not clamped)
//   - RTFlowSessionID==0 falls back to SessionID; both present => RTFlow
//     wins; double-zero omits session_id entirely
//   - tunnel-endpoint FibGen override beats the egress-derived endpoint
//     and clears TX/MAC fields; a stale FibGen naming no endpoint zeroes
//     egress; no flag => the egress-derived endpoint applies
//   - peer-egress fold (unresolvable) suppresses MACs and zeroes egress
//
// Every literal below was captured from the pre-collapse twins at
// 24f2c40e5e and verified byte-identical there before being pinned.
func TestSessionSyncGoldenOrderVariants16172(t *testing.T) {
	m := goldenManager16172()
	key4 := dataplane.SessionKey{SrcIP: [4]byte{10, 0, 0, 1}, DstIP: [4]byte{10, 0, 0, 2}, Protocol: 6}
	key6 := dataplane.SessionKeyV6{SrcIP: ip16("2001:db8::1"), DstIP: ip16("2001:db8::2"), Protocol: 6}
	dmac := [6]byte{1, 2, 3, 4, 5, 6}
	smac := [6]byte{6, 5, 4, 3, 2, 1}

	cases := []struct {
		name string
		got  string
		want string
	}{
		{"v4_stale_generation",
			mustJSON16172(t, m.buildSessionSyncRequestV4("upsert", key4, &dataplane.SessionValue{Generation: 0xFFFFFFFFFFFFFFFE})),
			`{"operation":"upsert","addr_family":2,"protocol":6,"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","generation":18446744073709551614,"tunnel_discriminator":0}`},
		{"v6_stale_generation",
			mustJSON16172(t, m.buildSessionSyncRequestV6("upsert", key6, &dataplane.SessionValueV6{Generation: 0xFFFFFFFFFFFFFFFE})),
			`{"operation":"upsert","addr_family":10,"protocol":6,"src_ip":"2001:db8::1","dst_ip":"2001:db8::2","generation":18446744073709551614,"tunnel_discriminator":0}`},
		{"v4_sessionid_fallback",
			mustJSON16172(t, m.buildSessionSyncRequestV4("upsert", key4, &dataplane.SessionValue{SessionID: 78})),
			`{"operation":"upsert","addr_family":2,"protocol":6,"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","generation":0,"session_id":78,"tunnel_discriminator":0}`},
		{"v6_sessionid_fallback",
			mustJSON16172(t, m.buildSessionSyncRequestV6("upsert", key6, &dataplane.SessionValueV6{SessionID: 78})),
			`{"operation":"upsert","addr_family":10,"protocol":6,"src_ip":"2001:db8::1","dst_ip":"2001:db8::2","generation":0,"session_id":78,"tunnel_discriminator":0}`},
		{"v4_rtflow_precedence",
			mustJSON16172(t, m.buildSessionSyncRequestV4("upsert", key4, &dataplane.SessionValue{SessionID: 78, RTFlowSessionID: 77})),
			`{"operation":"upsert","addr_family":2,"protocol":6,"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","generation":0,"session_id":77,"tunnel_discriminator":0}`},
		{"v6_rtflow_precedence",
			mustJSON16172(t, m.buildSessionSyncRequestV6("upsert", key6, &dataplane.SessionValueV6{SessionID: 78, RTFlowSessionID: 77})),
			`{"operation":"upsert","addr_family":10,"protocol":6,"src_ip":"2001:db8::1","dst_ip":"2001:db8::2","generation":0,"session_id":77,"tunnel_discriminator":0}`},
		{"v4_double_zero_identity",
			mustJSON16172(t, m.buildSessionSyncRequestV4("upsert", key4, &dataplane.SessionValue{})),
			`{"operation":"upsert","addr_family":2,"protocol":6,"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","generation":0,"tunnel_discriminator":0}`},
		{"v6_double_zero_identity",
			mustJSON16172(t, m.buildSessionSyncRequestV6("upsert", key6, &dataplane.SessionValueV6{})),
			`{"operation":"upsert","addr_family":10,"protocol":6,"src_ip":"2001:db8::1","dst_ip":"2001:db8::2","generation":0,"tunnel_discriminator":0}`},
		{"v4_tunnel_fibgen_live",
			mustJSON16172(t, m.buildSessionSyncRequestV4("upsert", key4, &dataplane.SessionValue{LogFlags: dataplane.LogFlagUserspaceTunnelEndpoint, FibGen: 3, FibIfindex: 894, FibVlanID: 80, FibDmac: dmac, FibSmac: smac})),
			`{"operation":"upsert","addr_family":2,"protocol":6,"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","owner_rg_id":1,"egress_ifindex":586,"tunnel_endpoint_id":3,"generation":0,"tunnel_discriminator":0}`},
		{"v6_tunnel_fibgen_live",
			mustJSON16172(t, m.buildSessionSyncRequestV6("upsert", key6, &dataplane.SessionValueV6{LogFlags: dataplane.LogFlagUserspaceTunnelEndpoint, FibGen: 3, FibIfindex: 894, FibVlanID: 80, FibDmac: dmac, FibSmac: smac})),
			`{"operation":"upsert","addr_family":10,"protocol":6,"src_ip":"2001:db8::1","dst_ip":"2001:db8::2","owner_rg_id":1,"egress_ifindex":586,"tunnel_endpoint_id":3,"generation":0,"tunnel_discriminator":0}`},
		{"v4_tunnel_fibgen_stale",
			mustJSON16172(t, m.buildSessionSyncRequestV4("upsert", key4, &dataplane.SessionValue{LogFlags: dataplane.LogFlagUserspaceTunnelEndpoint, FibGen: 99, FibIfindex: 6, FibVlanID: 80})),
			`{"operation":"upsert","addr_family":2,"protocol":6,"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","tunnel_endpoint_id":99,"generation":0,"tunnel_discriminator":0}`},
		{"v6_tunnel_fibgen_stale",
			mustJSON16172(t, m.buildSessionSyncRequestV6("upsert", key6, &dataplane.SessionValueV6{LogFlags: dataplane.LogFlagUserspaceTunnelEndpoint, FibGen: 99, FibIfindex: 6, FibVlanID: 80})),
			`{"operation":"upsert","addr_family":10,"protocol":6,"src_ip":"2001:db8::1","dst_ip":"2001:db8::2","tunnel_endpoint_id":99,"generation":0,"tunnel_discriminator":0}`},
		{"v4_tunnel_derived",
			mustJSON16172(t, m.buildSessionSyncRequestV4("upsert", key4, &dataplane.SessionValue{FibIfindex: 586})),
			`{"operation":"upsert","addr_family":2,"protocol":6,"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","owner_rg_id":1,"egress_ifindex":586,"tunnel_endpoint_id":3,"generation":0,"tunnel_discriminator":0}`},
		{"v6_tunnel_derived",
			mustJSON16172(t, m.buildSessionSyncRequestV6("upsert", key6, &dataplane.SessionValueV6{FibIfindex: 586})),
			`{"operation":"upsert","addr_family":10,"protocol":6,"src_ip":"2001:db8::1","dst_ip":"2001:db8::2","owner_rg_id":1,"egress_ifindex":586,"tunnel_endpoint_id":3,"generation":0,"tunnel_discriminator":0}`},
		{"v4_peer_egress",
			mustJSON16172(t, m.buildSessionSyncRequestV4("upsert", key4, &dataplane.SessionValue{FibIfindex: 42, EgressIfaceFold: 0xDEADBEEF, FibDmac: dmac, FibSmac: smac})),
			`{"operation":"upsert","addr_family":2,"protocol":6,"src_ip":"10.0.0.1","dst_ip":"10.0.0.2","generation":0,"tunnel_discriminator":0}`},
		{"v6_peer_egress",
			mustJSON16172(t, m.buildSessionSyncRequestV6("upsert", key6, &dataplane.SessionValueV6{FibIfindex: 42, EgressIfaceFold: 0xDEADBEEF, FibDmac: dmac, FibSmac: smac})),
			`{"operation":"upsert","addr_family":10,"protocol":6,"src_ip":"2001:db8::1","dst_ip":"2001:db8::2","generation":0,"tunnel_discriminator":0}`},
	}
	for _, tc := range cases {
		if tc.got != tc.want {
			t.Fatalf("%s golden mismatch:\n got: %s\nwant: %s", tc.name, tc.got, tc.want)
		}
	}
}
