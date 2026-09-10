package userspace

import (
	"encoding/json"
	"strings"
	"testing"
)

// #1865: cross-language wire pin for the per-WG-tunnel telemetry rows.
// The JSON literal below uses the EXACT key set the Rust side emits
// (userspace-dp/src/protocol/control.rs WgTunnelStatus serde renames;
// pinned there by process_status_wg_tunnels_roundtrip_and_compat with
// the same 1..44 counter ladder). A key drift on either side breaks
// one of the two pins.
func TestProcessStatusWgTunnelsPopulatedDecode(t *testing.T) {
	payload := `{
		"pid": 1,
		"started_at": "2026-06-11T00:00:00Z",
		"control_socket": "", "state_file": "",
		"workers": 0, "ring_entries": 0, "helper_mode": "",
		"io_uring_planned": false, "enabled": true,
		"last_snapshot_generation": 0,
		"wg_tunnels": [{
			"tunnel": "wg0",
			"tunnel_endpoint_id": 7,
			"listen_port": 51820,
			"local_pubkey_hex": "` + strings.Repeat("cd", 32) + `",
			"peers": [{
				"peer_pubkey_hex": "` + strings.Repeat("ab", 32) + `",
				"peer_endpoint": "192.0.2.10:51820",
				"session_confirmed": true
			}],
			"last_handshake_unix_secs": 1770000000,
			"hs_initiations_created": 1,
			"hs_initiation_build_failures": 2,
			"hs_responses_created": 3,
			"hs_completions_initiator": 4,
			"hs_rx_drops_mac1_mismatch": 5,
			"hs_rx_drops_malformed": 6,
			"hs_rx_drops_crypto": 7,
			"hs_rx_drops_unknown_peer": 8,
			"hs_rx_drops_stale_response": 9,
			"hs_rx_drops_index_exhausted": 10,
			"hs_rx_drops_replayed_init": 45,
			"hs_rx_cookie_unsupported": 11,
			"rx_unknown_type": 12,
			"hs_send_errors": 13,
			"hs_requests_armed": 14,
			"decap_packets": 15,
			"decap_bytes": 16,
			"decap_keepalives": 17,
			"decap_drops_malformed_header": 18,
			"decap_drops_unknown_session": 19,
			"decap_drops_counter_ceiling": 20,
			"decap_drops_crypto": 21,
			"decap_drops_replay": 22,
			"decap_drops_allowed_ips": 23,
			"decap_drops_malformed_inner": 24,
			"decap_drops_buffer": 25,
			"rx_unsteered_transport_drops": 55,
			"rx_degraded_transit_drops": 91,
			"encap_packets": 26,
			"encap_bytes": 27,
			"encap_drops_no_session": 28,
			"encap_drops_unconfirmed": 29,
			"encap_drops_rekey_required": 30,
			"encap_drops_other": 31,
			"encap_mtu_drops": 32,
			"transport_send_errors": 33,
			"tun_write_errors": 34,
			"tun_rx_drops_no_endpoint": 35,
			"encap_drops_expired": 36,
			"decap_drops_expired": 37,
			"sessions_expired": 38,
			"rekeys_initiated_age": 39,
			"rekeys_initiated_dead_peer": 40,
			"rekeys_initiated_keepalive_no_session": 41,
			"keepalives_tx_passive": 42,
			"keepalives_tx_persistent": 43,
			"pending_aborted_attempt_window": 44,
			"endpoint_resolve_ok": 51,
			"endpoint_resolve_fail": 52,
			"endpoint_family_mismatch": 53,
			"endpoint_changed": 54,
			"endpoint_last_error": "vpn.example.com: no AAAA for a v6 socket"
		}]
	}`
	var status ProcessStatus
	if err := json.Unmarshal([]byte(payload), &status); err != nil {
		t.Fatalf("unmarshal populated wg_tunnels payload: %v", err)
	}
	if len(status.WgTunnels) != 1 {
		t.Fatalf("WgTunnels rows = %d, want 1", len(status.WgTunnels))
	}
	row := status.WgTunnels[0]
	if row.Tunnel != "wg0" || row.TunnelEndpointID != 7 || row.ListenPort != 51820 {
		t.Fatalf("identity fields = %+v", row)
	}
	if len(row.Peers) != 1 {
		t.Fatalf("Peers = %d, want 1", len(row.Peers))
	}
	if row.Peers[0].PeerPubkeyHex != strings.Repeat("ab", 32) {
		t.Fatalf("Peers[0].PeerPubkeyHex = %q", row.Peers[0].PeerPubkeyHex)
	}
	// #1434 Increment 1: the local public key must plumb through with a
	// distinct value (cd-ladder) so a swapped peer/local tag is caught.
	if row.LocalPubkeyHex != strings.Repeat("cd", 32) {
		t.Fatalf("LocalPubkeyHex = %q", row.LocalPubkeyHex)
	}
	if row.Peers[0].PeerEndpoint != "192.0.2.10:51820" || !row.Peers[0].SessionConfirmed {
		t.Fatalf("endpoint/confirmed = %q/%v", row.Peers[0].PeerEndpoint, row.Peers[0].SessionConfirmed)
	}
	if row.LastHandshakeUnixSecs != 1770000000 {
		t.Fatalf("LastHandshakeUnixSecs = %d", row.LastHandshakeUnixSecs)
	}
	// The 1..44 counter ladder: every field carries its ordinal, so a
	// swapped/mistagged field shows up as the wrong value.
	ladder := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"HsInitiationsCreated", row.HsInitiationsCreated, 1},
		{"HsInitiationBuildFailures", row.HsInitiationBuildFailures, 2},
		{"HsResponsesCreated", row.HsResponsesCreated, 3},
		{"HsCompletionsInitiator", row.HsCompletionsInitiator, 4},
		{"HsRxDropsMac1Mismatch", row.HsRxDropsMac1Mismatch, 5},
		{"HsRxDropsMalformed", row.HsRxDropsMalformed, 6},
		{"HsRxDropsCrypto", row.HsRxDropsCrypto, 7},
		{"HsRxDropsUnknownPeer", row.HsRxDropsUnknownPeer, 8},
		{"HsRxDropsStaleResponse", row.HsRxDropsStaleResponse, 9},
		{"HsRxDropsIndexExhausted", row.HsRxDropsIndexExhausted, 10},
		{"HsRxDropsReplayedInit", row.HsRxDropsReplayedInit, 45},
		{"HsRxCookieUnsupported", row.HsRxCookieUnsupported, 11},
		{"RxUnknownType", row.RxUnknownType, 12},
		{"HsSendErrors", row.HsSendErrors, 13},
		{"HsRequestsArmed", row.HsRequestsArmed, 14},
		{"DecapPackets", row.DecapPackets, 15},
		{"DecapBytes", row.DecapBytes, 16},
		{"DecapKeepalives", row.DecapKeepalives, 17},
		{"DecapDropsMalformedHeader", row.DecapDropsMalformedHeader, 18},
		{"DecapDropsUnknownSession", row.DecapDropsUnknownSession, 19},
		{"DecapDropsCounterCeiling", row.DecapDropsCounterCeiling, 20},
		{"DecapDropsCrypto", row.DecapDropsCrypto, 21},
		{"DecapDropsReplay", row.DecapDropsReplay, 22},
		{"DecapDropsAllowedIPs", row.DecapDropsAllowedIPs, 23},
		{"DecapDropsMalformedInner", row.DecapDropsMalformedInner, 24},
		{"DecapDropsBuffer", row.DecapDropsBuffer, 25},
		{"RxUnsteeredTransportDrops", row.RxUnsteeredTransportDrops, 55},
		{"RxDegradedTransitDrops", row.RxDegradedTransitDrops, 91},
		{"EncapPackets", row.EncapPackets, 26},
		{"EncapBytes", row.EncapBytes, 27},
		{"EncapDropsNoSession", row.EncapDropsNoSession, 28},
		{"EncapDropsUnconfirmed", row.EncapDropsUnconfirmed, 29},
		{"EncapDropsRekeyRequired", row.EncapDropsRekeyRequired, 30},
		{"EncapDropsOther", row.EncapDropsOther, 31},
		{"EncapMtuDrops", row.EncapMtuDrops, 32},
		{"TransportSendErrors", row.TransportSendErrors, 33},
		{"TunWriteErrors", row.TunWriteErrors, 34},
		{"TunRxDropsNoEndpoint", row.TunRxDropsNoEndpoint, 35},
		{"EncapDropsExpired", row.EncapDropsExpired, 36},
		{"DecapDropsExpired", row.DecapDropsExpired, 37},
		{"SessionsExpired", row.SessionsExpired, 38},
		{"RekeysInitiatedAge", row.RekeysInitiatedAge, 39},
		{"RekeysInitiatedDeadPeer", row.RekeysInitiatedDeadPeer, 40},
		{"RekeysInitiatedKeepaliveNoSession", row.RekeysInitiatedKeepaliveNoSession, 41},
		{"KeepalivesTxPassive", row.KeepalivesTxPassive, 42},
		{"KeepalivesTxPersistent", row.KeepalivesTxPersistent, 43},
		{"PendingAbortedAttemptWindow", row.PendingAbortedAttemptWindow, 44},
		// #7936 endpoint resolver. The ladder values match the Rust-side
		// literal in protocol/tests.rs so a swapped pair of json tags shows up
		// as a wrong NUMBER on both sides rather than as two green suites.
		{"EndpointResolveOk", row.EndpointResolveOk, 51},
		{"EndpointResolveFail", row.EndpointResolveFail, 52},
		{"EndpointFamilyMismatch", row.EndpointFamilyMismatch, 53},
		{"EndpointChanged", row.EndpointChanged, 54},
	}
	for _, c := range ladder {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d (json tag drift?)", c.name, c.got, c.want)
		}
	}
	// #7936: the STRING is checked separately because the ladder is uint64.
	// It is not decoration — `endpoint_family_mismatch` counts how often, and
	// only this says WHICH name resolved to the wrong family, which is the
	// difference between a number and a diagnosis.
	if row.EndpointLastError != "vpn.example.com: no AAAA for a v6 socket" {
		t.Errorf("EndpointLastError = %q, want the resolver's retained text",
			row.EndpointLastError)
	}
}

// Pre-#1865 helper payload: key absent entirely → nil slice, and a
// re-marshal of a WG-less status must NOT introduce the key (the
// non-WG wire stays byte-identical — mirror of the Rust
// empty-invariant pin).
func TestProcessStatusWgTunnelsAbsentAndOmitted(t *testing.T) {
	var status ProcessStatus
	if err := json.Unmarshal([]byte(`{"pid":1,"started_at":"2026-06-11T00:00:00Z","control_socket":"","state_file":"","workers":0,"ring_entries":0,"helper_mode":"","io_uring_planned":false,"last_snapshot_generation":0}`), &status); err != nil {
		t.Fatalf("unmarshal legacy payload: %v", err)
	}
	if status.WgTunnels != nil {
		t.Fatalf("WgTunnels = %v, want nil for absent key", status.WgTunnels)
	}
	out, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(out), "wg_tunnels") {
		t.Fatalf("re-marshal of WG-less status must omit wg_tunnels: %s", out)
	}
}
