package api

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #1865: full series-set + label-value pin for emitWireguardTelemetry.
// Drives the emitter directly with one populated tunnel row (the 1..35
// ladder mirroring the cross-language wire pins) and asserts:
//   - the exact set of emitted series (name + labels), so a dropped
//     reason/kind/role/direction label value fails here;
//   - counter-vs-gauge dto types;
//   - the never-handshaked gating of the last-handshake gauge;
//   - zero-valued reasons are EMITTED (0 is a real signal).
func TestEmitWireguardTelemetrySeriesSet(t *testing.T) {
	c := &xpfCollector{
		wgHandshakesCompletedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshakes_completed_total", "t", []string{"tunnel", "role"}, nil),
		wgHandshakeInitiationsCreatedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_initiations_created_total", "t", []string{"tunnel"}, nil),
		wgHandshakeInitiationBuildFailuresTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_initiation_build_failures_total", "t", []string{"tunnel"}, nil),
		wgHandshakeRxDropsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_rx_drops_total", "t", []string{"tunnel", "reason"}, nil),
		wgCookieRepliesTotal: prometheus.NewDesc(
			"xpf_userspace_wg_cookie_replies_total", "t", []string{"tunnel", "event"}, nil),
		wgHandshakeRequestsArmedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_requests_armed_total", "t", []string{"tunnel"}, nil),
		wgTransportPacketsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_transport_packets_total", "t", []string{"tunnel", "direction"}, nil),
		wgTransportBytesTotal: prometheus.NewDesc(
			"xpf_userspace_wg_transport_bytes_total", "t", []string{"tunnel", "direction"}, nil),
		wgKeepalivesReceivedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_keepalives_received_total", "t", []string{"tunnel"}, nil),
		wgTransportDropsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_transport_drops_total", "t", []string{"tunnel", "direction", "reason"}, nil),
		wgSendErrorsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_send_errors_total", "t", []string{"tunnel", "kind"}, nil),
		wgSessionConfirmed: prometheus.NewDesc(
			"xpf_userspace_wg_session_confirmed", "t", []string{"tunnel", "peer"}, nil),
		wgLastHandshakeTimeSeconds: prometheus.NewDesc(
			"xpf_userspace_wg_last_handshake_time_seconds", "t", []string{"tunnel"}, nil),
		wgRekeysInitiatedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_rekeys_initiated_total", "t", []string{"tunnel", "reason"}, nil),
		wgKeepalivesSentTotal: prometheus.NewDesc(
			"xpf_userspace_wg_keepalives_sent_total", "t", []string{"tunnel", "kind"}, nil),
		wgSessionsExpiredTotal: prometheus.NewDesc(
			"xpf_userspace_wg_sessions_expired_total", "t", []string{"tunnel"}, nil),
		wgHandshakeAttemptsAbortedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_attempts_aborted_total", "t", []string{"tunnel"}, nil),
		wgEndpointResolutionsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_endpoint_resolutions_total", "t", []string{"tunnel", "outcome"}, nil),
	}
	status := dpuserspace.ProcessStatus{
		WgTunnels: []dpuserspace.WgTunnelStatus{{
			Tunnel: "wg0",
			Peers: []dpuserspace.WgPeerStatus{{
				PeerPubkeyHex:    "ab",
				SessionConfirmed: true,
			}},
			LastHandshakeUnixSecs:     1770000000,
			HsInitiationsCreated:      1,
			HsInitiationBuildFailures: 2,
			HsResponsesCreated:        3,
			HsCompletionsInitiator:    4,
			HsRxDropsMac1Mismatch:     5,
			HsRxDropsMalformed:        6,
			HsRxDropsCrypto:           7,
			HsRxDropsUnknownPeer:      8,
			HsRxDropsStaleResponse:    9,
			HsRxDropsIndexExhausted:   10,
			HsRxDropsReplayedInit:     45,
			HsRxCookieUnsupported:     11,
			// #4094 PR-B initiator cookie-replies consumed (50, off-ladder).
			HsRxCookieConsumed: 50,
			// #4094 PR-A responder cookie mechanism (46.. continuing).
			HsCookieRepliesSent:       46,
			HsRxUnderLoadNoMac2:       47,
			HsRxUnderLoadMac2Ok:       48,
			HsCookieReplyBudgetDrops:  49,
			RxUnknownType:             12,
			HsSendErrors:              13,
			HsRequestsArmed:           14,
			DecapPackets:              15,
			DecapBytes:                16,
			DecapKeepalives:           17,
			DecapDropsMalformedHeader: 18,
			DecapDropsUnknownSession:  19,
			DecapDropsCounterCeiling:  20,
			DecapDropsCrypto:          21,
			DecapDropsReplay:          22,
			DecapDropsAllowedIPs:      23,
			DecapDropsMalformedInner:  24,
			DecapDropsBuffer:          25,
			RxUnsteeredTransportDrops: 55,
			EncapPackets:              26,
			EncapBytes:                27,
			EncapDropsNoSession:       28,
			EncapDropsUnconfirmed:     29,
			EncapDropsRekeyRequired:   30,
			EncapDropsOther:           31,
			EncapMtuDrops:             32,
			TransportSendErrors:       33,
			TunWriteErrors:            34,
			TunRxDropsNoEndpoint:      0, // zero on purpose: must still emit
			// #1888 S5 timer telemetry (36.. continuing the ladder).
			EncapDropsExpired:                 36,
			DecapDropsExpired:                 37,
			SessionsExpired:                   38,
			RekeysInitiatedAge:                39,
			RekeysInitiatedDeadPeer:           40,
			RekeysInitiatedKeepaliveNoSession: 41,
			KeepalivesTxPassive:               42,
			KeepalivesTxPersistent:            43,
			PendingAbortedAttemptWindow:       44,
			EndpointResolveOk:                 51,
			EndpointResolveFail:               52,
			EndpointFamilyMismatch:            53,
			EndpointChanged:                   54,
		}},
	}

	ch := make(chan prometheus.Metric, 256)
	c.emitWireguardTelemetry(ch, status)
	close(ch)

	got := map[string]float64{}
	gotType := map[string]string{}
	for m := range ch {
		var d dto.Metric
		if err := m.Write(&d); err != nil {
			t.Fatalf("metric Write: %v", err)
		}
		key := m.Desc().String()
		// Build a stable key: fqName is embedded in Desc().String();
		// append sorted label pairs from the dto.
		lbl := ""
		for _, lp := range d.GetLabel() {
			lbl += "," + lp.GetName() + "=" + lp.GetValue()
		}
		key = descFQName(key) + lbl
		switch {
		case d.Counter != nil:
			got[key] = d.Counter.GetValue()
			gotType[key] = "counter"
		case d.Gauge != nil:
			got[key] = d.Gauge.GetValue()
			gotType[key] = "gauge"
		default:
			t.Fatalf("unexpected metric type for %s", key)
		}
	}

	want := map[string]float64{
		"xpf_userspace_wg_handshakes_completed_total,role=initiator,tunnel=wg0":                     4,
		"xpf_userspace_wg_handshakes_completed_total,role=responder,tunnel=wg0":                     3,
		"xpf_userspace_wg_handshake_initiations_created_total,tunnel=wg0":                           1,
		"xpf_userspace_wg_handshake_initiation_build_failures_total,tunnel=wg0":                     2,
		"xpf_userspace_wg_handshake_requests_armed_total,tunnel=wg0":                                14,
		"xpf_userspace_wg_handshake_rx_drops_total,reason=mac1_mismatch,tunnel=wg0":                 5,
		"xpf_userspace_wg_handshake_rx_drops_total,reason=malformed,tunnel=wg0":                     6,
		"xpf_userspace_wg_handshake_rx_drops_total,reason=crypto,tunnel=wg0":                        7,
		"xpf_userspace_wg_handshake_rx_drops_total,reason=unknown_peer,tunnel=wg0":                  8,
		"xpf_userspace_wg_handshake_rx_drops_total,reason=stale_response,tunnel=wg0":                9,
		"xpf_userspace_wg_handshake_rx_drops_total,reason=index_exhausted,tunnel=wg0":               10,
		"xpf_userspace_wg_handshake_rx_drops_total,reason=replayed_init,tunnel=wg0":                 45,
		"xpf_userspace_wg_handshake_rx_drops_total,reason=cookie_unsupported,tunnel=wg0":            11,
		"xpf_userspace_wg_handshake_rx_drops_total,reason=under_load_no_mac2,tunnel=wg0":            47,
		"xpf_userspace_wg_handshake_rx_drops_total,reason=cookie_reply_budget,tunnel=wg0":           49,
		"xpf_userspace_wg_cookie_replies_total,event=sent,tunnel=wg0":                               46,
		"xpf_userspace_wg_cookie_replies_total,event=mac2_ok,tunnel=wg0":                            48,
		"xpf_userspace_wg_cookie_replies_total,event=consumed,tunnel=wg0":                           50,
		"xpf_userspace_wg_handshake_rx_drops_total,reason=unknown_type,tunnel=wg0":                  12,
		"xpf_userspace_wg_transport_packets_total,direction=encap,tunnel=wg0":                       26,
		"xpf_userspace_wg_transport_packets_total,direction=decap,tunnel=wg0":                       15,
		"xpf_userspace_wg_transport_bytes_total,direction=encap,tunnel=wg0":                         27,
		"xpf_userspace_wg_transport_bytes_total,direction=decap,tunnel=wg0":                         16,
		"xpf_userspace_wg_keepalives_received_total,tunnel=wg0":                                     17,
		"xpf_userspace_wg_transport_drops_total,direction=decap,reason=malformed_header,tunnel=wg0": 18,
		"xpf_userspace_wg_transport_drops_total,direction=decap,reason=unknown_session,tunnel=wg0":  19,
		"xpf_userspace_wg_transport_drops_total,direction=decap,reason=counter_ceiling,tunnel=wg0":  20,
		"xpf_userspace_wg_transport_drops_total,direction=decap,reason=crypto,tunnel=wg0":           21,
		"xpf_userspace_wg_transport_drops_total,direction=decap,reason=replay,tunnel=wg0":           22,
		"xpf_userspace_wg_transport_drops_total,direction=decap,reason=allowed_ips,tunnel=wg0":      23,
		"xpf_userspace_wg_transport_drops_total,direction=decap,reason=malformed_inner,tunnel=wg0":  24,
		"xpf_userspace_wg_transport_drops_total,direction=decap,reason=buffer,tunnel=wg0":           25,
		"xpf_userspace_wg_transport_drops_total,direction=decap,reason=unsteered_port,tunnel=wg0":   55,
		"xpf_userspace_wg_transport_drops_total,direction=encap,reason=no_session,tunnel=wg0":       28,
		"xpf_userspace_wg_transport_drops_total,direction=encap,reason=unconfirmed,tunnel=wg0":      29,
		"xpf_userspace_wg_transport_drops_total,direction=encap,reason=rekey_required,tunnel=wg0":   30,
		"xpf_userspace_wg_transport_drops_total,direction=encap,reason=mtu,tunnel=wg0":              32,
		"xpf_userspace_wg_transport_drops_total,direction=encap,reason=other,tunnel=wg0":            31,
		"xpf_userspace_wg_send_errors_total,kind=handshake,tunnel=wg0":                              13,
		"xpf_userspace_wg_send_errors_total,kind=transport,tunnel=wg0":                              33,
		"xpf_userspace_wg_send_errors_total,kind=tun_write,tunnel=wg0":                              34,
		"xpf_userspace_wg_send_errors_total,kind=tun_rx_no_endpoint,tunnel=wg0":                     0,
		"xpf_userspace_wg_session_confirmed,peer=ab,tunnel=wg0":                                     1,
		"xpf_userspace_wg_last_handshake_time_seconds,tunnel=wg0":                                   1770000000,
		"xpf_userspace_wg_transport_drops_total,direction=encap,reason=expired,tunnel=wg0":          36,
		"xpf_userspace_wg_transport_drops_total,direction=decap,reason=expired,tunnel=wg0":          37,
		"xpf_userspace_wg_sessions_expired_total,tunnel=wg0":                                        38,
		"xpf_userspace_wg_rekeys_initiated_total,reason=age,tunnel=wg0":                             39,
		"xpf_userspace_wg_rekeys_initiated_total,reason=dead_peer,tunnel=wg0":                       40,
		"xpf_userspace_wg_rekeys_initiated_total,reason=keepalive_no_session,tunnel=wg0":            41,
		"xpf_userspace_wg_keepalives_sent_total,kind=passive,tunnel=wg0":                            42,
		"xpf_userspace_wg_keepalives_sent_total,kind=persistent,tunnel=wg0":                         43,
		"xpf_userspace_wg_handshake_attempts_aborted_total,tunnel=wg0":                              44,
		// #7936: one metric, four outcomes. The exact-set assertion is what
		// makes this list load-bearing — a fifth outcome added without a row
		// here reds rather than passing unnoticed.
		"xpf_userspace_wg_endpoint_resolutions_total,outcome=ok,tunnel=wg0":              51,
		"xpf_userspace_wg_endpoint_resolutions_total,outcome=fail,tunnel=wg0":            52,
		"xpf_userspace_wg_endpoint_resolutions_total,outcome=family_mismatch,tunnel=wg0": 53,
		"xpf_userspace_wg_endpoint_resolutions_total,outcome=changed,tunnel=wg0":         54,
	}
	if len(got) != len(want) {
		t.Errorf("emitted %d series, want %d", len(got), len(want))
	}
	for k, v := range want {
		gv, ok := got[k]
		if !ok {
			t.Errorf("missing series %s", k)
			continue
		}
		if gv != v {
			t.Errorf("series %s = %v, want %v", k, gv, v)
		}
	}
	for k := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("unexpected series %s", k)
		}
	}
	if gotType["xpf_userspace_wg_session_confirmed,peer=ab,tunnel=wg0"] != "gauge" {
		t.Errorf("session_confirmed must be a gauge")
	}
	if gotType["xpf_userspace_wg_transport_packets_total,direction=encap,tunnel=wg0"] != "counter" {
		t.Errorf("transport packets must be a counter")
	}
}

// Never-handshaked: the last-handshake gauge is ABSENT (0 is the
// in-band wire sentinel for never, not a valid gauge sample), while
// every counter series still emits with value 0.
func TestEmitWireguardTelemetryNeverHandshakedGauge(t *testing.T) {
	c := &xpfCollector{
		wgHandshakesCompletedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshakes_completed_total", "t", []string{"tunnel", "role"}, nil),
		wgHandshakeInitiationsCreatedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_initiations_created_total", "t", []string{"tunnel"}, nil),
		wgHandshakeInitiationBuildFailuresTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_initiation_build_failures_total", "t", []string{"tunnel"}, nil),
		wgHandshakeRxDropsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_rx_drops_total", "t", []string{"tunnel", "reason"}, nil),
		wgCookieRepliesTotal: prometheus.NewDesc(
			"xpf_userspace_wg_cookie_replies_total", "t", []string{"tunnel", "event"}, nil),
		wgHandshakeRequestsArmedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_requests_armed_total", "t", []string{"tunnel"}, nil),
		wgTransportPacketsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_transport_packets_total", "t", []string{"tunnel", "direction"}, nil),
		wgTransportBytesTotal: prometheus.NewDesc(
			"xpf_userspace_wg_transport_bytes_total", "t", []string{"tunnel", "direction"}, nil),
		wgKeepalivesReceivedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_keepalives_received_total", "t", []string{"tunnel"}, nil),
		wgTransportDropsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_transport_drops_total", "t", []string{"tunnel", "direction", "reason"}, nil),
		wgSendErrorsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_send_errors_total", "t", []string{"tunnel", "kind"}, nil),
		wgSessionConfirmed: prometheus.NewDesc(
			"xpf_userspace_wg_session_confirmed", "t", []string{"tunnel", "peer"}, nil),
		wgLastHandshakeTimeSeconds: prometheus.NewDesc(
			"xpf_userspace_wg_last_handshake_time_seconds", "t", []string{"tunnel"}, nil),
		wgRekeysInitiatedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_rekeys_initiated_total", "t", []string{"tunnel", "reason"}, nil),
		wgKeepalivesSentTotal: prometheus.NewDesc(
			"xpf_userspace_wg_keepalives_sent_total", "t", []string{"tunnel", "kind"}, nil),
		wgSessionsExpiredTotal: prometheus.NewDesc(
			"xpf_userspace_wg_sessions_expired_total", "t", []string{"tunnel"}, nil),
		wgHandshakeAttemptsAbortedTotal: prometheus.NewDesc(
			"xpf_userspace_wg_handshake_attempts_aborted_total", "t", []string{"tunnel"}, nil),
		wgEndpointResolutionsTotal: prometheus.NewDesc(
			"xpf_userspace_wg_endpoint_resolutions_total", "t", []string{"tunnel", "outcome"}, nil),
	}
	status := dpuserspace.ProcessStatus{
		// One peer (no session) so the per-peer session_confirmed gauge
		// (#1434) still emits exactly one series for the never-handshaked
		// tunnel.
		WgTunnels: []dpuserspace.WgTunnelStatus{{
			Tunnel: "wg1",
			Peers:  []dpuserspace.WgPeerStatus{{PeerPubkeyHex: "ab"}},
		}},
	}
	ch := make(chan prometheus.Metric, 256)
	c.emitWireguardTelemetry(ch, status)
	close(ch)
	count := 0
	for m := range ch {
		count++
		if descFQName(m.Desc().String()) == "xpf_userspace_wg_last_handshake_time_seconds" {
			t.Errorf("last-handshake gauge emitted for a never-handshaked tunnel")
		}
	}
	// 2 completions + 3 singles + 9 hs reasons (incl. replayed_init,
	// #4092) + 2 pkts + 2 bytes + 1 keepalive + 15 drop reasons (incl.
	// 2x expired, #1888) + 4 send kinds + 1 confirmed (per-peer, #1434;
	// one peer here) + 3 rekey reasons + 2 keepalive-sent kinds +
	// 1 sessions-expired + 1 attempts-aborted; +2 hs reasons #4094
	// (under_load_no_mac2 + cookie_reply_budget) + 3 cookie-reply events
	// #4094 (sent + mac2_ok [PR-A] + consumed [PR-B]) = 51;
	// + 4 endpoint-resolution outcomes (#7936) = 55;
	// + 1 unsteered-port decap drop reason (#9521) = 56.
	//
	// The four #7936 series are emitted for a zeroed tunnel ON PURPOSE, and
	// this count is where that decision is pinned. A tunnel whose peers are all
	// IP literals starts no resolver at all, so its counters are legitimately
	// zero — and suppressing the series would make "no resolver configured"
	// indistinguishable from "the exporter does not know about this tunnel",
	// which is the difference between a dashboard reading zero and a dashboard
	// reading nothing.
	if count != 56 {
		t.Errorf("emitted %d series for a zeroed tunnel, want 56 (zeros are real signals)", count)
	}
}

// descFQName extracts the fqName from prometheus.Desc.String(), which
// renders as `Desc{fqName: "name", help: ...}`.
func descFQName(s string) string {
	const pfx = `Desc{fqName: "`
	i := len(pfx)
	j := i
	for j < len(s) && s[j] != '"' {
		j++
	}
	if i >= len(s) {
		return s
	}
	return s[i:j]
}
