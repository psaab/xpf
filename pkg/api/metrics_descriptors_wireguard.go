package api

import "github.com/prometheus/client_golang/prometheus"

func (c *xpfCollector) initWireGuardDescriptors() {
	// #1865: per-tunnel WireGuard telemetry. The tunnel label is
	// the tunnel interface NAME (stable across commits — #1873
	// positional ids renumber and are never a label). Counters
	// reset when a commit changes the tunnel's crypto identity
	// (engine rebuild); rate() handles the monotonic reset.
	c.wgHandshakesCompletedTotal = prometheus.NewDesc(
		"xpf_userspace_wg_handshakes_completed_total",
		"WireGuard handshake completions by role: initiator = a consumed response promoted our initiation; responder = we accepted an initiation and created (and installed the session for) the response (#1865).",
		[]string{"tunnel", "role"}, nil,
	)
	c.wgHandshakeInitiationsCreatedTotal = prometheus.NewDesc(
		"xpf_userspace_wg_handshake_initiations_created_total",
		"WireGuard handshake initiations BUILT (not necessarily sent — a failing socket send counts in xpf_userspace_wg_send_errors_total{kind=\"handshake\"}; created rising with completions flat and send errors rising is the silent-send fingerprint from #1736) (#1865).",
		[]string{"tunnel"}, nil,
	)
	c.wgHandshakeInitiationBuildFailuresTotal = prometheus.NewDesc(
		"xpf_userspace_wg_handshake_initiation_build_failures_total",
		"WireGuard initiation build failures (engine could not construct msg1 — unknown peer, index exhaustion, crypto/internal error; all folded) (#1865).",
		[]string{"tunnel"}, nil,
	)
	c.wgHandshakeRxDropsTotal = prometheus.NewDesc(
		"xpf_userspace_wg_handshake_rx_drops_total",
		"Inbound WireGuard handshake-path datagrams dropped, by reason (mac1_mismatch | malformed | crypto | unknown_peer | stale_response | index_exhausted | cookie_unsupported | under_load_no_mac2 | cookie_reply_budget | unknown_type). mac1_mismatch is the wrong-key-peer signature; under_load_no_mac2 is the #4094 responder under-load DoS mitigation refusing a forged/unprimed initiation and issuing a cookie challenge; cookie_reply_budget is that same path when the per-window cookie-reply budget clamps (#1865, #4094).",
		[]string{"tunnel", "reason"}, nil,
	)
	c.wgCookieRepliesTotal = prometheus.NewDesc(
		"xpf_userspace_wg_cookie_replies_total",
		"WireGuard cookie mechanism (#4094) by event: sent = type-3 CookieReply challenges the RESPONDER emitted under load to valid-MAC1 initiations lacking a valid MAC2; mac2_ok = under-load initiations that carried a valid MAC2 (a primed peer) and were allowed through to the Noise handshake; consumed = cookie-replies the INITIATOR decrypted and stored (PR-B) to arm a valid MAC2 on its next initiation.",
		[]string{"tunnel", "event"}, nil,
	)
	c.wgHandshakeRequestsArmedTotal = prometheus.NewDesc(
		"xpf_userspace_wg_handshake_requests_armed_total",
		"Accepted NoSession worker→control handshake-request edges (rate-limited to 1/s) — ties an encap-drop burst to the re-initiation it triggered (#1865).",
		[]string{"tunnel"}, nil,
	)
	c.wgTransportPacketsTotal = prometheus.NewDesc(
		"xpf_userspace_wg_transport_packets_total",
		"WireGuard transport packets successfully processed, by direction (encap = egress encrypt, decap = ingress decrypt+deliver) (#1865).",
		[]string{"tunnel", "direction"}, nil,
	)
	c.wgTransportBytesTotal = prometheus.NewDesc(
		"xpf_userspace_wg_transport_bytes_total",
		"WireGuard transport INNER-IP bytes by direction (logical tunnel payload bytes, excluding WG+outer overhead — will not match a kernel peer's `wg show` transfer numbers) (#1865).",
		[]string{"tunnel", "direction"}, nil,
	)
	c.wgKeepalivesReceivedTotal = prometheus.NewDesc(
		"xpf_userspace_wg_keepalives_received_total",
		"Authenticated zero-length WireGuard transport records (peer persistent keepalives). Classified separately so keepalive traffic never inflates the malformed_inner drop reason (#1865).",
		[]string{"tunnel"}, nil,
	)
	c.wgTransportDropsTotal = prometheus.NewDesc(
		"xpf_userspace_wg_transport_drops_total",
		"WireGuard transport drops by direction and reason. decap: malformed_header | unknown_session | counter_ceiling | crypto | replay | allowed_ips | malformed_inner | buffer | unsteered_port | degraded_transit | expired. encap: no_session | unconfirmed | rekey_required | mtu | other | expired. `unsteered_port` is a steered-set miss refused by #9521; `degraded_transit` is authenticated transit refused on covered degraded ingress (#9594) and shim-uncovered ingress (#10527), including the steady-state uncovered case. `expired` is the #1888 per-use REJECT_AFTER_TIME refusal (drop-only on decap; arms the rekey edge on encap). `unconfirmed` is the responder key-confirmation window (transient at rekey — distinct from no_session so operators do not tcpdump a blip); `mtu` is the exact pad-aware guard at BOTH egress sites (the #1736 v4-mapped blackhole class) (#1865).",
		[]string{"tunnel", "direction", "reason"}, nil,
	)
	c.wgSendErrorsTotal = prometheus.NewDesc(
		"xpf_userspace_wg_send_errors_total",
		"WireGuard I/O errors by kind: handshake = msg1/msg2 socket send failed (the #1736 EINVAL class); transport = encap'd datagram send failed; tun_write = decap'd inner delivery to the wgN TUN failed; tun_rx_no_endpoint = inner packets drained+dropped while a responder-only peer has no learned endpoint (#1865).",
		[]string{"tunnel", "kind"}, nil,
	)
	c.wgSessionConfirmed = prometheus.NewDesc(
		"xpf_userspace_wg_session_confirmed",
		"Whether a tunnel peer currently holds a CONFIRMED (egress-usable) transport session (1/0 gauge). Labeled by tunnel AND peer public key (#1434 multi-peer). The liveness signal — a responder-side handshake completion alone does not imply the peer ever received our response (#1865).",
		[]string{"tunnel", "peer"}, nil,
	)
	c.wgLastHandshakeTimeSeconds = prometheus.NewDesc(
		"xpf_userspace_wg_last_handshake_time_seconds",
		"Wall-clock epoch seconds of the most recent WireGuard handshake completion (either role). Absent until the first handshake completes; compute age as time() - this (#1865).",
		[]string{"tunnel"}, nil,
	)
	c.wgRekeysInitiatedTotal = prometheus.NewDesc(
		"xpf_userspace_wg_rekeys_initiated_total",
		"Timer-driven WireGuard handshake initiations by reason: age = REKEY_AFTER_TIME/receive-horizon/expiry on the live session; dead_peer = 15s no-reply reinit (sent data, heard nothing); keepalive_no_session = persistent keepalive due with no usable session (#1888 S5).",
		[]string{"tunnel", "reason"}, nil,
	)
	c.wgKeepalivesSentTotal = prometheus.NewDesc(
		"xpf_userspace_wg_keepalives_sent_total",
		"WireGuard keepalives SENT by kind: passive = 10s KEEPALIVE_TIMEOUT replies to inbound data (incl. the post-handshake key-confirmation keepalive); persistent = operator-configured persistent-keepalive interval (#1888 S5).",
		[]string{"tunnel", "kind"}, nil,
	)
	c.wgSessionsExpiredTotal = prometheus.NewDesc(
		"xpf_userspace_wg_sessions_expired_total",
		"WireGuard transport sessions torn down at REJECT_AFTER_TIME (180s) by the control thread's expiry pass. Per-use refusals are the expired reason under xpf_userspace_wg_transport_drops_total (#1888 S5).",
		[]string{"tunnel"}, nil,
	)
	c.wgHandshakeAttemptsAbortedTotal = prometheus.NewDesc(
		"xpf_userspace_wg_handshake_attempts_aborted_total",
		"Pending WireGuard handshake reservations released by the REKEY_ATTEMPT_TIME (90s) give-up — a stale msg2 after this cannot complete the abandoned handshake (#1888 S5).",
		[]string{"tunnel"}, nil,
	)
	// #7936: endpoint-resolver telemetry. ONE metric with an `outcome` label
	// rather than four metrics, because the four counts are alternatives of the
	// same event — a resolution attempt ended one of these ways — and an
	// operator's question is which outcome dominates. Four separate series
	// would make that a join.
	c.wgEndpointResolutionsTotal = prometheus.NewDesc(
		"xpf_userspace_wg_endpoint_resolutions_total",
		"WireGuard peer-endpoint DNS resolutions by outcome (#7158, #7936). `family_mismatch` is the one worth alerting on: the name resolved but to no address of the family this interface's single UDP socket can send from, which otherwise presents as a peer that never initiates. `changed` counts actual endpoint moves, not lookups.",
		[]string{"tunnel", "outcome"}, nil,
	)
}
