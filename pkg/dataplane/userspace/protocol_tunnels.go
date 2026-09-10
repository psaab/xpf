package userspace

type TunnelEndpointSnapshot struct {
	ID              uint16 `json:"id,omitempty"`
	Interface       string `json:"interface,omitempty"`
	LinuxName       string `json:"linux_name,omitempty"`
	Ifindex         int    `json:"ifindex,omitempty"`
	Zone            string `json:"zone,omitempty"`
	RedundancyGroup int    `json:"redundancy_group,omitempty"`
	MTU             int    `json:"mtu,omitempty"`
	Mode            string `json:"mode,omitempty"`
	OuterFamily     string `json:"outer_family,omitempty"`
	Source          string `json:"source,omitempty"`
	Destination     string `json:"destination,omitempty"`
	Key             uint32 `json:"key,omitempty"`
	TTL             int    `json:"ttl,omitempty"`
	TransportTable  string `json:"transport_table,omitempty"`

	// WireGuard clean-room termination (see docs/pr/wireguard-clean/plan.md).
	// All fields are wire-compatible additions: a daemon built before the
	// plan landed will simply omit them, and the Rust side defaults each
	// field via #[serde(default)]. The control plane only populates them
	// when Mode == "wireguard".
	//
	// WgListenPort is the local UDP port we listen on for inbound WG
	// transport. Listen-port selection happens at the integration
	// layer's UDP-socket dispatch (one layer above the engine); the
	// engine itself demuxes by `receiver_index` alone via the
	// `sessions_by_local_index` map (see userspace-dp
	// afxdp/wg/engine.rs:275). The receiver index is chosen by the
	// local side at handshake time, so it identifies the session
	// unambiguously without a (port, index) tuple match.
	WgListenPort uint16 `json:"wg_listen_port,omitempty"`
	// WgLocalPrivkeyHex is the local static X25519 private key as
	// hex (64 chars). Control-plane-internal; never logged.
	WgLocalPrivkeyHex string `json:"wg_local_privkey_hex,omitempty"`
	// WgPeers is the ordered per-peer set (#1434 multi-peer),
	// sorted by pubkey at the snapshot-builder boundary for HA
	// determinism. Replaces the scalar Wg{PeerPubkeyHex,AllowedIPs,
	// Endpoint,KeepaliveSecs} fields. The Rust side feeds the engine
	// peer table from this slice; RX/decap demuxes by receiver_index
	// across all peers, and TX/encap selects the peer by inner-dst
	// AllowedIPs LPM (#1434 B1b).
	WgPeers []TunnelWgPeerWire `json:"wg_peers,omitempty"`
}

// TunnelWgPeerWire is one WireGuard peer on the Go→Rust wire (#1434).
// Mirrors the Rust TunnelWgPeerSnapshot (snapshot.rs). Keep json tags
// identical on BOTH sides (feedback_wire_protocol_both_sides).
type TunnelWgPeerWire struct {
	// WgPeerPubkeyHex is the peer's static X25519 public key as hex.
	WgPeerPubkeyHex string `json:"wg_peer_pubkey_hex,omitempty"`
	// WgAllowedIPs is the peer's AllowedIPs as CIDR strings.
	WgAllowedIPs []string `json:"wg_allowed_ips,omitempty"`
	// WgEndpoint is the optional peer endpoint (IP:port). Empty for
	// responder-only.
	WgEndpoint string `json:"wg_endpoint,omitempty"`
	// WgKeepaliveSecs is the optional persistent-keepalive interval.
	// 0 means disabled.
	WgKeepaliveSecs uint16 `json:"wg_keepalive_secs,omitempty"`
	// WgPresharedKeyHex is the optional per-peer preshared key as hex
	// (#1434 B2). Empty = zero PSK. SECRET: like wg_local_privkey_hex
	// it is delivered on the control socket (the engine needs it) but
	// MUST never reach an on-disk state snapshot or a log — the Rust
	// side marks the matching field skip_serializing.
	WgPresharedKeyHex string `json:"wg_preshared_key_hex,omitempty"`
}

// WgPeerStatus mirrors the Rust WgPeerStatus in
// userspace-dp/src/protocol/control.rs (#1434 multi-peer) — keep json
// tags identical on BOTH sides.
type WgPeerStatus struct {
	// PeerPubkeyHex is the peer static public key, 64-char lowercase hex
	// (same rendering as the config-side wg_peer_pubkey_hex; note
	// `wg show` renders base64 — xpf surfaces are uniformly hex).
	PeerPubkeyHex string `json:"peer_pubkey_hex,omitempty"`
	// PeerEndpoint is the configured-or-learned endpoint (empty for a
	// responder-only peer with no learned endpoint yet).
	PeerEndpoint string `json:"peer_endpoint,omitempty"`
	// SessionConfirmed is whether this peer holds a confirmed
	// (egress-usable) transport session.
	SessionConfirmed bool `json:"session_confirmed,omitempty"`
}

// WgTunnelStatus mirrors the Rust WgTunnelStatus in
// userspace-dp/src/protocol/control.rs — keep json tags identical on
// BOTH sides (feedback_wire_protocol_both_sides). Counter semantics
// and the reset rules live in userspace-dp/src/afxdp/wg/counters.rs;
// the Prometheus emitters are in pkg/api/metrics_userspace.go.
type WgTunnelStatus struct {
	// Tunnel is the interface name (e.g. "wg0") — the PRIMARY key and
	// the only Prometheus label. Helper falls back to
	// "wg-endpoint-<id>" when the ifindex has no resolved name.
	Tunnel           string `json:"tunnel,omitempty"`
	TunnelEndpointID uint16 `json:"tunnel_endpoint_id,omitempty"`
	ListenPort       uint16 `json:"listen_port,omitempty"`
	// LocalPubkeyHex is OUR local static public key, 64-char lowercase
	// hex (#1434 Increment 1) — the key an operator hands to the peer.
	// Derived once by the helper from the local private key at engine
	// construction; the snapshot redacts the private key, so this is the
	// only surface for it. Travels as a hex STRING (not []byte, to dodge
	// the Go↔Rust base64 wire trap, MEMORY #1961); `show security
	// wireguard public-key` re-renders it as WireGuard-canonical base64.
	// omitempty keeps a pre-#1434 helper payload (field absent) decoding
	// to "".
	LocalPubkeyHex string `json:"local_pubkey_hex,omitempty"`
	// Peers carries the per-peer rows (#1434 multi-peer): pubkey,
	// endpoint, and confirmed-session per configured peer. Replaces the
	// scalar PeerPubkeyHex/PeerEndpoint/SessionConfirmed. The counters
	// below remain tunnel-level (per-engine).
	Peers []WgPeerStatus `json:"peers,omitempty"`
	// LastHandshakeUnixSecs is wall-clock epoch seconds of the most
	// recent handshake completion (either role); 0 = never (epoch 0 is
	// unreachable, so the in-band sentinel is unambiguous).
	LastHandshakeUnixSecs uint64 `json:"last_handshake_unix_secs,omitempty"`

	HsInitiationsCreated      uint64 `json:"hs_initiations_created,omitempty"`
	HsInitiationBuildFailures uint64 `json:"hs_initiation_build_failures,omitempty"`
	HsResponsesCreated        uint64 `json:"hs_responses_created,omitempty"`
	HsCompletionsInitiator    uint64 `json:"hs_completions_initiator,omitempty"`
	HsRxDropsMac1Mismatch     uint64 `json:"hs_rx_drops_mac1_mismatch,omitempty"`
	HsRxDropsMalformed        uint64 `json:"hs_rx_drops_malformed,omitempty"`
	HsRxDropsCrypto           uint64 `json:"hs_rx_drops_crypto,omitempty"`
	HsRxDropsUnknownPeer      uint64 `json:"hs_rx_drops_unknown_peer,omitempty"`
	HsRxDropsStaleResponse    uint64 `json:"hs_rx_drops_stale_response,omitempty"`
	HsRxDropsIndexExhausted   uint64 `json:"hs_rx_drops_index_exhausted,omitempty"`
	// #4092 responder handshake anti-replay rejects: a type-1
	// initiation whose TAI64N was <= the greatest already accepted from
	// that peer. Distinct from the transport DecapDropsReplay window.
	HsRxDropsReplayedInit uint64 `json:"hs_rx_drops_replayed_init,omitempty"`
	HsRxCookieUnsupported uint64 `json:"hs_rx_cookie_unsupported,omitempty"`
	// #4094 PR-B initiator-side cookie-replies successfully consumed
	// (decrypted + stored, arming a valid MAC2 on the next initiation).
	HsRxCookieConsumed uint64 `json:"hs_rx_cookie_consumed,omitempty"`
	// #4094 PR-A responder cookie-reply / MAC2 under-load DoS mitigation:
	// cookie replies emitted, under-load initiations dropped for a
	// missing/bad MAC2 (challenged instead of handshaked), under-load
	// initiations that carried a valid MAC2 and proceeded, and cookie
	// replies suppressed by the per-window emission budget.
	HsCookieRepliesSent      uint64 `json:"hs_cookie_replies_sent,omitempty"`
	HsRxUnderLoadNoMac2      uint64 `json:"hs_rx_under_load_no_mac2,omitempty"`
	HsRxUnderLoadMac2Ok      uint64 `json:"hs_rx_under_load_mac2_ok,omitempty"`
	HsCookieReplyBudgetDrops uint64 `json:"hs_cookie_reply_budget_drops,omitempty"`
	RxUnknownType            uint64 `json:"rx_unknown_type,omitempty"`
	HsSendErrors             uint64 `json:"hs_send_errors,omitempty"`
	HsRequestsArmed          uint64 `json:"hs_requests_armed,omitempty"`

	DecapPackets              uint64 `json:"decap_packets,omitempty"`
	DecapBytes                uint64 `json:"decap_bytes,omitempty"`
	DecapKeepalives           uint64 `json:"decap_keepalives,omitempty"`
	DecapDropsMalformedHeader uint64 `json:"decap_drops_malformed_header,omitempty"`
	DecapDropsUnknownSession  uint64 `json:"decap_drops_unknown_session,omitempty"`
	DecapDropsCounterCeiling  uint64 `json:"decap_drops_counter_ceiling,omitempty"`
	DecapDropsCrypto          uint64 `json:"decap_drops_crypto,omitempty"`
	DecapDropsReplay          uint64 `json:"decap_drops_replay,omitempty"`
	DecapDropsAllowedIPs      uint64 `json:"decap_drops_allowed_ips,omitempty"`
	DecapDropsMalformedInner  uint64 `json:"decap_drops_malformed_inner,omitempty"`
	DecapDropsBuffer          uint64 `json:"decap_drops_buffer,omitempty"`
	// #9521: transport records that reached an UNSTEERED listen port's socket
	// through the kernel and were dropped instead of being written to the wgN
	// TUN, where the kernel would have forwarded them with no zone policy.
	RxUnsteeredTransportDrops uint64 `json:"rx_unsteered_transport_drops,omitempty"`
	// #9594: transport records for the STEERED listen port that reached its
	// control thread through the kernel on an ingress the XDP shim adjudicates
	// (only while the dataplane is degraded) and carried TRANSIT, so they were
	// dropped instead of being forwarded by the kernel with no zone policy.
	RxDegradedTransitDrops uint64 `json:"rx_degraded_transit_drops,omitempty"`

	EncapPackets            uint64 `json:"encap_packets,omitempty"`
	EncapBytes              uint64 `json:"encap_bytes,omitempty"`
	EncapDropsNoSession     uint64 `json:"encap_drops_no_session,omitempty"`
	EncapDropsUnconfirmed   uint64 `json:"encap_drops_unconfirmed,omitempty"`
	EncapDropsRekeyRequired uint64 `json:"encap_drops_rekey_required,omitempty"`
	EncapDropsOther         uint64 `json:"encap_drops_other,omitempty"`
	EncapMtuDrops           uint64 `json:"encap_mtu_drops,omitempty"`
	TransportSendErrors     uint64 `json:"transport_send_errors,omitempty"`
	TunWriteErrors          uint64 `json:"tun_write_errors,omitempty"`
	TunRxDropsNoEndpoint    uint64 `json:"tun_rx_drops_no_endpoint,omitempty"`

	// #1888 S5 timer telemetry (wire-additive; zero on pre-S5 helpers).
	EncapDropsExpired                 uint64 `json:"encap_drops_expired,omitempty"`
	DecapDropsExpired                 uint64 `json:"decap_drops_expired,omitempty"`
	SessionsExpired                   uint64 `json:"sessions_expired,omitempty"`
	RekeysInitiatedAge                uint64 `json:"rekeys_initiated_age,omitempty"`
	RekeysInitiatedDeadPeer           uint64 `json:"rekeys_initiated_dead_peer,omitempty"`
	RekeysInitiatedKeepaliveNoSession uint64 `json:"rekeys_initiated_keepalive_no_session,omitempty"`
	KeepalivesTxPassive               uint64 `json:"keepalives_tx_passive,omitempty"`
	KeepalivesTxPersistent            uint64 `json:"keepalives_tx_persistent,omitempty"`
	PendingAbortedAttemptWindow       uint64 `json:"pending_aborted_attempt_window,omitempty"`

	// #7936: endpoint-resolver telemetry (#7158's counters, now on the wire).
	//
	// `omitempty` matches every other field here and is what makes the change
	// skew-tolerant in BOTH directions: an old helper that never emits these
	// decodes to zero, and an old Go binary that never sets them emits nothing
	// for a new helper to misread.
	EndpointResolveOk   uint64 `json:"endpoint_resolve_ok,omitempty"`
	EndpointResolveFail uint64 `json:"endpoint_resolve_fail,omitempty"`
	// The name resolved but to no address of the family this interface's UDP
	// socket can send from. The counter this row exists for: it is a
	// configuration error that otherwise looks like a peer that never
	// initiates.
	EndpointFamilyMismatch uint64 `json:"endpoint_family_mismatch,omitempty"`
	EndpointChanged        uint64 `json:"endpoint_changed,omitempty"`
	// Most recent resolver failure text. No Prometheus home — an unbounded
	// label would be worse than useless — so it is rendered on the
	// `show security wireguard detail` line, where the count alone would not
	// tell an operator WHICH name resolved to the wrong family.
	EndpointLastError string `json:"endpoint_last_error,omitempty"`
}
