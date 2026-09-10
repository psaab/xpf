package format

import (
	"fmt"
	"strings"
	"time"

	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/wgkey"
)

// FormatWireguardStatus renders the #1865 per-WG-tunnel telemetry rows
// for `show security wireguard [detail]`. Shared by the local CLI
// (pkg/cli) and the gRPC text server (pkg/grpcapi) so both surfaces
// render identically — the FormatSystemBuffers pattern.
//
// `now` is passed explicitly (rather than read inside) so the
// handshake-age rendering is testable; callers pass time.Now().
//
// The summary view is the wg-show-shaped operator glance: identity,
// session state, latest handshake, transfer, and a drop TOTAL. The
// detail view adds the full per-reason drop tables — the one-glance
// diagnosis for the #1736 class of failures (silent sends, MTU
// blackholes, wrong-key peers).
func FormatWireguardStatus(status userspace.ProcessStatus, detail bool, now time.Time) string {
	if len(status.WgTunnels) == 0 {
		return "No WireGuard tunnels configured\n"
	}
	var b strings.Builder
	for i, t := range status.WgTunnels {
		if i > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "Tunnel: %s (endpoint id %d)\n", t.Tunnel, t.TunnelEndpointID)
		fmt.Fprintf(&b, "  Listen port:        %d\n", t.ListenPort)
		// #1434 multi-peer: one block per peer. Counters below are
		// tunnel-level (per-engine).
		if len(t.Peers) == 0 {
			fmt.Fprintf(&b, "  Peers:              (none configured)\n")
		}
		for pi, p := range t.Peers {
			if len(t.Peers) > 1 {
				fmt.Fprintf(&b, "  Peer %d:\n", pi+1)
			}
			fmt.Fprintf(&b, "  Peer public key:    %s\n", p.PeerPubkeyHex)
			endpoint := p.PeerEndpoint
			if endpoint == "" {
				endpoint = "(responder-only; learned at runtime)"
			}
			fmt.Fprintf(&b, "  Peer endpoint:      %s\n", endpoint)
			state := "no session"
			if p.SessionConfirmed {
				state = "session confirmed"
			} else if t.LastHandshakeUnixSecs > 0 {
				state = "handshake completed, unconfirmed"
			}
			fmt.Fprintf(&b, "  Session:            %s\n", state)
		}
		fmt.Fprintf(&b, "  Latest handshake:   %s\n",
			formatHandshakeAge(t.LastHandshakeUnixSecs, now))
		fmt.Fprintf(&b, "  Handshakes:         %d initiator, %d responder (initiations created %d, send errors %d)\n",
			t.HsCompletionsInitiator, t.HsResponsesCreated,
			t.HsInitiationsCreated, t.HsSendErrors)
		fmt.Fprintf(&b, "  Transfer:           %d pkts / %d bytes received, %d pkts / %d bytes sent (inner IP)\n",
			t.DecapPackets, t.DecapBytes, t.EncapPackets, t.EncapBytes)
		if !detail && t.DecapKeepalives > 0 {
			// Detail view prints the unconditional keepalive line at
			// the bottom; suppress the summary form there to avoid a
			// duplicate row.
			fmt.Fprintf(&b, "  Keepalives:         %d received\n", t.DecapKeepalives)
		}
		decapDrops := t.DecapDropsMalformedHeader + t.DecapDropsUnknownSession +
			t.DecapDropsCounterCeiling + t.DecapDropsCrypto + t.DecapDropsReplay +
			t.DecapDropsAllowedIPs + t.DecapDropsMalformedInner + t.DecapDropsBuffer +
			t.RxUnsteeredTransportDrops
		encapDrops := t.EncapDropsNoSession + t.EncapDropsUnconfirmed +
			t.EncapDropsRekeyRequired + t.EncapDropsOther + t.EncapMtuDrops
		hsDrops := t.HsRxDropsMac1Mismatch + t.HsRxDropsMalformed + t.HsRxDropsCrypto +
			t.HsRxDropsUnknownPeer + t.HsRxDropsStaleResponse + t.HsRxDropsIndexExhausted +
			t.HsRxDropsReplayedInit + t.HsRxCookieUnsupported + t.RxUnknownType
		ioErrors := t.HsSendErrors + t.TransportSendErrors + t.TunWriteErrors +
			t.TunRxDropsNoEndpoint
		fmt.Fprintf(&b, "  Drops:              %d receive, %d transmit, %d handshake, %d I/O errors\n",
			decapDrops, encapDrops, hsDrops, ioErrors)
		if !detail {
			continue
		}
		// #7936: endpoint resolution. Printed ONLY for a tunnel that actually
		// resolves — a tunnel of IP literals starts no resolver, and four zeros
		// under a heading would read as "resolution is failing" rather than
		// "there is nothing to resolve".
		if t.EndpointResolveOk+t.EndpointResolveFail+t.EndpointFamilyMismatch+
			t.EndpointChanged > 0 || t.EndpointLastError != "" {
			fmt.Fprintf(&b, "  Endpoint resolution: %d ok, %d failed, %d family-mismatch, %d changed\n",
				t.EndpointResolveOk, t.EndpointResolveFail, t.EndpointFamilyMismatch,
				t.EndpointChanged)
			if t.EndpointFamilyMismatch > 0 {
				// The count alone is not a diagnosis. This says what the
				// condition IS, because it is the one resolver outcome an
				// operator will otherwise read as "the peer just never
				// initiates" — the name resolves, so DNS looks healthy.
				b.WriteString("    family-mismatch: the name resolved, but to no address of " +
					"this interface's socket family — the peer cannot be reached from here\n")
			}
			if t.EndpointLastError != "" {
				fmt.Fprintf(&b, "    Last error:       %s\n", t.EndpointLastError)
			}
		}
		b.WriteString("  Receive drops by reason:\n")
		writeWgReasonRows(&b, []wgReasonRow{
			{"malformed-header", t.DecapDropsMalformedHeader},
			{"unknown-session", t.DecapDropsUnknownSession},
			{"counter-ceiling", t.DecapDropsCounterCeiling},
			{"decrypt-failed", t.DecapDropsCrypto},
			{"replay", t.DecapDropsReplay},
			{"allowed-ips-violation", t.DecapDropsAllowedIPs},
			{"malformed-inner", t.DecapDropsMalformedInner},
			{"buffer", t.DecapDropsBuffer},
			{"unsteered-port", t.RxUnsteeredTransportDrops},
		})
		b.WriteString("  Transmit drops by reason:\n")
		writeWgReasonRows(&b, []wgReasonRow{
			{"no-session", t.EncapDropsNoSession},
			{"unconfirmed-session", t.EncapDropsUnconfirmed},
			{"rekey-required", t.EncapDropsRekeyRequired},
			{"mtu-exceeded", t.EncapMtuDrops},
			{"other", t.EncapDropsOther},
		})
		b.WriteString("  Handshake drops by reason:\n")
		writeWgReasonRows(&b, []wgReasonRow{
			{"mac1-mismatch", t.HsRxDropsMac1Mismatch},
			{"malformed", t.HsRxDropsMalformed},
			{"crypto", t.HsRxDropsCrypto},
			{"unknown-peer", t.HsRxDropsUnknownPeer},
			{"stale-response", t.HsRxDropsStaleResponse},
			{"index-exhausted", t.HsRxDropsIndexExhausted},
			{"replayed-init", t.HsRxDropsReplayedInit},
			{"cookie-unsupported", t.HsRxCookieUnsupported},
			{"unknown-type", t.RxUnknownType},
		})
		b.WriteString("  I/O errors:\n")
		writeWgReasonRows(&b, []wgReasonRow{
			{"handshake-send", t.HsSendErrors},
			{"transport-send", t.TransportSendErrors},
			{"tun-write", t.TunWriteErrors},
			{"tun-read-no-endpoint", t.TunRxDropsNoEndpoint},
		})
		fmt.Fprintf(&b, "  Handshake activity: %d initiations created, %d build failures, %d requests armed\n",
			t.HsInitiationsCreated, t.HsInitiationBuildFailures, t.HsRequestsArmed)
		fmt.Fprintf(&b, "  Keepalives:         %d received\n", t.DecapKeepalives)
	}
	return b.String()
}

// FormatWireguardPublicKeys renders `show security wireguard
// public-key` (#1434 Increment 1): the LOCAL public key per configured
// WG tunnel, in the WireGuard-canonical base64 an operator pastes into
// the peer's `[Peer] PublicKey =`. The status wire carries the key as
// hex (local_pubkey_hex); this converts it to base64 for display. A
// tunnel whose helper has not yet surfaced a local key (older payload,
// or an engine that has not derived one) renders "(unavailable)" rather
// than being dropped.
//
// Shared by the local CLI (pkg/cli) and the gRPC text server
// (pkg/grpcapi) so both surfaces render identically — the
// FormatWireguardStatus pattern.
func FormatWireguardPublicKeys(status userspace.ProcessStatus) string {
	if len(status.WgTunnels) == 0 {
		return "No WireGuard tunnels configured\n"
	}
	var b strings.Builder
	for _, t := range status.WgTunnels {
		fmt.Fprintf(&b, "Tunnel: %s (endpoint id %d)\n", t.Tunnel, t.TunnelEndpointID)
		fmt.Fprintf(&b, "  Listen port:        %d\n", t.ListenPort)
		fmt.Fprintf(&b, "  Local public key:   %s\n", renderWgPublicKey(t.LocalPubkeyHex))
	}
	return b.String()
}

// renderWgPublicKey converts a hex WG public key to WireGuard-canonical
// base64 for operator display. An empty key (helper has not surfaced
// one) or a malformed hex value renders "(unavailable)" — the row is
// never dropped, so an operator always sees the tunnel exists.
func renderWgPublicKey(hexKey string) string {
	b64, err := wgkey.HexToBase64(hexKey)
	if err != nil || b64 == "" {
		return "(unavailable)"
	}
	return b64
}

type wgReasonRow struct {
	reason string
	count  uint64
}

func writeWgReasonRows(b *strings.Builder, rows []wgReasonRow) {
	for _, r := range rows {
		fmt.Fprintf(b, "    %-24s %d\n", r.reason, r.count)
	}
}

// formatHandshakeAge renders the last-handshake timestamp like wg
// show's "latest handshake" line. 0 means never (the in-band wire
// sentinel). A timestamp in the future (clock step between helper
// conversion and this render) clamps to "0 seconds ago" rather than
// going negative.
func formatHandshakeAge(unixSecs uint64, now time.Time) string {
	if unixSecs == 0 {
		return "never"
	}
	age := now.Unix() - int64(unixSecs)
	if age < 0 {
		age = 0
	}
	d := time.Duration(age) * time.Second
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d seconds ago", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm%ds ago", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%dm ago", int(d.Hours()), int(d.Minutes())%60)
	}
}
