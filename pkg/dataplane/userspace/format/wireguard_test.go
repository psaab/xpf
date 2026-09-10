package format

import (
	"regexp"
	"strings"
	"testing"
	"time"

	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

func wgFmtFixture() userspace.ProcessStatus {
	return userspace.ProcessStatus{
		WgTunnels: []userspace.WgTunnelStatus{{
			Tunnel:           "wg0",
			TunnelEndpointID: 3,
			ListenPort:       51820,
			LocalPubkeyHex:   strings.Repeat("cd", 32),
			Peers: []userspace.WgPeerStatus{{
				PeerPubkeyHex:    strings.Repeat("ab", 32),
				PeerEndpoint:     "192.0.2.10:51820",
				SessionConfirmed: true,
			}},
			LastHandshakeUnixSecs:  1_770_000_000,
			HsCompletionsInitiator: 2,
			HsResponsesCreated:     1,
			HsInitiationsCreated:   4,
			HsSendErrors:           1,
			DecapPackets:           100,
			DecapBytes:             5000,
			EncapPackets:           90,
			EncapBytes:             4500,
			DecapKeepalives:        7,
			DecapDropsReplay:       2,
			EncapMtuDrops:          3,
			HsRxDropsMac1Mismatch:  5,
		}},
	}
}

func TestFormatWireguardStatusSummary(t *testing.T) {
	now := time.Unix(1_770_000_090, 0) // 90s after the handshake
	out := FormatWireguardStatus(wgFmtFixture(), false, now)
	for _, want := range []string{
		"Tunnel: wg0 (endpoint id 3)",
		"Listen port:        51820",
		"Peer public key:    " + strings.Repeat("ab", 32),
		"Peer endpoint:      192.0.2.10:51820",
		"Session:            session confirmed",
		"Latest handshake:   1m30s ago",
		"Handshakes:         2 initiator, 1 responder (initiations created 4, send errors 1)",
		"Transfer:           100 pkts / 5000 bytes received, 90 pkts / 4500 bytes sent (inner IP)",
		"Keepalives:         7 received",
		"Drops:              2 receive, 3 transmit, 5 handshake, 1 I/O errors",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("summary missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "by reason") {
		t.Errorf("summary must not include the detail reason tables:\n%s", out)
	}
}

func TestFormatWireguardStatusDetailReasonTables(t *testing.T) {
	now := time.Unix(1_770_000_090, 0)
	out := FormatWireguardStatus(wgFmtFixture(), true, now)
	for _, want := range []string{
		"Receive drops by reason:",
		"replay                   2",
		"Transmit drops by reason:",
		"mtu-exceeded             3",
		"Handshake drops by reason:",
		"mac1-mismatch            5",
		"I/O errors:",
		"handshake-send           1",
		"Handshake activity: 4 initiations created, 0 build failures, 0 requests armed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detail missing %q in:\n%s", want, out)
		}
	}
}

func TestFormatWireguardStatusNeverAndEmpty(t *testing.T) {
	out := FormatWireguardStatus(userspace.ProcessStatus{}, false, time.Now())
	if !strings.Contains(out, "No WireGuard tunnels configured") {
		t.Errorf("empty status rendering = %q", out)
	}
	// A tunnel with one peer that has no endpoint / no session: renders
	// "never", "no session", and the responder-only placeholder.
	status := userspace.ProcessStatus{WgTunnels: []userspace.WgTunnelStatus{{
		Tunnel: "wg1",
		Peers:  []userspace.WgPeerStatus{{PeerPubkeyHex: strings.Repeat("ab", 32)}},
	}}}
	out = FormatWireguardStatus(status, false, time.Now())
	if !strings.Contains(out, "Latest handshake:   never") {
		t.Errorf("never-handshaked tunnel must render 'never':\n%s", out)
	}
	if !strings.Contains(out, "Session:            no session") {
		t.Errorf("no-session state missing:\n%s", out)
	}
	if !strings.Contains(out, "(responder-only; learned at runtime)") {
		t.Errorf("empty endpoint placeholder missing:\n%s", out)
	}
	// A tunnel with NO peers configured renders the explicit marker.
	noPeers := userspace.ProcessStatus{WgTunnels: []userspace.WgTunnelStatus{{Tunnel: "wg2"}}}
	out = FormatWireguardStatus(noPeers, false, time.Now())
	if !strings.Contains(out, "Peers:              (none configured)") {
		t.Errorf("no-peer tunnel must render the (none configured) marker:\n%s", out)
	}
}

// #1434 Increment 1: `show security wireguard public-key` renders the
// LOCAL public key per tunnel in WireGuard-canonical base64. The wire
// carries it as hex; the formatter must convert to base64 (the form a
// peer pastes). The expected base64 is the canonical encoding of the
// cd-ladder hex key — a tautology-proof fixed value.
func TestFormatWireguardPublicKeys(t *testing.T) {
	// base64.StdEncoding of bytes.fromhex("cd"*32).
	const wantB64 = "zc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc0="
	out := FormatWireguardPublicKeys(wgFmtFixture())
	for _, want := range []string{
		"Tunnel: wg0 (endpoint id 3)",
		"Listen port:        51820",
		"Local public key:   " + wantB64,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("public-key view missing %q in:\n%s", want, out)
		}
	}
	// It must NOT render the hex form — base64 is the operator surface.
	if strings.Contains(out, strings.Repeat("cd", 32)) {
		t.Errorf("public-key view must render base64, not hex:\n%s", out)
	}
}

// No tunnels → the same placeholder as the status view.
func TestFormatWireguardPublicKeysEmpty(t *testing.T) {
	out := FormatWireguardPublicKeys(userspace.ProcessStatus{})
	if !strings.Contains(out, "No WireGuard tunnels configured") {
		t.Errorf("empty public-key rendering = %q", out)
	}
}

// A tunnel whose helper has not surfaced a local key (empty hex) renders
// "(unavailable)" rather than an empty line or a panic.
func TestFormatWireguardPublicKeysUnavailable(t *testing.T) {
	status := userspace.ProcessStatus{
		WgTunnels: []userspace.WgTunnelStatus{{Tunnel: "wg1", LocalPubkeyHex: ""}},
	}
	out := FormatWireguardPublicKeys(status)
	if !strings.Contains(out, "Local public key:   (unavailable)") {
		t.Errorf("missing-key tunnel must render (unavailable):\n%s", out)
	}
}

// A future timestamp (clock step between the helper's conversion and
// this render) clamps to "0 seconds ago", never negative.
func TestFormatHandshakeAgeClamps(t *testing.T) {
	if got := formatHandshakeAge(2_000_000_000, time.Unix(1_900_000_000, 0)); got != "0 seconds ago" {
		t.Errorf("future stamp = %q, want clamp to 0 seconds ago", got)
	}
	if got := formatHandshakeAge(0, time.Now()); got != "never" {
		t.Errorf("zero stamp = %q, want never", got)
	}
}

// #7936: the endpoint-resolver line, and the three things that make it a
// diagnosis rather than four numbers.
//
// `family_mismatch` is the outcome this whole change exists for: the name
// resolves, so DNS looks healthy, and the peer simply never initiates — which
// is indistinguishable from a dozen other causes unless something says what the
// condition actually is.
func TestWireguardDetailRendersEndpointResolution7936(t *testing.T) {
	status := userspace.ProcessStatus{WgTunnels: []userspace.WgTunnelStatus{{
		Tunnel:                 "wg0",
		EndpointResolveOk:      9,
		EndpointFamilyMismatch: 3,
		EndpointLastError:      "vpn.example.com: no AAAA for a v6 socket",
	}}}
	out := FormatWireguardStatus(status, true, time.Unix(1_770_000_000, 0))

	for _, want := range []string{
		"Endpoint resolution: 9 ok, 0 failed, 3 family-mismatch, 0 changed",
		"the name resolved, but to no address of",
		"vpn.example.com: no AAAA for a v6 socket",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detail view is missing %q — the count alone does not tell an operator "+
				"WHICH name resolved to the wrong family, which is the diagnosis:\n%s", want, out)
		}
	}
}

// The complement, and the reason the block is conditional: a tunnel of IP
// literals starts no resolver at all, so four zeros under a heading would read
// as "resolution is failing" when there is nothing to resolve.
func TestWireguardDetailOmitsEndpointResolutionWhenNoResolver7936(t *testing.T) {
	status := userspace.ProcessStatus{WgTunnels: []userspace.WgTunnelStatus{{Tunnel: "wg0"}}}
	out := FormatWireguardStatus(status, true, time.Unix(1_770_000_000, 0))
	if strings.Contains(out, "Endpoint resolution") {
		t.Errorf("a literal-endpoint tunnel runs no resolver; printing zeros would read as "+
			"a failure:\n%s", out)
	}
	// And the non-detail view never carries it at all.
	brief := FormatWireguardStatus(userspace.ProcessStatus{WgTunnels: []userspace.WgTunnelStatus{{
		Tunnel: "wg0", EndpointFamilyMismatch: 3,
	}}}, false, time.Unix(1_770_000_000, 0))
	if strings.Contains(brief, "Endpoint resolution") {
		t.Errorf("the one-glance view must stay one-glance:\n%s", brief)
	}
}

// #9521: an unsteered listen port's kernel-path transport records are dropped
// by the helper instead of being written to the wgN TUN, and this is the
// operator's runtime view of that. The drops must be counted in the summary's
// receive total AND named in the detail table: a drop that lands in neither
// reads as a tunnel that simply receives nothing.
func TestFormatWireguardUnsteeredPortDrops9521(t *testing.T) {
	now := time.Unix(1_770_000_090, 0)
	st := wgFmtFixture()
	st.WgTunnels[0].RxUnsteeredTransportDrops = 6
	if out := FormatWireguardStatus(st, false, now); !strings.Contains(out, "Drops:              8 receive,") {
		t.Errorf("summary receive-drop total must include the 6 unsteered-port drops (2 replay + 6):\n%s", out)
	}
	if out := FormatWireguardStatus(st, true, now); !strings.Contains(out, "unsteered-port           6") {
		t.Errorf("detail reason table must name the unsteered-port drops:\n%s", out)
	}
}

// #9594: the steered port's degraded-window TRANSIT drops (records that reached
// its control thread through the kernel on an ingress the XDP shim adjudicates)
// are the operator's only runtime evidence that a failover window refused
// tunnel transit instead of forwarding it. Same rule as #9521: counted in the
// summary's receive total AND named in the detail table.
func TestFormatWireguardDegradedTransitDrops9594(t *testing.T) {
	now := time.Unix(1_770_000_090, 0)
	st := wgFmtFixture()
	st.WgTunnels[0].RxDegradedTransitDrops = 7
	if out := FormatWireguardStatus(st, false, now); !strings.Contains(out, "Drops:              9 receive,") {
		t.Errorf("summary receive-drop total must include the 7 degraded-transit drops (2 replay + 7):\n%s", out)
	}
	out := FormatWireguardStatus(st, true, now)
	if !regexp.MustCompile(`(?m)^\s*degraded-transit\s+7\s*$`).MatchString(out) {
		t.Errorf("detail reason table must name the degraded-transit drops:\n%s", out)
	}
}
