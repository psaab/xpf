package config

import (
	"bufio"
	"os"
	"strings"
	"testing"
)

// wgEndpointShapeCases reads the cross-language agreement fixture. Both this
// test and the Rust hydrate test in
// userspace-dp/src/afxdp/forwarding_build/tunnels.rs read the SAME file, so the
// two implementations are asserted to agree rather than each pinned to its own
// literal table that can drift.
func wgEndpointShapeCases(t *testing.T) map[string]string {
	t.Helper()
	const path = "../../test/fixtures/wg-endpoint-shape.txt"
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v (the shared #7158 agreement fixture must exist; "+
			"without it this test silently checks nothing)", path, err)
	}
	defer f.Close()

	cases := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			t.Fatalf("malformed fixture line %q (want <endpoint>\\t<verdict>)", line)
		}
		cases[parts[0]] = parts[1]
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	// Non-vacuity: an empty or comment-only fixture would make every assertion
	// below pass by never running.
	if len(cases) < 20 {
		t.Fatalf("fixture yielded only %d cases; it is supposed to cover "+
			"literals, hostnames, port rules and malformed hosts", len(cases))
	}
	return cases
}

// TestWireguardEndpointShapeMatchesTheSharedFixture_7158 pins the commit-side
// half of the agreement.
//
// #7158 relaxed the IP-literal requirement so a DDNS peer is authorable. The
// risk that relaxation introduces is not that a hostname is accepted — that is
// the feature — but that the two sides disagree about WHICH strings are
// hostnames. An endpoint Go accepts and Rust drops commits clean and then
// silently loses the peer.
func TestWireguardEndpointShapeMatchesTheSharedFixture_7158(t *testing.T) {
	for endpoint, want := range wgEndpointShapeCases(t) {
		t.Run(endpoint, func(t *testing.T) {
			fam, err := endpointFamily(endpoint)
			switch want {
			case "reject":
				if err == nil {
					t.Fatalf("endpointFamily(%q) accepted an endpoint the shared "+
						"fixture marks reject; the Rust hydrate drops it, so this "+
						"config would commit clean and lose the peer", endpoint)
				}
			case "v4", "v6":
				if err != nil {
					t.Fatalf("endpointFamily(%q) rejected an IP literal: %v", endpoint, err)
				}
				if fam == nil {
					t.Fatalf("endpointFamily(%q) returned an unknown family for an IP "+
						"literal; a literal MUST constrain the mixed-family gate", endpoint)
				}
				if got := map[bool]string{true: "v6", false: "v4"}[*fam]; got != want {
					t.Fatalf("endpointFamily(%q) = %s, want %s", endpoint, got, want)
				}
			case "hostname":
				if err != nil {
					t.Fatalf("endpointFamily(%q) rejected a DNS hostname: %v "+
						"(this is the #7158 feature — the DDNS topology must be "+
						"authorable)", endpoint, err)
				}
				if fam != nil {
					t.Fatalf("endpointFamily(%q) claimed a family for a hostname; it "+
						"is not knowable at commit, and a guess is wrong in both "+
						"directions — see the mixed-family gate", endpoint)
				}
			default:
				t.Fatalf("unknown verdict %q in the shared fixture", want)
			}
		})
	}
}

// TestWireguardHostnamePeerStillGetsAllowedIPsValidation_7158 guards a defect
// this change nearly shipped.
//
// The family classification sits in the per-peer loop ABOVE the allowed-ips
// gates. Skipping the rest of the iteration for a hostname peer (the obvious
// spelling, `continue`, since a hostname does not constrain the family) would
// exempt every hostname peer from the malformed-CIDR and duplicate-prefix
// checks. Such a peer would commit clean and then be DROPPED by the Rust
// hydrate, which parses the same prefixes and fails the row closed — a peer
// that silently routes nothing.
//
// FAIL-ON-REVERT: replace the `if fam != nil { ... }` block with
// `if fam == nil { continue }` and this test goes RED while every other
// WireGuard test stays green.
func TestWireguardHostnamePeerStillGetsAllowedIPsValidation_7158(t *testing.T) {
	tc := &TunnelConfig{
		WgListenPort:      51820,
		WgLocalPrivkeyHex: Secret("2ff953c7f696fb2b203cd0fc455ee0936d53e587a99bd7076dcef27710a6b762"),
		WgPeers: []WgPeerConfig{{
			PublicKeyHex: "3234c2b228336f93d91937d8cf5704b76a02ac6d1c7ad02a4c06c0af18ae1b8d",
			Endpoint:     "ddns.example.com:51820",
			AllowedIPs:   []string{"this-is-not-a-cidr"},
		}},
	}
	err := validateOneWireguardTunnel(tc)
	if err == nil {
		t.Fatal("a hostname-endpoint peer with a malformed allowed-ips prefix " +
			"must still be rejected at commit; accepting it here means the row " +
			"is dropped at hydrate instead, with no diagnostic (#7158)")
	}
	if !strings.Contains(err.Error(), "allowed-ips") {
		t.Fatalf("expected the allowed-ips diagnostic, got: %v", err)
	}
}

// TestWireguardMixedFamilyGateUnchangedByHostnames_7158 is #7158 acceptance 5:
// the one-UDP-socket gate must still reject exactly what it rejected before.
func TestWireguardMixedFamilyGateUnchangedByHostnames_7158(t *testing.T) {
	peer := func(n byte, endpoint string) WgPeerConfig {
		// Distinct non-degenerate keys (#14373: a repeated-char key is
		// now refused before the family gate this test exercises).
		keys := []string{
			"00bedd4ed26623ab2f765d16af2dcba4f6dbe17c284a66c6494b48b823f4c654",
			"04d9dab116416940a490d8bab5d0dd921094f0a278dee3db867df8fbd2db6e16",
			"15d9fd16500e6a671c69ef3dfa24e72ae7a463c3cf2a659b2969de785bb98504",
		}
		return WgPeerConfig{
			PublicKeyHex: keys[int(n)%len(keys)],
			Endpoint:     endpoint,
			AllowedIPs:   []string{"10.0.0.0/24"},
		}
	}
	// Mixed LITERALS still reject — unchanged behaviour.
	mixed := &TunnelConfig{WgListenPort: 51820, WgLocalPrivkeyHex: Secret("2ff953c7f696fb2b203cd0fc455ee0936d53e587a99bd7076dcef27710a6b762"), WgPeers: []WgPeerConfig{
		peer(1, "203.0.113.7:51820"),
		peer(2, "[2001:db8::1]:51820"),
	}}
	mixed.WgPeers[1].AllowedIPs = []string{"10.0.1.0/24"}
	if err := validateOneWireguardTunnel(mixed); err == nil {
		t.Fatal("mixed-family literal endpoints must still be rejected: a " +
			"WireGuard interface binds ONE UDP socket")
	}

	// A hostname alongside a literal does NOT trip the gate: its family is
	// unknowable at commit, so it neither constrains nor is constrained.
	withHostname := &TunnelConfig{WgListenPort: 51820, WgLocalPrivkeyHex: Secret("2ff953c7f696fb2b203cd0fc455ee0936d53e587a99bd7076dcef27710a6b762"), WgPeers: []WgPeerConfig{
		peer(3, "203.0.113.7:51820"),
		peer(4, "ddns.example.com:51820"),
	}}
	withHostname.WgPeers[1].AllowedIPs = []string{"10.0.1.0/24"}
	if err := validateOneWireguardTunnel(withHostname); err != nil {
		t.Fatalf("a hostname peer must not trip the mixed-family gate: %v", err)
	}

	// And two hostnames are fine together.
	twoHostnames := &TunnelConfig{WgListenPort: 51820, WgLocalPrivkeyHex: Secret("2ff953c7f696fb2b203cd0fc455ee0936d53e587a99bd7076dcef27710a6b762"), WgPeers: []WgPeerConfig{
		peer(5, "a.example.com:51820"),
		peer(6, "b.example.com:51820"),
	}}
	twoHostnames.WgPeers[1].AllowedIPs = []string{"10.0.1.0/24"}
	if err := validateOneWireguardTunnel(twoHostnames); err != nil {
		t.Fatalf("two hostname peers must commit clean: %v", err)
	}
}
