package appid

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9899 F102: numeric protocol tokens are canonical raw ASCII decimal 0..255
// only — no sign, no surrounding whitespace. Names/aliases keep their existing
// case/trim behavior. This pins appid.ProtocolNumber directly (absolute
// verdicts, not a mirror comparison) so it fails on the pre-fix
// strconv.Atoi(TrimSpace) reader which accepts "+6" and " 6".
func TestProtocolCanonicalNumeric9899(t *testing.T) {
	// Canonical numerics still resolve, including the deliberate "0" (HOPOPT)
	// and the 0..255 bounds. Leading zeros remain canonical: the shared
	// ParseCanonicalUint primitive accepts a bare digit run ("006" -> 6),
	// matching the #3606 port precedent (TestParseCanonicalPort_3606 accepts
	// "00080").
	for _, tc := range []struct {
		tok  string
		want uint8
	}{
		{"0", 0}, {"6", 6}, {"255", 255}, {"1", 1}, {"17", 17},
		{"47", 47}, {"41", 41}, {"132", 132},
		{"006", 6}, {"000", 0},
	} {
		n, ok := ProtocolNumber(tc.tok)
		if !ok || n != tc.want {
			t.Errorf("ProtocolNumber(%q) = (%d, %v), want (%d, true)", tc.tok, n, ok, tc.want)
		}
	}

	// Non-canonical numerics must reject. "+6"/whitespace-padded are the RED
	// cases on base (Atoi+TrimSpace accepts them); "-1"/"256"/overflow/malformed
	// already reject and are pinned against regression.
	for _, tok := range []string{
		"+6", "+0", "+255", "+17", "+1",
		"-1", "-0", "-6",
		" 6", "6 ", " 6 ", "\t6", "6\t", " 0", "0 ", " 255 ",
		"256", "300", "99999999999999999999999",
		"0x6", "0x50", "6a", "a6", "++6", "--6", "+ 6",
		"", " ", "bogus", "definitely-not-a-proto", "junos-foobar",
	} {
		if n, ok := ProtocolNumber(tok); ok {
			t.Errorf("ProtocolNumber(%q) = (%d, true), want ok=false (non-canonical/unrepresentable)", tok, n)
		}
	}

	// Named case/trim/aliases preserved: every name the SSOT resolves keeps
	// resolving, case-insensitively and with surrounding whitespace trimmed.
	for _, tc := range []struct {
		tok  string
		want uint8
	}{
		{"tcp", 6}, {"TCP", 6}, {" Tcp ", 6},
		{"udp", 17}, {"UDP", 17}, {" udp ", 17},
		{"icmp", 1}, {"ICMP", 1},
		{"icmpv6", 58}, {"ICMPV6", 58}, {"icmp6", 58}, {"ICMP6", 58},
		{"gre", 47}, {"GRE", 47},
		{"ipv6", 41}, {"IPV6", 41},
		{"junos-tcp-any", 6}, {"JUNOS-TCP-ANY", 6}, {" junos-tcp-any ", 6},
		{"junos-udp-any", 17},
		{"junos-ping", 1}, {"JUNOS-PING", 1}, {" junos-ping ", 1},
		{"junos-pingv6", 58},
		{"junos-gre", 47},
	} {
		n, ok := ProtocolNumber(tc.tok)
		if !ok || n != tc.want {
			t.Errorf("ProtocolNumber(%q) = (%d, %v), want (%d, true) — named case/trim/alias must be preserved", tc.tok, n, ok, tc.want)
		}
	}
}

// #9899 F102: cross-package behavior pin. The existing
// TestFilterProtocolResolvableMatchesProtocolNumber only asserts the two
// mirrors AGREE — on base both accept "+6"/" 6", so it stays green while the
// defect ships. Here both sides get ABSOLUTE verdicts: canonical tokens must be
// accepted and non-canonical tokens rejected by each reader, so a shared
// defect still goes RED.
func TestProtocolCanonicalCrossPackageBehavior9899(t *testing.T) {
	// Firewall-filter gate mirrors the SSOT acceptance set.
	for _, tc := range []struct {
		tok  string
		want bool
	}{
		{"0", true}, {"6", true}, {"255", true}, {"006", true},
		{"tcp", true}, {"TCP", true}, {" tcp ", true},
		{"junos-ping", true}, {"ipv6", true},
		{"+6", false}, {"+0", false}, {"-1", false},
		{" 6", false}, {"6 ", false}, {" 6 ", false},
		{"256", false}, {"99999999999999999999999", false},
		{"0x6", false}, {"bogus", false}, {"junos-foobar", false}, {"", false},
	} {
		if _, ok := ProtocolNumber(tc.tok); ok != tc.want {
			t.Errorf("ProtocolNumber(%q) ok = %v, want %v", tc.tok, ok, tc.want)
		}
		if got := config.FilterProtocolResolvable(tc.tok); got != tc.want {
			t.Errorf("FilterProtocolResolvable(%q) = %v, want %v", tc.tok, got, tc.want)
		}
	}

	// Port-bearing subset: only TCP(6)/UDP(17) — numeric or named — with the
	// same canonical-numeric discipline.
	for _, tc := range []struct {
		tok  string
		want bool
	}{
		{"6", true}, {"17", true}, {"006", true}, {"017", true},
		{"tcp", true}, {"TCP", true}, {" udp ", true}, {"junos-tcp-any", true},
		{"+6", false}, {"+17", false}, {" 6", false}, {"6 ", false}, {" 17", false},
		{"0", false}, {"1", false}, {"47", false}, {"132", false},
		{"icmp", false}, {"sctp", false}, {"256", false}, {"-1", false},
		{"bogus", false}, {"", false},
	} {
		if got := config.ProtocolIsPortBearing(tc.tok); got != tc.want {
			t.Errorf("ProtocolIsPortBearing(%q) = %v, want %v", tc.tok, got, tc.want)
		}
	}

	// DNAT gate: same canonical numerics, empty wildcard preserved, and the
	// deliberate tighter exclusions (junos-* aliases, "ipv6") preserved.
	for _, tc := range []struct {
		tok  string
		want bool
	}{
		{"", true},
		{"0", true}, {"6", true}, {"255", true}, {"47", true}, {"006", true},
		{"tcp", true}, {"TCP", true}, {" udp ", true},
		{"+6", false}, {" 6", false}, {"6 ", false}, {"-1", false},
		{"256", false}, {"99999999999999999999999", false},
		{"bogus", false}, {"0x6", false},
		{"junos-tcp-any", false}, {"junos-ping", false},
		{"ipv6", false}, {"IPV6", false},
	} {
		if got := config.DNATProtocolResolvable(tc.tok); got != tc.want {
			t.Errorf("DNATProtocolResolvable(%q) = %v, want %v", tc.tok, got, tc.want)
		}
	}
}
