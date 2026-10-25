package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #14701 pinned two semantics that #16797 proved wrong against real
// systemd-networkd 262 (see networkd_parity_16797_test.go): a same-line
// Name= value whose first word is negated does NOT keep per-word
// negation for a later "!word" (systemd stores "!!eth1", a negated
// pattern "!eth1" that matches nothing, so eth1 is not vetoed), and an
// IP literal IS accepted as a MACAddress= predicate (config_parse_hw_addrs
// with ltype 0 accepts IPv4/IPv6 forms as tunnel hardware addresses).
// The cells below now pin the 262 verdicts; the MAC-reset and control
// cells from #14701 that 262 agrees with are unchanged. Bug 3
// (MatchesForApply ignoring unknown keys when a supported predicate
// matches) is deliberate and pinned by
// TestApplyConservativelyPreservesUnknownExternalMatchKeys12135.
func TestFindExternallyManagedUnparseableMACAndMultiNegatedName(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		iface     string
		mac       string
		wantMatch bool
		wantApply bool
	}{
		// systemd 262 (net_condition_test_strv strips exactly one
		// "!"): the parser prefixes "!" onto every word of a
		// line-negated Name= assignment, so Name=!eth0 !eth1 is
		// stored as ["!eth0", "!!eth1"]; "!!eth1" is a negated
		// pattern "!eth1", which fnmatches no real name, so eth1 is
		// NOT vetoed. The all-negative set then matches eth1/eth2
		// by default, while eth0 (stored "!eth0") is vetoed.
		// Real-networkd proof: networkd_parity_16797_test.go.
		{name: "same-line literal second neg excludes second", body: "[Match]\nName=eth* !eth1\n", iface: "eth1", wantMatch: false, wantApply: false},
		{name: "same-line literal second neg allows other positive", body: "[Match]\nName=eth* !eth1\n", iface: "eth2", wantMatch: true, wantApply: true},
		{name: "same-line multi-neg allows second (262)", body: "[Match]\nName=!eth0 !eth1\n", iface: "eth1", wantMatch: true, wantApply: true},
		{name: "same-line multi-neg excludes first", body: "[Match]\nName=!eth0 !eth1\n", iface: "eth0", wantMatch: false, wantApply: false},
		{name: "same-line multi-neg defaults true for other", body: "[Match]\nName=!eth0 !eth1\n", iface: "eth2", wantMatch: true, wantApply: true},
		// A doubled "!" on a LATER line is likewise one negation of
		// a literal-"!" pattern: "!!eth1" vetoes nothing.
		{name: "later line double neg vetoes nothing (262)", body: "[Match]\nName=eth0\nName=!!eth1\n", iface: "eth0", wantMatch: true, wantApply: true},
		// IP literals ARE hardware addresses in systemd 262:
		// config_parse_hw_addrs calls parse_hw_addr_full(word, 0),
		// which accepts IPv4 (4-byte) and IPv6 (16-byte) forms for
		// tunnel hardware addresses. An IP-only file is therefore a
		// valid MAC predicate matching the interface whose hardware
		// address is that IP (gre tunnel local address), for both
		// matchers and both families. The caller's mac string is the
		// raw form (netlink HardwareAddr.String()): "192.0.2.1" for
		// v4, the colon form for v6.
		{name: "ipv4 literal is a tunnel MAC (262)", body: "[Match]\nMACAddress=192.0.2.1\n", iface: "gre1", mac: "192.0.2.1", wantMatch: true, wantApply: true},
		{name: "ipv4 literal MAC requires equal tunnel addr", body: "[Match]\nMACAddress=192.0.2.1\n", iface: "eth9", mac: "52:54:00:aa:bb:cc", wantMatch: false, wantApply: false},
		{name: "ipv6 literal is a tunnel MAC (262)", body: "[Match]\nMACAddress=2001:db8::1\n", iface: "gre1", mac: "2001:db8:0:0:0:0:0:1", wantMatch: true, wantApply: true},
		{name: "ipv6 literal MAC requires equal tunnel addr", body: "[Match]\nMACAddress=2001:db8::1\n", iface: "eth9", mac: "52:54:00:aa:bb:cc", wantMatch: false, wantApply: false},
		// An 8-group colon word parses in systemd as a 16-byte
		// IPv6-form address (inet_pton, each group 16 bits), so the
		// file IS a valid predicate — it simply cannot equal this
		// 6-byte interface. Against the 16-byte spelling of the
		// same bytes it matches (next cells).
		{name: "eight-group colon literal is not a MAC", body: "[Match]\nMACAddress=52:54:00:aa:bb:cc:dd:ee\n", iface: "eth0", mac: "52:54:00:aa:bb:cc", wantMatch: false, wantApply: false},
		{name: "eight-group colon word equals 16-byte form (262)", body: "[Match]\nMACAddress=52:54:00:aa:bb:cc:dd:ee\n", iface: "gre6", mac: "0:52:0:54:0:0:0:aa:0:bb:0:cc:0:dd:0:ee", wantMatch: true, wantApply: true},
		{name: "ipv6 tunnel colon form matches (262)", body: "[Match]\nMACAddress=2001:db8::1\n", iface: "gre6", mac: "20:01:d:b8:0:0:0:0:0:0:0:0:0:0:0:1", wantMatch: true, wantApply: true},
		{name: "ipv4 tunnel colon form matches (262)", body: "[Match]\nMACAddress=192.0.2.1\n", iface: "gre1", mac: "c0:0:2:1", wantMatch: true, wantApply: true},
		// A MACAddress= reset clears earlier valid words even when the
		// resetting assignment itself has no parseable word.
		{name: "invalid MAC assignment resets earlier valid MAC for Apply", body: "[Match]\nMACAddress=52:54:00:aa:bb:cc\nMACAddress=invalid\n", iface: "eth0", mac: "52:54:00:aa:bb:cc", wantMatch: false, wantApply: false},
		{name: "empty MAC assignment resets earlier valid MAC", body: "[Match]\nMACAddress=52:54:00:aa:bb:cc\nMACAddress=\n", iface: "eth0", mac: "52:54:00:aa:bb:cc", wantMatch: false, wantApply: false},
		// Controls that must stay green: negated / malformed
		// MAC-only files leave no valid predicate. A 20-byte IPoIB
		// address IS a valid systemd word (length 20), so that file
		// is a valid predicate that simply does not match this
		// 6-byte interface — the verdict (false) is unchanged.
		{name: "control negated MAC only", body: "[Match]\nMACAddress=!52:54:00:aa:bb:cc\n", iface: "eth0", mac: "52:54:00:aa:bb:cc", wantMatch: false, wantApply: false},
		{name: "control ipoib 20-byte MAC only", body: "[Match]\nMACAddress=00:00:00:00:fe:80:00:00:00:00:00:00:00:00:00:00:00:00:00:00\n", iface: "eth0", mac: "52:54:00:aa:bb:cc", wantMatch: false, wantApply: false},
		{name: "ipoib 20-byte MAC matches equal address (262)", body: "[Match]\nMACAddress=00:00:00:00:fe:80:00:00:00:00:00:00:00:00:00:00:00:00:00:00\n", iface: "ib0", mac: "00:00:00:00:fe:80:00:00:00:00:00:00:00:00:00:00:00:00:00:00", wantMatch: true, wantApply: true},
		{name: "control valid MAC still matches", body: "[Match]\nMACAddress=52:54:00:aa:bb:cc\n", iface: "eth0", mac: "52:54:00:aa:bb:cc", wantMatch: true, wantApply: true},
		{name: "control valid Name still matches", body: "[Match]\nName=eth0\n", iface: "eth0", wantMatch: true, wantApply: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeExternalNetwork12135(t, dir, "20-external.network", tc.body)
			matches := FindExternallyManaged(dir)
			if got := matches.Matches(tc.iface, tc.mac); got != tc.wantMatch {
				t.Errorf("Matches(%q, %q) = %v, want %v for %q", tc.iface, tc.mac, got, tc.wantMatch, tc.body)
			}
			if got := matches.MatchesForApply(tc.iface, tc.mac); got != tc.wantApply {
				t.Errorf("MatchesForApply(%q, %q) = %v, want %v for %q", tc.iface, tc.mac, got, tc.wantApply, tc.body)
			}
		})
	}

	// Apply-level (262 verdicts): the multi-negated file matches eth1
	// (no veto — see table) so it suppresses eth1's always-down unit,
	// while eth0 IS vetoed and retains its unit; the IP-literal file
	// matches the tunnel interface and suppresses its unit, while an
	// unequal interface retains its unit.
	t.Run("apply multi-negated name", func(t *testing.T) {
		stubNetworkctl9886(t)
		dir := t.TempDir()
		writeExternalNetwork12135(t, dir, "20-external.network", "[Match]\nName=!eth0 !eth1\n")
		if err := NewInDir(dir).Apply([]InterfaceConfig{{Name: "eth1", Unmanaged: true}}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, filePrefix+"eth1.network")); !os.IsNotExist(err) {
			t.Fatalf("eth1 matched by Name=!eth0 !eth1 (262: no veto) must suppress always-down unit; stat err=%v", err)
		}
		if err := NewInDir(dir).Apply([]InterfaceConfig{{Name: "eth0", Unmanaged: true}}); err != nil {
			t.Fatal(err)
		}
		xpf, err := os.ReadFile(filepath.Join(dir, filePrefix+"eth0.network"))
		if err != nil || !strings.Contains(string(xpf), "ActivationPolicy=always-down") {
			t.Fatalf("eth0 vetoed by !eth0 must retain always-down unit; got %q, err %v", xpf, err)
		}
	})
	t.Run("apply ipv4 literal MAC", func(t *testing.T) {
		stubNetworkctl9886(t)
		dir := t.TempDir()
		writeExternalNetwork12135(t, dir, "20-external.network", "[Match]\nMACAddress=192.0.2.1\n")
		if err := NewInDir(dir).Apply([]InterfaceConfig{{Name: "gre1", MACAddress: "192.0.2.1", Unmanaged: true}}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, filePrefix+"gre1.network")); !os.IsNotExist(err) {
			t.Fatalf("IP-literal MACAddress=192.0.2.1 matches gre1 (262) and must suppress always-down unit; stat err=%v", err)
		}
		if err := NewInDir(dir).Apply([]InterfaceConfig{{Name: "eth9", MACAddress: "52:54:00:aa:bb:cc", Unmanaged: true}}); err != nil {
			t.Fatal(err)
		}
		xpf, err := os.ReadFile(filepath.Join(dir, filePrefix+"eth9.network"))
		if err != nil || !strings.Contains(string(xpf), "ActivationPolicy=always-down") {
			t.Fatalf("unequal MAC must retain always-down unit; got %q, err %v", xpf, err)
		}
	})
}

// parseExternalMACAddress accepts IP literals as raw 4/16-byte tunnel
// hardware addresses (#16797, systemd parse_hw_addr_full expected_len
// 0) and still rejects other non-{4,16,6,20} lengths.
func TestParseExternalMACAddressIPLiteralParity16797(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		wantLen int // 0 = must not parse
	}{
		{pattern: "192.0.2.1", wantLen: 4},
		{pattern: "2001:db8::1", wantLen: 16},
		{pattern: "::1", wantLen: 16},
		{pattern: "0.0.0.0", wantLen: 4},
		// inet_pton claims the 8-group colon spelling as a 16-byte
		// IPv6-form address (each group 16 bits) — it is NOT an
		// 8-byte EUI-64 and must not parse as one.
		{pattern: "52:54:00:aa:bb:cc:dd:ee", wantLen: 16},
		{pattern: "52:54:00:aa:bb:cc", wantLen: 6},
		{pattern: "c0:00:02:01", wantLen: 4},
		{pattern: "20:01:0d:b8:00:00:00:00:00:00:00:00:00:00:00:01", wantLen: 16},
	} {
		got, ok := parseExternalMACAddress(tc.pattern)
		if tc.wantLen == 0 {
			if ok {
				t.Errorf("parseExternalMACAddress(%q) = %v, want rejected", tc.pattern, got)
			}
			continue
		}
		if !ok || len(got) != tc.wantLen {
			t.Errorf("parseExternalMACAddress(%q) = (%v, %v), want %d bytes", tc.pattern, got, ok, tc.wantLen)
		}
	}
	// The v4 literal and its colon-hex spelling are the same bytes:
	// networkctl shows gre1's address as c0:00:02:01 for local 192.0.2.1.
	v4, _ := parseExternalMACAddress("192.0.2.1")
	hexForm, _ := parseExternalMACAddress("c0:00:02:01")
	if len(v4) != len(hexForm) {
		t.Fatalf("length mismatch: %v vs %v", v4, hexForm)
	}
	for i := range v4 {
		if v4[i] != hexForm[i] {
			t.Fatalf("byte mismatch: %v vs %v", v4, hexForm)
		}
	}
}
