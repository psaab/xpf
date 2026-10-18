package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #14701: a same-line Name= value whose first word is negated must keep
// per-word negation for later words, and an IP literal must not be
// accepted as a MACAddress= predicate. Bug 3 (MatchesForApply ignoring
// unknown keys when a supported predicate matches) is deliberate and
// pinned by TestApplyConservativelyPreservesUnknownExternalMatchKeys12135.
func TestFindExternallyManagedUnparseableMACAndMultiNegatedName(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		iface     string
		mac       string
		wantMatch bool
		wantApply bool
	}{
		// Bug 2 (issue text): Name=!eth0 !eth1 double-prefixes the
		// second word to "!!eth1", so fnmatch matches a literal !
		// and eth1 is not vetoed. The fix is matcher-side: a run of
		// leading ! collapses to one negation. (The parser's
		// line-leading-! prefixing of every word on the line is
		// systemd's config_parse_match_ifnames behavior and is
		// pinned by the 12135 same-line tests; it is not changed.)
		{name: "same-line literal second neg excludes second", body: "[Match]\nName=eth* !eth1\n", iface: "eth1", wantMatch: false, wantApply: false},
		{name: "same-line literal second neg allows other positive", body: "[Match]\nName=eth* !eth1\n", iface: "eth2", wantMatch: true, wantApply: true},
		{name: "same-line multi-neg excludes second", body: "[Match]\nName=!eth0 !eth1\n", iface: "eth1", wantMatch: false, wantApply: false},
		{name: "same-line multi-neg excludes first", body: "[Match]\nName=!eth0 !eth1\n", iface: "eth0", wantMatch: false, wantApply: false},
		{name: "same-line multi-neg defaults true for other", body: "[Match]\nName=!eth0 !eth1\n", iface: "eth2", wantMatch: true, wantApply: true},
		// IP literals are not hardware addresses: systemd's
		// config_parse_hw_addrs rejects them, so an IP-only MACAddress=
		// leaves no valid predicate and the file is ignored (#14593
		// mechanism), for both matchers and both address families.
		{name: "ipv4 literal is not a MAC", body: "[Match]\nMACAddress=192.0.2.1\n", iface: "eth0", mac: "192.0.2.1", wantMatch: false, wantApply: false},
		{name: "ipv6 literal is not a MAC", body: "[Match]\nMACAddress=2001:db8::1\n", iface: "eth0", mac: "52:54:00:aa:bb:cc", wantMatch: false, wantApply: false},
		{name: "eight-group colon IP literal is not a MAC", body: "[Match]\nMACAddress=52:54:00:aa:bb:cc:dd:ee\n", iface: "eth0", mac: "52:54:00:aa:bb:cc", wantMatch: false, wantApply: false},
		// A MACAddress= reset clears earlier valid words even when the
		// resetting assignment itself has no parseable word.
		{name: "invalid MAC assignment resets earlier valid MAC for Apply", body: "[Match]\nMACAddress=52:54:00:aa:bb:cc\nMACAddress=invalid\n", iface: "eth0", mac: "52:54:00:aa:bb:cc", wantMatch: false, wantApply: false},
		{name: "empty MAC assignment resets earlier valid MAC", body: "[Match]\nMACAddress=52:54:00:aa:bb:cc\nMACAddress=\n", iface: "eth0", mac: "52:54:00:aa:bb:cc", wantMatch: false, wantApply: false},
		// Controls that must stay green: IPoIB / negated / malformed
		// MAC-only files already leave no valid predicate.
		{name: "control negated MAC only", body: "[Match]\nMACAddress=!52:54:00:aa:bb:cc\n", iface: "eth0", mac: "52:54:00:aa:bb:cc", wantMatch: false, wantApply: false},
		{name: "control ipoib 20-byte MAC only", body: "[Match]\nMACAddress=00:00:00:00:fe:80:00:00:00:00:00:00:00:00:00:00:00:00:00:00\n", iface: "eth0", mac: "52:54:00:aa:bb:cc", wantMatch: false, wantApply: false},
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

	// Apply-level: the IP-literal and multi-negated files must not
	// suppress the always-down unit for the excluded interface, while
	// the multi-negated file still suppresses it for an unexcluded one.
	t.Run("apply multi-negated name", func(t *testing.T) {
		stubNetworkctl9886(t)
		dir := t.TempDir()
		writeExternalNetwork12135(t, dir, "20-external.network", "[Match]\nName=!eth0 !eth1\n")
		if err := NewInDir(dir).Apply([]InterfaceConfig{{Name: "eth1", Unmanaged: true}}); err != nil {
			t.Fatal(err)
		}
		xpf, err := os.ReadFile(filepath.Join(dir, filePrefix+"eth1.network"))
		if err != nil || !strings.Contains(string(xpf), "ActivationPolicy=always-down") {
			t.Fatalf("eth1 excluded by !eth1 must retain always-down unit; got %q, err %v", xpf, err)
		}
		if err := NewInDir(dir).Apply([]InterfaceConfig{{Name: "eth2", Unmanaged: true}}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, filePrefix+"eth2.network")); !os.IsNotExist(err) {
			t.Fatalf("eth2 matched by all-negative Name must suppress always-down unit; stat err=%v", err)
		}
	})
	t.Run("apply ipv4 literal MAC", func(t *testing.T) {
		stubNetworkctl9886(t)
		dir := t.TempDir()
		writeExternalNetwork12135(t, dir, "20-external.network", "[Match]\nMACAddress=192.0.2.1\n")
		if err := NewInDir(dir).Apply([]InterfaceConfig{{Name: "eth0", MACAddress: "192.0.2.1", Unmanaged: true}}); err != nil {
			t.Fatal(err)
		}
		xpf, err := os.ReadFile(filepath.Join(dir, filePrefix+"eth0.network"))
		if err != nil || !strings.Contains(string(xpf), "ActivationPolicy=always-down") {
			t.Fatalf("IP-literal MACAddress must not suppress always-down unit; got %q, err %v", xpf, err)
		}
	})
}

// parseExternalMACAddress must reject IP literals directly: they were
// previously accepted via net.ParseIP before the EUI-48 checks.
func TestParseExternalMACAddressRejectsIPLiteral14701(t *testing.T) {
	for _, pattern := range []string{"192.0.2.1", "2001:db8::1", "52:54:00:aa:bb:cc:dd:ee", "::1", "0.0.0.0"} {
		if _, ok := parseExternalMACAddress(pattern); ok {
			t.Errorf("parseExternalMACAddress(%q) accepted an IP literal as a hardware address", pattern)
		}
	}
	if _, ok := parseExternalMACAddress("52:54:00:aa:bb:cc"); !ok {
		t.Error("control: EUI-48 must still parse")
	}
}
