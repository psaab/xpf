package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeExternalNetwork12135(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFindExternallyManagedMatchesNameGlobsAndMACAddress12135(t *testing.T) {
	dir := t.TempDir()
	writeExternalNetwork12135(t, dir, "20-glob.network", "[Match]\nName=enp* eth9\n\n[Network]\nName=ignored*\n")
	writeExternalNetwork12135(t, dir, "30-mac.network", "[Match]\nMACAddress=52-54-00-AA-BB-CC\n\n[Network]\nDHCP=yes\n")
	writeExternalNetwork12135(t, dir, "40-both.network", "[Match]\nName=wan*\nMACAddress=52:54:00:aa:bb:cc\n")
	writeExternalNetwork12135(t, dir, "60-unsupported.network", "[Match]\nName=other*\nDriver=ixgbe\n")
	writeExternalNetwork12135(t, dir, "10-xpf-trust0.network", "[Match]\nName=trust0\n")
	writeExternalNetwork12135(t, dir, "70-not-network.link", "[Match]\nName=link0\n")

	matches := FindExternallyManaged(dir)
	for _, tc := range []struct {
		name string
		mac  string
		want bool
	}{
		{name: "enp3s0", want: true},
		{name: "eth9", want: true},
		{name: "eth0", want: false},
		{name: "eth1", want: false},
		{name: "eth2", want: false},
		{name: "other0", want: false},
		{name: "not-wan", mac: "52:54:00:aa:bb:cc", want: true},
		{name: "wan0", mac: "52:54:00:AA:BB:CC", want: true},
		{name: "wan0", mac: "52:54:00:00:00:01", want: false},
		{name: "trust0", want: false},
		{name: "link0", want: false},
	} {
		t.Run(tc.name+"/"+tc.mac, func(t *testing.T) {
			if got := matches.Matches(tc.name, tc.mac); got != tc.want {
				t.Errorf("Matches(%q, %q) = %v, want %v", tc.name, tc.mac, got, tc.want)
			}
		})
	}
}

func TestExternalNameNegationOrdersAndClassExclusions12135(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rule  string
		iface string
		want  bool
	}{
		{name: "negative after positive excluded", rule: "Name=en*\nName=!enp0s31f6\n", iface: "enp0s31f6"},
		{name: "negative after positive allows other", rule: "Name=en*\nName=!enp0s31f6\n", iface: "enp1s0", want: true},
		{name: "positive after negative allows match", rule: "Name=!enp0s31f6\nName=en*\n", iface: "enp1s0", want: true},
		{name: "positive after negative excluded", rule: "Name=!enp0s31f6\nName=en*\n", iface: "enp0s31f6"},
		{name: "all negative excludes either", rule: "Name=!eth0\nName=!eth1\n", iface: "eth1"},
		{name: "all negative defaults true", rule: "Name=!eth0\nName=!eth1\n", iface: "eth2", want: true},
		{name: "same line excludes negative word", rule: "Name=en* !enp0s31f6\n", iface: "enp0s31f6"},
		{name: "same line matches positive word", rule: "Name=en* !enp0s31f6\n", iface: "enp1s0", want: true},
		{name: "same-line leading negation prefixes each word", rule: "Name=!en* eth*\n", iface: "eth0"},
		{name: "same-line all-negative rules default true", rule: "Name=!en* eth*\n", iface: "wlan0", want: true},
		{name: "class excludes zero", rule: "Name=eth[!0]\n", iface: "eth0"},
		{name: "class includes one", rule: "Name=eth[!0]\n", iface: "eth1", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeExternalNetwork12135(t, dir, "50-external.network", "[Match]\n"+tc.rule)
			if got := FindExternallyManaged(dir).Matches(tc.iface, ""); got != tc.want {
				t.Errorf("Matches(%q) = %v, want %v", tc.iface, got, tc.want)
			}
		})
	}
}

func TestApplyConservativelyPreservesUnknownExternalMatchKeys12135(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	writeExternalNetwork12135(t, dir, "20-external.network", "[Match]\nName=eth0\nDriver=igb\n")
	matches := FindExternallyManaged(dir)
	if matches.Matches("eth0", "") {
		t.Fatal("compiler matcher must not claim an incomplete conjunctive rule")
	}
	if !matches.MatchesForApply("eth0", "") {
		t.Fatal("Apply matcher must preserve master’s durable protection when supported predicates match")
	}
	m := NewInDir(dir)
	if err := m.Apply([]InterfaceConfig{{Name: "eth0", Unmanaged: true}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, filePrefix+"eth0.network")); !os.IsNotExist(err) {
		t.Fatalf("Apply must not emit an always-down file for a potentially externally-owned link; stat err=%v", err)
	}
}

func TestApplyExternalSkipPrecedesGlobRefusal12135(t *testing.T) {
	stubNetworkctl9886(t)
	dir := t.TempDir()
	external := "[Match]\nName=ge*\n\n[Network]\nDHCP=yes\n"
	writeExternalNetwork12135(t, dir, "20-external.network", external)
	m := NewInDir(dir)
	if err := m.Apply([]InterfaceConfig{{Name: "ge*0", Unmanaged: true}}); err != nil {
		t.Fatalf("externally matched unmanaged interface must skip before glob refusal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, filePrefix+"ge*0.network")); !os.IsNotExist(err) {
		t.Fatalf("skipped interface must not get an xpf unit; stat err=%v", err)
	}
}

func TestExternalMatchDropsInvalidMACWordsResetsEmptyNameAndAcceptsShortGroups12135(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rule  string
		iface string
		mac   string
		want  bool
	}{
		{
			name:  "invalid MAC word dropped",
			rule:  "Name=eth0\nMACAddress=invalid\n",
			iface: "eth0",
			want:  true,
		},
		{
			name:  "empty Name resets to empty Match",
			rule:  "Name=eth0\nName=\nMACAddress=invalid\n",
			iface: "other0",
			want:  true,
		},
		{
			name:  "short MAC groups",
			rule:  "MACAddress=52:54:0:aa:bb:cc\n",
			iface: "eth0",
			mac:   "52:54:00:aa:bb:cc",
			want:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeExternalNetwork12135(t, dir, "50-external.network", "[Match]\n"+tc.rule)
			if got := FindExternallyManaged(dir).Matches(tc.iface, tc.mac); got != tc.want {
				t.Errorf("Matches(%q, %q) = %v, want %v", tc.iface, tc.mac, got, tc.want)
			}
		})
	}
}

func TestApplyHonorsExternalNameGlobAndMACBeforeAlwaysDown12135(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mac          string
		match        string
		wantExternal bool
	}{
		{name: "enp3s0", match: "Name=enp*", wantExternal: true},
		{name: "eth9", match: "Name=eth0 eth9", wantExternal: true},
		{name: "wan0", mac: "52:54:00:aa:bb:cc", match: "MACAddress=52:54:00:AA:BB:CC", wantExternal: true},
		{name: "enp3s0", match: "Name=eth*", wantExternal: false},
	} {
		t.Run(tc.name+"/"+tc.match, func(t *testing.T) {
			stubNetworkctl9886(t)
			dir := t.TempDir()
			external := "[Match]\n" + tc.match + "\n\n[Network]\nDHCP=yes\n"
			writeExternalNetwork12135(t, dir, "20-external.network", external)
			m := NewInDir(dir)
			if err := m.Apply([]InterfaceConfig{{Name: tc.name, MACAddress: tc.mac, Unmanaged: true}}); err != nil {
				t.Fatal(err)
			}
			xpfPath := filepath.Join(dir, filePrefix+tc.name+".network")
			xpf, err := os.ReadFile(xpfPath)
			if tc.wantExternal {
				if !os.IsNotExist(err) {
					t.Fatalf("external match must suppress xpf's earlier always-down file; got content %q, err %v", xpf, err)
				}
			} else {
				if err != nil {
					t.Fatalf("non-matching unmanaged interface should retain xpf file: %v", err)
				}
				if !strings.Contains(string(xpf), "ActivationPolicy=always-down") {
					t.Fatalf("non-matching unmanaged interface lacks always-down policy: %s", xpf)
				}
			}
			if got, err := os.ReadFile(filepath.Join(dir, "20-external.network")); err != nil || string(got) != external {
				t.Fatalf("external config changed: got %q, err %v", got, err)
			}
		})
	}
}

func TestExternalMACAddressForms12135(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
		want    bool
	}{
		{
			name:    "bare hex",
			pattern: "525400aabbcc",
		},
		{
			name:    "eight-byte EUI-64",
			pattern: "52-54-00-aa-bb-cc-dd-ee",
		},
		{
			name:    "dotted EUI-48",
			pattern: "5254.00aa.bbcc",
			want:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := parseExternalMACAddress(tc.pattern); got != tc.want {
				t.Errorf("parseExternalMACAddress(%q) valid = %v, want %v", tc.pattern, got, tc.want)
			}
		})
	}
}
