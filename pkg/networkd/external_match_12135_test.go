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
		{name: "nested opening bracket does not match caret", rule: "Name=eth[[!0]\n", iface: "eth^"},
		{name: "nested opening bracket includes zero", rule: "Name=eth[[!0]\n", iface: "eth0", want: true},
		{name: "nested opening bracket includes literal bracket", rule: "Name=eth[[!0]\n", iface: "eth[", want: true},
		{name: "literal closing bracket first in class", rule: "Name=eth[]0]\n", iface: "eth0", want: true},
		{name: "negative name rule with literal closing bracket class", rule: "Name=!eth[]0]\n", iface: "eth0"},
		{name: "negative class with literal closing bracket first", rule: "Name=eth[!]]\n", iface: "eth0", want: true},
		{name: "literal closing bracket first in class matches bracket", rule: "Name=eth[]0]\n", iface: "eth]", want: true},
		{name: "negated class with literal closing bracket rejects bracket", rule: "Name=eth[!]]\n", iface: "eth]"},
		{name: "leading hyphen in class is literal", rule: "Name=eth[-0]\n", iface: "eth-", want: true},
		{name: "trailing hyphen in class is literal", rule: "Name=eth[0-]\n", iface: "eth-", want: true},
		{name: "unmatched opening bracket is literal", rule: "Name=eth[\n", iface: "eth[", want: true},
		{name: "unmatched opening bracket does not match other names", rule: "Name=eth[\n", iface: "eth0"},
		{name: "invalid positive range does not match", rule: "Name=eth[z-a]\n", iface: "eth0"},
		{name: "invalid negative range uses all-negative default", rule: "Name=!eth[z-a]\n", iface: "eth0", want: true},
		{name: "POSIX digit class matches", rule: "Name=eth[[:digit:]]\n", iface: "eth0", want: true},
		{name: "POSIX collating symbol matches its character", rule: "Name=eth[.ch.]\n", iface: "ethc", want: true},
		{name: "POSIX equivalence class matches its character", rule: "Name=eth[=ab=]\n", iface: "etha", want: true},
		{name: "unknown POSIX character class does not match", rule: "Name=eth[[:bogus:]]\n", iface: "eth0"},
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
		{name: "bare hex rejected", pattern: "525400aabbcc"},
		{name: "eight-byte EUI-64 rejected", pattern: "52-54-00-aa-bb-cc-dd-ee"},
		{name: "eight-group colon IPv6 literal", pattern: "52:54:00:aa:bb:cc:dd:ee", want: true},
		{name: "IPv4 literal", pattern: "192.0.2.1", want: true},
		{name: "IPv6 literal", pattern: "2001:db8::1", want: true},
		{name: "colon-separated address", pattern: "52:54:00:aa:bb:cc", want: true},
		{name: "short colon groups", pattern: "5:4:0:a:b:c", want: true},
		{name: "hyphen-separated address", pattern: "52-54-00-aa-bb-cc", want: true},
		{name: "short hyphen groups", pattern: "5-4-0-a-b-c", want: true},
		{name: "dotted four-digit groups", pattern: "5254.00aa.bbcc", want: true},
		{name: "short dotted groups", pattern: "5254.aa.bbcc", want: true},
		{name: "one-digit dotted groups", pattern: "1.a.1", want: true},
		{name: "three-digit dotted groups", pattern: "a1.123.4abc", want: true},
		{name: "two-digit dotted groups", pattern: "52.54.00", want: true},
		{name: "overlong dotted field rejected", pattern: "12345.aa.bb"},
		{name: "systemd-accepted four-byte dotted form remains out of scope", pattern: "aa.bb"},
		{name: "mixed separators rejected", pattern: "52:54-00:aa:bb:cc"},
		{name: "empty dotted field rejected", pattern: "aa..bb"},
		{name: "too many dotted fields rejected", pattern: "aa.bb.cc.dd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := parseExternalMACAddress(tc.pattern); got != tc.want {
				t.Errorf("parseExternalMACAddress(%q) valid = %v, want %v", tc.pattern, got, tc.want)
			}
		})
	}
}

func TestApplyExternalMACAddressFormsMatchSystemd12135(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
		equal   string
		unequal string
	}{
		{name: "short dotted groups", pattern: "5254.aa.bbcc", equal: "52:54:00:aa:bb:cc", unequal: "52:54:00:aa:bb:cd"},
		{name: "dotted leading-zero groups", pattern: "5254.0aa.bbcc", equal: "52:54:00:aa:bb:cc", unequal: "52:54:00:aa:bb:cd"},
		{name: "dotted full-width groups", pattern: "5254.00aa.bbcc", equal: "52:54:00:aa:bb:cc", unequal: "52:54:00:aa:bb:cd"},
		{name: "short colon groups", pattern: "52:54:0:aa:bb:cc", equal: "52:54:00:aa:bb:cc", unequal: "52:54:00:aa:bb:cd"},
		{name: "short hyphen groups", pattern: "52-54-0-aa-bb-cc", equal: "52:54:00:aa:bb:cc", unequal: "52:54:00:aa:bb:cd"},
		{name: "one-digit dotted groups", pattern: "1.a.1", equal: "0:1:0:a:0:1", unequal: "0:1:0:a:0:2"},
		{name: "mixed-width dotted groups", pattern: "a1.123.4abc", equal: "0:a1:1:23:4a:bc", unequal: "0:a1:1:23:4a:bd"},
	} {
		for _, address := range []struct {
			name string
			mac  string
			want bool
		}{
			{name: "equal", mac: tc.equal, want: true},
			{name: "adjacent unequal", mac: tc.unequal},
		} {
			t.Run(tc.name+"/"+address.name, func(t *testing.T) {
				stubNetworkctl9886(t)
				dir := t.TempDir()
				writeExternalNetwork12135(t, dir, "20-external.network", "[Match]\nMACAddress="+tc.pattern+"\n\n[Network]\nDHCP=yes\n")
				matches := FindExternallyManaged(dir)
				if got := matches.Matches("eth0", address.mac); got != address.want {
					t.Fatalf("Matches(%q) = %v, want %v", address.mac, got, address.want)
				}
				if got := matches.MatchesForApply("eth0", address.mac); got != address.want {
					t.Fatalf("MatchesForApply(%q) = %v, want %v", address.mac, got, address.want)
				}
				if err := NewInDir(dir).Apply([]InterfaceConfig{{Name: "eth0", MACAddress: address.mac, Unmanaged: true}}); err != nil {
					t.Fatal(err)
				}
				xpf, err := os.ReadFile(filepath.Join(dir, filePrefix+"eth0.network"))
				if address.want {
					if !os.IsNotExist(err) {
						t.Fatalf("equal external MAC must suppress xpf's always-down unit; got %q, err %v", xpf, err)
					}
				} else if err != nil || !strings.Contains(string(xpf), "ActivationPolicy=always-down") {
					t.Fatalf("adjacent unequal MAC must retain xpf's always-down unit; got %q, err %v", xpf, err)
				}
			})
		}
	}
}
func TestApplyExternalFnmatchClassesMatchSystemd12135(t *testing.T) {
	for _, tc := range []struct {
		name         string
		match        string
		iface        string
		wantExternal bool
	}{
		{name: "nested opening bracket excludes caret", match: "Name=eth[[!0]", iface: "eth^"},
		{name: "nested opening bracket includes zero", match: "Name=eth[[!0]", iface: "eth0", wantExternal: true},
		{name: "negative literal closing bracket class", match: "Name=!eth[]0]", iface: "eth0"},
		{name: "literal closing bracket class", match: "Name=eth[]0]", iface: "eth0", wantExternal: true},
		{name: "negative class with literal closing bracket", match: "Name=eth[!]]", iface: "eth0", wantExternal: true},
		{name: "leading hyphen class", match: "Name=eth[-0]", iface: "eth-", wantExternal: true},
		{name: "trailing hyphen class", match: "Name=eth[0-]", iface: "eth-", wantExternal: true},
		{name: "invalid positive range", match: "Name=eth[z-a]", iface: "eth0"},
		{name: "invalid negative range uses all-negative default", match: "Name=!eth[z-a]", iface: "eth0", wantExternal: true},
		{name: "POSIX digit class", match: "Name=eth[[:digit:]]", iface: "eth0", wantExternal: true},
		{name: "unmatched bracket literal does not match", match: "Name=eth[", iface: "eth0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubNetworkctl9886(t)
			dir := t.TempDir()
			writeExternalNetwork12135(t, dir, "20-external.network", "[Match]\n"+tc.match+"\n\n[Network]\nDHCP=yes\n")
			matches := FindExternallyManaged(dir)
			if got := matches.Matches(tc.iface, ""); got != tc.wantExternal {
				t.Fatalf("Matches(%q) = %v, want %v", tc.iface, got, tc.wantExternal)
			}
			if got := matches.MatchesForApply(tc.iface, ""); got != tc.wantExternal {
				t.Fatalf("MatchesForApply(%q) = %v, want %v", tc.iface, got, tc.wantExternal)
			}
			if err := NewInDir(dir).Apply([]InterfaceConfig{{Name: tc.iface, Unmanaged: true}}); err != nil {
				t.Fatal(err)
			}
			xpf, err := os.ReadFile(filepath.Join(dir, filePrefix+tc.iface+".network"))
			if tc.wantExternal {
				if !os.IsNotExist(err) {
					t.Fatalf("external match must suppress xpf's always-down unit; got %q, err %v", xpf, err)
				}
			} else if err != nil || !strings.Contains(string(xpf), "ActivationPolicy=always-down") {
				t.Fatalf("non-match must retain xpf's always-down unit; got %q, err %v", xpf, err)
			}
		})
	}
}

func TestFnmatchInterfaceNamePatternEscapes12135(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		value   string
		want    bool
	}{
		{pattern: `eth\*`, value: "eth*", want: true},
		{pattern: `eth\*`, value: "eth0"},
		{pattern: `eth[\]]`, value: "eth]", want: true},
		{pattern: `eth[\]]`, value: "eth0"},
	} {
		if got := fnmatchInterfaceName(tc.pattern, tc.value); got != tc.want {
			t.Errorf("fnmatchInterfaceName(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
	dir := t.TempDir()
	writeExternalNetwork12135(t, dir, "50-external.network", "[Match]\nName=eth\\*\n")
	matches := FindExternallyManaged(dir)
	if !matches.Matches("eth*", "") {
		t.Fatal("escaped asterisk should match its literal interface name")
	}
	if matches.Matches("eth0", "") {
		t.Fatal("escaped asterisk should not match a wildcard expansion")
	}
}
