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
func TestExternalNameLeadingNegationInvertsWholePatternList12135(t *testing.T) {
	dir := t.TempDir()
	writeExternalNetwork12135(t, dir, "50-negative.network", "[Match]\nName=!eth0 eth2\n")
	matches := FindExternallyManaged(dir)
	for _, tc := range []struct {
		name string
		want bool
	}{
		{name: "eth0", want: false},
		{name: "eth2", want: false},
		{name: "eth1", want: true},
		{name: "enp3s0", want: true},
	} {
		if got := matches.Matches(tc.name, ""); got != tc.want {
			t.Errorf("Matches(%q, empty MAC) = %v, want %v", tc.name, got, tc.want)
		}
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

func TestExternalMACAddressRejectsUnsupportedForms12135(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pattern string
		address string
		want    bool
	}{
		{
			name:    "bare hex",
			pattern: "525400aabbcc",
			address: "52:54:00:aa:bb:cc",
		},
		{
			name:    "eight-byte EUI-64",
			pattern: "52-54-00-aa-bb-cc-dd-ee",
			address: "52-54-00-aa-bb-cc-dd-ee",
		},
		{
			name:    "dotted EUI-48",
			pattern: "5254.00aa.bbcc",
			address: "52:54:00:aa:bb:cc",
			want:    true,
		},
		{
			name:    "IPv4",
			pattern: "192.0.2.1",
			address: "192.0.2.1",
			want:    true,
		},
		{
			name:    "IPv6",
			pattern: "2001:db8::1",
			address: "2001:0db8:0:0:0:0:0:1",
			want:    true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeExternalNetwork12135(t, dir, "20-external.network", "[Match]\nMACAddress="+tc.pattern+"\n")
			matches := FindExternallyManaged(dir)
			if got := matches.Matches("eth0", tc.address); got != tc.want {
				t.Errorf("Matches(%q, %q) = %v, want %v", "eth0", tc.address, got, tc.want)
			}
		})
	}
}
