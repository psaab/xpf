package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// #14593: systemd ignores a .network whose effective [Match] is empty
// ("No valid settings found in the [Match] section, ignoring file").
// xpf must not treat it as match-all: Matches/MatchesForApply are false
// and Apply still writes the always-down unit for unmanaged NICs.
// Explicit Name=* remains the match-all spelling.
func TestEmptyEffectiveMatchIsIgnored14593(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "bare empty match", body: "[Match]\n\n[Network]\nDHCP=yes\n"},
		{name: "empty name resets", body: "[Match]\nName=eth0\nName=\n\n[Network]\nDHCP=yes\n"},
		{name: "only invalid MAC", body: "[Match]\nMACAddress=invalid\n\n[Network]\nDHCP=yes\n"},
		{name: "invalid MAC after name reset", body: "[Match]\nName=eth0\nName=\nMACAddress=invalid\n\n[Network]\nDHCP=yes\n"},
		{name: "empty MAC", body: "[Match]\nMACAddress=\n\n[Network]\nDHCP=yes\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubNetworkctl9886(t)
			dir := t.TempDir()
			writeExternalNetwork12135(t, dir, "20-external.network", tc.body)
			matches := FindExternallyManaged(dir)
			if matches.Matches("eth0", "52:54:00:aa:bb:cc") {
				t.Errorf("Matches must be false for empty effective [Match] %q", tc.body)
			}
			if matches.MatchesForApply("eth0", "52:54:00:aa:bb:cc") {
				t.Errorf("MatchesForApply must be false for empty effective [Match] %q", tc.body)
			}
			if err := NewInDir(dir).Apply([]InterfaceConfig{{Name: "eth0", MACAddress: "52:54:00:aa:bb:cc", Unmanaged: true}}); err != nil {
				t.Fatal(err)
			}
			xpf, err := os.ReadFile(filepath.Join(dir, filePrefix+"eth0.network"))
			if err != nil || !strings.Contains(string(xpf), "ActivationPolicy=always-down") {
				t.Fatalf("empty-match external file must not suppress always-down unit; got %q, err %v", xpf, err)
			}
		})
	}
	t.Run("explicit Name star still matches all", func(t *testing.T) {
		stubNetworkctl9886(t)
		dir := t.TempDir()
		writeExternalNetwork12135(t, dir, "20-external.network", "[Match]\nName=*\n\n[Network]\nDHCP=yes\n")
		matches := FindExternallyManaged(dir)
		if !matches.Matches("eth0", "") || !matches.MatchesForApply("eth0", "") {
			t.Fatal("Name=* must still match all interfaces")
		}
		if err := NewInDir(dir).Apply([]InterfaceConfig{{Name: "eth0", Unmanaged: true}}); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(dir, filePrefix+"eth0.network")); !os.IsNotExist(err) {
			t.Fatalf("Name=* must suppress always-down unit; stat err=%v", err)
		}
	})
	// Control: a valid Name rule still matches (non-vacuous Apply).
	t.Run("control valid name matches", func(t *testing.T) {
		dir := t.TempDir()
		writeExternalNetwork12135(t, dir, "20-external.network", "[Match]\nName=eth0\n")
		if !FindExternallyManaged(dir).Matches("eth0", "") {
			t.Fatal("Name=eth0 control must match eth0")
		}
	})
}
