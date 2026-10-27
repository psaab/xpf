package networkd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRenderLinkParity17042 pins #17042 (R4-Q43-01): RenderLink is the
// single .link renderer, so its output must be byte-identical to
// generateLink for the equivalent InterfaceConfig — including the full
// property set (MTUBytes/BitsPerSecond/Duplex/Description) the daemon's
// old stripped copies dropped.
func TestRenderLinkParity17042(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec LinkSpec
		ifc  InterfaceConfig
	}{
		{
			name: "original-name full properties",
			spec: LinkSpec{Name: "ge-0-0-1", OriginalName: "enp8s0", MTU: 9000, Speed: "10g", Duplex: "full", Description: "reth member"},
			ifc:  InterfaceConfig{Name: "ge-0-0-1", OriginalName: "enp8s0", MACAddress: "52:54:00:aa:bb:cc", MTU: 9000, Speed: "10g", Duplex: "full", Description: "reth member"},
		},
		{
			name: "mac form",
			spec: LinkSpec{Name: "trust0", MACAddress: "52:54:00:aa:bb:cc"},
			ifc:  InterfaceConfig{Name: "trust0", MACAddress: "52:54:00:aa:bb:cc"},
		},
		{
			name: "auto duplex",
			spec: LinkSpec{Name: "ge-0-0-2", OriginalName: "enp9s0", Duplex: "auto"},
			ifc:  InterfaceConfig{Name: "ge-0-0-2", OriginalName: "enp9s0", MACAddress: "52:54:00:aa:bb:cd", Duplex: "auto"},
		},
		{
			name: "boot minimal",
			spec: LinkSpec{Name: "ge-0-0-3", OriginalName: "enp9s0"},
			ifc:  InterfaceConfig{Name: "ge-0-0-3", OriginalName: "enp9s0", MACAddress: "52:54:00:aa:bb:ce"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RenderLink(tc.spec)
			if err != nil {
				t.Fatalf("RenderLink(%+v): %v", tc.spec, err)
			}
			want := New().generateLink(tc.ifc)
			if got != want {
				t.Fatalf("RenderLink != generateLink:\n got=%q\nwant=%q", got, want)
			}
		})
	}
	// The full-property rendering carries the fields the daemon copies lost.
	got, err := RenderLink(LinkSpec{Name: "ge-0-0-1", OriginalName: "enp8s0", MTU: 9000, Speed: "10g", Duplex: "full"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"MTUBytes=9000\n", "BitsPerSecond=10000000000\n", "Duplex=full\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("RenderLink missing %q:\n%s", want, got)
		}
	}
}

// TestRenderLinkRefusals17042 pins the single guard ladder: both slots,
// glob, negation, confinement and the neither-match refusal.
func TestRenderLinkRefusals17042(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec LinkSpec
		want string
	}{
		{"space target", LinkSpec{Name: "ge 0", OriginalName: "enp9s0"}, "#9886"},
		{"glob target", LinkSpec{Name: "ge*", OriginalName: "enp9s0"}, "#10089"},
		{"negated target", LinkSpec{Name: "!ge-0-0-3", OriginalName: "enp9s0"}, "#15079"},
		{"slash target", LinkSpec{Name: "ge/0", OriginalName: "enp9s0"}, "#9494"},
		{"space original", LinkSpec{Name: "ge-0-0-3", OriginalName: "enp 9s0"}, "#9886"},
		{"glob original", LinkSpec{Name: "ge-0-0-3", OriginalName: "enp*"}, "#10089"},
		{"negated original", LinkSpec{Name: "ge-0-0-3", OriginalName: "!enp9s0"}, "#15079"},
		{"neither match", LinkSpec{Name: "ge-0-0-3"}, "#17042"},
		{"unsafe mac", LinkSpec{Name: "ge-0-0-3", MACAddress: "52:54:00:aa:bb:cc junk"}, "#10718"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RenderLink(tc.spec)
			if err == nil || got != "" {
				t.Fatalf("RenderLink(%+v) = (%q, %v), want refusal", tc.spec, got, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q must mention %q", err, tc.want)
			}
		})
	}
}

// TestWriteUnitIfChanged17042 pins the exported read-compare-write: the
// path is built from FilePrefix, unchanged content reports changed=false,
// and a blocked path fails closed (#2987).
func TestWriteUnitIfChanged17042(t *testing.T) {
	dir := t.TempDir()
	changed, err := WriteUnitIfChanged(dir, "ge-0-0-3", ".link", "body\n")
	if err != nil || !changed {
		t.Fatalf("first WriteUnitIfChanged = (%v, %v), want (true, nil)", changed, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, FilePrefix+"ge-0-0-3.link"))
	if err != nil || string(data) != "body\n" {
		t.Fatalf("written file = (%q, %v)", data, err)
	}
	changed, err = WriteUnitIfChanged(dir, "ge-0-0-3", ".link", "body\n")
	if err != nil || changed {
		t.Fatalf("identical WriteUnitIfChanged = (%v, %v), want (false, nil)", changed, err)
	}
	changed, err = WriteUnitIfChanged(dir, "ge-0-0-3", ".link", "other\n")
	if err != nil || !changed {
		t.Fatalf("changed WriteUnitIfChanged = (%v, %v), want (true, nil)", changed, err)
	}
	if _, err := WriteUnitIfChanged(dir, "ge/0", ".link", "x"); err == nil {
		t.Error("slash name must be refused (#9494 confinement)")
	}
	// Blocked path: a directory where the file belongs fails closed.
	if err := os.Mkdir(filepath.Join(dir, FilePrefix+"ge-0-0-4.link"), 0o755); err != nil {
		t.Fatal(err)
	}
	if changed, err := WriteUnitIfChanged(dir, "ge-0-0-4", ".link", "x"); err == nil || changed {
		t.Errorf("blocked WriteUnitIfChanged = (%v, %v), want (false, error)", changed, err)
	}
}
