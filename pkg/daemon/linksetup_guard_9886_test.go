package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteLinkFileRefusesUnsafeNames_9886 pins the #9886 guard at the second
// .link writer: writeLinkFile must refuse a render-unsafe target or
// OriginalName BEFORE any mutation — no file, loud error — because both slots
// interpolate raw ([Link] Name= plus the file name, [Match] OriginalName=).
func TestWriteLinkFileRefusesUnsafeNames_9886(t *testing.T) {
	dir := withTempLinkDir(t)
	for _, tc := range []struct {
		name, target, original, want string
	}{
		{"space target", "ge 0", "enp9s0", "refusing .link target name"},
		{"tab target", "ge\t0", "enp9s0", "refusing .link target name"},
		{"control target", "ge\x010", "enp9s0", "refusing .link target name"},
		{"line-continuation target", "ge-0-0-3\\", "enp9s0", "line-continuation backslash"},
		{"empty target", "", "enp9s0", "refusing .link target name"},
		{"space original", "ge-0-0-3", "enp 9s0", "refusing .link OriginalName"},
		{"control original", "ge-0-0-3", "enp\x019s0", "refusing .link OriginalName"},
		{"line-continuation original", "ge-0-0-3", "enp9s0\\", "line-continuation backslash"},
		{"empty original", "ge-0-0-3", "", "refusing .link OriginalName"},
	} {
		wrote, err := writeLinkFile(tc.target, tc.original)
		if err == nil || wrote {
			t.Errorf("%s: writeLinkFile(%q, %q) = (%v, %v), want (false, refusal error)",
				tc.name, tc.target, tc.original, wrote, err)
			continue
		}
		for _, want := range []string{tc.want, "#9886"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: error must mention %q, got %v", tc.name, want, err)
			}
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("#9886: refused writes must leave no files, found %v", entries)
	}

	// Control: clean names still write byte-exact content.
	wrote, err := writeLinkFile("ge-0-0-3", "enp9s0")
	if err != nil || !wrote {
		t.Fatalf("clean writeLinkFile = (%v, %v), want (true, nil)", wrote, err)
	}
	got, err := os.ReadFile(filepath.Join(dir, linkPrefix+"ge-0-0-3.link"))
	if err != nil {
		t.Fatal(err)
	}
	want := "# Managed by xpfd — do not edit\n[Match]\nOriginalName=enp9s0\n\n[Link]\nName=ge-0-0-3"
	if string(got) != want {
		t.Fatalf("clean .link content differs:\n got=%q\nwant=%q", got, want)
	}
}

// TestWriteDeviceMapLinkFileRefusesUnsafeTarget_9886 covers the tolerant
// device-map caller explicitly: a poisoned logical name that survived to the
// daemon (e.g. a retained tree that predates the compile gate) must not land
// a .link — the guard fires inside writeDeviceMapLinkFile's shared writer.
func TestWriteDeviceMapLinkFileRefusesUnsafeTarget_9886(t *testing.T) {
	dir := withTempLinkDir(t)
	wrote, err := writeDeviceMapLinkFile("ge 0", "enp9s0", nil, nil)
	if err == nil || wrote {
		t.Fatalf("writeDeviceMapLinkFile(poisoned) = (%v, %v), want (false, refusal error)", wrote, err)
	}
	if !strings.Contains(err.Error(), "#9886") {
		t.Fatalf("error must mention #9886, got %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("#9886: refused write must leave no files, found %v", entries)
	}
}
