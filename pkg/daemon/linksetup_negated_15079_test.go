package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteLinkFileRefusesNegatedOriginalName_15079(t *testing.T) {
	dir := withTempLinkDir(t)
	for _, original := range []string{"!enp9s0", "!!enp9s0", "!x"} {
		wrote, err := writeLinkFile("ge-0-0-3", original)
		if err == nil || wrote {
			t.Fatalf("writeLinkFile(%q) = (%v, %v), want (false, refusal error)", original, wrote, err)
		}
		for _, want := range []string{"OriginalName", "#15079", "leading '!'", "inverts the match list"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q must mention %q", err, want)
			}
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("#15079: refused OriginalName writes must leave no files, found %v", entries)
	}
}

func TestWriteLinkFileAllowsLiteralBangTarget_15079(t *testing.T) {
	dir := withTempLinkDir(t)
	wrote, err := writeLinkFile("!ge-0-0-3", "enp9s0")
	if err != nil || !wrote {
		t.Fatalf("[Link] Name '!' target is non-match syntax and must remain writable: (%v, %v)", wrote, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, linkPrefix+"!ge-0-0-3.link"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "OriginalName=enp9s0") || !strings.Contains(string(data), "Name=!ge-0-0-3") {
		t.Fatalf("literal target '!' was not rendered byte-for-byte: %q", data)
	}
}

func TestWriteLinkFileAllowsNonLeadingBangOriginalName_15079(t *testing.T) {
	dir := withTempLinkDir(t)
	wrote, err := writeLinkFile("ge-0-0-3", "enp9s0!")
	if err != nil || !wrote {
		t.Fatalf("non-leading '!' OriginalName must remain writable: (%v, %v)", wrote, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, linkPrefix+"ge-0-0-3.link"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "OriginalName=enp9s0!") {
		t.Fatalf("non-leading '!' OriginalName was not rendered byte-for-byte: %q", data)
	}
}
