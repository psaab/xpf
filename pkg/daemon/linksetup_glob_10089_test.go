package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteLinkFileRefusesGlobOriginalName_10089(t *testing.T) {
	dir := withTempLinkDir(t)
	for _, tc := range []struct {
		name, original, token string
	}{
		{"star", "ge*", "*"},
		{"question", "ge?", "?"},
		{"class", "ge[0-9]", "["},
		{"close-class", "ge]0", "]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrote, err := writeLinkFile("ge-0-0-3", tc.original)
			if err == nil || wrote {
				t.Fatalf("writeLinkFile(%q) = (%v, %v), want (false, refusal error)", tc.original, wrote, err)
			}
			for _, want := range []string{"OriginalName", "#10089", "glob metacharacter", `"` + tc.token + `"`} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q must mention %q", err, want)
				}
			}
		})
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("#10089: refused OriginalName writes must leave no files, found %v", entries)
	}
}

func TestWriteLinkFileAllowsLiteralGlobTarget_10089(t *testing.T) {
	dir := withTempLinkDir(t)
	wrote, err := writeLinkFile("ge*", "enp9s0")
	if err != nil || !wrote {
		t.Fatalf("[Link] Name glob target is non-match syntax and must remain writable: (%v, %v)", wrote, err)
	}
	data, err := os.ReadFile(filepath.Join(dir, linkPrefix+"ge*.link"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "OriginalName=enp9s0") || !strings.Contains(string(data), "Name=ge*") {
		t.Fatalf("literal target glob was not rendered byte-for-byte: %q", data)
	}
}
