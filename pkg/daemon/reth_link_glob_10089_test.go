package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixRethLinkFileRefusesGlobKernelName_10089(t *testing.T) {
	dir := withTempLinkDir(t)
	for _, tc := range []struct {
		name, kernelName, token string
	}{
		{"star", "ge*", "*"},
		{"question", "ge?", "?"},
		{"class", "ge[0-9]", "["},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// #17042: a refusal is now a returned error, not a Warn-only skip.
			if err := fixRethLinkFile("ge-0-0-3", tc.kernelName); err == nil {
				t.Fatalf("#10089: fixRethLinkFile(%q) = nil, want refusal error", tc.kernelName)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("#10089: refused RETH OriginalName %q wrote files: %v", tc.kernelName, entries)
			}
		})
	}
}

func TestFixRethLinkFileWritesCleanKernelName_10089(t *testing.T) {
	dir := withTempLinkDir(t)
	if err := fixRethLinkFile("ge-0-0-3", "enp9s0"); err != nil {
		t.Fatalf("fixRethLinkFile(clean): %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, linkPrefix+"ge-0-0-3.link"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "OriginalName=enp9s0") {
		t.Fatalf("clean RETH OriginalName was not rendered: %q", data)
	}
}
