package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFixRethLinkFileRefusesNegatedKernelName_15079(t *testing.T) {
	dir := withTempLinkDir(t)
	for _, kernelName := range []string{"!enp9s0", "!!enp9s0", "!x"} {
		// #17042: a refusal is now a returned error, not a Warn-only skip.
		if err := fixRethLinkFile("ge-0-0-3", kernelName); err == nil {
			t.Fatalf("#15079: fixRethLinkFile(%q) = nil, want refusal error", kernelName)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(entries) != 0 {
			t.Fatalf("#15079: refused RETH OriginalName %q wrote files: %v", kernelName, entries)
		}
	}
}

func TestFixRethLinkFileAllowsNonLeadingBangKernelName_15079(t *testing.T) {
	dir := withTempLinkDir(t)
	if err := fixRethLinkFile("ge-0-0-3", "enp9s0!"); err != nil {
		t.Fatalf("fixRethLinkFile(non-leading bang): %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, linkPrefix+"ge-0-0-3.link"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "OriginalName=enp9s0!") {
		t.Fatalf("non-leading '!' RETH OriginalName was not rendered: %q", data)
	}
}
