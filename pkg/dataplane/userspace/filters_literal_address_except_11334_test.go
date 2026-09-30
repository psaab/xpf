package userspace

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestFilterSnapshotLiteralAddressExceptFailsClosed11334(t *testing.T) {
	tree := &config.ConfigTree{}
	for _, cmd := range []string{
		"set firewall family inet filter f term t from source-address 10.0.0.0/8 except",
		"set firewall family inet filter f term t then discard",
	} {
		path, err := config.ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	cfg, err := config.CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	terms := buildFirewallFilterSnapshots(cfg)
	if len(terms) != 1 || len(terms[0].Terms) != 1 {
		t.Fatalf("snapshots = %#v, want one filter with one term", terms)
	}
	term := terms[0].Terms[0]
	if !term.FromUnrepresentable {
		t.Fatal("unsupported literal-address except must poison the tolerant filter snapshot (#11334)")
	}
	if term.AddressUnrepresentable {
		t.Fatal("the `except` modifier is unsupported, not a malformed address")
	}
	if len(term.SourceAddresses) != 1 || term.SourceAddresses[0] != "10.0.0.0/8" {
		t.Fatalf("SourceAddresses = %v, want only the representable prefix", term.SourceAddresses)
	}
}
