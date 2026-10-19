package config

import (
	"strings"
	"testing"
)

// #15698: `system services dns` was modelled childless (children: nil), so
// the flat-set path collapsed `dns dns-proxy forwarders 1.1.1.1` onto ONE
// leaf node. DeletePath then refused with the #8992 packed-run error, the
// FormatSet round-trip left residue, and a bare `set system services dns`
// leaf beside a braced dns container shadowed the proxy from
// hasDNSProxyChild (FindChild returns the bare leaf first).
//
// RED on pre-fix: SetPath builds leaf [dns-proxy forwarders 1.1.1.1];
// DeletePath errors "ELIDED ... packed together"; bare+proxy tree compiles
// with DNSProxyConfigured=false. GREEN after modelling the subtree and
// iterating FindChildren("dns").

func buildTree15698(t *testing.T, cmds ...string) *ConfigTree {
	t.Helper()
	tree := &ConfigTree{}
	for _, cmd := range cmds {
		path, err := ParseSetCommand(cmd)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", cmd, err)
		}
	}
	return tree
}

func deletePath15698(t *testing.T, tree *ConfigTree, cmd string) {
	t.Helper()
	path, err := ParseSetCommand(cmd)
	if err != nil {
		t.Fatalf("ParseSetCommand(%q): %v", cmd, err)
	}
	if err := tree.DeletePath(path); err != nil {
		t.Fatalf("DeletePath(%q): %v", cmd, err)
	}
}

func TestDNSProxySetDeleteRoundTrip15698(t *testing.T) {
	tree := buildTree15698(t,
		"set system services dns dns-proxy forwarders 1.1.1.1",
		"set system services dns dns-proxy forwarders 8.8.8.8",
		"set system services dns dns-proxy default-domain example.net",
		"set system services dns dns-proxy cache-size 10000",
		"set system services dns dns-proxy interface ge-0/0/0",
	)
	got := tree.FormatSet()
	for _, want := range []string{
		"set system services dns dns-proxy forwarders 1.1.1.1",
		"set system services dns dns-proxy forwarders 8.8.8.8",
		"set system services dns dns-proxy default-domain example.net",
		"set system services dns dns-proxy cache-size 10000",
		"set system services dns dns-proxy interface ge-0/0/0",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("FormatSet missing %q, got:\n%s", want, got)
		}
	}
	// Round-trip: replaying FormatSet must rebuild the identical text.
	replayed := &ConfigTree{}
	for _, line := range strings.Split(strings.TrimSpace(got), "\n") {
		path, err := ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := replayed.SetPath(path); err != nil {
			t.Fatalf("SetPath replay %q: %v", line, err)
		}
	}
	if replayed.FormatSet() != got {
		t.Fatalf("round-trip mismatch:\nfirst:\n%s\nsecond:\n%s", got, replayed.FormatSet())
	}
	// Delete one forwarder, then the whole dns-proxy stanza.
	deletePath15698(t, tree, "delete system services dns dns-proxy forwarders 1.1.1.1")
	after := tree.FormatSet()
	if strings.Contains(after, "1.1.1.1") {
		t.Fatalf("forwarder 1.1.1.1 survived delete:\n%s", after)
	}
	if !strings.Contains(after, "8.8.8.8") {
		t.Fatalf("forwarder 8.8.8.8 lost by sibling delete:\n%s", after)
	}
	deletePath15698(t, tree, "delete system services dns dns-proxy")
	after = tree.FormatSet()
	if strings.Contains(after, "dns-proxy") {
		t.Fatalf("dns-proxy residue after delete:\n%s", after)
	}
	// Deleting dns removes the dns subtree; the empty `services` container
	// still renders its own set line (#9126), like any other container.
	deletePath15698(t, tree, "delete system services dns")
	if out := tree.FormatSet(); strings.Contains(out, "dns") {
		t.Fatalf("dns residue after deleting dns: %q", out)
	}
}

func TestDNSProxyBareSiblingWarning15698(t *testing.T) {
	// Bare `set system services dns` as a leaf beside the braced/flat
	// proxy container: pre-fix FindChild returned the bare leaf and
	// DNSProxyConfigured stayed false, so the unimplemented-runtime
	// warning never fired.
	tree := buildTree15698(t,
		"set system services dns",
		"set system services dns dns-proxy forwarders 1.1.1.1",
	)
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.System.Services == nil || !cfg.System.Services.DNSEnabled {
		t.Fatal("expected DNSEnabled")
	}
	if !cfg.System.Services.DNSProxyConfigured {
		t.Fatal("expected DNSProxyConfigured with bare dns leaf beside proxy container (#15698)")
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "dns-proxy") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected dns-proxy warning, got %v", cfg.Warnings)
	}
}

func TestDNSProxyBareDNSStillWorks15698(t *testing.T) {
	tree := buildTree15698(t, "set system services dns")
	if got := tree.FormatSet(); !strings.Contains(got, "set system services dns") {
		t.Fatalf("bare dns lost: %q", got)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !cfg.System.Services.DNSEnabled || cfg.System.Services.DNSProxyConfigured {
		t.Fatalf("bare dns: DNSEnabled=%v DNSProxyConfigured=%v", cfg.System.Services.DNSEnabled, cfg.System.Services.DNSProxyConfigured)
	}
}
