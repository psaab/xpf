package config_test

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #6875: `security log stream <name> source-interface <x>` committed clean and
// did nothing. `source-interface` was modelled only under `security log` (top
// level); the `stream` subtree is OPEN-WORLD, so the per-stream spelling parsed
// as an unmodelled keyword, `SyslogStream` had no field to receive it, and
// nothing read it. The operator saw a clean commit and the stream sourced from
// the global setting or from nothing.
//
// Disposition taken: ACCEPT AND IMPLEMENT (option 2 of the issue). The apply
// path already resolved a per-stream `source-address` with a global fallback,
// so this is a bounded thread rather than new machinery — which is what made
// option 2 preferable to marking the leaf inert. Rejecting at commit was
// declined because it is real Junos syntax and would break importing configs
// that carry it.
func TestStreamSourceInterfaceCompiles_6875(t *testing.T) {
	cfg := compile6875(t,
		"set security log mode stream",
		"set security log stream s host 192.0.2.1",
		"set security log stream s source-interface reth1.100",
	)
	s := cfg.Security.Log.Streams["s"]
	if s == nil {
		t.Fatalf("stream s did not compile")
	}
	if s.SourceInterface != "reth1.100" {
		t.Errorf("SourceInterface = %q, want reth1.100", s.SourceInterface)
	}
}

// The leaf must be VALIDATED now, not merely stored. Before #6875 it was
// absorbed by the open-world subtree, so a malformed value could not be
// rejected — there was nothing to reject it against. This is the half that
// distinguishes "modelled" from "has a field": a struct field alone would
// accept `reth1.abc` exactly as silently as the open-world path did.
func TestStreamSourceInterfaceIsValidated_6875(t *testing.T) {
	for _, bad := range []struct{ name, cmd string }{
		{"non-numeric unit", "set security log stream s source-interface reth1.abc"},
		{"unit out of range", "set security log stream s source-interface ge-0-0-0.99999"},
	} {
		t.Run(bad.name, func(t *testing.T) {
			tree := setTree6875(t,
				"set security log mode stream",
				"set security log stream s host 192.0.2.1",
				bad.cmd,
			)
			if err := config.SchemaValidate(tree, nil); err == nil {
				t.Errorf("%q must be REJECTED at commit — the same validator the "+
					"top-level source-interface uses now applies per stream (#6875)", bad.cmd)
			}
		})
	}
}

// The precedence chain, which is the part a reviewer should argue with:
//
//	source-address  >  source-interface  >  global source-interface
//
// An explicitly configured address beats one derived from an interface, and
// both beat the global fallback. Asserting only the middle rung would leave
// either end free to change.
func TestStreamSourceInterfacePrecedence_6875(t *testing.T) {
	// An interface whose unit carries a primary address, so resolution has
	// something real to return. Without this the "resolves" cases below would
	// pass for the wrong reason — an empty resolution falls through to the
	// global, which is indistinguishable from the global winning outright.
	base := []string{
		"set security log mode stream",
		// #15731: reth1 unit 100 must be a tagged unit — the #15034 gate
		// correctly rejects a non-zero untagged unit on an untagged parent,
		// and reth1.100 is only a real device under vlan-tagging + vlan-id.
		// The tagged form is the #15034 control shape; the address and the
		// source-interface resolution under test are unchanged.
		"set interfaces reth1 vlan-tagging",
		"set interfaces reth1 unit 100 vlan-id 100",
		// `primary` is load-bearing and not decoration: ResolveSyslogSourceAddr
		// reads ONLY unit.PrimaryAddress from config, and a plain `address`
		// line populates Addresses while leaving PrimaryAddress empty. Measured
		// — without it both resolutions below return "" and the cells would
		// pass or fail for a reason unrelated to #6875. This is a property of
		// the EXISTING top-level feature, not something #6875 introduces.
		"set interfaces reth1 unit 100 family inet address 10.9.9.9/24 primary",
		"set interfaces reth2 unit 0 family inet address 10.8.8.8/24 primary",
		"set security log source-interface reth2.0",
	}

	t.Run("source-interface resolves when no source-address", func(t *testing.T) {
		cfg := compile6875(t, append(append([]string{}, base...),
			"set security log stream s host 192.0.2.1",
			"set security log stream s source-interface reth1.100",
		)...)
		if got := config.ResolveSyslogSourceAddr(cfg, cfg.Security.Log.Streams["s"].SourceInterface); got != "10.9.9.9" {
			t.Errorf("per-stream source-interface resolved to %q, want 10.9.9.9", got)
		}
	})

	t.Run("source-address wins over source-interface", func(t *testing.T) {
		cfg := compile6875(t, append(append([]string{}, base...),
			"set security log stream s host 192.0.2.1",
			"set security log stream s source-address 10.7.7.7",
			"set security log stream s source-interface reth1.100",
		)...)
		s := cfg.Security.Log.Streams["s"]
		if s.SourceAddress != "10.7.7.7" {
			t.Errorf("SourceAddress = %q, want 10.7.7.7", s.SourceAddress)
		}
		// Both are present in the typed config; the apply path is what ranks
		// them, and it consults SourceAddress first. Asserting both survive
		// compilation is what makes that ranking meaningful — if the compiler
		// dropped one, the apply-side precedence would be untestable.
		if s.SourceInterface != "reth1.100" {
			t.Errorf("SourceInterface = %q, want reth1.100 — both must survive "+
				"compilation or the apply-path precedence has nothing to rank",
				s.SourceInterface)
		}
	})

	t.Run("global remains the fallback when the stream sets neither", func(t *testing.T) {
		cfg := compile6875(t, append(append([]string{}, base...),
			"set security log stream s host 192.0.2.1",
		)...)
		s := cfg.Security.Log.Streams["s"]
		if s.SourceAddress != "" || s.SourceInterface != "" {
			t.Fatalf("stream should carry neither; got addr=%q iface=%q",
				s.SourceAddress, s.SourceInterface)
		}
		if got := config.ResolveSyslogSourceAddr(cfg, cfg.Security.Log.SourceInterface); got != "10.8.8.8" {
			t.Errorf("global source-interface resolved to %q, want 10.8.8.8", got)
		}
	})
}

func setTree6875(t *testing.T, cmds ...string) *config.ConfigTree {
	t.Helper()
	tree := &config.ConfigTree{}
	for _, c := range cmds {
		path, err := config.ParseSetCommand(c)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", c, err)
		}
		if err := tree.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", c, err)
		}
	}
	return tree
}

func compile6875(t *testing.T, cmds ...string) *config.Config {
	t.Helper()
	cfg, err := config.CompileConfig(setTree6875(t, cmds...))
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return cfg
}
