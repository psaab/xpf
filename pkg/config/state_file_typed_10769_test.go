package config

import (
	"strings"
	"testing"
)

// #10769 d05-F6: `system dataplane state-file` was an untyped `{args: 1}`
// leaf, so any string committed and reached the factory-reset helper sweep
// verbatim — including aliases of the reset gates (/etc/xpf markers,
// handoff flag) and OS identity (/etc/machine-id) that the sweep would
// then delete instead of helper state. Typing it moves those from a
// silent gate/identity deletion to a commit-check error.

func TestValidateStateFilePath_10769(t *testing.T) {
	good := []string{
		"/var/lib/xpf/userspace-dp.json",
		"/run/xpf/userspace-dp.json",
		"/srv/xpf-dp/state.json",
	}
	for _, raw := range good {
		if err := ValidateStateFilePath(raw, nil); err != nil {
			t.Errorf("ValidateStateFilePath(%q) = %v, want accepted", raw, err)
		}
	}

	bad := []struct {
		raw     string
		wantSub string
	}{
		{"", "missing value"},
		{"userspace-dp.json", "must be absolute"},
		{"var/lib/xpf/dp.json", "must be absolute"},
		{"/var/lib/xpf/", "not a directory"},
		{"/", "not a directory"},
		{"/var//lib/xpf/dp.json", "empty component"},
		{"/var/lib/xpf/../../etc/shadow", `".."`},
		{"/var/./lib/xpf/dp.json", `"."`},
		{"/var/lib/xpf/dp\x00.json", "control characters"},
		{"/etc/machine-id", "reserved"},
		{"/var/lib/dbus/machine-id", "reserved"},
		{"/etc/hostname", "reserved"},
		{"/etc/hosts", "reserved"},
		{"/etc/resolv.conf", "reserved"},
		{"/etc/passwd", "reserved"},
		{"/etc/shadow", "reserved"},
		{"/etc/group", "reserved"},
		{"/etc/gshadow", "reserved"},
		{"/etc/xpf/.day0-config-applied", "reserved"},
		{"/etc/xpf/.reset-handoff", "reserved"},
		{"/etc/xpf/xpf.conf", "reserved"},
		{"/etc/xpf/.configdb/active.json", "reserved"},
		{"/srv/xpf/.day0-config-applied", "reserved"},
		{"/srv/xpf/.reset-handoff", "reserved"},
	}
	for _, tc := range bad {
		err := ValidateStateFilePath(tc.raw, nil)
		if err == nil {
			t.Errorf("ValidateStateFilePath(%q) = nil, want rejection", tc.raw)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("ValidateStateFilePath(%q) error = %q, want it to mention %q", tc.raw, err, tc.wantSub)
		}
	}

	atLimit := "/" + strings.Repeat("a", maxStateFilePathLen-1)
	if got := len(atLimit); got != maxStateFilePathLen {
		t.Fatalf("fixture length = %d, want %d", got, maxStateFilePathLen)
	}
	if err := ValidateStateFilePath(atLimit, nil); err != nil {
		t.Errorf("ValidateStateFilePath(at-limit) = %v, want accepted", err)
	}
	if err := ValidateStateFilePath(atLimit+"a", nil); err == nil {
		t.Error("ValidateStateFilePath(over-limit) = nil, want rejection")
	}
}

func TestStateFileTypedLeafGate_10769(t *testing.T) {
	build := func(t *testing.T, value string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		path, err := ParseSetCommand("set system dataplane state-file " + value)
		if err != nil {
			t.Fatalf("ParseSetCommand: %v", err)
		}
		tree.SetPath(path)
		return tree
	}

	t.Run("valid path commits and compiles", func(t *testing.T) {
		tree := build(t, "/var/lib/xpf/userspace-dp.json")
		if err := SchemaValidate(tree, nil); err != nil {
			t.Fatalf("SchemaValidate: %v", err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if cfg.System.UserspaceDataplane == nil {
			t.Fatal("compiled config has no userspace dataplane stanza")
		}
		if got := cfg.System.UserspaceDataplane.StateFile; got != "/var/lib/xpf/userspace-dp.json" {
			t.Fatalf("compiled StateFile = %q, want /var/lib/xpf/userspace-dp.json", got)
		}
	})

	for _, bad := range []string{"dp.json", "/etc/machine-id", "/etc/xpf/.reset-handoff"} {
		t.Run("rejected: "+bad, func(t *testing.T) {
			tree := build(t, bad)
			if err := SchemaValidate(tree, nil); err == nil {
				t.Fatalf("SchemaValidate accepted state-file %q, want a commit-check error", bad)
			}
		})
	}
}

func TestHelperStateFileSocketEqualityStrict_10769(t *testing.T) {
	build := func(t *testing.T, socket, state string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		for _, line := range []string{
			"set system dataplane control-socket " + socket,
			"set system dataplane state-file " + state,
		} {
			path, err := ParseSetCommand(line)
			if err != nil {
				t.Fatalf("ParseSetCommand: %v", err)
			}
			tree.SetPath(path)
		}
		return tree
	}

	t.Run("equal paths rejected", func(t *testing.T) {
		tree := build(t, "/run/xpf/dp.sock", "/run/xpf/dp.sock")
		if _, err := CompileConfig(tree); err == nil {
			t.Fatal("state-file equal to control-socket must fail strict commit")
		} else if !strings.Contains(err.Error(), "control-socket") {
			t.Fatalf("strict error must name the control socket, got %v", err)
		}
	})

	t.Run("distinct paths accepted", func(t *testing.T) {
		tree := build(t, "/run/xpf/dp.sock", "/var/lib/xpf/dp-state.json")
		if _, err := CompileConfig(tree); err != nil {
			t.Fatalf("distinct paths must compile: %v", err)
		}
	})
}
