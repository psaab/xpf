package config

import (
	"strings"
	"testing"
)

// #5839: `system dataplane control-socket` was an untyped `{args: 1}` leaf, so
// any string committed and reached the dataplane verbatim — including a
// relative path (resolved against whatever working directory the daemon and the
// helper each hold), a `..` traversal (the path is handed to a stale-socket
// unlink at every bring-up), and a path over the AF_UNIX sun_path limit (which
// can never bind). Typing it moves those from an opaque runtime bring-up
// failure to a commit-check error.

func TestValidateUnixSocketPath_5839(t *testing.T) {
	good := []string{
		"/run/xpf/userspace-dp.sock",
		"/tmp/xpf-userspace-dp/control.sock",
		"/var/run/xpf/dp-0.sock",
	}
	for _, raw := range good {
		if err := ValidateUnixSocketPath(raw); err != nil {
			t.Errorf("ValidateUnixSocketPath(%q) = %v, want accepted", raw, err)
		}
	}

	bad := []struct {
		raw     string
		wantSub string
	}{
		{"", "missing value"},
		{"userspace-dp.sock", "must be absolute"},
		{"run/xpf/dp.sock", "must be absolute"},
		{"/run/xpf/../../etc/shadow", `".."`},
		{"/run/./xpf/dp.sock", `"."`},
		{"/run/xpf/", "not a directory"},
		{"/", "not a directory"},
		{"/run//xpf/dp.sock", "empty component"},
		{"/run/xpf/dp\x00.sock", "control characters"},
		{"/" + strings.Repeat("a", 107) + "/dp.sock", "sun_path limit"},
	}
	for _, tc := range bad {
		err := ValidateUnixSocketPath(tc.raw)
		if err == nil {
			t.Errorf("ValidateUnixSocketPath(%q) = nil, want rejection", tc.raw)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("ValidateUnixSocketPath(%q) error = %q, want it to mention %q", tc.raw, err, tc.wantSub)
		}
	}

	// The boundary is the sun_path limit itself, not an approximation of it:
	// 107 octets binds, 108 does not.
	atLimit := "/" + strings.Repeat("a", maxUnixSocketPathLen-1)
	if got := len(atLimit); got != maxUnixSocketPathLen {
		t.Fatalf("fixture length = %d, want %d", got, maxUnixSocketPathLen)
	}
	if err := ValidateUnixSocketPath(atLimit); err != nil {
		t.Errorf("ValidateUnixSocketPath(<%d octets>) = %v, want accepted", maxUnixSocketPathLen, err)
	}
	if err := ValidateUnixSocketPath(atLimit + "a"); err == nil {
		t.Errorf("ValidateUnixSocketPath(<%d octets>) = nil, want rejection", maxUnixSocketPathLen+1)
	}
}

// TestControlSocketTypedLeafGate_5839 drives the value through the same two
// steps a commit takes — SchemaValidate then the compiler — so the leaf is
// pinned as WIRED, not merely as a validator that exists.
func TestControlSocketTypedLeafGate_5839(t *testing.T) {
	build := func(t *testing.T, value string) *ConfigTree {
		t.Helper()
		tree := &ConfigTree{}
		path, err := ParseSetCommand("set system dataplane control-socket " + value)
		if err != nil {
			t.Fatalf("ParseSetCommand: %v", err)
		}
		tree.SetPath(path)
		return tree
	}

	t.Run("valid path commits and compiles", func(t *testing.T) {
		tree := build(t, "/run/xpf/userspace-dp.sock")
		if err := SchemaValidate(tree); err != nil {
			t.Fatalf("SchemaValidate: %v", err)
		}
		cfg, err := CompileConfig(tree)
		if err != nil {
			t.Fatalf("CompileConfig: %v", err)
		}
		if cfg.System.UserspaceDataplane == nil {
			t.Fatal("compiled config has no userspace dataplane stanza")
		}
		if got := cfg.System.UserspaceDataplane.ControlSocket; got != "/run/xpf/userspace-dp.sock" {
			t.Fatalf("compiled ControlSocket = %q, want /run/xpf/userspace-dp.sock", got)
		}
	})

	for _, bad := range []string{"userspace-dp.sock", "/run/xpf/../../etc/shadow"} {
		t.Run("rejected: "+bad, func(t *testing.T) {
			tree := build(t, bad)
			if err := SchemaValidate(tree); err == nil {
				t.Fatalf("SchemaValidate accepted control-socket %q, want a commit-check error", bad)
			}
		})
	}
}
