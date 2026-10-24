package config

import (
	"strings"
	"testing"
)

// #16077 (MGMT-16): the tolerant AAA warning was transient only — it
// lived in cfg.Warnings, whose sole post-compile consumer is one
// boot-time slog.Warn loop, while `show system alarms` recomputes from
// ValidateConfig + tolerated-stanza helpers and never re-derived the
// AAA condition. A legacy persisted / peer-synced AAA tree therefore
// ran local-only auth with no persistent signal after boot. The fix
// retains the leaf identities on the compiled Config and re-derives
// the alarm from that marker.

func TestUnimplementedAAALeavesRetainedOnLenientCompile16077(t *testing.T) {
	tree := aaaTree10831(t, "set system radius-server 192.0.2.10 secret s3cr3t-16077")
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if len(cfg.UnimplementedAAALeaves) != 1 || cfg.UnimplementedAAALeaves[0] != "radius-server" {
		t.Fatalf("UnimplementedAAALeaves = %v, want [radius-server]", cfg.UnimplementedAAALeaves)
	}
	for _, leaf := range cfg.UnimplementedAAALeaves {
		if strings.Contains(leaf, "s3cr3t-16077") {
			t.Fatalf("retained leaf leaked the AAA secret: %q", leaf)
		}
	}
	alarms := UnimplementedAAAWarnings(cfg)
	if len(alarms) != 1 {
		t.Fatalf("UnimplementedAAAWarnings = %v, want one line", alarms)
	}
	for _, want := range []string{"local-only authentication", "radius-server", "tolerant path"} {
		if !strings.Contains(alarms[0], want) {
			t.Errorf("alarm %q does not contain %q", alarms[0], want)
		}
	}
	if strings.Contains(alarms[0], "s3cr3t-16077") {
		t.Fatalf("alarm leaked the AAA secret: %q", alarms[0])
	}
}

func TestUnimplementedAAALeavesStrictAndCleanStayEmpty16077(t *testing.T) {
	// Strict compile refuses outright and retains nothing.
	if _, err := CompileConfig(aaaTree10831(t, "set system tacplus-server 192.0.2.20 secret x")); err == nil {
		t.Fatal("strict compile accepted tacplus-server")
	}
	if got := UnimplementedAAAWarnings(nil); got != nil {
		t.Fatalf("nil config alarms = %v, want nil", got)
	}
	clean, err := CompileConfigLenient(aaaTree10831(t, "set system host-name fw1"))
	if err != nil {
		t.Fatalf("clean lenient compile: %v", err)
	}
	if len(clean.UnimplementedAAALeaves) != 0 {
		t.Fatalf("clean config retained %v", clean.UnimplementedAAALeaves)
	}
	if got := UnimplementedAAAWarnings(clean); len(got) != 0 {
		t.Fatalf("clean config alarms = %v, want none", got)
	}
}

func TestUnimplementedAAALeavesMultipleAndDeduped16077(t *testing.T) {
	tree := aaaTree10831(t,
		"set system radius-server 192.0.2.10 secret x",
		"set system tacplus-server 192.0.2.20 secret y",
		"set system radius-server 192.0.2.11 secret z",
		"set system authentication-order radius",
	)
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if len(cfg.UnimplementedAAALeaves) != 3 {
		t.Fatalf("UnimplementedAAALeaves = %v, want 3 deduped leaves", cfg.UnimplementedAAALeaves)
	}
	if got := UnimplementedAAAWarnings(cfg); len(got) != 3 {
		t.Fatalf("alarms = %v, want 3 lines", got)
	}
}

// #16077 fold: duplicate `system` roots merge in author order, and each
// root's compileSystem used to append its leaves straight to the marker,
// so the same leaf authored under two roots produced duplicate alarms.
// compileSections now stages per-root leaves and merges them deduped.
func TestUnimplementedAAALeavesDedupedAcrossDuplicateSystemRoots16077(t *testing.T) {
	tree, errs := NewParser("system {\n    radius-server 192.0.2.10 {\n        secret x;\n    }\n}\nsystem {\n    tacplus-server 192.0.2.20 {\n        secret y;\n    }\n    radius-server 192.0.2.11 {\n        secret z;\n    }\n}\n").Parse()
	if len(errs) != 0 {
		t.Fatalf("NewParser: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("lenient compile of duplicate system roots: %v", err)
	}
	want := []string{"radius-server", "tacplus-server"}
	if len(cfg.UnimplementedAAALeaves) != len(want) {
		t.Fatalf("UnimplementedAAALeaves = %v, want %v (deduped across roots)", cfg.UnimplementedAAALeaves, want)
	}
	for i, leaf := range want {
		if cfg.UnimplementedAAALeaves[i] != leaf {
			t.Fatalf("UnimplementedAAALeaves = %v, want %v in author order", cfg.UnimplementedAAALeaves, want)
		}
	}
	if got := UnimplementedAAAWarnings(cfg); len(got) != len(want) {
		t.Fatalf("alarms = %v, want %d lines, no duplicates", got, len(want))
	}
}
