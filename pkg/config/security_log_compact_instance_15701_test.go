package config

import (
	"strings"
	"testing"
)

// #15701 (V16-03): compileLog used first-wins FindChild for the top-level
// mode/format/source-interface/source-address leaves, and every reader of a
// named stream/profile instance dropped the compact named-instance body
// `stream { <name> ... }` / `profile { <name> ... }` (the whole body packed
// onto the instance sub-node's Keys, e.g. `s1 host <addr> port 70000`),
// bypassing the strict #3349 port gate, the #3350 tls-profile gate, and the
// #2008 profile stream-name cross-reference for that spelling.
//
// Pre-fix (measured): duplicate `mode` kept the FIRST value; a compact
// stream compiled host-less (dropped), its invalid port / tls-profile never
// gated; a compact profile's dangling stream-name compiled clean.

func compileLogText15701(t *testing.T, text string) (*Config, error) {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return CompileConfig(tree)
}

func compileLogTextLenient15701(t *testing.T, text string) (*Config, error) {
	t.Helper()
	tree, errs := NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	return CompileConfigLenient(tree)
}

func TestSecurityLogDuplicateLeafLastWins15701(t *testing.T) {
	cfg, err := compileLogText15701(t, `security {
		log {
			mode stream;
			mode event;
			format syslog;
			format binary;
			source-interface fxp0;
			source-interface ge-0/0/0;
			source-address 192.0.2.1;
			source-address 192.0.2.2;
		}
	}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.Security.Log.Mode != "event" {
		t.Errorf("Mode = %q, want event (last wins)", cfg.Security.Log.Mode)
	}
	if cfg.Security.Log.Format != "binary" {
		t.Errorf("Format = %q, want binary (last wins)", cfg.Security.Log.Format)
	}
	if cfg.Security.Log.SourceInterface != "ge-0/0/0" {
		t.Errorf("SourceInterface = %q, want ge-0/0/0 (last wins)", cfg.Security.Log.SourceInterface)
	}
	if cfg.Security.Log.SourceAddress != "192.0.2.2" {
		t.Errorf("SourceAddress = %q, want 192.0.2.2 (last wins)", cfg.Security.Log.SourceAddress)
	}
}

// Compact named-instance stream: the valid spelling must compile as
// authored (not silently dropped), and the invalid spellings must fail
// closed through the same strict gates as the named/braced spellings.
func TestSecurityLogCompactStreamCompiles15701(t *testing.T) {
	cfg, err := compileLogText15701(t, `security {
		log {
			stream { s1 host 192.0.2.10 port 5514 category policy; }
		}
	}`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	s := cfg.Security.Log.Streams["s1"]
	if s == nil {
		t.Fatalf("compact stream s1 dropped: streams=%v", cfg.Security.Log.Streams)
	}
	if s.Host != "192.0.2.10" || s.Port != 5514 || s.Category != "policy" {
		t.Errorf("stream = %+v, want host=192.0.2.10 port=5514 category=policy", s)
	}
}

func TestSecurityLogCompactStreamPortGate15701(t *testing.T) {
	_, err := compileLogText15701(t, `security {
		log {
			stream { s1 host 192.0.2.10 port 70000; }
		}
	}`)
	if err == nil || !strings.Contains(err.Error(), "invalid syslog port") {
		t.Fatalf("compact stream invalid port must be strict-rejected, got %v", err)
	}
	// Lenient path: warn, keep the 514 default, still compile the stream.
	cfg, err := compileLogTextLenient15701(t, `security {
		log {
			stream { s1 host 192.0.2.10 port 70000; }
		}
	}`)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	s := cfg.Security.Log.Streams["s1"]
	if s == nil || s.Port != 514 {
		t.Fatalf("lenient stream = %+v, want port 514 default", s)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "invalid syslog port") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected lenient port warning, got %v", cfg.Warnings)
	}
}

func TestSecurityLogCompactStreamTLSProfileGate15701(t *testing.T) {
	_, err := compileLogText15701(t, `security {
		log {
			stream { s1 host 192.0.2.10 transport protocol tls tls-profile P1; }
		}
	}`)
	if err == nil || !strings.Contains(err.Error(), "tls-profile") {
		t.Fatalf("compact stream tls-profile must be strict-rejected, got %v", err)
	}
	cfg, err := compileLogTextLenient15701(t, `security {
		log {
			stream { s1 host 192.0.2.10 transport protocol tls tls-profile P1; }
		}
	}`)
	if err != nil {
		t.Fatalf("lenient compile: %v", err)
	}
	if s := cfg.Security.Log.Streams["s1"]; s == nil {
		t.Fatalf("lenient compact stream dropped: %v", cfg.Security.Log.Streams)
	}
	found := false
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "tls-profile") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected lenient tls-profile warning, got %v", cfg.Warnings)
	}
}

// Compact named-instance profile: the stream-name must be compiled (so the
// cross-reference gate can see it) and a dangling reference must reject.
func TestSecurityLogCompactProfileStreamNameGate15701(t *testing.T) {
	_, err := compileLogText15701(t, `security {
		log {
			stream real { host 192.0.2.10; }
			profile { p1 stream-name nosuch default-profile; }
		}
	}`)
	if err == nil || !strings.Contains(err.Error(), "nosuch") {
		t.Fatalf("compact profile dangling stream-name must be strict-rejected, got %v", err)
	}
	// Valid reference compiles with the profile fields populated.
	cfg, err := compileLogText15701(t, `security {
		log {
			stream real { host 192.0.2.10; }
			profile { p1 stream-name real default-profile; }
		}
	}`)
	if err != nil {
		t.Fatalf("compile valid compact profile: %v", err)
	}
	p := cfg.Security.Log.Profiles["p1"]
	if p == nil || p.StreamName != "real" || !p.DefaultProfile {
		t.Fatalf("profile = %+v, want stream-name=real default-profile", p)
	}
}

// The shared helper must resolve both instance schemas; a nil schema would
// silently turn the expansion off again (same guard as #6821/#9235).
func TestSecurityLogInstanceSchemasResolve15701(t *testing.T) {
	if securityLogStreamSchema9391() == nil {
		t.Fatal("securityLogStreamSchema9391() = nil")
	}
	if securityLogProfileSchema() == nil {
		t.Fatal("securityLogProfileSchema() = nil")
	}
}
