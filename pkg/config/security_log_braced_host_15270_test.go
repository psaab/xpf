package config_test

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

const reference15270 = `security {
    log {
        mode stream;
        format sd-syslog;
        source-address 192.168.99.1;
        stream syslog-server {
            severity info;
            format sd-syslog;
            host {
                192.168.99.252;
                port 514;
            }
        }
    }
}
`

func parse15270(t *testing.T, text string) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser(text).Parse()
	if len(errs) != 0 {
		t.Fatalf("parse: %v", errs)
	}
	return tree
}

func TestReferenceStanza15270(t *testing.T) {
	tree := parse15270(t, reference15270)
	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("SchemaValidate(reference): %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig(reference): %v", err)
	}
	if got := cfg.Security.Log.SourceAddress; got != "192.168.99.1" {
		t.Fatalf("global SourceAddress=%q want 192.168.99.1", got)
	}
	s := cfg.Security.Log.Streams["syslog-server"]
	if s == nil {
		t.Fatalf("stream missing: %v", cfg.Security.Log.Streams)
	}
	if s.Host != "192.168.99.252" || s.Port != 514 {
		t.Fatalf("stream host/port=%q/%d want 192.168.99.252/514", s.Host, s.Port)
	}
	// FormatSet round-trip must preserve host/port and global source.
	out := tree.FormatSet()
	if !strings.Contains(out, "security log stream syslog-server host 192.168.99.252") {
		t.Fatalf("FormatSet missing flat host:\n%s", out)
	}
	if !strings.Contains(out, "security log source-address 192.168.99.1") {
		t.Fatalf("FormatSet missing global source-address:\n%s", out)
	}
	tree2 := &config.ConfigTree{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		path, err := config.ParseSetCommand(line)
		if err != nil {
			t.Fatalf("ParseSetCommand(%q): %v", line, err)
		}
		if err := tree2.SetPath(path); err != nil {
			t.Fatalf("SetPath(%q): %v", line, err)
		}
	}
	if err := config.SchemaValidate(tree2, nil); err != nil {
		t.Fatalf("SchemaValidate(round-trip): %v\n%s", err, out)
	}
	cfg2, err := config.CompileConfig(tree2)
	if err != nil {
		t.Fatalf("CompileConfig(round-trip): %v", err)
	}
	if cfg2.Security.Log.SourceAddress != "192.168.99.1" {
		t.Fatalf("round-trip global=%q", cfg2.Security.Log.SourceAddress)
	}
	s2 := cfg2.Security.Log.Streams["syslog-server"]
	if s2 == nil || s2.Host != "192.168.99.252" || s2.Port != 514 {
		t.Fatalf("round-trip stream=%+v", s2)
	}
}

func TestInvalid15270(t *testing.T) {
	cases := map[string]string{
		"bad braced host":          `security { log { stream s { host { "not_an_ip!!"; port 514; } } } }`,
		"bad braced port text":     `security { log { stream s { host { 192.0.2.1; port 6514x; } } } }`,
		"bad braced port range":    `security { log { stream s { host { 192.0.2.1; port 70000; } } } }`,
		"bad global source":        `security { log { source-address not-an-ip; stream s { host 192.0.2.1; } } }`,
		"empty host block":         `security { log { stream s { host { } } } }`,
		"host block port only":     `security { log { stream s { host { port 514; } } } }`,
		"host block two addrs":     `security { log { stream s { host { 192.0.2.1; 192.0.2.2; } } } }`,
		"host block unknown child": `security { log { stream s { host { 192.0.2.1; bogus 1; } } } }`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			tree := parse15270(t, text)
			schemaErr := config.SchemaValidate(tree, nil)
			_, compileErr := config.CompileConfig(tree)
			if schemaErr == nil && compileErr == nil {
				t.Fatalf("expected rejection, got nil (schema & compile)")
			}
			t.Logf("schema=%v compile=%v", schemaErr, compileErr)
		})
	}
	// flat invalid global source via SchemaValidate
	tree := &config.ConfigTree{}
	for _, cmd := range []string{"set security log source-address not-an-ip", "set security log stream s host 192.0.2.1"} {
		path, _ := config.ParseSetCommand(cmd)
		_ = tree.SetPath(path)
	}
	if err := config.SchemaValidate(tree, nil); err == nil {
		t.Fatalf("flat bad global source-address accepted")
	}
}

func TestControls15270(t *testing.T) {
	// flat host, direct port, per-stream source-address unchanged
	tree := parse15270(t, `security { log { stream s { host 192.0.2.1; port 5514; source-address 10.0.0.5; } } }`)
	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("flat control schema: %v", err)
	}
	cfg, err := config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("flat control compile: %v", err)
	}
	s := cfg.Security.Log.Streams["s"]
	if s == nil || s.Host != "192.0.2.1" || s.Port != 5514 || s.SourceAddress != "10.0.0.5" {
		t.Fatalf("flat control stream=%+v", s)
	}
	if cfg.Security.Log.SourceAddress != "" {
		t.Fatalf("per-stream source leaked to global: %q", cfg.Security.Log.SourceAddress)
	}
	// hostname braced host
	tree = parse15270(t, `security { log { stream s { host { logs.example.net; port 5514; } } } }`)
	if err := config.SchemaValidate(tree, nil); err != nil {
		t.Fatalf("hostname braced schema: %v", err)
	}
	cfg, err = config.CompileConfig(tree)
	if err != nil {
		t.Fatalf("hostname braced compile: %v", err)
	}
	s = cfg.Security.Log.Streams["s"]
	if s == nil || s.Host != "logs.example.net" || s.Port != 5514 {
		t.Fatalf("hostname braced stream=%+v", s)
	}
}
