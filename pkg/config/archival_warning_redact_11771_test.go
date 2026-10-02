package config

import (
	"strings"
	"testing"
)

// #11771: the archive-sites warning names a site whose URL may itself carry
// credentials. Warnings reach commit responses, apply logs, and the config GET,
// so the producer must redact before storing the message.
func TestArchivalWarningRedactsCredentialURL11771(t *testing.T) {
	const secretURL = "scp://alice:secret@archive.example/configs"
	input := `system {
    archival {
        configuration {
            archive-sites { "` + secretURL + `" password "$9$hash"; }
        }
    }
}`
	p := NewParser(input)
	tree, errs := p.Parse()
	if len(errs) > 0 {
		t.Fatalf("parse errors: %v", errs)
	}
	cfg, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("CompileConfig: %v", err)
	}
	var warning string
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "system archival archive-sites") {
			warning = w
			break
		}
	}
	if warning == "" {
		t.Fatalf("no archival credential warning in %v", cfg.Warnings)
	}
	if strings.Contains(warning, "secret") || strings.Contains(warning, "alice:") {
		t.Fatalf("archival warning exposes URL credentials: %q", warning)
	}
	if !strings.Contains(warning, "archive.example") {
		t.Fatalf("archival warning lost its diagnostic host: %q", warning)
	}
}

// #11771's warning-producer census also found that a tolerant RPM load stores
// the http-get scheme-gate error, which names the authored target URL. Keep
// credential-bearing target URLs out of that Warnings sink too.
func TestRPMWarningRedactsCredentialURL11771(t *testing.T) {
	for _, tc := range []struct {
		name, target, diagnosticHost string
	}{
		{"unsupported-scheme", "ftp://alice:secret@probe.example/path", "probe.example"},
		{"hostless-url", "http://alice:secret@", ""},
		{"malformed-url", "http://alice:secret@%zz", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree := buildTree(t, []string{
				"set services rpm probe P test t probe-type http-get",
				`set services rpm probe P test t target "` + tc.target + `"`,
			})
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient: %v", err)
			}
			var warning string
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "rpm http-get scheme") {
					warning = w
					break
				}
			}
			if warning == "" {
				t.Fatalf("no RPM http-get scheme warning in %v", cfg.Warnings)
			}
			if strings.Contains(warning, "secret") || strings.Contains(warning, "alice:") {
				t.Fatalf("RPM warning exposes target URL credentials: %q", warning)
			}
			if tc.diagnosticHost != "" && !strings.Contains(warning, tc.diagnosticHost) {
				t.Fatalf("RPM warning lost its diagnostic host %q: %q", tc.diagnosticHost, warning)
			}
		})
	}
}
