package config

import (
	"strings"
	"testing"
)

// #16075: the `interactive-commands` syslog facility is accepted and
// rendered (it maps to local7 in pkg/logging), but no code emits a
// per-command record to it. An operator configuring Junos-style command
// audit via `interactive-commands` on any syslog destination got an empty
// file/collector and false assurance. These tests pin the commit-time
// advisory (in ValidateConfig, which reaches both strict-commit warnings
// via cfg.Warnings and the show/validate surface) naming the facility and
// the destination, and that it stays silent for other facilities.
//
// RED-on-revert: deleting the #16075 block in compiler_validate_warn.go
// makes every positive cell below fail (no warning names
// interactive-commands); removing the facility-name check makes the
// negative controls fail.

func interactiveWarnings16075(cfg *Config) []string {
	var out []string
	for _, w := range ValidateConfig(cfg) {
		if strings.Contains(w, "interactive-commands") && strings.Contains(w, "#16075") {
			out = append(out, w)
		}
	}
	// cfg.Warnings is what the strict-commit path prints; ValidateConfig
	// is folded into it by runTailGates, so both surfaces must carry it.
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "interactive-commands") && strings.Contains(w, "#16075") {
			found := false
			for _, o := range out {
				if o == w {
					found = true
					break
				}
			}
			if !found {
				out = append(out, w)
			}
		}
	}
	return out
}

func TestInteractiveCommandsWarnsOnFileDestination16075(t *testing.T) {
	cfg := compileSyslogSinks(t,
		"set system syslog file audit interactive-commands info",
	)
	got := interactiveWarnings16075(cfg)
	if len(got) != 1 {
		t.Fatalf("want exactly 1 #16075 warning for file destination, got %v (all warnings: %v)", got, ValidateConfig(cfg))
	}
	for _, want := range []string{"file audit", "interactive-commands", "NOT implemented", "no CLI audit"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("warning %q must contain %q", got[0], want)
		}
	}
}

func TestInteractiveCommandsWarnsOnHostAndUser16075(t *testing.T) {
	cfg := compileSyslogSinks(t,
		"set system syslog host 10.0.0.1 interactive-commands info",
		"set system syslog user * interactive-commands notice",
	)
	got := interactiveWarnings16075(cfg)
	if len(got) != 2 {
		t.Fatalf("want 2 #16075 warnings (host + user), got %v", got)
	}
	joined := strings.Join(got, "\n")
	for _, want := range []string{"host 10.0.0.1", "user *"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings must name destination %q: %v", want, got)
		}
	}
}

func TestInteractiveCommandsWarnsOncePerDestination16075(t *testing.T) {
	// Two selectors naming the facility on one destination (with another
	// facility between them) must warn once for that destination, not
	// once per selector.
	cfg := compileSyslogSinks(t,
		"set system syslog file audit interactive-commands info",
		"set system syslog file audit daemon info",
		"set system syslog file audit interactive-commands warning",
	)
	got := interactiveWarnings16075(cfg)
	if len(got) != 1 {
		t.Fatalf("want 1 #16075 warning for the single file destination, got %v", got)
	}
}

func TestInteractiveCommandsWarnsOnCommaSeparatedSelector16075(t *testing.T) {
	// rsyslog's selector grammar accepts a comma-separated facility list,
	// and the compiler preserves it as one authored selector value such as
	// auth,interactive-commands. Membership must inspect each list member;
	// whole-token equality missed this accepted spelling entirely.
	tests := []struct {
		name string
		line string
		dest string
	}{
		{
			name: "file leading member",
			line: "set system syslog file audit interactive-commands,daemon info",
			dest: "file audit",
		},
		{
			name: "host trailing member",
			line: "set system syslog host 10.0.0.1 auth,interactive-commands info",
			dest: "host 10.0.0.1",
		},
		{
			name: "user middle member",
			line: "set system syslog user * auth,interactive-commands,daemon notice",
			dest: "user *",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := compileSyslogSinks(t, tc.line)
			got := interactiveWarnings16075(cfg)
			if len(got) != 1 {
				t.Fatalf("want exactly 1 #16075 warning for comma-separated selector, got %v (all warnings: %v)", got, ValidateConfig(cfg))
			}
			if !strings.Contains(got[0], tc.dest) {
				t.Errorf("warning %q must name destination %q", got[0], tc.dest)
			}
		})
	}
}

func TestInteractiveCommandsSilentForOtherFacilities16075(t *testing.T) {
	cfg := compileSyslogSinks(t,
		"set system syslog file messages daemon info",
		"set system syslog file messages change-log any",
		"set system syslog file messages auth,daemon info",
		"set system syslog host 10.0.0.1 daemon info",
		"set system syslog user * auth warning",
	)
	if got := interactiveWarnings16075(cfg); len(got) != 0 {
		t.Fatalf("no interactive-commands selector, but got #16075 warnings: %v", got)
	}
}

func TestInteractiveCommandsSilentWhenAbsent16075(t *testing.T) {
	cfg := compileSyslogSinks(t,
		"set system host-name fw1",
	)
	if got := interactiveWarnings16075(cfg); len(got) != 0 {
		t.Fatalf("no syslog destinations, but got #16075 warnings: %v", got)
	}
}
