package configstore

import (
	"fmt"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// The tolerant ingress is the exact Store.Load/SyncApply compiler helper.
// A compact invalid name is visible to compileSystem (the schema walk
// deliberately does not inspect packed system tails), so this cell proves
// the warning is retained on the compiled config while the bad value remains
// available for a no-brick boot.
func TestTolerantCompileWarnsSystemHostname10003(t *testing.T) {
	for _, tc := range []struct {
		name string
		host string
	}{
		{name: "spaced", host: "bad name"},
		{name: "overlong", host: strings.Repeat("a", 300)},
		{name: "kernel-overlong", host: strings.Repeat("a", 32) + "." + strings.Repeat("b", 32)},
		{name: "kernel-overlong-trailing-dot", host: strings.Repeat("a", 31) + "." + strings.Repeat("b", 32) + "."},
		{name: "bad-charset", host: "bad!name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newTestStore(t)
			text := fmt.Sprintf("system host-name %q;", tc.host)
			tree, perrs := config.NewParser(text).Parse()
			if len(perrs) > 0 {
				t.Fatalf("parse errors: %v", perrs)
			}
			cfg, err := s.compileTreeLenient(tree)
			if err != nil {
				t.Fatalf("tolerant compile must not brick: %v", err)
			}
			if cfg == nil || cfg.System.HostName != tc.host {
				t.Fatalf("tolerant compile lost host-name %q: cfg=%+v", tc.host, cfg)
			}
			found := false
			for _, warning := range cfg.Warnings {
				if strings.Contains(warning, "host-name") {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("tolerant compile must warn naming host-name; warnings=%v", cfg.Warnings)
			}
		})
	}
}

// #10003: the operator-driven Store path must reject the same malformed
// system host-names that the schema/compact compiler cells reject. This is
// the production CommitCheck/Commit gate, not a direct SchemaValidate probe.
func TestCommitCheckRejectsSystemHostname10003(t *testing.T) {
	cases := []string{
		`system host-name "bad name"`,
		`system host-name "bad!name"`,
		`system host-name "under_score"`,
		`system host-name "` + strings.Repeat("a", 64) + `"`,
		`system host-name "` + strings.Repeat("a", 32) + "." + strings.Repeat("b", 32) + `"`,
		`system host-name "` + strings.Repeat("a", 31) + "." + strings.Repeat("b", 32) + `."`,
		`system host-name "` + strings.Repeat("b", 300) + `"`,
	}
	for _, command := range cases {
		t.Run(command, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := s.SetFromInput(command); err != nil {
				t.Fatalf("SetFromInput(%q): %v", command, err)
			}
			_, err := s.CommitCheck()
			if err == nil {
				t.Fatalf("CommitCheck accepted malformed host-name %q", command)
			}
			if !strings.Contains(err.Error(), "host-name") {
				t.Fatalf("CommitCheck diagnostic must name host-name: %v", err)
			}
			if _, err := s.Commit(); err == nil {
				t.Fatalf("Commit accepted malformed host-name %q", command)
			} else if !strings.Contains(err.Error(), "host-name") {
				t.Fatalf("Commit diagnostic must name host-name: %v", err)
			}
		})
	}
}

// A valid FQDN remains an ordinary committed scalar. This control catches a
// validator that accidentally narrows the admission rule to short labels or
// rejects dots/trailing absolute-name syntax.
func TestCommitAcceptsValidSystemHostname10003(t *testing.T) {
	for _, host := range []string{
		"router1.example.net",
		"router1.example.net.",
		strings.Repeat("a", 32) + "." + strings.Repeat("b", 31),
		strings.Repeat("a", 31) + "." + strings.Repeat("b", 31) + ".",
	} {
		t.Run(host, func(t *testing.T) {
			s := newTestStore(t)
			if err := s.EnterConfigure(); err != nil {
				t.Fatalf("EnterConfigure: %v", err)
			}
			if err := s.SetFromInput(fmt.Sprintf("system host-name %q", host)); err != nil {
				t.Fatalf("SetFromInput: %v", err)
			}
			cfg, err := s.Commit()
			if err != nil {
				t.Fatalf("valid FQDN commit rejected: %v", err)
			}
			if cfg == nil || cfg.System.HostName != host {
				got := "<nil>"
				if cfg != nil {
					got = cfg.System.HostName
				}
				t.Fatalf("committed host-name = %q, want %q", got, host)
			}
		})
	}
}
