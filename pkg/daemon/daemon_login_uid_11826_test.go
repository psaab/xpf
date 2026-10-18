package daemon

import (
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

func TestApplySystemLoginRefusesInvalidUID11826(t *testing.T) {
	var calls []string
	original := runCommandTimeout
	runCommandTimeout = func(name string, _ ...string) ([]byte, error) {
		calls = append(calls, name)
		return nil, nil
	}
	t.Cleanup(func() { runCommandTimeout = original })

	cfg := &config.Config{System: config.SystemConfig{
		Login: &config.LoginConfig{Users: []*config.LoginUser{{
			Name:  "alice",
			Class: "super-user",
			UID:   -1,
		}}},
	}}
	// #14694: the negative UID must now SURFACE as an error (previously
	// silently skipped). No account command other than the existence
	// probe may run — in particular useradd must never auto-assign.
	if err := (&Daemon{}).applySystemLogin(cfg); err == nil {
		t.Fatalf("applySystemLogin with UID -1 = nil, want surfaced error (#14694)")
	}
	for _, c := range calls {
		if c == "useradd" || c == "usermod" {
			t.Fatalf("invalid UID reached account mutation command %q in %v; invalid values must not request useradd auto-assignment", c, calls)
		}
	}
}
