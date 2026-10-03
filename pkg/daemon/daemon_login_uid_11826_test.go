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
	if err := (&Daemon{}).applySystemLogin(cfg); err != nil {
		t.Fatalf("applySystemLogin: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("invalid UID reached account commands %v; invalid values must not request useradd auto-assignment", calls)
	}
}
