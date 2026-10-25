package configstore

import (
	"strings"
	"testing"
)

// #16712 on the operator surfaces: CheckText (strict commit-check
// pipeline) and Store CommitCheck/Commit via SetFromInput must
// reject `then interface <if> enable|disable`, while the
// preferred-route-only control commits.

func ipMonText16712(action string) string {
	return "services {\n rpm { probe WAN { test t { probe-type icmp-ping; target address 1.1.1.1; } } }\n" +
		" ip-monitoring { policy p {\n  match { rpm-probe WAN; }\n  then {\n   preferred-route { route 0.0.0.0/0 { next-hop 10.0.0.1; } }\n   " + action + "\n  }\n } }\n}\n"
}

func TestIPMonThenInterfaceCheckText16712(t *testing.T) {
	for _, action := range []string{"interface ge-0/0/1 enable;", "interface ge-0/0/1 disable;"} {
		if _, err := CheckText(ipMonText16712(action), -1); err == nil ||
			!strings.Contains(err.Error(), "interface") || !strings.Contains(err.Error(), "#16712") {
			t.Fatalf("CheckText action %q err=%v, want #16712 interface reject", action, err)
		}
	}
	cfg, err := CheckText(ipMonText16712(""), -1)
	if err != nil {
		t.Fatalf("CheckText control: %v", err)
	}
	for _, w := range cfg.Warnings {
		if strings.Contains(w, "#16712") {
			t.Fatalf("control carried #16712 warning: %q", w)
		}
	}
}

func TestIPMonThenInterfaceStoreCommit16712(t *testing.T) {
	sets := []string{
		"set services rpm probe WAN test t probe-type icmp-ping",
		"set services rpm probe WAN test t target address 1.1.1.1",
		"set services ip-monitoring policy p match rpm-probe WAN",
		"set services ip-monitoring policy p then preferred-route route 0.0.0.0/0 next-hop 10.0.0.1",
		"set services ip-monitoring policy p then interface ge-0/0/1 enable",
	}
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, line := range sets {
		if err := s.SetFromInput(strings.TrimPrefix(line, "set ")); err != nil {
			t.Fatalf("SetFromInput %q: %v", line, err)
		}
	}
	if _, err := s.CommitCheck(); err == nil || !strings.Contains(err.Error(), "interface") || !strings.Contains(err.Error(), "#16712") {
		t.Fatalf("CommitCheck = %v, want #16712 interface reject", err)
	}
	if _, err := s.Commit(); err == nil || !strings.Contains(err.Error(), "interface") {
		t.Fatalf("Commit = %v, want interface reject", err)
	}
	s.ExitConfigure()

	// Control: same sets without the interface action commit clean.
	s2 := newTestStore(t)
	if err := s2.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	for _, line := range sets[:4] {
		if err := s2.SetFromInput(strings.TrimPrefix(line, "set ")); err != nil {
			t.Fatalf("control SetFromInput %q: %v", line, err)
		}
	}
	if _, err := s2.Commit(); err != nil {
		t.Fatalf("control Commit: %v", err)
	}
}
