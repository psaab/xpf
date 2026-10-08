package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

func newCLINativeVLANStore12248(t *testing.T, lines ...string) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	for _, line := range lines {
		if _, err := store.LoadSet(line); err != nil {
			t.Fatalf("LoadSet(%q): %v", line, err)
		}
	}
	return &CLI{store: store}
}

func TestNativeVLANBindingAdvisorySurfacesOnCommit12248(t *testing.T) {
	c := newCLINativeVLANStore12248(t,
		"set interfaces ge-0/0/0 native-vlan-id 100",
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
	)

	var callErr error
	out := captureStdout(t, func() { callErr = c.handleCommit(nil) })
	if callErr != nil {
		t.Fatalf("commit failed: %v; the binding advisory must be warning-only", callErr)
	}
	for _, want := range []string{
		"commit complete",
		"interfaces ge-0/0/0",
		"native-vlan-id 100",
		"no unique matching unit",
		"untagged ingress is rejected",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("commit output missing %q:\n%s", want, out)
		}
	}
}

func TestNativeVLANBindingAdvisoryStaysSilentWithUniqueUnit12248(t *testing.T) {
	c := newCLINativeVLANStore12248(t,
		"set interfaces ge-0/0/0 native-vlan-id 100",
		"set interfaces ge-0/0/0 unit 100 vlan-id 100",
		"set interfaces ge-0/0/0 unit 100 family inet address 10.0.1.1/24",
	)

	var callErr error
	out := captureStdout(t, func() { callErr = c.handleCommit([]string{"check"}) })
	if callErr != nil {
		t.Fatalf("commit check failed: %v", callErr)
	}
	if !strings.Contains(out, "configuration check succeeds") {
		t.Fatalf("commit check did not succeed: %q", out)
	}
	if strings.Contains(out, "native-vlan-id") {
		t.Fatalf("unique native VLAN binding produced an advisory: %q", out)
	}
}
