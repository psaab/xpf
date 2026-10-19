package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #15207 A18-01: shadowed predefined must not print as live; predefined sets listed.

func shadowStore15207(t *testing.T) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatal(err)
	}
	if err := store.LoadOverride(`
applications {
    application junos-http {
        protocol tcp;
        destination-port 8080;
    }
}
`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatal(err)
	}
	return &CLI{store: store}
}

func TestShowApplicationsShadowed15207(t *testing.T) {
	c := shadowStore15207(t)
	out := captureStdout(t, func() { _ = c.showApplications([]string{"junos-http"}) })
	if !strings.Contains(out, "8080") {
		t.Fatalf("user junos-http missing:\n%s", out)
	}
	if strings.Contains(out, "Destination port: 80") && !strings.Contains(out, "shadowed") {
		t.Fatalf("predefined junos-http printed as live without shadowed label:\n%s", out)
	}
	if strings.Contains(out, "Predefined application:") && !strings.Contains(out, "shadowed") {
		t.Fatalf("predefined block unmarked:\n%s", out)
	}
	// exactly one effective: shadowed note must appear
	if !strings.Contains(out, "shadowed") {
		t.Fatalf("expected shadowed note:\n%s", out)
	}
}

func TestShowApplicationsPredefinedSet15207(t *testing.T) {
	c := shadowStore15207(t)
	out := captureStdout(t, func() { _ = c.showApplications([]string{"junos-sip"}) })
	if !strings.Contains(out, "junos-sip") || !strings.Contains(out, "junos-sip-udp") {
		t.Fatalf("predefined set junos-sip not listed with members:\n%s", out)
	}
	list := captureStdout(t, func() { _ = c.showApplications(nil) })
	if !strings.Contains(list, "junos-sip") {
		t.Fatalf("list mode missing predefined sets:\n%s", list)
	}
	// predefined app filter still works when not shadowed
	out2 := captureStdout(t, func() { _ = c.showApplications([]string{"junos-ssh"}) })
	if !strings.Contains(out2, "junos-ssh") {
		t.Fatalf("predefined junos-ssh filter broken:\n%s", out2)
	}
}
