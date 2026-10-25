package cli

import (
	"path/filepath"
	"strings"
	"testing"
)

// #16825 e2e through dispatchConfig + handleCommit: under
// [edit system], `copy services ssh to services telnet` expands to
// `system services telnet`, denied by anchored
// `deny-configuration "^system services telnet"`. Pre-fix the gate
// judged `services telnet`, allowed the copy, and the commit landed
// it. The deny target is non-credential so #16080 cannot mask the
// anchored-regex leg. Bare (#15757) and allowed non-bare controls
// must keep working.

func TestCopyRenameNonBareDstUnderCursorE2E16825(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := store.LoadOverride(`
system {
    host-name e2e16825;
    services { ssh; }
    login {
        class limited {
            permissions all;
            deny-configuration "^system services telnet";
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit setup: %v", err)
	}
	store.ExitConfigure()
	if store.ActiveConfig() == nil {
		t.Fatal("no active config")
	}
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure 2: %v", err)
	}
	c := &CLI{store: store, userClass: "limited"}
	store.SetEditPath([]string{"system"})

	for _, verb := range []string{"copy", "rename"} {
		line := verb + " services ssh to services telnet"
		if err := c.dispatchConfig(line); err == nil {
			t.Errorf("%q under [edit system] ALLOWED; expanded dst system services telnet is denied (#16825)", line)
		}
		if out := store.ShowCandidateSet(); strings.Contains(out, "set system services telnet") {
			t.Errorf("%q landed telnet in candidate:\n%s (#16825)", line, out)
		}
	}
	// Bare control under cursor (#15757) also denied at same target:
	// ssh identity is 1 token (`ssh`), bare dst `telnet` lands under
	// system services.
	if err := c.dispatchConfig("copy services ssh to telnet"); err == nil {
		t.Error("bare copy services ssh to telnet under [edit system] ALLOWED (#16825/#15757)")
	}
	if out := store.ShowCandidateSet(); strings.Contains(out, "set system services telnet") {
		t.Fatalf("bare copy landed telnet:\n%s", out)
	}
	if err := c.dispatchConfig("copy services ssh to services netconf"); err != nil {
		t.Fatalf("allowed copy under [edit system] refused: %v (#16825)", err)
	}
	if out := store.ShowCandidateSet(); !strings.Contains(out, "netconf") {
		t.Fatalf("allowed copy did not land netconf:\n%s", out)
	}
	store.SetEditPath(nil)
	if err := c.handleCommit(nil); err != nil {
		t.Fatalf("commit of allowed copy: %v", err)
	}
	if out := store.ShowCandidateSet(); strings.Contains(out, "set system services telnet") {
		t.Fatalf("committed candidate contains denied telnet:\n%s", out)
	}
	// Top-level root-spelled control: already denied pre-fix.
	store.ExitConfigure()
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure 3: %v", err)
	}
	c2 := &CLI{store: store, userClass: "limited"}
	if err := c2.dispatchConfig("copy system services ssh to system services telnet"); err == nil {
		t.Error("top-level root-spelled copy to system services telnet ALLOWED (control, #16825)")
	}
}
