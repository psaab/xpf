package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
)

// #14986 (D37-01): dispatch() routed purely on the store-GLOBAL
// InConfigMode() flag. The single configstore.Store is shared by every
// surface (gRPC/REST sessions call EnterConfigureSession, the daemon
// itself may hold it); once ANY holder put it in config mode, a local
// read-only/unauthorized/operator CLI user's EVERY line — including
// `set`/`delete`/`load`/`commit` — was routed to dispatchConfig, whose
// only coarse gate is the *-configuration regex pair. A built-in class
// with no PermConfig and no regexes (read-only, unauthorized, operator)
// therefore mutated and committed the shared candidate with full
// PermConfig effect, and the empty sessionID ("") on every mutation
// bypassed configure-exclusive holder enforcement.
//
// The fixture below is the exact packet: enter config mode on the store
// WITHOUT going through this CLI's (correctly gated) `configure` verb —
// as another session/daemon holder would — then drive the victim CLI
// through dispatch(), the real entry point of the interactive loop.

func storeInConfigMode14986(t *testing.T, holder string) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	// Seed ACTIVE so the commit below has a host-name to overwrite.
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(seed): %v", err)
	}
	if err := store.LoadMerge("system {\n    host-name base-14986;\n}\n"); err != nil {
		t.Fatalf("LoadMerge(seed): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(seed): %v", err)
	}
	store.ExitConfigure()
	// Another holder puts the shared store in config mode.
	if holder == "exclusive" {
		if err := store.EnterConfigureExclusive("other-session"); err != nil {
			t.Fatalf("EnterConfigureExclusive: %v", err)
		}
	} else if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	return store
}

func TestDispatchInConfigModeRequiresPermConfig14986(t *testing.T) {
	for _, tc := range []struct {
		class string
		line  string
	}{
		{"read-only", "set system host-name pwned-14986"},
		{"unauthorized", "set system host-name pwned-14986"},
		{"operator", "set system host-name pwned-14986"},
		{"read-only", "delete system host-name"},
		{"read-only", "commit"},
		{"unauthorized", "commit"},
		{"operator", "commit"},
		{"read-only", "rollback 0"},
	} {
		t.Run(tc.class+"/"+tc.line, func(t *testing.T) {
			store := storeInConfigMode14986(t, "shared")
			defer store.ExitConfigure()
			c := &CLI{store: store, userClass: tc.class}
			var err error
			captureStdout(t, func() { err = c.dispatch(tc.line) })
			if err == nil {
				t.Fatalf("dispatch(%q) as %q = nil while store globally in config mode; read-only escalation to PermConfig (#14986)", tc.line, tc.class)
			}
			if !strings.Contains(err.Error(), "permission denied") && !strings.Contains(err.Error(), "configure") {
				t.Fatalf("dispatch(%q) as %q refused for wrong reason (want coarse PermConfig denial): %v", tc.line, tc.class, err)
			}
			if got := store.ShowCandidate(); strings.Contains(got, "pwned-14986") {
				t.Fatalf("candidate mutated by %q via %q:\n%s", tc.class, tc.line, got)
			}
			if got := store.ActiveConfig(); got != nil && got.System.HostName == "pwned-14986" {
				t.Fatal("active config committed by read-only class (#14986)")
			}
		})
	}
}

func TestDispatchInConfigModePreservesViewAndPrivileged14986(t *testing.T) {
	// Control: view commands keep working for read-only while the store
	// is globally in config mode (config-mode `show` stays available).
	store := storeInConfigMode14986(t, "shared")
	defer store.ExitConfigure()
	ro := &CLI{store: store, userClass: "read-only"}
	var err error
	out := captureStdout(t, func() { err = ro.dispatch("show") })
	if err != nil {
		t.Fatalf("read-only dispatch(show) in config mode = %v, want served", err)
	}
	if !strings.Contains(out, "base-14986") {
		t.Fatalf("read-only show did not render candidate:\n%s", out)
	}
	if err := store.EnterConfigure(); err != nil {
		// already in config mode is the shared case; tolerate
		_ = err
	}
	defer store.ExitConfigure()
	// Control: a PermConfig class may still mutate/commit in config mode.
	su := &CLI{store: store, userClass: "super-user"}
	captureStdout(t, func() { err = su.dispatch("set system host-name legit-14986") })
	if err != nil {
		t.Fatalf("super-user dispatch(set) in config mode = %v, want allowed", err)
	}
	if got := store.ShowCandidate(); !strings.Contains(got, "legit-14986") {
		t.Fatalf("super-user set did not land:\n%s", got)
	}
	// Control: unset class (legacy no-RBAC) untouched.
	if err := store.EnterConfigure(); err == nil {
		// already in config mode is fine
	}
	unset := &CLI{store: store, userClass: ""}
	captureStdout(t, func() { err = unset.dispatch("set system host-name unset-14986") })
	if err != nil {
		t.Fatalf("unset-class dispatch(set) = %v, want allowed (legacy no-RBAC)", err)
	}
}

func TestDispatchInConfigModeExclusiveBypass14986(t *testing.T) {
	// Exclusive held by ANOTHER session: even a PermConfig class on this
	// CLI must not mutate/commit through the empty-session bypass.
	store := storeInConfigMode14986(t, "exclusive")
	defer store.ExitConfigure()
	// Sanity: exclusive is held by other-session.
	if holder, locked := store.ConfigHolder(); !locked || holder != "other-session" {
		t.Fatalf("premise: exclusive holder = %q/%v, want other-session/true", holder, locked)
	}
	c := &CLI{store: store, userClass: "super-user"}
	var err error
	captureStdout(t, func() { err = c.dispatch("set system host-name excl-pwned-14986") })
	if err == nil {
		t.Fatal("super-user dispatch(set) mutated a candidate exclusively held by another session via empty-session bypass (#14986)")
	}
	if got := store.ShowCandidate(); strings.Contains(got, "excl-pwned-14986") {
		t.Fatalf("exclusive candidate mutated:\n%s", got)
	}
	// Control: the local CLI's OWN configure exclusive still works end to end.
	store2 := newConfigStore(t, filepath.Join(t.TempDir(), "xpf2.conf"))
	c2 := &CLI{store: store2, userClass: "super-user"}
	captureStdout(t, func() { err = c2.dispatch("configure exclusive") })
	if err != nil {
		t.Fatalf("own configure exclusive: %v", err)
	}
	captureStdout(t, func() { err = c2.dispatch("set system host-name own-excl-14986") })
	if err != nil {
		t.Fatalf("own exclusive set: %v", err)
	}
	if got := store2.ShowCandidate(); !strings.Contains(got, "own-excl-14986") {
		t.Fatalf("own exclusive set did not land:\n%s", got)
	}
}

func TestConfigureVerbStillGated14986(t *testing.T) {
	// Control: the operational `configure` entry was already correctly
	// priced at PermConfig; pin it so the fix cannot widen it.
	for _, class := range []string{"read-only", "unauthorized", "operator"} {
		store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
		c := &CLI{store: store, userClass: class}
		var err error
		captureStdout(t, func() { err = c.dispatch("configure") })
		if err == nil {
			t.Fatalf("%q entered configure via dispatch(configure); want PermConfig denial", class)
		}
		if store.InConfigMode() {
			t.Fatalf("%q left store in config mode after denied configure", class)
		}
	}
}
