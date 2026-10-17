package config

import (
	"strings"
	"testing"
)

// #14596: `system ntp server <addr> key <n>` rendered chrony `key n` with no
// key material anywhere, so chronyd logged "Key n is missing" and never
// polled that source — silently, with a green commit. The documented
// contract was "NTP authentication accepted but NOT enforced", which
// implies time keeps syncing unauthenticated; the renderer broke that by
// still emitting `key`.
//
// The fix is the strip-and-warn half of the issue's acceptance: xpf does
// not implement NTP authentication, so the compiler records per-server
// key ids as unenforceable (NTPServerKeyIDs) and the daemon renderer
// omits `key` for them, while EVERY `server ... key <n>` — not only the
// full Junos form that happens to carry an `authentication-key` block —
// warns naming the key id. These tests pin the compiler half; the
// renderer half is pinned in pkg/daemon (ntp_key_14596_test.go).

func compileNTPKey14596(t *testing.T, sets []string) *Config {
	t.Helper()
	tree := buildTree4303(t, sets)
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile %v: %v", sets, err)
	}
	if err := SchemaValidate(tree, c); err != nil {
		t.Fatalf("SchemaValidate %v: %v", sets, err)
	}
	return c
}

func warningsContain14596(c *Config, substr string) bool {
	for _, w := range c.Warnings {
		if strings.Contains(w, substr) {
			return true
		}
	}
	return false
}

// The decisive cell from the issue: bare `server A key 5` with no key
// material at all must warn naming key 5. Before the fix this compiled
// with zero warnings and rendered `server A iburst key 5`.
func TestNTPServerKeyWithoutMaterialWarns14596(t *testing.T) {
	c := compileNTPKey14596(t, []string{
		"set system ntp server 192.0.2.1 key 5",
	})
	if !warningsContain14596(c, "key 5") {
		t.Fatalf("bare `server 192.0.2.1 key 5` produced no warning naming "+
			"key 5; warnings=%v. The renderer would emit chrony `key 5` "+
			"with no keyfile, so chronyd never polls the source (#14596)",
			c.Warnings)
	}
	if !warningsContain14596(c, "NOT enforced") {
		t.Fatalf("warning must say authentication is not enforced; warnings=%v", c.Warnings)
	}
	// The unenforceable key id is recorded for the renderer, and the
	// typed per-server option no longer carries it as enforceable.
	if got := c.System.NTPServerKeyIDs; len(got) != 1 || got[0] != 5 {
		t.Fatalf("NTPServerKeyIDs = %v, want [5]", got)
	}
	if got := c.System.NTPServerOptions["192.0.2.1"].Key; got != 0 {
		t.Fatalf("NTPServerOptions[192.0.2.1].Key = %d, want 0 (unenforceable keys must not reach the renderer as chrony `key`)", got)
	}
}

// Control: a server with no key modifier stays silent and records nothing.
func TestNTPServerNoKeyNoWarning14596(t *testing.T) {
	c := compileNTPKey14596(t, []string{
		"set system ntp server 192.0.2.1",
		"set system ntp server 192.0.2.2 prefer",
	})
	if warningsContain14596(c, "key") && warningsContain14596(c, "NOT enforced") {
		t.Fatalf("keyless servers must not warn about NTP keys; warnings=%v", c.Warnings)
	}
	if len(c.System.NTPServerKeyIDs) != 0 {
		t.Fatalf("NTPServerKeyIDs = %v, want empty for keyless servers", c.System.NTPServerKeyIDs)
	}
}

// The full Junos form: authentication-key + trusted-key + server key.
// xpf still does not enforce NTP auth, so the warning must say the key
// is stripped/not enforced — never imply the keyfile exists — and the
// secret value must never be echoed.
func TestNTPFullJunosAuthFormWarnsStripped14596(t *testing.T) {
	c := compileNTPKey14596(t, []string{
		"set system ntp server 192.0.2.1 key 5",
		"set system ntp authentication-key 5 type md5 value NTPSECRETKEY14596",
		"set system ntp trusted-key 5",
	})
	all := strings.Join(c.Warnings, "\n")
	if !strings.Contains(all, "key 5") {
		t.Fatalf("full Junos form must warn naming key 5; warnings:\n%s", all)
	}
	if strings.Contains(all, "NTPSECRETKEY14596") {
		t.Fatalf("warning echoed the NTP authentication-key value; warnings:\n%s", all)
	}
	if got := c.System.NTPServerOptions["192.0.2.1"].Key; got != 0 {
		t.Fatalf("Key = %d, want 0: even with authentication-key/trusted-key configured, xpf writes no chrony keyfile, so `key` must be stripped (#14596)", got)
	}
}

// Every distinct key id is named once; a repeated id does not spam, and
// two servers sharing an id warn once for that id while a second id
// warns separately. Version/prefer/routing-instance handling is
// untouched.
func TestNTPServerKeyIDsCollected14596(t *testing.T) {
	c := compileNTPKey14596(t, []string{
		"set system ntp server 192.0.2.1 key 5",
		"set system ntp server 192.0.2.2 key 5",
		"set system ntp server 192.0.2.3 key 7 version 4 prefer",
	})
	if got := c.System.NTPServerKeyIDs; len(got) != 2 || got[0] != 5 || got[1] != 7 {
		t.Fatalf("NTPServerKeyIDs = %v, want [5 7] (sorted, deduplicated)", got)
	}
	for _, want := range []string{"key 5", "key 7"} {
		if !warningsContain14596(c, want) {
			t.Errorf("missing warning naming %q; warnings=%v", want, c.Warnings)
		}
	}
	count5 := 0
	for _, w := range c.Warnings {
		if strings.Contains(w, "key 5") {
			count5++
		}
	}
	if count5 != 1 {
		t.Errorf("key 5 warned %d times, want exactly 1; warnings=%v", count5, c.Warnings)
	}
	if got := c.System.NTPServerOptions["192.0.2.3"]; got.Version != 4 || !got.Prefer {
		t.Errorf("192.0.2.3 options = %+v, want Version 4 + Prefer preserved alongside the stripped key", got)
	}
}

// Braced and compact spellings of the same keyed server warn identically
// (#2419 equivalence for the new warning path).
func TestNTPServerKeyBracedSpellingWarns14596(t *testing.T) {
	p := NewParser("system { ntp { server 192.0.2.1 { key 5; } } }")
	tree, perrs := p.Parse()
	if len(perrs) > 0 {
		t.Fatalf("parse: %v", perrs)
	}
	c, err := CompileConfig(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !warningsContain14596(c, "key 5") {
		t.Fatalf("braced `server 192.0.2.1 { key 5; }` produced no warning naming key 5; warnings=%v", c.Warnings)
	}
	if got := c.System.NTPServerKeyIDs; len(got) != 1 || got[0] != 5 {
		t.Fatalf("NTPServerKeyIDs = %v, want [5]", got)
	}
}
