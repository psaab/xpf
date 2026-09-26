// RED-on-revert tests for #4099: the on-box interactive CLI config-render show
// paths (`show configuration` in every display format, `show system rollback`,
// `show system root-authentication`, and `show system configuration rescue`)
// must mask secret leaves for a VIEW-only login class (read-only /
// config-viewer / operator) exactly as the always-redacted REST/gRPC
// ShowConfig does (#4051). Before the fix these called the cleartext Show*
// store methods, leaking IKE PSKs, SNMP communities, BGP auth-keys, WireGuard
// private keys and the encrypted root password to a class that can only VIEW.
//
// Reverting the wiring makes the read-only / config-viewer / operator subtests
// go RED (cleartext sentinel reappears). super-user keeps cleartext (the #4057
// operator-reads-own-secret allowance; root has direct DB access), so the
// super-user subtest asserts the cleartext IS present — a revert that redacts
// everyone would also be caught.
package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// cliSecretSet stages the secrets #4099/#4051 name explicitly (IKE PSK + SNMP
// community) plus representative others and the encrypted root password, each
// with a distinctive cleartext sentinel so a leak is identifiable. A non-secret
// host-name sentinel rides along to prove redaction is surgical.
var cliSecretSet = []string{
	"set system host-name XPF-NONSECRET-HOST",
	`set system root-authentication encrypted-password "$6$CLILEAK00$ROOTPWHASH0000000000000000000000000000000000000000000000000000000000000000000000000000"`,
	"set security ike policy pol1 pre-shared-key ascii-text CLI-LEAK-IKE-PSK",
	"set snmp community CLI-LEAK-SNMP-COMMUNITY authorization read-only",
	"set protocols bgp group ext authentication-key CLI-LEAK-BGP-AUTHPW",
	"set interfaces wg0 tunnel wireguard private-key CLI-LEAK-WG-PRIVKEY",
}

var cliSecretSentinels = []string{
	"ROOTPWHASH", "CLI-LEAK-IKE-PSK", "CLI-LEAK-SNMP-COMMUNITY",
	"CLI-LEAK-BGP-AUTHPW", "CLI-LEAK-WG-PRIVKEY",
}

func newCLISecretStore(t *testing.T) *configstore.Store {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure(): %v", err)
	}
	if _, err := store.LoadSet(strings.Join(cliSecretSet, "\n")); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}
	return store
}

// classWantsRedaction is the per-class expectation table shared by the show
// path tests: redact everyone EXCEPT super-user and the unset (no-RBAC) class.
var classWantsRedaction = []struct {
	class  string
	redact bool
}{
	{"super-user", false},
	{"", false}, // unset — legacy no-RBAC allow-everything, cleartext
	{"operator", true},
	{"read-only", true},
	{"config-viewer", true},
	{"unauthorized", true}, // fail-closed
}

// TestCLIShowConfigurationRedactsPerClass is the primary #4099 RED-on-revert
// net: `show configuration` across hierarchical / set / json / xml / display
// inheritance formats masks every secret for a VIEW-only class, preserves the
// non-secret host-name, and still shows cleartext for super-user.
func TestCLIShowConfigurationRedactsPerClass(t *testing.T) {
	store := newCLISecretStore(t)

	formatArgs := map[string][]string{
		"hierarchical": {"configuration"},
		"set":          {"configuration", "|", "display", "set"},
		"json":         {"configuration", "|", "display", "json"},
		"xml":          {"configuration", "|", "display", "xml"},
		"inheritance":  {"configuration", "|", "display", "inheritance"},
	}

	for _, tc := range classWantsRedaction {
		for fname, args := range formatArgs {
			t.Run(tc.class+"/"+fname, func(t *testing.T) {
				c := &CLI{store: store, userClass: tc.class}
				// handleShow mutates args[0] via resolveCommand; hand it a copy.
				a := append([]string(nil), args...)
				out := captureStdout(t, func() {
					if err := c.handleShow(a); err != nil {
						t.Fatalf("handleShow(%v): %v", args, err)
					}
				})

				// Non-secret leaf survives in every case.
				if !strings.Contains(out, "XPF-NONSECRET-HOST") {
					t.Errorf("class=%q fmt=%s dropped non-secret host-name:\n%s", tc.class, fname, out)
				}

				if tc.redact {
					for _, leak := range cliSecretSentinels {
						if strings.Contains(out, leak) {
							t.Errorf("class=%q fmt=%s LEAKED cleartext secret %q:\n%s", tc.class, fname, leak, out)
						}
					}
					if !strings.Contains(out, config.SecretDataPlaceholder) {
						t.Errorf("class=%q fmt=%s missing redaction placeholder %q:\n%s",
							tc.class, fname, config.SecretDataPlaceholder, out)
					}
				} else {
					// Privileged class must still see cleartext (the #4057
					// allowance) — assert the IKE PSK survives.
					if !strings.Contains(out, "CLI-LEAK-IKE-PSK") {
						t.Errorf("class=%q fmt=%s unexpectedly redacted the IKE PSK for a privileged class:\n%s",
							tc.class, fname, out)
					}
				}
			})
		}
	}
}

// TestCLIShowConfigurationPathRedacts confirms a path-scoped `show
// configuration security` subtree render also redacts for a VIEW-only class.
func TestCLIShowConfigurationPathRedacts(t *testing.T) {
	store := newCLISecretStore(t)
	c := &CLI{store: store, userClass: "read-only"}
	out := captureStdout(t, func() {
		if err := c.handleShow([]string{"configuration", "security", "|", "display", "set"}); err != nil {
			t.Fatalf("handleShow: %v", err)
		}
	})
	if strings.Contains(out, "CLI-LEAK-IKE-PSK") {
		t.Errorf("path-scoped show configuration leaked IKE PSK:\n%s", out)
	}
	if !strings.Contains(out, config.SecretDataPlaceholder) {
		t.Errorf("path-scoped show configuration missing placeholder:\n%s", out)
	}
}

// TestCLIShowSystemRollbackRedactsPerClass pins the rollback render path: a
// historical config slot carries the same secrets and must be masked for a
// VIEW-only class in both hierarchical and `| display set` forms.
func TestCLIShowSystemRollbackRedactsPerClass(t *testing.T) {
	store := newCLISecretStore(t)
	// A second commit pushes the secret-bearing config into rollback slot 1.
	// The store is still in configure mode after the first commit (candidate
	// is retained as a clone of active), so re-entering would deadlock the
	// lock — LoadSet directly onto the live candidate.
	if _, err := store.LoadSet("set system domain-name example.net"); err != nil {
		t.Fatalf("LoadSet(): %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit(): %v", err)
	}

	for _, tc := range classWantsRedaction {
		for _, args := range [][]string{
			{"rollback", "1"},
			{"rollback", "1", "|", "display", "set"},
		} {
			t.Run(tc.class+"/"+strings.Join(args, "_"), func(t *testing.T) {
				c := &CLI{store: store, userClass: tc.class}
				a := append([]string(nil), args...)
				out := captureStdout(t, func() {
					if err := c.handleShowSystem(a); err != nil {
						t.Fatalf("handleShowSystem(%v): %v", args, err)
					}
				})
				if tc.redact {
					for _, leak := range cliSecretSentinels {
						if strings.Contains(out, leak) {
							t.Errorf("class=%q rollback LEAKED cleartext secret %q:\n%s", tc.class, leak, out)
						}
					}
					if !strings.Contains(out, config.SecretDataPlaceholder) {
						t.Errorf("class=%q rollback missing placeholder:\n%s", tc.class, out)
					}
				} else if !strings.Contains(out, "CLI-LEAK-IKE-PSK") {
					t.Errorf("class=%q rollback unexpectedly redacted for privileged class:\n%s", tc.class, out)
				}
			})
		}
	}
}

// TestCLIShowSystemRootAuthRedacts pins `show system root-authentication`: the
// encrypted root password is masked for a VIEW-only class, cleartext for
// super-user.
func TestCLIShowSystemRootAuthRedacts(t *testing.T) {
	store := newCLISecretStore(t)
	for _, tc := range classWantsRedaction {
		t.Run(tc.class, func(t *testing.T) {
			c := &CLI{store: store, userClass: tc.class}
			out := captureStdout(t, func() {
				if err := c.handleShowSystem([]string{"root-authentication"}); err != nil {
					t.Fatalf("handleShowSystem(root-authentication): %v", err)
				}
			})
			if tc.redact {
				if strings.Contains(out, "ROOTPWHASH") {
					t.Errorf("class=%q root-authentication LEAKED root password:\n%s", tc.class, out)
				}
				if !strings.Contains(out, config.SecretDataPlaceholder) {
					t.Errorf("class=%q root-authentication missing placeholder:\n%s", tc.class, out)
				}
			} else if !strings.Contains(out, "ROOTPWHASH") {
				t.Errorf("class=%q root-authentication unexpectedly redacted for privileged class:\n%s", tc.class, out)
			}
		})
	}
}

// TestCLIShowSystemRescueRedacts pins `show system configuration rescue`: the
// raw rescue.conf text (full active config with cleartext secrets, #4056) is
// reparsed and masked for a VIEW-only class via LoadRescueConfigRedacted.
func TestCLIShowSystemRescueRedacts(t *testing.T) {
	store := newCLISecretStore(t)
	if err := store.SaveRescueConfig(); err != nil {
		t.Fatalf("SaveRescueConfig(): %v", err)
	}
	for _, tc := range classWantsRedaction {
		t.Run(tc.class, func(t *testing.T) {
			c := &CLI{store: store, userClass: tc.class}
			out := captureStdout(t, func() {
				if err := c.handleShowSystem([]string{"configuration", "rescue"}); err != nil {
					t.Fatalf("handleShowSystem(configuration rescue): %v", err)
				}
			})
			if tc.redact {
				for _, leak := range cliSecretSentinels {
					if strings.Contains(out, leak) {
						t.Errorf("class=%q rescue LEAKED cleartext secret %q:\n%s", tc.class, leak, out)
					}
				}
				if !strings.Contains(out, config.SecretDataPlaceholder) {
					t.Errorf("class=%q rescue missing placeholder:\n%s", tc.class, out)
				}
			} else if !strings.Contains(out, "CLI-LEAK-IKE-PSK") {
				t.Errorf("class=%q rescue unexpectedly redacted for privileged class:\n%s", tc.class, out)
			}
		})
	}
}

// TestShowConfigRedactedHelper unit-tests the redact predicate directly so the
// per-class policy is pinned independently of the render plumbing.
func TestShowConfigRedactedHelper(t *testing.T) {
	for _, tc := range classWantsRedaction {
		c := &CLI{userClass: tc.class}
		if got := c.showConfigRedacted(); got != tc.redact {
			t.Errorf("showConfigRedacted(class=%q) = %v, want %v", tc.class, got, tc.redact)
		}
	}
	// An unknown (never-configured) class fails closed.
	c := &CLI{userClass: "bogus-class"}
	if !c.showConfigRedacted() {
		t.Errorf("showConfigRedacted(unknown class) = false, want true (fail-closed)")
	}
}
