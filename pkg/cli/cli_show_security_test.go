package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

type firewallFilterUserspaceDP struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
}

func (f *firewallFilterUserspaceDP) Status() (dpuserspace.ProcessStatus, error) {
	return f.status, nil
}

func newFirewallFilterTestStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"firewall family inet filter bandwidth-output term 0 from destination-port 80",
		"firewall family inet filter bandwidth-output term 0 then accept",
		"firewall family inet6 filter bandwidth-output term 0 from destination-port 5201",
		"firewall family inet6 filter bandwidth-output term 0 then count iperf-a-v6",
		"firewall family inet6 filter bandwidth-output term 0 then accept",
		"firewall family inet6 filter bandwidth-output term 1 from destination-port 5300",
		"firewall family inet6 filter bandwidth-output term 1 then accept",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestHandleShowFirewallFilterHonorsFamilyAndUserspaceCounters(t *testing.T) {
	store := newFirewallFilterTestStore(t)
	c := &CLI{
		store: store,
		dp: &firewallFilterUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
					{
						Family:     "inet6",
						FilterName: "bandwidth-output",
						TermName:   "0",
						Packets:    12,
						Bytes:      3456,
					},
				},
			},
		},
	}

	var callErr error
	out := captureStdout(t, func() {
		callErr = c.handleShow([]string{"firewall", "filter", "bandwidth-output", "family", "inet6"})
	})
	if callErr != nil {
		t.Fatalf("handleShow() error = %v", callErr)
	}
	if !strings.Contains(out, "Filter: bandwidth-output (family inet6)") {
		t.Fatalf("output = %q, want inet6 filter heading", out)
	}
	if strings.Contains(out, "destination-port 80") {
		t.Fatalf("output = %q, unexpectedly rendered inet family term", out)
	}
	if !strings.Contains(out, "destination-port 5201") {
		t.Fatalf("output = %q, want inet6 destination-port 5201", out)
	}
	if !strings.Contains(out, "Hit count: 12 packets, 3456 bytes") {
		t.Fatalf("output = %q, want userspace hit counters", out)
	}
	if strings.Count(out, "Hit count:") != 1 {
		t.Fatalf("output = %q, want a hit count only for the counted term", out)
	}
}

func TestScreenSYNCookieCounterRowsUsesUserspaceStatus(t *testing.T) {
	c := &CLI{
		dp: &firewallFilterUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				Bindings: []dpuserspace.BindingStatus{
					{
						SYNCookieChallenges:        3,
						SYNCookieSecretUnavailable: 5,
						SYNCookieSynAckSent:        7,
						SYNCookieAckRstSent:        11,
						SYNCookieReplyBudgetDrops:  13,
						SYNCookieAckValid:          17,
						SYNCookieAckInvalid:        19,
						SYNCookieBypass:            23,
					},
					{
						SYNCookieChallenges:        17,
						SYNCookieSecretUnavailable: 19,
						SYNCookieSynAckSent:        29,
						SYNCookieAckRstSent:        31,
						SYNCookieReplyBudgetDrops:  37,
						SYNCookieAckValid:          41,
						SYNCookieAckInvalid:        43,
						SYNCookieBypass:            47,
					},
				},
			},
		},
	}

	out := c.screenSYNCookieCounterRows()
	for _, want := range []string{
		"Userspace SYN-cookie scope",
		"all bindings",
		"SYN-cookie challenges",
		"20",
		"SYN-cookie secret unavailable",
		"24",
		"SYN-cookie SYN-ACK sent",
		"36",
		"SYN-cookie ACK RST sent",
		"42",
		"SYN-cookie budget drops",
		"50",
		"SYN-cookie ACK valid",
		"58",
		"SYN-cookie ACK invalid",
		"62",
		"SYN-cookie bypass",
		"70",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("screen SYN-cookie rows missing %q:\n%s", want, out)
		}
	}
}

// matchPoliciesCLITestConfig builds a config with a single trust->untrust
// policy whose terms reference a restricted address-book entry (not
// "any"), so the test exercises the actual #1711 false-positive shape in
// the local in-process simulator.
func matchPoliciesCLITestConfig(t *testing.T) *config.Config {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address trust-net 10.0.1.0/24;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy restricted-allow {
                match { source-address trust-net; destination-address trust-net; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil {
		t.Fatal("ActiveConfig() = nil")
	}
	return cfg
}

// TestShowMatchPoliciesValidation covers the local interactive CLI
// simulator (which runs in-process, not via the gRPC handler): malformed
// source/destination IP input must return an error rather than silently
// wildcard-matching, while empty IPs preserve the "any" semantics (#1711).
func TestShowMatchPoliciesValidation(t *testing.T) {
	cfg := matchPoliciesCLITestConfig(t)
	c := &CLI{}

	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		wantMatch bool // for the no-error cases: must the simulator report a match?
	}{
		{
			name:    "invalid source-ip",
			args:    []string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "10.0.0.999"},
			wantErr: true,
		},
		{
			name:    "invalid destination-ip",
			args:    []string{"from-zone", "trust", "to-zone", "untrust", "destination-ip", "garbage"},
			wantErr: true,
		},
		{
			name:    "cidr in ip field rejected",
			args:    []string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "10.0.0.0/24"},
			wantErr: true,
		},
		{
			name:      "empty ips match any",
			args:      []string{"from-zone", "trust", "to-zone", "untrust"},
			wantErr:   false,
			wantMatch: true,
		},
		{
			name:      "valid in-term ip",
			args:      []string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "10.0.1.5", "destination-ip", "10.0.1.6"},
			wantErr:   false,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			out := captureStdout(t, func() {
				err = c.showMatchPolicies(cfg, tt.args)
			})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("showMatchPolicies(%v) returned no error; out = %q (false-positive #1711)", tt.args, out)
				}
				if strings.Contains(out, "Matching policy") {
					t.Fatalf("showMatchPolicies(%v) printed a match for malformed input: %q", tt.args, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("showMatchPolicies(%v) error = %v, want nil", tt.args, err)
			}
			// Assert the actual simulator verdict, not just "no error" — a
			// silent default-deny would otherwise pass the no-error cases.
			gotMatch := strings.Contains(out, "Matching policy") && strings.Contains(out, "restricted-allow")
			if gotMatch != tt.wantMatch {
				t.Fatalf("showMatchPolicies(%v) match=%v, want %v; out = %q", tt.args, gotMatch, tt.wantMatch, out)
			}
		})
	}
}

// TestTestPolicyValidation covers the operational `test policy` CLI
// simulator (pkg/cli/cli_request.go testPolicy), a separate in-process
// copy of the matcher. Malformed IPs must error rather than
// wildcard-match; empty/valid inputs report a match (#1711).
func TestTestPolicyValidation(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
security {
    address-book {
        global {
            address trust-net 10.0.1.0/24;
        }
    }
    zones {
        security-zone trust;
        security-zone untrust;
    }
    policies {
        from-zone trust to-zone untrust {
            policy restricted-allow {
                match { source-address trust-net; destination-address trust-net; application any; }
                then { permit; }
            }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	c := &CLI{store: store}

	tests := []struct {
		name      string
		args      []string
		wantErr   bool
		wantMatch bool
	}{
		{
			name:    "invalid source-ip",
			args:    []string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "10.0.0.999"},
			wantErr: true,
		},
		{
			name:    "invalid destination-ip",
			args:    []string{"from-zone", "trust", "to-zone", "untrust", "destination-ip", "garbage"},
			wantErr: true,
		},
		{
			name:      "empty ips match any",
			args:      []string{"from-zone", "trust", "to-zone", "untrust"},
			wantErr:   false,
			wantMatch: true,
		},
		{
			name:      "valid in-term ip",
			args:      []string{"from-zone", "trust", "to-zone", "untrust", "source-ip", "10.0.1.5"},
			wantErr:   false,
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			out := captureStdout(t, func() {
				err = c.testPolicy(tt.args)
			})
			if tt.wantErr {
				if err == nil {
					t.Fatalf("testPolicy(%v) returned no error; out = %q (false-positive #1711)", tt.args, out)
				}
				if strings.Contains(out, "Policy match") {
					t.Fatalf("testPolicy(%v) printed a match for malformed input: %q", tt.args, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("testPolicy(%v) error = %v, want nil", tt.args, err)
			}
			gotMatch := strings.Contains(out, "Policy match") && strings.Contains(out, "restricted-allow")
			if gotMatch != tt.wantMatch {
				t.Fatalf("testPolicy(%v) match=%v, want %v; out = %q", tt.args, gotMatch, tt.wantMatch, out)
			}
		})
	}
}

// addressBookNilFixtureStore builds the shared #6218/#7197 fixture: a real
// address "a1" and a real address-set "s1" (member a1), committed normally,
// then EITHER a nil *Address or a nil *AddressSet map value injected in place
// — the SAME admitted-nil contract compiler_validate_warn_nil_3494_test.go
// codifies for AddressBook.Addresses ("zz-nil-addr") and AddressBook.
// AddressSets ("zz-nil-set"): the tolerant-load / peer-sync path (#1960) can
// deliver a present-but-nil map value here, and #3494 IS that contract, not a
// hypothetical. Reusing its exact key names ties this fixture to that
// established precedent.
func addressBookNilFixtureStore(t *testing.T, injectNilAddress, injectNilSet bool) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"security address-book global address a1 10.0.0.1/32",
		"security address-book global address-set s1 address a1",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	cfg := store.ActiveConfig()
	if cfg == nil || cfg.Security.AddressBook == nil {
		t.Fatalf("fixture missing address book")
	}
	if injectNilAddress {
		cfg.Security.AddressBook.Addresses["zz-nil-addr"] = nil
	}
	if injectNilSet {
		cfg.Security.AddressBook.AddressSets["zz-nil-set"] = nil
	}
	return &CLI{store: store}
}

// TestShowAddressBookNilAddressNoPanic pins #7197: a present-but-nil
// *Address map value crashed the in-process CLI (CLI.Run has no panic
// recovery). Two guards close FOUR dereference sites in
// cli_show_security_objects.go: this one (the Addresses loop head) protects
// its own print (`addr.Name, addr.Value`) AND the filtered-by-name compare
// (`addr.Name != filterName`) — the exact repro trigger, reached only when
// filterName is non-empty. The sibling AddressSets guard (tested separately
// below) is untouched by this fixture (no nil AddressSet present here), so
// this test isolates the Addresses guard: reverting ONLY it must RED this
// test while the AddressSet test stays GREEN.
//
// Both call shapes matter: unfiltered exercises the plain listing loop over
// the nil entry; filtered by the address-SET name "s1" exercises the
// top-level Addresses compare AND (via a real, non-nil member "a1") the
// #6218 item 13 member-detail direct-map-lookup rewrite in the same pass.
//
// RED on revert: dropping the `if addr == nil { continue }` guard panics on
// `addr.Name` for "zz-nil-addr" in both sub-tests below.
func TestShowAddressBookNilAddressNoPanic(t *testing.T) {
	t.Run("unfiltered", func(t *testing.T) {
		c := addressBookNilFixtureStore(t, true, false)
		out := captureStdout(t, func() {
			if err := c.showAddressBook(nil); err != nil {
				t.Fatalf("showAddressBook: %v", err)
			}
		})
		if !strings.Contains(out, "a1") {
			t.Errorf("expected a1 in unfiltered listing, got:\n%s", out)
		}
	})
	t.Run("filtered-by-set-name", func(t *testing.T) {
		c := addressBookNilFixtureStore(t, true, false)
		out := captureStdout(t, func() {
			if err := c.showAddressBook([]string{"s1"}); err != nil {
				t.Fatalf("showAddressBook: %v", err)
			}
		})
		if !strings.Contains(out, "a1") || !strings.Contains(out, "10.0.0.1/32") {
			t.Errorf("expected member detail for a1 (via the row-13 direct-lookup "+
				"rewrite), got:\n%s", out)
		}
	})
}

// TestShowAddressBookNilAddressSetNoPanic pins #7197's mirror guard: a
// present-but-nil *AddressSet map value crashed the same function's
// "Address sets:" listing (`as.Name` in the filter compare, then
// `as.Addresses` / `as.AddressSets` / `as.Name` in the set body). This
// fixture injects ONLY a nil AddressSet (no nil Address), so it isolates the
// AddressSets guard from the Addresses guard above: reverting ONLY the
// AddressSets guard must RED this test while
// TestShowAddressBookNilAddressNoPanic stays GREEN, and vice versa.
//
// RED on revert: dropping the `if as == nil { continue }` guard panics on
// `as.Name` for "zz-nil-set" in both sub-tests below.
func TestShowAddressBookNilAddressSetNoPanic(t *testing.T) {
	t.Run("unfiltered", func(t *testing.T) {
		c := addressBookNilFixtureStore(t, false, true)
		out := captureStdout(t, func() {
			if err := c.showAddressBook(nil); err != nil {
				t.Fatalf("showAddressBook: %v", err)
			}
		})
		if !strings.Contains(out, "s1") {
			t.Errorf("expected s1 in unfiltered listing, got:\n%s", out)
		}
	})
	t.Run("filtered-by-set-name", func(t *testing.T) {
		c := addressBookNilFixtureStore(t, false, true)
		out := captureStdout(t, func() {
			if err := c.showAddressBook([]string{"s1"}); err != nil {
				t.Fatalf("showAddressBook: %v", err)
			}
		})
		if !strings.Contains(out, "a1") || !strings.Contains(out, "10.0.0.1/32") {
			t.Errorf("expected member detail for a1, got:\n%s", out)
		}
	})
}
