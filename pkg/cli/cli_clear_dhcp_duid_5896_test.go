package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dhcp"
)

// seedDUIDs writes placeholder DHCPv6 DUID state files for the named interfaces
// into a manager's state directory. A subsequent clear is then observed purely
// by which files survive: ClearDUID removes exactly one, ClearAllDUIDs removes
// every file carrying the "dhcpv6-duid-" prefix.
func seedDUIDs(t *testing.T, dir string, ifaces ...string) {
	t.Helper()
	for _, ifn := range ifaces {
		p := filepath.Join(dir, "dhcpv6-duid-"+ifn)
		if err := os.WriteFile(p, []byte("duid"), 0o644); err != nil {
			t.Fatalf("seed DUID %s: %v", ifn, err)
		}
	}
}

func duidPresent(t *testing.T, dir, ifn string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dir, "dhcpv6-duid-"+ifn))
	return err == nil
}

// TestHandleClearDHCP_MalformedSelectorGuard_5896 locks the in-process CLI's
// `clear dhcp client-identifier` handler to the SAME malformed-selector guard
// the remote CLI already enforces (#4883-E, cmd/cli/clear.go handleClearDHCP).
//
// The bug (#5896): the in-process handler recognized only a fully-formed
// `interface <name>` selector and let EVERY other shape fall through to the
// unscoped ClearAllDUIDs(), so `clear dhcp client-identifier interface` (no
// name), `... interfce ge-0-0-0` (misspelled selector), or a stray trailing
// token wiped every DHCPv6 DUID on the box instead of the one the operator
// scoped. A bare `clear dhcp client-identifier` (no selector) is the ONLY
// intentional clear-all.
//
// Fail-on-revert: delete the guard and the three malformed cases fall back to
// clear-all (files vanish, err is nil) — flipping wantErr AND the survival
// assertions red. The stray-token case additionally regresses to a scoped
// clear of ge-0-0-0 under the old `len(args) >= 3` branch, which the wantA
// assertion catches.
func TestHandleClearDHCP_MalformedSelectorGuard_5896(t *testing.T) {
	const (
		ifA = "ge-0-0-0"
		ifB = "ge-0-0-1"
	)
	cases := []struct {
		name    string
		args    []string
		wantErr bool
		wantA   bool // ge-0-0-0 DUID file survives the call
		wantB   bool // ge-0-0-1 DUID file survives the call
	}{
		{
			name:    "bare client-identifier is the intentional clear-all",
			args:    []string{"client-identifier"},
			wantErr: false,
			wantA:   false,
			wantB:   false,
		},
		{
			name:    "well-formed scoped clears only that interface",
			args:    []string{"client-identifier", "interface", ifA},
			wantErr: false,
			wantA:   false,
			wantB:   true,
		},
		{
			name:    "interface without a name is rejected, nothing cleared",
			args:    []string{"client-identifier", "interface"},
			wantErr: true,
			wantA:   true,
			wantB:   true,
		},
		{
			name:    "unknown selector token is rejected, nothing cleared",
			args:    []string{"client-identifier", "interfce", ifA},
			wantErr: true,
			wantA:   true,
			wantB:   true,
		},
		{
			name:    "stray trailing token is rejected, nothing cleared",
			args:    []string{"client-identifier", "interface", ifA, "extra"},
			wantErr: true,
			wantA:   true,
			wantB:   true,
		},
	}

	// #15756: the scoped case now resolves through the active config, so
	// the fixture carries a committed store declaring both interfaces.
	clearStore15756 := func(t *testing.T) *configstore.Store {
		t.Helper()
		st, err := configstore.New(filepath.Join(t.TempDir(), "cfg.db"))
		if err != nil {
			t.Fatalf("configstore.New: %v", err)
		}
		if err := st.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := st.LoadMerge("interfaces { ge-0/0/0 { unit 0 { family inet { dhcp; } } } ge-0/0/1 { unit 0 { family inet { dhcp; } } } }"); err != nil {
			t.Fatalf("LoadMerge: %v", err)
		}
		if _, err := st.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		return st
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			mgr, err := dhcp.New(dir, nil, nil)
			if err != nil {
				t.Fatalf("dhcp.New: %v", err)
			}
			seedDUIDs(t, dir, ifA, ifB)

			c := &CLI{dhcp: mgr, store: clearStore15756(t)}
			err = c.handleClearDHCP(tc.args)

			if tc.wantErr && err == nil {
				t.Fatalf("args %v: want error (malformed selector must not silently clear), got nil", tc.args)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("args %v: unexpected error: %v", tc.args, err)
			}
			if got := duidPresent(t, dir, ifA); got != tc.wantA {
				t.Errorf("args %v: DUID %s present=%v, want %v", tc.args, ifA, got, tc.wantA)
			}
			if got := duidPresent(t, dir, ifB); got != tc.wantB {
				t.Errorf("args %v: DUID %s present=%v, want %v", tc.args, ifB, got, tc.wantB)
			}
		})
	}
}

// TestHandleClearDHCPResolvesOperatorSpellings15756 is the #15756
// RED/GREEN cell: a scoped clear must delete the DUID persisted under
// the lease key for every legitimate operator spelling, and must refuse
// (deleting nothing) for unknown / non-DHCP names instead of silently
// succeeding. Pre-fix, `ge-0/0/0` errored at ClearDUID's filename
// validator (file survives), while `ge-0/0/0.0`-adjacent unit/VLAN/unknown
// spellings returned success with the actual unit's file intact.
func TestHandleClearDHCPResolvesOperatorSpellings15756(t *testing.T) {
	newStore := func(t *testing.T) *configstore.Store {
		t.Helper()
		st, err := configstore.New(filepath.Join(t.TempDir(), "cfg.db"))
		if err != nil {
			t.Fatalf("configstore.New: %v", err)
		}
		if err := st.EnterConfigure(); err != nil {
			t.Fatalf("EnterConfigure: %v", err)
		}
		if err := st.LoadMerge("interfaces { ge-0/0/0 { unit 0 { family inet { dhcp; } } } ge-0/0/3 { vlan-tagging; unit 7 { vlan-id 50; family inet6 { dhcpv6; } } } ge-0/0/1 { unit 0 { family inet { address 192.0.2.1/24; } } } }"); err != nil {
			t.Fatalf("LoadMerge: %v", err)
		}
		if _, err := st.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		return st
	}
	clears := []struct{ in, key string }{
		{"ge-0/0/0", "ge-0-0-0"},
		{"ge-0/0/0.0", "ge-0-0-0"},
		{"ge-0-0-0", "ge-0-0-0"},
		{"ge-0/0/3.7", "ge-0-0-3.50"},
		{"ge-0-0-3.7", "ge-0-0-3.50"},
		{"ge-0-0-3.50", "ge-0-0-3.50"},
		{"ge-0/0/3", "ge-0-0-3.50"},
	}
	for _, tc := range clears {
		t.Run("clear "+tc.in, func(t *testing.T) {
			dir := t.TempDir()
			mgr, err := dhcp.New(dir, nil, nil)
			if err != nil {
				t.Fatalf("dhcp.New: %v", err)
			}
			seedDUIDs(t, dir, "ge-0-0-0", "ge-0-0-3.50")
			c := &CLI{dhcp: mgr, store: newStore(t)}
			if err := c.handleClearDHCP([]string{"client-identifier", "interface", tc.in}); err != nil {
				t.Fatalf("clear %q: %v", tc.in, err)
			}
			if duidPresent(t, dir, tc.key) {
				t.Errorf("clear %q: DUID under lease key %q survived", tc.in, tc.key)
			}
			other := "ge-0-0-3.50"
			if tc.key == other {
				other = "ge-0-0-0"
			}
			if !duidPresent(t, dir, other) {
				t.Errorf("clear %q: unrelated DUID %q was deleted", tc.in, other)
			}
		})
	}
	for _, in := range []string{"ge-0/0/9", "ge-0/0/1", "ge-0/0/3.9", "ge-0-0-3.99"} {
		t.Run("refuse "+in, func(t *testing.T) {
			dir := t.TempDir()
			mgr, err := dhcp.New(dir, nil, nil)
			if err != nil {
				t.Fatalf("dhcp.New: %v", err)
			}
			seedDUIDs(t, dir, "ge-0-0-0", "ge-0-0-3.50")
			c := &CLI{dhcp: mgr, store: newStore(t)}
			if err := c.handleClearDHCP([]string{"client-identifier", "interface", in}); err == nil {
				t.Errorf("clear %q succeeded silently, want refusal", in)
			}
			if !duidPresent(t, dir, "ge-0-0-0") || !duidPresent(t, dir, "ge-0-0-3.50") {
				t.Errorf("clear %q deleted a DUID despite refusing", in)
			}
		})
	}
	// Lease-key-shaped but unconfigured names clear idempotently on the
	// exact key named, leaving other units' DUIDs untouched.
	for _, in := range []string{"reth0.0"} {
		t.Run("idempotent "+in, func(t *testing.T) {
			dir := t.TempDir()
			mgr, err := dhcp.New(dir, nil, nil)
			if err != nil {
				t.Fatalf("dhcp.New: %v", err)
			}
			seedDUIDs(t, dir, "ge-0-0-0", "ge-0-0-3.50")
			c := &CLI{dhcp: mgr, store: newStore(t)}
			if err := c.handleClearDHCP([]string{"client-identifier", "interface", in}); err != nil {
				t.Errorf("clear %q: %v, want idempotent success", in, err)
			}
			if !duidPresent(t, dir, "ge-0-0-0") || !duidPresent(t, dir, "ge-0-0-3.50") {
				t.Errorf("clear %q deleted a different unit's DUID", in)
			}
		})
	}
	// No store: a lease-key-shaped name still clears idempotently; a
	// Junos spelling refuses rather than silently succeeding.
	dir := t.TempDir()
	mgr, err := dhcp.New(dir, nil, nil)
	if err != nil {
		t.Fatalf("dhcp.New: %v", err)
	}
	seedDUIDs(t, dir, "ge-0-0-0")
	if err := (&CLI{dhcp: mgr}).handleClearDHCP([]string{"client-identifier", "interface", "ge-0-0-0"}); err != nil {
		t.Errorf("no-store lease-key clear: %v, want idempotent success", err)
	}
	if duidPresent(t, dir, "ge-0-0-0") {
		t.Error("no-store lease-key clear left ge-0-0-0 DUID behind")
	}
	dir2 := t.TempDir()
	mgr2, err := dhcp.New(dir2, nil, nil)
	if err != nil {
		t.Fatalf("dhcp.New: %v", err)
	}
	seedDUIDs(t, dir2, "ge-0-0-0")
	if err := (&CLI{dhcp: mgr2}).handleClearDHCP([]string{"client-identifier", "interface", "ge-0/0/0"}); err == nil {
		t.Error("no-store Junos clear succeeded, want refusal")
	}
	if !duidPresent(t, dir2, "ge-0-0-0") {
		t.Error("no-store Junos clear deleted the DUID despite refusing")
	}
}

// TestHandleClearDHCP_MalformedSelectorRejectedBeforeNilCheck_5896 pins the
// ordering choice: selector validation runs BEFORE the c.dhcp==nil
// short-circuit, so malformed input always errors regardless of DHCP client
// state, matching the remote CLI (which has no nil path). A bare clear-all
// with no running client remains a benign no-op.
func TestHandleClearDHCP_MalformedSelectorRejectedBeforeNilCheck_5896(t *testing.T) {
	c := &CLI{dhcp: nil}
	if err := c.handleClearDHCP([]string{"client-identifier", "interface"}); err == nil {
		t.Fatal("malformed selector with nil dhcp: want error, got nil")
	}
	if err := c.handleClearDHCP([]string{"client-identifier"}); err != nil {
		t.Fatalf("bare clear-all with nil dhcp: unexpected error: %v", err)
	}
}
