package networkd

import (
	"errors"
	"slices"
	"testing"
)

// #16791: one managed row whose netdev does not exist (an unzoned VLAN unit
// such as ge-0-0-1.60, an over-IFNAMSIZ br-*, or a transiently absent
// dynamically-created device) must not fail the whole reconfigure batch.
//
// Pre-fix Apply issued ONE `networkctl reconfigure -- <all names>` argv.
// networkctl resolves every operand before acting, so the absent name made
// the whole call fail ("Failed to resolve interface ...: No such device",
// rc=1, nothing reconfigured), Apply recorded #4954 debt for EVERY name,
// and every later Apply re-ran the same doomed batch — the forced
// reconfigure of the existing links (#5718/#6912) never ran and the debt
// could never clear while the absent row persisted.
//
// Post-fix: reconfigure is per-interface, names that definitively resolve
// to no live link are skipped and carry NO debt, and a failure is isolated
// to (and owed only by) its own name.
//
// FAIL-ON-REVERT: restore the single-batch argv (or record debt for the
// absent/skipped names) and every test in this file reds.

// stubLinkExists16791 models the kernel link inventory for a test: names in
// present resolve, everything else is definitively absent. It restores the
// production lookup on cleanup, like the runNetworkctl stubs.
func stubLinkExists16791(t *testing.T, present map[string]bool) {
	t.Helper()
	orig := linkExists
	linkExists = func(name string) (bool, error) {
		return present[name], nil
	}
	t.Cleanup(func() { linkExists = orig })
}

// absentRowIfaces16791 is the acceptance fixture from the issue: an existing
// managed link (wan0, modelled on a name the stub marks present) plus the
// unzoned VLAN row ge-0-0-1.60 whose kernel child was never created, with a
// second existing link after it so order and isolation are both observable.
func absentRowIfaces16791() []InterfaceConfig {
	return []InterfaceConfig{
		{Name: "wan0", MACAddress: "52:54:00:aa:bb:c0", Addresses: []string{"10.0.0.10/24"}},
		{Name: "ge-0-0-1.60", MACAddress: "52:54:00:aa:bb:c1", Addresses: []string{"10.0.60.10/24"}},
		{Name: "dmz0", MACAddress: "52:54:00:aa:bb:c2", Addresses: []string{"10.0.30.10/24"}},
	}
}

// with an unzoned ge-0-0-1.60 row present, the tail reconfigures the
// existing links successfully and clears their debt — and stays clear on a
// steady-state Apply instead of re-running a doomed batch forever.
func TestReconfigureAbsentRowDoesNotPoisonBatch16791(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	stubLinkExists16791(t, map[string]bool{"wan0": true, "dmz0": true})
	m := NewInDir(t.TempDir())

	var reconfigureArgs [][]string
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "reconfigure" {
			// Model real networkctl faithfully: an operand that resolves
			// to no device fails the call. If the absent name ever
			// reaches an argv, this stub fails it exactly as networkd
			// 262 does — so a green run proves it never did.
			for _, operand := range args[2:] {
				if operand == "ge-0-0-1.60" {
					return errors.New("Failed to resolve interface \"ge-0-0-1.60\": No such device")
				}
			}
			reconfigureArgs = append(reconfigureArgs, append([]string(nil), args...))
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := absentRowIfaces16791()
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("Apply with an absent managed row must succeed: %v", err)
	}

	// The existing links — and ONLY they — were reconfigured, per
	// interface, in row order. The absent name appears in no argv.
	want := [][]string{
		{"reconfigure", "--", "wan0"},
		{"reconfigure", "--", "dmz0"},
	}
	if !slices.EqualFunc(reconfigureArgs, want, func(a, b []string) bool { return slices.Equal(a, b) }) {
		t.Fatalf("reconfigure argv = %v, want %v (existing links only, absent row isolated)", reconfigureArgs, want)
	}

	// No debt is owed: neither for the succeeded links nor for the absent
	// row (there is no link to apply addresses to).
	m.mu.Lock()
	pending := m.reconfigurePending
	m.mu.Unlock()
	if len(pending) != 0 {
		t.Fatalf("reconfigurePending = %v, want empty: existing links succeeded and the absent row owes nothing", pending)
	}

	// Steady state: an identical Apply must NOT re-run the tail. Pre-fix
	// the never-clearing debt forced the doomed batch on every Apply.
	before := len(reconfigureArgs)
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("steady-state Apply: %v", err)
	}
	if len(reconfigureArgs) != before {
		t.Fatalf("steady-state Apply re-ran reconfigure (%d -> %d calls): the absent row's debt never cleared", before, len(reconfigureArgs))
	}
}

// TestReconfigureFailureIsolatedToItsOwnName16791: a genuine reconfigure
// failure on an EXISTING link is still warn-only, still owed (#4954), and
// retried — but it must not drag the other existing links' success down
// with it, and the absent row must not join the debt either.
func TestReconfigureFailureIsolatedToItsOwnName16791(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	stubLinkExists16791(t, map[string]bool{"wan0": true, "dmz0": true})
	m := NewInDir(t.TempDir())

	failDMZ := true
	var attempted []string
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "reconfigure" {
			attempted = append(attempted, args[2])
			if failDMZ && args[2] == "dmz0" {
				return errors.New("simulated reconfigure failure on dmz0")
			}
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := absentRowIfaces16791()
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("Apply must stay warn-only on reconfigure failure: %v", err)
	}
	// wan0 attempted (and succeeded), dmz0 attempted (and failed), the
	// absent row never attempted.
	if want := []string{"wan0", "dmz0"}; !slices.Equal(attempted, want) {
		t.Fatalf("attempted reconfigures = %v, want %v", attempted, want)
	}
	m.mu.Lock()
	pending := m.reconfigurePending
	m.mu.Unlock()
	if len(pending) != 1 || !pending["dmz0"] {
		t.Fatalf("reconfigurePending = %v, want exactly {dmz0}: only the failed existing link owes a retry", pending)
	}

	// The debt forces a retry on an identical Apply; when dmz0 recovers the
	// debt clears and steady state is quiet again.
	attempted = nil
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("retry Apply: %v", err)
	}
	if len(attempted) == 0 {
		t.Fatal("identical retry did not re-attempt reconfigure despite the dmz0 debt")
	}
	failDMZ = false
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("recovering Apply: %v", err)
	}
	m.mu.Lock()
	pending = m.reconfigurePending
	m.mu.Unlock()
	if len(pending) != 0 {
		t.Fatalf("reconfigurePending = %v after recovery, want empty", pending)
	}
}

// TestReconfigureAbsentRowAppearingLaterIsReconfigured16791: skipping an
// absent name must not blacklist it. When the link later appears (the unit
// gets zoned and its VLAN child is created), the next Apply that runs the
// tail reconfigures it like any other managed link.
func TestReconfigureAbsentRowAppearingLaterIsReconfigured16791(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	present := map[string]bool{"wan0": true, "dmz0": true}
	stubLinkExists16791(t, present)
	m := NewInDir(t.TempDir())

	var reconfigureArgs [][]string
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "reconfigure" {
			reconfigureArgs = append(reconfigureArgs, append([]string(nil), args...))
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := absentRowIfaces16791()
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("first Apply: %v", err)
	}
	for _, argv := range reconfigureArgs {
		if slices.Contains(argv, "ge-0-0-1.60") {
			t.Fatalf("absent row was reconfigured while it had no link: %v", argv)
		}
	}

	// The link appears; a changed Apply (a new address on wan0) re-runs the
	// tail, and now the previously-absent name is included.
	present["ge-0-0-1.60"] = true
	reconfigureArgs = nil
	changed := absentRowIfaces16791()
	changed[0].Addresses = []string{"10.0.0.11/24"}
	if err := m.Apply(changed); err != nil {
		t.Fatalf("Apply after the link appeared: %v", err)
	}
	want := [][]string{
		{"reconfigure", "--", "wan0"},
		{"reconfigure", "--", "ge-0-0-1.60"},
		{"reconfigure", "--", "dmz0"},
	}
	if !slices.EqualFunc(reconfigureArgs, want, func(a, b []string) bool { return slices.Equal(a, b) }) {
		t.Fatalf("reconfigure argv after link appeared = %v, want %v", reconfigureArgs, want)
	}
}

// TestReconfigureInconclusiveLookupStillAttempts16791: an existence lookup
// that errors inconclusively (not a definitive absence) must NOT drop the
// name — fail-open toward attempting, so a transient lookup failure never
// silently skips address application for a real link. Its failure is then
// ordinary #4954 debt.
func TestReconfigureInconclusiveLookupStillAttempts16791(t *testing.T) {
	resetReloadDebtForTest(t)
	rpFilterFixture(t)
	origLink := linkExists
	linkExists = func(name string) (bool, error) {
		return false, errors.New("simulated inconclusive lookup failure")
	}
	t.Cleanup(func() { linkExists = origLink })
	m := NewInDir(t.TempDir())

	var attempted []string
	orig := runNetworkctl
	runNetworkctl = func(args ...string) error {
		if len(args) > 0 && args[0] == "reconfigure" {
			attempted = append(attempted, args[2])
			return errors.New("simulated reconfigure failure")
		}
		return nil
	}
	t.Cleanup(func() { runNetworkctl = orig })

	ifaces := []InterfaceConfig{
		{Name: "wan0", MACAddress: "52:54:00:aa:bb:c0", Addresses: []string{"10.0.0.10/24"}},
	}
	if err := m.Apply(ifaces); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if want := []string{"wan0"}; !slices.Equal(attempted, want) {
		t.Fatalf("attempted = %v, want %v: an inconclusive lookup must still attempt the reconfigure", attempted, want)
	}
	m.mu.Lock()
	pending := m.reconfigurePending
	m.mu.Unlock()
	if len(pending) != 1 || !pending["wan0"] {
		t.Fatalf("reconfigurePending = %v, want {wan0}: an attempted-and-failed name owes a retry", pending)
	}
}

// TestIsNoSuchInterface16791 pins the absence classifier: only a definitive
// no-such-interface error counts; any other lookup failure is inconclusive.
func TestIsNoSuchInterface16791(t *testing.T) {
	if !isNoSuchInterface(errors.New("route ip+net: no such network interface")) {
		t.Fatal("the InterfaceByName absence wording must classify as absent")
	}
	if isNoSuchInterface(errors.New("operation not permitted")) {
		t.Fatal("an unrelated lookup error must not classify as absent")
	}
}
