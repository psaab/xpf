package daemon

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/natshow"
)

func persistentNatLeaseScopeDaemon(v uint32) *uint32 {
	return &v
}

// #8607: the persistent-NAT SHOW table under the userspace dataplane.
//
// The reported symptom is a RENDERING — "No persistent NAT bindings" for a pool
// that is translating — so the cells assert the rendering, not just the
// conversion. A cell that only checked the intermediate slice would pass while
// the operator still saw the empty line.

func leaseWire8607(src string, sport uint16, nat string, nport uint16, remaining, timeout time.Duration) dpuserspace.IdleLeaseWire {
	return dpuserspace.IdleLeaseWire{
		RoutingScope:   persistentNatLeaseScopeDaemon(0),
		Pool:           "pool-snat-pool",
		Protocol:       6,
		SrcIP:          src,
		SrcPort:        sport,
		TranslatedIP:   nat,
		TranslatedPort: nport,
		RemainingNs:    uint64(remaining),
		TimeoutNs:      uint64(timeout),
	}
}

// TestHelperLeasesRenderAsPersistentBindings8607 is the fail-on-revert cell for
// the defect itself: the exact values from the bug report must reach the
// rendered table.
//
// MUTATION: drop the ReplaceAll call in refreshPersistentNatShowTable (or
// convert to an empty slice) and this reds with the "No persistent NAT
// bindings" line the issue reports.
func TestHelperLeasesRenderAsPersistentBindings8607(t *testing.T) {
	now := time.Now()
	leases := []dpuserspace.IdleLeaseWire{
		leaseWire8607("10.0.61.241", 39165, "172.16.80.7", 30000, 4*time.Minute, 5*time.Minute),
		leaseWire8607("10.0.61.241", 34389, "172.16.80.7", 30001, 5*time.Minute, 5*time.Minute),
	}

	table := dataplane.NewPersistentNATTable()
	table.ReplaceAll(persistentNatBindingsFromLeases(leases, now))

	dp := dataplane.New()
	dp.PersistentNAT = table
	var b strings.Builder
	natshow.RenderPersistent(&b, dp)
	out := b.String()

	if strings.Contains(out, "No persistent NAT bindings") {
		t.Fatalf("the table still renders EMPTY for two live helper leases — this is the "+
			"#8607 symptom verbatim:\n%s", out)
	}
	for _, want := range []string{
		"Total persistent NAT bindings: 2",
		"10.0.61.241", "39165", "172.16.80.7", "30000",
		"34389", "30001", "pool-snat-pool",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered table is missing %q:\n%s", want, out)
		}
	}
}

// TestPersistentBindingTimeoutIsTheHELPERSRemaining8607 pins the derivation the
// conversion exists for.
//
// The wire carries REMAINING lifetime, never an absolute deadline (#8121 design
// note 2: expires_at_ns is CLOCK_MONOTONIC and boot-relative). The renderer
// computes remaining as time.Until(LastSeen + Timeout), so stamping LastSeen =
// now would display the FULL timeout for every binding on every refresh —
// a countdown from a value it never had, and one that would look plausible.
//
// Two leases with DIFFERENT remaining lifetimes are used deliberately: with one
// sample, "displays the remaining" and "displays the timeout" are the same
// number whenever remaining == timeout.
//
// MUTATION: set LastSeen: now instead of back-dating, and the 4-minute row
// renders 5m.
func TestPersistentBindingTimeoutIsTheHELPERSRemaining8607(t *testing.T) {
	now := time.Now()
	got := persistentNatBindingsFromLeases([]dpuserspace.IdleLeaseWire{
		leaseWire8607("10.0.61.241", 39165, "172.16.80.7", 30000, 4*time.Minute, 5*time.Minute),
		leaseWire8607("10.0.61.242", 39166, "172.16.80.7", 30002, 30*time.Second, 5*time.Minute),
	}, now)
	if len(got) != 2 {
		t.Fatalf("converted %d bindings, want 2", len(got))
	}
	for i, wantRemaining := range []time.Duration{4 * time.Minute, 30 * time.Second} {
		b := got[i]
		remaining := b.LastSeen.Add(b.Timeout).Sub(now)
		if d := remaining - wantRemaining; d > time.Second || d < -time.Second {
			t.Errorf("binding %d renders %v remaining, want ~%v — the helper's remaining "+
				"lifetime was replaced by the full timeout (#8607)", i, remaining, wantRemaining)
		}
	}
}

// TestPersistentPermitScopeComesFromTheRemoteTuple8607 pins the three-way
// #2823/#3193 scope, which the wire does not carry directly.
//
// All three arms in one cell: with only the any-remote-host case a derivation
// that returned it unconditionally would pass.
//
// MUTATION: return PersistentNATPermitAnyRemoteHost unconditionally -> the
// second and third rows red.
func TestPersistentPermitScopeComesFromTheRemoteTuple8607(t *testing.T) {
	cases := []struct {
		name       string
		remoteIP   string
		remotePort uint16
		want       config.PersistentNATPermit
	}{
		{"no remote", "", 0, config.PersistentNATPermitAnyRemoteHost},
		{"remote host", "203.0.113.9", 0, config.PersistentNATPermitTargetHost},
		{"remote host+port", "203.0.113.9", 443, config.PersistentNATPermitTargetHostPort},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := leaseWire8607("10.0.61.241", 39165, "172.16.80.7", 30000, time.Minute, time.Minute)
			l.RemoteIP, l.RemotePort = tc.remoteIP, tc.remotePort
			got := persistentNatBindingsFromLeases([]dpuserspace.IdleLeaseWire{l}, time.Now())
			if len(got) != 1 {
				t.Fatalf("converted %d bindings, want 1", len(got))
			}
			if got[0].Permit != tc.want {
				t.Errorf("Permit = %v, want %v", got[0].Permit, tc.want)
			}
		})
	}
}

// TestReplaceAllIsASnapshotNotAnAccumulator8607 pins the semantics the userspace
// path needs, in both directions.
//
// The helper owns existence AND expiry — pnat.GC() is unreachable here because
// daemon_run.go skips the sweep it is called from — so a binding the helper has
// released must disappear because it is ABSENT from the next snapshot. Save
// would also be wrong on the way in: it treats a repeat as a refresh and stamps
// LastSeen = now, resetting every binding's displayed lifetime on every tick.
//
// MUTATION: implement the refresh as Clear + a loop of Save and the "carries the
// helper's remaining, not a reset one" assertion reds.
func TestReplaceAllIsASnapshotNotAnAccumulator8607(t *testing.T) {
	now := time.Now()
	table := dataplane.NewPersistentNATTable()

	first := []dpuserspace.IdleLeaseWire{
		leaseWire8607("10.0.61.241", 39165, "172.16.80.7", 30000, 5*time.Minute, 5*time.Minute),
		leaseWire8607("10.0.61.242", 39166, "172.16.80.7", 30001, 5*time.Minute, 5*time.Minute),
	}
	table.ReplaceAll(persistentNatBindingsFromLeases(first, now))
	if n := len(table.All()); n != 2 {
		t.Fatalf("first snapshot: %d bindings, want 2", n)
	}

	// The helper released one and the other has aged 4 minutes.
	later := now.Add(4 * time.Minute)
	second := []dpuserspace.IdleLeaseWire{
		leaseWire8607("10.0.61.241", 39165, "172.16.80.7", 30000, time.Minute, 5*time.Minute),
	}
	table.ReplaceAll(persistentNatBindingsFromLeases(second, later))

	all := table.All()
	if len(all) != 1 {
		t.Fatalf("second snapshot: %d bindings, want 1 — a binding the helper released "+
			"must disappear, and nothing local can expire it (pnat.GC() is behind the "+
			"skipped sweep) (#8607)", len(all))
	}
	if all[0].SrcPort != 39165 {
		t.Errorf("the surviving binding is %d, want 39165", all[0].SrcPort)
	}
	remaining := all[0].LastSeen.Add(all[0].Timeout).Sub(later)
	if d := remaining - time.Minute; d > time.Second || d < -time.Second {
		t.Errorf("surviving binding renders %v remaining, want ~1m — a refresh that "+
			"Save()d instead of replacing would reset it to the full timeout (#8607)",
			remaining)
	}
}

// TestEmptyHelperExportStillRendersTheEmptyLine8607 is the negative control.
//
// "The helper has no bindings" must still produce the existing line verbatim —
// this is what keeps the three pre-existing natshow cells honest rather than
// merely still-passing, and it is the arm that distinguishes a real fix from
// one that just puts something in the table.
func TestEmptyHelperExportStillRendersTheEmptyLine8607(t *testing.T) {
	table := dataplane.NewPersistentNATTable()
	table.ReplaceAll(persistentNatBindingsFromLeases(nil, time.Now()))
	dp := dataplane.New()
	dp.PersistentNAT = table
	var b strings.Builder
	natshow.RenderPersistent(&b, dp)
	if got, want := b.String(), "No persistent NAT bindings\n"; got != want {
		t.Errorf("empty export rendered %q, want %q", got, want)
	}
}

// TestUnparseableLeaseAddressIsSkippedNotRendered8607: the wire carries
// addresses as STRINGS, and a lease whose address does not parse must be
// dropped rather than rendered as the zero Addr — an invalid row in an operator
// table is worse than a missing one, and netip's zero value prints as "invalid
// IP".
func TestUnparseableLeaseAddressIsSkippedNotRendered8607(t *testing.T) {
	good := leaseWire8607("10.0.61.241", 39165, "172.16.80.7", 30000, time.Minute, time.Minute)
	badSrc := leaseWire8607("not-an-ip", 1, "172.16.80.7", 2, time.Minute, time.Minute)
	badNat := leaseWire8607("10.0.61.242", 3, "", 4, time.Minute, time.Minute)

	got := persistentNatBindingsFromLeases(
		[]dpuserspace.IdleLeaseWire{good, badSrc, badNat}, time.Now())
	if len(got) != 1 {
		t.Fatalf("converted %d bindings, want 1 (only the well-formed lease)", len(got))
	}
	if got[0].SrcPort != 39165 {
		t.Errorf("the surviving binding is %d, want 39165", got[0].SrcPort)
	}
}

// TestRefreshKeepsThePreviousSnapshotOnError8607 pins the difference between
// "the helper has no bindings" and "we could not ask it".
//
// Replacing on an error would render "No persistent NAT bindings" — the exact
// false statement #8607 is about — for a helper that is merely restarting, and
// would do it for the whole 30-second tick. A cell that only drove the success
// path cannot see this: both paths leave a table that renders *something*.
//
// MUTATION: drop the `if err != nil` arm from applyPersistentNatShowRefresh and
// this reds with an emptied table.
func TestRefreshKeepsThePreviousSnapshotOnError8607(t *testing.T) {
	now := time.Now()
	table := dataplane.NewPersistentNATTable()
	if !applyPersistentNatShowRefresh(table, []dpuserspace.IdleLeaseWire{
		leaseWire8607("10.0.61.241", 39165, "172.16.80.7", 30000, 5*time.Minute, 5*time.Minute),
	}, nil, now) {
		t.Fatal("the success path must report that it replaced")
	}
	if n := len(table.All()); n != 1 {
		t.Fatalf("precondition: %d bindings after a good refresh, want 1", n)
	}

	if applyPersistentNatShowRefresh(table, nil, errRefresh8607, now) {
		t.Error("an errored refresh must NOT report a replace")
	}
	if n := len(table.All()); n != 1 {
		t.Errorf("an errored refresh emptied the table (%d bindings, want 1 kept). The "+
			"operator would then be told there are no persistent NAT bindings because "+
			"the helper was unreachable — which is the #8607 symptom, reintroduced as "+
			"an intermittent one", n)
	}

	// ...and a SUCCESSFUL empty export DOES empty it: "none" is an answer.
	if !applyPersistentNatShowRefresh(table, nil, nil, now) {
		t.Fatal("a successful empty export must report a replace")
	}
	if n := len(table.All()); n != 0 {
		t.Errorf("a successful EMPTY export left %d bindings; the helper is authoritative "+
			"for existence, so an empty answer must empty the table", n)
	}
}

var errRefresh8607 = errors.New("helper unreachable")

// TestPersistentNatShowRefreshIsWiredIntoRun8607 binds the WIRING.
//
// Every cell above drives the refresh directly. None of them notices if
// daemon_run.go never starts the loop — the shape that leaves a fix present and
// inert, and the shape this campaign keeps meeting. The loop cannot be driven
// from a unit test (it needs a live backend), so the binding is made at the
// source level.
//
// It also asserts the loop is started from daemon_run.go and NOT only from the
// cluster-comms wiring where the #8121 push loop lives: that one is gated on
// being RG master, so a standalone box with a persistent-NAT pool would keep
// the empty table this exists to fix.
//
// MUTATION: delete the `go d.runPersistentNatShowRefreshLoop(ctx)` block from
// daemon_run.go and this reds.
func TestPersistentNatShowRefreshIsWiredIntoRun8607(t *testing.T) {
	src, err := os.ReadFile("daemon_run.go")
	if err != nil {
		t.Fatalf("read daemon_run.go: %v", err)
	}
	if !strings.Contains(string(src), "runPersistentNatShowRefreshLoop(ctx)") {
		t.Error("daemon_run.go does not start runPersistentNatShowRefreshLoop — the " +
			"persistent-NAT SHOW table is never refreshed, so the fix is present and " +
			"inert and `show security nat source persistent-nat-table` stays empty (#8607)")
	}
	// The refresher must not be reachable ONLY from cluster comms: that path is
	// gated on RG-master and would leave a standalone box unfixed.
	wiring, err := os.ReadFile("daemon_ha_comms_wiring.go")
	if err != nil {
		t.Fatalf("read daemon_ha_comms_wiring.go: %v", err)
	}
	if strings.Contains(string(wiring), "runPersistentNatShowRefreshLoop") &&
		!strings.Contains(string(src), "runPersistentNatShowRefreshLoop(ctx)") {
		t.Error("the SHOW refresh is started only from cluster-comms wiring, which is " +
			"gated on being RG master; a standalone box would keep the empty table")
	}
}
