// #5811: global-only `clear` commands (whose backend can ONLY clear
// everything) previously recognized a fixed keyword prefix and silently
// DISCARDED any trailing tokens, then performed the unscoped mutation — a
// scoped-LOOKING command reported success while wiping the ENTIRE
// cache/counter/table. These tests pin the exact-arity rejection on the
// IN-PROCESS CLI, mirroring cmd/cli, so the two parsers reject the same input
// identically.
//
// Fail-on-revert: drop a `requireClearNoScope(...)` guard (return to discarding
// the suffix) and the matching reject test flips RED — no error is returned and
// (for the dp-backed handlers) the clear method runs.
package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
)

// arityClearDP is a cliRuntime that reports IsLoaded()==true and records the
// destructive dataplane clears a handler would issue, so a test can assert a
// scoped-looking clear ran NONE of them. It embeds *dataplane.Manager to
// satisfy the full cliRuntime surface; only IsLoaded + the clear methods are
// overridden.
type arityClearDP struct {
	*dataplane.Manager

	natCounters    int
	allCounters    int
	filterCounters int
	policyCounters int
}

func (d *arityClearDP) IsLoaded() bool              { return true }
func (d *arityClearDP) ClearNATRuleCounters() error { d.natCounters++; return nil }
func (d *arityClearDP) ClearAllCounters() error     { d.allCounters++; return nil }
func (d *arityClearDP) ClearFilterCounters() error  { d.filterCounters++; return nil }
func (d *arityClearDP) ClearPolicyCounters() error  { d.policyCounters++; return nil }

func newArityDP() *arityClearDP { return &arityClearDP{Manager: dataplane.New()} }

// A trailing scope operand must ERROR before any dataplane mutation for every
// global-only clear command.
func TestClearGlobalOnlyTrailingScopeRejected_5811(t *testing.T) {
	tests := []struct {
		name string
		call func(c *CLI) error
	}{
		{"arp addr via dispatch", func(c *CLI) error { return c.handleClear([]string{"arp", "192.0.2.10"}) }},
		{"arp addr", func(c *CLI) error { return c.handleClearArp([]string{"192.0.2.10"}) }},
		{"ipv6 neighbors iface", func(c *CLI) error { return c.handleClearIPv6([]string{"neighbors", "interface", "ge-0-0-0"}) }},
		{"interfaces statistics iface", func(c *CLI) error { return c.handleClearInterfaces([]string{"statistics", "ge-0-0-0"}) }},
		{"system config-lock session", func(c *CLI) error { return c.handleClearSystem([]string{"config-lock", "session", "42"}) }},
		{"nat statistics rule", func(c *CLI) error { return c.handleClearSecurity([]string{"nat", "statistics", "rule", "web"}) }},
		{"nat persistent-nat-table pool", func(c *CLI) error {
			return c.handleClearSecurity([]string{"nat", "source", "persistent-nat-table", "pool", "p1"})
		}},
		{"security counters zone", func(c *CLI) error { return c.handleClearSecurity([]string{"counters", "zone", "untrust"}) }},
		{"policies hit-count selector", func(c *CLI) error {
			return c.handleClearSecurity([]string{"policies", "hit-count", "from-zone", "trust"})
		}},
		{"firewall all filter", func(c *CLI) error { return c.handleClearFirewall([]string{"all", "filter", "edge"}) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dp := newArityDP()
			// Store intentionally nil: every arity guard returns BEFORE any
			// store/dataplane/exec access, so a scoped-looking clear never
			// reaches a mutation.
			c := &CLI{dp: dp}
			err := tt.call(c)
			if err == nil {
				t.Fatalf("%s: expected an error for a scoped-looking global clear, got nil", tt.name)
			}
			if !strings.Contains(err.Error(), "takes no scope") {
				t.Fatalf("%s: error %q does not explain the no-scope rejection", tt.name, err)
			}
			if n := dp.natCounters + dp.allCounters + dp.filterCounters + dp.policyCounters; n != 0 {
				t.Fatalf("%s: a dataplane clear ran (%d total); a scoped-looking clear must wipe NOTHING", tt.name, n)
			}
		})
	}
}

// The bare (exact-arity) form of each dp-backed global-only clear still runs.
func TestClearGlobalOnlyBareStillClears_5811(t *testing.T) {
	// #16457: `clear firewall all` also resets kernel lo0 counters via
	// netlink; stub the seam so this arity test needs no CAP_NET_ADMIN.
	origReset := resetLo0CountersCLI
	resetLo0CountersCLI = func() error { return nil }
	defer func() { resetLo0CountersCLI = origReset }()
	tests := []struct {
		name  string
		call  func(c *CLI) error
		count func(d *arityClearDP) int
	}{
		{"nat statistics", func(c *CLI) error { return c.handleClearSecurity([]string{"nat", "statistics"}) }, func(d *arityClearDP) int { return d.natCounters }},
		{"security counters", func(c *CLI) error { return c.handleClearSecurity([]string{"counters"}) }, func(d *arityClearDP) int { return d.allCounters }},
		{"policies hit-count", func(c *CLI) error { return c.handleClearSecurity([]string{"policies", "hit-count"}) }, func(d *arityClearDP) int { return d.policyCounters }},
		{"firewall all", func(c *CLI) error { return c.handleClearFirewall([]string{"all"}) }, func(d *arityClearDP) int { return d.filterCounters }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dp := newArityDP()
			c := &CLI{dp: dp}
			var err error
			_ = captureStdout(t, func() { err = tt.call(c) })
			if err != nil {
				t.Fatalf("%s: bare form returned unexpected error: %v", tt.name, err)
			}
			if got := tt.count(dp); got != 1 {
				t.Fatalf("%s: bare form ran the clear %d times, want 1", tt.name, got)
			}
		})
	}
}
