package cli

import (
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #5067: `show firewall [filter <name>] effective` compiles its snapshots from
// ActiveConfig(), which commitAndApply promotes via store.Commit() BEFORE the
// dataplane apply runs. A required-protocol-gate apply error leaves the
// dataplane DISARMED while ActiveConfig is already the new generation, so the
// compiled-desired snapshot is NOT what the dataplane is enforcing. The
// effective view must bind its output to the helper-acknowledged generation:
// certify it as live only when the dataplane is armed and the acknowledged
// generation matches the last applied generation, else flag the drift.

// effectiveGenCLIDP stubs the CLI runtime with a fixed ApplyResult (the daemon's
// last successfully-recorded apply) and a fixed helper ProcessStatus (armed
// state + acknowledged generation). It embeds *dataplane.Manager so it satisfies
// the full cliRuntime surface; only the accessors the effective view reads are
// overridden.
type effectiveGenCLIDP struct {
	*dataplane.Manager
	apply  *dataplane.ApplyResult
	status dpuserspace.ProcessStatus
}

func (d *effectiveGenCLIDP) IsLoaded() bool { return true }

func (d *effectiveGenCLIDP) LastApplyResult() *dataplane.ApplyResult {
	return d.apply.Clone()
}

func (d *effectiveGenCLIDP) Status() (dpuserspace.ProcessStatus, error) {
	return d.status, nil
}

// TestShowEffectiveFirewallFiltersArmedAcknowledged: the dataplane is armed and
// the acknowledged generation matches the last applied generation, so the view
// renders the compiled snapshots and certifies them as dataplane-acknowledged —
// no drift banner.
func TestShowEffectiveFirewallFiltersArmedAcknowledged(t *testing.T) {
	store := newEffectiveFilterTestStore(t)
	store.MarkActiveApplied() // #16451: live now also requires the applied marker
	c := &CLI{
		store: store,
		dp: &effectiveGenCLIDP{
			Manager: dataplane.New(),
			apply: &dataplane.ApplyResult{
				Generation:   5,
				Capabilities: dataplane.Capabilities{ForwardingSupported: true},
			},
			status: dpuserspace.ProcessStatus{
				Enabled:                true,
				ForwardingArmed:        true,
				Capabilities:           dpuserspace.UserspaceCapabilities{ForwardingSupported: true},
				LastSnapshotGeneration: 5,
			},
		},
	}

	out := captureStdout(t, func() {
		if err := c.showEffectiveFirewallFilters(""); err != nil {
			t.Fatalf("showEffectiveFirewallFilters() error = %v", err)
		}
	})

	if !strings.Contains(out, "Effective firewall filters — dataplane-acknowledged (generation 5).") {
		t.Fatalf("output = %q, want dataplane-acknowledged generation certification", out)
	}
	if strings.Contains(out, "WARNING") || strings.Contains(out, "COMPILED-DESIRED") {
		t.Fatalf("output = %q, unexpectedly flags drift on an armed+coherent dataplane", out)
	}
	// The compiled snapshot is still rendered.
	if !strings.Contains(out, "Filter: demo (family inet) [effective]") {
		t.Fatalf("output = %q, want compiled snapshot body", out)
	}
}

// TestShowEffectiveFirewallFiltersDisarmedDrift reproduces the #5067 window:
// ActiveConfig is the promoted config B, but a required-protocol-gate apply
// error left the dataplane DISARMED (ForwardingArmed=false) while the last
// recorded apply is still the previously-live generation. The view must NOT
// certify B as live — it prints the compiled-desired snapshots under a prominent
// disarmed/drift banner surfacing the acknowledged generation.
//
// RED-on-revert: with the production change reverted the banner is absent and
// this test fails (the compiled snapshot is falsely presented as effective with
// no drift warning).
func TestShowEffectiveFirewallFiltersDisarmedDrift(t *testing.T) {
	c := &CLI{
		store: newEffectiveFilterTestStore(t),
		dp: &effectiveGenCLIDP{
			Manager: dataplane.New(),
			// Last successful apply was the previous generation (config A).
			apply: &dataplane.ApplyResult{
				Generation:   5,
				Capabilities: dataplane.Capabilities{ForwardingSupported: true},
			},
			// Helper acknowledged generation 5 but is now DISARMED after the
			// required-protocol-gate failure while committing config B.
			status: dpuserspace.ProcessStatus{
				Enabled:                true,
				ForwardingArmed:        false,
				Capabilities:           dpuserspace.UserspaceCapabilities{ForwardingSupported: true},
				LastSnapshotGeneration: 5,
			},
		},
	}

	out := captureStdout(t, func() {
		if err := c.showEffectiveFirewallFilters(""); err != nil {
			t.Fatalf("showEffectiveFirewallFilters() error = %v", err)
		}
	})

	if !strings.Contains(out, "WARNING: dataplane is NOT enforcing the active configuration.") {
		t.Fatalf("output = %q, want prominent disarmed drift banner", out)
	}
	if !strings.Contains(out, "COMPILED-DESIRED") {
		t.Fatalf("output = %q, want compiled-desired labeling", out)
	}
	if !strings.Contains(out, "dataplane disarmed (forwarding not armed)") {
		t.Fatalf("output = %q, want disarmed reason surfaced", out)
	}
	// Desired-vs-applied generations are surfaced.
	if !strings.Contains(out, "Last dataplane-acknowledged generation: 5.") {
		t.Fatalf("output = %q, want acknowledged generation surfaced", out)
	}
	if !strings.Contains(out, "Desired: active configuration (not acknowledged).") {
		t.Fatalf("output = %q, want desired-vs-acknowledged distinction", out)
	}
	// It must NOT certify the config as live.
	if strings.Contains(out, "Effective firewall filters — dataplane-acknowledged") {
		t.Fatalf("output = %q, must NOT certify a disarmed dataplane as acknowledged", out)
	}
	// The compiled-desired snapshot is still shown (so the operator can inspect
	// the desired compile) — under the banner.
	if !strings.Contains(out, "Filter: demo (family inet) [effective]") {
		t.Fatalf("output = %q, want compiled-desired snapshot body under the banner", out)
	}
}

// TestShowEffectiveFirewallFiltersGenerationDrift covers the second drift class:
// the dataplane is armed but the helper's acknowledged generation lags the
// daemon's last applied generation (an in-flight or rejected publish). The view
// flags the drift rather than certifying the newer applied generation as live.
func TestShowEffectiveFirewallFiltersGenerationDrift(t *testing.T) {
	c := &CLI{
		store: newEffectiveFilterTestStore(t),
		dp: &effectiveGenCLIDP{
			Manager: dataplane.New(),
			apply: &dataplane.ApplyResult{
				Generation:   7,
				Capabilities: dataplane.Capabilities{ForwardingSupported: true},
			},
			status: dpuserspace.ProcessStatus{
				Enabled:                true,
				ForwardingArmed:        true,
				Capabilities:           dpuserspace.UserspaceCapabilities{ForwardingSupported: true},
				LastSnapshotGeneration: 5, // helper still on the older generation
			},
		},
	}

	out := captureStdout(t, func() {
		if err := c.showEffectiveFirewallFilters(""); err != nil {
			t.Fatalf("showEffectiveFirewallFilters() error = %v", err)
		}
	})

	if !strings.Contains(out, "dataplane generation drift") {
		t.Fatalf("output = %q, want generation-drift reason", out)
	}
	if !strings.Contains(out, "Last dataplane-acknowledged generation: 5.") {
		t.Fatalf("output = %q, want acknowledged generation 5 surfaced", out)
	}
	if !strings.Contains(out, "Last daemon-applied generation: 7.") {
		t.Fatalf("output = %q, want applied generation 7 surfaced when it diverges", out)
	}
	if strings.Contains(out, "Effective firewall filters — dataplane-acknowledged") {
		t.Fatalf("output = %q, must NOT certify a lagging generation as acknowledged", out)
	}
}

// TestShowEffectiveFirewallFiltersHelperAheadIsLive covers the benign helper-
// AHEAD edge (#5420 review): a scheduler-only republish
// (Manager.UpdatePolicyScheduleStateWithLatch) advances the helper's snapshot generation
// and the helper ACKs it, but that path never calls recordApplyResultLocked — so
// LastApplyResult().Generation lags the helper's LastSnapshotGeneration on a
// perfectly HEALTHY, armed box. The republish carries the same filter content
// (it only re-times policy enable/disable), so the effective view must still
// render LIVE with NO drift banner. An `==` coherence check would spuriously
// warn "NOT enforcing" here; `>=` accepts helper-at-or-ahead.
func TestShowEffectiveFirewallFiltersHelperAheadIsLive(t *testing.T) {
	store := newEffectiveFilterTestStore(t)
	store.MarkActiveApplied() // #16451: helper-ahead stays live only when applied
	c := &CLI{
		store: store,
		dp: &effectiveGenCLIDP{
			Manager: dataplane.New(),
			// Daemon's last recorded apply is generation 5.
			apply: &dataplane.ApplyResult{
				Generation:   5,
				Capabilities: dataplane.Capabilities{ForwardingSupported: true},
			},
			// Armed, and the helper has moved AHEAD to generation 6 via a
			// scheduler republish (recordApplyResultLocked was not called).
			status: dpuserspace.ProcessStatus{
				Enabled:                true,
				ForwardingArmed:        true,
				Capabilities:           dpuserspace.UserspaceCapabilities{ForwardingSupported: true},
				LastSnapshotGeneration: 6,
			},
		},
	}

	out := captureStdout(t, func() {
		if err := c.showEffectiveFirewallFilters(""); err != nil {
			t.Fatalf("showEffectiveFirewallFilters() error = %v", err)
		}
	})

	if !strings.Contains(out, "Effective firewall filters — dataplane-acknowledged (generation 6).") {
		t.Fatalf("output = %q, want live certification at the helper-ahead generation", out)
	}
	if strings.Contains(out, "WARNING") || strings.Contains(out, "COMPILED-DESIRED") {
		t.Fatalf("output = %q, must NOT flag drift when the helper is at or ahead of the applied generation", out)
	}
	if !strings.Contains(out, "Filter: demo (family inet) [effective]") {
		t.Fatalf("output = %q, want compiled snapshot body", out)
	}
}

// TestShowEffectiveFirewallFiltersNoRuntime: with no dataplane runtime wired the
// view cannot confirm the acknowledged generation, so it renders compiled-desired
// under a soft note rather than falsely certifying it as live.
func TestShowEffectiveFirewallFiltersNoRuntime(t *testing.T) {
	c := &CLI{store: newEffectiveFilterTestStore(t)}

	out := captureStdout(t, func() {
		if err := c.showEffectiveFirewallFilters(""); err != nil {
			t.Fatalf("showEffectiveFirewallFilters() error = %v", err)
		}
	})

	if !strings.Contains(out, "dataplane status unavailable") {
		t.Fatalf("output = %q, want compiled-desired note when no runtime is wired", out)
	}
	if strings.Contains(out, "Effective firewall filters — dataplane-acknowledged") {
		t.Fatalf("output = %q, must NOT certify as acknowledged with no runtime", out)
	}
	if !strings.Contains(out, "Filter: demo (family inet) [effective]") {
		t.Fatalf("output = %q, want compiled-desired snapshot body", out)
	}
}

// refusedGenCLIDP models the #16451 refusal state: armed, both generations
// frozen at the prior generation (7/7), with the previous generation's term
// counters still published by the helper.
func refusedGenCLIDP() *effectiveGenCLIDP {
	return &effectiveGenCLIDP{
		Manager: dataplane.New(),
		apply: &dataplane.ApplyResult{
			Generation:   7,
			Capabilities: dataplane.Capabilities{ForwardingSupported: true},
		},
		status: dpuserspace.ProcessStatus{
			Enabled:                true,
			ForwardingArmed:        true,
			Capabilities:           dpuserspace.UserspaceCapabilities{ForwardingSupported: true},
			LastSnapshotGeneration: 7,
			FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
				{Family: "inet", FilterName: "demo", TermName: "t1", Packets: 500, Bytes: 5000},
			},
		},
	}
}

// TestShowEffectiveFirewallFiltersHelperRefused16451 is the #16451 refusal
// cell: the helper refused the promoted config in-band, so helper ack (7) and
// last recorded apply (7) are EQUAL and armed — the pre-fix predicate printed
// "dataplane-acknowledged (generation 7)" over the refused config. The store
// is deliberately NOT stamped (ActiveApplied()==false, as after Commit whose
// apply was refused). The view must print the WARNING, never the live banner.
// RED-on-revert: dropping the ActiveApplied() gate restores live=true here.
func TestShowEffectiveFirewallFiltersHelperRefused16451(t *testing.T) {
	store := newEffectiveFilterTestStore(t)
	if store.ActiveApplied() {
		t.Fatal("fixture: promoted-but-unstamped store must read not-applied")
	}
	c := &CLI{store: store, dp: refusedGenCLIDP()}

	out := captureStdout(t, func() {
		if err := c.showEffectiveFirewallFilters(""); err != nil {
			t.Fatalf("showEffectiveFirewallFilters() error = %v", err)
		}
	})
	if !strings.Contains(out, "WARNING: dataplane is NOT enforcing the active configuration.") {
		t.Fatalf("output = %q, want NOT-enforcing WARNING for refused config", out)
	}
	if !strings.Contains(out, "active configuration not applied") {
		t.Fatalf("output = %q, want not-applied reason", out)
	}
	if !strings.Contains(out, "Last dataplane-acknowledged generation: 7.") {
		t.Fatalf("output = %q, want acknowledged generation 7 surfaced", out)
	}
	if strings.Contains(out, "Effective firewall filters — dataplane-acknowledged") {
		t.Fatalf("output = %q, must NOT certify a refused config as acknowledged", out)
	}
	if !strings.Contains(out, "Filter: demo (family inet) [effective]") {
		t.Fatalf("output = %q, want compiled-desired snapshot body under the banner", out)
	}

	// Control: the SAME 7/7/armed state with the active config stamped applied
	// still prints the live banner (a stamped config is not spuriously warned).
	store.MarkActiveApplied()
	out = captureStdout(t, func() {
		if err := c.showEffectiveFirewallFilters(""); err != nil {
			t.Fatalf("showEffectiveFirewallFilters() error = %v", err)
		}
	})
	if !strings.Contains(out, "Effective firewall filters — dataplane-acknowledged (generation 7).") {
		t.Fatalf("output = %q, want live banner for stamped config", out)
	}
	if strings.Contains(out, "WARNING") {
		t.Fatalf("output = %q, stamped config must not warn", out)
	}
}

// TestShowFirewallRawStaleCounters16451 covers the RAW views in the same
// refused state: they pair the active (refused) config's terms with the
// previous generation's counters keyed only by (family, filter, term). Both
// raw surfaces must warn that the counters belong to the previous generation.
// RED-on-revert: removing the raw warning leaves the 500-packet counter
// silently attributed to the refused config's term.
func TestShowFirewallRawStaleCounters16451(t *testing.T) {
	store := newEffectiveFilterTestStore(t)
	c := &CLI{store: store, dp: refusedGenCLIDP()}

	surfaces := map[string]func() error{
		"show_firewall":        c.showFirewallFilters,
		"show_firewall_filter": func() error { return c.showFirewallFilter("demo", "") },
	}
	for name, fn := range surfaces {
		t.Run(name, func(t *testing.T) {
			out := captureStdout(t, func() {
				if err := fn(); err != nil {
					t.Fatalf("render error = %v", err)
				}
			})
			if !strings.Contains(out, "WARNING: dataplane is NOT enforcing the active configuration.") {
				t.Fatalf("output = %q, want stale-counter WARNING", out)
			}
			if !strings.Contains(out, "belong to the previous generation") {
				t.Fatalf("output = %q, want previous-generation counter note", out)
			}
			// The misleading pairing is still visible but now warned: the
			// previous generation's 500 hits appear under term t1 (t2 is
			// uncounted, so #16454 renders no Hit count for it).
			if !strings.Contains(out, "Hit count: 500 packets") {
				t.Fatalf("output = %q, want previous-generation counter still shown under warning", out)
			}
		})
	}

	// Control: stamped applied — no stale warning on the raw view.
	store.MarkActiveApplied()
	out := captureStdout(t, func() {
		if err := c.showFirewallFilters(); err != nil {
			t.Fatalf("showFirewallFilters() error = %v", err)
		}
	})
	if strings.Contains(out, "belong to the previous generation") {
		t.Fatalf("output = %q, stamped config must not carry stale-counter warning", out)
	}
}
