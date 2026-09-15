package cli

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/dataplane"
)

// mtuShowCLIDP9841 is a cliRuntime fake publishing a scripted last-apply
// result. It embeds *dataplane.Manager to satisfy the rest of the
// interface and overrides only IsLoaded + LastApplyResult.
type mtuShowCLIDP9841 struct {
	*dataplane.Manager
	loaded bool
	result *dataplane.ApplyResult
}

func (d *mtuShowCLIDP9841) IsLoaded() bool                          { return d.loaded }
func (d *mtuShowCLIDP9841) LastApplyResult() *dataplane.ApplyResult { return d.result.Clone() }

// mtuSeqCLIDP9841 scripts the generation guard: the first LastApplyResult
// call (commitApply's entry snapshot) sees before, every later call (the
// post-apply probe) sees after. A nil before models an unpublished backend.
type mtuSeqCLIDP9841 struct {
	*dataplane.Manager
	calls         int
	before, after *dataplane.ApplyResult
}

func (d *mtuSeqCLIDP9841) IsLoaded() bool { return false }
func (d *mtuSeqCLIDP9841) LastApplyResult() *dataplane.ApplyResult {
	d.calls++
	if d.calls == 1 {
		return d.before.Clone()
	}
	return d.after.Clone()
}

func mtuLoCLI9841(t *testing.T, dp *mtuShowCLIDP9841, text string) *CLI {
	t.Helper()
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(text); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return &CLI{store: store, dp: dp}
}

const mtuLoUnit09841 = `
interfaces {
    lo { unit 0 { family inet { address 127.0.0.2/32; } } }
}
security {
    zones {
        security-zone trust {
            interfaces { lo.0; }
        }
    }
}
`

const mtuLoUnit509841 = `
interfaces {
    lo {
        vlan-tagging;
        unit 50 { vlan-id 50; family inet { address 127.0.0.2/32; } }
    }
}
security {
    zones {
        security-zone trust {
            interfaces { lo.50; }
        }
    }
}
`

func mtuLo9841(t *testing.T) net.Interface {
	t.Helper()
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("net.InterfaceByName(%q) unavailable in this environment (%v)", "lo", err)
	}
	return *lo
}

// A diverged record for the loopback annotates its phys row with the live
// value re-read at show time — and, consumed by the row, never reprints in
// the leftover section.
func TestShowInterfacesMTUAnnotatePhys9841(t *testing.T) {
	lo := mtuLo9841(t)
	rec := dataplane.MTUUnconverged{Name: "lo", ConfigRef: "lo",
		WantMTU: lo.MTU + 1000, LiveMTU: lo.MTU, Grade: dataplane.MTUGradeWriteFailed,
		ExpectIfindex: lo.Index, Detail: "refused"}
	c := mtuLoCLI9841(t, &mtuShowCLIDP9841{Manager: dataplane.New(),
		result: &dataplane.ApplyResult{Generation: 3, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}}, mtuLoUnit09841)
	out := captureStdout(t, func() {
		if err := c.showInterfaces(nil); err != nil {
			t.Fatalf("showInterfaces: %v", err)
		}
	})
	if !strings.Contains(out, "Physical interface: lo") {
		t.Fatalf("fixture did not render the lo phys row:\n%s", out)
	}
	for _, want := range []string{"MTU unconverged: ", "live "} {
		if !strings.Contains(out, want) {
			t.Errorf("phys row missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "no matching interface row") {
		t.Errorf("row-consumed record reprinted as a leftover:\n%s", out)
	}
}

// A record whose want now equals the verified live MTU suppresses
// everywhere: no row annotation, and — still consumed — no leftover.
func TestShowInterfacesMTUConvergedSuppresses9841(t *testing.T) {
	lo := mtuLo9841(t)
	rec := dataplane.MTUUnconverged{Name: "lo", ConfigRef: "lo",
		WantMTU: lo.MTU, LiveMTU: 1500, Grade: dataplane.MTUGradeWriteFailed, ExpectIfindex: lo.Index}
	c := mtuLoCLI9841(t, &mtuShowCLIDP9841{Manager: dataplane.New(),
		result: &dataplane.ApplyResult{Generation: 3, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}}, mtuLoUnit09841)
	out := captureStdout(t, func() {
		if err := c.showInterfaces(nil); err != nil {
			t.Fatalf("showInterfaces: %v", err)
		}
	})
	if strings.Contains(out, "MTU unconverged") {
		t.Errorf("verified-converged record must suppress, got:\n%s", out)
	}
}

// A unit record for a kernel child that does not exist annotates its unit
// section with live=unknown — never suppressed, never the parent's MTU.
func TestShowInterfacesMTUUnitUnknown9841(t *testing.T) {
	mtuLo9841(t)
	rec := dataplane.MTUUnconverged{Name: "lo.50", ConfigRef: "lo.50",
		WantMTU: 1500, LiveMTU: -1, Grade: dataplane.MTUGradeLookupFailed}
	c := mtuLoCLI9841(t, &mtuShowCLIDP9841{Manager: dataplane.New(),
		result: &dataplane.ApplyResult{Generation: 3, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}}, mtuLoUnit509841)
	out := captureStdout(t, func() {
		if err := c.showInterfaces(nil); err != nil {
			t.Fatalf("showInterfaces: %v", err)
		}
	})
	if !strings.Contains(out, "Logical interface lo.50") {
		t.Fatalf("fixture did not render the lo.50 unit section:\n%s", out)
	}
	if !strings.Contains(out, "live unknown") {
		t.Errorf("absent child must annotate live=unknown, got:\n%s", out)
	}
	if strings.Contains(out, "-1") {
		t.Errorf("annotation leaked the -1 sentinel:\n%s", out)
	}
}

// Rowless records (absent at show time, renamed since the apply) render in
// the leftover section on an unfiltered show — and ahead of the not-found
// error when the filter matches no row.
func TestShowInterfacesMTULeftover9841(t *testing.T) {
	mtuLo9841(t)
	rec := dataplane.MTUUnconverged{Name: "ge-0-0-9", ConfigRef: "ge-0/0/9",
		WantMTU: 9000, LiveMTU: 1500, Grade: dataplane.MTUGradeWriteFailed, Detail: "refused"}
	dp := &mtuShowCLIDP9841{Manager: dataplane.New(),
		result: &dataplane.ApplyResult{Generation: 3, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}}
	c := mtuLoCLI9841(t, dp, mtuLoUnit09841)

	out := captureStdout(t, func() {
		if err := c.showInterfaces(nil); err != nil {
			t.Fatalf("showInterfaces: %v", err)
		}
	})
	for _, want := range []string{"MTU unconverged (no matching interface row):", "ge-0/0/9", "netdev ge-0-0-9"} {
		if !strings.Contains(out, want) {
			t.Errorf("unfiltered show missing leftover %q:\n%s", want, out)
		}
	}

	out = captureStdout(t, func() {
		if err := c.showInterfaces([]string{"ge-0/0/9"}); err == nil {
			t.Fatalf("filtered show must still report the missing interface")
		}
	})
	for _, want := range []string{"MTU unconverged (no matching interface row):", "ge-0/0/9"} {
		if !strings.Contains(out, want) {
			t.Errorf("error-path show missing leftover %q:\n%s", want, out)
		}
	}
}

// A RETH unit record matches its aggregate's unit section by authored ref
// (reth0.50), while a member-filtered query surfaces the same record as a
// leftover via the kernel-name prefix — mirroring the row selector.
func TestShowInterfacesMTUReth9841(t *testing.T) {
	c := rethShowCLI(t)
	rec := dataplane.MTUUnconverged{Name: "ge-0-0-2.50", ConfigRef: "reth0.50",
		WantMTU: 9000, LiveMTU: 1500, Grade: dataplane.MTUGradeParentWritePending}
	c.dp = &mtuShowCLIDP9841{Manager: dataplane.New(),
		result: &dataplane.ApplyResult{Generation: 3, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}}

	out := captureStdout(t, func() {
		if err := c.showInterfaces([]string{"reth0"}); err != nil {
			t.Fatalf("showInterfaces(reth0): %v", err)
		}
	})
	if !strings.Contains(out, "Logical interface reth0.50") {
		t.Fatalf("fixture did not render the reth0.50 unit section:\n%s", out)
	}
	if !strings.Contains(out, "MTU unconverged: ") {
		t.Errorf("reth unit section missing its annotation:\n%s", out)
	}
	if strings.Contains(out, "no matching interface row") {
		t.Errorf("row-consumed reth record reprinted as a leftover:\n%s", out)
	}

	out = captureStdout(t, func() {
		if err := c.showInterfaces([]string{"ge-0/0/2"}); err != nil {
			t.Fatalf("showInterfaces(ge-0/0/2): %v", err)
		}
	})
	for _, want := range []string{"member of reth0", "MTU unconverged (no matching interface row):", "reth0.50"} {
		if !strings.Contains(out, want) {
			t.Errorf("member-filtered show missing %q:\n%s", want, out)
		}
	}
}

// live==want on a device that fails the identity check is NOT convergence:
// the annotation stays, flagged unverified, so a same-named squatter at
// the wanted MTU cannot clear the record.
func TestShowInterfacesMTUIdentityMismatchKept9841(t *testing.T) {
	lo := mtuLo9841(t)
	rec := dataplane.MTUUnconverged{Name: "lo", ConfigRef: "lo",
		WantMTU: lo.MTU, LiveMTU: 1500, Grade: dataplane.MTUGradeWriteFailed,
		ExpectIfindex: lo.Index, ExpectParentIfindex: 9999}
	c := mtuLoCLI9841(t, &mtuShowCLIDP9841{Manager: dataplane.New(),
		result: &dataplane.ApplyResult{Generation: 3, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}}, mtuLoUnit09841)
	out := captureStdout(t, func() {
		if err := c.showInterfaces(nil); err != nil {
			t.Fatalf("showInterfaces: %v", err)
		}
	})
	if !strings.Contains(out, "unverified") {
		t.Errorf("identity-mismatched record must stay flagged unverified, got:\n%s", out)
	}
}

// commitApply projects the just-published records onto a RESPONSE COPY on
// BOTH reconcile paths — the legacy dataplane apply and the daemon-backed
// hybrid — and only when the generation actually advanced past the entry
// snapshot (a stale or unpublished backend returns the input unchanged).
// The applied object is never mutated: the dataplane retains it, so a
// post-apply write would race snapshot readers on either path.
func TestCommitApplyMTUSync9841(t *testing.T) {
	rec := dataplane.MTUUnconverged{Name: "ge-0-0-9", ConfigRef: "ge-0/0/9",
		WantMTU: 9000, LiveMTU: 1500, Grade: dataplane.MTUGradeWriteFailed}
	after := &dataplane.ApplyResult{Generation: 2, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}

	t.Run("legacy apply projects fresh records onto a copy", func(t *testing.T) {
		c := &CLI{dp: &mtuSeqCLIDP9841{Manager: dataplane.New(),
			before: &dataplane.ApplyResult{Generation: 1}, after: after}}
		compiled := &config.Config{}
		resp := c.commitApply(compiled)
		if resp == compiled {
			t.Fatalf("response aliases the applied object: must project onto a copy")
		}
		if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "interface MTU not realized") {
			t.Fatalf("legacy commitApply projected %v, want the #9841 line", resp.Warnings)
		}
		if len(compiled.Warnings) != 0 {
			t.Fatalf("applied object gained %v, want it untouched", compiled.Warnings)
		}
	})

	t.Run("legacy apply ignores a stale publication", func(t *testing.T) {
		stale := &dataplane.ApplyResult{Generation: 1, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}
		c := &CLI{dp: &mtuSeqCLIDP9841{Manager: dataplane.New(), before: stale, after: stale}}
		compiled := &config.Config{}
		if resp := c.commitApply(compiled); resp != compiled {
			t.Fatalf("stale generation copied the config: no fresh publish means no projection")
		}
		if len(compiled.Warnings) != 0 {
			t.Fatalf("stale generation projected %v, want nothing", compiled.Warnings)
		}
	})

	t.Run("daemon hybrid projects fresh records onto a copy", func(t *testing.T) {
		c := &CLI{dp: &mtuSeqCLIDP9841{Manager: dataplane.New(), after: after}}
		c.applyConfigFn = func(*config.Config) {}
		compiled := &config.Config{}
		resp := c.commitApply(compiled)
		if resp == compiled {
			t.Fatalf("response aliases the applied object: must project onto a copy")
		}
		if len(resp.Warnings) != 1 || !strings.Contains(resp.Warnings[0], "ge-0/0/9") {
			t.Fatalf("hybrid commitApply projected %v, want the #9841 line", resp.Warnings)
		}
		if len(compiled.Warnings) != 0 {
			t.Fatalf("applied object gained %v, want it untouched", compiled.Warnings)
		}
	})

	t.Run("daemon hybrid ignores an unpublished backend", func(t *testing.T) {
		c := &CLI{}
		c.applyConfigFn = func(*config.Config) {}
		compiled := &config.Config{}
		if resp := c.commitApply(compiled); resp != compiled {
			t.Fatalf("unpublished backend copied the config: want the input unchanged")
		}
		if len(compiled.Warnings) != 0 {
			t.Fatalf("unpublished backend projected %v, want nothing", compiled.Warnings)
		}
	})
}

// End to end on the legacy path: runCommit returns the response object
// carrying the line, while the store's active config — the retained
// original — keeps only its validation warnings.
func TestRunCommitMTUResponse9841(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(mtuLoUnit09841); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	rec := dataplane.MTUUnconverged{Name: "lo", ConfigRef: "lo",
		WantMTU: 9000, LiveMTU: 1500, Grade: dataplane.MTUGradeWriteFailed}
	c := &CLI{store: store, dp: &mtuSeqCLIDP9841{Manager: dataplane.New(),
		before: &dataplane.ApplyResult{Generation: 1},
		after:  &dataplane.ApplyResult{Generation: 2, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}}}
	resp, err := c.runCommit("")
	if err != nil {
		t.Fatalf("runCommit: %v", err)
	}
	found := false
	for _, w := range resp.Warnings {
		if strings.Contains(w, "interface MTU not realized") {
			found = true
		}
	}
	if !found {
		t.Fatalf("runCommit response = %v, want the #9841 line", resp.Warnings)
	}
	for _, w := range store.ActiveConfig().Warnings {
		if strings.Contains(w, "(#9841)") {
			t.Fatalf("active config carries %q: the projection must not write through", w)
		}
	}
}

// An aliased zone spelling ("lo.080") matches the record carrying the same
// authored ConfigRef exactly: the producer preserves the spelling verbatim,
// so the row annotates instead of hiding the divergence.
func TestShowInterfacesMTUAliasedRef9841(t *testing.T) {
	mtuLo9841(t)
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	if err := store.LoadOverride(`
interfaces {
    lo {
        vlan-tagging;
        unit 80 { vlan-id 80; family inet { address 127.0.0.2/32; } }
    }
}
security {
    zones {
        security-zone trust {
            interfaces { lo.080; }
        }
    }
}
`); err != nil {
		t.Fatalf("LoadOverride() error = %v", err)
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	rec := dataplane.MTUUnconverged{Name: "lo.80", ConfigRef: "lo.080",
		WantMTU: 1500, LiveMTU: 1500, Grade: dataplane.MTUGradeWriteFailed}
	c := &CLI{store: store, dp: &mtuShowCLIDP9841{Manager: dataplane.New(),
		result: &dataplane.ApplyResult{Generation: 3, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}}}
	out := captureStdout(t, func() {
		if err := c.showInterfaces(nil); err != nil {
			t.Fatalf("showInterfaces: %v", err)
		}
	})
	if !strings.Contains(out, "Logical interface lo.80") {
		t.Fatalf("fixture did not render the lo.80 unit section:\n%s", out)
	}
	if !strings.Contains(out, "MTU unconverged: ") {
		t.Errorf("aliased row missing its annotation (ConfigRef mismatch hides it):\n%s", out)
	}
	if strings.Contains(out, "no matching interface row") {
		t.Errorf("exactly-matched record reprinted as a leftover:\n%s", out)
	}
}

// A RETH unit row falls back through the actual member: a record for the
// shared kernel child under a member-direct ConfigRef (exact-matching no
// reth row) still annotates reth0.50 via ge-0-0-2.50 — the same device,
// the same true numbers — instead of vanishing under the reth filter.
func TestShowInterfacesMTUMemberFallback9841(t *testing.T) {
	c := rethShowCLI(t)
	rec := dataplane.MTUUnconverged{Name: "ge-0-0-2.50", ConfigRef: "ge-0/0/2.50",
		WantMTU: 9000, LiveMTU: 1500, Grade: dataplane.MTUGradeWriteFailed}
	c.dp = &mtuShowCLIDP9841{Manager: dataplane.New(),
		result: &dataplane.ApplyResult{Generation: 3, UnconvergedMTUs: []dataplane.MTUUnconverged{rec}}}
	out := captureStdout(t, func() {
		if err := c.showInterfaces([]string{"reth0"}); err != nil {
			t.Fatalf("showInterfaces(reth0): %v", err)
		}
	})
	if !strings.Contains(out, "MTU unconverged: ") {
		t.Errorf("reth row missing its member-fallback annotation:\n%s", out)
	}
	if strings.Contains(out, "no matching interface row") {
		t.Errorf("fallback-consumed record reprinted as a leftover:\n%s", out)
	}
}
