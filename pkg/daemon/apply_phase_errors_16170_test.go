package daemon

// apply_phase_errors_16170_test.go — #16170 (daemon R2).
//
// The decisive acceptance check for replacing applyTailReconciles' 11
// positional same-typed error parameters (and applyDataplaneAndHACore's
// 5-value return) with applyPhaseErrors / applyCoreResult: one distinct
// sentinel per phase, each asserted to land in its own field, and the
// errors.Join ordering + errors.Is results identical to the pre-struct flat
// join. This test is genuinely unwriteable against the positional form — a
// transposition there compiles cleanly and only this per-field sentinel
// attribution catches it.
//
// FAIL-ON-REVERT: swap any two operands in applyPhaseErrors.join (or in the
// tail's lead/follow interleave) and the ordering cells go RED; drop a field
// from join and its sentinel's errors.Is cell goes RED; transpose two fields
// at a construction site and that site's sentinel lands in the wrong field.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// phaseSentinels16170 returns one distinct sentinel per applyPhaseErrors
// field, in the fields' declaration/join order.
func phaseSentinels16170() (sentinels []error, phase applyPhaseErrors) {
	names := []string{"networkd", "dataplane", "dhcp-server", "ipsec", "iface",
		"route-leak", "routing-rule", "mgmt-route", "vrf", "fabric", "frr"}
	sentinels = make([]error, len(names))
	for i, n := range names {
		sentinels[i] = errors.New("sentinel-16170-" + n)
	}
	phase = applyPhaseErrors{
		Networkd:    sentinels[0],
		Dataplane:   sentinels[1],
		DHCPServer:  sentinels[2],
		IPsec:       sentinels[3],
		Iface:       sentinels[4],
		RouteLeak:   sentinels[5],
		RoutingRule: sentinels[6],
		MgmtRoute:   sentinels[7],
		VRF:         sentinels[8],
		Fabric:      sentinels[9],
		FRR:         sentinels[10],
	}
	return sentinels, phase
}

// TestApplyPhaseErrorsSentinelPerPhase16170 pins join(): every sentinel is
// reachable via errors.Is from its own field, and the joined error string is
// exactly the sentinels in field order, newline-joined — the observable
// commit-output ordering the flat pre-struct join produced.
func TestApplyPhaseErrorsSentinelPerPhase16170(t *testing.T) {
	sentinels, phase := phaseSentinels16170()

	joined := phase.join()
	if joined == nil {
		t.Fatal("applyPhaseErrors.join() returned nil with every phase failed")
	}
	for i, s := range sentinels {
		if !errors.Is(joined, s) {
			t.Fatalf("errors.Is(joined, sentinel[%d]=%q) = false; sentinel dropped or mis-fielded in join()", i, s)
		}
	}

	want := make([]string, len(sentinels))
	for i, s := range sentinels {
		want[i] = s.Error()
	}
	if got := joined.Error(); got != strings.Join(want, "\n") {
		t.Fatalf("join() error-string order changed (observable in commit output):\n got: %q\nwant: %q",
			got, strings.Join(want, "\n"))
	}

	// Identity with the pre-struct flat join: the same operands joined flat
	// must give the same string and the same Is results for every sentinel.
	flat := errors.Join(sentinels...)
	if joined.Error() != flat.Error() {
		t.Fatalf("join() != flat pre-struct join:\n got: %q\nwant: %q", joined.Error(), flat.Error())
	}
	for i, s := range sentinels {
		if errors.Is(joined, s) != errors.Is(flat, s) {
			t.Fatalf("errors.Is mismatch vs flat join for sentinel[%d]", i)
		}
	}
}

// TestApplyPhaseErrorsSingleSentinelAttribution16170 proves each field
// contributes exactly its own sentinel: with only one field set, join()
// surfaces only that sentinel. A transposed join operand would surface the
// wrong sentinel here (or none).
func TestApplyPhaseErrorsSingleSentinelAttribution16170(t *testing.T) {
	sentinels, _ := phaseSentinels16170()
	setters := []func(*applyPhaseErrors, error){
		func(p *applyPhaseErrors, e error) { p.Networkd = e },
		func(p *applyPhaseErrors, e error) { p.Dataplane = e },
		func(p *applyPhaseErrors, e error) { p.DHCPServer = e },
		func(p *applyPhaseErrors, e error) { p.IPsec = e },
		func(p *applyPhaseErrors, e error) { p.Iface = e },
		func(p *applyPhaseErrors, e error) { p.RouteLeak = e },
		func(p *applyPhaseErrors, e error) { p.RoutingRule = e },
		func(p *applyPhaseErrors, e error) { p.MgmtRoute = e },
		func(p *applyPhaseErrors, e error) { p.VRF = e },
		func(p *applyPhaseErrors, e error) { p.Fabric = e },
		func(p *applyPhaseErrors, e error) { p.FRR = e },
	}
	for i, set := range setters {
		var phase applyPhaseErrors
		set(&phase, sentinels[i])
		joined := phase.join()
		if joined == nil || joined.Error() != sentinels[i].Error() {
			t.Fatalf("field %d alone: join() = %v, want exactly %q", i, joined, sentinels[i])
		}
		for j, s := range sentinels {
			if got := errors.Is(joined, s); got != (i == j) {
				t.Fatalf("field %d alone: errors.Is(joined, sentinel[%d]) = %v, want %v", i, j, got, i == j)
			}
		}
	}

	// The zero value joins to nil, matching errors.Join of all-nil operands.
	if got := (applyPhaseErrors{}).join(); got != nil {
		t.Fatalf("zero applyPhaseErrors join() = %v, want nil", got)
	}
}

// TestApplyTailJoinInterleaveOrder16170 pins the tail's interleaving of its
// local operands (hostInboundErr/lo0Err/dnsErr, the five host-credential
// errors, vrrpErr) among the phase operands by driving the REAL
// applyTailReconciles with every phase sentinel set and asserting the
// resulting commit error's string order equals the pre-struct flat join's
// order. The tail-local steps run clean in this fixture, so only the phase
// sentinels can appear — in lead/follow/FRR positions.
func TestApplyTailJoinInterleaveOrder16170(t *testing.T) {
	sentinels, phase := phaseSentinels16170()

	f := newCredentialTailFixture6790(t)
	err := f.d.applyTailReconciles(f.cfg, phase)
	if err == nil {
		t.Fatal("applyTailReconciles returned nil with every phase failed")
	}
	for i, s := range sentinels {
		if !errors.Is(err, s) {
			t.Fatalf("tail commit error lost phase sentinel[%d] %q (got %v)", i, s, err)
		}
	}

	// Reconstruct the flat pre-struct join order minus the clean tail-local
	// operands: errors.Join drops nil operands, so with the tail steps clean
	// the commit string is exactly the phase sentinels in flat order.
	want := make([]string, len(sentinels))
	for i, s := range sentinels {
		want[i] = s.Error()
	}
	if got := err.Error(); got != strings.Join(want, "\n") {
		t.Fatalf("tail join ordering changed vs pre-struct flat join:\n got: %q\nwant: %q",
			got, strings.Join(want, "\n"))
	}
}

// TestApplyCoreResultTerminalVsDeferred16170 pins the applyCoreResult
// contract at the real core: a context abort lands ONLY in Terminal (the
// deferred Dataplane slot stays nil, so the caller bails without running the
// tail), while a clean core leaves Terminal nil. Transposing Terminal and
// Phase.Dataplane would invert the #5679 deferred-vs-terminal semantics.
func TestApplyCoreResultTerminalVsDeferred16170(t *testing.T) {
	d := &Daemon{opts: Options{NoDataplane: true}}
	cfg := &config.Config{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := d.applyDataplaneAndHACore(ctx, cfg)
	if res.Terminal == nil {
		t.Fatal("cancelled context: Terminal = nil, want the context abort")
	}
	if !errors.Is(res.Terminal, context.Canceled) {
		t.Fatalf("cancelled context: Terminal = %v, want context.Canceled", res.Terminal)
	}
	if res.Phase.Dataplane != nil {
		t.Fatalf("cancelled context: Phase.Dataplane = %v, want nil (terminal aborts are not deferred)", res.Phase.Dataplane)
	}

	res = d.applyDataplaneAndHACore(context.Background(), cfg)
	if res.Terminal != nil {
		t.Fatalf("clean core: Terminal = %v, want nil", res.Terminal)
	}
	if res.Phase.join() != nil {
		t.Fatalf("clean core: Phase.join() = %v, want nil", res.Phase.join())
	}
}
