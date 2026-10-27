package daemon

// apply_phase_errors_16170_test.go — #16170 (daemon R2), updated #17034.
//
// The tests in this file have distinct, limited purposes:
//
//   - phaseSentinels16170 is built by reflection over applyPhaseErrors
//     (#17034), so a field added to the struct automatically gets a
//     sentinel here instead of requiring a third hand list.
//   - The sentinel cells below characterize applyPhaseErrors.join itself:
//     every reflected field reaches errors.Is through join (with zero
//     tail-locals), and join's string is the flat field order. They
//     deliberately construct applyPhaseErrors in the test, so they do NOT
//     prove that production assigns any producer's error to the correct
//     field.
//   - The tail-order cell drives the real applyTailReconciles with all
//     tail-local producers healthy; it therefore pins only phase-relative
//     order, not interleaving against non-nil local errors.
//   - Production producer -> field attribution, retry-debt observation,
//     exact local/phase interleaving, and exact leaf unwrapping are pinned
//     separately in apply_phase_errors_production_16170_test.go, whose
//     fixtures fail real production seams and drive applyConfigLocked /
//     applyDataplaneAndHACore.
//   - TestEveryApplyPhaseErrorReachesTheCommit17034 (in
//     apply_phase_errors_production_16170_test.go) is the mutation cell:
//     it reflects over the struct and drives the production tail, so a
//     field added per the documented recipe but not wired into join()
//     turns RED.
//
// FAIL-ON-REVERT for these unit cells: swap two operands in join and the
// all-sentinel order cell goes RED; drop a field from join and the matching
// field-attribution/order cell goes RED.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// phaseSentinels16170 returns one distinct sentinel per applyPhaseErrors
// field, in struct declaration order (= join operand order for phase
// fields). Built by reflection (#17034) so a field added to the struct
// automatically gets a sentinel — there is no third hand list to forget.
// Sentinel strings keep the historic "sentinel-16170-<slug>" shape so
// exact-string cells in the production file stay byte-identical.
func phaseSentinels16170() (sentinels []error, phase applyPhaseErrors) {
	slugs := map[string]string{
		"Networkd": "networkd", "Dataplane": "dataplane", "DHCPServer": "dhcp-server",
		"IPsec": "ipsec", "Iface": "iface", "RouteLeak": "route-leak",
		"RoutingRule": "routing-rule", "MgmtRoute": "mgmt-route", "VRF": "vrf",
		"Fabric": "fabric", "FRR": "frr",
	}
	t := reflect.TypeOf(applyPhaseErrors{})
	v := reflect.ValueOf(&phase).Elem()
	sentinels = make([]error, 0, t.NumField())
	for i := range t.NumField() {
		name := t.Field(i).Name
		slug, ok := slugs[name]
		if !ok {
			slug = strings.ToLower(name)
		}
		s := errors.New("sentinel-16170-" + slug)
		sentinels = append(sentinels, s)
		v.Field(i).Set(reflect.ValueOf(s))
	}
	return sentinels, phase
}

// TestApplyPhaseErrorsSentinelPerPhase16170 pins join(): every sentinel is
// reachable via errors.Is from its own field, and the joined error string is
// exactly the sentinels in field order, newline-joined — the observable
// commit-output ordering the flat pre-struct join produced. Called with
// zero tail-locals, so the string is exactly the phase fields in order.
func TestApplyPhaseErrorsSentinelPerPhase16170(t *testing.T) {
	sentinels, phase := phaseSentinels16170()

	joined := phase.join(applyTailLocals{})
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
// reaches join by itself and no other field's sentinel appears. Fields are
// set by reflection (#17034) so a new field is covered automatically. It
// is a join/drop characterization only: because just one operand is
// non-nil, it cannot detect a permutation among join operands, and because
// the test constructs the struct itself it cannot detect a production
// construction-site transposition.
func TestApplyPhaseErrorsSingleSentinelAttribution16170(t *testing.T) {
	sentinels, _ := phaseSentinels16170()
	typ := reflect.TypeOf(applyPhaseErrors{})
	if len(sentinels) != typ.NumField() {
		t.Fatalf("phaseSentinels16170 returned %d sentinels for %d fields", len(sentinels), typ.NumField())
	}
	for i := range sentinels {
		var phase applyPhaseErrors
		reflect.ValueOf(&phase).Elem().Field(i).Set(reflect.ValueOf(sentinels[i]))
		joined := phase.join(applyTailLocals{})
		if joined == nil || joined.Error() != sentinels[i].Error() {
			t.Fatalf("field %d (%s) alone: join() = %v, want exactly %q", i, typ.Field(i).Name, joined, sentinels[i])
		}
		for j, s := range sentinels {
			if got := errors.Is(joined, s); got != (i == j) {
				t.Fatalf("field %d alone: errors.Is(joined, sentinel[%d]) = %v, want %v", i, j, got, i == j)
			}
		}
	}

	// The zero value joins to nil, matching errors.Join of all-nil operands.
	if got := (applyPhaseErrors{}).join(applyTailLocals{}); got != nil {
		t.Fatalf("zero applyPhaseErrors join() = %v, want nil", got)
	}
}

// TestApplyTailJoinInterleaveOrder16170 drives the real applyTailReconciles
// with every phase sentinel set while this fixture's tail-local producers
// are healthy. It therefore pins phase-relative order only. It cannot
// detect moving a phase group across a non-nil local error, swapping
// local errors, or misplacing VRRP relative to FRR; the production-path
// test in apply_phase_errors_production_16170_test.go covers those cases
// with distinguishable non-nil local failures.
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
	if res.Phase.join(applyTailLocals{}) != nil {
		t.Fatalf("clean core: Phase.join() = %v, want nil", res.Phase.join(applyTailLocals{}))
	}
}
