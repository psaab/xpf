package userspace

import (
	"bytes"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// TestOwnerlessFabricParentIsRefused is the #6691 round 10 regression guard.
//
// THE FIXTURE'S WHOLE POINT IS WHAT IT DOES NOT CONTAIN. Round 9's fabric guard
// (TestFabricLoopCannotReadmitARefusedMember) authors
//
//	set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24
//
// alongside the fabric stanza, which manufactures an interface ROW for the
// member netdev — and userspaceRefusedNetdevs was built from rows, so that line
// is what made the netdev refusable at all. A fabric MEMBER NEEDS NO STANZA:
// delete it and the same config still runs, the netdev is still emitted into
// both sets by the fabric loops, and round 9's tally saw ZERO owners. A
// unanimity rule over an empty bucket answers "not refused", so the guard
// passed on a config it did not cover.
//
// Measured at 4cf507638 with exactly this config: `rows OWNING ge-0-0-0: 0`,
// `refusesName(ge-0-0-0) = false`, `refusesIfindex(20) = false`, ingress
// `[20 21]`, allowlist `[ge-0-0-0 ge-0-0-3]`. The refused device was in both.
//
// FAIL-ON-REVERT: restore the `owners > 0` reading by dropping the fabric arm
// from buildUserspaceRefusedNetdevs, or make fabricParentUnbindable return
// false, and this reds on both sets.
func TestOwnerlessFabricParentIsRefused(t *testing.T) {
	const (
		memberIfindex = 20
		lanIfindex    = 21
	)
	defer stubLinkSnapshot5619(t, map[string]int{
		"ge-0-0-0": memberIfindex, "ge-0-0-3": lanIfindex, "fab0": 22,
	})()
	// The member netdev IS an xfrm device by kernel kind, under a slot-shaped
	// name. This is the reachable shape: the kernel-kind half refuses a device
	// for what it IS, and a slot-shaped name is a legal fabric member.
	defer stubXfrmNetdevs(t, "ge-0-0-0")()

	cfg := compileForTest5619(t,
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key abcdefghijklmnopqrstuvwxyz012345",
		"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
		// DELIBERATELY NO `set interfaces ge-0/0/0 ...` — see above.
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.9.1/24",
		"set security zones security-zone trust interfaces ge-0/0/3.0",
	)
	snap, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}

	// PREMISE 1: no interface row owns the member netdev. If a future change to
	// the compiler starts synthesising one, this test silently becomes round
	// 9's test again and stops covering the case it exists for.
	owners := 0
	for _, iface := range snap.Interfaces {
		if userspaceOwnsItsNetdev(iface) && iface.LinuxName == "ge-0-0-0" {
			owners++
		}
	}
	if owners != 0 {
		t.Fatalf("premise broken: %d interface rows own ge-0-0-0, so this is the "+
			"OWNED case round 9 already covered. The ownerless case needs a member "+
			"with no `set interfaces` stanza", owners)
	}

	// PREMISE 2: the fabric row exists and names the netdev — otherwise nothing
	// emits it and there is nothing to refuse.
	var fab *FabricSnapshot
	for i := range snap.Fabrics {
		if snap.Fabrics[i].ParentLinuxName == "ge-0-0-0" {
			fab = &snap.Fabrics[i]
		}
	}
	if fab == nil {
		t.Fatalf("premise broken: no fabric row resolves to ge-0-0-0 (fabrics %+v)", snap.Fabrics)
	}
	if fab.ParentIfindex != memberIfindex {
		t.Fatalf("premise broken: fabric parent ifindex = %d, want %d", fab.ParentIfindex, memberIfindex)
	}

	// The fabric carries the verdict — this is the wire field the Rust plane
	// reads, so an assertion on the sets alone would not tell us the Go and
	// Rust planes agree.
	if !fab.ParentUnbindable {
		t.Error("FabricSnapshot.ParentUnbindable = false for a live xfrm netdev. " +
			"The Rust plane has no other evidence about an ownerless parent, so a " +
			"false here plans an AF_XDP binding on the xfrmi: one RX queue becomes " +
			"the global minimum and every interface collapses to one worker (#3091)")
	}

	refused := buildUserspaceRefusedNetdevs(snap)
	if !refused.refusesName("ge-0-0-0") {
		t.Error("refusesName(ge-0-0-0) = false: the fabric's own emission does not " +
			"count as an owner, so the unanimity is taken over an empty bucket")
	}
	if !refused.refusesIfindex(memberIfindex) {
		t.Errorf("refusesIfindex(%d) = false", memberIfindex)
	}

	if got := UserspaceBoundLinuxInterfaces(cfg); slices.Contains(got, "ge-0-0-0") {
		t.Errorf("RSS/AF_XDP allowlist = %v: an entry is permission to reshape that "+
			"NIC's RSS table and pin its coalescing", got)
	}
	if got := buildUserspaceIngressIfindexes(snap); slices.Contains(got, uint32(memberIfindex)) {
		t.Errorf("ingress-adjudication set = %v: contains the refused member's "+
			"ifindex %d", got, memberIfindex)
	}
	// NEGATIVE CONTROL: the LAN must survive, or the guard is dropping the box
	// rather than the member.
	if got := buildUserspaceIngressIfindexes(snap); !slices.Contains(got, uint32(lanIfindex)) {
		t.Fatalf("premise broken: the LAN (ifindex %d) fell out of the ingress set %v",
			lanIfindex, got)
	}
}

// TestOwnerlessBindableFabricParentStaysAdmitted is the negative control for
// the guard above, and it is not a formality: it is THE REFERENCE CLUSTER.
//
// loss:xpf-userspace-fw0/fw1 authors `fab0 fabric-options member-interfaces
// ge-0/0/0` with no `set interfaces ge-0/0/0` row (measured: 16 interface rows,
// `FAB fab0 parent=ge-0-0-0 ifx=13`, and ge-0-0-0 in the allowlist supplied by
// the fabric loop alone). So "an ownerless parent is refused" would have broken
// every cluster this project runs. The rule has to be the CLASS TABLE's verdict
// on the netdev, not the absence of a row.
func TestOwnerlessBindableFabricParentStaysAdmitted(t *testing.T) {
	const (
		memberIfindex = 20
		lanIfindex    = 21
	)
	defer stubLinkSnapshot5619(t, map[string]int{
		"ge-0-0-0": memberIfindex, "ge-0-0-3": lanIfindex, "fab0": 22,
	})()
	// No xfrm devices at all — an ordinary NIC as a fabric member.
	defer stubXfrmNetdevs(t)()

	cfg := compileForTest5619(t,
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key abcdefghijklmnopqrstuvwxyz012345",
		"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.9.1/24",
		"set security zones security-zone trust interfaces ge-0/0/3.0",
	)
	snap, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	for _, fab := range snap.Fabrics {
		if fab.ParentLinuxName == "ge-0-0-0" && fab.ParentUnbindable {
			t.Fatal("ParentUnbindable = true for an ordinary NIC used as a fabric " +
				"member — this is the reference cluster's own shape and refusing it " +
				"takes the fabric parent out of the ingress map and the AF_XDP plan")
		}
	}
	refused := buildUserspaceRefusedNetdevs(snap)
	if refused.refusesName("ge-0-0-0") || refused.refusesIfindex(memberIfindex) {
		t.Fatal("the ownerless fabric parent is refused with no class matching it. " +
			"An ownerless netdev is not refusable BY BEING ownerless; it is refusable " +
			"when the class table says the DEVICE may not be bound")
	}
	if got := UserspaceBoundLinuxInterfaces(cfg); !slices.Contains(got, "ge-0-0-0") {
		t.Errorf("RSS/AF_XDP allowlist = %v: lost the fabric parent", got)
	}
	if got := buildUserspaceIngressIfindexes(snap); !slices.Contains(got, uint32(memberIfindex)) {
		t.Errorf("ingress set = %v: lost the fabric parent ifindex %d", got, memberIfindex)
	}
}

// TestFabricParentVerdictReadsTheClassTable pins that fabricParentUnbindable
// asks userspaceNetdevExclusionClass rather than restating a secure-tunnel
// check, by driving a class that has nothing to do with IPsec.
//
// It matters because the enumeration guard
// (TestExclusionClassesAgreeAcrossParentAndChild) reads
// netdevExclusionClasses, and a fabric verdict that hand-rolled its own test
// would sit outside that guard entirely — a new class would cover interface
// rows and silently not cover fabric parents.
func TestFabricParentVerdictReadsTheClassTable(t *testing.T) {
	defer stubXfrmNetdevs(t)()
	for _, tc := range []struct {
		name  string
		lines []string
		want  bool
		class string
	}{
		{
			name: "interface-level tunnel on the member",
			lines: []string{
				"set interfaces gr-0/0/3 tunnel source 10.0.0.1",
				"set interfaces gr-0/0/3 tunnel destination 10.0.0.2",
				"set interfaces fab0 fabric-options member-interfaces gr-0/0/3",
			},
			want:  true,
			class: "Tunnel",
		},
		{
			name: "ordinary slot-shaped member",
			lines: []string{
				"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
			},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lines := append([]string{
				"set chassis cluster reth-count 2",
				"set chassis cluster authentication-key abcdefghijklmnopqrstuvwxyz012345",
			}, tc.lines...)
			cfg := compileForTest5619(t, lines...)
			var member, linux string
			if cfg.Chassis.Cluster != nil {
				if ifCfg := cfg.Interfaces.Interfaces[cfg.Chassis.Cluster.FabricInterface]; ifCfg != nil {
					member = ifCfg.LocalFabricMember
				}
			}
			if member == "" {
				t.Fatalf("premise broken: no fabric member resolved from %v", tc.lines)
			}
			linux = config.LinuxIfName(member)
			if got := fabricParentUnbindable(cfg, member, linux, nil); got != tc.want {
				t.Fatalf("fabricParentUnbindable(%q/%q) = %v, want %v", member, linux, got, tc.want)
			}
			if !tc.want {
				return
			}
			// And it must be the class we think it is: a positive control that
			// only asserts "something refused it" cannot see the verdict moving
			// to a different class for a different reason.
			got := userspaceNetdevExclusionClass(InterfaceSnapshot{Name: member, LinuxName: linux, Tunnel: true})
			if got != tc.class {
				t.Fatalf("exclusion class = %q, want %q", got, tc.class)
			}
		})
	}
}

// TestOneXfrmSamplePerSnapshot binds the hoist in buildSnapshot: the interface
// rows and the fabric parents are judged against ONE kernel sample.
//
// The property is not decoration. Both consumers ask the same question about
// the same device — "is this netdev an xfrm interface?" — and they now feed one
// unanimity tally, so two samples straddling a device's creation or removal put
// that device's owners on opposite sides of a rule that is only sound when they
// agree. The concrete bad state: the fabric votes "bindable" from a sample taken
// before the xfrmi appeared while the row votes "unbindable" from a sample taken
// after, the bucket is not unanimous, and the netdev is admitted.
//
// The driver returns a DIFFERENT answer on each call, so a second dump anywhere
// in the build is observable rather than merely suspected.
//
// FAIL-ON-REVERT: put the sample back inside buildInterfaceSnapshotsFrom, or
// have buildSnapshot call buildFabricSnapshots (the self-sampling form) instead
// of buildFabricSnapshotsFrom, and this reds.
func TestOneXfrmSamplePerSnapshot(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{
		"ge-0-0-0": 20, "ge-0-0-3": 21, "fab0": 22,
	})()

	prev := liveXfrmNetdevs
	t.Cleanup(func() { liveXfrmNetdevs = prev })
	calls := 0
	liveXfrmNetdevs = func() (map[string]bool, error) {
		calls++
		// First sample: ge-0-0-0 is an xfrm device. Every later sample: it is
		// not. A build that samples once cannot see the second answer.
		if calls == 1 {
			return map[string]bool{"ge-0-0-0": true}, nil
		}
		return map[string]bool{}, nil
	}

	cfg := compileForTest5619(t,
		"set chassis cluster reth-count 2",
		"set chassis cluster authentication-key abcdefghijklmnopqrstuvwxyz012345",
		"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
		"set interfaces ge-0/0/3 unit 0 family inet address 10.0.9.1/24",
		"set security zones security-zone trust interfaces ge-0/0/3.0",
	)
	snap, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 0, 0)
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	if calls != 1 {
		t.Fatalf("buildSnapshot took %d kernel xfrm samples, want 1. Two samples of "+
			"a changing kernel are two answers, and both feed one unanimity tally", calls)
	}
	// And the single sample is the one the fabric verdict used: the FIRST
	// answer said ge-0-0-0 is an xfrm device.
	for _, fab := range snap.Fabrics {
		if fab.ParentLinuxName != "ge-0-0-0" {
			continue
		}
		if !fab.ParentUnbindable {
			t.Error("the fabric parent's verdict does not reflect the snapshot's own " +
				"xfrm sample — it was computed against a different (later) dump")
		}
	}
}

// TestXfrmDumpFailureIsLoggedNotSwallowed binds the diagnostic in
// sampleLiveXfrmNetdevs.
//
// The fallback is deliberately silent in its EFFECT — the config half of
// snapshotSecureTunnel stays authoritative and the build continues — so the log
// line is the only operator-visible trace that the kernel half was unavailable
// for this snapshot. Round 9 left it as a bare slog.Error inside a 200-line
// builder where nothing could reach it; extracting the sampler is what makes it
// testable.
//
// FAIL-ON-REVERT: delete the slog.Error (or downgrade it to Debug) and this
// reds.
func TestXfrmDumpFailureIsLoggedNotSwallowed(t *testing.T) {
	prev := liveXfrmNetdevs
	t.Cleanup(func() { liveXfrmNetdevs = prev })
	liveXfrmNetdevs = func() (map[string]bool, error) {
		return map[string]bool{}, errors.New("RTM_GETLINK: no buffer space available")
	}

	var buf bytes.Buffer
	prevLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prevLogger) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))

	if got, failed := sampleLiveXfrmNetdevs(); len(got) != 0 || !failed {
		t.Fatalf("sample = %v, failed = %v; want empty sample with failure status", got, failed)
	}
	line := buf.String()
	if !bytes.Contains([]byte(line), []byte("level=ERROR")) {
		t.Errorf("the xfrm dump failure was not logged at ERROR: %q. The fallback "+
			"is silent in its effect, so this line is the only trace that the "+
			"kernel half of the secure-tunnel evidence was missing", line)
	}
	if !bytes.Contains([]byte(line), []byte("no buffer space available")) {
		t.Errorf("the log line does not carry the underlying error: %q", line)
	}

	// NEGATIVE CONTROL: a successful dump must not log an error, or the
	// assertion above would pass on every build and say nothing.
	buf.Reset()
	liveXfrmNetdevs = func() (map[string]bool, error) { return map[string]bool{"st0": true}, nil }
	if got, failed := sampleLiveXfrmNetdevs(); !got["st0"] || failed {
		t.Fatalf("sample = %v, failed = %v; want st0 and no failure", got, failed)
	}
	if bytes.Contains(buf.Bytes(), []byte("level=ERROR")) {
		t.Errorf("a successful dump logged an error: %q", buf.String())
	}
}

// TestFabricAndBaseRowNeverDisagree pins the invariant that makes the
// unanimity rule safe now that a fabric parent votes in it (#6691 round 10).
//
// A netdev's owners are allowed to disagree — that is the round-9 rule, and a
// disagreement ADMITS the netdev, on the argument that a bindable owner will
// contribute it to the plan anyway. The argument holds only for disagreements
// production can actually produce, which are between a UNIT row and its base
// (a unit's Tunnel flag ORs the parent's; a unit-0 row resolves to the base
// netdev). A BASE row and a FABRIC parent on the same netdev must never
// disagree, because a fabric that voted "bindable" against an unbindable base
// row would break the unanimity and re-admit the device — the exact fall-through
// this round closes, arriving from the other side.
//
// The invariant is structural rather than asserted-by-convention:
// fabricParentUnbindable reads the same config fields and the SAME kernel
// sample that buildInterfaceSnapshotsFrom stamps onto the base row (see the
// hoist in buildSnapshot), so identical inputs give identical verdicts. This
// test drives it across the classes rather than trusting the reading.
//
// MATCHED BY NETDEV (#6691 round 11). This test used to pair a row with a fabric
// only when `iface.Name == fab.ParentInterface`, i.e. when the two carried the
// same AUTHORED spelling — so the one shape that actually produced a
// disagreement was invisible to it. LinuxIfName maps '/' to '-' and nothing
// else, so a member `gr-0/0/3` and a stanza `gr-0-0-3` are one device under two
// legal names, and the exact-name pairing skipped precisely that pair. The
// netdev is the identity both planes key on, so it is the identity this pairing
// uses; base rows only (a unit row sharing the base netdev is the disagreement
// production IS allowed to produce).
//
// Since round 11 a base/fabric disagreement is no longer itself a fail-open —
// the fabric abstains where a row owns the netdev (snapshotNetdevVotes) — but
// the verdict still ships on the wire and still scopes the protocol gate where
// it is ownerless, so an honest verdict is still the contract.
//
// FAIL-ON-REVERT: give fabricParentUnbindable a different evidence source
// — a second kernel sample, the unit-level tunnel flag instead of the
// interface-level one, or an exact-spelling lookup of the parent's stanza —
// and a row/fabric pair disagrees here.
func TestFabricAndBaseRowNeverDisagree(t *testing.T) {
	for _, tc := range []struct {
		name  string
		xfrm  []string
		lines []string
	}{
		{
			name: "live xfrm device as the member",
			xfrm: []string{"ge-0-0-0"},
			lines: []string{
				"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
			},
		},
		{
			name: "interface-level tunnel on the member",
			lines: []string{
				"set interfaces gr-0/0/3 tunnel source 10.0.0.1",
				"set interfaces gr-0/0/3 tunnel destination 10.0.0.2",
				"set interfaces gr-0/0/3 unit 0 family inet address 10.0.1.1/24",
				"set interfaces fab0 fabric-options member-interfaces gr-0/0/3",
			},
		},
		{
			name: "ordinary member with a row",
			lines: []string{
				"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
				"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
			},
		},
		{
			// #6691 round 11: ONE device, two legal authored spellings. The
			// member must be slash-spelled (InterfaceSlot resolves the node from
			// it); the stanza name is a wildcard, so it may be either. An
			// exact-spelling lookup of the parent's stanza misses the tunnel and
			// the fabric votes bindable against an unbindable base row.
			name: "canonical alias between the member and its stanza",
			lines: []string{
				"set interfaces gr-0-0-3 tunnel source 10.0.0.1",
				"set interfaces gr-0-0-3 tunnel destination 10.0.0.2",
				"set interfaces fab0 fabric-options member-interfaces gr-0/0/3",
			},
		},
		{
			// The disagreement production IS allowed to produce, kept here as
			// the control: a unit-level tunnel leaves the BASE row bindable, so
			// the fabric (which reads the base) must agree with the BASE, not
			// with the unit.
			name: "unit-level tunnel leaves the base bindable",
			lines: []string{
				"set interfaces ge-0/0/0 unit 0 tunnel source 10.0.0.1",
				"set interfaces ge-0/0/0 unit 0 tunnel destination 10.0.0.2",
				"set interfaces fab0 fabric-options member-interfaces ge-0/0/0",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer stubLinkSnapshot5619(t, map[string]int{
				"ge-0-0-0": 20, "gr-0-0-3": 20, "ge-0-0-3": 21, "fab0": 22,
			})()
			defer stubXfrmNetdevs(t, tc.xfrm...)()

			lines := append([]string{
				"set chassis cluster reth-count 2",
				"set chassis cluster authentication-key abcdefghijklmnopqrstuvwxyz012345",
				"set interfaces ge-0/0/3 unit 0 family inet address 10.0.9.1/24",
				"set security zones security-zone trust interfaces ge-0/0/3.0",
			}, tc.lines...)
			cfg := compileForTest5619(t, lines...)
			snap, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 0, 0)
			if err != nil {
				t.Fatalf("buildSnapshot: %v", err)
			}
			for _, fab := range snap.Fabrics {
				if fab.ParentLinuxName == "" {
					continue
				}
				for _, iface := range snap.Interfaces {
					// BASE rows only, paired by NETDEV: the row whose name has
					// no unit suffix and whose netdev is the fabric parent —
					// whatever spelling either of them was authored with.
					if iface.LinuxName != fab.ParentLinuxName || strings.Contains(iface.Name, ".") {
						continue
					}
					if got := userspaceUnbindableNetdev(iface); got != fab.ParentUnbindable {
						t.Fatalf("base row %q says unbindable=%v, the fabric parent says %v "+
							"for the SAME netdev %q. Two owners of one device disagreeing "+
							"breaks the unanimity and re-admits it — and unlike a unit/base "+
							"disagreement, this one has no bindable owner behind it",
							iface.Name, got, fab.ParentUnbindable, fab.ParentLinuxName)
					}
				}
			}
		})
	}
}

// stubXfrmNetdevsErr presents a kernel whose xfrm dump HARD-FAILS (#12580):
// no evidence at all, as opposed to stubXfrmNetdevs' successful empty dump.
func stubXfrmNetdevsErr(t *testing.T, err error) func() {
	t.Helper()
	prev := liveXfrmNetdevs
	liveXfrmNetdevs = func() (map[string]bool, error) { return nil, err }
	return func() { liveXfrmNetdevs = prev }
}

// TestAllowlistDegradesToNilOnXfrmDumpFailure12580 is the #12580 regression
// guard.
//
// liveXfrmNetdevs documents that when its dump REPORTS an error,
// UserspaceBoundLinuxInterfaces "degrades to touching no NIC at all" — each
// consumer resolves the error in "its own conservative direction". The
// ingress side of the same failed sample deliberately falls back to
// configuration ownership only (sampleLiveXfrmNetdevs) — but the allowlist is
// PERMISSION to reshape a NIC's RSS table and pin its coalescing, and on a
// failed dump nothing can tell a stale live xfrmi (a zoned `st10` row the
// config no longer binds, still in the kernel) from an ordinary NIC.
//
// SCOPE: a HARD dump error only. An interrupted dump (ErrDumpInterrupted) is
// not reported as an error at all — xfrmDumpNames keeps its partial device
// list as the sample — so an xfrmi missing from that list is still granted.
// #12710 owns that decision; this test makes no claim about it.
//
// The fixture is the issue's measured composition: a stale zoned `st10`
// row (no VPN names it) beside an ordinary LAN NIC, with the dump stubbed
// to a hard error. At pre-fix head the allowlist came back
// [ge-0-0-0 st10] — the stale xfrmi granted reshape permission.
//
// The degrade lands on a commit that otherwise SUCCEEDS (the apply snapshot
// keeps its configuration-ownership fallback), so every NIC-tuning consumer
// of the list does nothing until the next apply. The WARN is the operator's
// only record of that, so it is part of the contract.
//
// FAIL-ON-REVERT / MUTANT KILLS:
//   - drop the degrade-to-nil (snapshot flag never stamped or never read):
//     the failed-dump row reds on both the nil assertion and st10.
//   - degrade on EVERY build (ignore the flag's value): the success-dump
//     control reds — the LAN must survive a healthy dump.
//   - fail buildSnapshot itself on dump error: the snapshot-build control
//     reds because a hard dump error must not fail the apply snapshot.
//   - drop the WARN, demote it below WARN, or stop naming a skipped
//     consumer or the retry point: the failed-dump row reds on the record.
//   - log the WARN on every build: the success-dump control reds.
func TestAllowlistDegradesToNilOnXfrmDumpFailure12580(t *testing.T) {
	defer stubLinkSnapshot5619(t, map[string]int{"ge-0-0-0": 10, "st10": 11})()

	lines := []string{
		"set interfaces ge-0/0/0 unit 0 family inet address 10.0.1.1/24",
		"set interfaces st10 unit 0 family inet address 192.0.2.1/24",
		"set security zones security-zone trust interfaces ge-0/0/0.0",
		"set security zones security-zone trust interfaces st10.0",
	}

	t.Run("failed dump grants reshape permission to nothing", func(t *testing.T) {
		defer stubXfrmNetdevsErr(t, errors.New("RTM_GETLINK: no buffer space available"))()
		cfg := compileForTest5619(t, lines...)
		logs := captureSlog12580(t)
		if got := UserspaceBoundLinuxInterfaces(cfg); got != nil {
			t.Errorf("allowlist on a failed xfrm dump = %v, want nil (degrade to "+
				"touching no NIC at all): the stale xfrmi st10 is indistinguishable "+
				"from an ordinary NIC without the kernel half of the evidence", got)
		}
		warns := allowlistDegradeWarns12580(logs.String())
		if len(warns) != 1 {
			t.Fatalf("WARN records reporting the withheld allowlist = %d, want exactly 1: "+
				"the commit succeeds, so this record is the operator's only signal that "+
				"NIC tuning was skipped.\nlogs:\n%s", len(warns), logs.String())
		}
		for _, want := range []string{
			"RSS indirection", "kill-switch", "coalescence", "hand-back", "next config apply",
		} {
			if !strings.Contains(warns[0], want) {
				t.Errorf("the degrade WARN does not name %q: an operator cannot tell "+
					"which NIC tuning was skipped, or until when.\ngot: %s", want, warns[0])
			}
		}
		// The failure belongs to this one snapshot; it must not turn into
		// a snapshot-build error or get lost before the allowlist reads it.
		snap, err := buildSnapshot(cfg, deriveUserspaceConfig(cfg), 0, 0)
		if err != nil {
			t.Fatalf("buildSnapshot on a failed xfrm dump: %v", err)
		}
		if !snap.xfrmDumpFailed {
			t.Fatal("snapshot lost the xfrm dump failure status")
		}
	})

	t.Run("successful dump keeps the LAN and still refuses the stale xfrmi", func(t *testing.T) {
		defer stubXfrmNetdevs(t, "st10")()
		cfg := compileForTest5619(t, lines...)
		logs := captureSlog12580(t)
		got := UserspaceBoundLinuxInterfaces(cfg)
		if !slices.Contains(got, "ge-0-0-0") {
			t.Errorf("allowlist on a healthy dump = %v, want the LAN ge-0-0-0: "+
				"the degrade must fire on dump failure only", got)
		}
		if slices.Contains(got, "st10") {
			t.Errorf("allowlist on a healthy dump = %v contains the live xfrmi st10", got)
		}
		if warns := allowlistDegradeWarns12580(logs.String()); len(warns) != 0 {
			t.Errorf("a healthy dump logged the allowlist-degrade WARN: %q", warns)
		}
	})
}

// captureSlog12580 routes the default logger into a buffer for the rest of
// the calling (sub)test.
func captureSlog12580(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return &buf
}

// allowlistDegradeWarns12580 returns the WARN records that report the reshape
// allowlist being withheld.
func allowlistDegradeWarns12580(logs string) []string {
	var out []string
	for _, line := range strings.Split(logs, "\n") {
		if strings.Contains(line, "level=WARN") && strings.Contains(line, "allowlist") {
			out = append(out, line)
		}
	}
	return out
}
