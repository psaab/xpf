package dataplane

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// mtuAttempt9845 records one linkSetMTUSeam call: the exact link object it was
// attempted on, the value, and the kernel-modeled outcome.
type mtuAttempt9845 struct {
	link netlink.Link
	mtu  int
	err  error
}

// mtuFixture9845 tunes applyWithKernelMTU9845 for one cell. The zero value is
// the plain kernel model: only a child write above its parent's current MTU
// fails.
type mtuFixture9845 struct {
	// omitLinks names devices left OUT of the result's link caches, so their
	// lookups miss and fail through the stubbed fetch seams — the
	// failed-parent-read shape, with no GETLINK reaching the kernel.
	omitLinks []string
	// failMTU, when non-nil, forces linkSetMTUSeam to fail wherever it
	// returns non-nil. It runs BEFORE the kernel model, so it can fail a
	// write the kernel would accept (the failed-parent-write shape).
	failMTU func(name string, mtu int) error
	// seqLog, when non-nil, records the link name of every MTU attempt in
	// call order — the cross-link sequence the per-link attempts map cannot
	// show (which zone order the loop took).
	seqLog *[]string
}

// applyWithKernelMTU9845 runs one programZoneMaps apply of cfg against a fake
// host whose MTU seam models vlan_dev_change_mtu: a VLAN child write above its
// parent's CURRENT fake-host MTU fails; every other write succeeds. Successful
// writes land in h.mtu only — never back into the passed Link object (#8119).
// It returns the host, the MTU attempts per link, and the CompileResult (for
// #4960 assertions).
//
// initialMTU must name every device the apply touches (parents and children);
// ifindexes are assigned deterministically from 4300.
//
// HOST SAFETY — this fixture performs NO real-host mutation, privileged or
// not, by construction (reviewed call by call):
//
//   - programZoneMaps, NOT compileZones, is the entry point — so
//     stripUnmanagedInterfaces (real net.Interfaces enumeration, LinkDel,
//     AddrDel, LinkSetDown on REAL interfaces) is never reached. The MTU
//     logic under test lives entirely in programZoneMaps -> mapZoneInterface
//     (precedent: unarmedFromZoneMaps drives the same path).
//   - tuneInterfaceBuffers (direct LinkSetTxQLen plus /proc/sys and
//     /sys/class/net writes) is skipped by pre-setting
//     ethtoolApplied["buffers:"+phys] for every phys; buffer tuning is
//     orthogonal to MTU ordering.
//   - netlink.LinkSetUp/LinkSetDown stay direct but run only on fake
//     ifindexes (4300+), which the kernel rejects with ENODEV — warn-only,
//     no host effect even as root.
//   - linkByNameSeam/linkByIndexSeam are stubbed to fail: every lookup in
//     these cells either hits the pre-populated caches or is MEANT to fail
//     (the failed-read cell; #9841's fresh-verification reads on failure
//     paths). No GETLINK reaches the kernel at all, so the fixture is
//     syscall-deterministic as well as mutation-free.
//   - Everything else is seamed or stubbed: linkSetMTUSeam (this helper),
//     addr*Seams (fakeHost8119.install), ensureVLANSubInterfaceFn (stub),
//     runEthtool (mockEthtool), dp.* (convergenceTestDP). applyEthtool
//     early-returns (fixtures carry no speed/duplex). linkLister is never
//     reached (#9841's child-blocking probe runs only with a known live
//     value, and every fresh read here fails by construction).
//
// Two tripwires below guard the construction against regressions: no ethtool
// "-g" call (tuneInterfaceBuffers is its only caller) and no
// ManagedInterfaces entries (only the compileZones-only model builders and
// the strip append those).
func applyWithKernelMTU9845(t *testing.T, cfg *config.Config, initialMTU map[string]int, opts ...mtuFixture9845) (*fakeHost8119, map[string][]mtuAttempt9845, *CompileResult) {
	t.Helper()
	var fix mtuFixture9845
	if len(opts) > 1 {
		t.Fatalf("premise: at most one mtuFixture9845, got %d", len(opts))
	} else if len(opts) == 1 {
		fix = opts[0]
	}
	omit := map[string]bool{}
	for _, n := range fix.omitLinks {
		omit[n] = true
	}
	names := make([]string, 0, len(initialMTU))
	for n := range initialMTU {
		names = append(names, n)
	}
	sort.Strings(names)
	mtu := map[string]int{}
	addrs := map[string]map[string]bool{}
	index := map[string]int{}
	for i, n := range names {
		mtu[n] = initialMTU[n]
		addrs[n] = map[string]bool{}
		index[n] = 4300 + i
	}
	h := &fakeHost8119{mtu: mtu, addrs: addrs, index: index}
	h.install(t)

	attempts := map[string][]mtuAttempt9845{}
	write := linkSetMTUSeam
	t.Cleanup(func() { linkSetMTUSeam = write })
	linkSetMTUSeam = func(l netlink.Link, m int) error {
		name := l.Attrs().Name
		var err error
		if fix.failMTU != nil {
			err = fix.failMTU(name, m)
		}
		// vlan_dev_change_mtu: the child may not exceed its parent's CURRENT mtu.
		if err == nil {
			if dot := strings.LastIndex(name, "."); dot > 0 {
				if live, ok := h.mtu[name[:dot]]; ok && m > live {
					err = fmt.Errorf("netlink: vlan %s mtu %d exceeds parent %s current mtu %d: invalid argument", name, m, name[:dot], live)
				}
			}
		}
		if err == nil {
			// Deliberately does NOT update l.Attrs().MTU — see fakeHost8119.
			h.mtu[name] = m
		}
		attempts[name] = append(attempts[name], mtuAttempt9845{link: l, mtu: m, err: err})
		if fix.seqLog != nil {
			*fix.seqLog = append(*fix.seqLog, name)
		}
		return err
	}

	// Fetch seams fail closed: cache misses (the deliberate omission) and
	// #9841's fresh-verification reads never reach the kernel (see HOST
	// SAFETY above).
	origByName, origByIndex := linkByNameSeam, linkByIndexSeam
	t.Cleanup(func() { linkByNameSeam, linkByIndexSeam = origByName, origByIndex })
	linkByNameSeam = func(string) (netlink.Link, error) { return nil, fmt.Errorf("no such device (9845 fixture)") }
	linkByIndexSeam = func(int) (netlink.Link, error) { return nil, fmt.Errorf("no such device (9845 fixture)") }

	var ethtoolCalls [][]string
	mockEthtool(t, func(args ...string) ([]byte, error) {
		ethtoolCalls = append(ethtoolCalls, args)
		return []byte("rx-vlan-offload: off\n"), nil
	})
	origVLAN := ensureVLANSubInterfaceFn
	t.Cleanup(func() { ensureVLANSubInterfaceFn = origVLAN })
	ensureVLANSubInterfaceFn = func(parent string, vlanID int) (int, bool, error) {
		name := fmt.Sprintf("%s.%d", parent, vlanID)
		idx, ok := h.index[name]
		if !ok {
			t.Fatalf("premise: %s is not in the fake host's index map; initialMTU must name every device the apply touches", name)
		}
		return idx, false, nil
	}

	result := newValidationResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)
	for _, zone := range cfg.Security.Zones {
		if zone == nil {
			continue
		}
		for _, ref := range zone.Interfaces {
			phys, _, _, _ := resolveInterfaceRef(ref, cfg)
			if _, ok := h.index[phys]; !ok {
				t.Fatalf("premise: phys %q of ref %q is not in initialMTU", phys, ref)
			}
			result.ifCache[phys] = &net.Interface{Index: h.index[phys], Name: phys}
			// Skip tuneInterfaceBuffers' direct LinkSetTxQLen and /proc/sys
			// + /sys writes (see HOST SAFETY above).
			result.ethtoolApplied["buffers:"+phys] = true
		}
	}
	for _, name := range names {
		if omit[name] {
			continue
		}
		link := h.link(name)
		result.linkCache[name] = link
		result.linkIdxMap[h.index[name]] = link
	}
	if _, err := programZoneMaps(convergenceTestDP{}, cfg, result); err != nil {
		t.Fatalf("programZoneMaps: %v", err)
	}
	// Host-safety tripwires (see HOST SAFETY above): tuneInterfaceBuffers
	// is the only ethtool "-g" caller, and only the compileZones-only model
	// builders and the unmanaged strip append ManagedInterfaces. The
	// liveness premise keeps the "-g" tripwire from going vacuous: every
	// cell drives at least one per-phys setup, which always queries
	// rx-vlan state via ethtool "-k" first.
	if len(ethtoolCalls) == 0 {
		t.Fatalf("premise: no ethtool calls recorded — the recorder is dead and the -g tripwire proves nothing")
	}
	for _, call := range ethtoolCalls {
		if len(call) > 0 && call[0] == "-g" {
			t.Fatalf("host-safety tripwire: tuneInterfaceBuffers ran for %v — the buffers guard regressed and the apply reached direct LinkSetTxQLen + /proc/sys writes", call)
		}
	}
	if len(result.ManagedInterfaces) != 0 {
		t.Fatalf("host-safety tripwire: %d ManagedInterfaces entries — the fixture reached a compileZones-only builder or the unmanaged strip", len(result.ManagedInterfaces))
	}
	return h, attempts, result
}

// #9845: raising a parent and its VLAN child's unit MTU together must converge
// in ONE apply. Master writes the child first — refused, because it exceeds
// the parent's CURRENT MTU — and the parent second, so the child keeps its old
// MTU until the next commit.
func TestRaiseParentAndChildMTUTogetherConvergesInOneApply_9845(t *testing.T) {
	const parent = "ge-0-0-9"
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{parent + ".50"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		parent: {
			Name: parent, VlanTagging: true, MTU: 9000,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, MTU: 9000},
			},
		},
	}
	// Premise: the tagged reference plans the interface-level MTU on the
	// parent (#9761). Without that there is no parent write to order against.
	if pd := planPhysDesired(cfg)[parent]; pd == nil || pd.mtu != 9000 {
		t.Fatalf("premise: parent plan = %+v, want mtu 9000", pd)
	}
	child := parent + ".50"
	h, attempts, result := applyWithKernelMTU9845(t, cfg, map[string]int{parent: 1500, child: 1500})

	if got := h.mtu[parent]; got != 9000 {
		t.Fatalf("parent %s mtu = %d after one apply, want 9000", parent, got)
	}
	if got := h.mtu[child]; got != 9000 {
		t.Fatalf("#9845: %s kept MTU %d after one apply raising both parent and child to 9000, want 9000.\n"+
			"The child write runs before the parent's raise in the same mapZoneInterface call, the kernel refuses "+
			"it, and the apply reports success with the child still at its old MTU until the next commit", child, got)
	}
	// Retry-once pin: the first child write is refused (the parent is still at
	// 1500), the retry after the parent's raise succeeds.
	if n := len(attempts[child]); n != 2 {
		t.Errorf("child %s drew %d MTU attempts, want 2 (refused-attempt + one retry after the parent's raise)", child, n)
	} else {
		if attempts[child][0].err == nil {
			t.Errorf("first child write to %s succeeded while the parent was still at 1500; the kernel model must refuse it or this cell measures nothing", child)
		}
		if err := attempts[child][1].err; err != nil {
			t.Errorf("retry of %s after the parent's raise failed: %v", child, err)
		}
	}
	if n := len(attempts[parent]); n != 1 {
		t.Errorf("parent %s drew %d MTU attempts, want exactly 1", parent, n)
	}
	// Composition with #9841: the refused first attempt records, and the
	// retry's success MUST clear (every write-success path clears) — a
	// converged apply carries no records.
	if recs := result.sortedMTUUnconverged(); len(recs) != 0 {
		t.Errorf("converged apply carries %d MTUUnconverged records, want none (the retry success must clear): %+v", len(recs), recs)
	}
}

// A child REDUCTION applies inline on the first attempt: the kernel accepts a
// child MTU below the parent's current MTU, so no retry is needed and none
// must fire. The parent is already converged, so it draws no write at all.
func TestChildReductionAppliesInlineWithNoRetry_9845(t *testing.T) {
	const parent = "ge-0-0-9"
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{parent + ".50"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		parent: {
			Name: parent, VlanTagging: true, MTU: 9000,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, MTU: 1500},
			},
		},
	}
	child := parent + ".50"
	h, attempts, _ := applyWithKernelMTU9845(t, cfg, map[string]int{parent: 9000, child: 9000})

	if got := h.mtu[child]; got != 1500 {
		t.Fatalf("child %s mtu = %d after one apply, want the reduced 1500", child, got)
	}
	if n := len(attempts[child]); n != 1 {
		t.Errorf("child %s drew %d MTU attempts, want exactly 1: a reduction the kernel accepts must not be retried", child, n)
	}
	if n := len(attempts[parent]); n != 0 {
		t.Errorf("converged parent %s drew %d MTU attempts, want none", parent, n)
	}
}

// The retry reuses the VALIDATED link object from the refused attempt — it
// must not resolve the VLAN name again, or a foreign device renamed onto that
// name in the meantime would be modified instead. The direct-contract
// companion (UsesTheGivenLinkWithoutLookup) proves no lookup happens at all:
// the cache would hand a re-resolve this same object, so identity alone
// cannot show it.
func TestRetryReusesTheValidatedLink_9845(t *testing.T) {
	const parent = "ge-0-0-9"
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{parent + ".50"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		parent: {
			Name: parent, VlanTagging: true, MTU: 9000,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, MTU: 9000},
			},
		},
	}
	child := parent + ".50"
	_, attempts, _ := applyWithKernelMTU9845(t, cfg, map[string]int{parent: 1500, child: 1500})

	got := attempts[child]
	if len(got) != 2 {
		t.Fatalf("premise: child %s drew %d attempts, want the refused-attempt + retry pair", child, len(got))
	}
	if got[0].link != got[1].link {
		t.Errorf("retry resolved a different link object than the refused attempt: retry must reuse the validated link, never re-resolve the name")
	}
	if got[0].mtu != 9000 || got[1].mtu != 9000 {
		t.Errorf("retry changed the value: attempts wrote %d then %d, want the same 9000 both times", got[0].mtu, got[1].mtu)
	}
}

// A failed parent READ must not veto a child write the kernel would accept.
// The parent link is left out of the caches (its lookup fails), the parent
// write is skipped, and the child's reduction still applies — the initial
// write stays inline and ungated on parent state.
func TestFailedParentReadDoesNotVetoChildReduction_9845(t *testing.T) {
	const parent = "ge-0-0-9"
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{parent + ".50"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		parent: {
			Name: parent, VlanTagging: true, MTU: 9000,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, MTU: 1500},
			},
		},
	}
	child := parent + ".50"
	h, attempts, _ := applyWithKernelMTU9845(t, cfg, map[string]int{parent: 9000, child: 9000}, mtuFixture9845{omitLinks: []string{parent}})

	if got := h.mtu[child]; got != 1500 {
		t.Fatalf("child %s mtu = %d with the parent link unreadable, want the reduced 1500: "+
			"a failed parent read must not veto a child write the kernel accepts", child, got)
	}
	if n := len(attempts[parent]); n != 0 {
		t.Errorf("parent %s drew %d MTU attempts with its link unreadable, want none", parent, n)
	}
}

// Successful MTU writes join the #4960 host-mutation record (previously no
// MTU write recorded anything), and a converged apply records nothing.
func TestSuccessfulMTUWritesRecordHostMutation_9845(t *testing.T) {
	const parent = "ge-0-0-9"
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{parent + ".50"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		parent: {
			Name: parent, VlanTagging: true, MTU: 9000,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, MTU: 9000},
			},
		},
	}
	child := parent + ".50"

	_, _, moved := applyWithKernelMTU9845(t, cfg, map[string]int{parent: 1500, child: 1500})
	if !moved.HostMutated() {
		t.Fatalf("an apply that raised two MTUs reports no host mutation")
	}
	summary := moved.hostMutationSummary()
	for _, want := range []string{"set interface MTU", "set VLAN sub-interface MTU"} {
		if !strings.Contains(summary, want) {
			t.Errorf("host-mutation summary %q omits %q", summary, want)
		}
	}

	_, _, converged := applyWithKernelMTU9845(t, cfg, map[string]int{parent: 9000, child: 9000})
	if converged.HostMutated() {
		t.Errorf("a converged apply reports host mutation %q, want none", converged.hostMutationSummary())
	}
}

// A converged apply writes no MTU anywhere: neither the parent write nor the
// child write fires, so there is nothing to retry and nothing to record.
func TestConvergedApplyWritesNoMTU_9845(t *testing.T) {
	const parent = "ge-0-0-9"
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{parent + ".50"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		parent: {
			Name: parent, VlanTagging: true, MTU: 9000,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, MTU: 9000},
			},
		},
	}
	child := parent + ".50"
	h, attempts, _ := applyWithKernelMTU9845(t, cfg, map[string]int{parent: 9000, child: 9000})

	if len(attempts) != 0 {
		t.Errorf("a converged apply tried MTU writes %v, want none", attempts)
	}
	if h.mtu[parent] != 9000 || h.mtu[child] != 9000 {
		t.Errorf("converged MTUs moved: parent=%d child=%d, want 9000/9000", h.mtu[parent], h.mtu[child])
	}
}

// Two children raised with their parent converge in one apply with exactly
// ONE retry between them: whichever child the zone order reaches first is
// refused and retried, the second already finds the parent raised. The
// assertions are order-independent (the zone loop order is Go map order).
func TestTwoRaisedChildrenConvergeWithOneRetryTotal_9845(t *testing.T) {
	const parent = "ge-0-0-9"
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{parent + ".50"}},
		"untrust": {Name: "untrust", Interfaces: []string{parent + ".80"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		parent: {
			Name: parent, VlanTagging: true, MTU: 9000,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, MTU: 9000},
				80: {Number: 80, VlanID: 80, MTU: 9000},
			},
		},
	}
	sub50, sub80 := parent+".50", parent+".80"
	h, attempts, _ := applyWithKernelMTU9845(t, cfg, map[string]int{parent: 1500, sub50: 1500, sub80: 1500})

	for _, child := range []string{sub50, sub80} {
		if got := h.mtu[child]; got != 9000 {
			t.Errorf("child %s mtu = %d after one apply, want 9000", child, got)
		}
	}
	if total := len(attempts[sub50]) + len(attempts[sub80]); total != 3 {
		t.Errorf("two raised children drew %d MTU attempts total, want 3 (one refused-attempt + retry pair, one first-try success)", total)
	}
	if n := len(attempts[parent]); n != 1 {
		t.Errorf("parent %s drew %d MTU attempts, want exactly 1", parent, n)
	}
}

// The issue's primary shape: an untagged unit plans the parent's MTU and a
// tagged unit carries its own. Whichever zone order the loop takes, one apply
// converges both — the tagged-first order is the one master leaves for the
// next commit. The loop runs until BOTH orders are observed (not merely
// hoped-for): the first attempt's link discriminates them — the untagged ref
// writes the parent with no child attempt before it, while the tagged ref's
// first act is the child attempt — and each order must converge on its own.
func TestMixedUntaggedAndTaggedRaiseConvergesInOneApply_9845(t *testing.T) {
	const parent = "ge-0-0-9"
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{parent + ".0"}},
		"untrust": {Name: "untrust", Interfaces: []string{parent + ".50"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		parent: {
			Name: parent,
			Units: map[int]*config.InterfaceUnit{
				0:  {Number: 0, MTU: 9000},
				50: {Number: 50, VlanID: 50, MTU: 9000},
			},
		},
	}
	// Premise: the untagged unit's MTU plans the parent's.
	if pd := planPhysDesired(cfg)[parent]; pd == nil || pd.mtu != 9000 {
		t.Fatalf("premise: parent plan = %+v, want mtu 9000 from untagged unit 0", pd)
	}
	child := parent + ".50"
	sawParentFirst, sawChildFirst := false, false
	for i := range 100 {
		var seq []string
		h, _, _ := applyWithKernelMTU9845(t, cfg, map[string]int{parent: 1500, child: 1500},
			mtuFixture9845{seqLog: &seq})
		if h.mtu[parent] != 9000 || h.mtu[child] != 9000 {
			t.Fatalf("apply %d (attempt order %v): parent=%d child=%d after one apply, want 9000/9000", i, seq, h.mtu[parent], h.mtu[child])
		}
		if len(seq) == 0 {
			t.Fatalf("apply %d: no MTU attempts recorded; the order discriminator is blind", i)
		}
		switch seq[0] {
		case parent:
			sawParentFirst = true
		case child:
			sawChildFirst = true
		default:
			t.Fatalf("apply %d: first attempt on %q, want the parent or the child", i, seq[0])
		}
		if sawParentFirst && sawChildFirst {
			break
		}
	}
	if !sawParentFirst || !sawChildFirst {
		t.Fatalf("only one zone order observed in 100 applies (parent-first=%v child-first=%v); this cell must cover both", sawParentFirst, sawChildFirst)
	}
}

// A FAILED parent write suppresses the retry: the parent never moved, so the
// child's admission cannot have changed and a second attempt would only log a
// second refusal. Removing the parentMTUWrote gate reddens this cell (the
// child would draw a futile second attempt).
func TestFailedParentWriteSuppressesTheRetry_9845(t *testing.T) {
	const parent = "ge-0-0-9"
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{parent + ".50"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		parent: {
			Name: parent, VlanTagging: true, MTU: 9000,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, MTU: 9000},
			},
		},
	}
	child := parent + ".50"
	h, attempts, _ := applyWithKernelMTU9845(t, cfg,
		map[string]int{parent: 1500, child: 1500},
		mtuFixture9845{failMTU: func(name string, _ int) error {
			if name == parent {
				return fmt.Errorf("test-forced parent refusal")
			}
			return nil
		}})

	if got := h.mtu[parent]; got != 1500 {
		t.Fatalf("premise: parent %s mtu = %d, want 1500 (the forced failure must leave it unmoved)", parent, got)
	}
	if got := h.mtu[child]; got != 1500 {
		t.Errorf("child %s mtu = %d with the parent write failed, want 1500: nothing about its admission changed", child, got)
	}
	if n := len(attempts[parent]); n != 1 || attempts[parent][0].err == nil {
		t.Fatalf("premise: parent drew %d attempts, want exactly 1 failed one", n)
	}
	if n := len(attempts[child]); n != 1 {
		t.Errorf("child %s drew %d MTU attempts after a failed parent write, want exactly 1: the retry must not fire when the parent never moved", child, n)
	}
}

// The retry terminates: when the parent's raise still leaves the child above
// the cap (here the parent plans only 2000 while the child wants 9000), the
// retry is refused a second time, warns, and the apply still succeeds —
// exactly master's warn-only behavior, with no third attempt and no loop.
func TestRetryTerminatesWhenStillRefused_9845(t *testing.T) {
	const parent = "ge-0-0-9"
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{parent + ".50"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		parent: {
			Name: parent, VlanTagging: true, MTU: 2000,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, MTU: 9000},
			},
		},
	}
	child := parent + ".50"
	h, attempts, result := applyWithKernelMTU9845(t, cfg, map[string]int{parent: 1500, child: 1500})

	if got := h.mtu[parent]; got != 2000 {
		t.Fatalf("premise: parent %s mtu = %d, want its planned 2000", parent, got)
	}
	if got := h.mtu[child]; got != 1500 {
		t.Errorf("child %s mtu = %d, want 1500: 9000 still exceeds the raised parent's 2000", child, got)
	}
	got := attempts[child]
	if len(got) != 2 {
		t.Fatalf("child %s drew %d MTU attempts, want exactly 2 (refused attempt + one refused retry, then stop)", child, len(got))
	}
	if got[0].err == nil || got[1].err == nil {
		t.Errorf("both child attempts must be refused (attempt errors: %v, %v)", got[0].err, got[1].err)
	}
	// Composition with #9841: the persistent refusal IS recorded (once —
	// the failed retry warns but takes no second record), while the
	// converged parent records nothing.
	recs := result.sortedMTUUnconverged()
	if len(recs) != 1 || recs[0].Name != child || recs[0].WantMTU != 9000 {
		t.Errorf("want exactly the child's MTUUnconverged record (want 9000), got %+v", recs)
	}
}

// A child write that succeeds on its FIRST try records its own #4960 entry,
// independent of the retry arm's mark (and of the parent's): the parent is
// converged here, so no other MTU mark can fire. Removing the success-arm
// markHostMutated in applyVLANSubInterfaceMTU9757 reddens this cell — the
// raise-both cell cannot, because its retry arm would cover for it.
func TestChildOnlySuccessRecordsItsOwnMutation_9845(t *testing.T) {
	const parent = "ge-0-0-9"
	cfg := &config.Config{}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{parent + ".50"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		parent: {
			Name: parent, VlanTagging: true, MTU: 9000,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, MTU: 1500},
			},
		},
	}
	child := parent + ".50"
	h, attempts, result := applyWithKernelMTU9845(t, cfg, map[string]int{parent: 9000, child: 9000})

	if got := h.mtu[child]; got != 1500 {
		t.Fatalf("premise: child %s mtu = %d, want the reduced 1500", child, got)
	}
	if n := len(attempts[child]); n != 1 {
		t.Fatalf("premise: child drew %d attempts, want the single first-try success (no retry may fire here)", n)
	}
	if !result.HostMutated() {
		t.Fatalf("a first-try child MTU write reports no host mutation")
	}
	summary := result.hostMutationSummary()
	if !strings.Contains(summary, "set VLAN sub-interface MTU") {
		t.Errorf("host-mutation summary %q omits the child-only success mark", summary)
	}
	if strings.Contains(summary, "set interface MTU") {
		t.Errorf("host-mutation summary %q names the parent mark, but the converged parent drew no write", summary)
	}
}

// The retry uses the GIVEN link object without any name lookup. The in-apply
// pin above shows the same object flowing through both attempts, but the
// per-apply link cache would hand a re-resolve the identical object too — so
// this cell calls the retry directly with a link NO cache holds (empty
// result, unregistered ifindex): whatever reaches the seam must be exactly
// what was passed, because there is nothing to resolve.
func TestRetryUsesTheGivenLinkWithoutLookup_9845(t *testing.T) {
	link := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-9.50", Index: 4399, MTU: 1500}}
	var got []netlink.Link
	write := linkSetMTUSeam
	t.Cleanup(func() { linkSetMTUSeam = write })
	linkSetMTUSeam = func(l netlink.Link, _ int) error {
		got = append(got, l)
		return nil
	}

	retryVLANSubInterfaceMTU9845(newValidationResult(), &vlanMTUPending9845{link: link, wantMTU: 9000, subName: "ge-0-0-9.50", configRef: "ge-0-0-9.50"})

	if len(got) != 1 {
		t.Fatalf("retry drew %d seam calls, want exactly 1", len(got))
	}
	if got[0] != netlink.Link(link) {
		t.Errorf("retry did not use the given link object: a name re-resolve would hand back a different (or no) object for this uncached link")
	}
}

// A failed syscall whose end state already converged takes no retry token:
// fresh verification shows live==want (a concurrent writer won), so there
// is nothing to converge. The stale cache still drives the one attempt,
// the failure stays journal-only with no record, and — the point of this
// cell — no token comes back even though the seam errored. Removing the
// converged-check in the helper reddens here, not just in #9841's pin.
func TestConvergedEndStateSkipsTheRetry_9845(t *testing.T) {
	const parent, child = "ge-0-0-9", "ge-0-0-9.50"
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		parent: {
			Name: parent, VlanTagging: true, MTU: 1400,
			Units: map[int]*config.InterfaceUnit{
				50: {Number: 50, VlanID: 50, MTU: 1300},
			},
		},
	}
	result := newValidationResult()
	// Stale cache: both links read 1500, while the host below already sits
	// at the wanted 1300 for the child.
	result.linkCache[parent] = &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: parent, Index: 4300, MTU: 1500}}
	result.linkCache[child] = &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: child, Index: 4301, MTU: 1500}}
	calls := 0
	write := linkSetMTUSeam
	t.Cleanup(func() { linkSetMTUSeam = write })
	linkSetMTUSeam = func(netlink.Link, int) error {
		calls++
		return fmt.Errorf("simulated refusal against a converged host")
	}
	byName := linkByNameSeam
	t.Cleanup(func() { linkByNameSeam = byName })
	linkByNameSeam = func(name string) (netlink.Link, error) {
		// Fresh read: the live child is already where it belongs (VLAN
		// kind + proved ifindexes, so retry validation accepts it).
		return &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: child, Index: 4301, MTU: 1300, ParentIndex: 4300}}, nil
	}

	token := applyVLANSubInterfaceMTU9757(cfg, result, child, parent, 50, parent, child,
		vlanMTUContext9841{parentWant: 1400, parentIfindex: 4300, subIfindex: 4301})

	if token != nil {
		t.Errorf("converged end state took a retry token: fresh verification shows live==want, so there is nothing to retry")
	}
	if calls != 1 {
		t.Errorf("child drew %d seam calls, want exactly 1 (the stale cache must still drive the attempt)", calls)
	}
	if recs := result.sortedMTUUnconverged(); len(recs) != 0 {
		t.Errorf("records = %+v, want none: the converged end state is journal-only", recs)
	}
}
