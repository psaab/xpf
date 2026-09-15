package dataplane

import (
	"fmt"
	"net"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"

	"github.com/psaab/xpf/pkg/config"
)

// mtuDriveOpts9841 scripts one compileZones apply for the #9841 cells:
// which links are pre-seeded into the result's caches (omitted names miss
// and reach the scriptable seams), and how the MTU write and the netlink
// read surfaces behave.
type mtuDriveOpts9841 struct {
	seedCache []string
	seedIdx   []string
	// mtuErr, when non-nil, fails the MTU write for the named link. A
	// failing write never reaches the fake host.
	mtuErr   func(name string, mtu int) error
	byName   func(name string) (netlink.Link, error)
	byIndex  func(idx int) (netlink.Link, error)
	linkList func() ([]netlink.Link, error)
}

type mtuDrive9841 struct {
	t      *testing.T
	cfg    *config.Config
	h      *fakeHost8119
	writes map[string]int
	result *CompileResult
}

// setupMTUApply9841 builds the fixture without running it, so cells can
// skew the host between seeding and the apply (stale-cache shapes). Call
// run to drive compileZones; the apply must succeed (policy (b) keeps
// applying — every #9841 cell asserts success plus the record).
func setupMTUApply9841(t *testing.T, cfg *config.Config, hostMTU map[string]int, opts mtuDriveOpts9841) *mtuDrive9841 {
	t.Helper()
	names := make([]string, 0, len(hostMTU))
	for n := range hostMTU {
		names = append(names, n)
	}
	slices.Sort(names)
	h := &fakeHost8119{
		mtu:   make(map[string]int, len(hostMTU)),
		addrs: make(map[string]map[string]bool, len(hostMTU)),
		index: make(map[string]int, len(hostMTU)),
	}
	for i, n := range names {
		h.mtu[n] = hostMTU[n]
		h.index[n] = 4212 + i
		if strings.Contains(n, ".") {
			h.addrs[n] = map[string]bool{}
		} else {
			h.addrs[n] = map[string]bool{"192.0.2.9/24": true}
		}
	}
	h.install(t)
	base := linkSetMTUSeam
	writes := map[string]int{}
	t.Cleanup(func() { linkSetMTUSeam = base })
	linkSetMTUSeam = func(l netlink.Link, mtu int) error {
		writes[l.Attrs().Name]++
		if opts.mtuErr != nil {
			if err := opts.mtuErr(l.Attrs().Name, mtu); err != nil {
				return err
			}
		}
		return base(l, mtu)
	}
	mockEthtool(t, func(...string) ([]byte, error) { return []byte("rx-vlan-offload: off\n"), nil })
	origVLAN := ensureVLANSubInterfaceFn
	t.Cleanup(func() { ensureVLANSubInterfaceFn = origVLAN })
	ensureVLANSubInterfaceFn = func(parent string, vlanID int) (int, bool, error) {
		return h.index[fmt.Sprintf("%s.%d", parent, vlanID)], false, nil
	}
	if opts.byName != nil {
		orig := linkByNameSeam
		t.Cleanup(func() { linkByNameSeam = orig })
		linkByNameSeam = opts.byName
	}
	if opts.byIndex != nil {
		orig := linkByIndexSeam
		t.Cleanup(func() { linkByIndexSeam = orig })
		linkByIndexSeam = opts.byIndex
	}
	if opts.linkList != nil {
		orig := linkLister
		t.Cleanup(func() { linkLister = orig })
		linkLister = opts.linkList
	}

	result := newValidationResult()
	assignZoneIDs(result, cfg)
	assignScreenIDs(result, cfg)
	for _, n := range names {
		if strings.Contains(n, ".") {
			continue
		}
		result.ifCache[n] = &net.Interface{Index: h.index[n], Name: n}
	}
	links := map[string]netlink.Link{}
	get := func(n string) netlink.Link {
		if l, ok := links[n]; ok {
			return l
		}
		l := h.link(n)
		links[n] = l
		return l
	}
	for _, n := range opts.seedCache {
		result.linkCache[n] = get(n)
	}
	for _, n := range opts.seedIdx {
		result.linkIdxMap[h.index[n]] = get(n)
	}
	return &mtuDrive9841{t: t, cfg: cfg, h: h, writes: writes, result: result}
}

func (d *mtuDrive9841) run() {
	d.t.Helper()
	if err := compileZones(convergenceTestDP{}, d.cfg, d.result); err != nil {
		d.t.Fatalf("compileZones: %v", err)
	}
}

func (d *mtuDrive9841) records() []MTUUnconverged {
	return d.result.sortedMTUUnconverged()
}

// deviceLink9841 mirrors the fake host's current MTU into a fresh Device,
// so scripted seam hits observe post-write host state like real netlink.
func deviceLink9841(h *fakeHost8119, name string) netlink.Link {
	return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: h.index[name], MTU: h.mtu[name]}}
}

// vlanLink9841 mirrors the fake host into a well-formed 802.1Q child for
// identity-validated retry hits.
func vlanLink9841(h *fakeHost8119, subName string, parentIdx int) netlink.Link {
	return &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{
		Name: subName, Index: h.index[subName], MTU: h.mtu[subName], ParentIndex: parentIdx,
	}}
}

func findRecord9841(t *testing.T, recs []MTUUnconverged, name string) MTUUnconverged {
	t.Helper()
	for _, r := range recs {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no record for %s in %+v", name, recs)
	return MTUUnconverged{}
}

// A physical lookup failure on both attempts records lookup-failed while
// the apply succeeds and the netdev sits provably at its old MTU. The
// parent is seeded by NAME only, so the child's reset-target read still
// resolves and this cell isolates exactly one record.
func TestPhysMTULookupFailureRecordsUnconverged9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	d := setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1500},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{sub50, sub80},
			byIndex:   func(int) (netlink.Link, error) { return nil, fmt.Errorf("no such device") },
		})
	d.run()

	if got := d.h.mtu[parent]; got != 1500 {
		t.Fatalf("parent MTU = %d, want the old 1500: no write may reach a netdev whose lookup failed", got)
	}
	if got := d.writes[parent]; got != 0 {
		t.Fatalf("parent drew %d MTU writes without a resolved link, want 0", got)
	}
	recs := d.records()
	if len(recs) != 1 {
		t.Fatalf("records = %+v, want exactly the parent's lookup failure", recs)
	}
	r := recs[0]
	if r.Name != parent || r.ConfigRef != parent || r.WantMTU != 1400 || r.LiveMTU != mtuUnknown9841 || r.Grade != MTUGradeLookupFailed {
		t.Errorf("record = %+v, want {parent, parent, want 1400, live unknown, lookup-failed}", r)
	}
	if !strings.Contains(r.Detail, "retry") {
		t.Errorf("detail %q must say the retry ran", r.Detail)
	}
}

// A transient first-attempt failure healed by the uncached retry writes
// and stays silent: the retry is a repair path, not a warning source.
func TestPhysMTULookupRetrySuccessWrites9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	calls := 0
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1500},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{sub50, sub80},
			byIndex: func(idx int) (netlink.Link, error) {
				calls++
				if calls == 1 {
					return nil, fmt.Errorf("simulated transient RTM failure")
				}
				return deviceLink9841(d.h, parent), nil
			},
		})
	d.run()

	if got := d.h.mtu[parent]; got != 1400 {
		t.Fatalf("parent MTU = %d, want 1400: the retry must repair a transient lookup failure", got)
	}
	if got := d.records(); len(got) != 0 {
		t.Fatalf("records = %+v, want none: a healed lookup warns about nothing", got)
	}
}

// A refused physical write records write-failed with the fresh-observed
// live MTU; the netdev sits provably at its old value and the write was
// attempted exactly once.
func TestPhysMTUWriteFailureRecordsWithLiveMTU9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1500},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{parent, sub50, sub80},
			mtuErr: func(name string, _ int) error {
				if name == parent {
					return fmt.Errorf("operation not supported")
				}
				return nil
			},
			byIndex:  func(idx int) (netlink.Link, error) { return deviceLink9841(d.h, parent), nil },
			linkList: func() ([]netlink.Link, error) { return nil, nil },
		})
	d.run()

	if got := d.h.mtu[parent]; got != 1500 {
		t.Fatalf("parent MTU = %d, want the old 1500", got)
	}
	if got := d.writes[parent]; got != 1 {
		t.Fatalf("parent write attempts = %d, want 1 (attempted once, refused)", got)
	}
	r := findRecord9841(t, d.records(), parent)
	if r.WantMTU != 1400 || r.LiveMTU != 1500 || r.Grade != MTUGradeWriteFailed {
		t.Errorf("record = %+v, want {want 1400, live 1500, write-failed}", r)
	}
	if !strings.Contains(r.Detail, "operation not supported") {
		t.Errorf("detail %q must carry the kernel errno", r.Detail)
	}
}

// When the fresh-verification read itself fails, the record says unknown
// rather than laundering the stale cached value as live.
func TestPhysMTUWriteFailureUnknownWhenUnreadable9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	d := setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1500},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{parent, sub50, sub80},
			mtuErr: func(name string, _ int) error {
				if name == parent {
					return fmt.Errorf("operation not supported")
				}
				return nil
			},
			byIndex:  func(int) (netlink.Link, error) { return nil, fmt.Errorf("no such device") },
			linkList: func() ([]netlink.Link, error) { return nil, nil },
		})
	d.run()

	r := findRecord9841(t, d.records(), parent)
	if r.LiveMTU != mtuUnknown9841 {
		t.Errorf("record live = %d, want unknown: an unreadable device must not borrow the stale cache", r.LiveMTU)
	}
}

// A converged physical netdev records nothing and draws no write.
func TestPhysMTUConvergedWritesNothing9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	d := setupMTUApply9841(t, cfg,
		map[string]int{parent: 1400, sub50: 1300, sub80: 1400},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{parent, sub50, sub80},
		})
	d.run()

	if got := d.records(); len(got) != 0 {
		t.Fatalf("records = %+v, want none on a converged apply", got)
	}
	if got := d.writes[parent]; got != 0 {
		t.Fatalf("converged parent drew %d writes, want 0", got)
	}
}

// A nil link with a nil lookup error records lookup-failed instead of
// panicking or skipping silently. Unreachable via production lookups
// (they error rather than returning nil); reachable via a poisoned cache.
func TestPhysMTUNilLinkRecords9841(t *testing.T) {
	result := newValidationResult()
	attemptPhysMTU9841(result, physMTUAttempt9841{
		physName: "ge-0-0-9", configRef: "ge-0-0-9", ifindex: 4242, want: 1500,
	})
	recs := result.sortedMTUUnconverged()
	if len(recs) != 1 || recs[0].Grade != MTUGradeLookupFailed {
		t.Fatalf("records = %+v, want one lookup-failed", recs)
	}
}

// A refused lower with a live VLAN child above the want grades
// blocked-by-child-live and names the child; the parent sits at its old
// MTU. The sub-1400 child must already be converged so zone order cannot
// move the max between children.
func TestPhysLowerBlockedByLiveChild9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1500},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{parent, sub50, sub80},
			mtuErr: func(name string, _ int) error {
				if name == parent {
					return fmt.Errorf("device or resource busy")
				}
				return nil
			},
			byIndex: func(idx int) (netlink.Link, error) { return deviceLink9841(d.h, parent), nil },
			linkList: func() ([]netlink.Link, error) {
				return []netlink.Link{
					vlanLink9841(d.h, sub50, d.h.index[parent]),
					vlanLink9841(d.h, sub80, d.h.index[parent]),
				}, nil
			},
		})
	d.run()

	if got := d.h.mtu[parent]; got != 1500 {
		t.Fatalf("parent MTU = %d, want the old 1500", got)
	}
	r := findRecord9841(t, d.records(), parent)
	if r.Grade != MTUGradeBlockedByChildLive {
		t.Fatalf("record = %+v, want blocked-by-child-live", r)
	}
	if !strings.Contains(r.Detail, sub80) || !strings.Contains(r.Detail, "1500") {
		t.Errorf("detail %q must name the blocking child and its live MTU", r.Detail)
	}
}

// A LinkList failure on the grading path degrades to ungraded
// write-failed, never to a guessed attribution.
func TestPhysLowerListErrorDegrades9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1500},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{parent, sub50, sub80},
			mtuErr: func(name string, _ int) error {
				if name == parent {
					return fmt.Errorf("device or resource busy")
				}
				return nil
			},
			byIndex:  func(idx int) (netlink.Link, error) { return deviceLink9841(d.h, parent), nil },
			linkList: func() ([]netlink.Link, error) { return nil, fmt.Errorf("netlink dump failed") },
		})
	d.run()

	r := findRecord9841(t, d.records(), parent)
	if r.Grade != MTUGradeWriteFailed {
		t.Errorf("record = %+v, want ungraded write-failed when the child list is unreadable", r)
	}
}

// The raise-both shape: unit 9000 refused while the parent sits at 1500
// with a 9000 plan grades parent-write-pending. The parent's own write is
// failed too, so grading observes 1500 deterministically regardless of
// zone order.
func TestChildMTURaiseGradesParentPending9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	cfg.Interfaces.Interfaces[taggedParent9761].MTU = 9000
	cfg.Interfaces.Interfaces[taggedParent9761].Units[80].MTU = 9000
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1500},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{parent, sub50, sub80},
			mtuErr: func(name string, _ int) error {
				if name == parent || name == sub80 {
					return fmt.Errorf("invalid argument")
				}
				return nil
			},
			byName: func(name string) (netlink.Link, error) {
				if name == sub80 {
					return vlanLink9841(d.h, sub80, d.h.index[parent]), nil
				}
				return deviceLink9841(d.h, name), nil
			},
			byIndex:  func(idx int) (netlink.Link, error) { return deviceLink9841(d.h, parent), nil },
			linkList: func() ([]netlink.Link, error) { return nil, nil },
		})
	d.run()

	if got := d.h.mtu[sub80]; got != 1500 {
		t.Fatalf("child MTU = %d, want the old 1500", got)
	}
	r := findRecord9841(t, d.records(), sub80)
	if r.WantMTU != 9000 || r.LiveMTU != 1500 || r.Grade != MTUGradeParentWritePending {
		t.Errorf("record = %+v, want {want 9000, live 1500, parent-write-pending}", r)
	}
	if r.ConfigRef != parent+".80" {
		t.Errorf("configRef = %q, want the authored unit reference", r.ConfigRef)
	}
	if pr := findRecord9841(t, d.records(), parent); pr.Grade != MTUGradeWriteFailed {
		t.Errorf("parent record = %+v, want write-failed alongside", pr)
	}
}

// A unit want above the parent's plan grades config-impossible: no
// sequence of applies converges it.
func TestChildMTUAbovePlanGradesImpossible9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	cfg.Interfaces.Interfaces[taggedParent9761].Units[80].MTU = 9000
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1500},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{parent, sub50, sub80},
			mtuErr: func(name string, _ int) error {
				if name == sub80 {
					return fmt.Errorf("invalid argument")
				}
				return nil
			},
			byName: func(name string) (netlink.Link, error) {
				if name == sub80 {
					return vlanLink9841(d.h, sub80, d.h.index[parent]), nil
				}
				return deviceLink9841(d.h, name), nil
			},
		})
	d.run()

	r := findRecord9841(t, d.records(), sub80)
	if r.Grade != MTUGradeConfigImpossible {
		t.Errorf("record = %+v, want config-impossible for a want above the parent plan", r)
	}
	if !strings.Contains(r.Detail, "1400") {
		t.Errorf("detail %q must name the parent plan it exceeds", r.Detail)
	}
}

// A unit want above the parent's live MTU with no parent plan at all is
// likewise impossible: nothing will ever raise the parent.
func TestChildMTUAboveLiveWithoutPlanGradesImpossible9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	cfg.Interfaces.Interfaces[taggedParent9761].MTU = 0
	cfg.Interfaces.Interfaces[taggedParent9761].Units[80].MTU = 9000
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1500},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{parent, sub50, sub80},
			mtuErr: func(name string, _ int) error {
				if name == sub80 {
					return fmt.Errorf("invalid argument")
				}
				return nil
			},
			byName: func(name string) (netlink.Link, error) {
				if name == sub80 {
					return vlanLink9841(d.h, sub80, d.h.index[parent]), nil
				}
				return deviceLink9841(d.h, name), nil
			},
		})
	d.run()

	recs := d.records()
	if len(recs) != 1 {
		t.Fatalf("records = %+v, want only the child's (no parent plan, no parent attempt)", recs)
	}
	if recs[0].Grade != MTUGradeConfigImpossible {
		t.Errorf("record = %+v, want config-impossible", recs[0])
	}
	if !strings.Contains(recs[0].Detail, "no parent MTU is planned") {
		t.Errorf("detail %q must say no parent MTU is planned", recs[0].Detail)
	}
}

// A refused want that fits the parent's live MTU grades plain
// write-failed: driver, permissions, or anything but ordering/config.
func TestChildMTUFittingRefusalGradesWriteFailed9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1500, sub80: 1500},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{parent, sub50, sub80},
			mtuErr: func(name string, _ int) error {
				if name == sub50 {
					return fmt.Errorf("operation not supported")
				}
				return nil
			},
			byName: func(name string) (netlink.Link, error) {
				if !strings.Contains(name, ".") {
					return deviceLink9841(d.h, name), nil
				}
				return vlanLink9841(d.h, name, d.h.index[parent]), nil
			},
		})
	d.run()

	if got := d.h.mtu[sub50]; got != 1500 {
		t.Fatalf("child MTU = %d, want the old 1500", got)
	}
	r := findRecord9841(t, d.records(), sub50)
	if r.WantMTU != 1300 || r.LiveMTU != 1500 || r.Grade != MTUGradeWriteFailed {
		t.Errorf("record = %+v, want {want 1300, live 1500, write-failed}", r)
	}
}

// A child lookup failure on both attempts records lookup-failed with the
// RESOLVED reset want: the parent read fine, only the child is missing.
func TestChildMTULookupFailureRecords9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	d := setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1500},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50},
			seedIdx:   []string{parent, sub50, sub80},
			byName: func(name string) (netlink.Link, error) {
				return nil, fmt.Errorf("no such device")
			},
		})
	d.run()

	if got := d.h.mtu[sub80]; got != 1500 {
		t.Fatalf("child MTU = %d, want the old 1500: no write without a resolved link", got)
	}
	if got := d.writes[sub80]; got != 0 {
		t.Fatalf("child drew %d writes without a resolved link, want 0", got)
	}
	r := findRecord9841(t, d.records(), sub80)
	if r.WantMTU != 1500 || r.LiveMTU != mtuUnknown9841 || r.Grade != MTUGradeLookupFailed {
		t.Errorf("record = %+v, want {want 1500 (reset target), live unknown, lookup-failed}", r)
	}
}

// A transient child-lookup failure healed by the retry resets and stays
// silent.
func TestChildMTURetrySuccessResets9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	calls := 0
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1400},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50},
			seedIdx:   []string{parent, sub50, sub80},
			byName: func(name string) (netlink.Link, error) {
				if name != sub80 {
					return nil, fmt.Errorf("no such device")
				}
				calls++
				if calls == 1 {
					return nil, fmt.Errorf("simulated transient RTM failure")
				}
				return vlanLink9841(d.h, sub80, d.h.index[parent]), nil
			},
		})
	d.run()

	if got := d.h.mtu[sub80]; got != 1500 {
		t.Fatalf("child MTU = %d, want the reset 1500: the retry must repair a transient failure", got)
	}
	if got := d.records(); len(got) != 0 {
		t.Fatalf("records = %+v, want none: a healed lookup warns about nothing", got)
	}
}

// No MTU statement plus an unreadable parent records
// reset-target-unresolved with an UNKNOWN want: the required #9757 reset
// cannot be aimed, and silence would reinstate the stale-device harm with
// no trace. The parent is unseeded by name but seeded by index, so its own
// write proceeds and this cell isolates the child's record.
func TestChildMTUResetTargetUnresolvedRecords9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1400},
		mtuDriveOpts9841{
			seedCache: []string{sub50, sub80},
			seedIdx:   []string{parent, sub50, sub80},
			byName: func(name string) (netlink.Link, error) {
				if name == sub80 {
					return vlanLink9841(d.h, sub80, d.h.index[parent]), nil
				}
				return nil, fmt.Errorf("no such device")
			},
		})
	d.run()

	if got := d.h.mtu[sub80]; got != 1400 {
		t.Fatalf("child MTU = %d, want the stale 1400: an unresolvable reset must not invent a target", got)
	}
	recs := d.records()
	if len(recs) != 1 {
		t.Fatalf("records = %+v, want only the reset-target record", recs)
	}
	r := recs[0]
	if r.Name != sub80 || r.WantMTU != mtuUnknown9841 || r.LiveMTU != 1400 || r.Grade != MTUGradeResetTargetUnresolved {
		t.Errorf("record = %+v, want {child, want unknown, live 1400, reset-target-unresolved}", r)
	}
	if !strings.Contains(r.Detail, parent) {
		t.Errorf("detail %q must name the unreadable parent", r.Detail)
	}
}

// The same child referenced by two zones, failing once then succeeding,
// ends the apply with NO record: the success clears the pending failure.
// Zone order is randomized; the fail-first script keys on attempt count,
// so this holds under both orders.
func TestChildMTUFailureThenSuccessClears9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	cfg.Security.Zones["dmz"] = &config.ZoneConfig{Name: "dmz", Interfaces: []string{taggedParent9761 + ".80"}}
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	attempts := 0
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1300},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{parent, sub50, sub80},
			mtuErr: func(name string, _ int) error {
				if name == sub80 {
					attempts++
					if attempts == 1 {
						return fmt.Errorf("simulated first-attempt refusal")
					}
				}
				return nil
			},
			byName: func(name string) (netlink.Link, error) {
				if !strings.Contains(name, ".") {
					return deviceLink9841(d.h, name), nil
				}
				return vlanLink9841(d.h, name, d.h.index[parent]), nil
			},
		})
	d.run()

	if attempts != 2 {
		t.Fatalf("child attempts = %d, want 2 (fail once, then succeed)", attempts)
	}
	if got := d.h.mtu[sub80]; got == 1300 {
		t.Fatalf("child MTU still at the stale 1300: the second attempt must have landed")
	}
	if got := d.records(); len(got) != 0 {
		t.Fatalf("records = %+v, want none: the success must clear the pending failure", got)
	}
}

// A repeat attempt that fails its syscall against a just-converged device
// clears the earlier record: the first attempt recorded divergence, a
// concurrent writer converged the device, and the second attempt's fresh
// observation proves it. Without the clear the stale record publishes.
// (Same-composite-key repeats reach here when two zones name one ref.)
func TestChildMTUFailedRepeatConvergedClears9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	cfg.Security.Zones["dmz"] = &config.ZoneConfig{Name: "dmz", Interfaces: []string{taggedParent9761 + ".80"}}
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	attempts := 0
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1300},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{parent, sub50, sub80},
			mtuErr: func(name string, want int) error {
				if name == sub80 {
					attempts++
					if attempts == 2 {
						// A concurrent writer wins between our write and
						// our fresh-verification: the device now sits at
						// this attempt's want. (The want itself is
						// order-dependent — the reset target tracks the
						// parent's live MTU, which the per-phys setup
						// lowers mid-apply — so converge to the passed
						// want rather than a literal.)
						d.h.mtu[sub80] = want
					}
					return fmt.Errorf("simulated refusal (attempt %d)", attempts)
				}
				return nil
			},
			byName: func(name string) (netlink.Link, error) {
				if !strings.Contains(name, ".") {
					return deviceLink9841(d.h, name), nil
				}
				return vlanLink9841(d.h, name, d.h.index[parent]), nil
			},
		})
	d.run()

	if attempts != 2 {
		t.Fatalf("child attempts = %d, want 2 (fail divergent, then fail converged)", attempts)
	}
	if got := d.records(); len(got) != 0 {
		t.Fatalf("records = %+v, want none: fresh-verified convergence must clear the pending failure", got)
	}
}

// The physical converged arm clears too: a pending record for the key plus
// a fresh observation at want leaves nothing behind.
func TestPhysMTUConvergedRepeatClearsStaleRecord9841(t *testing.T) {
	orig := linkByIndexSeam
	t.Cleanup(func() { linkByIndexSeam = orig })
	linkByIndexSeam = func(idx int) (netlink.Link, error) {
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-2", Index: idx, MTU: 1400}}, nil
	}
	r := newValidationResult()
	r.recordMTUUnconverged(MTUUnconverged{Name: "ge-0-0-2", ConfigRef: "ge-0/0/2",
		WantMTU: 1400, LiveMTU: 1500, Grade: MTUGradeWriteFailed})
	recordPhysMTUWriteFailure9841(r,
		physMTUAttempt9841{physName: "ge-0-0-2", configRef: "ge-0/0/2", ifindex: 4212, want: 1400},
		fmt.Errorf("simulated refusal against a converged device"))
	if got := r.sortedMTUUnconverged(); len(got) != 0 {
		t.Fatalf("records = %+v, want none: fresh-verified convergence must clear", got)
	}
}

// An UNVERIFIED cached-equality skip keeps its pending record: only fresh
// proof clears. Under #8119 the cached hit can predate a write this same
// apply already failed, so clearing here would drop a true divergence.
func TestPhysMTUCachedSkipKeepsPendingRecord9841(t *testing.T) {
	r := newValidationResult()
	r.recordMTUUnconverged(MTUUnconverged{Name: "ge-0-0-2", ConfigRef: "ge-0/0/2",
		WantMTU: 1400, LiveMTU: 1500, Grade: MTUGradeWriteFailed})
	attemptPhysMTU9841(r, physMTUAttempt9841{
		physName: "ge-0-0-2", configRef: "ge-0/0/2", ifindex: 4212, want: 1400,
		link: &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-2", Index: 4212, MTU: 1400}},
	})
	if got := r.sortedMTUUnconverged(); len(got) != 1 {
		t.Fatalf("records = %+v, want the pending record kept across an unverified skip", got)
	}
}

// A write refused against a STALE cached link, where the host is already
// converged, records nothing: fresh-verification suppresses the false
// failure and the journal keeps the syscall error.
func TestChildMTUStaleCacheErrorSuppressedWhenConverged9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1500, sub80: 1500},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{parent, sub50, sub80},
			mtuErr: func(name string, _ int) error {
				if name == sub50 {
					return fmt.Errorf("simulated refusal against a converged host")
				}
				return nil
			},
			byName: func(name string) (netlink.Link, error) {
				if !strings.Contains(name, ".") {
					return deviceLink9841(d.h, name), nil
				}
				return vlanLink9841(d.h, name, d.h.index[parent]), nil
			},
		})
	// Converge the host behind the cache's back before the apply runs.
	d.h.mtu[sub50] = 1300
	d.run()

	if got := d.writes[sub50]; got != 1 {
		t.Fatalf("child attempts = %d, want 1: the stale cache must still drive an attempt", got)
	}
	if got := d.records(); len(got) != 0 {
		t.Fatalf("records = %+v, want none: fresh-verification must suppress a stale-cache failure against a converged host", got)
	}
}

// Each retry-identity branch kills its own mutant: a same-named stranger
// with the wrong ifindex, wrong parent, or wrong kind is refused — no
// write, no cache pollution, and a lookup-failed record. One table row per
// branch of misidentifiedLink9841, distinguished by the detail it pins.
func TestChildRetryRejectsSquatterIdentities9841(t *testing.T) {
	parent, sub80 := taggedParent9761, taggedParent9761+".80"
	for _, tc := range []struct {
		name      string
		link      func(h *fakeHost8119) netlink.Link
		wantGlass string
	}{
		{"wrong ifindex",
			func(h *fakeHost8119) netlink.Link {
				return &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: sub80, Index: 9999, MTU: 1500, ParentIndex: h.index[parent]}}
			}, "ifindex"},
		{"wrong parent",
			func(h *fakeHost8119) netlink.Link {
				return &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: sub80, Index: h.index[sub80], MTU: 1500, ParentIndex: 7777}}
			}, "parent"},
		{"wrong kind",
			func(h *fakeHost8119) netlink.Link {
				return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: sub80, Index: h.index[sub80], MTU: 1500, ParentIndex: h.index[parent]}}
			}, "kind"},
		{"wrong name",
			func(h *fakeHost8119) netlink.Link {
				return &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: "wrong-name-squatter", Index: h.index[sub80], MTU: 1500, ParentIndex: h.index[parent]}}
			}, "name"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := taggedOnlyConfig9761()
			sub50 := taggedParent9761 + ".50"
			var d *mtuDrive9841
			calls := 0
			d = setupMTUApply9841(t, cfg,
				map[string]int{parent: 1500, sub50: 1300, sub80: 1400},
				mtuDriveOpts9841{
					seedCache: []string{parent, sub50},
					seedIdx:   []string{parent, sub50},
					byName: func(name string) (netlink.Link, error) {
						if name != sub80 {
							return nil, fmt.Errorf("no such device")
						}
						calls++
						if calls == 1 {
							return nil, fmt.Errorf("simulated transient RTM failure")
						}
						return tc.link(d.h), nil
					},
				})
			d.run()

			if got := d.h.mtu[sub80]; got != 1400 {
				t.Fatalf("child MTU = %d, want the old 1400: no write may reach a misidentified device", got)
			}
			if got := d.writes[sub80]; got != 0 {
				t.Fatalf("child drew %d writes to a misidentified device, want 0", got)
			}
			r := findRecord9841(t, d.records(), sub80)
			if r.Grade != MTUGradeLookupFailed {
				t.Errorf("record = %+v, want lookup-failed for a refused retry identity", r)
			}
			if !strings.Contains(r.Detail, tc.wantGlass) {
				t.Errorf("detail %q must name the mismatching identity attribute (%s)", r.Detail, tc.wantGlass)
			}
			if _, ok := d.result.linkCache[sub80]; ok {
				t.Errorf("the stranger was memoized into linkCache; a refused retry must not pollute the caches")
			}
			if _, ok := d.result.linkIdxMap[d.h.index[sub80]]; ok {
				t.Errorf("the stranger was memoized into linkIdxMap; a refused retry must not pollute the caches")
			}
		})
	}
}

// After a wrong-named stranger is refused, the requested key holds nothing:
// a later cached lookup re-fetches instead of trusting the stranger with no
// validation. (Evicting attrs.Name instead of the requested name leaves the
// stranger cached here and this returns the wrong device.)
func TestRetryByNameEvictsWrongNamedStranger9841(t *testing.T) {
	orig := linkByNameSeam
	t.Cleanup(func() { linkByNameSeam = orig })
	stranger := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "wrong-name-squatter", Index: 4242, MTU: 1500}}
	good := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-9", Index: 4242, MTU: 1500}}
	calls := 0
	linkByNameSeam = func(string) (netlink.Link, error) {
		calls++
		if calls == 1 {
			return stranger, nil
		}
		return good, nil
	}
	r := newValidationResult()
	if _, err := r.retryLinkByName9841("ge-0-0-9", 4242, 0, false); err == nil {
		t.Fatalf("retry accepted a wrong-named stranger")
	}
	if _, ok := r.linkCache["ge-0-0-9"]; ok {
		t.Fatalf("stranger cached under the requested name; the next cached lookup would trust it")
	}
	got, err := r.cachedLinkByName("ge-0-0-9")
	if err != nil {
		t.Fatalf("subsequent cached lookup: %v", err)
	}
	if got.Attrs().Name != "ge-0-0-9" {
		t.Fatalf("subsequent cached lookup returned %q, want the re-fetched device", got.Attrs().Name)
	}
}

// A by-index retry hit naming a different device is refused and evicted:
// no write, no pollution, lookup-failed recorded.
func TestPhysRetryRejectsRenamedDevice9841(t *testing.T) {
	cfg := taggedOnlyConfig9761()
	parent, sub50, sub80 := taggedParent9761, taggedParent9761+".50", taggedParent9761+".80"
	var d *mtuDrive9841
	calls := 0
	d = setupMTUApply9841(t, cfg,
		map[string]int{parent: 1500, sub50: 1300, sub80: 1500},
		mtuDriveOpts9841{
			seedCache: []string{parent, sub50, sub80},
			seedIdx:   []string{sub50, sub80},
			byIndex: func(idx int) (netlink.Link, error) {
				calls++
				if calls == 1 {
					return nil, fmt.Errorf("simulated transient RTM failure")
				}
				if calls == 2 {
					// The retry hit only: a same-index stranger. Later
					// phases must miss (errors memoize nothing), so the end
					// state proves the retry evicted rather than kept it.
					return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "renamed-squatter", Index: idx, MTU: 1500}}, nil
				}
				return nil, fmt.Errorf("no such device")
			},
		})
	d.run()

	if got := d.h.mtu[parent]; got != 1500 {
		t.Fatalf("parent MTU = %d, want the old 1500", got)
	}
	r := findRecord9841(t, d.records(), parent)
	if r.Grade != MTUGradeLookupFailed || !strings.Contains(r.Detail, "renamed-squatter") {
		t.Errorf("record = %+v, want lookup-failed naming the stranger", r)
	}
	if _, ok := d.result.linkIdxMap[d.h.index[parent]]; ok {
		t.Errorf("the stranger was memoized into linkIdxMap; a refused retry must not pollute the caches")
	}
	if _, ok := d.result.linkCache["renamed-squatter"]; ok {
		t.Errorf("the stranger was memoized into linkCache; a refused retry must not pollute the caches")
	}
}

// Two references resolving to one kernel child with different wants keep
// BOTH records: keying by Name alone would let the second attempt drop
// the first.
func TestDualRefSameChildKeepsBothRecords9841(t *testing.T) {
	cfg := &config.Config{}
	cfg.Chassis.Cluster = &config.ClusterConfig{NodeID: 0}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust":   {Name: "trust", Interfaces: []string{"reth0.80"}},
		"untrust": {Name: "untrust", Interfaces: []string{"ge-0/0/2.80"}},
	}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {
			Name: "reth0", RedundancyGroup: 1, VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{80: {Number: 80, VlanID: 80, MTU: 9000}},
		},
		"ge-0/0/2": {
			Name: "ge-0/0/2", RedundantParent: "reth0", VlanTagging: true,
			Units: map[int]*config.InterfaceUnit{80: {Number: 80, VlanID: 80, MTU: 1500}},
		},
	}
	phys, _, _, _ := resolveInterfaceRef("reth0.80", cfg)
	phys2, _, _, _ := resolveInterfaceRef("ge-0/0/2.80", cfg)
	if phys == "" || phys != phys2 {
		t.Fatalf("premise: both refs must resolve to one member, got %q and %q", phys, phys2)
	}
	sub80 := phys + ".80"
	var d *mtuDrive9841
	d = setupMTUApply9841(t, cfg,
		map[string]int{phys: 1500, sub80: 1400},
		mtuDriveOpts9841{
			seedCache: []string{phys, sub80},
			seedIdx:   []string{phys, sub80},
			mtuErr: func(name string, _ int) error {
				if name == sub80 {
					return fmt.Errorf("invalid argument")
				}
				return nil
			},
			byName: func(name string) (netlink.Link, error) {
				if name == sub80 {
					return vlanLink9841(d.h, sub80, d.h.index[phys]), nil
				}
				return deviceLink9841(d.h, name), nil
			},
		})
	d.run()

	if got := d.h.mtu[sub80]; got != 1400 {
		t.Fatalf("child MTU = %d, want the old 1400", got)
	}
	if got := d.writes[sub80]; got != 2 {
		t.Fatalf("child attempts = %d, want 2 (one per reference)", got)
	}
	recs := d.records()
	if len(recs) != 2 {
		t.Fatalf("records = %+v, want one per reference (composite key)", recs)
	}
	wants := map[string]int{}
	for _, r := range recs {
		if r.Name != sub80 {
			t.Errorf("record names %q, want the shared child %q", r.Name, sub80)
		}
		wants[r.ConfigRef] = r.WantMTU
	}
	if wants["reth0.80"] != 9000 || wants["ge-0/0/2.80"] != 1500 {
		t.Errorf("per-ref wants = %v, want {reth0.80: 9000, ge-0/0/2.80: 1500}", wants)
	}
}

// The record's ConfigRef is the AUTHORED zone reference verbatim: an
// aliased spelling ("reth0.080") survives onto the record rather than
// being rebuilt from the parsed unit number ("reth0.80"), which would hide
// it from its own show row (exact ConfigRef match) and its own filter
// (leftover prefixes).
func TestChildMTURecordPreservesAuthoredRef9841(t *testing.T) {
	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"reth0": {Name: "reth0", VlanTagging: true, Units: map[int]*config.InterfaceUnit{
			80: {Number: 80, VlanID: 80, MTU: 9000},
		}},
	}
	base := linkSetMTUSeam
	t.Cleanup(func() { linkSetMTUSeam = base })
	linkSetMTUSeam = func(netlink.Link, int) error { return fmt.Errorf("operation not supported") }
	origName := linkByNameSeam
	t.Cleanup(func() { linkByNameSeam = origName })
	linkByNameSeam = func(string) (netlink.Link, error) { return nil, fmt.Errorf("no such device") }

	sub := "ge-0-0-2.80"
	r := newValidationResult()
	r.linkCache[sub] = &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: sub, Index: 4214, MTU: 1500, ParentIndex: 4212}}
	applyVLANSubInterfaceMTU9757(cfg, r, "reth0.080", "reth0", 80, "ge-0-0-2", sub,
		vlanMTUContext9841{parentWant: 9000, parentIfindex: 4212, subIfindex: 4214})
	recs := r.sortedMTUUnconverged()
	if len(recs) != 1 {
		t.Fatalf("records = %+v, want exactly one", recs)
	}
	if recs[0].ConfigRef != "reth0.080" {
		t.Fatalf("ConfigRef = %q, want the authored %q", recs[0].ConfigRef, "reth0.080")
	}
	if recs[0].Name != sub || recs[0].WantMTU != 9000 {
		t.Fatalf("record = %+v, want the member child at want 9000", recs[0])
	}
}

// The grading boundary table: every row pins one arm of
// gradeChildMTUFailure9841, including the equalities.
func TestGradeChildMTUFailureBoundaries9841(t *testing.T) {
	for _, tc := range []struct {
		name             string
		want, live, plan int
		liveOK           bool
		grade            MTUUnconvergedGrade
	}{
		{"fits live and plan", 1300, 1500, 1400, true, MTUGradeWriteFailed},
		{"equal to live but above plan is impossible", 1500, 1500, 1400, true, MTUGradeConfigImpossible},
		{"order transient", 9000, 1500, 9000, true, MTUGradeParentWritePending},
		{"equal to plan is pending not impossible", 9000, 1500, 9000, true, MTUGradeParentWritePending},
		{"above plan is impossible", 9000, 1500, 1400, true, MTUGradeConfigImpossible},
		{"above live without a plan is impossible", 9000, 1500, 0, true, MTUGradeConfigImpossible},
		{"unreadable parent with impossible plan", 9000, 0, 1400, false, MTUGradeConfigImpossible},
		{"unreadable parent without a verdict degrades", 9000, 0, 0, false, MTUGradeWriteFailed},
		{"unreadable parent with fitting plan degrades", 1300, 0, 1400, false, MTUGradeWriteFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := gradeChildMTUFailure9841(tc.want, tc.live, tc.plan, tc.liveOK); got != tc.grade {
				t.Errorf("grade(%d, live %d ok=%v, plan %d) = %q, want %q",
					tc.want, tc.live, tc.liveOK, tc.plan, got, tc.grade)
			}
		})
	}
}

// Record upsert (same key replaces), clear (by composite key), and sorted
// publication order.
func TestRecordClearSortedSemantics9841(t *testing.T) {
	r := newValidationResult()
	r.recordMTUUnconverged(MTUUnconverged{Name: "b", ConfigRef: "b", WantMTU: 1})
	r.recordMTUUnconverged(MTUUnconverged{Name: "a", ConfigRef: "a", WantMTU: 1})
	r.recordMTUUnconverged(MTUUnconverged{Name: "b", ConfigRef: "b", WantMTU: 2})
	r.recordMTUUnconverged(MTUUnconverged{Name: "b", ConfigRef: "b2", WantMTU: 3})
	if len(r.mtuUnconverged) != 3 {
		t.Fatalf("records = %+v, want 3 (same-key upsert, distinct keys coexist)", r.mtuUnconverged)
	}
	r.clearMTUUnconverged("b", "b")
	got := r.sortedMTUUnconverged()
	if len(got) != 2 || got[0].Name != "a" || got[1].ConfigRef != "b2" {
		t.Fatalf("after clear+sort = %+v, want [a, b/b2] in key order", got)
	}
	// Clearing an absent key is a no-op, and nil receivers are safe.
	r.clearMTUUnconverged("missing", "missing")
	var nilResult *CompileResult
	nilResult.recordMTUUnconverged(MTUUnconverged{})
	nilResult.clearMTUUnconverged("x", "x")
	if nilResult.sortedMTUUnconverged() != nil {
		t.Fatalf("nil result must sort to nil")
	}
}

// ApplyResultFromCompileResult carries the records sorted.
func TestApplyResultCarriesUnconvergedMTUs9841(t *testing.T) {
	r := newValidationResult()
	r.recordMTUUnconverged(MTUUnconverged{Name: "z", ConfigRef: "z", WantMTU: 1, Grade: MTUGradeWriteFailed})
	r.recordMTUUnconverged(MTUUnconverged{Name: "a", ConfigRef: "a", WantMTU: 2, Grade: MTUGradeLookupFailed})
	got := ApplyResultFromCompileResult(r)
	if got == nil || len(got.UnconvergedMTUs) != 2 {
		t.Fatalf("carried = %+v, want both records", got)
	}
	if got.UnconvergedMTUs[0].Name != "a" || got.UnconvergedMTUs[1].Name != "z" {
		t.Fatalf("carried order = %+v, want sorted by Name", got.UnconvergedMTUs)
	}
	if got.UnconvergedMTUs[1].Grade != MTUGradeWriteFailed {
		t.Fatalf("grade did not survive the carry: %+v", got.UnconvergedMTUs[1])
	}
}

// From and Clone isolate storage: later tracker appends and holder
// mutations cannot cross-contaminate published metadata.
func TestApplyResultCloneIsolatesUnconvergedMTUs9841(t *testing.T) {
	r := newValidationResult()
	r.recordMTUUnconverged(MTUUnconverged{Name: "a", ConfigRef: "a", WantMTU: 1})
	published := ApplyResultFromCompileResult(r)
	r.recordMTUUnconverged(MTUUnconverged{Name: "b", ConfigRef: "b", WantMTU: 2})
	if len(published.UnconvergedMTUs) != 1 {
		t.Fatalf("published grew after a later tracker append: %+v", published.UnconvergedMTUs)
	}
	clone := published.Clone()
	clone.UnconvergedMTUs[0].WantMTU = 999
	clone.UnconvergedMTUs = append(clone.UnconvergedMTUs, MTUUnconverged{Name: "c"})
	if published.UnconvergedMTUs[0].WantMTU != 1 || len(published.UnconvergedMTUs) != 1 {
		t.Fatalf("clone mutation leaked into the published result: %+v", published.UnconvergedMTUs)
	}
	if ApplyResultFromCompileResult(nil) != nil || (*ApplyResult)(nil).Clone() != nil {
		t.Fatalf("nil inputs must map to nil outputs")
	}
}

// The producer contract behind the daemon's generation guard: every
// recorded apply advances the observed generation, on the real publisher
// rather than a test fake.
func TestRecordApplyResultAdvancesGeneration9841(t *testing.T) {
	m := New()
	first := m.recordApplyResult(&ApplyResult{})
	second := m.recordApplyResult(&ApplyResult{})
	if first == nil || second == nil {
		t.Fatalf("recordApplyResult returned nil")
	}
	if second.Generation <= first.Generation {
		t.Fatalf("generations %d then %d: every recorded apply must advance", first.Generation, second.Generation)
	}
	if got := m.LastApplyResult(); got.Generation != second.Generation {
		t.Fatalf("LastApplyResult generation = %d, want the latest %d", got.Generation, second.Generation)
	}
}

// Warning rendering: authored ref first, kernel netdev parenthesized only
// when it differs, unknowns spelled out, grade bracketed, detail suffixed.
func TestMTUUnconvergedWarningFormat9841(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  MTUUnconverged
		want string
	}{
		{"full",
			MTUUnconverged{Name: "ge-0-0-2.80", ConfigRef: "reth0.80",
				WantMTU: 9000, LiveMTU: 1500, Grade: MTUGradeParentWritePending, Detail: "unit MTU 9000 exceeds parent's live MTU 1500 (parent plans 9000)"},
			"interface MTU not realized: reth0.80 (netdev ge-0-0-2.80) want 9000 live 1500 [parent-write-pending]: unit MTU 9000 exceeds parent's live MTU 1500 (parent plans 9000) (#9841)"},
		{"same name omits netdev",
			MTUUnconverged{Name: "ge-0-0-2", ConfigRef: "ge-0-0-2",
				WantMTU: 1400, LiveMTU: 1500, Grade: MTUGradeWriteFailed, Detail: "LinkSetMTU refused: boom"},
			"interface MTU not realized: ge-0-0-2 want 1400 live 1500 [write-failed]: LinkSetMTU refused: boom (#9841)"},
		{"unknown live",
			MTUUnconverged{Name: "ge-0-0-2", ConfigRef: "ge-0-0-2",
				WantMTU: 1400, LiveMTU: mtuUnknown9841, Grade: MTUGradeLookupFailed, Detail: "link lookup failed"},
			"interface MTU not realized: ge-0-0-2 want 1400 live unknown [lookup-failed]: link lookup failed (#9841)"},
		{"unknown want",
			MTUUnconverged{Name: "ge-0-0-2.80", ConfigRef: "ge-0-0-2.80",
				WantMTU: mtuUnknown9841, LiveMTU: 1400, Grade: MTUGradeResetTargetUnresolved, Detail: "no MTU statement"},
			"interface MTU not realized: ge-0-0-2.80 want unknown live 1400 [reset-target-unresolved]: no MTU statement (#9841)"},
		{"empty detail omits colon",
			MTUUnconverged{Name: "ge-0-0-2", ConfigRef: "ge-0-0-2",
				WantMTU: 1400, LiveMTU: 1500, Grade: MTUGradeWriteFailed},
			"interface MTU not realized: ge-0-0-2 want 1400 live 1500 [write-failed] (#9841)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rec.Warning(); got != tc.want {
				t.Errorf("warning:\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

// ShowAnnotation suppresses ONLY on fully verified convergence; every
// other outcome annotates, and unknowns never render as -1.
func TestMTUUnconvergedShowAnnotation9841(t *testing.T) {
	rec := MTUUnconverged{Name: "ge-0-0-2.80", ConfigRef: "reth0.80",
		WantMTU: 9000, LiveMTU: 1500, Grade: MTUGradeParentWritePending, Detail: "d"}
	if got := rec.ShowAnnotation(9000, true, true); got != "" {
		t.Errorf("verified convergence must suppress, got %q", got)
	}
	for _, tc := range []struct {
		name           string
		live           int
		found, identOK bool
		wantSubstrings []string
	}{
		{"still divergent", 1500, true, true, []string{"want 9000", "live 1500", "[parent-write-pending]", "d"}},
		{"lookup failed", 0, false, false, []string{"live unknown"}},
		{"identity mismatch at equal MTU", 9000, true, false, []string{"live 9000", "unverified"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := rec.ShowAnnotation(tc.live, tc.found, tc.identOK)
			if got == "" {
				t.Fatalf("must annotate, got empty")
			}
			for _, want := range tc.wantSubstrings {
				if !strings.Contains(got, want) {
					t.Errorf("annotation %q must contain %q", got, want)
				}
			}
			if strings.Contains(got, "-1") {
				t.Errorf("annotation %q leaked the -1 sentinel", got)
			}
		})
	}
	unknown := MTUUnconverged{Name: "x", ConfigRef: "x",
		WantMTU: mtuUnknown9841, LiveMTU: 1400, Grade: MTUGradeResetTargetUnresolved}
	if got := unknown.ShowAnnotation(1400, true, true); got == "" || strings.Contains(got, "-1") {
		t.Errorf("unknown want must annotate without -1, got %q", got)
	}
}

// Exact ConfigRef matches win exclusively; the kernel fallback applies
// only to rows with no exact match.
func TestMTUUnconvergedRowMatching9841(t *testing.T) {
	a := MTUUnconverged{Name: "ge-0-0-2.80", ConfigRef: "reth0.80"}
	b := MTUUnconverged{Name: "ge-0-0-2.80", ConfigRef: "ge-0/0/2.80"}
	recs := []MTUUnconverged{a, b}
	if got := MatchMTUUnconvergedRow(recs, "reth0.80", "ge-0-0-2.80"); len(got) != 1 || got[0].ConfigRef != "reth0.80" {
		t.Fatalf("exact row matched %+v, want only the exact record", got)
	}
	if got := MatchMTUUnconvergedRow(recs, "unrelated", "ge-0-0-2.80"); len(got) != 2 {
		t.Fatalf("fallback row matched %+v, want both records sharing the netdev", got)
	}
	if got := MatchMTUUnconvergedRow(recs, "unrelated", "other"); len(got) != 0 {
		t.Fatalf("unrelated row matched %+v, want none", got)
	}
	if got := MatchMTUUnconvergedRow(nil, "reth0.80", "ge-0-0-2.80"); len(got) != 0 {
		t.Fatalf("nil records matched %+v, want none", got)
	}
}

// Leftover visibility mirrors the row selector's prefix looseness on both
// identities — including its looseness (reth1 sees reth10), which is
// pinned here so the two cannot drift apart.
func TestMTUUnconvergedFilterVisibility9841(t *testing.T) {
	r := MTUUnconverged{Name: "ge-0-0-2.80", ConfigRef: "reth0.80"}
	for _, filter := range []string{"", "reth0", "reth0.80", "ge-0/0/2", "ge-0-0-2.80"} {
		if !r.VisibleUnderFilter(filter) {
			t.Errorf("filter %q must show %+v", filter, r)
		}
	}
	for _, filter := range []string{"ge-0/0/9", "reth1", "lo"} {
		if r.VisibleUnderFilter(filter) {
			t.Errorf("filter %q must hide %+v", filter, r)
		}
	}
	loose := MTUUnconverged{Name: "ge-0-0-9", ConfigRef: "reth10.80"}
	if !loose.VisibleUnderFilter("reth1") {
		t.Errorf("leftover visibility must mirror the row selector's prefix looseness (reth1/reth10)")
	}
}

// Strip-then-append: foreign lines survive in order, stale #9841 lines go,
// current records append sorted; a second sync is a fixed point.
func TestSyncMTUUnconvergedWarnings9841(t *testing.T) {
	cfg := &config.Config{Warnings: []string{
		"foreign advisory",
		"interface MTU not realized: stale line (#9841)",
		"another advisory",
	}}
	recs := []MTUUnconverged{
		{Name: "z", ConfigRef: "z", WantMTU: 1, LiveMTU: 2, Grade: MTUGradeWriteFailed},
		{Name: "a", ConfigRef: "a", WantMTU: 3, LiveMTU: 4, Grade: MTUGradeLookupFailed},
	}
	SyncMTUUnconvergedWarnings(cfg, recs)
	if len(cfg.Warnings) != 4 {
		t.Fatalf("warnings = %v, want 2 foreign + 2 current", cfg.Warnings)
	}
	if cfg.Warnings[0] != "foreign advisory" || cfg.Warnings[1] != "another advisory" {
		t.Fatalf("foreign lines moved: %v", cfg.Warnings)
	}
	if !strings.Contains(cfg.Warnings[2], ": a want") || !strings.Contains(cfg.Warnings[3], ": z want") {
		t.Fatalf("current lines unsorted: %v", cfg.Warnings)
	}
	again := slices.Clone(cfg.Warnings)
	SyncMTUUnconvergedWarnings(cfg, recs)
	if !slices.Equal(cfg.Warnings, again) {
		t.Fatalf("second sync moved: %v vs %v", cfg.Warnings, again)
	}
	SyncMTUUnconvergedWarnings(cfg, nil)
	if len(cfg.Warnings) != 2 {
		t.Fatalf("empty sync must strip to foreign only: %v", cfg.Warnings)
	}
	SyncMTUUnconvergedWarnings(nil, recs)
}

// The strip allocates fresh storage: a header captured before the sync
// still reads its original contents after it. An in-place (`w[:0]`)
// compaction would corrupt that in-flight reader's view.
func TestSyncMTUWarningsStripAllocatesFresh9841(t *testing.T) {
	cfg := &config.Config{Warnings: []string{
		"interface MTU not realized: old (#9841)",
		"foreign",
	}}
	before := cfg.Warnings
	SyncMTUUnconvergedWarnings(cfg, []MTUUnconverged{
		{Name: "a", ConfigRef: "a", WantMTU: 1, LiveMTU: 2, Grade: MTUGradeWriteFailed},
	})
	if len(before) != 2 || before[0] != "interface MTU not realized: old (#9841)" || before[1] != "foreign" {
		t.Fatalf("pre-sync header corrupted to %v: the strip must allocate fresh", before)
	}
}

// WithMTUWarningsForResponse9841 projects onto a response copy: the copy
// carries foreign lines plus the current records' lines sorted (stale
// #9841 lines stripped), the applied original keeps its input verbatim,
// and the two share no Warnings storage. Empty records (and nil input)
// return the input itself — pointer identity for the record-less
// majority, no copy.
func TestWithMTUWarningsForResponse9841(t *testing.T) {
	recs := []MTUUnconverged{
		{Name: "n-zzz", ConfigRef: "c-zzz", WantMTU: 1, LiveMTU: 2, Grade: MTUGradeWriteFailed},
		{Name: "n-aaa", ConfigRef: "c-aaa", WantMTU: 1, LiveMTU: 2, Grade: MTUGradeWriteFailed},
	}
	cfg := &config.Config{Warnings: []string{
		"foreign advisory",
		"interface MTU not realized: stale line (#9841)",
	}}
	resp := WithMTUWarningsForResponse9841(cfg, recs)
	if resp == cfg {
		t.Fatalf("response aliases the applied object: must project onto a copy")
	}
	if len(resp.Warnings) != 3 || resp.Warnings[0] != "foreign advisory" {
		t.Fatalf("response warnings = %v, want [foreign, 2 sorted mtu lines]", resp.Warnings)
	}
	if !strings.Contains(resp.Warnings[1], "c-aaa") || !strings.Contains(resp.Warnings[2], "c-zzz") {
		t.Fatalf("response warnings = %v, want the records' lines in (Name, ConfigRef) order", resp.Warnings)
	}
	if len(cfg.Warnings) != 2 || cfg.Warnings[1] != "interface MTU not realized: stale line (#9841)" {
		t.Fatalf("applied warnings = %v, want the input verbatim", cfg.Warnings)
	}
	resp.Warnings[0] = "mutated"
	if cfg.Warnings[0] != "foreign advisory" {
		t.Fatalf("writing the response corrupted the applied original: storage is shared")
	}

	if got := WithMTUWarningsForResponse9841(cfg, nil); got != cfg {
		t.Fatalf("empty records copied the config: want the input pointer itself")
	}
	var nilCfg *config.Config
	if got := WithMTUWarningsForResponse9841(nilCfg, recs); got != nil {
		t.Fatalf("nil input returned %v, want nil", got)
	}
}

// Identity verdicts: phys needs the ifindex; children additionally need
// the parent and the 802.1Q kind; nil and zero expectations never verify.
func TestMTUUnconvergedIdentityMatches9841(t *testing.T) {
	phys := MTUUnconverged{Name: "ge-0-0-2", ExpectIfindex: 10}
	dev10 := &netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 10, Name: "ge-0-0-2"}}
	if !phys.IdentityMatches(dev10) {
		t.Errorf("matching phys device must verify")
	}
	if phys.IdentityMatches(&netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 11, Name: "ge-0-0-2"}}) {
		t.Errorf("wrong-ifindex phys device must not verify")
	}
	if phys.IdentityMatches(nil) || (MTUUnconverged{}).IdentityMatches(dev10) {
		t.Errorf("nil link and zero expectation must not verify")
	}
	child := MTUUnconverged{Name: "ge-0-0-2.80", ExpectIfindex: 20, ExpectParentIfindex: 10}
	good := &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Index: 20, Name: "ge-0-0-2.80", ParentIndex: 10}}
	if !child.IdentityMatches(good) {
		t.Fatalf("matching VLAN child must verify")
	}
	bad := []netlink.Link{
		&netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Index: 21, Name: "ge-0-0-2.80", ParentIndex: 10}},
		&netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Index: 20, Name: "ge-0-0-2.80", ParentIndex: 11}},
		&netlink.Device{LinkAttrs: netlink.LinkAttrs{Index: 20, Name: "ge-0-0-2.80", ParentIndex: 10}},
	}
	for i, l := range bad {
		if child.IdentityMatches(l) {
			t.Errorf("child case %d must not verify", i)
		}
	}
}

// The record is Go-struct/display only: no json/proto tags, so text
// formatters stay the sole delivery and a future serialization cannot
// silently start carrying (and freezing) the shape.
func TestMTUUnconvergedHasNoSerializationTags9841(t *testing.T) {
	rt := reflect.TypeOf(MTUUnconverged{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if v := f.Tag.Get("json"); v != "" {
			t.Errorf("field %s carries json tag %q", f.Name, v)
		}
		if v := f.Tag.Get("protobuf"); v != "" {
			t.Errorf("field %s carries protobuf tag %q", f.Name, v)
		}
	}
}

// The arm-coverage proof ignores MTU convergence records: identical
// verdicts with and without them. MTU is host state, not arming.
func TestArmProofIgnoresMTUUnconverged9841(t *testing.T) {
	plain := newProofResult([]int{10})
	with := newProofResult([]int{10})
	with.mtuUnconverged = []MTUUnconverged{
		{Name: "ge-0-0-2", ConfigRef: "ge-0-0-2", WantMTU: 9000, LiveMTU: 1500, Grade: MTUGradeWriteFailed},
	}
	a := classifyArmCoverage(plain, lookupFrom(map[int]uint32{10: 7}, nil))
	b := classifyArmCoverage(with, lookupFrom(map[int]uint32{10: 7}, nil))
	if a.Uncovered != b.Uncovered || a.Skipped != b.Skipped || a.Delegated != b.Delegated ||
		a.Ran != b.Ran || a.WouldGate != b.WouldGate || len(a.Surfaces) != len(b.Surfaces) {
		t.Fatalf("verdict changed under MTU records: %+v vs %+v", a, b)
	}
}

// The shared fetch contract: successes memoize (one syscall per key),
// failures memoize nothing (every call re-hits the seam).
func TestFetchMemoizesByNameAndIndex9841(t *testing.T) {
	origName, origIndex := linkByNameSeam, linkByIndexSeam
	t.Cleanup(func() { linkByNameSeam, linkByIndexSeam = origName, origIndex })
	nameCalls, idxCalls := 0, 0
	linkByNameSeam = func(name string) (netlink.Link, error) {
		nameCalls++
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: name, Index: 4212, MTU: 1500}}, nil
	}
	linkByIndexSeam = func(idx int) (netlink.Link, error) {
		idxCalls++
		return &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: "ge-0-0-2", Index: idx, MTU: 1500}}, nil
	}
	r := newValidationResult()
	first, err := r.cachedLinkByName("ge-0-0-2")
	if err != nil {
		t.Fatalf("cachedLinkByName: %v", err)
	}
	if second, _ := r.cachedLinkByName("ge-0-0-2"); second != first || nameCalls != 1 {
		t.Fatalf("by-name success did not memoize (calls=%d)", nameCalls)
	}
	if viaIdx, _ := r.cachedLinkByIndex(4212); viaIdx != first || idxCalls != 0 {
		t.Fatalf("cross-key memoize broken (idx calls=%d): the by-name fetch must populate both maps", idxCalls)
	}

	linkByNameSeam = func(string) (netlink.Link, error) { return nil, fmt.Errorf("no such device") }
	linkByIndexSeam = func(int) (netlink.Link, error) { return nil, fmt.Errorf("no such device") }
	r2 := newValidationResult()
	if _, err := r2.cachedLinkByName("missing"); err == nil {
		t.Fatalf("expected an error")
	}
	if _, err := r2.cachedLinkByName("missing"); err == nil {
		t.Fatalf("expected an error")
	}
	if _, err := r2.cachedLinkByIndex(4242); err == nil {
		t.Fatalf("expected an error")
	}
	if _, err := r2.cachedLinkByIndex(4242); err == nil {
		t.Fatalf("expected an error")
	}
	if len(r2.linkCache) != 0 || len(r2.linkIdxMap) != 0 {
		t.Fatalf("failures memoized: cache=%v idxmap=%v", r2.linkCache, r2.linkIdxMap)
	}
}

// liveChildMTU9841 prefers a fresh validated read, falls back to the last
// cached observation, and reports unknown when neither resolves.
func TestLiveChildMTUReads9841(t *testing.T) {
	orig := linkByNameSeam
	t.Cleanup(func() { linkByNameSeam = orig })
	sub := "ge-0-0-2.80"
	ctx := vlanMTUContext9841{parentWant: 1400, parentIfindex: 4212, subIfindex: 4214}

	fresh := newValidationResult()
	linkByNameSeam = func(name string) (netlink.Link, error) {
		return &netlink.Vlan{LinkAttrs: netlink.LinkAttrs{Name: sub, Index: 4214, MTU: 1450, ParentIndex: 4212}}, nil
	}
	if got := liveChildMTU9841(fresh, sub, ctx); got != 1450 {
		t.Fatalf("fresh read = %d, want 1450", got)
	}

	linkByNameSeam = func(string) (netlink.Link, error) { return nil, fmt.Errorf("no such device") }
	cached := newValidationResult()
	cached.linkCache[sub] = &netlink.Device{LinkAttrs: netlink.LinkAttrs{Name: sub, Index: 4214, MTU: 1430}}
	if got := liveChildMTU9841(cached, sub, ctx); got != 1430 {
		t.Fatalf("cache fallback = %d, want the last observed 1430", got)
	}

	if got := liveChildMTU9841(newValidationResult(), sub, ctx); got != mtuUnknown9841 {
		t.Fatalf("unresolvable = %d, want unknown", got)
	}
}

// ObserveLive re-reads the record's own kernel netdev: the loopback is
// found with its real MTU and a verified identity, while a name that
// resolves nowhere reports not-found (the show annotation then renders
// live=unknown rather than suppressing a known-unconverged record).
func TestMTUUnconvergedObserveLive9841(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("net.InterfaceByName(%q) unavailable in this environment (%v)", "lo", err)
	}
	rec := MTUUnconverged{Name: "lo", ConfigRef: "lo",
		WantMTU: 1500, LiveMTU: 1500, Grade: MTUGradeWriteFailed, ExpectIfindex: lo.Index}
	live, found, identityOK := rec.ObserveLive()
	if !found || !identityOK {
		t.Fatalf("ObserveLive(lo) = (%d, %v, %v), want found+verified", live, found, identityOK)
	}
	if live != lo.MTU {
		t.Fatalf("ObserveLive(lo) live = %d, want the real %d", live, lo.MTU)
	}
	absent := MTUUnconverged{Name: "xpf-9841-absent0", ConfigRef: "xpf-9841-absent0",
		WantMTU: 1500, Grade: MTUGradeLookupFailed}
	if live, found, identityOK := absent.ObserveLive(); found || identityOK {
		t.Fatalf("ObserveLive(absent) = (%d, %v, %v), want not-found", live, found, identityOK)
	}
}

// AnnotateMTUUnconvergedRow matches exact-first with the kernel fallback,
// observes each match once, and consumes every match — including one that
// verifies converged and renders nothing, which still owns its record so
// the leftover section never reprints it.
func TestAnnotateMTUUnconvergedRow9841(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("net.InterfaceByName(%q) unavailable in this environment (%v)", "lo", err)
	}
	diverged := MTUUnconverged{Name: "lo", ConfigRef: "lo",
		WantMTU: lo.MTU + 1000, LiveMTU: lo.MTU, Grade: MTUGradeWriteFailed,
		ExpectIfindex: lo.Index, Detail: "refused"}
	converged := MTUUnconverged{Name: "lo", ConfigRef: "lo",
		WantMTU: lo.MTU, LiveMTU: 1500, Grade: MTUGradeWriteFailed, ExpectIfindex: lo.Index}
	foreign := MTUUnconverged{Name: "lo", ConfigRef: "other-ref",
		WantMTU: lo.MTU + 1000, LiveMTU: lo.MTU, Grade: MTUGradeWriteFailed, ExpectIfindex: lo.Index}

	lines, matched := AnnotateMTUUnconvergedRow([]MTUUnconverged{diverged, foreign}, "lo", "lo", "  ")
	if len(matched) != 1 || matched[0] != diverged.Key() {
		t.Fatalf("exact row consumed %v, want only the exact record", matched)
	}
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "  MTU unconverged: ") {
		t.Fatalf("exact row rendered %q, want one indented annotation", lines)
	}

	lines, matched = AnnotateMTUUnconvergedRow([]MTUUnconverged{foreign}, "unrelated", "lo", "    ")
	if len(matched) != 1 || len(lines) != 1 || !strings.HasPrefix(lines[0], "    ") {
		t.Fatalf("fallback row rendered %q consumed %v, want one indented annotation", lines, matched)
	}

	lines, matched = AnnotateMTUUnconvergedRow([]MTUUnconverged{converged}, "lo", "lo", "  ")
	if len(lines) != 0 {
		t.Fatalf("verified-converged row rendered %q, want suppression", lines)
	}
	if len(matched) != 1 || matched[0] != converged.Key() {
		t.Fatalf("verified-converged row consumed %v, want the suppressed record still consumed", matched)
	}

	if lines, matched := AnnotateMTUUnconvergedRow(nil, "lo", "lo", "  "); len(lines) != 0 || len(matched) != 0 {
		t.Fatalf("nil records rendered %q consumed %v, want nothing", lines, matched)
	}
}

// RenderMTUUnconvergedLeftovers prints only rowless, filter-visible records
// that still diverge at show time, under a header naming the section — and
// nil when nothing qualifies, so record-less output stays byte-identical.
func TestRenderMTUUnconvergedLeftovers9841(t *testing.T) {
	lo, err := net.InterfaceByName("lo")
	if err != nil {
		t.Skipf("net.InterfaceByName(%q) unavailable in this environment (%v)", "lo", err)
	}
	diverged := MTUUnconverged{Name: "ge-0-0-9", ConfigRef: "ge-0/0/9",
		WantMTU: 9000, LiveMTU: 1500, Grade: MTUGradeWriteFailed}
	converged := MTUUnconverged{Name: "lo", ConfigRef: "lo",
		WantMTU: lo.MTU, LiveMTU: 1500, Grade: MTUGradeWriteFailed, ExpectIfindex: lo.Index}
	recs := []MTUUnconverged{diverged, converged}

	got := RenderMTUUnconvergedLeftovers(recs, nil, "")
	if len(got) != 2 || got[0] != "MTU unconverged (no matching interface row):" {
		t.Fatalf("unfiltered leftovers = %q, want header + the diverged record only", got)
	}
	if !strings.Contains(got[1], "ge-0/0/9") || !strings.Contains(got[1], "netdev ge-0-0-9") {
		t.Errorf("leftover line %q must name the authored ref and the kernel netdev", got[1])
	}

	if got := RenderMTUUnconvergedLeftovers(recs, nil, "ge-0/0/2"); got != nil {
		t.Fatalf("non-matching filter rendered %q, want nil", got)
	}
	if got := RenderMTUUnconvergedLeftovers(recs, nil, "ge-0/0/9"); len(got) != 2 {
		t.Fatalf("matching filter rendered %q, want header + record", got)
	}
	consumed := map[string]bool{diverged.Key(): true}
	if got := RenderMTUUnconvergedLeftovers(recs, consumed, ""); got != nil {
		t.Fatalf("consumed record re-rendered %q, want nil (the converged one suppresses)", got)
	}
	if got := RenderMTUUnconvergedLeftovers(nil, nil, ""); got != nil {
		t.Fatalf("nil records rendered %q, want nil", got)
	}
}
