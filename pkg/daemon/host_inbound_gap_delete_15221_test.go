package daemon

import (
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sync/semaphore"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	xnft "github.com/psaab/xpf/pkg/nftables"
	"github.com/vishvananda/netlink"
)

// TestGapDeleteFailureAfterRealInstallReportsFence15221 is the #15221
// (A36-03) acceptance cell: a failed delete of the obsolete
// xpf_hostinbound_gap table after a successful real install must not be
// swallowed into a Current report with GapFenceActive=false while the gap
// fence still drops. The gap-fence spec must also be retained so a later
// gap install merges (does not clobber) the still-standing fence.
//
// Phases mirror TestDoubleNftFailAutoConverges11497: phase 1 installs the
// real table, phase 2 lands a newcomer while the real install fails so the
// additive gap fence stands, phase 3 heals the real install but fails only
// the gap-table delete.
func TestGapDeleteFailureAfterRealInstallReportsFence15221(t *testing.T) {
	origInstaller := nftInstaller
	t.Cleanup(func() { nftInstaller = origInstaller })
	origSample := sampleHostInboundSnapshots
	t.Cleanup(func() { sampleHostInboundSnapshots = origSample })

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
		"ge-0/0/9": {Name: "ge-0/0/9", Units: map[int]*config.InterfaceUnit{0: {Number: 0, DHCP: true, DHCPv6: true}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0"}},
	}
	cfg.RoutingInstances = []*config.RoutingInstanceConfig{{Name: "data", Interfaces: []string{"ge-0/0/9.0"}}}

	uni := int(netlink.SCOPE_UNIVERSE)
	sib := scriptedSnap10751("ge-0/0/0.0", "trust", scriptedAddr10751("inet", "10.0.0.1/24", uni))
	vrfDown := scriptedSnap10751("ge-0/0/9.0", "")
	vrfDown.RoutingInstance = "data"
	s1 := []dpuserspace.InterfaceSnapshot{sib, vrfDown}
	vrfUp := scriptedSnap10751("ge-0/0/9.0", "",
		scriptedAddr10751("inet", "203.0.113.9/24", uni),
		scriptedAddr10751("inet6", "2001:db8:9::9/64", uni))
	vrfUp.RoutingInstance = "data"
	s2 := []dpuserspace.InterfaceSnapshot{sib, vrfUp}

	s, err := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}

	// Phase 1: real install succeeds.
	sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot { return s1 }
	nftInstaller = &fakeNftInstaller{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("phase 1 (install): %v", err)
	}
	if !d.earlyInputHandoffDone.Load() {
		t.Fatal("phase 1: first apply must hand off (later phases run day-2)")
	}
	if d.HostInboundApplied().GapFenceActive {
		t.Fatal("phase 1: no gap fence stands after a clean real install")
	}

	// Phase 2: newcomer lands while the real install fails; the additive
	// gap fence stands beside the retained table.
	realErr := errors.New("nftables: real host-inbound load failed")
	sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot { return s2 }
	nftInstaller = &fakeNftInstaller{
		hostInbound: func(xnft.HostInboundSpec) error { return realErr },
	}
	if err := d.applyHostInboundFilter(cfg); err == nil {
		t.Fatal("phase 2: failed real install must return an error")
	}
	if !d.HostInboundApplied().GapFenceActive {
		t.Fatal("phase 2: gap fence must stand after the failed rerender (fixture premise)")
	}
	if d.hostInboundGapFenceSpec == nil {
		t.Fatal("phase 2: gap fence spec must be retained while the gap table stands")
	}

	// Phase 3: the real install heals but deleting the obsolete gap table
	// fails. Acceptance (#15221): the probe reports GapFenceActive=true or
	// the commit errors — never Current with GapFenceActive=false.
	gapDeleteErr := errors.New("nftables: gap table delete failed")
	var deletedTables []string
	nftInstaller = &fakeNftInstaller{
		del: func(name string) error {
			deletedTables = append(deletedTables, name)
			if name == xnft.HostInboundGapTableName {
				return gapDeleteErr
			}
			return nil
		},
	}
	applyErr := d.applyHostInboundFilter(cfg)
	foundGapDelete := false
	for _, name := range deletedTables {
		if name == xnft.HostInboundGapTableName {
			foundGapDelete = true
		}
	}
	if !foundGapDelete {
		t.Fatalf("phase 3: obsolete gap table delete was not attempted, deleted=%v", deletedTables)
	}
	// The issue permits either reporting shape; this fix keeps the apply
	// successful (the real table covers the desired set) and reports truth.
	if applyErr != nil && !d.HostInboundApplied().GapFenceActive {
		t.Fatalf("phase 3: apply failed (%v) and the probe still hides the standing gap fence", applyErr)
	}
	st := d.HostInboundApplied()
	if st.Current() && !st.GapFenceActive {
		t.Fatalf("phase 3: applied state reports Current with GapFenceActive=false "+
			"while the gap fence still drops (apply err=%v): %+v", applyErr, st)
	}
	if !st.GapFenceActive {
		t.Fatalf("phase 3: GapFenceActive=false after a failed gap-table delete; "+
			"the lingering xpf_hostinbound_gap table is invisible to the operator: %+v", st)
	}
	if d.hostInboundGapFenceSpec == nil {
		t.Fatal("phase 3: gap fence spec was cleared despite the failed delete; " +
			"a later gap install would clobber the still-standing fence")
	}

	// Phase 4 (control): once the delete heals, the next successful real
	// install retires the fence and the probe clears — no behaviour change
	// outside the cited mechanism.
	nftInstaller = &fakeNftInstaller{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("phase 4 (healed install): %v", err)
	}
	st = d.HostInboundApplied()
	if st.GapFenceActive {
		t.Fatalf("phase 4: gap marker must clear once the delete succeeds: %+v", st)
	}
	if !st.Current() {
		t.Fatalf("phase 4: applied state must be Current after the healed install: %+v", st)
	}
	if d.hostInboundGapFenceSpec != nil {
		t.Fatal("phase 4: gap fence spec must clear once the delete succeeds")
	}
}

// TestGapDeleteSuccessClearsFence15221 is the adjacent control: the common
// case (gap delete succeeds after a real install, or no gap ever stood)
// stays Current with no fence reported.
func TestGapDeleteSuccessClearsFence15221(t *testing.T) {
	origInstaller := nftInstaller
	t.Cleanup(func() { nftInstaller = origInstaller })
	origSample := sampleHostInboundSnapshots
	t.Cleanup(func() { sampleHostInboundSnapshots = origSample })

	cfg := &config.Config{}
	cfg.Interfaces.Interfaces = map[string]*config.InterfaceConfig{
		"ge-0/0/0": {Name: "ge-0/0/0", Units: map[int]*config.InterfaceUnit{0: {Number: 0}}},
	}
	cfg.Security.Zones = map[string]*config.ZoneConfig{
		"trust": {Name: "trust", Interfaces: []string{"ge-0/0/0.0"}},
	}
	uni := int(netlink.SCOPE_UNIVERSE)
	s1 := []dpuserspace.InterfaceSnapshot{
		scriptedSnap10751("ge-0/0/0.0", "trust", scriptedAddr10751("inet", "10.0.0.1/24", uni)),
	}
	sampleHostInboundSnapshots = func(*config.Config) []dpuserspace.InterfaceSnapshot { return s1 }

	s, err := configstore.New(filepath.Join(t.TempDir(), "config"))
	if err != nil {
		t.Fatalf("configstore.New: %v", err)
	}
	d := &Daemon{applySem: semaphore.NewWeighted(1), store: s}
	nftInstaller = &fakeNftInstaller{}
	if err := d.applyHostInboundFilter(cfg); err != nil {
		t.Fatalf("install: %v", err)
	}
	st := d.HostInboundApplied()
	if !st.Current() || st.GapFenceActive {
		t.Fatalf("clean install must report Current with no gap fence: %+v", st)
	}
}
