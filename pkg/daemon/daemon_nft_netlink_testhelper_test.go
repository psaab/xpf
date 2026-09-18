package daemon

// daemon_nft_netlink_testhelper_test.go provides the #6387 PR-3 test seam that
// replaces the pre-cutover nftApplyPayload / nftDeleteTable stub seam. The
// fail-closed regression tests (#3333/#3392/#5644/#5789/#5790) inject an
// install/teardown FAILURE through fakeNftInstaller — the SINGLE failure-injection
// seam the plan §12.4 requires, covering every kernel-touching op (real
// host-inbound install, cold-boot fence, gap fence, lo0 install, table delete).
//
// A package init() also installs a NO-OP nftInstaller as the default for the whole
// daemon test binary, so the many tests that drive applyConfigLocked / applyConfig
// (and thus the host-inbound + lo0 apply tail) do not shell out to a real kernel
// nf_tables subsystem; a test that asserts a specific fail-closed behavior
// overrides nftInstaller with a fakeNftInstaller and restores it. It also forces
// nftProbeAvailable to "available" so the nf_tables-unavailable classification
// (tagNftInstallErr) is deterministic and never opens a real netlink socket during
// unit tests.

import xnft "github.com/psaab/xpf/pkg/nftables"

func init() {
	// Default every daemon unit test to a no-op installer (production defaults to
	// the real netlink installer). Fail-closed tests override per-test.
	nftInstaller = noopNftInstaller{}
	// Classification defaults to "subsystem available" so tagNftInstallErr does not
	// probe a real socket and does not tag an injected non-nf_tables failure.
	nftProbeAvailable = func() error { return nil }
}

// noopNftInstaller is the default test Installer: every op succeeds and touches
// no kernel state.
type noopNftInstaller struct{}

func (noopNftInstaller) InstallHostInbound(xnft.HostInboundSpec) error { return nil }
func (noopNftInstaller) InstallColdBootFence(xnft.FenceSpec) error     { return nil }
func (noopNftInstaller) InstallLo0ColdBootFence(xnft.FenceSpec) error  { return nil }
func (noopNftInstaller) InstallGapFence(xnft.GapFenceSpec) error       { return nil }
func (noopNftInstaller) InstallTransitBarrier() error                  { return nil }
func (noopNftInstaller) InstallArmedTransitFence(xnft.ForwardFenceSpec) error {
	return nil
}
func (noopNftInstaller) RemoveTransitBarrier() error                  { return nil }
func (noopNftInstaller) InstallLo0(s xnft.Lo0FilterSpec) (int, error) { return fakeLo0Rules(s), nil }
func (noopNftInstaller) DeleteTable(string) error                     { return nil }

// fakeNftInstaller is the per-test failure-injection seam. A nil hook succeeds
// (returns nil); a set hook decides the result and can capture the spec/name for
// assertions. This is the netlink equivalent of the pre-PR-3 nftApplyPayload /
// nftDeleteTable stubs.
type fakeNftInstaller struct {
	hostInbound      func(xnft.HostInboundSpec) error
	coldBootFence    func(xnft.FenceSpec) error
	lo0ColdBootFence func(xnft.FenceSpec) error
	gapFence         func(xnft.GapFenceSpec) error
	lo0              func(xnft.Lo0FilterSpec) error
	// lo0Rules overrides the rendered rule count InstallLo0 reports (#6529).
	// nil means "derive it from the spec" (fakeLo0Rules).
	lo0Rules *int
	del      func(string) error
	// #7191: barrier call recorder. barrierCalls appends "install"/"remove" in
	// order so a test can assert the SEQUENCE, not just that a call happened —
	// install-then-remove and remove-then-install have opposite meanings for a
	// fail-closed gate.
	barrierCalls   []string
	barrierInstall func() error
	barrierRemove  func() error
	// #10302: records armed-fence installs so fence cells can assert the armed
	// action is a fence install, not a bare barrier removal.
	fenceCalls10302   []string
	fenceSpecs10302   []xnft.ForwardFenceSpec
	fenceInstall10302 func(xnft.ForwardFenceSpec) error
}

func (f *fakeNftInstaller) InstallHostInbound(s xnft.HostInboundSpec) error {
	if f.hostInbound != nil {
		return f.hostInbound(s)
	}
	return nil
}

func (f *fakeNftInstaller) InstallColdBootFence(s xnft.FenceSpec) error {
	if f.coldBootFence != nil {
		return f.coldBootFence(s)
	}
	return nil
}

func (f *fakeNftInstaller) InstallLo0ColdBootFence(s xnft.FenceSpec) error {
	if f.lo0ColdBootFence != nil {
		return f.lo0ColdBootFence(s)
	}
	return nil
}

func (f *fakeNftInstaller) InstallGapFence(s xnft.GapFenceSpec) error {
	if f.gapFence != nil {
		return f.gapFence(s)
	}
	return nil
}

func (f *fakeNftInstaller) InstallLo0(s xnft.Lo0FilterSpec) (int, error) {
	var err error
	if f.lo0 != nil {
		err = f.lo0(s)
	}
	if err != nil {
		return 0, err
	}
	if f.lo0Rules != nil {
		return *f.lo0Rules, nil
	}
	return fakeLo0Rules(s), nil
}

// fakeLo0Rules is the fakes' stand-in for the #6529 RENDERED rule count that
// netlinkInstaller.InstallLo0 returns from nlPlan.rules. It counts TERMS, which
// agrees with the real render for every fixture in this package (each term
// lowers to exactly one rule) and, crucially, agrees on the value that matters:
// a spec with no terms — a dangling filter name, or a filter with no terms —
// renders ZERO rules. A test that needs the third door (terms present, every one
// lowering to zero rules) sets fakeNftInstaller.lo0Rules explicitly rather than
// relying on this approximation.
func fakeLo0Rules(s xnft.Lo0FilterSpec) int {
	return len(s.V4Terms) + len(s.V6Terms)
}

func (f *fakeNftInstaller) DeleteTable(name string) error {
	if f.del != nil {
		return f.del(name)
	}
	return nil
}

// countingNftInstaller counts every kernel-touching op (all succeed). Used by the
// #5643 post-promotion-cancel test to prove the host-authorization closeout ran
// the nftables tail after a cancel, replacing the pre-PR-3 nftApplyPayload/
// nftDeleteTable call counter.
type countingNftInstaller struct{ calls *int }

func (c countingNftInstaller) InstallHostInbound(xnft.HostInboundSpec) error { *c.calls++; return nil }
func (c countingNftInstaller) InstallColdBootFence(xnft.FenceSpec) error     { *c.calls++; return nil }
func (c countingNftInstaller) InstallLo0ColdBootFence(xnft.FenceSpec) error  { *c.calls++; return nil }
func (c countingNftInstaller) InstallGapFence(xnft.GapFenceSpec) error       { *c.calls++; return nil }
func (c countingNftInstaller) InstallLo0(s xnft.Lo0FilterSpec) (int, error) {
	*c.calls++
	return fakeLo0Rules(s), nil
}
func (c countingNftInstaller) DeleteTable(string) error { *c.calls++; return nil }

// hostInboundViewAddrs reports whether a HostInboundSpec view/unzoned set scopes
// the given bare address in the requested family. Used by fence/real spec
// assertions in the ported fail-closed tests to check WHICH addresses a netlink
// install would fence, replacing the pre-PR-3 nft-payload string matches.
func hostInboundViewAddrs(spec xnft.HostInboundSpec, v6 bool) []string {
	var out []string
	for _, v := range spec.Views {
		if v6 {
			out = append(out, v.V6Addrs...)
		} else {
			out = append(out, v.V4Addrs...)
		}
	}
	if v6 {
		out = append(out, spec.UnzonedV6...)
	} else {
		out = append(out, spec.UnzonedV4...)
	}
	return out
}

// fenceViewAddrs is the FenceSpec equivalent of hostInboundViewAddrs: the bare
// firewall-local addresses a cold-boot fence would DROP in the requested family.
func fenceViewAddrs(spec xnft.FenceSpec, v6 bool) []string {
	var out []string
	for _, v := range spec.Views {
		if v6 {
			out = append(out, v.V6Addrs...)
		} else {
			out = append(out, v.V4Addrs...)
		}
	}
	if v6 {
		out = append(out, spec.UnzonedV6...)
	} else {
		out = append(out, spec.UnzonedV4...)
	}
	return out
}

// sliceContains reports whether s contains v (helper for the spec assertions).
func sliceContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// hostInboundProgramHasSrc reports whether a HostInboundSpec carries a junos-host
// DENY program scoped to ifname whose v4/v6 rules match the given source. Replaces
// the pre-PR-3 `iifname "<if>" ip saddr <src> ... drop` nft-payload string match in
// the #5644/#5759 fail-closed tests with a structural spec assertion.
func hostInboundProgramHasSrc(spec xnft.HostInboundSpec, ifname, src string) bool {
	for _, p := range spec.Programs {
		if !sliceContains(p.IngressIfnames, ifname) {
			continue
		}
		for _, r := range p.RulesV4 {
			if sliceContains(r.Src, src) {
				return true
			}
		}
		for _, r := range p.RulesV6 {
			if sliceContains(r.Src, src) {
				return true
			}
		}
	}
	return false
}

func (f *fakeNftInstaller) InstallTransitBarrier() error {
	f.barrierCalls = append(f.barrierCalls, "install")
	if f.barrierInstall != nil {
		return f.barrierInstall()
	}
	return nil
}

func (f *fakeNftInstaller) RemoveTransitBarrier() error {
	f.barrierCalls = append(f.barrierCalls, "remove")
	if f.barrierRemove != nil {
		return f.barrierRemove()
	}
	return nil
}
func (f *fakeNftInstaller) InstallArmedTransitFence(spec xnft.ForwardFenceSpec) error {
	f.fenceCalls10302 = append(f.fenceCalls10302, "install")
	f.fenceSpecs10302 = append(f.fenceSpecs10302, spec)
	if f.fenceInstall10302 != nil {
		return f.fenceInstall10302(spec)
	}
	return nil
}

// #7191: barrier no-ops; this fake counts host-inbound installs only.
func (c *countingNftInstaller) InstallTransitBarrier() error { return nil }
func (c *countingNftInstaller) InstallArmedTransitFence(xnft.ForwardFenceSpec) error {
	return nil
}
func (c *countingNftInstaller) RemoveTransitBarrier() error { return nil }
