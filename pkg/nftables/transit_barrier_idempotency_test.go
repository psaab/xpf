package nftables

import (
	"errors"
	"testing"

	gnft "github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func witnessForwardFenceSpec10478(ifname string) ForwardFenceSpec {
	return ForwardFenceSpec{AllowedMarks: []ForwardFenceMark{{
		Ifname: ifname,
		Mark:   AdjudicatedTransitMark,
		Mask:   AdjudicatedTransitMarkMask,
	}}}
}

func TestTransitFenceWitnessCounterRender10478(t *testing.T) {
	p := newBuildPlan(t, "xpf_transit_10478_counter", *gnft.ChainPriorityFilter)
	p.chain = transitBarrierChain(p.table)
	spec := witnessForwardFenceSpec10478(HostInboundDelegatedIfname)
	emitTransitFencePinhole(p, spec)
	if p.err != nil {
		t.Fatalf("emit q0 witness pinhole: %v", p.err)
	}
	if len(p.counters) != 1 || p.counters[0] != TransitFenceDeliveredCounterName {
		t.Fatalf("counter declarations=%v, want [%q]", p.counters, TransitFenceDeliveredCounterName)
	}
	if len(p.rules) != 1 {
		t.Fatalf("rules=%d, want one q0 pinhole", len(p.rules))
	}
	rule := p.rules[0]
	if _, ok := rule[len(rule)-2].(*expr.Objref); !ok {
		t.Fatalf("q0 expression before verdict=%#v, want named counter reference", rule[len(rule)-2])
	}
	if verdict, ok := rule[len(rule)-1].(*expr.Verdict); !ok || verdict.Kind != expr.VerdictAccept {
		t.Fatalf("q0 final expression=%#v, want ACCEPT", rule[len(rule)-1])
	}

	bridge := newBuildPlan(t, "xpf_transit_10478_counter_bridge", *gnft.ChainPriorityFilter)
	bridge.table.Family = gnft.TableFamilyBridge
	bridge.chain = transitBarrierChain(bridge.table)
	emitTransitFencePinhole(bridge, spec)
	if bridge.err != nil {
		t.Fatalf("emit bridge q0 pinhole: %v", bridge.err)
	}
	if len(bridge.counters) != 0 {
		t.Fatalf("bridge counter declarations=%v, want none (inet reader owns witness)", bridge.counters)
	}
}

func TestTransitFenceLiveShapeIncludesCounter10478(t *testing.T) {
	p := newBuildPlan(t, "xpf_transit_10478_live", *gnft.ChainPriorityFilter)
	p.chain = transitBarrierChain(p.table)
	spec := witnessForwardFenceSpec10478(HostInboundDelegatedIfname)
	emitTransitFencePinhole(p, spec)
	if p.err != nil {
		t.Fatal(p.err)
	}
	live := transitFenceLiveShape{
		chain:   p.chain,
		rules:   []*gnft.Rule{{Exprs: p.rules[0]}},
		objects: []gnft.Obj{&gnft.CounterObj{Name: TransitFenceDeliveredCounterName}},
		sets:    map[string][]string{},
	}
	if !forwardFenceLiveShapeEqual(spec, gnft.TableFamilyINet, live) {
		t.Fatal("canonical live q0 fence with counter did not match desired shape")
	}
	if !transitFenceRulesContainWitnessCounter(live.rules) {
		t.Fatal("live armed q0 rule with counter was not recognized by reader guard")
	}
	live.objects = nil
	if forwardFenceLiveShapeEqual(spec, gnft.TableFamilyINet, live) {
		t.Fatal("counter-object missing live q0 fence must not compare equal")
	}
}

func TestTransitFenceEqualLiveShapeSkipsNetlinkWrite10478(t *testing.T) {
	spec := witnessForwardFenceSpec10478(HostInboundDelegatedIfname)
	writes := 0
	in := &netlinkInstaller{
		forwardFenceInstalled: true,
		forwardFenceSpec:      cloneForwardFenceSpec(spec),
		forwardFenceLiveEqualFn: func(ForwardFenceSpec) (bool, error) {
			return true, nil
		},
		forwardFenceReplaceFn: func(ForwardFenceSpec) error {
			writes++
			return nil
		},
	}
	if err := in.installForwardFence(spec); err != nil {
		t.Fatal(err)
	}
	if writes != 0 {
		t.Fatalf("equal live shape wrote netlink %d times, want zero", writes)
	}
}

func TestTransitFenceUnequalLiveShapeReinstalls10478(t *testing.T) {
	old := witnessForwardFenceSpec10478(HostInboundDelegatedIfname)
	want := witnessForwardFenceSpec10478("xpf-usp1")
	want.AllowedIfnames = []string{"owned0"}
	writes := 0
	in := &netlinkInstaller{
		forwardFenceInstalled: true,
		forwardFenceSpec:      cloneForwardFenceSpec(old),
		forwardFenceReplaceFn: func(ForwardFenceSpec) error {
			writes++
			return nil
		},
	}
	if err := in.installForwardFence(want); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("unequal desired spec wrote netlink %d times, want one", writes)
	}
}

func TestTransitFenceLiveReadErrorReinstalls10478(t *testing.T) {
	spec := witnessForwardFenceSpec10478(HostInboundDelegatedIfname)
	writes := 0
	in := &netlinkInstaller{
		forwardFenceInstalled: true,
		forwardFenceSpec:      cloneForwardFenceSpec(spec),
		forwardFenceLiveEqualFn: func(ForwardFenceSpec) (bool, error) {
			return false, errors.New("synthetic dump failure")
		},
		forwardFenceReplaceFn: func(ForwardFenceSpec) error {
			writes++
			return nil
		},
	}
	if err := in.installForwardFence(spec); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("live read error wrote netlink %d times, want one", writes)
	}
}

func TestTransitFenceMissingCounterReinstalls10478(t *testing.T) {
	spec := witnessForwardFenceSpec10478(HostInboundDelegatedIfname)
	writes := 0
	in := &netlinkInstaller{
		forwardFenceInstalled: true,
		forwardFenceSpec:      cloneForwardFenceSpec(spec),
		forwardFenceLiveEqualFn: func(ForwardFenceSpec) (bool, error) {
			return false, nil
		},
		forwardFenceReplaceFn: func(ForwardFenceSpec) error {
			writes++
			return nil
		},
	}
	if err := in.installForwardFence(spec); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("missing live counter wrote netlink %d times, want one", writes)
	}
}

func TestTransitFenceNonWitnessRetainsReplaceOnCall10478(t *testing.T) {
	spec := ForwardFenceSpec{AllowedIfnames: []string{"owned0"}}
	writes := 0
	in := &netlinkInstaller{
		forwardFenceInstalled: true,
		forwardFenceSpec:      cloneForwardFenceSpec(spec),
		forwardFenceReplaceFn: func(ForwardFenceSpec) error {
			writes++
			return nil
		},
	}
	if err := in.installForwardFence(spec); err != nil {
		t.Fatal(err)
	}
	if writes != 1 {
		t.Fatalf("non-witness fence wrote netlink %d times, want one", writes)
	}
}
func TestClassifyTransitFenceCounterAbsentVsZero10478(t *testing.T) {
	if got, ok := classifyTransitFenceCounterObjects(nil); ok || got != (TransitFenceCounter{}) {
		t.Fatalf("absent counter classification=(%+v,%v), want zero/unavailable", got, ok)
	}
	if got, ok := classifyTransitFenceCounterObjects([]gnft.Obj{
		&gnft.CounterObj{Name: TransitFenceDeliveredCounterName, Packets: 0, Bytes: 0},
	}); !ok || got != (TransitFenceCounter{}) {
		t.Fatalf("present zero counter classification=(%+v,%v), want authoritative zero/available", got, ok)
	}
}
