package grpcapi

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/configstore"
	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

type firewallFilterShowUserspaceDP struct {
	*dataplane.Manager
	status dpuserspace.ProcessStatus
}

func (f *firewallFilterShowUserspaceDP) Status() (dpuserspace.ProcessStatus, error) {
	return f.status, nil
}

func newFirewallFilterShowStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"firewall family inet filter bandwidth-output term 0 from destination-port 80",
		"firewall family inet filter bandwidth-output term 0 then accept",
		"firewall family inet6 filter bandwidth-output term 0 from destination-port 5201",
		"firewall family inet6 filter bandwidth-output term 0 then count iperf-a-v6",
		"firewall family inet6 filter bandwidth-output term 0 then accept",
		"firewall family inet6 filter bandwidth-output term 1 from destination-port 5300",
		"firewall family inet6 filter bandwidth-output term 1 then accept",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

func TestShowTextFirewallFilterHonorsFamilyAndUserspaceCounters(t *testing.T) {
	store := newFirewallFilterShowStore(t)
	s := &Server{
		store: store,
		dp: &firewallFilterShowUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
					{
						Family:     "inet6",
						FilterName: "bandwidth-output",
						TermName:   "0",
						Packets:    7,
						Bytes:      1024,
					},
				},
			},
		},
	}

	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "firewall-filter:bandwidth-output:inet6"})
	if err != nil {
		t.Fatalf("ShowText() error = %v", err)
	}
	out := resp.GetOutput()
	if !strings.Contains(out, "Filter: bandwidth-output (family inet6)") {
		t.Fatalf("output = %q, want inet6 filter heading", out)
	}
	if strings.Contains(out, "destination-port 80") {
		t.Fatalf("output = %q, unexpectedly rendered inet family term", out)
	}
	if !strings.Contains(out, "destination-port 5201") {
		t.Fatalf("output = %q, want inet6 destination-port 5201", out)
	}
	if !strings.Contains(out, "Hit count: 7 packets, 1024 bytes") {
		t.Fatalf("output = %q, want userspace hit counters", out)
	}
	if strings.Count(out, "Hit count:") != 1 {
		t.Fatalf("output = %q, want a hit count only for the counted term", out)
	}
}

func newFirewallPolicerShowStore(t *testing.T) *configstore.Store {
	t.Helper()

	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		// A valid single-rate three-color policer referenced by one term. The
		// strict filter validator rejects a dangling `then policer` reference,
		// so the policer must be defined for the config to commit.
		"firewall three-color-policer tcp-limit single-rate color-blind",
		"firewall three-color-policer tcp-limit single-rate committed-information-rate 1m",
		"firewall three-color-policer tcp-limit single-rate committed-burst-size 15k",
		"firewall three-color-policer tcp-limit single-rate excess-burst-size 30k",
		"firewall family inet filter rate-in term policed from destination-port 80",
		"firewall family inet filter rate-in term policed then policer tcp-limit",
		"firewall family inet filter rate-in term policed then accept",
		// A second term with NO policer — must be unaffected by the policer
		// surfacing.
		"firewall family inet filter rate-in term plain from destination-port 22",
		"firewall family inet filter rate-in term plain then accept",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	return store
}

// TestShowFirewallSurfacesThreeColorPolicerStatus is the #4372 RED-on-revert
// guard: `show firewall` / `show firewall filter` must surface the per-color
// (green/yellow/red conform/exceed) and treatment-drop counters the userspace
// dataplane publishes for a three-color policer a term references. Reverting
// the surfacing drops the "Policer ..." block (RED). A term with no policer is
// unaffected.
func TestShowFirewallSurfacesThreeColorPolicerStatus(t *testing.T) {
	store := newFirewallPolicerShowStore(t)
	s := &Server{
		store: store,
		dp: &firewallFilterShowUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				ThreeColorPolicerCounters: []dpuserspace.ThreeColorPolicerStatus{
					{
						ID:            3,
						Name:          "tcp-limit",
						Family:        "inet",
						FilterName:    "rate-in",
						TermName:      "policed",
						Mode:          "single-rate",
						ColorBlind:    true,
						GreenPackets:  100,
						GreenBytes:    6400,
						YellowPackets: 20,
						YellowBytes:   1280,
						RedPackets:    5,
						RedBytes:      320,
						DropPackets:   5,
						DropBytes:     320,
					},
				},
			},
		},
	}

	wants := []string{
		"then policer tcp-limit",
		"Policer tcp-limit (single-rate, color-blind):",
		"green (conform):  100 packets, 6400 bytes",
		"yellow (exceed):  20 packets, 1280 bytes",
		"red (violate):    5 packets, 320 bytes",
		"dropped:          5 packets, 320 bytes",
	}

	// show firewall filter <name>
	resp, err := s.ShowText(context.Background(), &pb.ShowTextRequest{Topic: "firewall-filter:rate-in:inet"})
	if err != nil {
		t.Fatalf("ShowText(firewall-filter) error = %v", err)
	}
	filterOut := resp.GetOutput()
	for _, want := range wants {
		if !strings.Contains(filterOut, want) {
			t.Fatalf("show firewall filter output missing %q:\n%s", want, filterOut)
		}
	}
	// The no-policer term must not sprout a policer block.
	if strings.Count(filterOut, "Policer tcp-limit") != 1 {
		t.Fatalf("show firewall filter rendered the policer block %d times, want 1:\n%s",
			strings.Count(filterOut, "Policer tcp-limit"), filterOut)
	}

	// show firewall (all filters)
	var buf strings.Builder
	s.showFirewall(store.ActiveConfig(), &buf)
	allOut := buf.String()
	for _, want := range wants {
		if !strings.Contains(allOut, want) {
			t.Fatalf("show firewall output missing %q:\n%s", want, allOut)
		}
	}
}

// TestShowFirewallOmitsPolicerBlockWithoutThreeColorPolicer is the negative half
// of the #4372 guard: a filter with no `then policer` reference renders no
// "Policer" block even when the dataplane publishes unrelated policer counters.
func TestShowFirewallOmitsPolicerBlockWithoutThreeColorPolicer(t *testing.T) {
	store := newFirewallFilterShowStore(t)
	s := &Server{
		store: store,
		dp: &firewallFilterShowUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				ThreeColorPolicerCounters: []dpuserspace.ThreeColorPolicerStatus{
					{ID: 1, Name: "unreferenced", Mode: "single-rate", GreenPackets: 9},
				},
			},
		},
	}

	var buf strings.Builder
	s.showFirewall(store.ActiveConfig(), &buf)
	out := buf.String()
	if strings.Contains(out, "Policer ") {
		t.Fatalf("show firewall rendered a policer block for a filter with no policer:\n%s", out)
	}
}

// #15680: two terms referencing the same policer must render only their
// own scoped counters. Pre-fix the index was keyed by policer name alone,
// so each term rendered the (aggregated) counters of every term.
func TestShowFirewallRendersPerTermPolicerCounters15680(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if err := store.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure() error = %v", err)
	}
	for _, cmd := range []string{
		"firewall three-color-policer shared single-rate color-blind",
		"firewall three-color-policer shared single-rate committed-information-rate 1m",
		"firewall three-color-policer shared single-rate committed-burst-size 15k",
		"firewall three-color-policer shared single-rate excess-burst-size 30k",
		"firewall family inet filter edge term first then policer shared",
		"firewall family inet filter edge term first then accept",
		"firewall family inet filter edge term second then policer shared",
		"firewall family inet filter edge term second then accept",
	} {
		if err := store.SetFromInput(cmd); err != nil {
			t.Fatalf("SetFromInput(%q) error = %v", cmd, err)
		}
	}
	if _, err := store.Commit(); err != nil {
		t.Fatalf("Commit() error = %v", err)
	}
	s := &Server{
		store: store,
		dp: &firewallFilterShowUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				ThreeColorPolicerCounters: []dpuserspace.ThreeColorPolicerStatus{
					{ID: 5, Name: "shared", Family: "inet", FilterName: "edge", TermName: "first", Mode: "single-rate", ColorBlind: true, GreenPackets: 10, GreenBytes: 1000},
					{ID: 6, Name: "shared", Family: "inet", FilterName: "edge", TermName: "second", Mode: "single-rate", ColorBlind: true, GreenPackets: 2, GreenBytes: 200, RedPackets: 1, RedBytes: 100, DropPackets: 1, DropBytes: 100},
				},
			},
		},
	}
	var buf strings.Builder
	s.showFirewall(store.ActiveConfig(), &buf)
	out := buf.String()
	if strings.Count(out, "Policer shared") != 2 {
		t.Fatalf("want one policer block per term, got:\n%s", out)
	}
	if !strings.Contains(out, "green (conform):  10 packets, 1000 bytes") {
		t.Fatalf("first term's own counters missing:\n%s", out)
	}
	if !strings.Contains(out, "green (conform):  2 packets, 200 bytes") {
		t.Fatalf("second term's own counters missing:\n%s", out)
	}
	// The pre-fix name-keyed rendering would show the same numbers under
	// both terms; guard against either count appearing twice.
	if strings.Count(out, "10 packets, 1000 bytes") != 1 || strings.Count(out, "2 packets, 200 bytes") != 1 {
		t.Fatalf("per-term counters bled across terms:\n%s", out)
	}
}

func TestShowTextScreenSYNCookieCounterRowsUsesUserspaceStatus(t *testing.T) {
	s := &Server{
		dp: &firewallFilterShowUserspaceDP{
			Manager: dataplane.New(),
			status: dpuserspace.ProcessStatus{
				Bindings: []dpuserspace.BindingStatus{
					{
						SYNCookieChallenges:        2,
						SYNCookieSecretUnavailable: 3,
						SYNCookieAckValid:          5,
						SYNCookieAckInvalid:        7,
						SYNCookieBypass:            11,
					},
					{
						SYNCookieChallenges:        13,
						SYNCookieSecretUnavailable: 17,
						SYNCookieAckValid:          19,
						SYNCookieAckInvalid:        23,
						SYNCookieBypass:            29,
					},
				},
			},
		},
	}

	out := s.screenSYNCookieCounterRows()
	for _, want := range []string{
		"Userspace SYN-cookie scope",
		"all bindings",
		"SYN-cookie challenges",
		"15",
		"SYN-cookie secret unavailable",
		"20",
		"SYN-cookie ACK valid",
		"24",
		"SYN-cookie ACK invalid",
		"30",
		"SYN-cookie bypass",
		"40",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("screen SYN-cookie rows missing %q:\n%s", want, out)
		}
	}
}
