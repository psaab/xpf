package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #16464: lenient clone counters fold into the authored filter on the
// local CLI raw views (all-filters and single-filter).
//
// FAIL-ON-REVERT: plain index leaves clone hits hidden; steer prints 40.
const clone16464TreeCLI = `routing-instances {
    member-ri {
        instance-type vrf;
        interface ge-0/0/1.0;
    }
    steer-ri {
        instance-type forwarding;
    }
}
firewall {
    family inet {
        filter shared-fbf {
            term steer {
                from {
                    source-address {
                        192.0.2.0/24;
                    }
                }
                then count hits;
                then routing-instance steer-ri;
            }
        }
    }
}
interfaces {
    ge-0/0/1 {
        unit 0 {
            family inet {
                filter {
                    input shared-fbf;
                }
            }
        }
    }
    ge-0/0/2 {
        unit 0 {
            family inet {
                filter {
                    input shared-fbf;
                }
            }
        }
    }
}
`

func TestCLIShowFirewallCloneCountersFold16464(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(clone16464TreeCLI, nil); err != nil {
		t.Fatalf("SyncApply (lenient): %v", err)
	}
	cfg := store.ActiveConfig()
	cloneName := ""
	for name, f := range cfg.Firewall.FiltersInet {
		if src, _ := f.SuppressedMemberFBF11321(); src == "shared-fbf" {
			cloneName = name
		}
	}
	if cloneName == "" {
		t.Fatalf("premise: no clone in %+v", cfg.Firewall.FiltersInet)
	}
	c := &CLI{store: store, dp: &firewallFilterUserspaceDP{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "shared-fbf", TermName: "steer", Packets: 40, Bytes: 4000},
			{Family: "inet", FilterName: cloneName, TermName: "steer", Packets: 60, Bytes: 6000},
		}},
	}}
	out := captureStdout(t, func() {
		if err := c.showFirewallFilters(); err != nil {
			t.Fatalf("showFirewallFilters: %v", err)
		}
	})
	if !strings.Contains(out, "Hit count: 100 packets, 10000 bytes") {
		t.Fatalf("all-filters = %q, want folded 100/10000", out)
	}
	if strings.Contains(out, cloneName) {
		t.Fatalf("all-filters leaks clone %q: %q", cloneName, out)
	}
	out = captureStdout(t, func() {
		if err := c.showFirewallFilter("shared-fbf", ""); err != nil {
			t.Fatalf("showFirewallFilter: %v", err)
		}
	})
	if !strings.Contains(out, "Hit count: 100 packets, 10000 bytes") {
		t.Fatalf("single-filter = %q, want folded 100/10000", out)
	}
}

// #16464 eBPF arm: clone map slots (FilterIDs carries the clone, as the
// compiler iterates every filter) must fold into the source term.
type clone16464MapDP struct {
	*dataplane.Manager
	apply *dataplane.ApplyResult
	// ruleStartByID maps filter ID -> RuleStart; slots map idx->value.
	starts map[uint32]uint32
	slots  map[uint32]dataplane.CounterValue
}

func (d *clone16464MapDP) IsLoaded() bool { return true }
func (d *clone16464MapDP) LastApplyResult() *dataplane.ApplyResult {
	return d.apply
}
func (d *clone16464MapDP) ReadFilterConfig(id uint32) (dataplane.FilterConfig, error) {
	return dataplane.FilterConfig{RuleStart: d.starts[id]}, nil
}
func (d *clone16464MapDP) ReadFilterCounters(idx uint32) (dataplane.CounterValue, error) {
	return d.slots[idx], nil
}

func TestCLIShowFirewallCloneMapCountersFold16464(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(clone16464TreeCLI, nil); err != nil {
		t.Fatalf("SyncApply (lenient): %v", err)
	}
	cfg := store.ActiveConfig()
	cloneName := ""
	for name, f := range cfg.Firewall.FiltersInet {
		if src, _ := f.SuppressedMemberFBF11321(); src == "shared-fbf" {
			cloneName = name
		}
	}
	if cloneName == "" {
		t.Fatalf("premise: no clone in %+v", cfg.Firewall.FiltersInet)
	}
	// Source steer occupies slot 0 (40), clone steer slot 10 (60).
	dp := &clone16464MapDP{
		Manager: dataplane.New(),
		apply: &dataplane.ApplyResult{FilterIDs: map[string]uint32{
			"inet:shared-fbf": 0, "inet:" + cloneName: 1,
		}},
		starts: map[uint32]uint32{0: 0, 1: 10},
		slots: map[uint32]dataplane.CounterValue{
			0: {Packets: 40, Bytes: 4000}, 10: {Packets: 60, Bytes: 6000},
		},
	}
	c := &CLI{store: store, dp: dp}
	out := captureStdout(t, func() {
		if err := c.showFirewallFilter("shared-fbf", ""); err != nil {
			t.Fatalf("showFirewallFilter: %v", err)
		}
	})
	if !strings.Contains(out, "Hit count: 100 packets, 10000 bytes") {
		t.Fatalf("map-fold single-filter = %q, want 100/10000", out)
	}
}
