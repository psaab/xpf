package api

import (
	"path/filepath"
	"testing"

	"github.com/psaab/xpf/pkg/dataplane"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// #16464: Prometheus xpf_filter_hits_total must fold clone hits into the
// source term and emit no clone-labelled series.
//
// FAIL-ON-REVERT: plain index + clone skip leaves steer at 40.
const clone16464TreeAPI = `routing-instances {
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

func TestCollectFilterCountersFoldsClone16464(t *testing.T) {
	store := newConfigStore(t, filepath.Join(t.TempDir(), "xpf.conf"))
	if _, err := store.SyncApply(clone16464TreeAPI, nil); err != nil {
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
	c := newCollector(&Server{store: store})
	dp := &filterUserspaceDP{
		Manager: dataplane.New(),
		status: dpuserspace.ProcessStatus{FilterTermCounters: []dpuserspace.FirewallFilterTermCounterStatus{
			{Family: "inet", FilterName: "shared-fbf", TermName: "steer", Packets: 40},
			{Family: "inet", FilterName: cloneName, TermName: "steer", Packets: 60},
		}},
	}
	got := filterHitsByTerm(t, c, dp)
	if got["steer"] != 100 {
		t.Fatalf("xpf_filter_hits_total steer = %v, want 100 (40+60 folded)", got)
	}
	if len(got) != 1 {
		t.Fatalf("series = %v, want only the source steer series (no clone series)", got)
	}
}
