package configstore

import (
	"strings"
	"testing"
)

// #9838, LoadMerge ingress half: the hierarchical merge path replays through
// FormatSet, which renders an empty braced container as a terminal `set`
// line (#9126). SetPath rebuilds that line as the container it was rendered
// from — never as a bare leaf — so a braced stanza merged here commits, and
// a no-op merge into a configured instance stays a no-op.

func loadMergeStore9838(t *testing.T) *Store {
	t.Helper()
	s := newTestStore(t)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	return s
}

func TestLoadMergeBracedEmptyInstancesCommit9838(t *testing.T) {
	s := loadMergeStore9838(t)
	if err := s.LoadMerge("interfaces {\n ge-0/0/0 { }\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"); err != nil {
		t.Fatalf("merge braced interface: %v", err)
	}
	cfg, err := s.CommitCheck()
	if err != nil {
		t.Fatalf("braced interface via LoadMerge: want a commit, got %v", err)
	}
	if cfg.Interfaces.Interfaces["ge-0/0/0"] == nil {
		t.Fatalf("braced interface via LoadMerge: ge-0/0/0 missing from the committed config")
	}

	s = loadMergeStore9838(t)
	if err := s.LoadMerge("routing-instances {\n ri1 { }\n}\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"); err != nil {
		t.Fatalf("merge braced RI: %v", err)
	}
	cfg, err = s.CommitCheck()
	if err != nil {
		t.Fatalf("braced RI via LoadMerge: want a commit, got %v", err)
	}
	found := false
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ri1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("braced RI via LoadMerge: ri1 missing from the committed config")
	}
}

func TestLoadMergeNoOpIntoConfiguredCommits9838(t *testing.T) {
	s := loadMergeStore9838(t)
	if err := s.LoadMerge("interfaces {\n ge-0/0/0 { unit 0 { family inet { address 10.0.0.5/24; } } }\n}\n"); err != nil {
		t.Fatalf("merge configured interface: %v", err)
	}
	// Merging the same instance with an empty body must not append a leaf
	// twin that the #9838 gate then refuses.
	if err := s.LoadMerge("interfaces {\n ge-0/0/0 { }\n}\n"); err != nil {
		t.Fatalf("merge no-op interface: %v", err)
	}
	cfg, err := s.CommitCheck()
	if err != nil {
		t.Fatalf("no-op interface merge: want a commit, got %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Units[0] == nil {
		t.Fatalf("no-op interface merge: the configured unit 0 went missing: %+v", ifc)
	}

	s = loadMergeStore9838(t)
	if err := s.LoadMerge("routing-instances {\n ri1 { instance-type virtual-router; }\n}\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"); err != nil {
		t.Fatalf("merge configured RI: %v", err)
	}
	if err := s.LoadMerge("routing-instances {\n ri1 { }\n}\n"); err != nil {
		t.Fatalf("merge no-op RI: %v", err)
	}
	cfg, err = s.CommitCheck()
	if err != nil {
		t.Fatalf("no-op RI merge: want a commit, got %v", err)
	}
	gotType := ""
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ri1" {
			gotType = ri.InstanceType
		}
	}
	if gotType != "virtual-router" {
		t.Fatalf("no-op RI merge: want ri1 keeping instance-type virtual-router, got %q", gotType)
	}
}

// TestLoadMergeBareLeafNormalizes9838 pins the one ingress difference, and
// why it is inherent rather than a hole: flat `set` has no spelling for a
// leaf at a container position, so the merge replay rebuilds the line as the
// empty container — the same text refused by CheckText / LoadOverride (which
// see the raw hierarchical shape) commits here as the empty instance. That
// is also what Junos `load merge` does with `ge-0/0/0;`: Junos has no bare
// instance leaves to preserve.
func TestLoadMergeBareLeafNormalizes9838(t *testing.T) {
	s := loadMergeStore9838(t)
	if err := s.LoadMerge("interfaces {\n ge-0/0/0;\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"); err != nil {
		t.Fatalf("merge leaf interface: %v", err)
	}
	cfg, err := s.CommitCheck()
	if err != nil {
		t.Fatalf("leaf interface via LoadMerge: want the normalized commit, got %v", err)
	}
	if cfg.Interfaces.Interfaces["ge-0/0/0"] == nil {
		t.Fatalf("leaf interface via LoadMerge: want ge-0/0/0 committed as the empty instance")
	}
	if joined := strings.Join(cfg.Warnings, "\n"); strings.Contains(joined, "#9838") {
		t.Fatalf("leaf interface via LoadMerge: want no #9838 refusal or warning, got %q", joined)
	}

	s = loadMergeStore9838(t)
	if err := s.LoadMerge("routing-instances {\n ri1;\n}\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"); err != nil {
		t.Fatalf("merge leaf RI: %v", err)
	}
	cfg, err = s.CommitCheck()
	if err != nil {
		t.Fatalf("leaf RI via LoadMerge: want the normalized commit, got %v", err)
	}
	found := false
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ri1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("leaf RI via LoadMerge: want ri1 committed as the empty instance")
	}
}

// TestLoadOverrideBareLeafRefused9838 is the other side of the pinned
// ingress asymmetry: `load override` splices the RAW hierarchical parse
// (no FormatSet round trip), so the bare leaf reaches CommitCheck as a
// leaf and is refused — the same text `load merge` normalizes and commits
// (TestLoadMergeBareLeafNormalizes9838). One ingress must not silently
// unify with or invert the other.
func TestLoadOverrideBareLeafRefused9838(t *testing.T) {
	s := loadMergeStore9838(t)
	if err := s.LoadOverride("interfaces {\n ge-0/0/0;\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"); err != nil {
		t.Fatalf("override leaf interface: %v", err)
	}
	if _, err := s.CommitCheck(); err == nil ||
		!strings.Contains(err.Error(), "interfaces ge-0/0/0") ||
		!strings.Contains(err.Error(), "#9838") {
		t.Fatalf("override leaf interface: want the #9838 refusal naming interfaces ge-0/0/0, got %v", err)
	}

	s = loadMergeStore9838(t)
	if err := s.LoadOverride("routing-instances {\n ri1;\n}\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"); err != nil {
		t.Fatalf("override leaf RI: %v", err)
	}
	if _, err := s.CommitCheck(); err == nil ||
		!strings.Contains(err.Error(), "routing-instances ri1") ||
		!strings.Contains(err.Error(), "#9838") {
		t.Fatalf("override leaf RI: want the #9838 refusal naming routing-instances ri1, got %v", err)
	}

	// Controls: braced empties through override commit with the instance.
	s = loadMergeStore9838(t)
	if err := s.LoadOverride("interfaces {\n ge-0/0/0 { }\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"); err != nil {
		t.Fatalf("override braced interface: %v", err)
	}
	cfg, err := s.CommitCheck()
	if err != nil {
		t.Fatalf("override braced interface: want a commit, got %v", err)
	}
	if cfg.Interfaces.Interfaces["ge-0/0/0"] == nil {
		t.Fatalf("override braced interface: ge-0/0/0 missing from the committed config")
	}

	s = loadMergeStore9838(t)
	if err := s.LoadOverride("routing-instances {\n ri1 { }\n}\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"); err != nil {
		t.Fatalf("override braced RI: %v", err)
	}
	cfg, err = s.CommitCheck()
	if err != nil {
		t.Fatalf("override braced RI: want a commit, got %v", err)
	}
	found := false
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ri1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("override braced RI: ri1 missing from the committed config")
	}
}

// TestMixedIngressGroupsLeafStaysSingle9838: `groups { G; }` is a
// legitimate bodyless group. Merging an empty `G { }` replays `set groups
// G`, which must reuse the leaf — not twin it into a container the
// duplicate-group gate (#5180) then refuses.
func TestMixedIngressGroupsLeafStaysSingle9838(t *testing.T) {
	s := loadMergeStore9838(t)
	base := "groups {\n G;\n}\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"
	if err := s.LoadOverride(base); err != nil {
		t.Fatalf("override group leaf: %v", err)
	}
	if err := s.LoadMerge("groups {\n G { }\n}\n"); err != nil {
		t.Fatalf("merge empty group: %v", err)
	}
	if _, err := s.CommitCheck(); err != nil {
		t.Fatalf("group leaf + empty merge: want a commit (one group G), got %v", err)
	}
}

// TestMixedIngressGroupsContainerStaysSingle9838: the same merge into a
// CONFIGURED group must leave the one container and its body alone. The
// body sets the hostname through apply-groups, so the compiled config
// proves both single-ness (no #5180 refusal) and intactness.
func TestMixedIngressGroupsContainerStaysSingle9838(t *testing.T) {
	s := loadMergeStore9838(t)
	base := "groups {\n G {\n system {\n host-name from-group;\n }\n }\n}\napply-groups G;\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"
	if err := s.LoadOverride(base); err != nil {
		t.Fatalf("override configured group: %v", err)
	}
	if err := s.LoadMerge("groups {\n G { }\n}\n"); err != nil {
		t.Fatalf("merge empty group: %v", err)
	}
	cfg, err := s.CommitCheck()
	if err != nil {
		t.Fatalf("configured group + empty merge: want a commit (one group G), got %v", err)
	}
	if cfg.System.HostName != "from-group" {
		t.Fatalf("configured group + empty merge: want hostname from-group, got %q", cfg.System.HostName)
	}
}

// TestMixedIngressMonitorLeafUnchanged9838: a bodyless ip-monitoring address
// leaf is a legitimate target (weight inherits global-weight). Merging the
// same address as an empty container must not twin it into a second target
// whose weight the runtime would sum independently. The compiled monitor
// config before and after the merge must be identical.
func TestMixedIngressMonitorLeafUnchanged9838(t *testing.T) {
	base := `chassis {
  cluster {
    cluster-id 1;
    authentication-key test-cluster-psk-6611;
    node 0;
    redundancy-group 1 {
      node 0 { priority 200; }
      ip-monitoring {
        global-weight 100;
        global-threshold 200;
        family inet {
          10.0.1.1;
        }
      }
    }
  }
}
interfaces {
  ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }
}
`
	merge := `chassis {
  cluster {
    redundancy-group 1 {
      ip-monitoring {
        family inet {
          10.0.1.1 { }
        }
      }
    }
  }
}
`
	snapshot := func(t *testing.T, s *Store) (targets int, addr string, weight int) {
		t.Helper()
		cfg, err := s.CommitCheck()
		if err != nil {
			t.Fatalf("CommitCheck: %v", err)
		}
		if cfg.Chassis.Cluster == nil {
			t.Fatal("want a compiled cluster")
		}
		for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
			if rg.IPMonitoring == nil {
				continue
			}
			for _, tgt := range rg.IPMonitoring.Targets {
				targets++
				addr, weight = tgt.Address, tgt.Weight
			}
		}
		return targets, addr, weight
	}
	s := loadMergeStore9838(t)
	if err := s.LoadOverride(base); err != nil {
		t.Fatalf("override monitor leaf: %v", err)
	}
	n0, a0, w0 := snapshot(t, s)
	if n0 != 1 || a0 != "10.0.1.1" {
		t.Fatalf("pre-merge: want exactly target 10.0.1.1, got %d targets addr=%q weight=%d", n0, a0, w0)
	}
	if err := s.LoadMerge(merge); err != nil {
		t.Fatalf("merge empty address: %v", err)
	}
	n1, a1, w1 := snapshot(t, s)
	if n1 != 1 || a1 != "10.0.1.1" || w1 != w0 {
		t.Fatalf("post-merge: want the unchanged single target (addr=%q weight=%d), got %d targets addr=%q weight=%d", a0, w0, n1, a1, w1)
	}
}

// TestMixedIngressBareLeafStillRefused9838: identity-preserving replay must
// NOT erase genuine #9838 refusal evidence. A bare leaf in the candidate
// plus an empty-braced merge of the same name still refuses.
func TestMixedIngressBareLeafStillRefused9838(t *testing.T) {
	s := loadMergeStore9838(t)
	if err := s.LoadOverride("interfaces {\n ge-0/0/0;\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"); err != nil {
		t.Fatalf("override leaf interface: %v", err)
	}
	if err := s.LoadMerge("interfaces {\n ge-0/0/0 { }\n}\n"); err != nil {
		t.Fatalf("merge empty interface: %v", err)
	}
	if _, err := s.CommitCheck(); err == nil ||
		!strings.Contains(err.Error(), "interfaces ge-0/0/0") ||
		!strings.Contains(err.Error(), "#9838") {
		t.Fatalf("iface leaf + empty merge: want the surviving #9838 refusal, got %v", err)
	}

	s = loadMergeStore9838(t)
	if err := s.LoadOverride("routing-instances {\n ri1;\n}\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"); err != nil {
		t.Fatalf("override leaf RI: %v", err)
	}
	if err := s.LoadMerge("routing-instances {\n ri1 { }\n}\n"); err != nil {
		t.Fatalf("merge empty RI: %v", err)
	}
	if _, err := s.CommitCheck(); err == nil ||
		!strings.Contains(err.Error(), "routing-instances ri1") ||
		!strings.Contains(err.Error(), "#9838") {
		t.Fatalf("RI leaf + empty merge: want the surviving #9838 refusal, got %v", err)
	}
}

// TestCrossRootNoOpMergeCommits9838: the target lives CONFIGURED in the
// second of two disjoint top-level roots (a raw LoadOverride retains
// both). Merging it empty replays a terminal `set` line that SetPath
// must resolve cross-root — root 1 must not gain an empty twin (a #5180
// duplicate refusal for interfaces, a doubled instance for
// routing-instances).
func TestCrossRootNoOpMergeCommits9838(t *testing.T) {
	s := loadMergeStore9838(t)
	ov := "interfaces {\n ge-0/0/9 { unit 0 { family inet { address 10.9.9.9/24; } } }\n}\ninterfaces {\n ge-0/0/0 { unit 0 { family inet { address 10.0.0.5/24; } } }\n}\n"
	if err := s.LoadOverride(ov); err != nil {
		t.Fatalf("override split roots: %v", err)
	}
	if err := s.LoadMerge("interfaces {\n ge-0/0/0 { }\n}\n"); err != nil {
		t.Fatalf("merge empty interface: %v", err)
	}
	cfg, err := s.CommitCheck()
	if err != nil {
		t.Fatalf("cross-root no-op interface merge: want a commit, got %v", err)
	}
	ifc := cfg.Interfaces.Interfaces["ge-0/0/0"]
	if ifc == nil || ifc.Units[0] == nil {
		t.Fatalf("cross-root no-op interface merge: the configured unit 0 went missing: %+v", ifc)
	}

	s = loadMergeStore9838(t)
	ov = "routing-instances {\n ri9 { instance-type virtual-router; }\n}\nrouting-instances {\n ri1 { instance-type virtual-router; }\n}\ninterfaces {\n ge-0/0/1 { unit 0 { family inet { address 10.0.0.1/24; } } }\n}\n"
	if err := s.LoadOverride(ov); err != nil {
		t.Fatalf("override split RI roots: %v", err)
	}
	if err := s.LoadMerge("routing-instances {\n ri1 { }\n}\n"); err != nil {
		t.Fatalf("merge empty RI: %v", err)
	}
	cfg, err = s.CommitCheck()
	if err != nil {
		t.Fatalf("cross-root no-op RI merge: want a commit, got %v", err)
	}
	n, typed := 0, 0
	for _, ri := range cfg.RoutingInstances {
		if ri.Name == "ri1" {
			n++
			if ri.InstanceType == "virtual-router" {
				typed++
			}
		}
	}
	if n != 1 || typed != 1 {
		t.Fatalf("cross-root no-op RI merge: want the one typed ri1, got %d instances (%d typed)", n, typed)
	}
}
