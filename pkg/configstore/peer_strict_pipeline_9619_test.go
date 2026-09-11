package configstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// #9619: a shared chassis-cluster commit must be refused when the PEER node's
// effective view breaks any strict gate, not only the two #5876/#4785 registry
// subjects. The witnesses are the ones the issue executed: a value valid in
// node0's group and out of range in node1's, selected by `apply-groups
// "${node}"`, which node1's own commit rejects and node0's commit used to accept.

// peerStrictGroup renders one `groups nodeN` body. clusterLeaf goes under
// `chassis cluster`, systemLeaf under `system dataplane`; either may be empty.
func peerStrictGroup(node int, clusterLeaf, systemLeaf string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "    node%d {\n        chassis {\n            cluster {\n                node %d;\n", node, node)
	if clusterLeaf != "" {
		fmt.Fprintf(&b, "                %s;\n", clusterLeaf)
	}
	b.WriteString("            }\n        }\n")
	if systemLeaf != "" {
		fmt.Fprintf(&b, "        system {\n            dataplane {\n                %s;\n            }\n        }\n", systemLeaf)
	}
	b.WriteString("    }\n")
	return b.String()
}

// peerStrictClusterText is a keyed two-node cluster config (the #6611 gate needs
// the key) with the given per-node group bodies.
func peerStrictClusterText(node0, node1 string) string {
	return "groups {\n" + node0 + node1 + "}\n" + `chassis {
    cluster {
        cluster-id 1;
        reth-count 2;
        authentication-key "peer-strict-9619-psk-long-enough";
    }
}
apply-groups "${node}";
`
}

func parsePeerStrictText(t *testing.T, text string) *config.ConfigTree {
	t.Helper()
	tree, errs := config.NewParser(text).Parse()
	if len(errs) > 0 {
		t.Fatalf("precondition: fixture must parse: %v\n%s", errs[0], text)
	}
	return tree
}

type peerStrictWitness struct {
	name                      string
	cluster, system           string // the leaf in the BAD node's group
	goodCluster, goodSystem   string // the same leaf, in range, in the other group
	validCluster, validSystem string // the in-range control for the bad node
	wantValue                 string // the offending value, which the rejection must quote
}

var peerStrictWitnesses = []peerStrictWitness{
	{
		name:        "ring-entries",
		system:      "ring-entries 16385",
		goodSystem:  "ring-entries 1024",
		validSystem: "ring-entries 16384",
		wantValue:   "16385",
	},
	{
		name:         "reth-advertise-interval",
		cluster:      "reth-advertise-interval 40960",
		goodCluster:  "reth-advertise-interval 30",
		validCluster: "reth-advertise-interval 40950",
		wantValue:    "40960",
	},
}

// textWithBadNode puts the witness's invalid leaf in badNode's group and the
// in-range leaf in the other node's group.
func (w peerStrictWitness) textWithBadNode(badNode int) string {
	bad := peerStrictGroup(badNode, w.cluster, w.system)
	good := peerStrictGroup(1-badNode, w.goodCluster, w.goodSystem)
	if badNode == 0 {
		return peerStrictClusterText(bad, good)
	}
	return peerStrictClusterText(good, bad)
}

func (w peerStrictWitness) validText() string {
	return peerStrictClusterText(
		peerStrictGroup(0, w.goodCluster, w.goodSystem),
		peerStrictGroup(1, w.validCluster, w.validSystem))
}

// TestPeerOnlyValueRejectedAtOriginCommit_9619 is the issue's executed witness
// pair, in both roles: authored on node0 with the bad value in `groups node1`,
// and authored on node1 with it in `groups node0`.
//
// RED-on-revert: drop the validatePeerStrictPipeline call from compileTreeStrict
// and the origin commit returns nil ("ACCEPTED").
func TestPeerOnlyValueRejectedAtOriginCommit_9619(t *testing.T) {
	for _, w := range peerStrictWitnesses {
		for _, origin := range []int{0, 1} {
			peer := 1 - origin
			t.Run(fmt.Sprintf("%s/origin_node%d", w.name, origin), func(t *testing.T) {
				tree := parsePeerStrictText(t, w.textWithBadNode(peer))

				// The bad node's OWN commit refuses the value, and for its own
				// reason: this is what makes the origin's acceptance a gap
				// rather than a policy.
				_, own := compileTreeStrict(tree, peer)
				if own == nil {
					t.Fatalf("precondition: node%d's own strict commit must reject %s", peer, w.wantValue)
				}
				if !strings.Contains(own.Error(), w.wantValue) {
					t.Fatalf("precondition: node%d's own rejection must be about %s: %v", peer, w.wantValue, own)
				}

				_, err := compileTreeStrict(tree, origin)
				if err == nil {
					t.Fatalf("node%d ACCEPTED a shared commit whose node%d view carries %s, "+
						"which node%d's own commit rejects; config-sync installs it there "+
						"through the tolerant ingress", origin, peer, w.wantValue, peer)
				}
				for _, want := range []string{fmt.Sprintf("peer node%d", peer), w.wantValue} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("rejection missing %q: %v", want, err)
					}
				}
			})
		}
	}
}

// TestPeerValidControlsStillCommit_9619 is the negative control: the in-range
// value at the boundary commits on both nodes, so the gate is not passing the
// witness cells by refusing every per-node group.
func TestPeerValidControlsStillCommit_9619(t *testing.T) {
	for _, w := range peerStrictWitnesses {
		tree := parsePeerStrictText(t, w.validText())
		for _, node := range []int{0, 1} {
			if _, err := compileTreeStrict(tree, node); err != nil {
				t.Errorf("%s: node%d rejected the in-range control: %v", w.name, node, err)
			}
		}
	}
}

// TestShippedHAConfigsCheckCleanOnBothNodes_9619 runs the shipped cluster
// configs through check-config for both node ids. They are the one real
// population of shared configs in the repo, and a peer gate that refused them
// would refuse every deployment that starts from them.
func TestShippedHAConfigsCheckCleanOnBothNodes_9619(t *testing.T) {
	for _, name := range []string{"ha-cluster.conf", "ha-cluster-userspace.conf"} {
		b, err := os.ReadFile(filepath.Join("..", "..", "docs", name))
		if err != nil {
			t.Fatalf("read docs/%s: %v", name, err)
		}
		for _, node := range []int{0, 1} {
			if _, err := CheckText(string(b), node); err != nil {
				t.Errorf("docs/%s: check-config for node%d rejected the shipped config: %v", name, node, err)
			}
		}
	}
}

// TestPeerViewThatDoesNotCompileIsRejected_9619 covers the registry's skip arm.
// Only `groups node0` exists, so node1's `${node}` expansion names an undefined
// group and node1 cannot compile the config at all — ValidatePeerEffectiveStrict
// returns nil for that by design, and the commit used to pass having checked
// nothing about node1.
func TestPeerViewThatDoesNotCompileIsRejected_9619(t *testing.T) {
	text := "groups {\n" + peerStrictGroup(0, "", "") + "}\n" + `chassis {
    cluster {
        cluster-id 1;
        reth-count 2;
        authentication-key "peer-strict-9619-psk-long-enough";
    }
}
apply-groups "${node}";
`
	tree := parsePeerStrictText(t, text)
	if _, err := config.CompileConfigForNodeLenient(tree, 1); err == nil {
		t.Fatal("precondition: node1's view must fail even the tolerant compile, " +
			"or this is not the registry's skip arm")
	}
	if err := config.ValidatePeerEffectiveStrict(tree, 0); err != nil {
		t.Fatalf("precondition: the registry must skip an uncompilable peer view: %v", err)
	}
	// The consequence: node1's config-sync ingress cannot apply this tree, so
	// accepting it on node0 leaves node1 unable to follow the commit.
	peer := newTestStore(t)
	peer.SetNodeID(1)
	if _, err := peer.SyncApply(text, nil); err == nil {
		t.Fatal("precondition: node1's SyncApply must fail on this tree, " +
			"or refusing it at the origin is an over-rejection")
	}
	_, err := compileTreeStrict(tree, 0)
	if err == nil {
		t.Fatal("node0 ACCEPTED a shared commit that node1 cannot compile at all")
	}
	if !strings.Contains(err.Error(), "peer node1") {
		t.Errorf("rejection must name the peer: %v", err)
	}
}

// TestPeerStrictPipelineStandaloneNoOp_9619 pins that a standalone node runs no
// peer pipeline. The tree is invalid in BOTH node groups, so any node id the
// pipeline picked for a standalone caller would fail.
func TestPeerStrictPipelineStandaloneNoOp_9619(t *testing.T) {
	w := peerStrictWitnesses[0]
	text := peerStrictClusterText(
		peerStrictGroup(0, "", w.system),
		peerStrictGroup(1, "", w.system))
	tree := parsePeerStrictText(t, text)
	if err := validatePeerStrictPipeline(tree, 1); err == nil {
		t.Fatal("precondition: the pipeline must reject this tree for a clustered caller")
	}
	if err := validatePeerStrictPipeline(tree, -1); err != nil {
		t.Fatalf("standalone (nodeID -1) ran a peer pipeline: %v", err)
	}

	standalone := parsePeerStrictText(t, "system {\n    dataplane {\n        ring-entries 16384;\n    }\n}\n")
	if _, err := compileTreeStrict(standalone, -1); err != nil {
		t.Fatalf("a clean standalone config must still commit: %v", err)
	}
}

// TestCheckTextRejectsPeerOnlyValue_9619 covers the day-0 `xpfd check-config`
// caller, which shares compileTreeStrict with the commit path.
func TestCheckTextRejectsPeerOnlyValue_9619(t *testing.T) {
	w := peerStrictWitnesses[0]
	_, err := CheckText(w.textWithBadNode(1), 0)
	if err == nil {
		t.Fatal("check-config for node0 ACCEPTED a config whose node1 view is invalid")
	}
	if !strings.Contains(err.Error(), "peer node1") {
		t.Errorf("rejection must name the peer: %v", err)
	}
}

// TestStoreCommitCheckRejectsPeerOnlyValue_9619 drives the operator path
// through the Store rather than the helper, so the wiring from CommitCheck to
// compileTreeStrict is bound too.
func TestStoreCommitCheckRejectsPeerOnlyValue_9619(t *testing.T) {
	w := peerStrictWitnesses[1]
	s := newTestStore(t)
	s.SetNodeID(0)
	if err := s.EnterConfigure(); err != nil {
		t.Fatalf("EnterConfigure: %v", err)
	}
	if err := s.LoadOverride(w.textWithBadNode(1)); err != nil {
		t.Fatalf("LoadOverride: %v", err)
	}
	_, err := s.CommitCheck()
	if err == nil {
		t.Fatal("Store.CommitCheck on node0 ACCEPTED a peer-only out-of-range reth-advertise-interval")
	}
	if !strings.Contains(err.Error(), "peer node1") || !strings.Contains(err.Error(), w.wantValue) {
		t.Errorf("rejection must name the peer and the value: %v", err)
	}
}

// TestTolerantIngressStillLoadsPeerInvalidTree_9619 is the no-brick half of the
// acceptance: a node that receives, or already has on disk, a tree whose own
// view is invalid still loads it with the value intact. Both ingresses are
// driven because they are separate call sites into compileTreeLenient.
func TestTolerantIngressStillLoadsPeerInvalidTree_9619(t *testing.T) {
	w := peerStrictWitnesses[0]
	text := w.textWithBadNode(1)

	t.Run("sync_apply", func(t *testing.T) {
		s := newTestStore(t)
		s.SetNodeID(1)
		cfg, err := s.SyncApply(text, nil)
		if err != nil {
			t.Fatalf("SyncApply REFUSED a tree invalid on this node; config-sync would alarm-loop: %v", err)
		}
		if cfg == nil || cfg.System.UserspaceDataplane == nil || cfg.System.UserspaceDataplane.RingEntries != 16385 {
			t.Fatalf("SyncApply must keep the tolerated value, got %+v", cfg)
		}
	})

	t.Run("load", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config")
		if err := newTestStoreAt(t, path).db.WriteActiveMarker(parsePeerStrictText(t, text), true); err != nil {
			t.Fatalf("precondition: persisting the tree must succeed: %v", err)
		}
		booted := newTestStoreAt(t, path)
		booted.SetNodeID(1)
		if err := booted.Load(); err != nil {
			t.Fatalf("Store.Load REFUSED a persisted tree invalid on this node; the node would boot unconfigured: %v", err)
		}
		cfg := booted.ActiveConfig()
		if cfg == nil || cfg.System.UserspaceDataplane == nil || cfg.System.UserspaceDataplane.RingEntries != 16385 {
			t.Fatalf("Store.Load must keep the tolerated value, got %+v", cfg)
		}
	})
}

// TestPeerOnlyCompileGateRejected_9619 isolates the peer COMPILE step. The
// schema admits reth-advertise-interval up to 40959 but the #9039 compile gate
// stops at 40950, so 40955 passes schema validation on node1's view and only
// config.CompileConfigForNode refuses it.
func TestPeerOnlyCompileGateRejected_9619(t *testing.T) {
	tree := parsePeerStrictText(t, peerStrictClusterText(
		peerStrictGroup(0, "reth-advertise-interval 30", ""),
		peerStrictGroup(1, "reth-advertise-interval 40955", "")))
	if err := schemaValidateExpandedTreeForNode(tree, 1); err != nil {
		t.Fatalf("precondition: the schema must admit 40955 on node1, or this cell "+
			"does not isolate the compile step: %v", err)
	}
	if _, err := compileTreeStrict(tree, 1); err == nil {
		t.Fatal("precondition: node1's own strict commit must reject 40955")
	}
	_, err := compileTreeStrict(tree, 0)
	if err == nil {
		t.Fatal("node0 ACCEPTED a shared commit whose node1 view fails the compile-side reth-advertise-interval gate")
	}
	for _, want := range []string{"peer node1", "40955"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("rejection missing %q: %v", want, err)
		}
	}
}

// peerStrictRAGroup renders a node group whose router-advertisement interface
// has max-advertisement-interval 12 and the given min.
func peerStrictRAGroup(node int, minInterval string) string {
	return fmt.Sprintf(`    node%d {
        chassis {
            cluster {
                node %d;
            }
        }
        protocols {
            router-advertisement {
                interface ge-%d-0-1 {
                    max-advertisement-interval 12;
                    min-advertisement-interval %s;
                }
            }
        }
    }
`, node, node, node*7, minInterval)
}

// TestPeerOnlyRAIntervalRatioRejected_9619 isolates crossCheckRAIntervals. Each
// leaf is in range on its own and the compile accepts it, so only the #4525
// ratio check (min <= 0.75*max) on node1's compiled view can refuse min 10 with
// max 12. node0's min 9 is exactly 0.75*12 and passes.
func TestPeerOnlyRAIntervalRatioRejected_9619(t *testing.T) {
	tree := parsePeerStrictText(t, peerStrictClusterText(peerStrictRAGroup(0, "9"), peerStrictRAGroup(1, "10")))
	if err := schemaValidateExpandedTreeForNode(tree, 1); err != nil {
		t.Fatalf("precondition: schema must admit node1's leaves: %v", err)
	}
	if _, err := config.CompileConfigForNode(tree, 1); err != nil {
		t.Fatalf("precondition: node1's compile must accept, or this cell does not isolate the ratio check: %v", err)
	}
	if _, err := compileTreeStrict(tree, 1); err == nil {
		t.Fatal("precondition: node1's own strict commit must reject min 10 with max 12")
	}
	_, err := compileTreeStrict(tree, 0)
	if err == nil {
		t.Fatal("node0 ACCEPTED a shared commit whose node1 view breaks the RFC 4861 min/max ratio")
	}
	for _, want := range []string{"peer node1", "min-advertisement-interval"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("rejection missing %q: %v", want, err)
		}
	}
}

// TestPeerOnlyRetiredDataplaneTypeStillCommits_9619 pins that the pipeline is
// given the tree the peer compiles, not the raw candidate (#6861 F2). node1's
// group carries a retired `dataplane-type dpdk`; node1's config-sync ingress
// strips it (rewriteRetiredDataplaneType, SyncCaller) and runs the rest, so the
// view node1 instantiates is valid and the origin's commit must not be refused
// for a leaf the standby never applies.
func TestPeerOnlyRetiredDataplaneTypeStillCommits_9619(t *testing.T) {
	text := "groups {\n" + peerStrictGroup(0, "", "") + `    node1 {
        chassis {
            cluster {
                node 1;
            }
        }
        system {
            dataplane-type dpdk;
        }
    }
}
` + `chassis {
    cluster {
        cluster-id 1;
        reth-count 2;
        authentication-key "peer-strict-9619-psk-long-enough";
    }
}
apply-groups "${node}";
`
	peer := newTestStore(t)
	peer.SetNodeID(1)
	if _, err := peer.SyncApply(text, nil); err != nil {
		t.Fatalf("precondition: node1's ingress must accept the tree once it strips the retired leaf: %v", err)
	}
	if err := validatePeerStrictPipeline(parsePeerStrictText(t, text), 0); err == nil {
		t.Fatal("precondition: on the RAW tree the peer pipeline must refuse the retired leaf, " +
			"or this cell cannot tell the rewritten tree from the raw one")
	}
	if _, err := compileTreeStrict(parsePeerStrictText(t, text), 0); err != nil {
		t.Fatalf("node0 refused a shared commit for a peer leaf node1's ingress strips; the "+
			"pipeline was handed the raw candidate instead of the rewritten clone: %v", err)
	}
}
