package configstore

import (
	"errors"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/config"
)

// minimal valid day-0 style config: management DHCP plus a zone.
const checkValidConfig = `
system {
    host-name day0-test;
}
interfaces {
    fxp0 {
        unit 0 {
            family inet {
                dhcp;
            }
        }
    }
}
`

func TestCheckTextValid(t *testing.T) {
	cfg, err := CheckText(checkValidConfig, -1)
	if err != nil {
		t.Fatalf("CheckText(valid) = %v, want nil", err)
	}
	if cfg == nil || cfg.System.HostName != "day0-test" {
		t.Fatalf("CheckText(valid) compiled config missing host-name: %+v", cfg)
	}
}

// CheckText must parse exactly the same representation as the real
// load-override bootstrap import (#10734): a Junos comment mentioning a flat
// verb must not reroute a hierarchical file, and display-set output must be
// accepted by the check-config gate.
func TestCheckTextMatchesLoadOverrideFormat10734(t *testing.T) {
	tree, errs := config.NewParser(checkValidConfig).Parse()
	if len(errs) != 0 {
		t.Fatalf("fixture parse: %v", errs[0])
	}
	flat := "/* saved from show configuration | display set */\n" + tree.FormatSet()
	cases := []struct {
		name, content string
	}{
		{
			name: "hierarchical comment contains delete prose",
			content: checkValidConfig + "\n/*\n" +
				"delete after the maintenance window, not before.\n*/\n",
		},
		{name: "flat display-set file", content: flat},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			compiled, err := CheckText(tc.content, -1)
			if err != nil {
				t.Fatalf("CheckText = %v, want importer-compatible parse and compile", err)
			}
			if compiled == nil || compiled.System.HostName != "day0-test" {
				t.Fatalf("CheckText compiled wrong configuration: %+v", compiled)
			}

			store := newTestStore(t)
			if err := store.EnterConfigure(); err != nil {
				t.Fatal(err)
			}
			if err := store.LoadOverride(tc.content); err != nil {
				t.Fatalf("LoadOverride = %v, want same accepted input as CheckText", err)
			}
			if got := store.ShowCandidateSet(); !strings.Contains(got, "set system host-name day0-test") {
				t.Fatalf("imported candidate lost host-name:\n%s", got)
			}
		})
	}
}

func TestCheckTextParseError(t *testing.T) {
	if _, err := CheckText("system { host-name {{{", -1); err == nil {
		t.Fatal("CheckText(garbage) = nil, want parse error")
	} else if !strings.Contains(err.Error(), "parse error") {
		t.Fatalf("CheckText(garbage) = %v, want parse error", err)
	}
}

// The strict gate must reject what a real commit rejects: the retired
// eBPF dataplane is a compile-time hard reject (#1373/#1476).
func TestCheckTextRetiredDataplaneRejected(t *testing.T) {
	conf := checkValidConfig + `
system {
    dataplane-type ebpf;
}
`
	_, err := CheckText(conf, -1)
	if err == nil {
		t.Fatal("CheckText(dataplane-type ebpf) = nil, want retired-dataplane reject")
	}
	if !errors.Is(err, config.ErrEBPFDataplaneRetired) {
		t.Fatalf("CheckText(dataplane-type ebpf) = %v, want ErrEBPFDataplaneRetired", err)
	}
}

// Typed-leaf SchemaValidate gate must fire exactly as it does on the
// operator commit path (#1319).
func TestCheckTextSchemaValidateGate(t *testing.T) {
	conf := checkValidConfig + `
chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        reth-advertise-interval garbage;
    }
}
`
	if _, err := CheckText(conf, -1); err == nil {
		t.Fatal("CheckText(typed-leaf garbage) = nil, want schema validation error")
	}
}

// ${node} apply-groups must expand for an explicit cluster node ID the
// same way Store.Commit does with SetNodeID.
func TestCheckTextNodeExpansion(t *testing.T) {
	conf := `
groups {
    node0 {
        system {
            host-name fw0;
        }
    }
    node1 {
        system {
            host-name fw1;
        }
    }
}
apply-groups "${node}";
` + checkValidConfig

	for _, nodeID := range []int{0, 1} {
		cfg, err := CheckText(conf, nodeID)
		if err != nil {
			t.Fatalf("CheckText(node %d) = %v, want nil", nodeID, err)
		}
		if cfg == nil {
			t.Fatalf("CheckText(node %d) returned nil config", nodeID)
		}
	}

	// Standalone (-1) keeps the historical "${node} → node0" fallback in
	// schemaValidateExpandedTreeForNode — must not hard-fail.
	if _, err := CheckText(conf, -1); err != nil {
		t.Fatalf("CheckText(standalone with ${node} groups) = %v, want nil", err)
	}
}

// #4185 (H-12): the strict gate must reject a config whose `chassis cluster
// node` leaf disagrees with the effective node identity (the /etc/xpf/node-id
// file value on commit, or -node-id on check-config). A silent mismatch yields
// two half-identities on the wire with no diagnostic. RED-on-revert: without
// the crossCheckNodeID gate, the -node-id 1 case below PASSES.
func TestCheckTextNodeIDMismatchRejected(t *testing.T) {
	// Literal `chassis cluster node 0` (as if copied from node 0's config).
	conf := checkValidConfig + `
chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
        node 0;
    }
}
`
	// File/flag says node 1, leaf resolves to 0 → mismatch → reject.
	if _, err := CheckText(conf, 1); err == nil {
		t.Fatal("CheckText(node leaf 0, -node-id 1) = nil, want node-identity mismatch reject")
	} else if !strings.Contains(err.Error(), "node identity mismatch") {
		t.Fatalf("CheckText mismatch error = %v, want 'node identity mismatch'", err)
	}

	// Agreement (leaf 0, node 0) must pass.
	if _, err := CheckText(conf, 0); err != nil {
		t.Fatalf("CheckText(node leaf 0, -node-id 0) = %v, want nil (identities agree)", err)
	}

	// Standalone (-1) never cross-checks — the leaf is advisory there.
	if _, err := CheckText(conf, -1); err != nil {
		t.Fatalf("CheckText(node leaf 0, standalone) = %v, want nil (no cross-check)", err)
	}
}

// #4185: a config with a cluster stanza but NO explicit `node` leaf must NOT
// false-reject on a node-1 box — an absent leaf is not "node 0". RED-on-revert
// if the cross-check keyed off NodeID's zero default instead of NodeIDSet.
func TestCheckTextNoNodeLeafNoFalseReject(t *testing.T) {
	conf := checkValidConfig + `
chassis {
    cluster {
        authentication-key test-cluster-psk-6611;
        cluster-id 1;
    }
}
`
	for _, nodeID := range []int{0, 1} {
		if _, err := CheckText(conf, nodeID); err != nil {
			t.Fatalf("CheckText(no node leaf, -node-id %d) = %v, want nil (absent leaf != node 0)", nodeID, err)
		}
	}
}
