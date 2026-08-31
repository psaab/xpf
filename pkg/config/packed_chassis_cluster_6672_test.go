package config

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// #6672 — a packed `chassis cluster` body dropped the ENTIRE cluster stanza.
//
// A packed statement puts all its tokens on ONE node's Keys with no Children,
// and compileChassis read the body with FindChild, i.e. off `.Children`. Three
// of the four spellings therefore compiled nothing while the commit SUCCEEDED
// and `show configuration` echoed what the operator wrote:
//
//	chassis { cluster { ... } }        -> compiles
//	chassis { cluster <body>; }        -> a ClusterConfig with every field zero
//	chassis cluster { ... }            -> Cluster == nil
//	chassis cluster <body>;            -> Cluster == nil
//
// The issue named two of those three. The `chassis cluster { ... }` shape — the
// brace at the top level, so the body IS in Children but the `cluster` keyword
// is packed onto the chassis line — drops just as silently and is covered here.
//
// The blast radius is the whole stanza: cluster-id, node identity, the control
// PSK, the fabric addresses, and every redundancy group under it. At the
// redundancy-group level (#6588) the same shape lost one group's election
// priority; here it loses the cluster.

// clusterOracleValues supplies one VALID value per statement so a fixture can
// be generated for every entry in clusterStatements rather than for a
// hand-picked sample. An entry missing here fails
// TestEveryClusterStatementHasAnOracleValue_6672, so adding a statement to the
// table without adding a fixture for it is a build failure, not a silent
// coverage hole.
var clusterOracleValues = map[string]string{
	"cluster-id":                    "22",
	"node":                          "1",
	"reth-count":                    "2",
	"heartbeat-interval":            "200",
	"heartbeat-threshold":           "5",
	"authentication-key":            "primary-psk",
	"additional-authentication-key": "rollover-psk",
	"control-interface":             "em0",
	"peer-address":                  "10.99.0.2",
	"fabric-interface":              "fab0",
	"fabric-peer-address":           "10.98.0.2",
	"fabric1-interface":             "fab1",
	"fabric1-peer-address":          "10.97.0.2",
	"reth-advertise-interval":       "30",
	"peer-fencing":                  "disable-rg",
	"takeover-hold-time":            "5000",
	"redundancy-group":              "1 node 0 priority 200",

	"control-link-recovery":         "",
	"strict-session-auth":           "",
	"configuration-synchronize":     "",
	"nat-state-synchronization":     "",
	"ipsec-session-synchronization": "",
	"dhcp-lease-synchronization":    "",
	"hitless-restart":               "",
	"no-reth-vrrp":                  "",
	"private-rg-election":           "",
	"no-private-rg-election":        "",
	"control-ports":                 "",
}

// clusterCompilerOnlyStatements are compiled by compileChassis but NOT declared
// in schemaChassis, so they have no tab completion and no typed-leaf validator.
// This set exists so the agreement test below can be an EQUALITY rather than a
// one-sided containment: when the schema gains these leaves, the test fails and
// the entry must be deleted here in the same change.
//
// EMPTY since #7448. It held `fabric1-interface` and `fabric1-peer-address`,
// the last two #6663-class divergences under `chassis cluster`; declaring them
// in schemaChassis is what emptied it. The equality half below did exactly what
// it was built to do — it fired on that commit and named both entries — so the
// set is kept, empty, rather than deleted along with its mechanism. An empty
// exception set is the correct steady state for a seam whose whole purpose is
// to make the NEXT divergence declare itself.
var clusterCompilerOnlyStatements = map[string]bool{}

func clusterSchemaChildren(t *testing.T) map[string]*schemaNode {
	t.Helper()
	cl := schemaChassis.children["cluster"]
	if cl == nil || len(cl.children) == 0 {
		t.Fatalf("schemaChassis has no cluster children — this test asserts nothing")
	}
	return cl.children
}

func compileClusterJSON6672(t *testing.T, src string) string {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture parse errors: %v\n%s", errs, src)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, src)
	}
	b, err := json.Marshal(cfg.Chassis.Cluster)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// clusterSpellings renders one cluster body in the four spellings. body is the
// statement text WITHOUT a trailing `;` and using packed (one-line) form; the
// container spelling wraps it in braces on its own line, which for a
// single-statement body is the same tokens with different structure.
func clusterSpellings(body string) map[string]string {
	return map[string]string{
		"container":         "chassis {\n    cluster {\n        " + body + ";\n    }\n}\n",
		"packed-in-chassis": "chassis {\n    cluster " + body + ";\n}\n",
		"packed-top-level":  "chassis cluster " + body + ";\n",
		"brace-top-level":   "chassis cluster {\n    " + body + ";\n}\n",
	}
}

// TestEveryClusterStatementCompilesTheSameInEverySpelling_6672 is the issue's
// acceptance: "pinned for every statement the cluster body admits, with a
// fail-on-revert test per statement rather than one aggregate assertion".
//
// One subtest per statement per spelling, so a revert names WHICH statement and
// WHICH spelling broke instead of failing one lump assertion. The oracle is the
// container spelling — the one that always worked — so the test cannot be
// satisfied by all four agreeing on nothing.
func TestEveryClusterStatementCompilesTheSameInEverySpelling_6672(t *testing.T) {
	keywords := make([]string, 0, len(clusterStatements))
	for kw := range clusterStatements {
		keywords = append(keywords, kw)
	}
	sort.Strings(keywords)

	for _, kw := range keywords {
		kw := kw
		t.Run(kw, func(t *testing.T) {
			val, ok := clusterOracleValues[kw]
			if !ok {
				t.Fatalf("no oracle value for %q", kw)
			}
			body := kw
			if val != "" {
				body += " " + val
			}
			spellings := clusterSpellings(body)
			want := compileClusterJSON6672(t, spellings["container"])

			// The oracle must be non-vacuous for every statement that has a
			// compiled effect: if the container form compiles to the same thing
			// as an EMPTY cluster body, the agreement below is satisfied by all
			// four spellings doing nothing.
			empty := compileClusterJSON6672(t, "chassis {\n    cluster {\n    }\n}\n")
			compiled := want != empty
			if !compiled && !clusterStatementIsKnownInert(kw) {
				t.Fatalf("container spelling of %q compiles to an empty cluster — "+
					"either the statement is not compiled (register it in "+
					"clusterStatementIsKnownInert with a reason) or the oracle "+
					"value %q is wrong", kw, val)
			}

			for _, spelling := range []string{"packed-in-chassis", "packed-top-level", "brace-top-level"} {
				got := compileClusterJSON6672(t, spellings[spelling])
				if got != want {
					t.Errorf("%s spelling of %q does not match the container spelling\n want %s\n  got %s",
						spelling, kw, want, got)
				}
			}
		})
	}
}

// clusterStatementIsKnownInert names the statements with NO compiled effect, so
// the non-vacuity guard above can tell "correctly compiles nothing" from
// "silently dropped". Each needs a reason, because the default answer is that a
// statement the operator can write should do something.
func clusterStatementIsKnownInert(kw string) bool {
	switch kw {
	case "control-ports":
		// Accepted for Junos compatibility, never read by compileChassis
		// (schema_chassis.go documents the compiled-leaf-only invariant).
		return true
	case "node":
		// The oracle sets node 1, and NodeID/NodeIDSet do land — but on a
		// standalone parse the compiled node identity is later overridden by
		// the node-id file, so treat a no-delta result as acceptable rather
		// than asserting on it here.
		return false
	case "private-rg-election":
		// The DEFAULT is already true, so setting it explicitly is a no-op on
		// the compiled struct. Its negation (no-private-rg-election) is the one
		// with an effect, and that is covered by its own subtest.
		return true
	}
	return false
}

// TestEveryClusterStatementHasAnOracleValue_6672 keeps the generated fixture
// set complete: adding a statement to clusterStatements without a value here
// would silently skip it in the per-statement test above.
func TestEveryClusterStatementHasAnOracleValue_6672(t *testing.T) {
	for kw := range clusterStatements {
		if _, ok := clusterOracleValues[kw]; !ok {
			t.Errorf("clusterStatements has %q with no clusterOracleValues entry — "+
				"the per-statement agreement test would skip it", kw)
		}
	}
	for kw := range clusterOracleValues {
		if !isClusterStatement(kw) {
			t.Errorf("clusterOracleValues has %q, which is not a cluster statement", kw)
		}
	}
}

// TestClusterSplitterAndSchemaAgree_6672 binds the splitter table to the schema
// in BOTH directions, with the one known divergence named rather than tolerated.
//
// Direction 1 (schema => splitter) is the one that corrupts: a statement the
// operator can write and the schema completes, but the splitter does not know,
// FOLDS onto whichever statement precedes it on a packed line — so it silently
// does nothing AND corrupts its neighbour, while the same statement alone on a
// line still works. A developer therefore sees it work.
//
// Direction 2 (splitter => schema) catches the reverse: a statement registered
// here that the grammar does not admit would reserve value slots for tokens
// that can never appear.
//
// The ARITY must agree too. A splitter that reserves the wrong number of value
// tokens is worse than one that reserves none: it swallows the following
// statement.
func TestClusterSplitterAndSchemaAgree_6672(t *testing.T) {
	schemaChildren := clusterSchemaChildren(t)

	for kw, sn := range schemaChildren {
		arity, ok := clusterStatements[kw]
		if !ok {
			t.Errorf("schema declares `chassis cluster %s` but the packed-line splitter "+
				"does not know it — on a packed line its tokens FOLD onto the preceding "+
				"statement, so it silently does nothing and corrupts its neighbour", kw)
			continue
		}
		if arity != sn.args {
			t.Errorf("`chassis cluster %s`: splitter reserves %d value token(s), schema "+
				"declares args=%d — a wrong reservation swallows the NEXT statement",
				kw, arity, sn.args)
		}
	}

	for kw := range clusterStatements {
		if _, ok := schemaChildren[kw]; ok {
			continue
		}
		if clusterCompilerOnlyStatements[kw] {
			continue
		}
		t.Errorf("the splitter registers `chassis cluster %s`, which the schema does not "+
			"declare and which is not in the documented compiler-only set", kw)
	}

	// EQUALITY, not containment: when the schema gains a compiler-only leaf,
	// the exception must be deleted in the same change or this fires. Without
	// this half the exception set would silently outlive the divergence it
	// documents.
	for kw := range clusterCompilerOnlyStatements {
		if _, ok := schemaChildren[kw]; ok {
			t.Errorf("`chassis cluster %s` is now declared in the schema — delete it from "+
				"clusterCompilerOnlyStatements", kw)
		}
		if !isClusterStatement(kw) {
			t.Errorf("clusterCompilerOnlyStatements names %q, which the splitter does not register", kw)
		}
	}
}

var clusterFindChildRe = regexp.MustCompile(`clusterNode\.FindChild(?:ren)?\("([a-z0-9-]+)"\)`)

// TestEveryCompiledClusterStatementIsSplit_6672 is the BEHAVIOURAL binding
// between the compiler and the splitter table, and it is what stops the table
// falling behind compileChassis.
//
// The assertion is behavioural on purpose: for each candidate keyword the
// splitter does NOT register, the container spelling must compile to an EMPTY
// cluster. If it compiles to something, the compiler honours a statement the
// splitter will fold on a packed line.
//
// The candidate POPULATION is a floor, and saying so matters. It is the union
// of the schema's cluster children, the splitter table, and a source scan of
// compileChassis for `clusterNode.FindChild("...")` literals. The source scan
// is used only to WIDEN the population, never as the assertion — modelling one
// program's source text as an oracle is the tool #6588 removed, because it
// misses a case on a named CONSTANT, a statement handled by a helper outside
// the block, and dispatch nested inside another arm. A keyword missed by all
// three sources degrades to "not covered", which is where it already was.
func TestEveryCompiledClusterStatementIsSplit_6672(t *testing.T) {
	candidates := map[string]bool{}
	for kw := range clusterSchemaChildren(t) {
		candidates[kw] = true
	}
	for kw := range clusterStatements {
		candidates[kw] = true
	}

	src, err := os.ReadFile("compiler_system.go")
	if err != nil {
		t.Fatalf("read compiler_system.go: %v", err)
	}
	scanned := clusterFindChildRe.FindAllStringSubmatch(string(src), -1)
	if len(scanned) == 0 {
		t.Fatalf("the source scan found no clusterNode.FindChild literals — the " +
			"candidate population lost one of its three sources, so this test is " +
			"weaker than it reads")
	}
	for _, m := range scanned {
		candidates[m[1]] = true
	}

	empty := compileClusterJSON6672(t, "chassis {\n    cluster {\n    }\n}\n")
	names := make([]string, 0, len(candidates))
	for kw := range candidates {
		names = append(names, kw)
	}
	sort.Strings(names)

	for _, kw := range names {
		if isClusterStatement(kw) {
			continue
		}
		for _, val := range []string{"", "x", "1"} {
			body := kw
			if val != "" {
				body += " " + val
			}
			got := compileClusterJSON6672(t, "chassis {\n    cluster {\n        "+body+";\n    }\n}\n")
			if got != empty {
				t.Errorf("compileChassis honours `chassis cluster %s` but the splitter does "+
					"not register it — on a packed line its tokens fold onto the preceding "+
					"statement\n compiled: %s", body, got)
				break
			}
		}
	}
}

// TestPackedClusterDoesNotEscapeTheRangeGates_6672 is the reason this fix is
// not just the compiler change.
//
// Every typed cluster leaf is bounded by its schema validator, and the schema
// WALKER only reaches a statement at its modeled depth. A packed statement sits
// below that depth, so no validator fires on it. While the packed spelling
// compiled to nothing that was inert; the moment it compiles, writing the
// config on ONE LINE would have been a way to install an out-of-range value
// that the container spelling refuses — an ungated `cluster-id` is one byte of
// the RETH virtual MAC (256 aliases another cluster's MAC) and an ungated
// `reth-advertise-interval` is a 12-bit VRRP wire field (40960 encodes as 0).
//
// Every typed leaf is exercised, and the REJECTION MESSAGE must match the
// container spelling's — same validator, not a second bounds table that agrees
// today and drifts tomorrow.
func TestPackedClusterDoesNotEscapeTheRangeGates_6672(t *testing.T) {
	outOfRange := map[string]string{
		"cluster-id":              "999",
		"node":                    "7",
		"reth-count":              "0",
		"heartbeat-interval":      "0",
		"heartbeat-threshold":     "0",
		"reth-advertise-interval": "40960",
		"takeover-hold-time":      "-1",
		"peer-fencing":            "shoot-the-other-node",
	}

	// Guard the population: every typed (validator-bearing) leaf must have a
	// bad value here, or a leaf could gain a gate and quietly go uncovered.
	for kw, sn := range clusterSchemaChildren(t) {
		if sn.validator == nil {
			continue
		}
		if _, ok := outOfRange[kw]; !ok {
			t.Errorf("`chassis cluster %s` has a schema validator but no out-of-range "+
				"fixture — the packed spelling could escape it uncovered", kw)
		}
	}

	names := make([]string, 0, len(outOfRange))
	for kw := range outOfRange {
		names = append(names, kw)
	}
	sort.Strings(names)

	for _, kw := range names {
		kw := kw
		t.Run(kw, func(t *testing.T) {
			body := kw + " " + outOfRange[kw]
			spellings := clusterSpellings(body)

			containerErr := schemaValidateSrc6672(t, spellings["container"])
			if containerErr == nil {
				t.Fatalf("fixture bug: the CONTAINER spelling of %q accepts %q, so this "+
					"test cannot show the packed spelling escaping anything",
					kw, outOfRange[kw])
			}
			for _, spelling := range []string{"packed-in-chassis", "packed-top-level", "brace-top-level"} {
				err := schemaValidateSrc6672(t, spellings[spelling])
				if err == nil {
					t.Errorf("%s spelling of `%s` was ACCEPTED while the container spelling "+
						"was rejected with: %v", spelling, body, containerErr)
					continue
				}
				if err.Error() != containerErr.Error() {
					t.Errorf("%s spelling of `%s` was rejected by a DIFFERENT gate\n"+
						" container: %v\n %s: %v", spelling, body, containerErr, spelling, err)
				}
			}
		})
	}
}

func schemaValidateSrc6672(t *testing.T, src string) error {
	t.Helper()
	tree, errs := NewParser(src).Parse()
	if len(errs) > 0 {
		t.Fatalf("fixture parse errors: %v\n%s", errs, src)
	}
	return SchemaValidate(tree, nil)
}

// TestPackedRedundancyGroupKeepsItsOwnNode_6672 is the nesting rule, and the
// single token where the two tables overlap decides it.
//
// `node` is BOTH a cluster statement (this box's identity) and a
// redundancy-group statement (that group's per-node priority). Under a flat
// splitter `redundancy-group 1 node 0 priority 200` re-arms at `node`, which
// sets the CLUSTER's node identity and drops the group's election priority —
// exactly the failure #6588 exists to prevent, reintroduced one level up. The
// overlap must resolve to the INNER scope.
func TestPackedRedundancyGroupKeepsItsOwnNode_6672(t *testing.T) {
	// The cluster's own node identity is 1; the group's per-node priority is
	// for node 0. If the splitter re-arms at the group's `node`, the cluster
	// identity flips to 0 and the priority vanishes — both observable.
	body := "node 1 redundancy-group 1 node 0 priority 200 reth-count 2"
	want := compileClusterJSON6672(t, `
chassis {
    cluster {
        node 1;
        redundancy-group 1 {
            node 0 priority 200;
        }
        reth-count 2;
    }
}
`)
	for spelling, src := range clusterSpellings(body) {
		if spelling == "container" {
			continue
		}
		if got := compileClusterJSON6672(t, src); got != want {
			t.Errorf("%s: the redundancy-group's `node` was stolen by the cluster splitter\n want %s\n  got %s",
				spelling, want, got)
		}
	}

	// And the oracle itself must be non-trivial: assert the values it is
	// supposed to carry actually appear, so a fixture that compiled to an empty
	// cluster could not satisfy the comparison above.
	for _, want := range []string{`"NodeID":1`, `"RethCount":2`, `"0":200`} {
		if !strings.Contains(compileClusterJSON6672(t, clusterSpellings(body)["container"]), want) {
			t.Fatalf("fixture bug: the container oracle does not contain %s", want)
		}
	}
}

// TestPackedClusterStatementReservesItsValueSlot_6672 is the cluster-level
// #6665 property, and it needs a value that SPELLS A KEYWORD to be observable
// at all — every ordinary fixture value (`22`, `em0`, `10.99.0.2`) can never
// re-arm the splitter, so a fixture built from those varies the right axis and
// samples only the passing point.
//
// `control-interface node` is the shape: a control link named after the cluster
// statement that sets this box's NODE IDENTITY. Without the reservation the
// splitter opens a `node` statement in the value slot, so the control interface
// compiles empty AND the following `reth-count` token is consumed as the node
// id — a firewall that believes it is a different node and has no control link.
func TestPackedClusterStatementReservesItsValueSlot_6672(t *testing.T) {
	body := "control-interface node reth-count 2"
	want := compileClusterJSON6672(t, `
chassis {
    cluster {
        control-interface node;
        reth-count 2;
    }
}
`)
	for _, need := range []string{`"ControlInterface":"node"`, `"RethCount":2`, `"NodeIDSet":false`} {
		if !strings.Contains(want, need) {
			t.Fatalf("fixture bug: the container oracle does not contain %s: %s", need, want)
		}
	}
	for spelling, src := range clusterSpellings(body) {
		if spelling == "container" {
			continue
		}
		if got := compileClusterJSON6672(t, src); got != want {
			t.Errorf("%s: a keyword-shaped value token re-armed the cluster splitter\n want %s\n  got %s",
				spelling, want, got)
		}
	}
}

// TestPackedMonitorKeepsAKeywordShapedInterfaceName_6672 carries the #6665
// value-slot reservation across the nesting boundary.
//
// The redundancy-group splitter reserves `interface-monitor`'s one free-form
// identifier slot so a monitored interface whose NAME spells a statement
// keyword is not consumed as that statement. At the cluster level the same
// theft is available with a CLUSTER keyword: an interface literally named
// `reth-count` would re-arm the outer splitter. ValidateDeviceMapLogicalName
// admits keyword-shaped names, so this is a name an operator can configure.
func TestPackedMonitorKeepsAKeywordShapedInterfaceName_6672(t *testing.T) {
	body := "redundancy-group 1 interface-monitor reth-count weight 255"
	want := compileClusterJSON6672(t, `
chassis {
    cluster {
        redundancy-group 1 {
            interface-monitor reth-count weight 255;
        }
    }
}
`)
	if !strings.Contains(want, `"Interface":"reth-count"`) {
		t.Fatalf("fixture bug: the container oracle did not keep the keyword-shaped name: %s", want)
	}
	for spelling, src := range clusterSpellings(body) {
		if spelling == "container" {
			continue
		}
		if got := compileClusterJSON6672(t, src); got != want {
			t.Errorf("%s: a monitored interface named after a cluster keyword was stolen\n want %s\n  got %s",
				spelling, want, got)
		}
	}
}

// TestPackedClusterKeepsASiblingDeviceMap_6672 pins the #1956 R-7 invariant
// through the normalization: a `device-map` beside a packed cluster must not be
// dropped when the chassis node is rebuilt.
func TestPackedClusterKeepsASiblingDeviceMap_6672(t *testing.T) {
	tree, errs := NewParser(`
chassis {
    cluster cluster-id 22 node 1;
    device-map {
        interface fxp0 { pci 0000:05:00.0; }
    }
}
`).Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	cfg, err := CompileConfigLenient(tree)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if cfg.Chassis.Cluster == nil || cfg.Chassis.Cluster.ClusterID != 22 {
		t.Errorf("packed cluster body did not compile: %+v", cfg.Chassis.Cluster)
	}
	if cfg.Chassis.DeviceMap == nil || len(cfg.Chassis.DeviceMap.Entries) == 0 {
		t.Errorf("the sibling device-map was dropped by the cluster normalization")
	}
}

// TestSchemaWalkStillSeesSiblingsOfAPackedCluster_6672 guards the normalization
// REBUILD. The tree normalizer replaces the whole `chassis` node, so a sibling
// statement dropped there would vanish from the schema walk — and vanishing
// from a validator is invisible: the config gets MORE permissive, not less, so
// nothing fails and no test that only checks the cluster would notice.
//
// The probe is a device-map with an invalid PCI address beside a packed
// cluster. It must still be rejected. A control with the same device-map beside
// a CONTAINER cluster proves the rejection is the device-map's, not an artifact
// of the packed spelling.
func TestSchemaWalkStillSeesSiblingsOfAPackedCluster_6672(t *testing.T) {
	const badDeviceMap = `
    device-map {
        interface fxp0 { pci not-a-pci-address; }
    }
`
	control := schemaValidateSrc6672(t, "chassis {\n    cluster {\n        cluster-id 22;\n    }\n"+badDeviceMap+"}\n")
	if control == nil {
		t.Fatalf("fixture bug: the invalid device-map is accepted even beside a CONTAINER " +
			"cluster, so this test cannot show the packed path dropping it")
	}
	packed := schemaValidateSrc6672(t, "chassis {\n    cluster cluster-id 22;\n"+badDeviceMap+"}\n")
	if packed == nil {
		t.Fatalf("the sibling device-map vanished from the schema walk when the cluster "+
			"body was packed — it was rejected beside a container cluster with: %v", control)
	}
	if packed.Error() != control.Error() {
		t.Errorf("the sibling device-map was rejected by a DIFFERENT gate on the packed path\n container: %v\n packed:    %v",
			control, packed)
	}
}

// TestNormalizeIsANoOpForTheContainerSpelling_6672 pins the zero-churn half:
// the spelling that always worked is returned as the SAME pointer, so this code
// cannot perturb it at all.
//
// The second half is the one that matters more. normalizePackedChassisCluster
// returns its input unchanged when there is nothing to do, so a test that only
// checked "the container tree is unchanged" would also pass with the transform
// deleted outright. Assert that a PACKED tree comes back changed.
func TestNormalizeIsANoOpForTheContainerSpelling_6672(t *testing.T) {
	container, errs := NewParser("chassis {\n    cluster {\n        cluster-id 22;\n    }\n}\n").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	if got := normalizePackedChassisCluster(container); got != container {
		t.Errorf("the container spelling was rewritten; it must be returned untouched")
	}

	packed, errs := NewParser("chassis {\n    cluster cluster-id 22;\n}\n").Parse()
	if len(errs) > 0 {
		t.Fatalf("parse: %v", errs)
	}
	got := normalizePackedChassisCluster(packed)
	if got == packed {
		t.Fatalf("the packed spelling was NOT rewritten — the transform declined to run, " +
			"so every other assertion in this file about it would be vacuous")
	}
	chassis := got.FindChild("chassis")
	if chassis == nil {
		t.Fatalf("normalized tree lost the chassis node")
	}
	cluster := chassis.FindChild("cluster")
	if cluster == nil {
		t.Fatalf("normalized tree has no cluster child: %v", chassis.Keys)
	}
	if len(cluster.Keys) != 1 {
		t.Errorf("normalized cluster node still carries a packed tail: %v", cluster.Keys)
	}
	if cluster.FindChild("cluster-id") == nil {
		t.Errorf("normalized cluster body has no cluster-id child: %v", cluster.Children)
	}
}

// TestPackedClusterSplitterIsNotFlat_6672 documents, by measurement, why this
// splitter is not packedStatementPropsArity (#6665). Under the flat rule the
// redundancy-group's `node` re-arms the outer splitter; under the nested rule
// it does not. Both readings are produced here so the difference is a fact in
// the tree rather than a claim in a comment.
func TestPackedClusterSplitterIsNotFlat_6672(t *testing.T) {
	packed := &Node{Keys: strings.Fields("cluster redundancy-group 1 node 0 priority 200")}

	nested := clusterBodyStatements(packed, 1)
	flat := packedStatementPropsArity(packed, 1, isClusterStatement, clusterStatementArity)

	describe := func(nodes []*Node) string {
		parts := make([]string, 0, len(nodes))
		for _, n := range nodes {
			parts = append(parts, fmt.Sprintf("%v", n.Keys))
		}
		return strings.Join(parts, " | ")
	}

	if len(nested) != 1 {
		t.Errorf("nested splitter produced %d statements, want 1 (the whole group): %s",
			len(nested), describe(nested))
	}
	if len(flat) == len(nested) {
		t.Fatalf("the flat splitter agrees with the nested one on this input, so it "+
			"cannot show why the nested rule is needed: %s", describe(flat))
	}
	for _, n := range flat {
		if n.Name() == "node" {
			return // the flat rule does steal it, as documented
		}
	}
	t.Errorf("expected the flat splitter to open a CLUSTER-level `node` statement "+
		"from the group's own node; it produced: %s", describe(flat))
}
