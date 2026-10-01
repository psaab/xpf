package config

import (
	"strings"
	"testing"
)

// #6768 — unnormalized duplicate containers silently lose configuration.
//
// The issue names three effects: BGP export policy, TLS syslog transport, and
// monitoring state. Its evidence and fix-direction sections are pointers to a
// review file that no longer exists, so every claim below was re-derived by
// SYMBOL at current master and measured before anything was changed.
//
// PREDICATE used to derive the population — not the three effects the issue
// happened to name: a container that can be authored more than once as a
// hierarchical sibling, and whose compile silently loses configuration the FLAT
// `set` spelling would have merged. `tree.SetPath` collapses a repeated flat
// statement onto one node, so a duplicate CONTAINER sibling is reachable only
// from the hierarchical shape — which is exactly the dual-AST-equivalence
// invariant the #5180 gate already exists to enforce.
//
// Population measured at master: SIX sites, in three distinct loss modes.
//
//	security log stream <n>      last-writer-wins  Streams[name] = stream
//	security log profile <n>     last-writer-wins  Profiles[name] = p
//	protocols bgp group <n>      split instances   per-instance local state
//	services flow-monitoring     first-wins        FindChild
//	services rpm                 first-wins        FindChild
//	services ip-monitoring       first-wins        FindChild
//
// Three of the six are the effects the issue names; the other three came from
// the predicate. A count that rises when the population is derived properly is
// the derivation working, not scope creep.
//
// The fix registers all six in the #5180 duplicate-named-block gate: strict
// reject on commit / commit-check, warn on the tolerant load / peer-sync path
// (#1960 no-brick). It deliberately does NOT fold the blocks together. #6992
// folded `system login user` because two READERS picked different blocks — a
// credential authored under a VIEW-only block could authenticate into a
// super-user CLI — and a fold was the only way to remove the divergence. There
// is no divergent reader here: the loss is a plain silent drop, which is the
// shape `groups` / `interfaces` / `screen ids-option` are handled with, so the
// gate alone is the matching remedy.

// dup6768Case is one registry row plus the fixture that reproduces its loss.
type dup6768Case struct {
	name     string // subtest name
	kind     string // the `kind` the gate reports
	instance string // the duplicated name the gate reports
	dupSrc   string // hierarchical config authoring the container TWICE
	oneSrc   string // the same content authored ONCE — must compile clean
	effect   string // a distinctive fragment of the effect sentence
}

func dup6768Cases() []dup6768Case {
	return []dup6768Case{
		// #8433. An IKE/IPsec proposal is stored as IKEProposals[name] /
		// Proposals[name], so the second block REPLACES the first. Worse than
		// the average last-wins row on this table: what is lost is not a weaker
		// tunnel but an INCOMPLETE crypto proposal — the dup below loses the
		// authentication-method AND the DH group, both of which the operator
		// authored. Measured at master before the row was added.
		{
			name:     "ike_proposal",
			kind:     "ike proposal",
			instance: "P1",
			effect:   "last-writer-wins",
			dupSrc: `security {
    ike {
        proposal P1 { authentication-method pre-shared-keys; dh-group group14; }
        proposal P1 { authentication-algorithm sha-256; encryption-algorithm aes-256-cbc; }
    }
}`,
			oneSrc: `security {
    ike {
        proposal P1 { authentication-method pre-shared-keys; dh-group group14; authentication-algorithm sha-256; encryption-algorithm aes-256-cbc; }
    }
}`,
		},
		{
			name:     "ipsec_proposal",
			kind:     "ipsec proposal",
			instance: "Q1",
			effect:   "last-writer-wins",
			dupSrc: `security {
    ipsec {
        proposal Q1 { protocol esp; }
        proposal Q1 { authentication-algorithm hmac-sha-256-128; encryption-algorithm aes-256-cbc; }
    }
}`,
			oneSrc: `security {
    ipsec {
        proposal Q1 { protocol esp; authentication-algorithm hmac-sha-256-128; encryption-algorithm aes-256-cbc; }
    }
}`,
		},
		{
			name:     "security_log_stream",
			kind:     "security log stream",
			instance: "s",
			effect:   "last-writer-wins",
			dupSrc: `security {
    log {
        stream s { host 10.0.0.9; transport { protocol tls; } }
        stream s { host 10.0.0.9; severity info; }
    }
}`,
			oneSrc: `security {
    log {
        stream s { host 10.0.0.9; transport { protocol tls; } severity info; }
    }
}`,
		},
		{
			name:     "security_log_profile",
			kind:     "security log profile",
			instance: "pf",
			effect:   "last-writer-wins",
			dupSrc: `security {
    log {
        stream s { host 10.0.0.9; }
        profile pf { stream-name s; default-profile; }
        profile pf { category all; }
    }
}`,
			oneSrc: `security {
    log {
        stream s { host 10.0.0.9; }
        profile pf { stream-name s; default-profile; category all; }
    }
}`,
		},
		{
			name:     "protocols_bgp_group",
			kind:     "bgp group",
			instance: "g",
			effect:   "compiled independently",
			dupSrc: `routing-options { autonomous-system 65000; }
policy-options { policy-statement EXPORT-POLICY { then accept; } }
protocols {
    bgp {
        group g { type external; peer-as 65001; export EXPORT-POLICY; }
        group g { neighbor 10.0.0.1; }
    }
}`,
			oneSrc: `routing-options { autonomous-system 65000; }
policy-options { policy-statement EXPORT-POLICY { then accept; } }
protocols {
    bgp {
        group g { type external; peer-as 65001; export EXPORT-POLICY; neighbor 10.0.0.1; }
    }
}`,
		},
		{
			name:     "services_flow_monitoring",
			kind:     "services container",
			instance: "flow-monitoring",
			effect:   "FIRST block",
			dupSrc: `services {
    flow-monitoring { version9 { template t { flow-active-timeout 30; } } }
    flow-monitoring { version-ipfix { template u { flow-active-timeout 40; } } }
}`,
			oneSrc: `services {
    flow-monitoring {
        version9 { template t { flow-active-timeout 30; } }
        version-ipfix { template u { flow-active-timeout 40; } }
    }
}`,
		},
		{
			name:     "services_rpm",
			kind:     "services container",
			instance: "rpm",
			effect:   "FIRST block",
			dupSrc: `services {
    rpm { probe p1 { test t1 { target address 10.0.0.1; } } }
    rpm { probe p2 { test t2 { target address 10.0.0.2; } } }
}`,
			oneSrc: `services {
    rpm {
        probe p1 { test t1 { target address 10.0.0.1; } }
        probe p2 { test t2 { target address 10.0.0.2; } }
    }
}`,
		},
		{
			name:     "services_ip_monitoring",
			kind:     "services container",
			instance: "ip-monitoring",
			effect:   "FIRST block",
			dupSrc: `services {
    rpm { probe pr { test tt { target address 10.0.0.1; } } }
    ip-monitoring {
        policy a { match { rpm-probe pr; } then { preferred-route { route 0.0.0.0/0 { next-hop 10.0.0.254; } } } }
    }
    ip-monitoring {
        policy b { match { rpm-probe pr; } then { preferred-route { route 1.0.0.0/8 { next-hop 10.0.0.253; } } } }
    }
}`,
			oneSrc: `services {
    rpm { probe pr { test tt { target address 10.0.0.1; } } }
    ip-monitoring {
        policy a { match { rpm-probe pr; } then { preferred-route { route 0.0.0.0/0 { next-hop 10.0.0.254; } } } }
        policy b { match { rpm-probe pr; } then { preferred-route { route 1.0.0.0/8 { next-hop 10.0.0.253; } } } }
    }
}`,
		},
	}
}

// TestDuplicateContainerRejectedAtCommit_6768 is the strict-path proof for
// every row. Removing a row from the registry reds only its own subtest, so a
// partial revert cannot hide behind the others.
func TestDuplicateContainerRejectedAtCommit_6768(t *testing.T) {
	for _, tc := range dup6768Cases() {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHier5180(t, tc.dupSrc)
			_, err := CompileConfig(tree)
			if err == nil {
				t.Fatalf("CompileConfig accepted a duplicate %s %q; the duplicate silently "+
					"loses configuration the flat spelling would have merged", tc.kind, tc.instance)
			}
			for _, want := range []string{"duplicate", tc.kind, tc.instance, tc.effect, "#5180"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q missing %q", err.Error(), want)
				}
			}
		})
	}
}

// TestDuplicateContainerLenientWarns_6768: the tolerant load / peer-sync path
// must NOT hard-reject — an already-persisted or peer-synced config authored by
// a pre-gate version still has to boot (#1960) — but it must say so.
func TestDuplicateContainerLenientWarns_6768(t *testing.T) {
	for _, tc := range dup6768Cases() {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHier5180(t, tc.dupSrc)
			cfg, err := CompileConfigLenient(tree)
			if err != nil {
				t.Fatalf("CompileConfigLenient hard-rejected a duplicate %s: %v", tc.kind, err)
			}
			found := false
			for _, w := range cfg.Warnings {
				if strings.Contains(w, "duplicate "+tc.kind) && strings.Contains(w, tc.instance) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("no downgraded warning naming %s %q; warnings=%v", tc.kind, tc.instance, cfg.Warnings)
			}
		})
	}
}

// TestSingleContainerStillCompiles_6768 is the negative control, and it is the
// cell that stops the gate from being satisfied by "reject everything": the
// SAME content authored once must compile clean at strict. Each fixture is the
// merged form of its duplicate twin, so this also pins that the gate rejects
// the SHAPE and not the content.
func TestSingleContainerStillCompiles_6768(t *testing.T) {
	for _, tc := range dup6768Cases() {
		t.Run(tc.name, func(t *testing.T) {
			tree := parseHier5180(t, tc.oneSrc)
			if _, err := CompileConfig(tree); err != nil {
				t.Fatalf("CompileConfig rejected the singly-authored form: %v", err)
			}
		})
	}
}

// TestUnregisteredContainerRepeatStillAccepted_6768 is the tightening control.
// `services application-identification` is deliberately NOT in the registry: it
// is a presence flag, so authoring it twice loses nothing. A gate that rejected
// every repeated sibling would satisfy every cell above while breaking configs
// that are fine, so this cell must stay green.
func TestUnregisteredContainerRepeatStillAccepted_6768(t *testing.T) {
	tree := parseHier5180(t, `services {
    application-identification;
    application-identification;
}`)
	if _, err := CompileConfig(tree); err != nil {
		t.Fatalf("CompileConfig rejected a repeated presence flag, which loses nothing: %v", err)
	}

	// And a REGISTERED container repeated as an empty leaf. The singleton walk
	// skips `c.IsLeaf` deliberately: two empty `flow-monitoring;` statements
	// carry no configuration, so neither can lose any, and rejecting them would
	// be a false positive on a config that is merely redundant. Without this
	// cell the guard is unbound — the mutation matrix removed it and every
	// other cell stayed green, because the presence-flag fixture above uses a
	// keyword that is not in the registry at all and so never reaches it.
	leafTree := parseHier5180(t, `services {
    flow-monitoring;
    flow-monitoring;
}`)
	if _, err := CompileConfig(leafTree); err != nil {
		t.Fatalf("CompileConfig rejected two EMPTY flow-monitoring statements, which "+
			"cannot lose configuration: %v", err)
	}
}

// TestEveryDuplicateContainerRuleHasAFixture_6768 binds the REGISTRY to the
// tests. A registry row is a claim that a duplicate of that container loses
// config; adding one without a fixture would leave the claim untested while the
// file still looked covered. The subtests above are per-row, so this cell is
// what makes their coverage total rather than incidental.
func TestEveryDuplicateContainerRuleHasAFixture_6768(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range dup6768Cases() {
		covered[tc.kind+"/"+tc.instance] = true
	}
	// The two pre-#6768 rows are covered by dup_named_blocks_5180_test.go and
	// are exempt here; every row this issue added owes a fixture.
	preexisting := map[string]bool{"screen ids-option": true, "login user": true}
	for _, r := range namedDupRules {
		if preexisting[r.kind] {
			continue
		}
		if !anyCoveredKind(covered, r.kind) {
			t.Errorf("namedDupRules row %q has no fixture in dup6768Cases()", r.kind)
		}
	}
	for _, r := range singletonDupRules {
		for _, kw := range r.keywords {
			if !covered[r.kind+"/"+kw] {
				t.Errorf("singletonDupRules row %s %q has no fixture in dup6768Cases()", r.kind, kw)
			}
		}
	}
}

func anyCoveredKind(covered map[string]bool, kind string) bool {
	for k := range covered {
		if strings.HasPrefix(k, kind+"/") {
			return true
		}
	}
	return false
}

// TestDuplicateContainerInGroupBodyCaught_6768: the #5180 walk runs
// PRE-expansion, so a duplicate authored entirely inside an applied group body
// is invisible to it — #6455 re-runs the same function on a group-expanded
// clone to close that. Existence-closure through a shared call site is
// transitive; GUARDEDNESS-closure is not, so this cell proves the new rows are
// actually reached on the expanded path rather than assuming it.
func TestDuplicateContainerInGroupBodyCaught_6768(t *testing.T) {
	tree := parseHier5180(t, `groups {
    g1 {
        services {
            flow-monitoring { version9 { template t { flow-active-timeout 30; } } }
            flow-monitoring { version-ipfix { template u { flow-active-timeout 40; } } }
        }
    }
}
apply-groups g1;`)
	_, err := CompileConfig(tree)
	if err == nil {
		t.Fatal("CompileConfig accepted a duplicate container authored inside an applied group body")
	}
	if !strings.Contains(err.Error(), "flow-monitoring") {
		t.Errorf("error %q does not name the duplicated container", err.Error())
	}
}

// TestDuplicateContainerHarmIsMeasured_6768 records WHAT the three effects the
// issue names actually cost, on the tolerant path where the historical result
// is deliberately preserved (#1960 no-brick). These are not aspirational
// assertions — they pin the contract that is in force. If the compiler is ever
// changed to FOLD duplicate blocks the way #6992 folded `system login user`,
// these cells must be updated to assert the merged result; that is the point of
// writing them down rather than leaving the loss implicit in a commit message.
func TestDuplicateContainerHarmIsMeasured_6768(t *testing.T) {
	t.Run("bgp_export_policy_erased", func(t *testing.T) {
		cfg := lenientHier6768(t, `policy-options { policy-statement EXPORT-POLICY { then accept; } }
protocols {
    bgp {
        group g { type external; peer-as 65001; export EXPORT-POLICY; }
        group g { neighbor 10.0.0.1; }
    }
}`)
		if cfg.Protocols.BGP == nil || len(cfg.Protocols.BGP.Neighbors) != 1 {
			t.Fatalf("expected exactly one compiled neighbour, got %+v", cfg.Protocols.BGP)
		}
		n := cfg.Protocols.BGP.Neighbors[0]
		if len(n.Export) != 0 {
			t.Fatalf("export = %v; the measured pre-gate behaviour is that the second "+
				"group block compiles with its own empty state — update this cell if a "+
				"fold was added", n.Export)
		}
		if n.PeerAS != 0 {
			t.Errorf("peer-as = %d, want 0 (same erasure, and the only half that warns)", n.PeerAS)
		}
	})

	t.Run("tls_syslog_transport_erased", func(t *testing.T) {
		cfg := lenientHier6768(t, `security {
    log {
        stream s { host 10.0.0.9; transport { protocol tls; } }
        stream s { host 10.0.0.9; severity info; }
    }
}`)
		s := cfg.Security.Log.Streams["s"]
		if s == nil {
			t.Fatal("stream s missing")
		}
		if s.Transport.Protocol != "" {
			t.Fatalf("transport protocol = %q; the measured pre-gate behaviour is that the "+
				"second block replaces the first wholesale, leaving the TLS transport "+
				"unset — a stream the operator configured for TLS reverts to plain "+
				"syslog", s.Transport.Protocol)
		}
		if s.Severity != "info" {
			t.Errorf("severity = %q, want info (the surviving block's value)", s.Severity)
		}
	})

	t.Run("monitoring_state_erased", func(t *testing.T) {
		cfg := lenientHier6768(t, `services {
    flow-monitoring { version9 { template t { flow-active-timeout 30; } } }
    flow-monitoring { version-ipfix { template u { flow-active-timeout 40; } } }
}`)
		fm := cfg.Services.FlowMonitoring
		if fm == nil {
			t.Fatal("flow-monitoring missing entirely")
		}
		if fm.Version9 == nil {
			t.Error("version9 (the FIRST block) should survive")
		}
		if fm.VersionIPFIX != nil {
			t.Fatal("version-ipfix survived; the measured pre-gate behaviour is that " +
				"compileServices reads flow-monitoring with FindChild, so the whole " +
				"second block is ignored")
		}
	})
}

func lenientHier6768(t *testing.T, src string) *Config {
	t.Helper()
	cfg, err := CompileConfigLenient(parseHier5180(t, src))
	if err != nil {
		t.Fatalf("CompileConfigLenient: %v", err)
	}
	return cfg
}
