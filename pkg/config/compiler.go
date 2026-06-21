package config

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// ErrDPDKDataplaneRetired is the sentinel error returned at commit
// time when a configuration sets `system dataplane-type dpdk`. External
// API consumers (gRPC orchestration, REST wrappers, CLI tooling) can
// match this with errors.Is rather than substring-searching the wrapped
// error text. The wrapped form is preserved verbatim so the operator-
// facing migration message remains stable; see #1525.
//
// Mirrors the runtime-side dataplane.ErrDPDKBackendRetired sentinel
// introduced by #1527 so the config-time and runtime layers both expose
// structured rejections.
var ErrDPDKDataplaneRetired = errors.New(
	"the DPDK dataplane backend has been retired; " +
		"use 'set system dataplane-type userspace' " +
		"(see #1525)")

// ErrEBPFDataplaneRetired is the sentinel error returned at commit
// time when a configuration sets `system dataplane-type ebpf`. The
// parse path still accepts the token as a legal value so that
// `load merge` / `load override` of a pre-retirement configuration
// does not syntax-error; this strict validator is what tells the
// operator to migrate.
//
// Mirrors the runtime-side dataplane.ErrEBPFBackendRetired sentinel
// introduced by #1476 so the config-time and runtime layers both
// expose structured rejections. The verbatim message must remain
// stable for downstream tooling that matches by text.
var ErrEBPFDataplaneRetired = errors.New(
	"the legacy eBPF dataplane backend has been retired; " +
		"use 'set system dataplane-type userspace' " +
		"(see #1373)")

// compileOpts carries per-call compilation policy. It is threaded into
// compileExpanded so the strict commit path and the tolerant
// load/peer-sync path can share the identical compile + group-expansion
// pipeline while differing on a single, narrow validator's severity.
type compileOpts struct {
	// #1830 (e): the former lenientEqualFlowWorkerCap flag (#1733) is
	// retired along with validateEqualFlowWorkerCapStrict — the
	// dataplane no longer caps equal-flow-enforcement at 32 workers, so
	// there is no severity to downgrade. The lenient compile entry
	// points remain for the flags below.

	// sanitizeFreeTextControlChars (#1798) downgrades the control-
	// character gate from a hard compile error to sanitize-in-place
	// plus a cfg.Warnings entry. The strict commit / commit-check path
	// rejects any value or annotation containing ASCII control
	// characters — the lexer maps "\n" inside a quoted string to a
	// real newline, which injects arbitrary directives into generated
	// networkd/FRR/strongSwan files. The tolerant load / peer-sync /
	// peer-display paths must instead scrub the value and keep going
	// so an already-persisted bad config cannot blackout-boot a node
	// or alarm-loop HA config sync. This check deliberately does NOT
	// live in SchemaValidate: the tolerant paths need the value scrubbed
	// in place, which the read-only schema walk cannot do (and since
	// #1319 PR 2 SchemaValidate violations are themselves downgraded to
	// warnings on the tolerant paths — see configstore.compileTreeLenient).
	// See freetext.go for the full three-layer design.
	sanitizeFreeTextControlChars bool

	// lenientVRRPTrackDuplicates (#1814) downgrades the duplicate
	// `track-interface` gate (more than one track-interface statement
	// inside a single vrrp-group) from a hard compile error to a
	// cfg.Warnings entry with deterministic first-wins pruning of the
	// extras. Set ONLY on the tolerant load / peer-sync paths
	// (CompileConfigLenient / CompileConfigForNodeLenient) so an
	// already-persisted or peer-synced config still boots; candidate
	// commit / commit-check stay strict and hard-reject new operator
	// edits. Like the other lenient gates, this check deliberately does
	// NOT live in SchemaValidate: pruning the duplicates is an AST-level
	// compile decision the read-only schema walk cannot make (and since
	// #1319 PR 2 SchemaValidate violations only warn on tolerant paths).
	lenientVRRPTrackDuplicates bool

	// lenientDeviceMap (#1956 V-1) downgrades the cross-entry device-map
	// validator (validateDeviceMapStrict) from a hard compile error to a
	// cfg.Warnings entry. Set ONLY on the tolerant load / peer-sync paths
	// (CompileConfigLenient / CompileConfigForNodeLenient): an active node's
	// strict commit validates only ITS OWN node section against its own
	// hardware (R-8 pre-flight does the live-hardware half), but it cannot
	// fail on the PEER node's section (different box, structural rules like
	// FPC/node alignment differ per node). The peer's SyncApply compiles
	// leniently, so a peer-section structural finding warns rather than
	// stalling the whole config sync. The narrow management-lockout class
	// that lenient must NOT swallow is handled by the daemon's passive-node
	// SyncApply admission gate (V-1), not by this compile flag.
	lenientDeviceMap bool

	// lenientTCPMSSRange (#1979 Layer B Tier 3) downgrades the tcp-mss
	// commit-time range gate (validateTCPMSSRanges) from a hard compile
	// error to a cfg.Warnings entry. Set ONLY on the tolerant load /
	// peer-sync paths (CompileConfigLenient / CompileConfigForNodeLenient):
	// a persisted or peer-synced config carrying an out-of-range MSS value
	// an OLDER binary accepted (before this gate existed) must still boot,
	// not blackout the upgraded node — the dataplane coerces it safely
	// (Layer A, flow.go coerceWireU16) and the operator's next strict commit
	// rejects it loudly. Same doctrine as lenientVRRPTrackDuplicates. Like
	// the other lenient gates this is an AST-level compile decision (the MSS
	// value can live in two positions) and deliberately does NOT live in
	// SchemaValidate (tcp-mss stays opaque there).
	lenientTCPMSSRange bool

	// lenientNATPoolAlarmThreshold (#2079) downgrades the
	// security-nat-source pool-utilization-alarm threshold gate
	// (validatePoolUtilizationAlarm) from a hard compile error to a
	// cfg.Warnings entry. Set ONLY on the tolerant load / peer-sync paths
	// (CompileConfigLenient / CompileConfigForNodeLenient): the thresholds
	// had NO validation before #2079, so an operator could (and would) have
	// committed a bare `pool-utilization-alarm;` (raise=0/clear=0) or an
	// inverted/equal pair, persisted to active.json. After upgrade that
	// config must still LOAD (warn) instead of failing the daemon closed on
	// restart (fail-closed-on-compile-failure, #1960); the operator's next
	// strict commit rejects it loudly. The runtime monitor treats raise<=0 as
	// "feature disabled", so a leniently-loaded bad config is inert, not
	// always-firing. Same doctrine as lenientTCPMSSRange.
	lenientNATPoolAlarmThreshold bool

	// lenientPolicyMatchAddress (#2008) downgrades the policy match-
	// address validator (validatePolicyMatchAddressesStrict) from a hard
	// compile error to a cfg.Warnings entry. The strict commit /
	// commit-check path hard-rejects a policy source-address /
	// destination-address token that is neither a known address-book
	// name, the `any` keyword, nor a parseable CIDR / IP — a typo would
	// otherwise reach the dataplane, be silently dropped to an empty
	// set, and (under `*-address-excluded` inversion) FAIL OPEN to
	// match-all. The tolerant load / peer-sync paths downgrade to a
	// warning so an already-persisted or peer-synced config still boots
	// (the dataplane is independently hardened to fail CLOSED on an
	// empty excluded set, so a slipped-through typo denies rather than
	// opens). Like the other lenient gates this is an AST/typed-config
	// compile decision and deliberately does NOT live in SchemaValidate
	// (which only warns on the tolerant paths since #1319 PR 2).
	lenientPolicyMatchAddress bool
	// lenientEventAttributesMatch downgrades an uncompilable
	// event-options attributes-match regex from a hard error to a warning
	// on the tolerant load path. A config persisted under pre-#2008 xpf
	// (literal-equality matcher, any string accepted) may hold a pattern
	// that is not valid RE2; a node upgrading to the regex matcher must
	// still boot through that already-committed config rather than fail to
	// load. Commit stays strict (see the validator call site).
	lenientEventAttributesMatch bool
	// lenientIPsecPolicyProposalRef (#2073) downgrades the IPsec policy
	// proposal cross-reference check from a hard error to a warning on the
	// tolerant load / peer-sync paths. A dangling `proposals` reference (or
	// a PFS policy with no resolvable proposal) silently drops the
	// configured perfect-forward-secrecy group to the strongSwan default at
	// render time; commit/commit-check hard-reject it so a new operator edit
	// fails loudly, but an already-persisted or peer-synced config carrying
	// this latent misconfiguration must still boot (the render-path safety
	// net in pkg/ipsec resolveESPSettings preserves the PFS group on that
	// boot). Same doctrine as lenientPolicyMatchAddress.
	lenientIPsecPolicyProposalRef bool

	// lenientIPsecGatewayRefs (#2074) downgrades the IPsec VPN -> IKE
	// gateway cross-reference check from a hard error to a warning on the
	// tolerant load / peer-sync paths (CompileConfigLenient /
	// CompileConfigForNodeLenient). A config persisted by an older binary,
	// or synced from a peer, may carry a VPN that references an undefined
	// or addressless gateway; an upgrading / receiving node must still
	// boot through it (warn) rather than fail-closed-on-load (#1960
	// class). Commit / commit-check stay strict — a new operator edit that
	// would render `remote_addrs = <gateway-name>` (a silently-dead
	// tunnel) is rejected. Same doctrine as lenientDeviceMap /
	// lenientPolicyMatchAddress.
	lenientIPsecGatewayRefs bool

	// lenientLogProfileStreamRef (#2008 H7) downgrades the
	// `security log profile <name> stream-name <stream>` cross-reference
	// from a hard error to a warning on the tolerant load / peer-sync
	// paths. A config persisted by an older binary (which silently dropped
	// the whole profile stanza), or synced from a peer, may carry a profile
	// naming a stream that is not configured; an upgrading / receiving node
	// must still boot through it (warn) rather than fail-closed-on-load
	// (#1960 class). Commit / commit-check stay strict — a new operator
	// edit that names a non-existent stream (a typo whose log routing would
	// silently never fire) is rejected. Same doctrine as
	// lenientIPsecPolicyProposalRef.
	lenientLogProfileStreamRef bool

	// lenientNATHostMask (#2173) downgrades the static-NAT / NAT64
	// host-mask gate (validateNATHostMaskStrict) from a hard compile error
	// to a cfg.Warnings entry. Set ONLY on the tolerant load / peer-sync
	// paths (CompileConfigLenient / CompileConfigForNodeLenient): #2132 made
	// the Rust dataplane tolerate the canonical host mask, PR #2167 then
	// hardened it to REJECT a non-host mask, so a config persisted/synced
	// with a non-host static-NAT match/prefix or NAT64 pool address (which
	// an older binary parsed-out silently, or a peer authored) must still
	// BOOT after upgrade (warn) instead of failing closed (#1960). Commit /
	// commit-check stay strict — a new operator edit whose rule the
	// dataplane will silently drop is rejected loudly. The dataplane drops
	// the bad entry independently, so a leniently-loaded config is already
	// inert for that rule. Same doctrine as lenientNATPoolAlarmThreshold.
	lenientNATHostMask bool

	// lenientUnsupportedInterfaceStanzas (#2008 H9/H10) downgrades the
	// interface silent-drop gate (validateUnsupportedInterfaceStanzasAST:
	// `interface [unit] mac` static-MAC override, `family inet|inet6
	// policer arp` per-unit ARP policer) from a hard error to a warning on
	// the tolerant load / peer-sync paths. Both stanzas parse-accept and
	// silently drop on every binary up to this gate, so an
	// already-persisted or peer-synced config may carry them; an upgrading
	// / receiving node must still boot through it (warn) rather than
	// fail-closed-on-load (#1960 class). Commit / commit-check stay strict
	// — a new operator edit that the dataplane cannot honour is rejected
	// instead of silently ignored. Same doctrine as
	// lenientVRRPTrackDuplicates / lenientLogProfileStreamRef.
	lenientUnsupportedInterfaceStanzas bool
}

// CompileConfig converts a parsed ConfigTree AST into a typed Config struct.
// It clones the tree before expansion so the original tree is not mutated.
func CompileConfig(tree *ConfigTree) (*Config, error) {
	return compileConfigWithOpts(tree, compileOpts{})
}

// CompileConfigLenient is CompileConfig with the tolerant-path
// downgrades enabled (#1798 control-char sanitize-in-place, lenient
// VRRP track duplicates). Use on TOLERANT paths that compile an
// already-active / already-persisted config the operator did not just
// author — e.g. Store.Load of a persisted config — so an upgraded node
// boots through. MUST NOT be used on the candidate-commit path:
// commit / commit-check use the strict CompileConfig so new operator
// edits hard-reject. The node-aware sibling CompileConfigForNodeLenient
// covers the cluster paths (Store.SyncApply, peer-interface display).
// (The former #1733 equal-flow worker-cap downgrade was retired in
// #1830 (e) — the dataplane no longer caps equal-flow at 32 workers.)
func CompileConfigLenient(tree *ConfigTree) (*Config, error) {
	return compileConfigWithOpts(tree, compileOpts{
		sanitizeFreeTextControlChars:       true,
		lenientVRRPTrackDuplicates:         true,
		lenientDeviceMap:                   true,
		lenientPolicyMatchAddress:          true,
		lenientTCPMSSRange:                 true,
		lenientEventAttributesMatch:        true,
		lenientIPsecPolicyProposalRef:      true,
		lenientIPsecGatewayRefs:            true,
		lenientLogProfileStreamRef:         true,
		lenientNATPoolAlarmThreshold:       true,
		lenientNATHostMask:                 true,
		lenientUnsupportedInterfaceStanzas: true,
	})
}

func compileConfigWithOpts(tree *ConfigTree, opts compileOpts) (*Config, error) {
	// #2008 H1: prune `inactive:`-marked subtrees BEFORE every other
	// pre-expansion gate, group expansion, and compilation. Doing it first
	// means the tunnel-id collision gate ignores inactive tunnel
	// definitions, an `inactive: apply-groups foo` suppresses the inherited
	// config, and inactive nodes inside a `groups {}` body are pruned —
	// none of the ~15 compiler files or validators ever observe an inactive
	// node. cloneForExpansion returns a fresh, freely-mutable pruned tree in a
	// single deep copy (no double-clone on the has-inactive path); the result
	// never aliases the caller's tree, so the caller retains groups/apply-groups
	// nodes for `show configuration` and ExpandGroups below mutates only our copy.
	tree = tree.cloneForExpansion()

	// #1873 R-B: tunnel-endpoint id collision gate. Runs on the
	// PRE-expansion tree (ExpandGroups removes the groups stanza) so
	// the check covers the UNION of tunnel names across all groups —
	// both cluster nodes accept/reject identically. Strict paths
	// hard-reject; lenient paths warn (see tunnelid.go). Read-only, so it is
	// safe to run on the soon-to-be-expanded copy.
	tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
		tree, opts.sanitizeFreeTextControlChars)
	if tunnelIDErr != nil {
		return nil, tunnelIDErr
	}

	usedNodeFallback := false

	// Expand groups before compilation — resolve all apply-groups references.
	if err := tree.ExpandGroups(); err != nil {
		if strings.Contains(err.Error(), `undefined group "${node}"`) {
			vars := map[string]string{"node": "node0"}
			if err2 := tree.ExpandGroupsWithVars(vars); err2 != nil {
				return nil, fmt.Errorf("apply-groups: %w", err2)
			}
			usedNodeFallback = true
		} else {
			return nil, fmt.Errorf("apply-groups: %w", err)
		}
	}

	cfg, err := compileExpanded(tree, opts)
	if err != nil {
		return nil, err
	}
	if usedNodeFallback {
		cfg.Warnings = append(cfg.Warnings, `apply-groups "${node}" resolved using default node0 context during generic compile`)
	}
	cfg.Warnings = append(cfg.Warnings, tunnelIDWarnings...)
	return cfg, nil
}

// CompileConfigForNode is like CompileConfig but resolves ${node} variables
// in apply-groups names before lookup. nodeID selects which per-node group
// to apply (e.g. nodeID=0 maps "node" -> "node0", so apply-groups "${node}"
// resolves to group "node0"). This supports a single shared config for both
// nodes in a chassis cluster.
func CompileConfigForNode(tree *ConfigTree, nodeID int) (*Config, error) {
	return compileConfigForNodeWithOpts(tree, nodeID, compileOpts{})
}

// CompileConfigForNodeLenient is CompileConfigForNode with the
// tolerant-path downgrades enabled (see CompileConfigLenient). Use on
// node-aware TOLERANT paths that compile an already-active / peer-synced
// config the local operator did not just author: Store.SyncApply (HA
// peer-sync ingress) and the read-only peer-interface display re-compiles
// (cli_show_interfaces.go, server_show_interfaces.go). MUST NOT be used on
// the candidate-commit path — see CompileConfigLenient.
func CompileConfigForNodeLenient(tree *ConfigTree, nodeID int) (*Config, error) {
	return compileConfigForNodeWithOpts(tree, nodeID, compileOpts{
		sanitizeFreeTextControlChars:       true,
		lenientVRRPTrackDuplicates:         true,
		lenientDeviceMap:                   true,
		lenientPolicyMatchAddress:          true,
		lenientTCPMSSRange:                 true,
		lenientEventAttributesMatch:        true,
		lenientIPsecPolicyProposalRef:      true,
		lenientIPsecGatewayRefs:            true,
		lenientLogProfileStreamRef:         true,
		lenientNATPoolAlarmThreshold:       true,
		lenientNATHostMask:                 true,
		lenientUnsupportedInterfaceStanzas: true,
	})
}

func compileConfigForNodeWithOpts(tree *ConfigTree, nodeID int, opts compileOpts) (*Config, error) {
	// #2008 H1: prune `inactive:` subtrees first — see compileConfigWithOpts.
	// Centralizing the strip in this shared node-aware entry guarantees BOTH
	// cluster nodes compile the identical active set from the same persisted
	// (Inactive-flag-carrying, JSON-synced) tree, so a deactivated stanza is
	// dead on both nodes — no split-brain firewall posture. cloneForExpansion
	// returns a fresh, freely-mutable pruned tree in a single deep copy (never
	// aliases the caller's tree) so ExpandGroupsWithVars below mutates only our copy.
	tree = tree.cloneForExpansion()

	// #1873 R-B: union-of-groups tunnel id collision gate — see
	// compileConfigWithOpts. Pre-expansion on purpose; read-only, safe on the copy.
	tunnelIDWarnings, tunnelIDErr := validateTunnelEndpointIDCollisionAST(
		tree, opts.sanitizeFreeTextControlChars)
	if tunnelIDErr != nil {
		return nil, tunnelIDErr
	}

	vars := map[string]string{"node": fmt.Sprintf("node%d", nodeID)}
	if err := tree.ExpandGroupsWithVars(vars); err != nil {
		return nil, fmt.Errorf("apply-groups: %w", err)
	}

	cfg, err := compileExpanded(tree, opts)
	if err != nil {
		return nil, err
	}
	cfg.Warnings = append(cfg.Warnings, tunnelIDWarnings...)
	return cfg, nil
}

// compileExpanded compiles an already-expanded (groups resolved) ConfigTree
// into a typed Config. Shared by CompileConfig and CompileConfigForNode.
func compileExpanded(tree *ConfigTree, opts compileOpts) (*Config, error) {
	// #1798 free-text control-character gate. Strict (commit /
	// commit-check): hard-reject. Lenient (load / peer-sync / peer
	// display): scrub in place on this already-cloned tree and warn.
	// Runs on the group-expanded tree so values inherited via
	// apply-groups are covered, and BEFORE section compilation so the
	// lenient path's typed Config is built from the scrubbed values.
	var ctrlCharWarnings []string
	if opts.sanitizeFreeTextControlChars {
		for _, p := range sanitizeNodesControlChars(tree.Children, "") {
			ctrlCharWarnings = append(ctrlCharWarnings, fmt.Sprintf(
				"sanitized control characters in configuration value at %q (#1798)", p))
		}
	} else if err := validateNodesControlChars(tree.Children, ""); err != nil {
		return nil, err
	}

	// #1814 VRRP track-interface AST pre-walk. Runs on the group-expanded
	// tree (so apply-groups-inherited statements are covered) and BEFORE
	// section compilation so the lenient path's first-wins pruning is
	// what the compiler actually sees. Strict (commit / commit-check):
	// duplicate track-interface inside one vrrp-group hard-rejects.
	// Lenient (load / peer-sync): prune to the first + warn. Shape-only
	// warnings (nested+sibling both present, orphan priority-cost) come
	// from here too — the typed config cannot distinguish them
	// post-compile.
	trackWarnings, err := validateVRRPTrackInterfaceAST(tree.Children, "", opts.lenientVRRPTrackDuplicates)
	if err != nil {
		return nil, err
	}

	// #1979 Layer B Tier 3: tcp-mss range AST pre-walk. tcp-mss carries its
	// MSS value in either the kind node's flat Keys[1] or a hierarchical
	// `mss` child — a dual value-location the declarative SchemaValidate
	// walker cannot express, so it stays opaque in setSchema and is
	// range-checked here on the group-expanded tree (apply-groups-inherited
	// values covered), BEFORE the snapshot builder's Layer-A coercion would
	// see it. Strict (commit / commit-check): out-of-range hard-rejects.
	// Lenient (load / peer-sync): warn + let Layer A coerce so an upgraded
	// node loading a legacy out-of-range MSS still boots.
	mssWarnings, err := validateTCPMSSRanges(tree.Children, "", opts.lenientTCPMSSRange)
	if err != nil {
		return nil, err
	}

	// #2008 H9/H10 interface silent-drop gate. Runs on the group-expanded,
	// inactive-pruned tree (apply-groups-inherited stanzas covered;
	// `inactive:` stanzas already stripped upstream) and BEFORE section
	// compilation. Strict (commit / commit-check): a static `mac` override
	// or a `family inet|inet6 policer arp` — neither of which the dataplane
	// can honour — hard-rejects. Lenient (load / peer-sync): warn so an
	// already-persisted or peer-synced config that an older binary silently
	// accepted still boots (#1960 fail-closed-on-load class).
	unsupportedIfaceWarnings, err := validateUnsupportedInterfaceStanzasAST(
		tree.Children, opts.lenientUnsupportedInterfaceStanzas)
	if err != nil {
		return nil, err
	}

	cfg := &Config{
		Security: SecurityConfig{
			Zones:  make(map[string]*ZoneConfig),
			Screen: make(map[string]*ScreenProfile),
		},
		Interfaces: InterfacesConfig{
			Interfaces: make(map[string]*InterfaceConfig),
		},
		Applications: ApplicationsConfig{
			Applications:    make(map[string]*Application),
			ApplicationSets: make(map[string]*ApplicationSet),
		},
		ClassOfService: &ClassOfServiceConfig{
			ForwardingClasses: make(map[string]*CoSForwardingClass),
			DSCPClassifiers:   make(map[string]*CoSDSCPClassifier),
			DSCPRewriteRules:  make(map[string]*CoSDSCPRewriteRule),
			Schedulers:        make(map[string]*CoSScheduler),
			SchedulerMaps:     make(map[string]*CoSSchedulerMap),
			Interfaces:        make(map[string]*CoSInterface),
		},
	}
	cfg.Warnings = append(cfg.Warnings, ctrlCharWarnings...)
	cfg.Warnings = append(cfg.Warnings, trackWarnings...)
	cfg.Warnings = append(cfg.Warnings, mssWarnings...)
	cfg.Warnings = append(cfg.Warnings, unsupportedIfaceWarnings...)

	for _, node := range tree.Children {
		switch node.Name() {
		case "security":
			if err := compileSecurity(node, &cfg.Security); err != nil {
				return nil, fmt.Errorf("security: %w", err)
			}
		case "interfaces":
			if err := compileInterfaces(node, &cfg.Interfaces); err != nil {
				return nil, fmt.Errorf("interfaces: %w", err)
			}
		case "applications":
			if err := compileApplications(node, &cfg.Applications); err != nil {
				return nil, fmt.Errorf("applications: %w", err)
			}
		case "routing-options":
			if err := compileRoutingOptions(node, &cfg.RoutingOptions); err != nil {
				return nil, fmt.Errorf("routing-options: %w", err)
			}
		case "protocols":
			if err := compileProtocols(node, &cfg.Protocols); err != nil {
				return nil, fmt.Errorf("protocols: %w", err)
			}
		case "routing-instances":
			if err := compileRoutingInstances(node, cfg); err != nil {
				return nil, fmt.Errorf("routing-instances: %w", err)
			}
		case "firewall":
			if err := compileFirewall(node, &cfg.Firewall); err != nil {
				return nil, fmt.Errorf("firewall: %w", err)
			}
		case "class-of-service":
			if err := compileClassOfService(node, cfg.ClassOfService); err != nil {
				return nil, fmt.Errorf("class-of-service: %w", err)
			}
		case "services":
			if err := compileServices(node, &cfg.Services); err != nil {
				return nil, fmt.Errorf("services: %w", err)
			}
		case "forwarding-options":
			if err := compileForwardingOptions(node, &cfg.ForwardingOptions); err != nil {
				return nil, fmt.Errorf("forwarding-options: %w", err)
			}
		case "system":
			if err := compileSystem(node, &cfg.System); err != nil {
				return nil, fmt.Errorf("system: %w", err)
			}
		case "schedulers":
			if err := compileSchedulers(node, cfg); err != nil {
				return nil, fmt.Errorf("schedulers: %w", err)
			}
		case "policy-options":
			if err := compilePolicyOptions(node, &cfg.PolicyOptions); err != nil {
				return nil, fmt.Errorf("policy-options: %w", err)
			}
		case "chassis":
			if err := compileChassis(node, &cfg.Chassis); err != nil {
				return nil, fmt.Errorf("chassis: %w", err)
			}
		case "event-options":
			if err := compileEventOptions(node, &cfg.EventOptions); err != nil {
				return nil, fmt.Errorf("event-options: %w", err)
			}
		case "snmp":
			// Top-level snmp stanza (same format as system { snmp { ... } })
			if err := compileSNMP(node, &cfg.System); err != nil {
				return nil, fmt.Errorf("snmp: %w", err)
			}
		case "bridge-domains":
			if err := compileBridgeDomains(node, &cfg.BridgeDomains); err != nil {
				return nil, fmt.Errorf("bridge-domains: %w", err)
			}
		}
	}

	// Extract lo0 filter input from parsed interfaces into SystemConfig.
	if lo0 := cfg.Interfaces.Interfaces["lo0"]; lo0 != nil {
		if u0 := lo0.Units[0]; u0 != nil {
			cfg.System.Lo0FilterInputV4 = u0.FilterInputV4
			cfg.System.Lo0FilterInputV6 = u0.FilterInputV6
		}
	}

	// Post-compilation fixup: resolve vSRX-style fabric member-interfaces.
	// For fab0/fab1 with fabric-options member-interfaces, resolve which member
	// belongs to the local node using FPC slot → node-id mapping (slot 0 → node0,
	// slot 7 → node1). Also auto-populate FabricInterface/Fabric1Interface when
	// not explicitly set in chassis cluster config.
	if cc := cfg.Chassis.Cluster; cc != nil {
		for ifName, ifc := range cfg.Interfaces.Interfaces {
			if !strings.HasPrefix(ifName, "fab") || len(ifc.FabricMembers) == 0 {
				continue
			}
			for _, member := range ifc.FabricMembers {
				slot := InterfaceSlot(member)
				if slot >= 0 && SlotToNodeID(slot) == cc.NodeID {
					ifc.LocalFabricMember = member
					break
				}
			}
		}
		// Auto-detect fabric interfaces from fab0/fab1 member-interfaces
		// when not explicitly configured via fabric-interface/fabric1-interface.
		// Only set if the local node has a member (LocalFabricMember resolved above).
		// Dual-fabric: if both fab0 and fab1 have local members, set both
		// FabricInterface and Fabric1Interface (#130).
		// Single-fabric: only one fab is local → FabricInterface only.
		if cc.FabricInterface == "" {
			if f0, ok := cfg.Interfaces.Interfaces["fab0"]; ok && f0.LocalFabricMember != "" {
				cc.FabricInterface = "fab0"
			} else if f1, ok := cfg.Interfaces.Interfaces["fab1"]; ok && f1.LocalFabricMember != "" {
				cc.FabricInterface = "fab1"
			}
		}
		// Auto-detect secondary fabric: fab1 when primary is fab0 and fab1
		// also has a local member (dual-fabric topology).
		if cc.Fabric1Interface == "" && cc.FabricInterface == "fab0" {
			if f1, ok := cfg.Interfaces.Interfaces["fab1"]; ok && f1.LocalFabricMember != "" {
				cc.Fabric1Interface = "fab1"
			}
		}
		// Auto-derive Fabric1PeerAddress from the fab1 interface's /30 or /31
		// address when not explicitly configured.
		if cc.Fabric1Interface != "" && cc.Fabric1PeerAddress == "" {
			if f1 := cfg.Interfaces.Interfaces[cc.Fabric1Interface]; f1 != nil {
				if u0 := f1.Units[0]; u0 != nil {
					for _, addr := range u0.Addresses {
						if peer := peerFromPointToPoint(addr); peer != "" {
							cc.Fabric1PeerAddress = peer
							break
						}
					}
				}
			}
		}
	}

	// #1526 — reject retired dataplane backends at commit time.
	// Placed BEFORE the other strict validators so that an operator
	// editing a candidate that has BOTH a retired dataplane-type and
	// an unrelated structural error (CoS, policers, scheduler-map)
	// sees the migration message first. The retirement is the
	// documented migration path; the other errors only become
	// actionable after migration. This precheck stays fail-fast
	// (the no-leak contract is pinned by
	// TestDataplaneTypeDPDKRejectedAtCommitFiresFirst in
	// parser_ast_test.go).
	//
	// Store.Load and Store.SyncApply tolerate retired-backend
	// configs via rewriteRetiredDataplaneType which strips the
	// retired leaf from the AST before compile (#1373 ebpf +
	// #1525 dpdk handle both this way). See
	// pkg/configstore/dataplane_retire.go.
	if err := validateDataplaneTypeStrict(cfg); err != nil {
		return nil, err
	}

	// #1538 — accumulate independent strict-validator families so
	// `commit check` surfaces one error per family in a single
	// response. This saves operator round-trips on first-touch
	// upgrades from legacy candidates that carry several dormant
	// structural findings at once. Validators in this group MUST
	// remain independent: each reads its own typed sub-struct of
	// *Config and does not depend on another's success. Each
	// validator still fail-fasts INTERNALLY (one error per family
	// in a single response), which is sufficient for the upgrade
	// UX win; full intra-validator accumulation is deliberately
	// out of scope. If a future validator depends on another's
	// success it must be added as a separate post-accumulator
	// step with its own guard rather than slotted in alongside
	// the independent set.
	var strictErrs []error
	if err := validateClassOfServiceStrict(cfg.ClassOfService); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validateThreeColorPolicersStrict(cfg.Firewall.ThreeColorPolicers); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validatePolicySchedulerReferencesStrict(cfg); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validateRPMProbePinsStrict(cfg); err != nil {
		strictErrs = append(strictErrs, err)
	}
	if err := validateIPMonitoringStrict(cfg); err != nil {
		strictErrs = append(strictErrs, err)
	}
	// #1830 (e): the #1733 equal-flow worker-cap validator
	// (validateEqualFlowWorkerCapStrict / MaxEqualFlowWorkers) is retired.
	// The v8 lease rotation now sizes its per-worker scratch from the true
	// worker count (heap scratch in rotate_epoch_v8.rs), so
	// equal-flow-enforcement no longer fail-opens above 32 workers and the
	// commit-time rejection has nothing left to guard.
	if err := errors.Join(strictErrs...); err != nil {
		return nil, err
	}

	// #1956 device-map cross-entry validation. Strict on commit /
	// commit-check (hard-reject duplicate names/PCI/MAC, RETH key-mac,
	// FPC/node misalignment); lenient on load / peer-sync (warn so an
	// already-persisted or peer-section config still boots — V-1). Runs
	// AFTER the accumulator so a structural CoS/policer error still wins
	// the first-error slot.
	if err := validateDeviceMapStrict(cfg); err != nil {
		if opts.lenientDeviceMap {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("device-map (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2008 policy match-address fail-open gate. Strict on commit /
	// commit-check (hard-reject a typo'd source/destination address
	// that would be silently dropped and — under `*-address-excluded`
	// inversion — fail open to match-all); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots).
	// Runs AFTER the strict accumulator + device-map so a structural
	// CoS/policer/device-map error still wins the first-error slot.
	if err := validatePolicyMatchAddressesStrict(cfg); err != nil {
		if opts.lenientPolicyMatchAddress {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("policy match-address (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2073 IPsec policy proposal cross-reference gate. Strict on commit /
	// commit-check (hard-reject a dangling ipsec policy -> proposal
	// reference that would silently drop the configured perfect-forward-
	// secrecy group to the strongSwan default); lenient on load / peer-sync
	// (warn so an already-persisted or peer-synced config still boots — the
	// render-path safety net in pkg/ipsec preserves the PFS group on that
	// boot). Runs alongside the other tolerant-downgradable cross-ref gates.
	if err := validateIPsecPolicyProposalReferencesStrict(cfg); err != nil {
		if opts.lenientIPsecPolicyProposalRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec policy proposal reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2008 M7 / #2141: event-options attributes-match patterns are RE2
	// regexes (Junos `matches` semantics). The strict validator rejects at
	// commit not only an uncompilable pattern (#2008 M7) but also a malformed
	// match expression and an unknown <field> name (#2141) — both previously
	// fail-open: the runtime matcher silently DROPPED the constraint, turning
	// targeted remediation into broad config mutation while commit succeeded.
	// Strict-reject gives the operator immediate feedback. On the tolerant
	// LOAD path (#2063 review), downgrade to a warning: a config persisted
	// under the pre-#2008 literal-equality matcher could hold a non-RE2
	// pattern or a now-rejected malformed/unknown line, and an upgrading node
	// must still boot through it (mirrors every sibling validator above). The
	// runtime matcher then fails CLOSED on the legacy malformed line (#2141 /
	// #2124 doctrine) so the suspicious policy does not over-fire. Commit
	// stays strict.
	if err := ValidateEventAttributesMatchStrict(cfg); err != nil {
		if opts.lenientEventAttributesMatch {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("event-options attributes-match (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2074 IPsec VPN -> IKE gateway cross-reference. A VPN that
	// references a gateway which is neither a defined gateway object nor a
	// usable inline IP/hostname would render `remote_addrs = <gateway-name>`
	// — a config-object name strongSwan cannot use, a silently-dead tunnel.
	// Strict on commit / commit-check (hard reject so the operator gets a
	// diagnostic); lenient on load / peer-sync (warn so a pre-fix or
	// peer-synced config still boots — #1960 fail-closed-on-load class).
	// Runs on the fully-compiled *Config so both ike{} and ipsec{} gateway
	// definitions are present regardless of stanza authoring order. Mirrors
	// validateDeviceMapStrict / the policy match-address gate above.
	if err := validateIPsecGatewayReferencesStrict(cfg); err != nil {
		if opts.lenientIPsecGatewayRefs {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("ipsec gateway reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	// #2008 H7 security log profile -> stream cross-reference. A
	// `security log profile <name> stream-name <stream>` that names a
	// stream which is not configured would route to nowhere — the operator
	// authored a log profile whose target silently never receives events.
	// Before H7 the whole profile stanza was dropped silently; now it is
	// compiled and the reference is checked. Strict on commit / commit-
	// check (hard reject so the typo is operator-visible); lenient on load
	// / peer-sync (warn so a config persisted by an older binary that
	// dropped the stanza, or a peer-synced config, still boots — #1960
	// fail-closed-on-load class). Runs on the fully-compiled *Config so the
	// stream map is fully populated regardless of authoring order. Mirrors
	// validateIPsecPolicyProposalReferencesStrict.
	if err := validateLogProfileStreamReferencesStrict(cfg); err != nil {
		if opts.lenientLogProfileStreamRef {
			cfg.Warnings = append(cfg.Warnings,
				fmt.Sprintf("security log profile stream reference (downgraded to warning on tolerant path): %v", err))
		} else {
			return nil, err
		}
	}

	if warnings := ValidateConfig(cfg); len(warnings) > 0 {
		for _, w := range warnings {
			cfg.Warnings = append(cfg.Warnings, w)
		}
	}

	// #1814 typed-config track warnings (both strict and lenient paths):
	// track-interface without any priority-cost (no effect),
	// track-priority-cost without track-interface (no effect), and
	// tracking on an address-owner group (priority 255) where the
	// runtime ignores tracking.
	cfg.Warnings = append(cfg.Warnings, vrrpTrackConfigWarnings(cfg)...)

	// #2079: NAT source pool-utilization-alarm threshold gate. Require
	// 0 < clear < raise <= 100. Strict (commit / commit-check): hard-reject a
	// bare `pool-utilization-alarm;` (raise=0/clear=0, always-firing) or an
	// inverted/equal pair. Lenient (load / peer-sync): warn + let the runtime
	// monitor treat raise<=0 as disabled, so an upgraded node loading a legacy
	// config committed before this gate existed still boots (#1960
	// fail-closed-on-compile-failure would otherwise brick it).
	napWarnings, err := validatePoolUtilizationAlarm(cfg, opts.lenientNATPoolAlarmThreshold)
	if err != nil {
		return nil, err
	}
	cfg.Warnings = append(cfg.Warnings, napWarnings...)

	// #2173: static-NAT / NAT64 host-mask gate. #2132 made the Rust
	// dataplane tolerate the canonical /32-/128 host mask and PR #2167 then
	// hardened it to REJECT a non-host mask — so a misconfigured non-host
	// static-NAT match/prefix or NAT64 pool address is now SILENTLY DROPPED
	// at the dataplane (parsed-out, never installed) with no operator
	// feedback. Strict (commit / commit-check): hard-reject a non-host mask
	// (static NAT is strictly host-1:1, NAT64 pool entries are discrete host
	// IPs). Lenient (load / peer-sync): warn so a config committed before
	// this gate existed (or peer-synced) still boots (#1960
	// fail-closed-on-compile-failure would otherwise brick restart); the
	// dataplane drops the bad entry independently, so it is already inert.
	hostMaskWarnings, err := validateNATHostMaskStrict(cfg, opts.lenientNATHostMask)
	if err != nil {
		return nil, err
	}
	cfg.Warnings = append(cfg.Warnings, hostMaskWarnings...)

	// #1892: retired DPDK-era `system dataplane` knobs (cores, memory,
	// socket-mem, rx-mode, ports) parse for stored-config compatibility
	// but configure nothing — warn so the operator knows the stanza is
	// inert instead of silently dropping it.
	cfg.Warnings = append(cfg.Warnings, userspaceRetiredKnobWarnings(cfg)...)

	// #1539: the structural invariant `cfg.System.DPDKDataplane = nil`
	// was added on master (PR #1553) as a runtime safeguard against
	// AST leakage of retired DPDK sub-tree fields. After this PR
	// deletes the DPDKDataplane field entirely (per #1539 author's
	// explicit note: "This is dead code after #1528 (Phase 3) deletes
	// the field entirely; remove this line in #1528"), the field no
	// longer exists, so the Go compiler enforces the invariant at
	// compile time — there is no value to nil out.

	return cfg, nil
}

func validateThreeColorPolicersStrict(policers map[string]*ThreeColorPolicerConfig) error {
	for name, pol := range policers {
		if pol == nil {
			continue
		}
		displayName := pol.Name
		if displayName == "" {
			displayName = name
		}
		if pol.SingleRateConfigured && pol.TwoRateConfigured {
			return fmt.Errorf("firewall three-color-policer %q cannot configure both single-rate and two-rate", displayName)
		}
		if pol.ColorBlindConfigured && pol.ColorAwareConfigured {
			return fmt.Errorf("firewall three-color-policer %q cannot configure both color-blind and color-aware", displayName)
		}
		if pol.CIR == 0 {
			return fmt.Errorf("firewall three-color-policer %q requires positive committed-information-rate", displayName)
		}
		if pol.CBS == 0 {
			return fmt.Errorf("firewall three-color-policer %q requires positive committed-burst-size", displayName)
		}
		if pol.PBS == 0 {
			if pol.TwoRate {
				return fmt.Errorf("firewall three-color-policer %q requires positive peak-burst-size", displayName)
			}
			return fmt.Errorf("firewall three-color-policer %q requires positive excess-burst-size", displayName)
		}
		if pol.TwoRate {
			if pol.PIR == 0 {
				return fmt.Errorf("firewall three-color-policer %q requires positive peak-information-rate", displayName)
			}
			if pol.PIR < pol.CIR {
				return fmt.Errorf("firewall three-color-policer %q peak-information-rate must be >= committed-information-rate", displayName)
			}
			if pol.PBS < pol.CBS {
				return fmt.Errorf("firewall three-color-policer %q peak-burst-size must be >= committed-burst-size", displayName)
			}
		}
	}
	return nil
}

// validateDataplaneTypeStrict rejects retired dataplane backends at
// commit time. The parse path accepts `dataplane-type dpdk` as a
// legal known value (see compileSystemDataplaneType +
// validDataplaneType) so that `load merge` / `load override` of a
// pre-retirement config does not syntax-error; this strict validator
// is what tells the operator to migrate.
//
// Acceptance criterion in #1526 pins the verbatim message:
//
//	"the DPDK dataplane backend has been retired; use 'set system dataplane-type userspace' (see #1525)"
//
// Tests substring-match the phrase so the same assertion holds
// whether the error is observed via `CompileConfig` directly,
// via `Store.CommitCheck()` (which returns the raw error), or via
// `Store.Commit()` (which wraps it as "commit check failed: ...").
func validateDataplaneTypeStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	if cfg.System.DataplaneType == dataplaneTypeDPDK {
		return ErrDPDKDataplaneRetired
	}
	if cfg.System.DataplaneType == dataplaneTypeEBPF {
		return ErrEBPFDataplaneRetired
	}
	return nil
}

func validatePolicySchedulerReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil || pol.SchedulerName == "" {
			return nil
		}
		if _, ok := cfg.Schedulers[pol.SchedulerName]; ok {
			return nil
		}
		if scope != "" {
			return fmt.Errorf("%s policy %q references undefined scheduler %q", scope, pol.Name, pol.SchedulerName)
		}
		return fmt.Errorf("policy %q references undefined scheduler %q", pol.Name, pol.SchedulerName)
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if err := check("", pol); err != nil {
				return err
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if err := check("global", pol); err != nil {
			return err
		}
	}
	return nil
}

// validateIPsecPolicyProposalReferencesStrict hard-rejects an IPsec
// (Phase 2) policy whose `proposals` reference does not resolve to a
// defined IPsec proposal (#2073). resolveESPSettings (pkg/ipsec/ike.go)
// resolves the policy's proposal ref, or falls back to the policy name
// when no `proposals` leaf is given. When that reference dangles, the
// renderer would otherwise fall through to `esp_proposals = default`,
// silently substituting the operator's entire Phase-2 proposal set —
// including any configured perfect-forward-secrecy DH group — with the
// strongSwan default (which carries no required modp term). That is the
// same silent-crypto-weakening class ValidateDHGroup closes for DH-group
// leaves; this validator closes it for the policy→proposal cross-
// reference.
//
// Rejected unconditionally (not only when PFSGroup > 0): a dangling
// reference substitutes the whole proposal, not just PFS. Mirrors
// validatePolicySchedulerReferencesStrict, which rejects any undefined
// scheduler reference.
//
// On the tolerant load / peer-sync paths the call site downgrades this
// to a warning (opts.lenientIPsecPolicyProposalRef) so an already-
// persisted or peer-synced config still boots; the render-path safety
// net in resolveESPSettings preserves the configured PFS group on that
// boot rather than dropping it.
func validateIPsecPolicyProposalReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	policies := cfg.Security.IPsec.Policies
	proposals := cfg.Security.IPsec.Proposals
	// Policies is a map (unordered); sort keys so the first-error
	// commit-check message is deterministic across runs.
	names := make([]string, 0, len(policies))
	for name := range policies {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		pol := policies[name]
		if pol == nil {
			continue
		}
		propRef := pol.Proposals
		explicitRef := propRef != ""
		if !explicitRef {
			// Mirror resolveESPSettings' policy-name fallback: a policy
			// with no `proposals` leaf resolves against a proposal named
			// after the policy itself.
			propRef = pol.Name
		}
		if _, ok := proposals[propRef]; ok {
			continue
		}
		if explicitRef {
			return fmt.Errorf("ipsec policy %q references undefined ipsec proposal %q "+
				"(the configured proposal set, including any perfect-forward-secrecy "+
				"group, would be silently dropped to the strongSwan default)",
				pol.Name, propRef)
		}
		// No explicit `proposals` leaf was given, so do not blame a
		// phantom proposal named after the policy — describe the actual
		// gap instead.
		return fmt.Errorf("ipsec policy %q has no resolvable ipsec proposal "+
			"(no `proposals` reference and no proposal named %q); the configured "+
			"perfect-forward-secrecy group would be silently dropped — define a "+
			"proposal or reference one", pol.Name, pol.Name)
	}
	return nil
}

// validateLogProfileStreamReferencesStrict hard-rejects a
// `security log profile <name>` whose `stream-name` reference does not
// resolve to a configured `security log stream` (#2008 H7). xpf routes
// log events per stream (a Junos superset — every matching stream
// receives the event), so a profile's `stream-name` designates the
// stream that carries its events. A profile naming a stream that is not
// configured routes to nowhere: the operator authored a log profile
// whose target silently never fires. Before H7 the whole profile stanza
// was dropped before compile, so the typo was invisible; now the
// reference is validated.
//
// A profile with no `stream-name` is accepted: Junos permits a profile
// that relies on the global routing inheritance, and there is nothing to
// dangle. Only a non-empty `stream-name` that misses the stream map is
// rejected.
//
// Note: compileLog only records a stream in Log.Streams when it has a
// host (a host-less stream is not a real destination and is dropped by
// the stream loop), so a profile referencing a host-less stream is
// treated as a dangling reference — consistent with the stream's own
// "must have a host to exist" semantics.
//
// On the tolerant load / peer-sync paths the call site downgrades this
// to a warning (opts.lenientLogProfileStreamRef) so an already-persisted
// config (older binaries dropped the stanza entirely) or a peer-synced
// config still boots. Mirrors validateIPsecPolicyProposalReferencesStrict.
func validateLogProfileStreamReferencesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	profiles := cfg.Security.Log.Profiles
	if len(profiles) == 0 {
		return nil
	}
	streams := cfg.Security.Log.Streams
	// Profiles is a map (unordered); sort keys so the first-error
	// commit-check message is deterministic across runs.
	names := make([]string, 0, len(profiles))
	for name := range profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := profiles[name]
		if p == nil || p.StreamName == "" {
			continue
		}
		if _, ok := streams[p.StreamName]; ok {
			continue
		}
		return fmt.Errorf("security log profile %q references undefined "+
			"log stream %q (the profile would route to nowhere — define "+
			"the stream or fix the stream-name)", p.Name, p.StreamName)
	}
	return nil
}

// validatePolicyMatchAddressesStrict hard-rejects a policy
// source-address / destination-address token that is neither a known
// address-book name (Address or AddressSet), the `any` keyword, nor a
// parseable CIDR / bare IP (#2008). Such a token (a typo) reaches the
// dataplane as an opaque string, fails CIDR/IP parsing in the Rust
// literal parser, and is silently dropped to an empty set. Under
// `*-address-excluded` inversion an empty set evaluates to MATCH-ALL —
// a silent fail-open security bypass (a policy meant to exclude one
// address ends up matching every address). Failing the typo at commit
// turns the bypass into an operator-visible error.
//
// Legitimate forms accepted: address-book names, `any` (and the
// family-scoped `any-ipv4` / `any-ipv6`, which compilePolicy already
// normalizes to `0.0.0.0/0` / `::/0` and which parse as CIDRs anyway),
// literal CIDRs, and bare IPv4 / IPv6 addresses. Junos address RANGES
// are an address-book construct (expanded to /32s under the book) and
// are referenced from a policy only by book NAME, so no range form
// reaches this token list.
func validatePolicyMatchAddressesStrict(cfg *Config) error {
	if cfg == nil {
		return nil
	}
	// Collect valid address-book names (Addresses + AddressSets).
	bookNames := make(map[string]bool)
	if ab := cfg.Security.AddressBook; ab != nil {
		for name := range ab.Addresses {
			bookNames[name] = true
		}
		for name := range ab.AddressSets {
			bookNames[name] = true
		}
	}
	validToken := func(tok string) bool {
		switch tok {
		case "", "any", "any-ipv4", "any-ipv6":
			return true
		}
		if bookNames[tok] {
			return true
		}
		if _, _, err := net.ParseCIDR(tok); err == nil {
			return true
		}
		return net.ParseIP(tok) != nil
	}
	check := func(scope string, pol *Policy) error {
		if pol == nil {
			return nil
		}
		for _, addr := range pol.Match.SourceAddresses {
			if !validToken(addr) {
				return policyMatchAddressError(scope, pol.Name, "source-address", addr)
			}
		}
		for _, addr := range pol.Match.DestinationAddresses {
			if !validToken(addr) {
				return policyMatchAddressError(scope, pol.Name, "destination-address", addr)
			}
		}
		return nil
	}
	for _, zpp := range cfg.Security.Policies {
		if zpp == nil {
			continue
		}
		for _, pol := range zpp.Policies {
			if err := check("", pol); err != nil {
				return err
			}
		}
	}
	for _, pol := range cfg.Security.GlobalPolicies {
		if err := check("global", pol); err != nil {
			return err
		}
	}
	return nil
}

func policyMatchAddressError(scope, polName, field, addr string) error {
	if scope != "" {
		return fmt.Errorf(
			"%s policy %q: %s %q is not a defined address-book entry, the `any` keyword, or a valid CIDR/IP address",
			scope, polName, field, addr)
	}
	return fmt.Errorf(
		"policy %q: %s %q is not a defined address-book entry, the `any` keyword, or a valid CIDR/IP address",
		polName, field, addr)
}

func validateClassOfServiceStrict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	for _, sched := range cos.Schedulers {
		if sched == nil {
			continue
		}
		if sched.EqualFlowEnforcement && (!sched.TransmitRateExact || sched.TransmitRateBytes == 0) {
			return fmt.Errorf(
				"class-of-service scheduler %q equal-flow-enforcement requires positive transmit-rate exact",
				sched.Name)
		}
		if sched.EqualFlowEnforcement && sched.SurplusSharing {
			return fmt.Errorf(
				"class-of-service scheduler %q equal-flow-enforcement cannot be combined with surplus-sharing",
				sched.Name)
		}
		// #1746: the schema enum validator catches bad values on the
		// set path; re-check here so externally-assembled configs
		// cannot smuggle an unknown policy to the dataplane (which
		// would silently parse it as "slowest").
		switch sched.EqualFlowTargetPolicy {
		case "", "slowest", "mean", "ideal-share":
		default:
			return fmt.Errorf(
				"class-of-service scheduler %q equal-flow-target-policy %q is not one of slowest | mean | ideal-share",
				sched.Name, sched.EqualFlowTargetPolicy)
		}
		// Both buffer-size forms set simultaneously is ambiguous. The compiler
		// always clears the unused field (see compiler_class_of_service.go
		// buffer-size case), so this can only arise in constructed or
		// externally-assembled configs. Reject early rather than silently
		// applying the "byte-size wins" runtime preference.
		if sched.BufferSizeBytes > 0 && sched.BufferSizePercent > 0 {
			return fmt.Errorf(
				"class-of-service scheduler %q has both buffer-size bytes (%d) "+
					"and buffer-size percent (%.4g%%) set; use one form only",
				sched.Name, sched.BufferSizeBytes, sched.BufferSizePercent)
		}
	}
	// Aggregate percent check: Junos does not allow per-queue buffer
	// allocations to exceed 100% of the interface's total buffer pool.
	// Check each scheduler-map independently and reject overcommit here
	// so the runtime never silently over-allocates. A sum of exactly
	// 100% is permitted (full pool allocation).
	//
	// A small epsilon (1e-9) guards against accumulated IEEE 754 rounding
	// when summing multiple float64 percent values: e.g. 33.33% * 3 may
	// round to 99.99000000000001% rather than exactly 99.99%, so the check
	// must not reject legitimate 100%-summing configs.
	const maxTotalBufferPercent = 100.0
	const bufferPercentEpsilon = 1e-9
	for _, schedMap := range cos.SchedulerMaps {
		if schedMap == nil {
			continue
		}
		var totalPercent float64
		for _, entry := range schedMap.Entries {
			if entry == nil || entry.Scheduler == "" {
				continue
			}
			sched, ok := cos.Schedulers[entry.Scheduler]
			if !ok || sched == nil {
				continue
			}
			totalPercent += sched.BufferSizePercent
		}
		if totalPercent > maxTotalBufferPercent+bufferPercentEpsilon {
			return fmt.Errorf(
				"class-of-service scheduler-map %q: "+
					"sum of buffer-size percent across all schedulers is %.4g%% "+
					"(must not exceed 100%%)",
				schedMap.Name, totalPercent)
		}
	}
	return nil
}

// #1830 (e): the #1733 MaxEqualFlowWorkers constant and
// validateEqualFlowWorkerCapStrict were retired together with the Rust
// MAX_WORKERS_SCRATCH cap they mirrored. The v8 lease rotation scratch
// is now heap-sized to the true worker count, so equal-flow-enforcement
// is supported at any configured worker count.

// ValidateConfig performs non-fatal validation on a compiled config.
// Returns warnings for unresolved references and operator-visible
// compatibility/deprecation conditions.
func ValidateConfig(cfg *Config) []string {
	var warnings []string

	// Note (#1476): the previous "ebpf is deprecated" warning was
	// removed because `validateDataplaneTypeStrict` now hard-rejects
	// `dataplane-type ebpf` at commit time with
	// `ErrEBPFDataplaneRetired`. ValidateConfig is never reached for
	// EBPF-typed configs after that gate; keeping the warning here
	// would be dead code.

	// #653: when `services application-identification` is enabled,
	// emit a one-line warning at commit time so operators see what
	// the knob actually does on xpf vs Junos vSRX. The runtime is
	// port + protocol matching only — there is NO L7 DPI / signature
	// engine. See `show services application-identification status`
	// and docs/services-application-identification.md for the full
	// contract.
	if cfg.Services.ApplicationIdentification {
		warnings = append(warnings,
			"services application-identification is enabled, but xpf "+
				"AppID is port+protocol catalog matching only — no L7 "+
				"DPI / signature engine. Run `show services "+
				"application-identification status` for the contract; "+
				"see docs/services-application-identification.md.")
	}

	if userspaceSynCookieProtectionActive(cfg) &&
		(cfg.System.RootAuthentication == nil ||
			cfg.System.RootAuthentication.EncryptedPassword == "") {
		warnings = append(warnings,
			"active userspace-dp SYN-cookie screen profiles require "+
				"system root-authentication encrypted-password material "+
				"for the userspace cookie key; the userspace dataplane "+
				"fails closed until it is set. Legacy eBPF SYN-cookie "+
				"handling uses kernel helpers and is not affected by "+
				"this warning.")
	}

	// #1944 §5.8: warn when a configured login user has no usable auth
	// method — no ssh-* keys AND no usable encrypted-password (absent, or
	// a bare lock sentinel which only locks the account). Mirrors the
	// root-auth warning style above; directly addresses the "non-root
	// operator cannot log in" bug class this issue closes.
	if cfg.System.Login != nil {
		for _, u := range cfg.System.Login.Users {
			if u == nil || u.Name == "" || u.Name == "root" {
				continue
			}
			// A usable password is a non-empty value that is neither a bare
			// lock sentinel ("*"/"!"/"!!") NOR a locked-but-restorable form
			// (any value beginning with "!", e.g. "!$6$salt$hash"). A
			// leading "!" means the account cannot password-login until it
			// is unlocked, so it does not count (Codex #1944 r1 Low).
			pw := u.EncryptedPassword.Reveal()
			usablePassword := pw != "" && pw != "*" && !strings.HasPrefix(pw, "!")
			if len(u.SSHKeys) == 0 && !usablePassword {
				warnings = append(warnings, fmt.Sprintf(
					"login user %s has no usable authentication method: no "+
						"ssh keys and no encrypted-password (a bare lock "+
						"sentinel does not count) — this account cannot log "+
						"in. Set `authentication encrypted-password` (hash "+
						"from `openssl passwd -6`) or an ssh key.", u.Name))
			}
		}
	}

	// Collect valid zone names
	zones := make(map[string]bool)
	for name := range cfg.Security.Zones {
		zones[name] = true
	}

	// Collect valid address-book entries
	addrs := make(map[string]bool)
	if ab := cfg.Security.AddressBook; ab != nil {
		for name := range ab.Addresses {
			addrs[name] = true
		}
		for name := range ab.AddressSets {
			addrs[name] = true
		}
	}

	// Collect valid applications
	apps := make(map[string]bool)
	for name := range cfg.Applications.Applications {
		apps[name] = true
	}
	for name := range cfg.Applications.ApplicationSets {
		apps[name] = true
	}
	// Built-in Junos application names
	builtins := []string{"any", "junos-http", "junos-https", "junos-ssh", "junos-telnet",
		"junos-dns-udp", "junos-dns-tcp", "junos-ping", "junos-icmp-all",
		"junos-bgp", "junos-ospf", "junos-ntp", "junos-dhcp-relay",
		"junos-ftp", "junos-smtp", "junos-icmp6-all", "junos-ike",
		"junos-ipsec-nat-t", "junos-dhcp-client", "junos-dhcp-server",
		"junos-snmp", "junos-syslog", "junos-traceroute", "junos-radius"}
	for _, b := range builtins {
		apps[b] = true
	}

	// Validate application port specs and protocols
	for name, app := range cfg.Applications.Applications {
		if err := validatePortSpec(app.DestinationPort); err != nil {
			warnings = append(warnings, fmt.Sprintf("application %s: destination-port: %v", name, err))
		}
		if err := validatePortSpec(app.SourcePort); err != nil {
			warnings = append(warnings, fmt.Sprintf("application %s: source-port: %v", name, err))
		}
		if app.Protocol != "" {
			if err := validateProtocol(app.Protocol); err != nil {
				warnings = append(warnings, fmt.Sprintf("application %s: %v", name, err))
			}
		}
	}

	// Validate policies
	for _, zpp := range cfg.Security.Policies {
		if zpp.FromZone != "any" && !zones[zpp.FromZone] {
			warnings = append(warnings, fmt.Sprintf(
				"policy from-zone %q: zone not defined", zpp.FromZone))
		}
		if zpp.ToZone != "any" && !zones[zpp.ToZone] {
			warnings = append(warnings, fmt.Sprintf(
				"policy to-zone %q: zone not defined", zpp.ToZone))
		}
		for _, p := range zpp.Policies {
			for _, addr := range p.Match.SourceAddresses {
				if addr != "any" && !addrs[addr] {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: source-address %q not in address-book", p.Name, addr))
				}
			}
			for _, addr := range p.Match.DestinationAddresses {
				if addr != "any" && !addrs[addr] {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: destination-address %q not in address-book", p.Name, addr))
				}
			}
			for _, app := range p.Match.Applications {
				if !apps[app] {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: application %q not defined", p.Name, app))
				}
			}
		}
	}

	// Validate NAT zone references
	for _, rs := range cfg.Security.NAT.Source {
		if rs.FromZone != "" && !zones[rs.FromZone] {
			warnings = append(warnings, fmt.Sprintf(
				"source-nat ruleset %q: from-zone %q not defined", rs.Name, rs.FromZone))
		}
		if rs.ToZone != "" && !zones[rs.ToZone] {
			warnings = append(warnings, fmt.Sprintf(
				"source-nat ruleset %q: to-zone %q not defined", rs.Name, rs.ToZone))
		}
	}
	// Static NAT rule-sets carry a `from zone` scope that the dataplane
	// enforces on the inbound (DNAT) direction (static_nat.rs match_dnat:
	// the entry is skipped unless its from_zone matches the ingress zone
	// name exactly). A typo'd or undefined zone therefore yields a rule
	// that silently never matches, with no other operator signal — mirror
	// the source-NAT zone validation above so the divergence surfaces at
	// commit (#2008 H15).
	for _, rs := range cfg.Security.NAT.Static {
		if rs == nil {
			continue
		}
		if rs.FromZone != "" && !zones[rs.FromZone] {
			warnings = append(warnings, fmt.Sprintf(
				"static-nat ruleset %q: from-zone %q not defined", rs.Name, rs.FromZone))
		}
	}

	// Validate screen references in zones
	for name, zone := range cfg.Security.Zones {
		if zone.ScreenProfile != "" {
			if _, ok := cfg.Security.Screen[zone.ScreenProfile]; !ok {
				warnings = append(warnings, fmt.Sprintf(
					"zone %q: screen profile %q not defined", name, zone.ScreenProfile))
			}
		}
	}

	// Validate address-book entries have valid CIDR or IP formats
	if ab := cfg.Security.AddressBook; ab != nil {
		for name, entry := range ab.Addresses {
			if entry.Value != "" {
				if _, _, err := net.ParseCIDR(entry.Value); err != nil {
					if net.ParseIP(entry.Value) == nil {
						warnings = append(warnings, fmt.Sprintf(
							"address-book %q: invalid address %q", name, entry.Value))
					}
				}
			}
		}
		// Validate address-set members reference valid entries
		for setName, as := range ab.AddressSets {
			for _, m := range as.Addresses {
				if !addrs[m] {
					warnings = append(warnings, fmt.Sprintf(
						"address-set %q: member %q not in address-book", setName, m))
				}
			}
			for _, m := range as.AddressSets {
				if !addrs[m] {
					warnings = append(warnings, fmt.Sprintf(
						"address-set %q: nested set %q not in address-book", setName, m))
				}
			}
		}
	}

	// Validate static route destinations are valid CIDR
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		if sr.Destination != "" {
			if _, _, err := net.ParseCIDR(sr.Destination); err != nil {
				warnings = append(warnings, fmt.Sprintf(
					"static route: invalid destination %q", sr.Destination))
			}
		}
	}

	// Validate DNAT pool references
	if dnat := cfg.Security.NAT.Destination; dnat != nil {
		for _, rs := range dnat.RuleSets {
			for _, rule := range rs.Rules {
				if rule.Then.PoolName != "" {
					if _, ok := dnat.Pools[rule.Then.PoolName]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"destination-nat %q rule %q: pool %q not defined",
							rs.Name, rule.Name, rule.Then.PoolName))
					}
				}
			}
		}
	}

	// Validate SNAT pool references
	for _, rs := range cfg.Security.NAT.Source {
		for _, rule := range rs.Rules {
			if rule.Then.PoolName != "" {
				if _, ok := cfg.Security.NAT.SourcePools[rule.Then.PoolName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"source-nat %q rule %q: pool %q not defined",
						rs.Name, rule.Name, rule.Then.PoolName))
				}
			}
		}
	}

	// Validate zone interface references
	configuredIfaces := make(map[string]bool)
	for name := range cfg.Interfaces.Interfaces {
		configuredIfaces[name] = true
	}
	for zoneName, zone := range cfg.Security.Zones {
		for _, ifName := range zone.Interfaces {
			// Strip unit suffix (e.g. "trust0.0" -> "trust0")
			base := ifName
			if idx := strings.Index(ifName, "."); idx > 0 {
				base = ifName[:idx]
			}
			if !configuredIfaces[base] {
				warnings = append(warnings, fmt.Sprintf(
					"zone %q: interface %q not in interfaces config", zoneName, ifName))
			}
		}
	}

	// Validate scheduler references in policies
	for _, zpp := range cfg.Security.Policies {
		for _, p := range zpp.Policies {
			if p.SchedulerName != "" {
				if _, ok := cfg.Schedulers[p.SchedulerName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"policy %q: scheduler %q not defined", p.Name, p.SchedulerName))
				}
			}
		}
	}
	for _, p := range cfg.Security.GlobalPolicies {
		if p.SchedulerName != "" {
			if _, ok := cfg.Schedulers[p.SchedulerName]; !ok {
				warnings = append(warnings, fmt.Sprintf(
					"global policy %q: scheduler %q not defined", p.Name, p.SchedulerName))
			}
		}
	}

	// Validate routing-instance interface references
	for _, ri := range cfg.RoutingInstances {
		for _, ifName := range ri.Interfaces {
			base := ifName
			if idx := strings.Index(ifName, "."); idx > 0 {
				base = ifName[:idx]
			}
			if !configuredIfaces[base] {
				warnings = append(warnings, fmt.Sprintf(
					"routing-instance %q: interface %q not in interfaces config",
					ri.Name, ifName))
			}
		}
	}

	// Validate firewall filter references on interfaces
	for ifName, ifc := range cfg.Interfaces.Interfaces {
		for unitNum, unit := range ifc.Units {
			if unit.FilterInputV4 != "" {
				if _, ok := cfg.Firewall.FiltersInet[unit.FilterInputV4]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter input %q not defined",
						ifName, unitNum, unit.FilterInputV4))
				}
			}
			if unit.FilterInputV6 != "" {
				if _, ok := cfg.Firewall.FiltersInet6[unit.FilterInputV6]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter input-v6 %q not defined",
						ifName, unitNum, unit.FilterInputV6))
				}
			}
			if unit.FilterOutputV4 != "" {
				if _, ok := cfg.Firewall.FiltersInet[unit.FilterOutputV4]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter output %q not defined",
						ifName, unitNum, unit.FilterOutputV4))
				}
			}
			if unit.FilterOutputV6 != "" {
				if _, ok := cfg.Firewall.FiltersInet6[unit.FilterOutputV6]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"interface %s unit %d: filter output-v6 %q not defined",
						ifName, unitNum, unit.FilterOutputV6))
				}
			}
		}
	}

	// Validate chassis cluster fabric config
	if cc := cfg.Chassis.Cluster; cc != nil {
		// fabric1-interface without fabric1-peer-address (or vice versa) is incomplete
		if (cc.Fabric1Interface != "") != (cc.Fabric1PeerAddress != "") {
			warnings = append(warnings, "chassis cluster: fabric1-interface and fabric1-peer-address must both be set for dual-fabric")
		}
		// Check fabric interfaces are defined in interface config
		for _, pair := range [][2]string{
			{cc.FabricInterface, "fabric-interface"},
			{cc.Fabric1Interface, "fabric1-interface"},
		} {
			ifName, label := pair[0], pair[1]
			if ifName != "" {
				if _, ok := cfg.Interfaces.Interfaces[ifName]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"chassis cluster %s %q: interface not defined", label, ifName))
				}
			}
		}
		// Check control interface is defined
		if cc.ControlInterface != "" {
			if _, ok := cfg.Interfaces.Interfaces[cc.ControlInterface]; !ok {
				warnings = append(warnings, fmt.Sprintf(
					"chassis cluster control-interface %q: interface not defined", cc.ControlInterface))
			}
		}
		// Check fabric member interfaces don't overlap between fab0 and fab1
		if cc.FabricInterface != "" && cc.Fabric1Interface != "" {
			fab0Members := make(map[string]bool)
			if f0 := cfg.Interfaces.Interfaces[cc.FabricInterface]; f0 != nil {
				for _, m := range f0.FabricMembers {
					fab0Members[m] = true
				}
			}
			if f1 := cfg.Interfaces.Interfaces[cc.Fabric1Interface]; f1 != nil {
				for _, m := range f1.FabricMembers {
					if fab0Members[m] {
						warnings = append(warnings, fmt.Sprintf(
							"chassis cluster: fabric member %q shared between %s and %s",
							m, cc.FabricInterface, cc.Fabric1Interface))
					}
				}
			}
		}
	}

	// Validate strict-vip-ownership requires VRRP (incompatible with no-reth-vrrp / private-rg-election)
	if cc := cfg.Chassis.Cluster; cc != nil && (cc.NoRethVRRP || cc.PrivateRGElection) {
		for _, rg := range cc.RedundancyGroups {
			if rg.StrictVIPOwnership {
				warnings = append(warnings, fmt.Sprintf(
					"redundancy-group %d: strict-vip-ownership incompatible with no-reth-vrrp (no VRRP instances to gate on)", rg.ID))
			}
		}
	}

	// Warn if no-reth-vrrp set explicitly — redundant since private-rg-election is now default
	if cc := cfg.Chassis.Cluster; cc != nil && cc.PrivateRGElection && cc.NoRethVRRP {
		warnings = append(warnings, "chassis cluster: no-reth-vrrp is redundant (private-rg-election is the default)")
	}

	if cfg.System.PersistGroupsInheritance {
		warnings = append(warnings, "system commit persist-groups-inheritance configured but group inheritance persistence is not implemented")
	}

	// #2008 H13 Stage 1: the leaf is now typed (schema + field) instead of
	// being silently dropped, but the idle-yield dataplane runtime is not
	// implemented — the userspace AF_XDP workers busy-poll. Warn so the
	// operator knows the knob is accepted but currently has no effect.
	if cfg.ForwardingOptions.AllowDataplaneSleep {
		warnings = append(warnings, "forwarding-options allow-dataplane-sleep configured but is accepted-only — the userspace dataplane workers busy-poll and idle-yield is not yet implemented")
	}

	// #2078: the `security flow tcp-session` presence flags are typed and
	// committed but the userspace AF_XDP dataplane enforces none of them
	// today. no-syn-check / no-syn-check-in-tunnel would gate the
	// session-create SYN check; rst-invalidate-session would tear a session
	// down on RST; no-sequence-check (#2008 M9) would skip sequence-window
	// validation. The dataplane session table is a pure 5-tuple flow entry
	// with no TCP state machine and no sequence/window tracking, so there is
	// nothing for any of these knobs to enforce or skip. This is an
	// intentional, reviewed parity gap (see #2008 M9 and the RST design
	// rationale in docs/active-active-new-connections.md); research #2078
	// converged PLAN-KILL on enforcement. Warn so an operator who sets one
	// of these is not silently misled into believing it has runtime effect.
	if ts := cfg.Security.Flow.TCPSession; ts != nil {
		var unenforced []string
		if ts.NoSynCheck {
			unenforced = append(unenforced, "no-syn-check")
		}
		if ts.NoSynCheckInTunnel {
			unenforced = append(unenforced, "no-syn-check-in-tunnel")
		}
		if ts.RstInvalidateSession {
			unenforced = append(unenforced, "rst-invalidate-session")
		}
		if ts.NoSequenceCheck {
			unenforced = append(unenforced, "no-sequence-check")
		}
		if len(unenforced) > 0 {
			warnings = append(warnings, fmt.Sprintf(
				"security flow tcp-session %s configured but accepted-only — the userspace dataplane has no TCP state machine and does not enforce these knobs (config-only parity, #2078)",
				strings.Join(unenforced, ", ")))
		}
	}

	// #654: warn on `system processes X disable` for a process that
	// bpfrx does not actually manage. Silently accepting the knob (as
	// used to happen with e.g. `utmd disable` on vSRX) means the
	// operator gets no signal that the setting is a no-op.
	for _, proc := range cfg.System.DisabledProcesses {
		if !isKnownProcessName(proc) {
			warnings = append(warnings, fmt.Sprintf(
				"system processes %q disable: bpfrx does not manage %q; setting has no runtime effect", proc, proc))
		}
	}

	// #651: warn when archive-sites include inline `password`
	// credentials. Runtime archival shells out to `scp` with
	// `-o BatchMode=yes`, so the password is silently ignored and
	// archival can fail unless matching SSH keys are already set up.
	if cfg.System.Archival != nil {
		for _, url := range cfg.System.Archival.ArchiveSitesWithPassword {
			warnings = append(warnings, fmt.Sprintf(
				"system archival archive-sites %q: inline password is accepted but ignored — archival uses scp BatchMode and relies on SSH keys, not passwords", url))
		}
	}

	if cfg.System.Services != nil && cfg.System.Services.DNSProxyConfigured {
		warnings = append(warnings, "system services dns dns-proxy configured but DNS proxy/forwarder runtime is not implemented")
	}

	// #1715: `system services dns` no longer selects a systemd-resolved
	// owner runtime branch. xpf owns /etc/resolv.conf directly as a
	// managed plain file and keeps resolved disabled+masked regardless of
	// this stanza. Warn so an operator who set it expecting resolved is
	// not surprised that resolved stays off.
	if cfg.System.Services != nil && cfg.System.Services.DNSEnabled {
		warnings = append(warnings, "system services dns: resolved-owner mode is not supported; xpf manages /etc/resolv.conf directly and keeps systemd-resolved disabled+masked")
	}

	if fm := cfg.Services.FlowMonitoring; fm != nil {
		checkExtWarning := func(kind, name string, exts []string) {
			for _, ext := range exts {
				if ext == "app-id" {
					warnings = append(warnings, fmt.Sprintf(
						"flow-monitoring %s template %s: export-extension app-id configured but application data is not available in flow records", kind, name))
				}
			}
		}
		if fm.Version9 != nil {
			for _, tmpl := range fm.Version9.Templates {
				checkExtWarning("version9", tmpl.Name, tmpl.ExportExtensions)
			}
		}
		if fm.VersionIPFIX != nil {
			for _, tmpl := range fm.VersionIPFIX.Templates {
				checkExtWarning("version-ipfix", tmpl.Name, tmpl.ExportExtensions)
			}
		}
	}

	if cos := cfg.ClassOfService; cos != nil {
		warnedClassifierLossPriority := false
		warnedRewriteLossPriority := false
		for _, class := range cos.ForwardingClasses {
			if class == nil {
				continue
			}
			if class.Queue < 0 || class.Queue > 255 {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service forwarding-class %q uses out-of-range queue %d (expected 0..255)",
					class.Name, class.Queue))
			}
		}
		// #915: surplus-sharing is meaningful only on transmit-rate
		// exact schedulers; warn-and-strip when set without exact so
		// the runtime never sees the no-op flag (see #1183 lesson).
		for _, sched := range cos.Schedulers {
			if sched == nil {
				continue
			}
			if sched.SurplusSharing && !sched.TransmitRateExact {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service scheduler %q surplus-sharing is meaningful only with transmit-rate exact; ignored",
					sched.Name))
				sched.SurplusSharing = false
			}
			// #1746: warn-not-strip. A policy without enforcement is a
			// harmless no-op (the dataplane gates it on
			// equal-flow-enforcement), but the operator should know it
			// is inert.
			if sched.EqualFlowTargetPolicy != "" && !sched.EqualFlowEnforcement {
				warnings = append(warnings, fmt.Sprintf(
					"class-of-service scheduler %q equal-flow-target-policy %q has no effect without equal-flow-enforcement",
					sched.Name, sched.EqualFlowTargetPolicy))
			}
			// #1746: non-work-conserving cost warning. Clipping fast
			// flows frees capacity that CANNOT reach slow flows on
			// other workers, so these policies trade aggregate
			// throughput for per-flow evenness (see
			// docs/cos-traffic-shaping.md).
			if sched.EqualFlowEnforcement {
				switch sched.EqualFlowTargetPolicy {
				case "slowest", "mean":
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service scheduler %q equal-flow-target-policy %s is non-work-conserving: it clips fast flows and reduces aggregate class throughput; it cannot lift slow flows",
						sched.Name, sched.EqualFlowTargetPolicy))
				}
			}
		}
		for _, schedMap := range cos.SchedulerMaps {
			if schedMap == nil {
				continue
			}
			for className, entry := range schedMap.Entries {
				if _, ok := cos.ForwardingClasses[className]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service scheduler-map %q references undefined forwarding-class %q",
						schedMap.Name, className))
				}
				if entry == nil || entry.Scheduler == "" {
					continue
				}
				if _, ok := cos.Schedulers[entry.Scheduler]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service scheduler-map %q references undefined scheduler %q",
						schedMap.Name, entry.Scheduler))
				}
			}
		}
		for _, classifier := range cos.DSCPClassifiers {
			if classifier == nil {
				continue
			}
			for _, entry := range classifier.Entries {
				if entry == nil || entry.ForwardingClass == "" {
					continue
				}
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service dscp classifier %q references undefined forwarding-class %q",
						classifier.Name, entry.ForwardingClass))
				}
				if entry.LossPriority != "" && !warnedClassifierLossPriority {
					warnings = append(warnings, "class-of-service dscp/802.1p classifier loss-priority is accepted for compatibility but not yet enforced by the userspace dataplane")
					warnedClassifierLossPriority = true
				}
			}
		}
		for _, classifier := range cos.IEEE8021Classifiers {
			if classifier == nil {
				continue
			}
			for _, entry := range classifier.Entries {
				if entry == nil || entry.ForwardingClass == "" {
					continue
				}
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service ieee-802.1 classifier %q references undefined forwarding-class %q",
						classifier.Name, entry.ForwardingClass))
				}
				if entry.LossPriority != "" && !warnedClassifierLossPriority {
					warnings = append(warnings, "class-of-service dscp/802.1p classifier loss-priority is accepted for compatibility but not yet enforced by the userspace dataplane")
					warnedClassifierLossPriority = true
				}
			}
		}
		for _, rewriteRule := range cos.DSCPRewriteRules {
			if rewriteRule == nil {
				continue
			}
			for _, entry := range rewriteRule.Entries {
				if entry == nil || entry.ForwardingClass == "" {
					continue
				}
				if _, ok := cos.ForwardingClasses[entry.ForwardingClass]; !ok {
					warnings = append(warnings, fmt.Sprintf(
						"class-of-service dscp rewrite-rule %q references undefined forwarding-class %q",
						rewriteRule.Name, entry.ForwardingClass))
				}
				if entry.LossPriority != "" && !warnedRewriteLossPriority {
					warnings = append(warnings, "class-of-service dscp rewrite-rule loss-priority is accepted for compatibility but not yet enforced by the userspace dataplane")
					warnedRewriteLossPriority = true
				}
			}
		}
		for _, iface := range cos.Interfaces {
			if iface == nil {
				continue
			}
			for _, unit := range iface.Units {
				if unit == nil {
					continue
				}
				if unit.SchedulerMap != "" {
					if _, ok := cos.SchedulerMaps[unit.SchedulerMap]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined scheduler-map %q",
							iface.Name, unit.Unit, unit.SchedulerMap))
					}
				}
				if unit.DSCPClassifier != "" {
					if _, ok := cos.DSCPClassifiers[unit.DSCPClassifier]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined dscp classifier %q",
							iface.Name, unit.Unit, unit.DSCPClassifier))
					}
				}
				if unit.IEEE8021Classifier != "" {
					if _, ok := cos.IEEE8021Classifiers[unit.IEEE8021Classifier]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined ieee-802.1 classifier %q",
							iface.Name, unit.Unit, unit.IEEE8021Classifier))
					}
				}
				if unit.DSCPRewriteRule != "" {
					if _, ok := cos.DSCPRewriteRules[unit.DSCPRewriteRule]; !ok {
						warnings = append(warnings, fmt.Sprintf(
							"class-of-service interface %s unit %d references undefined dscp rewrite-rule %q",
							iface.Name, unit.Unit, unit.DSCPRewriteRule))
					}
				}
			}
		}
		hasCoSRuntimeConfig := len(cos.Interfaces) > 0 ||
			len(cos.DSCPClassifiers) > 0 ||
			len(cos.IEEE8021Classifiers) > 0 ||
			len(cos.DSCPRewriteRules) > 0
		if hasCoSRuntimeConfig && effectiveDataplaneType(cfg.System.DataplaneType) != dataplaneTypeUserspace {
			warnings = append(warnings, "class-of-service shaping, classifier attachment, and dscp rewrite-rule attachment are only implemented in the userspace dataplane; configuration is accepted but will not take effect on this dataplane")
		}

		// #1614 A4: operator-visible warning when the sum of an
		// interface unit's exact-class transmit-rates exceeds the
		// unit's shaping-rate. Under oversubscription, every class
		// will receive less than its configured rate; the visible
		// distribution depends on the unit's oversubscription-policy.
		warnings = append(warnings, validateCoSOversubscriptionWarnings(cos)...)
	}

	// #1706: the next-table and rib-group ip-rule reconcilers program
	// into fixed 100-priority windows that their clear() passes scan.
	// The applier hard-caps at the window boundary so out-of-range rules
	// never leak, but a config that exceeds the window would be silently
	// truncated at apply time. Surface the over-limit condition here at
	// commit time so the operator sees it before applying.
	warnings = append(warnings, validateRoutingRuleWindowWarnings(cfg)...)

	// #1387: DHCP dynamic-DNS live-backend validation. Increment 2 wired the
	// live RFC 2136 backend, so the increment-1 "no records are published"
	// deferred-backend warning is retired. The warnings here flag a config
	// that the now-live path cannot act on (enabled rfc2136 with no
	// update-server), a still-deferred backend (kea-d2), and the now-consumed
	// free-form leaves (update-server parseability, TSIG algorithm support).
	// All are WARN-only (never an error) so a malformed inert value committed
	// against increment 1 cannot brick a boot (plan §4.5 / §7 Q-C).
	warnings = append(warnings, validateDDNSBackendWarnings(cfg)...)

	return warnings
}

// validateDDNSBackendWarnings emits WARN-only commit-time messages for the
// now-live DHCP dynamic-DNS backend (#1387 increment 2). It never returns
// an error: the typed schema already accepts these leaves, and a stricter
// HARD reject would brick a boot on a previously-inert malformed value
// (plan §7 Q-C). The reconciler/backend degrade safely at runtime (an
// unusable backend resolves to a no-op and counts a no-backend skip).
func validateDDNSBackendWarnings(cfg *Config) []string {
	d := cfg.System.DHCPServer.DynamicDNS
	if d == nil || !d.Enabled {
		return nil
	}
	var warnings []string

	backend := d.Backend
	if backend == "" {
		backend = "rfc2136"
	}
	switch backend {
	case "rfc2136":
		if d.UpdateServer == "" {
			warnings = append(warnings, "dhcp dynamic-dns is enabled with "+
				"backend rfc2136 but no update-server is configured; no records "+
				"will be published until an update-server is set")
		} else if !ddnsUpdateServerParseable(d.UpdateServer) {
			warnings = append(warnings, fmt.Sprintf("dhcp dynamic-dns "+
				"update-server %q is not a valid host or host:port; the backend "+
				"will fail to send updates", d.UpdateServer))
		}
		if d.TSIGKeyName != "" && !ddnsTSIGAlgorithmSupported(d.TSIGAlgorithm) {
			warnings = append(warnings, fmt.Sprintf("dhcp dynamic-dns "+
				"tsig-algorithm %q is not supported (use hmac-sha1, hmac-sha224, "+
				"hmac-sha256, hmac-sha384, or hmac-sha512; hmac-md5 is rejected as "+
				"insecure); the backend will fail to sign updates", d.TSIGAlgorithm))
		}
	case "kea-d2":
		warnings = append(warnings, "dhcp dynamic-dns backend kea-d2 is "+
			"reserved but not implemented (Kea D2 is not in the image); no "+
			"records will be published with this backend")
	}
	return warnings
}

// ddnsUpdateServerParseable reports whether an update-server string is a
// usable host or host:port (mirrors the backend's normalizeUpdateServer).
func ddnsUpdateServerParseable(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if _, _, err := net.SplitHostPort(s); err == nil {
		return true
	}
	// No port: treat as a bare host (the backend attaches :53). Reject only
	// when it is obviously not a host (e.g. embedded whitespace).
	return !strings.ContainsAny(s, " \t")
}

// ddnsTSIGAlgorithmSupported reports whether a TSIG algorithm string is one
// the backend can sign with (default hmac-sha256 when unset; hmac-md5
// rejected). Mirrors ddns_rfc2136.canonicalTSIGAlgorithm without importing
// the dhcpserver package into pkg/config.
func ddnsTSIGAlgorithmSupported(algo string) bool {
	a := strings.ToLower(strings.TrimSpace(algo))
	a = strings.TrimSuffix(a, ".")
	switch a {
	case "", "hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512":
		return true
	default:
		return false
	}
}

// validateRoutingRuleWindowWarnings emits commit-time warnings when a
// config would program more next-table or rib-group ip rules than the
// applier's fixed priority window can hold (see pkg/routing/rules.go:
// nextTableRulePriority window of 100, ribGroupRulePriority window of
// 100 split into 50 v4+v6 pairs). The counts here are CONSERVATIVE
// upper bounds computed from the same inputs the applier consumes —
// they intentionally do NOT replicate the applier's exact skip/dedup
// logic (unknown-instance skips, self-only rib-groups, duplicate source
// tables), so they may warn slightly early but never miss a real
// truncation. The runtime accepts the config; the apply-time cap is the
// hard guard against the rule leak.
func validateRoutingRuleWindowWarnings(cfg *Config) []string {
	var warnings []string

	// next-table: the applier feeds it the global inet + inet6 static
	// routes (daemon_apply.go), counting those with a NextTable set.
	const nextTableWindow = 100
	nextTableRoutes := 0
	for _, sr := range cfg.RoutingOptions.StaticRoutes {
		if sr != nil && sr.NextTable != "" {
			nextTableRoutes++
		}
	}
	for _, sr := range cfg.RoutingOptions.Inet6StaticRoutes {
		if sr != nil && sr.NextTable != "" {
			nextTableRoutes++
		}
	}
	if nextTableRoutes > nextTableWindow {
		warnings = append(warnings, fmt.Sprintf(
			"routing-options: %d static routes use next-table, but only %d can be "+
				"programmed as ip rules; routes beyond the limit will be ignored at "+
				"apply time. Reduce the number of next-table routes.",
			nextTableRoutes, nextTableWindow))
	}

	// rib-group: the applier walks routing-instances and programs two ip
	// rules (v4+v6) per source table that references an interface-routes
	// rib-group. Window of 100 priorities fits 50 such tables.
	const ribGroupTableLimit = 50
	ribGroupInstances := 0
	for _, inst := range cfg.RoutingInstances {
		if inst == nil {
			continue
		}
		if inst.InterfaceRoutesRibGroup != "" || inst.InterfaceRoutesRibGroupV6 != "" {
			ribGroupInstances++
		}
	}
	if ribGroupInstances > ribGroupTableLimit {
		warnings = append(warnings, fmt.Sprintf(
			"routing-options: %d routing-instances reference an interface-routes "+
				"rib-group, but only %d leaking tables can be programmed as ip rules "+
				"(two priorities each); instances beyond the limit will be ignored at "+
				"apply time. Reduce the number of rib-group-leaking instances.",
			ribGroupInstances, ribGroupTableLimit))
	}

	return warnings
}

// validateCoSOversubscriptionWarnings emits commit-time warnings for
// every CoS interface unit whose sum of exact-class transmit rates
// exceeds the unit's configured shaping-rate. Warnings are non-fatal;
// the runtime accepts the config and the new
// oversubscription-policy knob (#1614 A1) governs distribution.
func validateCoSOversubscriptionWarnings(cos *ClassOfServiceConfig) []string {
	var warnings []string
	if cos == nil {
		return warnings
	}
	for ifaceName, iface := range cos.Interfaces {
		if iface == nil {
			continue
		}
		for unitID, unit := range iface.Units {
			if unit == nil || unit.ShapingRateBytes == 0 || unit.SchedulerMap == "" {
				continue
			}
			schedMap, ok := cos.SchedulerMaps[unit.SchedulerMap]
			if !ok || schedMap == nil {
				continue
			}
			var sumExact uint64
			for _, entry := range schedMap.Entries {
				if entry == nil || entry.Scheduler == "" {
					continue
				}
				sched, ok := cos.Schedulers[entry.Scheduler]
				if !ok || sched == nil || !sched.TransmitRateExact {
					continue
				}
				sumExact += sched.TransmitRateBytes
			}
			if sumExact <= unit.ShapingRateBytes {
				continue
			}
			policyTail := "proportional (default): each class receives classRate × shaping / sumExact (current behaviour)"
			if unit.OversubscriptionPolicy == "guarantee-rate" {
				policyTail = fmt.Sprintf(
					"guarantee-rate %g: small classes honoured to configured rate; larger classes share residual proportionally (see #1614)",
					unit.OversubscriptionGuaranteeFraction,
				)
			}
			warnings = append(warnings, fmt.Sprintf(
				"class-of-service interfaces %s unit %d: sum of exact-class transmit-rates (%d B/s) exceeds shaping-rate (%d B/s); under oversubscription the configured oversubscription-policy=%s",
				ifaceName, unitID, sumExact, unit.ShapingRateBytes, policyTail,
			))
		}
	}
	return warnings
}

const (
	dataplaneTypeEBPF      = "ebpf"
	dataplaneTypeDPDK      = "dpdk"
	dataplaneTypeUserspace = "userspace"
)

func effectiveDataplaneType(dpType string) string {
	if dpType == "" {
		return dataplaneTypeUserspace
	}
	return dpType
}

func validDataplaneType(dpType string) bool {
	switch dpType {
	case dataplaneTypeEBPF, dataplaneTypeDPDK, dataplaneTypeUserspace:
		return true
	default:
		return false
	}
}

func userspaceSynCookieProtectionActive(cfg *Config) bool {
	if cfg == nil || effectiveDataplaneType(cfg.System.DataplaneType) != dataplaneTypeUserspace ||
		cfg.Security.Flow.SynFloodProtectionMode != "syn-cookie" {
		return false
	}
	for _, zone := range cfg.Security.Zones {
		if zone == nil || zone.ScreenProfile == "" {
			continue
		}
		profile := cfg.Security.Screen[zone.ScreenProfile]
		if profile != nil && profile.TCP.SynFlood != nil &&
			profile.TCP.SynFlood.AttackThreshold > 0 {
			return true
		}
	}
	return false
}

// knownManagedProcessNames is the set of Junos process names that bpfrx
// actually honours when `system processes X disable` is configured.
// The runtime sites hard-code their process name (not a table lookup):
//   - pkg/daemon/daemon.go ~:715 — `isProcessDisabled(cfg, "snmpd")`
//   - pkg/daemon/daemon_system.go ~:383 — `isProcessDisabled(cfg, "ntp")`
//
// This table mirrors those hard-codes for the purpose of the #654
// validation warning. Any addition here MUST be paired with a matching
// runtime gating site, or the warning will go quiet while the knob
// remains a no-op.
var knownManagedProcessNames = map[string]struct{}{
	"snmpd": {},
	"ntp":   {},
}

func isKnownProcessName(name string) bool {
	_, ok := knownManagedProcessNames[name]
	return ok
}

func compileApplications(node *Node, apps *ApplicationsConfig) error {
	for _, inst := range namedInstances(node.FindChildren("application")) {
		appName := inst.name
		app := &Application{Name: appName}

		var terms []*Application
		for _, prop := range inst.node.Children {
			switch prop.Name() {
			case "protocol":
				app.Protocol = nodeVal(prop)
			case "destination-port":
				app.DestinationPort = nodeVal(prop)
			case "source-port":
				app.SourcePort = nodeVal(prop)
			case "inactivity-timeout", "timeout":
				if v := nodeVal(prop); v != "" {
					if n, err := strconv.Atoi(v); err == nil {
						app.InactivityTimeout = n
					}
				}
			case "alg":
				app.ALG = nodeVal(prop)
			case "description":
				app.Description = nodeVal(prop)
			case "term":
				// Inline term: "term <name> [alg <a>] protocol <p> [source-port <sp>]
				//               [destination-port <dp>] [inactivity-timeout <t>];"
				if len(prop.Keys) < 2 {
					continue
				}
				// Hierarchical: all values in prop.Keys (inline statement)
				// Flat set: values split across prop.Keys and prop.Children
				allKeys := prop.Keys[1:]
				for _, c := range prop.Children {
					allKeys = append(allKeys, c.Keys...)
				}
				termApps := parseApplicationTerms(appName, allKeys)
				terms = append(terms, termApps...)
			}
		}

		if len(terms) > 0 {
			implicitSet := &ApplicationSet{Name: appName}
			for _, t := range terms {
				t.Description = app.Description
				apps.Applications[t.Name] = t
				implicitSet.Applications = append(implicitSet.Applications, t.Name)
			}
			apps.ApplicationSets[appName] = implicitSet
		} else {
			apps.Applications[appName] = app
		}
	}

	for _, inst := range namedInstances(node.FindChildren("application-set")) {
		as := &ApplicationSet{Name: inst.name}

		for _, member := range inst.node.Children {
			// An application-set member is either an individual application
			// reference (`application <name>`) or a nested application-set
			// reference (`application-set <name>`). Both kinds are stored in
			// as.Applications; ExpandApplicationSet distinguishes them by
			// looking each member name up in apps.ApplicationSets and recursing
			// (max depth 3). Dropping the nested-set arm here silently lost the
			// child set's applications from the parent, so a policy matching the
			// parent set under-matched (#2068). This mirrors compileAddressBook,
			// which handles both `address` and `address-set` members.
			switch member.Name() {
			case "application", "application-set":
				v := nodeVal(member)
				if v != "" {
					as.Applications = append(as.Applications, v)
				}
			}
		}

		apps.ApplicationSets[as.Name] = as
	}

	return nil
}

// parseApplicationTerms parses an inline term like:
// "term-name [alg ssh] protocol tcp [source-port 22] [destination-port 22] [inactivity-timeout 86400]"
// When multiple protocol values are present, returns one Application per
// unique protocol (each sharing the same ports/timeout/alg).
func parseApplicationTerms(parentName string, keys []string) []*Application {
	if len(keys) == 0 {
		return nil
	}
	termName := keys[0]

	var protocols []string
	var dstPort, srcPort, alg string
	var timeout int

	for i := 1; i < len(keys); i++ {
		switch keys[i] {
		case "protocol":
			if i+1 < len(keys) {
				i++
				protocols = append(protocols, normalizeProtocol(keys[i]))
			}
		case "destination-port":
			if i+1 < len(keys) {
				i++
				dstPort = keys[i]
			}
		case "source-port":
			if i+1 < len(keys) {
				i++
				srcPort = keys[i]
			}
		case "inactivity-timeout", "timeout":
			if i+1 < len(keys) {
				i++
				if v, err := strconv.Atoi(keys[i]); err == nil {
					timeout = v
				}
			}
		case "alg":
			if i+1 < len(keys) {
				i++
				alg = keys[i]
			}
		}
	}

	// Deduplicate protocols (e.g. "junos-icmp-all" and "icmp" both normalize to "icmp")
	if len(protocols) == 0 {
		protocols = []string{""}
	}
	seen := make(map[string]bool)
	var unique []string
	for _, p := range protocols {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}

	var result []*Application
	for _, proto := range unique {
		name := parentName + "-" + termName
		if len(unique) > 1 {
			suffix := proto
			if suffix == "" {
				suffix = "any"
			}
			name = parentName + "-" + termName + "-" + suffix
		}
		result = append(result, &Application{
			Name:              name,
			Protocol:          proto,
			DestinationPort:   dstPort,
			SourcePort:        srcPort,
			InactivityTimeout: timeout,
			ALG:               alg,
		})
	}
	return result
}

// normalizeProtocol maps Junos protocol aliases to canonical names
// so that "junos-icmp-all" and "icmp" deduplicate correctly.
func normalizeProtocol(name string) string {
	switch strings.ToLower(name) {
	case "junos-icmp-all", "junos-ping":
		return "icmp"
	case "junos-icmp6-all", "junos-pingv6", "icmp6":
		return "icmpv6"
	case "junos-gre":
		return "gre"
	case "junos-ospf":
		return "89"
	case "junos-tcp-any":
		return "tcp"
	case "junos-udp-any":
		return "udp"
	case "junos-ip-in-ip", "junos-ipip":
		return "4"
	default:
		return name
	}
}

// validatePortSpec checks that a port specification is valid.
// Valid formats: "80", "8080-8090", named ports like "http".
func validatePortSpec(spec string) error {
	if spec == "" {
		return nil
	}
	namedPorts := map[string]bool{
		"http": true, "https": true, "ssh": true, "telnet": true,
		"ftp": true, "ftp-data": true, "smtp": true, "dns": true,
		"pop3": true, "imap": true, "snmp": true, "ntp": true,
		"bgp": true, "ldap": true, "syslog": true,
	}
	if namedPorts[strings.ToLower(spec)] {
		return nil
	}
	if strings.Contains(spec, "-") {
		parts := strings.SplitN(spec, "-", 2)
		lo, err1 := strconv.Atoi(parts[0])
		hi, err2 := strconv.Atoi(parts[1])
		if err1 != nil || err2 != nil {
			return fmt.Errorf("invalid port range %q: non-numeric", spec)
		}
		if lo < 1 || lo > 65535 {
			return fmt.Errorf("invalid port %d: must be 1-65535", lo)
		}
		if hi < 1 || hi > 65535 {
			return fmt.Errorf("invalid port %d: must be 1-65535", hi)
		}
		if lo > hi {
			return fmt.Errorf("invalid port range %q: start > end", spec)
		}
		return nil
	}
	port, err := strconv.Atoi(spec)
	if err != nil {
		return fmt.Errorf("invalid port %q: not a number or known service", spec)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d: must be 1-65535", port)
	}
	return nil
}

// validateProtocol checks that a protocol specification is valid.
func validateProtocol(proto string) error {
	validProtos := map[string]bool{
		"tcp": true, "udp": true, "icmp": true, "icmp6": true, "icmpv6": true,
		"ospf": true, "gre": true, "ipip": true, "ah": true, "esp": true,
		"igmp": true, "pim": true, "sctp": true, "vrrp": true, "egp": true,
	}
	if validProtos[strings.ToLower(proto)] {
		return nil
	}
	// Accept junos-* protocol aliases
	if strings.HasPrefix(strings.ToLower(proto), "junos-") {
		return nil
	}
	n, err := strconv.Atoi(proto)
	if err != nil {
		return fmt.Errorf("invalid protocol %q", proto)
	}
	if n < 0 || n > 255 {
		return fmt.Errorf("invalid protocol number %d: must be 0-255", n)
	}
	return nil
}

func nodeVal(n *Node) string {
	if len(n.Keys) >= 2 {
		return n.Keys[1]
	}
	if len(n.Children) > 0 {
		return n.Children[0].Name()
	}
	return ""
}
