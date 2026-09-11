// Package cmdtree defines the canonical CLI command trees for xpf.
//
// This is the SINGLE SOURCE OF TRUTH for all command trees used by:
//   - pkg/cli (local interactive CLI)
//   - pkg/grpcapi (gRPC completion handler)
//   - cmd/cli (remote CLI client)
//
// When adding a new command, add it here and it automatically appears
// in tab completion, ? help, and resolveCommand across all CLIs.
package cmdtree

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// ValueType classifies the value a typed-leaf node accepts. #1319.
//
// The canonical definition lives in pkg/config (config.ValueType) so the
// config-grammar schema (config.setSchema — the live config-mode `set`
// completion + validation tree) can carry typed-leaf metadata directly
// without a config→cmdtree→config import cycle. cmdtree re-exports the
// type + constants + Placeholder via aliases so its operational-tree
// leaves are unchanged. See #1319 plan §5 ("Type ownership").
type ValueType = config.ValueType

const (
	// ValueAny is the legacy default: any string accepted, no validation.
	ValueAny = config.ValueAny
	// ValueRate is a Junos bandwidth value (bits/sec) with k/m/g suffix.
	ValueRate = config.ValueRate
	// ValueByteSize is a byte-count value with k/m/g suffix.
	ValueByteSize = config.ValueByteSize
	// ValueByteSizeOrPercent is a scheduler buffer size: byte-count with
	// k/m/g suffix, or percent with an explicit % suffix.
	ValueByteSizeOrPercent = config.ValueByteSizeOrPercent
	// ValuePercent is a percent value in the range [0, 100] (no suffix).
	ValuePercent = config.ValuePercent
	// ValueInteger is a bare integer; range enforced by the Validator.
	ValueInteger = config.ValueInteger
	// ValueIdentifier is a bare Junos identifier (no spaces, no quotes).
	ValueIdentifier = config.ValueIdentifier
	// ValueEnumOf is one of a fixed set of names (set lives in Validator).
	ValueEnumOf = config.ValueEnumOf
	// ValueBool is "true" or "false".
	ValueBool = config.ValueBool
	// ValueIPAddress is an IP address without a prefix length (#1319 PR 3).
	ValueIPAddress = config.ValueIPAddress
	// ValueCIDR is an IP address with a prefix length (#1319 PR 3).
	ValueCIDR = config.ValueCIDR
)

// LeafValidator is the typed-leaf validator signature. cfg is the
// candidate Config (may be nil when validation runs on the raw AST before
// compile). Validators return nil for accepted input.
//
// We alias config.LeafValidator (same function signature) so operational
// cmdtree Nodes can carry validators declared in pkg/config directly. The
// config-mode typed-leaf gate (config.SchemaValidate, #1319 PR 1) lives in
// pkg/config and validates config.setSchema; this alias only serves the
// operational tree's own typed leaves and the retained `set system
// dataplane` overlay.
type LeafValidator = config.LeafValidator

// Node defines a completion tree node with description, children, and optional dynamic values.
//
// #1319: optional typed-leaf fields (ValueType, ValueDesc, ValueExamples,
// Validator) describe the value an OPERATIONAL-tree leaf accepts. The zero
// value of ValueType is ValueAny — every existing Node is backward
// compatible by construction. Config-mode typed leaves live on
// config.setSchema, not here (see the two-SSOT note at the top of this
// package / docs/config-schema.md).
type Node struct {
	Desc      string
	Children  map[string]*Node
	DynamicFn func(cfg *config.Config) []string
	// ContextDynamicFn is like DynamicFn but receives the consumed words
	// so completions can depend on earlier arguments (e.g. zone pair).
	ContextDynamicFn func(cfg *config.Config, words []string) []string

	// ValueType, if set to a non-ValueAny value, marks this node as a
	// typed leaf: it accepts exactly one value of the given kind, and
	// SchemaValidate (pkg/config) will invoke Validator on the raw
	// string at commit-check time.
	ValueType ValueType
	// ValueDesc is a one-line human description of the value slot
	// shown in `?` completion (e.g. "Bandwidth (e.g. 100k, 10m, 1g)").
	ValueDesc string
	// ValueExamples lists illustrative values surfaced in `?` completion.
	// These appear as plain completion candidates so operators can pick
	// one. Examples are NOT validated as the only acceptable inputs;
	// Validator owns acceptance.
	ValueExamples []string
	// Validator, if set, is called at SchemaValidate time to accept or
	// reject the raw string at this leaf. cfg may be nil.
	Validator LeafValidator

	// AcceptsArgs marks a node that consumes trailing words this tree
	// deliberately does not model, so Canonicalize resolves the command
	// instead of returning CanonicalUnknown (#8304).
	//
	// It exists because "offers completions" and "accepts an argument" are
	// DIFFERENT properties that HasDynamic conflated. `show log <filename>`
	// takes an argument and has no completion source; before this the only
	// way to say "an argument is legal here" was to attach a DynamicFn that
	// returned nothing — declaring a completion source that does not exist in
	// order to describe acceptance.
	//
	// Having no way to say it was not cosmetic. A caller enforcing a
	// login-class restriction fails CLOSED on anything but CanonicalOK
	// (evaluateCommandRegex, pkg/cli/permissions_regex.go), so an
	// unmodelled-but-legal argument means ANY class carrying allow-commands or
	// deny-commands is refused a lawful command outright. Measured before this
	// change: `show log messages`, `show log 50` — the very `[N]` form that
	// node's own Desc advertises — and every `show configuration <stanza>
	// <deeper>` were CanonicalUnknown.
	//
	// OPT-IN, NEVER A RELAXATION. An unmarked node is exactly as strict as
	// before, so this cannot re-open the #8289 sibling-descent bypass. Set it
	// only where the dispatcher genuinely reads trailing words: it is a claim
	// that the command is REAL, and modelling one the CLI refuses is the
	// mirror defect. `clear security flow session all` is the worked example —
	// it looks like a peer of these, but parseClearSessionFilter rejects `all`
	// as an unknown filter, so it is correctly CanonicalUnknown and is NOT
	// marked.
	//
	// It consumes ARBITRARILY MANY trailing words, because Canonicalize leaves
	// currentNode in place across the skip. That is what a config hierarchy
	// path needs, and why a typed-leaf ValueType — admitting exactly one —
	// cannot express these. A dynamic node used to share this arm and its
	// unbounded absorption; since #9505 it takes one value, like a typed leaf.
	// Under an Options node the absorption stops at the next option keyword.
	AcceptsArgs bool

	// Options marks a node whose dispatcher parses its children as combinable
	// OPTIONS, in any order (#9505): `show security flow session zone trust
	// destination-port 22`, `ping <host> routing-instance <ri> count 5`.
	//
	// Canonicalize gives every value slot exactly one value. Without this
	// flag the word after that value must be a child of the node that took it,
	// or the line is refused: #8289's rule, extended to values. With it, the
	// walk returns to this node's children once an option is complete, so the
	// next option resolves (and is canonicalized) instead of being absorbed as
	// raw text.
	//
	// Set it only where the dispatcher really loops over its arguments.
	// `show route` looks like an option list and is not: handleShowRoute
	// dispatches on args[0] and drops the rest, so `show route table X
	// protocol Y` runs `show route table X`. Marking it would let an anchored
	// deny on that command be stepped around with a sibling keyword, the
	// bypass this flag must not reopen. Honoured only in Canonicalize.
	Options bool
}

// HasDynamic returns true if the node has any dynamic completion function.
func (n *Node) HasDynamic() bool {
	return n.DynamicFn != nil || n.ContextDynamicFn != nil
}

// IsTypedLeaf reports whether the node carries a non-default ValueType,
// i.e. it expects exactly one typed value at the next slot.
func (n *Node) IsTypedLeaf() bool {
	return n.ValueType != ValueAny
}

// DynamicValues returns dynamic completion values, preferring ContextDynamicFn.
func (n *Node) DynamicValues(cfg *config.Config, words []string) []string {
	if n.ContextDynamicFn != nil {
		return n.ContextDynamicFn(cfg, words)
	}
	if n.DynamicFn != nil {
		return n.DynamicFn(cfg)
	}
	return nil
}

// Candidate holds a command name and its description for display.
type Candidate struct {
	Name string
	Desc string
}

// routingInstanceNames returns the configured routing-instance names for the
// `show route instance`, `test routing instance`, and `ping/traceroute
// routing-instance` completers. It skips a nil slice element — the tolerant /
// HA-sync config path (#3494) may leave nil *RoutingInstanceConfig entries the
// daemon's own validators and route builder already tolerate. cmdtree is the
// completion SSOT for the local CLI, remote CLI, and gRPC, so a read-only
// completion request must never panic on that shape (#4866).
// sourceNATPoolNames returns the configured source-NAT pool names for
// completion (session pool filter, deterministic-NAT lookup pool filter).
func sourceNATPoolNames(cfg *config.Config) []string {
	if cfg == nil || cfg.Security.NAT.SourcePools == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Security.NAT.SourcePools))
	for name := range cfg.Security.NAT.SourcePools {
		names = append(names, name)
	}
	return names
}

func routingInstanceNames(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		names = append(names, ri.Name)
	}
	return names
}

// routingInstanceTableNames returns the per-instance route-table names
// (`<instance>.inet.0` / `<instance>.inet6.0`) appended to the main tables for
// `show route table` completion, nil-skipping like routingInstanceNames
// (#4866).
func routingInstanceTableNames(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	names := make([]string, 0, 2*len(cfg.RoutingInstances))
	for _, ri := range cfg.RoutingInstances {
		if ri == nil {
			continue
		}
		names = append(names, ri.Name+".inet.0", ri.Name+".inet6.0")
	}
	return names
}

// redundancyGroupIDs returns the configured redundancy-group IDs for the
// `request chassis cluster failover [reset] redundancy-group` completers,
// skipping a nil *RedundancyGroup entry the tolerant / HA-sync path (#3494)
// may leave in the slice (#4866).
func redundancyGroupIDs(cfg *config.Config) []string {
	if cfg == nil || cfg.Chassis.Cluster == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Chassis.Cluster.RedundancyGroups))
	for _, rg := range cfg.Chassis.Cluster.RedundancyGroups {
		if rg == nil {
			continue
		}
		names = append(names, fmt.Sprintf("%d", rg.ID))
	}
	return names
}

// OperationalTree defines tab completion for operational mode.
// This is the canonical source — all other trees derive from this.
var OperationalTree = map[string]*Node{
	"configure": {Desc: "Manipulate software configuration information", Children: map[string]*Node{
		"exclusive": {Desc: "Enter exclusive configuration mode"},
	}},
	"show": {Desc: "Show system information", Children: map[string]*Node{
		"chassis": {Desc: "Show chassis information", Children: map[string]*Node{
			"cluster": {Desc: "Show cluster/HA status", Children: map[string]*Node{
				"status":      {Desc: "Show cluster node status"},
				"interfaces":  {Desc: "Show cluster interfaces"},
				"information": {Desc: "Show cluster configuration details"},
				"statistics":  {Desc: "Show cluster statistics"},
				"fabric": {Desc: "Show fabric link information", Children: map[string]*Node{
					"statistics": {Desc: "Show fabric redirect statistics"},
				}},
				"control-plane": {Desc: "Show control-plane information", Children: map[string]*Node{
					"statistics": {Desc: "Show control-plane statistics"},
				}},
				"data-plane": {Desc: "Show data-plane information", Children: map[string]*Node{
					"statistics": {Desc: "Show data-plane statistics"},
					"interfaces": {Desc: "Show data-plane interfaces"},
					"fairness":   {Desc: "Show userspace fairness RSS structure"},
					"flows": {Desc: "Show userspace flow-to-worker diagnostics", Children: map[string]*Node{
						"all":   {Desc: "Show all helper-reported flow-to-worker rows"},
						"limit": {Desc: "Limit flow-to-worker rows"},
					}},
				}},
				"ip-monitoring": {Desc: "Show IP monitoring information", Children: map[string]*Node{
					"status": {Desc: "Show IP monitoring status"},
				}},
				"fence-status": {Desc: "Show peer fencing configuration and history"},
			}},
			"device-map": {Desc: "Show bare-metal device-map bindings (#1956)", Children: map[string]*Node{
				"candidates": {Desc: "List every NIC (addr/MAC/name/link) to author a device-map"},
			}},
			"alarms":         {Desc: "Show chassis alarm status"},
			"environment":    {Desc: "Show chassis environment"},
			"forwarding":     {Desc: "Show forwarding daemon status and utilization"},
			"hardware":       {Desc: "Show installed hardware components"},
			"routing-engine": {Desc: "Show Routing Engine status"},
		}},
		"class-of-service": {Desc: "Show class-of-service information", Children: map[string]*Node{
			"interface": {Desc: "Show per-interface CoS configuration"},
			"classifier": {Desc: "Show configured CoS classifiers", DynamicFn: func(cfg *config.Config) []string {
				return cosClassifierNames(cfg)
			}, Children: map[string]*Node{
				"name": {Desc: "Filter by classifier name", DynamicFn: func(cfg *config.Config) []string {
					return cosClassifierNames(cfg)
				}},
				"type": {Desc: "Filter by code-point type", Children: map[string]*Node{
					"dscp":       {Desc: "DSCP classifiers"},
					"ieee-802.1": {Desc: "IEEE 802.1p classifiers"},
					// #7080: the third ENFORCED behavior-aggregate classifier
					// (#6847). Without this value the filter could not name it,
					// and FormatCoSClassifiers had no arm for it either — so
					// the one classifier type the operator could not inspect
					// was the one steering their queueing.
					"inet-precedence": {Desc: "IP-precedence classifiers"},
				}},
			}},
			"scheduler-map": {Desc: "Show configured CoS scheduler-maps", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil || cfg.ClassOfService == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.ClassOfService.SchedulerMaps))
				for name := range cfg.ClassOfService.SchedulerMaps {
					names = append(names, name)
				}
				return names
			}},
			"forwarding-class": {Desc: "Show the forwarding-class to queue table"},
			// #6848 (#4228 Gap 7 residual): the one Junos CoS show command the
			// Gap 7 pass did not land. It matters more now than it did then —
			// `rewrite-rules` has since grown ieee-802.1, inet-precedence and
			// exp families, three of which are accepted-but-inert, so without
			// this command an operator can configure four kinds of rewrite rule,
			// three of which do nothing, and has no way to display any of them.
			"rewrite-rule": {Desc: "Show configured CoS rewrite-rules", DynamicFn: func(cfg *config.Config) []string {
				return cosRewriteRuleNames(cfg)
			}, Children: map[string]*Node{
				"name": {Desc: "Filter by rewrite-rule name", DynamicFn: func(cfg *config.Config) []string {
					return cosRewriteRuleNames(cfg)
				}},
				"type": {Desc: "Filter by code-point type", Children: map[string]*Node{
					"dscp":            {Desc: "DSCP rewrite-rules"},
					"ieee-802.1":      {Desc: "IEEE 802.1p (PCP) rewrite-rules (accepted-but-inert)"},
					"inet-precedence": {Desc: "IP-precedence rewrite-rules (accepted-but-inert)"},
					"exp":             {Desc: "MPLS EXP rewrite-rules (accepted-but-inert)"},
				}},
			}},
		}},

		// #8304: every stanza below is a CONFIG HIERARCHY ROOT, and
		// `show configuration <path...>` joins every remaining word into that
		// path (pkg/cli/cli_show.go). The depth is unbounded and belongs to the
		// config schema, not to this tree, so each leaf declares AcceptsArgs
		// rather than the tree trying to mirror a second schema. Before this,
		// `show configuration security zones` and every sibling — system
		// services, interfaces ge-0/0/0, firewall filter f1 — were
		// CanonicalUnknown, so a restricted class was refused all of them.
		"configuration": {Desc: "Show active configuration", Children: map[string]*Node{
			"applications": {Desc: "Application protocol definitions", AcceptsArgs: true},
			// #9064: `groups` and `apply-groups` are real config stanzas and were
			// absent from this map entirely, so `show configuration groups` was
			// CanonicalUnknown rather than merely arg-less.
			"apply-groups":       {Desc: "Applied configuration groups", AcceptsArgs: true},
			"groups":             {Desc: "Configuration groups", AcceptsArgs: true},
			"chassis":            {Desc: "Chassis configuration", AcceptsArgs: true},
			"class-of-service":   {Desc: "Class-of-service configuration", AcceptsArgs: true},
			"event-options":      {Desc: "Event processing configuration", AcceptsArgs: true},
			"firewall":           {Desc: "Firewall filter configuration", AcceptsArgs: true},
			"forwarding-options": {Desc: "Forwarding options configuration", AcceptsArgs: true},
			"interfaces":         {Desc: "Interface configuration", AcceptsArgs: true},
			"policy-options":     {Desc: "Policy framework configuration", AcceptsArgs: true},
			"protocols":          {Desc: "Routing protocol configuration", AcceptsArgs: true},
			"routing-instances":  {Desc: "Routing instance configuration", AcceptsArgs: true},
			"routing-options":    {Desc: "Protocol-independent routing options", AcceptsArgs: true},
			"schedulers":         {Desc: "Scheduler configuration", AcceptsArgs: true},
			"security":           {Desc: "Security configuration", AcceptsArgs: true},
			"services":           {Desc: "Service configuration", AcceptsArgs: true},
			"snmp":               {Desc: "SNMP configuration", AcceptsArgs: true},
			"system":             {Desc: "System configuration", AcceptsArgs: true},
		}},
		"dhcp": {Desc: "Show DHCP information", Children: map[string]*Node{
			"leases":            {Desc: "Show DHCP leases"},
			"client-identifier": {Desc: "Show DHCPv6 DUID(s)"},
		}},
		"firewall": {Desc: "Show firewall filter configuration", Children: map[string]*Node{
			"effective": {Desc: "Show effective (compiled) firewall filter the dataplane receives"},
			"filter": {Desc: "Show specific filter by name", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Firewall.FiltersInet)+len(cfg.Firewall.FiltersInet6))
				for n := range cfg.Firewall.FiltersInet {
					names = append(names, n)
				}
				for n := range cfg.Firewall.FiltersInet6 {
					names = append(names, n)
				}
				return names
			},
				// #9505: `family <f>` and `effective` are read anywhere after the
				// filter name (firewallFamilyArg / firewallArgsHaveWord), so they
				// are options of THIS node. They are not options of `show
				// firewall`: the dispatcher honours them only after `filter
				// <name>`, and `show firewall family inet filter X` lists every
				// filter.
				Options: true,
				Children: map[string]*Node{
					"effective": {Desc: "Show the effective (compiled) filter the dataplane receives"},
					"family":    {Desc: "Address family (inet, inet6)", ValueType: ValueIdentifier},
				}},
		}},
		"flow-monitoring": {Desc: "Show flow monitoring/NetFlow configuration", Children: map[string]*Node{
			"statistics": {Desc: "Show per-collector NetFlow v9/IPFIX write-health"},
		}},
		"log": {Desc: "Show daemon log entries [N]", AcceptsArgs: true},
		"route": {Desc: "Show routing table information", Children: map[string]*Node{
			"<destination>": {Desc: "IP address or prefix to look up", Children: map[string]*Node{
				"exact":    {Desc: "Exactly match the prefix"},
				"longer":   {Desc: "More-specific (longer) prefixes"},
				"orlonger": {Desc: "Equal or more-specific prefixes"},
			}},
			"terse":   {Desc: "Display terse output"},
			"detail":  {Desc: "Display detailed output"},
			"summary": {Desc: "Show routing table statistics"},
			"table": {Desc: "Show routes in named routing table", DynamicFn: func(cfg *config.Config) []string {
				// Include main tables plus per-instance tables. #4866:
				// routingInstanceTableNames nil-skips tolerated nil RI entries.
				return append([]string{"inet.0", "inet6.0"}, routingInstanceTableNames(cfg)...)
			}},
			"protocol": {Desc: "Show routes learned from named protocol", DynamicFn: func(_ *config.Config) []string {
				return []string{"static", "direct", "local", "ospf", "bgp", "rip", "isis", "kernel", "connected"}
			}},
			"instance": {Desc: "Show routes for a routing instance", DynamicFn: func(cfg *config.Config) []string {
				return routingInstanceNames(cfg) // #4866: nil-skip tolerated entries
			}},
		}},
		"security": {Desc: "Show security information", Children: map[string]*Node{
			"zones": {Desc: "Show security zone information", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Security.Zones))
				for name := range cfg.Security.Zones {
					names = append(names, name)
				}
				return names
			}, Children: map[string]*Node{
				"detail": {Desc: "Show detailed zone information"},
				"terse":  {Desc: "Display terse output"},
			}},
			"policies": {Desc: "Show security firewall policies", Children: map[string]*Node{
				"global":      {Desc: "Show global security policy information"},
				"policy-name": {Desc: "Show policy matching a specific name"},
				"brief":       {Desc: "Show brief policy summary"},
				"detail":      {Desc: "Show detailed policy information"},
				"hit-count":   {Desc: "Show policy hit counters [from-zone X to-zone Y]"},
				"from-zone": {Desc: "Filter by source zone", DynamicFn: func(cfg *config.Config) []string {
					if cfg == nil {
						return nil
					}
					names := make([]string, 0, len(cfg.Security.Zones))
					for name := range cfg.Security.Zones {
						names = append(names, name)
					}
					return names
				}, Children: map[string]*Node{
					"to-zone": {Desc: "Filter by destination zone", DynamicFn: func(cfg *config.Config) []string {
						if cfg == nil {
							return nil
						}
						names := make([]string, 0, len(cfg.Security.Zones))
						for name := range cfg.Security.Zones {
							names = append(names, name)
						}
						return names
					}, Children: map[string]*Node{
						"policy": {Desc: "Filter by policy name", ContextDynamicFn: func(cfg *config.Config, words []string) []string {
							if cfg == nil {
								return nil
							}
							// Extract from-zone and to-zone from consumed words.
							var fromZone, toZone string
							for i, w := range words {
								if w == "from-zone" && i+1 < len(words) {
									fromZone = words[i+1]
								}
								if w == "to-zone" && i+1 < len(words) {
									toZone = words[i+1]
								}
							}
							if fromZone == "" || toZone == "" {
								return nil
							}
							for _, zpp := range cfg.Security.Policies {
								// #3476: skip a nil zone-pair set (tolerant /
								// HA-sync config path the runtime walker skips)
								// rather than dereferencing zpp.FromZone.
								if zpp == nil {
									continue
								}
								if zpp.FromZone == fromZone && zpp.ToZone == toZone {
									names := make([]string, 0, len(zpp.Policies))
									for _, p := range zpp.Policies {
										// #3476: skip a nil rule rather than
										// dereferencing p.Name.
										if p == nil {
											continue
										}
										names = append(names, p.Name)
									}
									return names
								}
							}
							return nil
						}},
					}},
				}},
			}},
			"screen": {Desc: "Show screen service information", Children: map[string]*Node{
				"ids-option": {Desc: "Show configured screen profile", DynamicFn: func(cfg *config.Config) []string {
					if cfg == nil {
						return nil
					}
					names := make([]string, 0, len(cfg.Security.Screen))
					for name := range cfg.Security.Screen {
						names = append(names, name)
					}
					return names
				}, Children: map[string]*Node{
					"detail": {Desc: "Show detailed screen profile with thresholds"},
				}},
				"statistics": {Desc: "Show screen statistics", Children: map[string]*Node{
					"zone": {Desc: "Show per-zone screen counters", DynamicFn: func(cfg *config.Config) []string {
						if cfg == nil {
							return nil
						}
						names := make([]string, 0, len(cfg.Security.Zones))
						for name := range cfg.Security.Zones {
							names = append(names, name)
						}
						return names
					}},
				}},
			}},
			"alarms": {Desc: "Show active security alarm information", Children: map[string]*Node{
				"detail": {Desc: "Show detailed security alarm information"},
			}},
			"alg": {Desc: "Show ALG status", Children: map[string]*Node{
				"status": {Desc: "Show ALG status details"},
			}},
			"dynamic-address": {Desc: "Show dynamic address feeds"},
			"flow": {Desc: "Show security flow information", Children: map[string]*Node{
				// #9505: parseSessionFilterMode loops over every argument, so these are
				// options in any order, and each valued one takes exactly one value.
				"session": {Desc: "Show session table", Options: true, Children: map[string]*Node{
					"summary":            {Desc: "Show session count summary"},
					"brief":              {Desc: "Show sessions in compact table"},
					"application":        {Desc: "Filter sessions by application name", ValueType: ValueIdentifier},
					"interface":          {Desc: "Filter sessions by interface", ValueType: ValueIdentifier},
					"source-prefix":      {Desc: "Filter by source IP prefix", ValueType: ValueCIDR},
					"destination-prefix": {Desc: "Filter by destination IP prefix", ValueType: ValueCIDR},
					"source-port":        {Desc: "Filter by source port", ValueType: ValueInteger},
					"destination-port":   {Desc: "Filter by destination port", ValueType: ValueInteger},
					"protocol":           {Desc: "Filter by IP protocol", ValueType: ValueIdentifier},
					"zone": {Desc: "Filter by security zone", DynamicFn: func(cfg *config.Config) []string {
						if cfg == nil {
							return nil
						}
						names := make([]string, 0, len(cfg.Security.Zones))
						for name := range cfg.Security.Zones {
							names = append(names, name)
						}
						return names
					}},
					"nat-only":        {Desc: "Show only sessions with NAT translation"},
					"source-nat-pool": {Desc: "Filter sessions by source NAT pool", DynamicFn: sourceNATPoolNames},
					"sort-by": {Desc: "Sort sessions for top-talkers", Children: map[string]*Node{
						"bytes":   {Desc: "Sort by total bytes (descending)"},
						"packets": {Desc: "Sort by total packets (descending)"},
					}},
				}},
				"statistics":   {Desc: "Show security flow statistics"},
				"traceoptions": {Desc: "Show flow trace configuration"},
			}},
			"nat": {Desc: "Show Network Address Translation information", Children: map[string]*Node{
				"source": {Desc: "Show source NAT", Children: map[string]*Node{
					"summary": {Desc: "Show source NAT summary"},
					"pool":    {Desc: "Show source NAT pools"},
					"persistent-nat-table": {Desc: "Show persistent NAT bindings", Children: map[string]*Node{
						"detail": {Desc: "Show detailed persistent NAT bindings"},
					}},
					"rule": {Desc: "Show source NAT rules", Children: map[string]*Node{
						"detail": {Desc: "Show detailed source NAT rules"},
					}},
					// #9064: takes a rule-set NAME.
					"rule-set": {Desc: "Show source NAT rule sets", AcceptsArgs: true},
					"deterministic-nat": {Desc: "Resolve deterministic CGNAT/NAPT64 mappings (applied generation)", Children: map[string]*Node{
						"internal-host": {Desc: "Forward: map an internal subscriber to its translated IP + port block", Children: map[string]*Node{
							"<address>": {Desc: "Internal subscriber IP (IPv4 mode 1, or IPv6 mode 2 NAPT64)", Children: map[string]*Node{
								"pool": {Desc: "Restrict lookup to a source NAT pool", DynamicFn: sourceNATPoolNames},
							}},
						}},
						"nat-ip": {Desc: "Reverse: map a translated IP + port back to the internal subscriber", Children: map[string]*Node{
							"<address>": {Desc: "Translated external IPv4 address", Children: map[string]*Node{
								"nat-port": {Desc: "Translated port", Children: map[string]*Node{
									"<port>": {Desc: "Translated port number (1-65535)", Children: map[string]*Node{
										"pool": {Desc: "Restrict lookup to a source NAT pool", DynamicFn: sourceNATPoolNames},
									}},
								}},
							}},
						}},
					}},
				}},
				"destination": {Desc: "Show destination NAT", Children: map[string]*Node{
					"summary": {Desc: "Show destination NAT summary"},
					"pool":    {Desc: "Show destination NAT pools"},
					"rule": {Desc: "Show destination NAT rules", Children: map[string]*Node{
						"detail": {Desc: "Show detailed destination NAT rules"},
					}},
					// #9064: takes a rule-set NAME.
					"rule-set": {Desc: "Show destination NAT rule sets", AcceptsArgs: true},
				}},
				"static": {Desc: "Show static NAT", Children: map[string]*Node{
					"rule": {Desc: "Show static NAT rules", Children: map[string]*Node{
						"detail": {Desc: "Show detailed static NAT rules (source restriction, mapped-port, prefix-name, routing-instance)"},
					}},
				}},
				"nptv6": {Desc: "Show NPTv6 prefix translation rules"},
				"nat64": {Desc: "Show NAT64 rules"},
			}},
			"address-book": {Desc: "Show address book entries"},
			"applications": {Desc: "Show application definitions"},
			// #9505: logging.ParseEventFilterArgs loops over every argument and reads a
			// bare positive integer anywhere as the event count.
			"log": {Desc: "Show recent security events", Options: true, Children: map[string]*Node{
				"<count>": {Desc: "Number of events to show"},
				"zone": {Desc: "Filter by security zone", DynamicFn: func(cfg *config.Config) []string {
					if cfg == nil {
						return nil
					}
					names := make([]string, 0, len(cfg.Security.Zones))
					for name := range cfg.Security.Zones {
						names = append(names, name)
					}
					return names
				}},
				"protocol": {Desc: "Filter by IP protocol", ValueType: ValueIdentifier},
				"action":   {Desc: "Filter by action (permit, deny, reject)", ValueType: ValueIdentifier},
			}},
			"statistics": {Desc: "Show global statistics", Children: map[string]*Node{
				"detail": {Desc: "Show detailed statistics with screen and session breakdown"},
			}},
			"ike": {Desc: "Show Internet Key Exchange information", Children: map[string]*Node{
				"security-associations": {Desc: "Show IKE SAs", Children: map[string]*Node{
					"detail": {Desc: "Show detailed IKE SA information"},
				}},
			}},
			"ipsec": {Desc: "Show IP Security information", Children: map[string]*Node{
				"security-associations": {Desc: "Show IPsec SAs", Children: map[string]*Node{
					"detail": {Desc: "Show detailed IPsec SA information (bytes, packets, SPI, lifetime)"},
				}},
				"statistics": {Desc: "Show IPsec statistics"},
			}},
			"vrrp": {Desc: "Show VRRP high availability status"},
			"wireguard": {Desc: "Show WireGuard tunnel status", Children: map[string]*Node{
				"detail":     {Desc: "Show per-reason drop counters and handshake activity"},
				"public-key": {Desc: "Show local public key per tunnel (give this to the peer)"},
			}},
			"match-policies": {Desc: "Match 5-tuple against policies"},
		}},
		"services": {Desc: "Show services information", Children: map[string]*Node{
			"rpm": {Desc: "Show RPM probe results", Children: map[string]*Node{
				"probe-results": {Desc: "Show RPM probe results"},
			}},
			"ip-monitoring": {Desc: "Show IP monitoring policy status", Children: map[string]*Node{
				"status": {Desc: "Show IP monitoring policy status"},
			}},
			"application-identification": {Desc: "Show application-identification (AppID) status", Children: map[string]*Node{
				"status": {Desc: "Show AppID engine status and supported contract"},
			}},
			"dynamic-dns": {Desc: "Show Surface A (router/interface-address) dynamic-DNS status (#2691)", Children: map[string]*Node{
				"detail": {Desc: "Show per-scope published Surface A DDNS records"},
			}},
		}},
		"interfaces": {Desc: "Show interface information", DynamicFn: func(cfg *config.Config) []string {
			if cfg == nil || cfg.Interfaces.Interfaces == nil {
				return nil
			}
			names := make([]string, 0, len(cfg.Interfaces.Interfaces))
			for name := range cfg.Interfaces.Interfaces {
				names = append(names, name)
			}
			return names
		}, Children: map[string]*Node{
			"terse":      {Desc: "Display terse output"},
			"detail":     {Desc: "Display detailed output"},
			"extensive":  {Desc: "Display extensive output"},
			"statistics": {Desc: "Display statistics and detailed output"},
			"tunnel":     {Desc: "Show tunnel interfaces"},
			"queue": {Desc: "Show per-queue CoS statistics", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil || cfg.Interfaces.Interfaces == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Interfaces.Interfaces))
				for name := range cfg.Interfaces.Interfaces {
					names = append(names, name)
				}
				return names
			}},
		}},
		"protocols": {Desc: "Show protocol information", Children: map[string]*Node{
			"ospf": {Desc: "Show OSPF information", Children: map[string]*Node{
				"neighbor": {Desc: "Show OSPF neighbors", Children: map[string]*Node{
					"detail": {Desc: "Show detailed OSPF neighbor information"},
				}},
				"database":  {Desc: "Show OSPF database"},
				"interface": {Desc: "Show OSPF interface details"},
				"routes":    {Desc: "Show OSPF routes"},
			}},
			"bgp": {Desc: "Show BGP information", Children: map[string]*Node{
				"summary": {Desc: "Show BGP peer summary"},
				"routes":  {Desc: "Show BGP routes"},
				"neighbor": {Desc: "Show BGP neighbor details", Children: map[string]*Node{
					"received-routes":   {Desc: "Show received routes from neighbor"},
					"advertised-routes": {Desc: "Show advertised routes to neighbor"},
				}},
			}},
			"bfd": {Desc: "Show BFD status", Children: map[string]*Node{
				"peers": {Desc: "Show BFD peer status"},
			}},
			"rip": {Desc: "Show RIP information"},
			"isis": {Desc: "Show IS-IS information", Children: map[string]*Node{
				"adjacency": {Desc: "Show IS-IS adjacencies", Children: map[string]*Node{
					"detail": {Desc: "Show detailed IS-IS adjacency information"},
				}},
				"database": {Desc: "Show IS-IS link-state database"},
				"routes":   {Desc: "Show IS-IS routes"},
			}},
			"lldp": {Desc: "Show LLDP protocol status", Children: map[string]*Node{
				"neighbors": {Desc: "Show LLDP neighbors"},
			}},
		}},
		"bgp": {Desc: "Show BGP information (alias for show protocols bgp)", Children: map[string]*Node{
			"summary": {Desc: "Show BGP peer summary"},
			"routes":  {Desc: "Show BGP routes"},
			"neighbor": {Desc: "Show BGP neighbor details", Children: map[string]*Node{
				"received-routes":   {Desc: "Show received routes from neighbor"},
				"advertised-routes": {Desc: "Show advertised routes to neighbor"},
			}},
		}},
		"arp": {Desc: "Show system ARP table entries", Children: map[string]*Node{
			"no-resolve": {Desc: "Don't attempt to resolve addresses"},
		}},
		"ipv6": {Desc: "Show IPv6 information", Children: map[string]*Node{
			"neighbors":            {Desc: "Show IPv6 neighbor cache"},
			"router-advertisement": {Desc: "Show Router Advertisement status"},
		}},
		"schedulers": {Desc: "Show policy schedulers"},
		"dhcp-relay": {Desc: "Show DHCP relay status"},
		"dhcp-server": {Desc: "Show DHCP server leases", Children: map[string]*Node{
			"detail": {Desc: "Show detailed DHCP server information with pool utilization"},
			"dynamic-dns": {Desc: "Show DHCP dynamic-DNS status and counters", Children: map[string]*Node{
				"detail": {Desc: "Show owned DHCP dynamic-DNS records"},
			}},
		}},
		"snmp": {Desc: "Show SNMP statistics", Children: map[string]*Node{
			"v3": {Desc: "Show SNMPv3 USM user information"},
		}},
		"lldp": {Desc: "Show LLDP information", Children: map[string]*Node{
			"neighbors": {Desc: "Show LLDP neighbor table"},
		}},
		"system": {Desc: "Show system information", Children: map[string]*Node{
			"alarms":        {Desc: "Show system alarm status"},
			"boot-messages": {Desc: "Show boot time messages"},
			"commit": {Desc: "Show pending and historical commit information", Children: map[string]*Node{
				"history": {Desc: "Show recent commit log"},
			}},
			"connections": {Desc: "Show system connection activity"},
			"core-dumps":  {Desc: "Show system core dumps"},
			// #9064: `show system rollback 1` and `show system rollback compare 1`
			// both take a rollback INDEX. The parent needs AcceptsArgs for the
			// bare form and the child for the compare form -- declaring only one
			// leaves the other CanonicalUnknown.
			"rollback": {Desc: "Show rolled back configuration", AcceptsArgs: true, Children: map[string]*Node{
				"compare": {Desc: "Compare rollback with active config", AcceptsArgs: true},
			}},
			"backup-router":    {Desc: "Show backup router configuration"},
			"bootstrap-import": {Desc: "Show the day-0 / bootstrap configuration import outcome"},
			"buffers": {Desc: "Show buffer utilization", Children: map[string]*Node{
				"detail": {Desc: "Show detailed per-map statistics"},
			}},
			"internet-options": {Desc: "Show internet options"},
			"kernel-upgrade":   {Desc: "Show kernel-upgrade channel state (armed candidate, promotion marker, last roll)"},
			"license":          {Desc: "Show system license"},
			"login":            {Desc: "Show login configuration"},
			"memory":           {Desc: "Show system memory usage"},
			"ntp":              {Desc: "Show NTP status"},
			"processes": {Desc: "Show system process table", Children: map[string]*Node{
				"summary": {Desc: "Show summary of system processes (top-like view)"},
			}},
			"root-authentication": {Desc: "Show root authentication"},
			"configuration": {Desc: "Show configuration info", Children: map[string]*Node{
				"rescue": {Desc: "Show rescue configuration"},
			}},
			"services": {Desc: "Show configured system services"},
			"storage":  {Desc: "Show local filesystem usage"},
			"syslog":   {Desc: "Show system syslog configuration"},
			"uptime":   {Desc: "Show time since last reboot"},
			"users":    {Desc: "Show configured login users"},
		}},
		"task":            {Desc: "Show daemon task/runtime information"},
		"route-map":       {Desc: "Show route-map information"},
		"routing-options": {Desc: "Show routing options"},
		"routing-instances": {Desc: "Show routing instances", Children: map[string]*Node{
			"detail": {Desc: "Show detailed routing instance information"},
		}},
		"policy-options": {Desc: "Show policy options"},
		"event-options":  {Desc: "Show event policies"},
		"forwarding-options": {Desc: "Show forwarding options", Children: map[string]*Node{
			"port-mirroring": {Desc: "Show port mirroring instances"},
		}},
		"vlans":   {Desc: "Show VLAN configuration"},
		"version": {Desc: "Show software process revision levels"},
		"monitor": {Desc: "Show monitor information", Children: map[string]*Node{
			"security": {Desc: "Show security monitor information", Children: map[string]*Node{
				"flow": {Desc: "Show security flow monitor status"},
			}},
		}},
	}},
	"monitor": {Desc: "Show real-time debugging information", Children: map[string]*Node{
		// #9505: parseMonitorTrafficArgs loops over every argument. `matching`
		// takes a multi-word expression that the parser ends at the next option
		// keyword, which is exactly where the Options walk resumes.
		"traffic": {Desc: "Capture traffic on interface", Options: true, Children: map[string]*Node{
			"interface": {Desc: "Interface name to capture on", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil || cfg.Interfaces.Interfaces == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Interfaces.Interfaces))
				for name := range cfg.Interfaces.Interfaces {
					names = append(names, name)
				}
				return names
			}},
			"matching": {Desc: "Filter expression (tcpdump syntax)", AcceptsArgs: true},
			"count":    {Desc: "Number of packets to capture", ValueType: ValueInteger},
		}},
		"interface": {Desc: "Show interface traffic statistics", DynamicFn: func(cfg *config.Config) []string {
			if cfg == nil || cfg.Interfaces.Interfaces == nil {
				return nil
			}
			names := make([]string, 0, len(cfg.Interfaces.Interfaces))
			for name := range cfg.Interfaces.Interfaces {
				names = append(names, name)
			}
			return names
		}, Children: map[string]*Node{
			"traffic": {Desc: "Show traffic summary for all interfaces"},
		}},
		"security": {Desc: "Monitor security events", Children: map[string]*Node{
			"flow": {Desc: "Monitor security flow", Children: map[string]*Node{
				// #9505: handleMonitorSecurityFlowFile loops over size/files/match.
				"file": {Desc: "Configure flow trace file", Options: true, Children: map[string]*Node{
					"<filename>": {Desc: "Name of trace file"},
					"files":      {Desc: "Maximum number of trace files (2..1000)", ValueType: ValueInteger},
					"size":       {Desc: "Maximum trace file size (10240..1073741824)", ValueType: ValueInteger},
					"match":      {Desc: "Regular expression for lines to log", ValueType: ValueIdentifier},
				}},
				// #9505: handleMonitorSecurityFlowFilter loops over the options after
				// the filter name.
				"filter": {Desc: "Configure flow trace filter", Options: true, Children: map[string]*Node{
					"<filter-name>":      {Desc: "Name of filter"},
					"source-prefix":      {Desc: "Source IP prefix to match", ValueType: ValueCIDR},
					"destination-prefix": {Desc: "Destination IP prefix to match", ValueType: ValueCIDR},
					"source-port":        {Desc: "Source port to match", ValueType: ValueInteger},
					"destination-port":   {Desc: "Destination port to match", ValueType: ValueInteger},
					"protocol":           {Desc: "Protocol to match (tcp/udp/icmp/0..255)", ValueType: ValueIdentifier},
					"interface": {Desc: "Interface to match", DynamicFn: func(cfg *config.Config) []string {
						if cfg == nil || cfg.Interfaces.Interfaces == nil {
							return nil
						}
						names := make([]string, 0, len(cfg.Interfaces.Interfaces))
						for name := range cfg.Interfaces.Interfaces {
							names = append(names, name)
						}
						return names
					}},
				}},
				"start": {Desc: "Start flow tracing"},
				"stop":  {Desc: "Stop flow tracing"},
			}},
			// #9505: handleMonitorSecurityPacketDrop loops over every argument.
			"packet-drop": {Desc: "Monitor security packet drops", Options: true, Children: map[string]*Node{
				"source-prefix":      {Desc: "Source IP prefix to match", ValueType: ValueCIDR},
				"destination-prefix": {Desc: "Destination IP prefix to match", ValueType: ValueCIDR},
				"source-port":        {Desc: "Source port to match", ValueType: ValueInteger},
				"destination-port":   {Desc: "Destination port to match", ValueType: ValueInteger},
				"protocol":           {Desc: "Protocol to match (tcp/udp/icmp/0..255)", ValueType: ValueIdentifier},
				"from-zone": {Desc: "Ingress zone to match", DynamicFn: func(cfg *config.Config) []string {
					if cfg == nil {
						return nil
					}
					names := make([]string, 0, len(cfg.Security.Zones))
					for _, z := range cfg.Security.Zones {
						if z == nil { // #3493: tolerant/HA-sync path may carry a nil zone value
							continue
						}
						names = append(names, z.Name)
					}
					return names
				}},
				"interface": {Desc: "Ingress interface to match", DynamicFn: func(cfg *config.Config) []string {
					if cfg == nil || cfg.Interfaces.Interfaces == nil {
						return nil
					}
					names := make([]string, 0, len(cfg.Interfaces.Interfaces))
					for name := range cfg.Interfaces.Interfaces {
						names = append(names, name)
					}
					return names
				}},
				"count": {Desc: "Number of packet drops to display (1..8192)", ValueType: ValueInteger},
				"node":  {Desc: "Cluster node (0, 1, all, local, primary)", ValueType: ValueIdentifier},
			}},
		}},
	}},
	"clear": {Desc: "Clear statistics and protocol information", Children: map[string]*Node{
		"arp": {Desc: "Clear ARP table"},
		"system": {Desc: "Clear system information", Children: map[string]*Node{
			"config-lock": {Desc: "Force clear stale configuration lock"},
		}},
		"interfaces": {Desc: "Clear interface information", Children: map[string]*Node{
			"statistics": {Desc: "Clear interface statistics counters"},
		}},
		"ipv6": {Desc: "Clear IPv6 information", Children: map[string]*Node{
			"neighbors": {Desc: "Clear IPv6 neighbor cache"},
		}},
		"security": {Desc: "Clear security statistics and tables", Children: map[string]*Node{
			"flow": {Desc: "Clear flow information", Children: map[string]*Node{
				// #9505: the same parseSessionFilterMode loop as `show security flow
				// session`.
				"session": {Desc: "Clear session table entries", Options: true, Children: map[string]*Node{
					"source-prefix":      {Desc: "Filter sessions by source IP prefix", ValueType: ValueCIDR},
					"destination-prefix": {Desc: "Filter sessions by destination IP prefix", ValueType: ValueCIDR},
					"source-port":        {Desc: "Filter sessions by source port", ValueType: ValueInteger},
					"destination-port":   {Desc: "Filter sessions by destination port", ValueType: ValueInteger},
					"protocol":           {Desc: "Filter sessions by IP protocol", ValueType: ValueIdentifier},
					"zone": {Desc: "Filter sessions by security zone", DynamicFn: func(cfg *config.Config) []string {
						if cfg == nil {
							return nil
						}
						names := make([]string, 0, len(cfg.Security.Zones))
						for name := range cfg.Security.Zones {
							names = append(names, name)
						}
						return names
					}},
					"interface": {Desc: "Filter sessions by interface", DynamicFn: func(cfg *config.Config) []string {
						if cfg == nil || cfg.Interfaces.Interfaces == nil {
							return nil
						}
						names := make([]string, 0, len(cfg.Interfaces.Interfaces))
						for name := range cfg.Interfaces.Interfaces {
							names = append(names, name)
						}
						return names
					}},
					"application": {Desc: "Filter sessions by application name", ValueType: ValueIdentifier},
					"nat-only":    {Desc: "Clear only sessions with NAT translation"},
					"source-nat-pool": {Desc: "Clear sessions translated by a source NAT pool", DynamicFn: func(cfg *config.Config) []string {
						if cfg == nil || cfg.Security.NAT.SourcePools == nil {
							return nil
						}
						names := make([]string, 0, len(cfg.Security.NAT.SourcePools))
						for name := range cfg.Security.NAT.SourcePools {
							names = append(names, name)
						}
						return names
					}},
				}},
			}},
			"counters": {Desc: "Clear all security counters"},
			"policies": {Desc: "Clear policy information", Children: map[string]*Node{
				"hit-count": {Desc: "Clear policy hit counters"},
			}},
			"nat": {Desc: "Clear NAT information", Children: map[string]*Node{
				"source": {Desc: "Clear source NAT", Children: map[string]*Node{
					"persistent-nat-table": {Desc: "Clear persistent NAT bindings"},
				}},
				"statistics": {Desc: "Clear NAT translation statistics"},
			}},
		}},
		"firewall": {Desc: "Clear firewall counters", Children: map[string]*Node{
			"all": {Desc: "Clear all firewall filter counters"},
		}},
		"dhcp": {Desc: "Clear DHCP information", Children: map[string]*Node{
			// #9064: takes `interface <name>`.
			"client-identifier": {Desc: "Clear DHCPv6 DUID(s)", AcceptsArgs: true},
		}},
	}},
	"request": {Desc: "Make system-level requests", Children: map[string]*Node{
		"chassis": {Desc: "Perform chassis-specific operations", Children: map[string]*Node{
			"cluster": {Desc: "Cluster operations", Children: map[string]*Node{
				"failover": {Desc: "Trigger cluster failover", Children: map[string]*Node{
					"data": {Desc: "Fail over all data redundancy groups together", Children: map[string]*Node{
						"node": {Desc: "Target node ID (local or peer)", DynamicFn: func(cfg *config.Config) []string {
							return []string{"0", "1"}
						}},
					}},
					"redundancy-group": {Desc: "Failover a specific redundancy group", DynamicFn: func(cfg *config.Config) []string {
						return redundancyGroupIDs(cfg) // #4866: nil-skip tolerated RG entries
					}, Children: map[string]*Node{
						"node": {Desc: "Target node ID (local or peer)", DynamicFn: func(cfg *config.Config) []string {
							if cfg == nil || cfg.Chassis.Cluster == nil {
								return []string{"0", "1"}
							}
							// Cluster is currently 2-node only.
							return []string{"0", "1"}
						}},
					}},
					"reset": {Desc: "Reset manual failover", Children: map[string]*Node{
						"redundancy-group": {Desc: "Reset failover for a redundancy group", DynamicFn: func(cfg *config.Config) []string {
							return redundancyGroupIDs(cfg) // #4866: nil-skip tolerated RG entries
						}},
					}},
				}},
				"data-plane": {Desc: "Userspace dataplane operations", Children: map[string]*Node{
					"userspace": {Desc: "Userspace dataplane helper operations", Children: map[string]*Node{
						"forwarding": {Desc: "Control live userspace forwarding", Children: map[string]*Node{
							"arm":    {Desc: "Arm live userspace forwarding"},
							"disarm": {Desc: "Disarm live userspace forwarding"},
						}},
						"queue": {Desc: "Control a userspace queue", DynamicFn: func(cfg *config.Config) []string {
							out := make([]string, 0, 16)
							for i := 0; i < 16; i++ {
								out = append(out, fmt.Sprintf("%d", i))
							}
							return out
						}, Children: map[string]*Node{
							"register":   {Desc: "Register a queue without arming redirect"},
							"unregister": {Desc: "Unregister a queue and release redirect ownership"},
							"arm":        {Desc: "Register and arm a queue for redirect"},
							"disarm":     {Desc: "Disarm a queue while keeping it registered"},
						}},
						"binding": {Desc: "Control a userspace binding slot", Children: map[string]*Node{
							"slot": {Desc: "Binding slot", DynamicFn: func(cfg *config.Config) []string {
								out := make([]string, 0, 16)
								for i := 0; i < 16; i++ {
									out = append(out, fmt.Sprintf("%d", i))
								}
								return out
							}, Children: map[string]*Node{
								"register":   {Desc: "Register a binding without arming redirect"},
								"unregister": {Desc: "Unregister a binding and release redirect ownership"},
								"arm":        {Desc: "Register and arm a binding for redirect"},
								"disarm":     {Desc: "Disarm a binding while keeping it registered"},
							}},
						}},
						"inject-packet": {Desc: "Inject a synthetic userspace dataplane packet", Children: map[string]*Node{
							"slot": {Desc: "Binding slot", DynamicFn: func(cfg *config.Config) []string {
								out := make([]string, 0, 16)
								for i := 0; i < 16; i++ {
									out = append(out, fmt.Sprintf("%d", i))
								}
								return out
							}, Children: map[string]*Node{
								"valid": {Desc: "Inject a valid packet using the current snapshot generations", Children: map[string]*Node{
									"packet-length":    {Desc: "Optional packet length in bytes (max 4096; over-max is rejected)"},
									"destination-ip":   {Desc: "Optional destination IP used for forwarding resolution"},
									"emit-on-wire":     {Desc: "Emit a resolved synthetic packet on the egress interface"},
									"source-ip":        {Desc: "Source IP required when emitting on wire"},
									"source-port":      {Desc: "Source tuple port or ICMP identifier"},
									"destination-port": {Desc: "Destination tuple port"},
									"protocol":         {Desc: "Tuple protocol for emitted packet"},
								}},
								"fib-mismatch": {Desc: "Inject a packet with a mismatched FIB generation", Children: map[string]*Node{
									"packet-length":    {Desc: "Optional packet length in bytes (max 4096; over-max is rejected)"},
									"destination-ip":   {Desc: "Optional destination IP used for forwarding resolution"},
									"emit-on-wire":     {Desc: "Emit a resolved synthetic packet on the egress interface"},
									"source-ip":        {Desc: "Source IP required when emitting on wire"},
									"source-port":      {Desc: "Source tuple port or ICMP identifier"},
									"destination-port": {Desc: "Destination tuple port"},
									"protocol":         {Desc: "Tuple protocol for emitted packet"},
								}},
								"metadata-parse-error": {Desc: "Inject a malformed metadata packet", Children: map[string]*Node{
									"destination-ip": {Desc: "Optional destination IP used for forwarding resolution"},
								}},
							}},
						}},
					}},
				}},
			}},
		}},
		"dhcp": {Desc: "Perform DHCP operations", Children: map[string]*Node{
			"renew": {Desc: "Renew DHCP lease on an interface", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil || cfg.Interfaces.Interfaces == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Interfaces.Interfaces))
				for name := range cfg.Interfaces.Interfaces {
					names = append(names, name)
				}
				return names
			}},
		}},
		"protocols": {Desc: "Protocol operations", Children: map[string]*Node{
			"ospf": {Desc: "OSPF operations", Children: map[string]*Node{
				"clear": {Desc: "Clear OSPF process"},
			}},
			"bgp": {Desc: "BGP operations", Children: map[string]*Node{
				"clear": {Desc: "Clear BGP sessions"},
			}},
		}},
		"security": {Desc: "Request security operations", Children: map[string]*Node{
			"ipsec": {Desc: "IPsec operations", Children: map[string]*Node{
				"sa": {Desc: "IPsec SA operations", Children: map[string]*Node{
					"clear": {Desc: "Clear all IPsec SAs"},
				}},
			}},
			"policies": {Desc: "Security policy operations", Children: map[string]*Node{
				"check": {Desc: "Check the configured policy set for shadowed / redundant rules"},
			}},
			"wireguard": {Desc: "WireGuard operations", Children: map[string]*Node{
				"generate-private-key": {Desc: "Generate a fresh WireGuard private key and its public key"},
			}},
		}},
		"system": {Desc: "Perform system-level operations", Children: map[string]*Node{
			"reboot":    {Desc: "Reboot the system"},
			"halt":      {Desc: "Halt the system"},
			"power-off": {Desc: "Power off the system"},
			"zeroize":   {Desc: "Factory reset (erase all config)"},
			"configuration": {Desc: "Manage configuration", Children: map[string]*Node{
				"rescue": {Desc: "Rescue configuration", Children: map[string]*Node{
					"save":   {Desc: "Save rescue configuration"},
					"delete": {Desc: "Delete rescue configuration"},
				}},
			}},
			"software": {Desc: "Software management", Children: map[string]*Node{
				"in-service-upgrade": {Desc: "Prepare node for in-service software upgrade (ISSU)"},
			}},
			"dynamic-dns": {Desc: "Force a dynamic-DNS update out-of-band of the poll cycle (#3276)", Children: map[string]*Node{
				"update": {Desc: "Force an immediate publish of all DDNS records owned by this node"},
				"check":  {Desc: "Re-check the WAN/interface address now and publish only if it changed"},
			}},
		}},
	}},
	"test": {Desc: "Perform diagnostic testing", Children: map[string]*Node{
		"policy": {Desc: "Test security policy lookup", Children: map[string]*Node{
			"from-zone": {Desc: "Source zone", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Security.Zones))
				for name := range cfg.Security.Zones {
					names = append(names, name)
				}
				return names
			}, Children: map[string]*Node{
				"to-zone": {Desc: "Destination zone", DynamicFn: func(cfg *config.Config) []string {
					if cfg == nil {
						return nil
					}
					names := make([]string, 0, len(cfg.Security.Zones))
					for name := range cfg.Security.Zones {
						names = append(names, name)
					}
					return names
				}, Children: map[string]*Node{
					"source-ip": {Desc: "Source IP address", Children: map[string]*Node{
						"destination-ip": {Desc: "Destination IP address", Children: map[string]*Node{
							"source-port": {Desc: "Source port number", Children: map[string]*Node{
								"destination-port": {Desc: "Destination port number", Children: map[string]*Node{
									"protocol": {Desc: "IP protocol (tcp, udp)"},
								}},
							}},
							"destination-port": {Desc: "Destination port number", Children: map[string]*Node{
								"protocol": {Desc: "IP protocol (tcp, udp)"},
							}},
						}},
					}},
				}},
			}},
		}},
		// #9505: testRouting loops over destination/instance in any order.
		"routing": {Desc: "Test route lookup", Options: true, Children: map[string]*Node{
			"destination": {Desc: "Destination IP or prefix to look up", ValueType: ValueCIDR},
			"instance": {Desc: "Routing instance for route lookup", DynamicFn: func(cfg *config.Config) []string {
				return routingInstanceNames(cfg) // #4866: nil-skip tolerated entries
			}},
		}},
		"security-zone": {Desc: "Show zone for interface", Children: map[string]*Node{
			"interface": {Desc: "Interface name", DynamicFn: func(cfg *config.Config) []string {
				if cfg == nil || cfg.Interfaces.Interfaces == nil {
					return nil
				}
				names := make([]string, 0, len(cfg.Interfaces.Interfaces))
				for name := range cfg.Interfaces.Interfaces {
					names = append(names, name)
				}
				return names
			}},
		}},
	}},
	// #9505: handlePing loops over the options after the target.
	"ping": {Desc: "Ping remote host", Options: true, Children: map[string]*Node{
		"<host>": {Desc: "Hostname or IP address of remote host"},
		// #9064: each takes a real dispatcher-read VALUE (cli_request_ping.go
		// reads count/source/size), so a bare leaf made the whole command
		// CanonicalUnknown and a restricted login class was refused a command
		// the CLI's own `usage:` string documents.
		//
		// #9505: exactly ONE value each. AcceptsArgs absorbed every later word,
		// and the ping loop ignores a word it does not recognise, so
		// `ping <host> count 5 junk` was authorized as a different string from
		// the command that ran.
		"count":  {Desc: "Number of ping requests to send", ValueType: ValueInteger},
		"source": {Desc: "Source address to use", ValueType: ValueIPAddress},
		"size":   {Desc: "Request data size in bytes", ValueType: ValueInteger},
		"routing-instance": {Desc: "Routing instance for route lookup", DynamicFn: func(cfg *config.Config) []string {
			return routingInstanceNames(cfg) // #4866: nil-skip tolerated entries
		}},
	}},
	// #9505: the same option loop as ping.
	"traceroute": {Desc: "Trace route to remote host", Options: true, Children: map[string]*Node{
		"<host>": {Desc: "Hostname or IP address of remote host"},
		// #9064: takes a value, like ping's.
		"source": {Desc: "Source address to use", ValueType: ValueIPAddress},
		"routing-instance": {Desc: "Routing instance for route lookup", DynamicFn: func(cfg *config.Config) []string {
			return routingInstanceNames(cfg) // #4866: nil-skip tolerated entries
		}},
	}},
	"quit": {Desc: "Exit CLI"},
	"exit": {Desc: "Exit CLI"},
}

// ConfigSetDataplaneKnobs is the `?` help surface for `set system
// dataplane <knob>`. Codex M3 / Go F1: the schema in pkg/config/schema.go
// already backs tab completion for these knobs, but `?` help and the
// explicit per-knob description live in cmdtree. Keeping this map tiny
// and focused lets us grow it without restating the full config
// schema here — tab-completion for siblings still falls through to
// the schema walker.
var ConfigSetDataplaneKnobs = map[string]*Node{
	"rss-indirection":     {Desc: "mlx5 RSS indirection reshaping (enable|disable)"},
	"claim-host-tunables": {Desc: "Allow xpfd to write host-scope tunables (true|false; default false)"},
	"cpu-governor":        {Desc: "Host cpufreq governor (performance|schedutil|default)"},
	"netdev-budget":       {Desc: "net.core.netdev_budget value"},
	"coalescence": {Desc: "NIC interrupt-coalescence tuning (mlx5)", Children: map[string]*Node{
		"adaptive": {Desc: "Adaptive coalescing (enable|disable)"},
		"rx-usecs": {Desc: "RX coalescing microseconds"},
		"tx-usecs": {Desc: "TX coalescing microseconds"},
	}},
}

// #1319 PR 1 retired the cmdtree config-mode typed-leaf overlay
// (formerly ConfigClassOfServiceSchedulers + cmdtree.SchemaValidate).
// Config-mode typed leaves now live on pkg/config's setSchema, which is
// the tree the live `set`/`delete`/`show`/`edit` completer AND the
// commit-check SchemaValidate gate both read. cmdtree remains the SSOT
// for the operational ("run") tree; its Node still carries the typed-leaf
// fields (ValueType/ValueDesc/ValueExamples/Validator) for operational
// leaves and the retained `set system dataplane` description overlay. See
// pkg/cmdtree/README.md and docs/config-schema.md for the two-SSOT split.

// ConfigTopLevel defines tab completion for config mode top-level commands.
var ConfigTopLevel = map[string]*Node{
	"activate":   {Desc: "Remove the inactive tag from a statement"},
	"annotate":   {Desc: "Annotate the configuration statement"},
	"copy":       {Desc: "Copy a configuration statement"},
	"deactivate": {Desc: "Add the inactive tag to a statement"},
	"insert":     {Desc: "Insert a new ordered configuration statement"},
	"rename":     {Desc: "Rename a configuration statement"},
	"set": {Desc: "Set a configuration parameter", Children: map[string]*Node{
		"system": {Desc: "System configuration", Children: map[string]*Node{
			// Codex M3: surface the #785/#801 dataplane knobs so `?`
			// help and tab completion show descriptions for
			// rss-indirection / claim-host-tunables / cpu-governor /
			// netdev-budget / coalescence without the operator having
			// to guess at the spelling from the issue body. The schema
			// walker handles completion for every other `set system`
			// path; this hierarchy only supplies extra descriptions.
			"dataplane": {Desc: "Userspace dataplane tunables", Children: ConfigSetDataplaneKnobs},
		}},
	}},
	"delete": {Desc: "Delete a configuration statement"},
	"show":   {Desc: "Show configuration"},
	"commit": {Desc: "Commit current set of changes", Children: map[string]*Node{
		"check":     {Desc: "Check correctness of syntax; do not apply changes"},
		"comment":   {Desc: "Add comment to commit"},
		"confirmed": {Desc: "Automatically rollback if not confirmed"},
	}},
	"load": {Desc: "Load configuration from ASCII file", Children: map[string]*Node{
		"override": {Desc: "Override existing configuration"},
		"merge":    {Desc: "Merge contents with existing configuration"},
		"set":      {Desc: "Execute set commands from terminal"},
	}},
	"edit":     {Desc: "Edit a sub-level of configuration"},
	"top":      {Desc: "Exit to top level of configuration"},
	"up":       {Desc: "Exit one level of configuration"},
	"rollback": {Desc: "Roll back to a previous committed configuration"},
	"run":      {Desc: "Run an operational-mode command"},
	"exit":     {Desc: "Exit configuration mode"},
	"quit":     {Desc: "Exit configuration mode"},
}

// --- Helper functions ---

// KeysFromTree returns a sorted list of keys from a Node map.
func KeysFromTree(tree map[string]*Node) []string {
	keys := make([]string, 0, len(tree))
	for k := range tree {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// HelpCandidates returns Candidates from a tree's children for help display.
func HelpCandidates(tree map[string]*Node) []Candidate {
	candidates := make([]Candidate, 0, len(tree))
	for name, node := range tree {
		candidates = append(candidates, Candidate{Name: name, Desc: node.Desc})
	}
	return candidates
}

// isPlaceholder returns true for angle-bracket nodes like "<host>" that act as
// positional argument wildcards in the tree.
func isPlaceholder(name string) bool {
	return len(name) > 2 && name[0] == '<' && name[len(name)-1] == '>'
}

// findPlaceholder returns the placeholder node in a tree level, if any.
func findPlaceholder(tree map[string]*Node) *Node {
	for name, node := range tree {
		if isPlaceholder(name) {
			return node
		}
	}
	return nil
}

// ResolveUniquePrefix returns the exact item, or a uniquely matching prefix.
func ResolveUniquePrefix(items []string, input string) (string, bool) {
	for _, item := range items {
		if item == input {
			return item, true
		}
	}
	matches := FilterPrefix(items, input)
	if len(matches) != 1 {
		return "", false
	}
	return matches[0], true
}

func resolveTreeWord(tree map[string]*Node, word string) (string, *Node, []string, bool) {
	if node, ok := tree[word]; ok {
		return word, node, nil, true
	}
	matches := FilterPrefix(KeysOf(tree), word)
	if len(matches) == 1 {
		name := matches[0]
		return name, tree[name], matches, true
	}
	return "", nil, matches, false
}

// CompleteFromTree walks the tree to find completion candidates for the given words and partial.
func CompleteFromTree(tree map[string]*Node, words []string, partial string, cfg *config.Config) []string {
	current := tree
	var currentNode *Node
	// parentTyped tracks whether the most recent matched node is a typed
	// leaf whose value slot has not yet been consumed. If so, the next
	// unmatched word is the value and we stay at the same children
	// level after consuming it (#1319: same shape as <placeholder> but
	// derived from ValueType instead of an explicit "<name>" node).
	parentTyped := false
	dynamicConsumed := false
	// #5196 (A3-b1-F4): resolveTreeWord accepts unique keyword prefixes
	// for traversal, but ContextDynamicFn providers scan the consumed
	// words for exact keywords (e.g. the policy provider looks for
	// "from-zone"/"to-zone"). Track the CANONICAL keyword for each
	// resolved word so an accepted abbreviation ("from-z"/"to-z") still
	// carries the state those providers key off. Value slots (dynamic /
	// typed / placeholder — the !ok branches) keep the raw word, since
	// that is the operator-supplied value, not a keyword.
	canonWords := append([]string(nil), words...)
	for wi, w := range words {
		dynamicConsumed = false
		name, node, matches, ok := resolveTreeWord(current, w)
		if !ok {
			if parentTyped {
				// Typed-leaf value slot consumed this word; stay at same level.
				parentTyped = false
				dynamicConsumed = true
				continue
			}
			if currentNode != nil && currentNode.HasDynamic() {
				dynamicConsumed = true
				continue
			}
			// Check for placeholder node that consumes any value
			if ph := findPlaceholder(current); ph != nil {
				// Placeholder consumed this word. If the placeholder has
				// children, descend so follow-on keywords can complete
				// (e.g. "show route <dest> exact"). Otherwise stay at this
				// level so sibling options remain available (e.g. "ping
				// <host> count").
				if ph.Children != nil {
					currentNode = ph
					current = ph.Children
				}
				dynamicConsumed = true
				continue
			}
			if wi == len(words)-1 && len(matches) > 0 {
				return matches
			}
			return nil
		}
		// Resolved (possibly via unique prefix): record the canonical
		// keyword so downstream ContextDynamicFn providers see it (#5196).
		canonWords[wi] = name
		currentNode = node
		parentTyped = node.IsTypedLeaf()
		if node.Children == nil {
			if node.HasDynamic() && wi < len(words)-1 {
				dynamicConsumed = true
				continue
			}
			if node.HasDynamic() {
				// #5196 (A3-b1-F3): invoke the provider even when cfg==nil.
				// nil-safety is the provider contract (all DynamicFn /
				// ContextDynamicFn either guard `cfg == nil` or ignore cfg),
				// and config-independent providers (e.g. `show route table`
				// → inet.0/inet6.0, `show route protocol`) intentionally
				// supply defaults for a nil config (fresh boot /
				// compile-failure recovery). The old `&& cfg != nil` caller
				// gate suppressed those defaults.
				return FilterPrefix(node.DynamicValues(cfg, canonWords), partial)
			}
			return nil
		}
		current = node.Children
	}
	candidates := KeysOf(current)
	if parentTyped && currentNode != nil {
		// At the value slot of a typed leaf: surface examples for
		// `?` completion.
		candidates = append(candidates, currentNode.ValueExamples...)
		if ph := currentNode.ValueType.Placeholder(); ph != "" {
			candidates = append(candidates, ph)
		}
	}
	if !dynamicConsumed && currentNode != nil && currentNode.HasDynamic() {
		// #5196 (A3-b1-F3): nil-config-aware providers must still run.
		// #5196 (A3-b1-F4): pass canonical keywords, not raw abbreviations.
		candidates = append(candidates, currentNode.DynamicValues(cfg, canonWords)...)
	}
	return FilterPrefix(candidates, partial)
}

// CompleteFromTreeWithDesc walks the tree returning name+description pairs.
func CompleteFromTreeWithDesc(tree map[string]*Node, words []string, partial string, cfg *config.Config) []Candidate {
	current := tree
	var currentNode *Node
	parentTyped := false
	dynamicConsumed := false
	// #5196 (A3-b1-F4): canonicalize accepted keyword prefixes so
	// ContextDynamicFn providers see exact keywords. Mirrors CompleteFromTree.
	canonWords := append([]string(nil), words...)
	for wi, w := range words {
		dynamicConsumed = false
		canonName, node, matches, ok := resolveTreeWord(current, w)
		if !ok {
			if parentTyped {
				parentTyped = false
				dynamicConsumed = true
				continue
			}
			if currentNode != nil && currentNode.HasDynamic() {
				dynamicConsumed = true
				continue
			}
			// Check for placeholder node that consumes any value
			if ph := findPlaceholder(current); ph != nil {
				if ph.Children != nil {
					currentNode = ph
					current = ph.Children
				}
				dynamicConsumed = true
				continue
			}
			if wi == len(words)-1 && len(matches) > 0 {
				var candidates []Candidate
				for _, name := range matches {
					candidates = append(candidates, Candidate{Name: name, Desc: current[name].Desc})
				}
				return candidates
			}
			return nil
		}
		// Record the canonical keyword for the resolved word (#5196).
		canonWords[wi] = canonName
		currentNode = node
		parentTyped = node.IsTypedLeaf()
		if node.Children == nil {
			if node.HasDynamic() && wi < len(words)-1 {
				dynamicConsumed = true
				continue
			}
			if node.HasDynamic() {
				// #5196 (A3-b1-F3): run the provider on nil cfg too.
				// #5196 (A3-b1-F4): pass canonical keywords.
				var candidates []Candidate
				for _, name := range node.DynamicValues(cfg, canonWords) {
					if strings.HasPrefix(name, partial) {
						candidates = append(candidates, Candidate{Name: name, Desc: "(configured)"})
					}
				}
				return candidates
			}
			// Pure typed leaf with no children: surface placeholder + examples.
			if parentTyped {
				return typedLeafCandidates(node, partial)
			}
			return nil
		}
		current = node.Children
	}

	var candidates []Candidate
	for name, node := range current {
		if strings.HasPrefix(name, partial) {
			candidates = append(candidates, Candidate{Name: name, Desc: node.Desc})
		}
	}
	if parentTyped && currentNode != nil {
		candidates = append(candidates, typedLeafCandidates(currentNode, partial)...)
	}
	if !dynamicConsumed && currentNode != nil && currentNode.HasDynamic() {
		// #5196 (A3-b1-F3): nil-config-aware providers must still run.
		// #5196 (A3-b1-F4): pass canonical keywords, not raw abbreviations.
		for _, name := range currentNode.DynamicValues(cfg, canonWords) {
			if strings.HasPrefix(name, partial) {
				candidates = append(candidates, Candidate{Name: name, Desc: "(configured)"})
			}
		}
	}
	return candidates
}

// typedLeafCandidates returns the `?` completion entries for the value
// slot of a typed leaf: a single placeholder entry carrying the value's
// description, plus one entry per declared example.
func typedLeafCandidates(node *Node, partial string) []Candidate {
	var out []Candidate
	if ph := node.ValueType.Placeholder(); ph != "" {
		desc := node.ValueDesc
		if desc == "" {
			desc = node.Desc
		}
		if strings.HasPrefix(ph, partial) {
			out = append(out, Candidate{Name: ph, Desc: desc})
		}
	}
	for _, ex := range node.ValueExamples {
		if strings.HasPrefix(ex, partial) {
			out = append(out, Candidate{Name: ex, Desc: "example"})
		}
	}
	return out
}

// LookupDesc finds the description for a candidate name given the command path words.
// Works for both operational and config mode.
func LookupDesc(words []string, name string, configMode bool) string {
	var tree map[string]*Node
	if configMode {
		if len(words) == 0 {
			if node, ok := ConfigTopLevel[name]; ok {
				return node.Desc
			}
			return ""
		}
		resolvedTop, ok := ResolveUniquePrefix(KeysFromTree(ConfigTopLevel), words[0])
		if !ok {
			return ""
		}
		if resolvedTop == "run" {
			tree = OperationalTree
			words = words[1:]
		} else {
			// Walk config top-level children (e.g. "commit" → "check")
			node, ok := ConfigTopLevel[resolvedTop]
			if !ok {
				return ""
			}
			for _, w := range words[1:] {
				if node.Children == nil {
					return ""
				}
				_, node, _, ok = resolveTreeWord(node.Children, w)
				if !ok {
					return ""
				}
			}
			if node.Children != nil {
				if child, ok := node.Children[name]; ok {
					return child.Desc
				}
			}
			return ""
		}
	} else {
		tree = OperationalTree
	}

	// Walk operational tree
	current := tree
	var currentNode *Node
	for _, w := range words {
		_, node, _, ok := resolveTreeWord(current, w)
		if !ok {
			// Dynamic value — skip but stay at same children level.
			if currentNode != nil && currentNode.HasDynamic() {
				continue
			}
			// Placeholder node consumes any value.
			if ph := findPlaceholder(current); ph != nil {
				if ph.Children != nil {
					currentNode = ph
					current = ph.Children
				}
				continue
			}
			return ""
		}
		currentNode = node
		if node.Children == nil {
			return ""
		}
		current = node.Children
	}
	if node, ok := current[name]; ok {
		return node.Desc
	}
	return ""
}

// WriteHelp prints aligned completion candidates to w.
// The entire output is built as a single string and written in one call
// so that readline's wrapWriter triggers only one Refresh cycle.
func WriteHelp(w io.Writer, candidates []Candidate) {
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Name < candidates[j].Name })
	maxWidth := 20
	for _, c := range candidates {
		if len(c.Name)+2 > maxWidth {
			maxWidth = len(c.Name) + 2
		}
	}
	var sb strings.Builder
	sb.WriteString("Possible completions:\n")
	for _, c := range candidates {
		if c.Desc != "" {
			fmt.Fprintf(&sb, "  %-*s %s\n", maxWidth, c.Name, c.Desc)
		} else {
			fmt.Fprintf(&sb, "  %s\n", c.Name)
		}
	}
	io.WriteString(w, sb.String())
}

// PrintTreeHelp prints self-generating help from a tree path.
func PrintTreeHelp(header string, tree map[string]*Node, path ...string) {
	fmt.Println(header)
	current := tree
	for _, p := range path {
		node, ok := current[p]
		if !ok {
			return
		}
		if node.Children == nil {
			return
		}
		current = node.Children
	}
	WriteHelp(os.Stdout, HelpCandidates(current))
}

// CommonPrefix returns the longest shared prefix among the given strings.
func CommonPrefix(items []string) string {
	if len(items) == 0 {
		return ""
	}
	prefix := items[0]
	for _, s := range items[1:] {
		for !strings.HasPrefix(s, prefix) {
			prefix = prefix[:len(prefix)-1]
			if prefix == "" {
				return ""
			}
		}
	}
	return prefix
}

// KeysOf returns an unsorted list of keys from a Node map.
func KeysOf(m map[string]*Node) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// cosClassifierNames returns the configured CoS classifier names (DSCP and
// IEEE-802.1p) for tab-completion of `show class-of-service classifier`.
func cosClassifierNames(cfg *config.Config) []string {
	if cfg == nil || cfg.ClassOfService == nil {
		return nil
	}
	names := make([]string, 0,
		len(cfg.ClassOfService.DSCPClassifiers)+len(cfg.ClassOfService.IEEE8021Classifiers))
	for name := range cfg.ClassOfService.DSCPClassifiers {
		names = append(names, name)
	}
	for name := range cfg.ClassOfService.IEEE8021Classifiers {
		names = append(names, name)
	}
	return names
}

// cosRewriteRuleNames returns every configured rewrite-rule name across all
// four code-point families, for `show class-of-service rewrite-rule` completion
// (#6848). It deliberately includes the accepted-but-inert families
// (ieee-802.1, inet-precedence, exp): an operator who configured an inert rule
// must be able to tab-complete it and SEE that it is inert — completing only
// the enforced dscp rules would hide exactly the rules this command exists to
// surface. The two name-only families are stored as slices, not maps
// (ClassOfServiceConfig.INetPrecedenceRewriteRules / EXPRewriteRules).
func cosRewriteRuleNames(cfg *config.Config) []string {
	if cfg == nil || cfg.ClassOfService == nil {
		return nil
	}
	cos := cfg.ClassOfService
	names := make([]string, 0,
		len(cos.DSCPRewriteRules)+len(cos.IEEE8021RewriteRules)+
			len(cos.INetPrecedenceRewriteRules)+len(cos.EXPRewriteRules))
	for name := range cos.DSCPRewriteRules {
		names = append(names, name)
	}
	for name := range cos.IEEE8021RewriteRules {
		names = append(names, name)
	}
	names = append(names, cos.INetPrecedenceRewriteRules...)
	names = append(names, cos.EXPRewriteRules...)
	return names
}

// FilterPrefix returns only items that start with the given prefix.
func FilterPrefix(items []string, prefix string) []string {
	if prefix == "" {
		return items
	}
	var result []string
	for _, item := range items {
		if strings.HasPrefix(item, prefix) {
			result = append(result, item)
		}
	}
	return result
}
