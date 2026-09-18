package config

// schema_cos.go carries the traffic-conditioning subtrees of the
// config-mode grammar SSOT (#1891 domain split): `class-of-service`
// and `firewall` (filters are the CoS classifier/rewrite attachment
// point — forwarding-class and DSCP actions). The root composition,
// the schemaNode type, and the split rationale live in schema.go.

var schemaClassOfService = &schemaNode{desc: "Class of service configuration", children: map[string]*schemaNode{
	"forwarding-classes": {desc: "Forwarding class definitions", children: map[string]*schemaNode{
		"queue": {desc: "Map a queue number to a forwarding-class name (one queue per class, one class per queue)", args: 2, multi: true, keyValidatorPos: ValidateForwardingClassQueueArg, children: nil},
	}},
	"classifiers": {desc: "Classifiers mapping incoming code points to forwarding classes", children: map[string]*schemaNode{
		"dscp": {desc: "DSCP classifier", args: 1, multi: true, placeholder: "<classifier-name>", children: map[string]*schemaNode{
			"forwarding-class": {desc: "Forwarding class to assign to matching code points", args: 1, multi: true, placeholder: "<class-name>", keyValidator: ValidateForwardingClassName, children: map[string]*schemaNode{
				"loss-priority": {desc: "Loss priority for packets matching this code point (ENFORCED: feeds dscp_lp_by_dscp, which selects the egress DSCP rewrite row)", args: 1, multi: true, placeholder: "<level>", children: map[string]*schemaNode{
					"code-points": {desc: "DSCP code points to match (alias such as ef, af11, cs6, or numeric 0..63)", args: 1, multi: true, placeholder: "<code-points>", children: nil},
				}},
			}},
		}},
		"ieee-802.1": {desc: "IEEE 802.1p classifier", args: 1, multi: true, placeholder: "<classifier-name>", children: map[string]*schemaNode{
			"forwarding-class": {desc: "Forwarding class to assign to matching code points", args: 1, multi: true, placeholder: "<class-name>", keyValidator: ValidateForwardingClassName, children: map[string]*schemaNode{
				"loss-priority": {desc: "Loss priority for packets matching this code point (ENFORCED: feeds ieee8021_lp_by_pcp, which selects the egress DSCP rewrite row)", args: 1, multi: true, placeholder: "<level>", children: map[string]*schemaNode{
					"code-points": {desc: "IEEE 802.1p code points to match (0..7)", args: 1, multi: true, placeholder: "<code-points>", children: nil},
				}},
			}},
		}},
		// IP-precedence classifier. Added inert for Junos compatibility in
		// #4316 (fable-167 F-3b); ENFORCED since #6847 — the entries compile,
		// cross the wire as inet_precedence_classifiers, and the dataplane
		// classifies on the top 3 bits of the DS field. The matching
		// accepted-but-inert commit advisory was retracted with it. The
		// `rewrite-rules inet-precedence` direction below is still inert.
		"inet-precedence": {desc: "IP-precedence classifier (classify on the 3-bit IP precedence field)", args: 1, multi: true, placeholder: "<classifier-name>", children: map[string]*schemaNode{
			"forwarding-class": {desc: "Forwarding class to assign to matching code points", args: 1, multi: true, placeholder: "<class-name>", keyValidator: ValidateForwardingClassName, children: map[string]*schemaNode{
				"loss-priority": {desc: "Loss priority for packets matching this precedence (ENFORCED: feeds inet_precedence_lp_by_prec, which selects the egress DSCP rewrite row)", args: 1, multi: true, placeholder: "<level>", children: map[string]*schemaNode{
					"code-points": {desc: "IP-precedence code points to match (0..7)", args: 1, multi: true, placeholder: "<code-points>", children: nil},
				}},
			}},
		}},
	}},
	"rewrite-rules": {desc: "Egress rewrite rules mapping forwarding classes to code points", children: map[string]*schemaNode{
		"dscp": {desc: "DSCP rewrite rule", args: 1, multi: true, placeholder: "<rewrite-rule-name>", children: map[string]*schemaNode{
			"forwarding-class": {desc: "Forwarding class whose packets get the rewritten code point", args: 1, multi: true, placeholder: "<class-name>", keyValidator: ValidateForwardingClassName, children: map[string]*schemaNode{
				"loss-priority": {desc: "Loss priority this rewrite entry applies to (ENFORCED: the egress DSCP is chosen by (queue, loss-priority))", args: 1, multi: true, placeholder: "<level>", children: map[string]*schemaNode{
					"code-point":  {desc: "DSCP code point to write (alias such as ef, af11, cs6, or numeric 0..63)", args: 1, placeholder: "<code-point>", children: nil},
					"code-points": {desc: "DSCP code point to write (alias of code-point; first value is used)", args: 1, multi: true, placeholder: "<code-points>", children: nil},
				}},
			}},
		}},
		// #4228 Gap 4: IEEE 802.1p (PCP) egress rewrite. Fully modeled
		// (forwarding-class -> loss-priority -> code-point 0..7) so a vSRX
		// config commits clean and the mapping is validated, but ACCEPTED-BUT-
		// INERT — the userspace dataplane rewrites only dscp on egress today and
		// does not yet own the 802.1Q tag write (a commit advisory surfaces the
		// inertness). Mirrors the `dscp` rewrite subtree; the classifier side
		// (classifiers ieee-802.1) is already enforced.
		"ieee-802.1": {desc: "IEEE 802.1p (PCP) rewrite rule (accepted for Junos compatibility; NOT yet enforced — the dataplane rewrites dscp only)", args: 1, multi: true, placeholder: "<rewrite-rule-name>", children: map[string]*schemaNode{
			"forwarding-class": {desc: "Forwarding class whose packets get the rewritten code point", args: 1, multi: true, placeholder: "<class-name>", keyValidator: ValidateForwardingClassName, children: map[string]*schemaNode{
				"loss-priority": {desc: "Loss priority (accepted for Junos compatibility; not enforced by the userspace dataplane)", args: 1, multi: true, placeholder: "<level>", children: map[string]*schemaNode{
					"code-point":  {desc: "802.1p PCP code point to write (0..7)", args: 1, placeholder: "<code-point>", children: nil},
					"code-points": {desc: "802.1p PCP code point to write (alias of code-point; first value is used)", args: 1, multi: true, placeholder: "<code-points>", children: nil},
				}},
			}},
		}},
		// #4316 (fable-167 F-3b): IP-precedence and MPLS EXP egress rewrite.
		// Accepted for Junos compatibility (completion + ? help) but INERT —
		// the userspace dataplane rewrites only dscp on egress. Commit advisory.
		"inet-precedence": {desc: "IP-precedence rewrite rule (accepted for Junos compatibility; NOT enforced — the dataplane rewrites dscp only)", args: 1, multi: true, placeholder: "<rewrite-rule-name>", children: map[string]*schemaNode{
			"forwarding-class": {desc: "Forwarding class whose packets get the rewritten code point", args: 1, multi: true, placeholder: "<class-name>", keyValidator: ValidateForwardingClassName, children: map[string]*schemaNode{
				"loss-priority": {desc: "Loss priority (accepted for Junos compatibility; not enforced by the userspace dataplane)", args: 1, multi: true, placeholder: "<level>", children: map[string]*schemaNode{
					"code-point":  {desc: "IP-precedence code point to write (0..7)", args: 1, placeholder: "<code-point>", children: nil},
					"code-points": {desc: "IP-precedence code point to write (alias of code-point; first value is used)", args: 1, multi: true, placeholder: "<code-points>", children: nil},
				}},
			}},
		}},
		"exp": {desc: "MPLS EXP rewrite rule (accepted for Junos compatibility; NOT enforced — the dataplane rewrites dscp only)", args: 1, multi: true, placeholder: "<rewrite-rule-name>", children: map[string]*schemaNode{
			"forwarding-class": {desc: "Forwarding class whose packets get the rewritten code point", args: 1, multi: true, placeholder: "<class-name>", keyValidator: ValidateForwardingClassName, children: map[string]*schemaNode{
				"loss-priority": {desc: "Loss priority (accepted for Junos compatibility; not enforced by the userspace dataplane)", args: 1, multi: true, placeholder: "<level>", children: map[string]*schemaNode{
					"code-point":  {desc: "MPLS EXP code point to write (0..7)", args: 1, placeholder: "<code-point>", children: nil},
					"code-points": {desc: "MPLS EXP code point to write (alias of code-point; first value is used)", args: 1, multi: true, placeholder: "<code-points>", children: nil},
				}},
			}},
		}},
	}},
	"schedulers": {desc: "Scheduler definitions (transmit rate, priority, buffer)", args: 1, multi: true, placeholder: "<scheduler-name>", children: map[string]*schemaNode{
		// #1319 typed leaves. Re-homed from the cmdtree overlay
		// (cmdtree.ConfigClassOfServiceSchedulers, retired in this PR)
		// onto setSchema so the live config-mode `set ... ?` completer
		// and the SchemaValidate commit-check gate read one tree. The
		// `exact` child predates #1319 and is unchanged — adding fields
		// to transmit-rate does not alter SetPath grouping.
		// #4228 Gap 2: transmit-rate accepts an absolute bandwidth (10m), the
		// Junos `percent <n>` form (share of the bound interface's rate), or
		// `remainder` (leftover bandwidth), each optionally `exact`. The
		// heterogeneous tail is validated as a unit (tailValidator) because the
		// first token is EITHER a value or a keyword — the standard typed-leaf
		// path cannot express that. percent/remainder compile to a stored
		// percent/flag that the dataplane does not yet resolve to an absolute
		// rate (commit advisory, compiler_validate_warn.go). valueType drives
		// `?` completion only; validator MUST stay nil so the tail path owns
		// acceptance. percent/remainder are also declared as children purely so
		// `set ... transmit-rate ?` surfaces them.
		"transmit-rate": {
			desc:          "Transmit rate: a bandwidth (100k, 10m, 1g), `percent <n>`, or `remainder`",
			args:          1,
			valueType:     ValueRateOrPercent,
			valueDesc:     "Bandwidth (e.g. 100k, 10m, 1g), `percent <n>`, or `remainder`",
			valueExamples: []string{"100k", "10m", "1g", "10g", "percent", "remainder"},
			tailValidator: ValidateCoSTransmitRateTail,
			children: map[string]*schemaNode{
				"exact":     {desc: "Cap the queue at the configured rate (no surplus borrowing unless surplus-sharing is set)", children: nil},
				"percent":   {desc: "Transmit rate as a percent of the bound interface's rate (accepted for Junos compatibility; NOT yet resolved to an absolute rate by the dataplane)", args: 1, placeholder: "<percent>", children: nil},
				"remainder": {desc: "Share of the leftover bandwidth (accepted for Junos compatibility; NOT yet resolved to an absolute rate by the dataplane)", children: nil},
			},
		},
		"priority": {
			desc:          "Scheduler priority level",
			args:          1,
			valueType:     ValueEnumOf,
			valueDesc:     "Scheduler priority (low | medium-low | medium-high | high | strict-high)",
			valueExamples: []string{"low", "medium-low", "medium-high", "high", "strict-high"},
			validator: ValidateEnum([]string{
				"low", "medium-low", "medium-high", "high", "strict-high",
			}),
			children: nil,
		},
		// #4228 Gap 2 follow-up: buffer-size accepts an absolute byte-size
		// (16m), a percent of the interface buffer pool (10%), OR the Junos
		// `temporal <microseconds>` form (size the buffer by target queue
		// delay). The heterogeneous tail is validated as a unit (tailValidator)
		// because the first token is EITHER a value or the `temporal` keyword —
		// the generic typed-leaf path cannot express that. temporal compiles to
		// a stored microsecond value that the dataplane does not yet resolve to
		// bytes (commit advisory, compiler_validate_warn.go). valueType drives
		// `?` completion only; validator MUST stay nil so the tail path owns
		// acceptance. `temporal` is declared as a child purely so `set ...
		// buffer-size ?` surfaces it.
		"buffer-size": {
			desc:          "Queue buffer size: bytes (16m), a percent of the interface buffer pool (10%), or `temporal <microseconds>` (target queue delay)",
			args:          1,
			valueType:     ValueByteSizeOrPercent,
			valueDesc:     "Byte-size (16m, 256k), percent of interface CoS burst pool (10%), or `temporal <microseconds>`",
			valueExamples: []string{"16m", "256k", "10%", "temporal"},
			tailValidator: ValidateCoSBufferSizeTail,
			children: map[string]*schemaNode{
				"temporal": {desc: "Size the buffer by target queue delay in microseconds (accepted for Junos compatibility; NOT yet resolved to bytes by the dataplane)", args: 1, placeholder: "<microseconds>", children: nil},
			},
		},
		// `surplus-sharing` (#915) and `equal-flow-enforcement` are
		// presence-only flags — no value to validate.
		"surplus-sharing":        {desc: "Let this exact-rate queue draw surplus bandwidth once its own rate is exhausted (only meaningful with transmit-rate exact)", children: nil},
		"equal-flow-enforcement": {desc: "Enforce equal per-flow rates on this queue (requires positive transmit-rate exact; cannot be combined with surplus-sharing)", children: nil},
		// #1746: equal-flow target policy. Only meaningful with
		// `equal-flow-enforcement`; unset == `slowest` (the
		// byte-unchanged clip-to-slowest default). `mean` and
		// `slowest` are non-work-conserving (commit warning).
		"equal-flow-target-policy": {
			desc:          "Per-flow target policy for equal-flow enforcement (slowest | mean | ideal-share, unset = slowest)",
			args:          1,
			valueType:     ValueEnumOf,
			valueDesc:     "Equal-flow per-flow target policy (slowest | mean | ideal-share)",
			valueExamples: []string{"slowest", "mean", "ideal-share"},
			validator: ValidateEnum([]string{
				"slowest", "mean", "ideal-share",
			}),
			children: nil,
		},
		// #1614 A3 CoDel AQM target queue delay in milliseconds. The
		// value is typed so `codel-target banana` is REJECTED at commit
		// (the compiler otherwise swallows the parse error and drops the
		// value silently), but the AQM itself is NOT enforced — #1829
		// Phase 2 was PLAN-KILLED. A commit warning
		// (compiler_validate_warn.go CoS scheduler loop) surfaces the
		// inertness when CodelTargetNS>0 (#4218).
		"codel-target": {
			desc:          "CoDel AQM target queue delay in milliseconds (accepted for Junos compatibility; AQM not yet enforced by the userspace dataplane)",
			args:          1,
			valueType:     ValueInteger,
			valueDesc:     "CoDel target queue delay in milliseconds (non-negative integer; AQM not yet enforced)",
			valueExamples: []string{"5", "10"},
			validator:     ValidateIntegerMin(0),
			children:      nil,
		},
	}},
	"scheduler-maps": {desc: "Scheduler map assigning schedulers to forwarding classes", args: 1, multi: true, placeholder: "<map-name>", children: map[string]*schemaNode{
		"forwarding-class": {desc: "Forwarding class entry in this map", args: 1, multi: true, placeholder: "<class-name>", keyValidator: ValidateForwardingClassName, closedWorld: true, children: map[string]*schemaNode{
			"scheduler": {desc: "Scheduler to apply to this forwarding class", args: 1, placeholder: "<scheduler-name>", children: nil},
		}},
	}},
	// #4315 (fable-167 F-2): the Junos hierarchical shaping profile. A
	// profile is bound to a logical interface's egress via
	// `interfaces <if> unit N output-traffic-control-profile <name>`;
	// resolveCoSTrafficControlProfiles folds shaping-rate + scheduler-map
	// into the referencing unit's existing per-unit shaper. shaping-rate is
	// a plain typed rate leaf here (no burst-size child, unlike the
	// interface-level cosShapingRateSchema — Junos sizes the buffer via
	// delay-buffer-rate, not burst-size). guaranteed-rate / delay-buffer-rate
	// are typed (garbage rejected at commit) but currently INERT — no
	// per-unit dataplane consumer — and carry a commit advisory.
	"traffic-control-profiles": {desc: "Hierarchical traffic-shaping profiles bound to an interface via output-traffic-control-profile", args: 1, multi: true, placeholder: "<profile-name>", children: map[string]*schemaNode{
		// #4228 Gap 2: shaping-rate accepts an absolute bandwidth (10m) or the
		// Junos `percent <n>` form (share of the bound interface's speed). The
		// absolute form is enforced as the root shaper on the bound unit; the
		// percent form is accepted for vSRX-config import parity but is inert
		// until the dataplane can resolve it against the interface speed
		// (commit advisory). Whole-tail validated; children stay nil so
		// re-setting shaping-rate REPLACES (single-valued) rather than
		// appending, and the `percent 90` container groups its value as a
		// child that gatherLeafTailTokens flattens.
		"shaping-rate": {
			desc:          "Peak shaping rate: a bandwidth (k/m/g) or `percent <n>` — enforced as the root shaper on the bound unit (percent accepted-but-inert)",
			args:          1,
			placeholder:   "<rate|percent>",
			valueType:     ValueRateOrPercent,
			valueDesc:     "Bandwidth (e.g. 100k, 10m, 1g) or `percent <n>`",
			valueExamples: []string{"10m", "1g", "10g", "percent"},
			tailValidator: ValidateCoSShapingRateTail,
			children:      nil,
		},
		"guaranteed-rate": {
			desc:          "Guaranteed minimum rate in bits per second (accepted for Junos compatibility; NOT yet enforced per-unit by the userspace dataplane)",
			args:          1,
			placeholder:   "<rate>",
			valueType:     ValueRate,
			valueDesc:     "Bandwidth (e.g. 100k, 10m, 1g) or bps integer; >= 8 bps (accepted but currently inert)",
			valueExamples: []string{"5m", "500m"},
			validator:     ValidateRate,
			children:      nil,
		},
		"delay-buffer-rate": {
			desc:          "Delay-buffer sizing rate in bits per second (accepted for Junos compatibility; NOT yet enforced by the userspace dataplane)",
			args:          1,
			placeholder:   "<rate>",
			valueType:     ValueRate,
			valueDesc:     "Bandwidth (e.g. 100k, 10m, 1g) or bps integer; >= 8 bps (accepted but currently inert)",
			valueExamples: []string{"10m", "1g"},
			validator:     ValidateRate,
			children:      nil,
		},
		"scheduler-map": {desc: "Scheduler map applied to the unit bound to this profile", args: 1, placeholder: "<map-name>", children: nil},
	}},
	"interfaces": {desc: "Apply CoS to an interface", args: 1, multi: true, placeholder: "<interface-name>", children: map[string]*schemaNode{
		"unit": {desc: "Logical unit number", args: 1, multi: true, placeholder: "<unit-number>", children: map[string]*schemaNode{
			// issue 8939: packedStatements so a run written on one line --
			// `classifiers dscp c1 ieee-802.1 c2;` -- splits into siblings
			// instead of landing whole on this node's Keys, where the compiler
			// reads the first binding and drops the rest.
			//
			// The loss is the FALLBACK shape rather than the missing shape:
			// pkg/dataplane/userspace/interfaces.go records that an unpublished
			// classifier binding means "the dataplane sees no classifier and
			// every packet falls through to the DEFAULT QUEUE". Traffic is
			// still classified, into the wrong queue -- and because the FIRST
			// binding survives, the interface visibly carries a working
			// classifier while the second silently does nothing. Partial
			// application reads as success.
			//
			// Declared on the NODE, so no #8921 collision check is owed: this
			// reaches these four binding sites and not the top-level
			// classifier/rewrite-rule DEFINITIONS, which are a different shape.
			"classifiers": {desc: "Classifiers applied to traffic arriving on this unit", packedStatements: true, children: map[string]*schemaNode{
				"dscp": {desc: "DSCP classifier to apply", args: 1, placeholder: "<classifier-name>", children: nil},
				// #6847: before this the unit had NO inet-precedence binding
				// site, so an inet-precedence classifier was definable at the
				// top level but not bindable — the bind line was rejected by
				// the schema. Mutually exclusive with `dscp` (both read the
				// same IPv4 TOS byte); the conflict is rejected at commit
				// rather than resolved by a silent precedence order.
				"inet-precedence": {desc: "IP-precedence classifier to apply (cannot be combined with dscp on the same unit)", args: 1, placeholder: "<classifier-name>", children: nil},
				"ieee-802.1":      {desc: "IEEE 802.1p classifier to apply", args: 1, placeholder: "<classifier-name>", children: nil},
			}},
			// issue 8939: packedStatements so a run written on one line --
			// `classifiers dscp c1 ieee-802.1 c2;` -- splits into siblings
			// instead of landing whole on this node's Keys, where the compiler
			// reads the first binding and drops the rest.
			//
			// The loss is the FALLBACK shape rather than the missing shape:
			// pkg/dataplane/userspace/interfaces.go records that an unpublished
			// classifier binding means "the dataplane sees no classifier and
			// every packet falls through to the DEFAULT QUEUE". Traffic is
			// still classified, into the wrong queue -- and because the FIRST
			// binding survives, the interface visibly carries a working
			// classifier while the second silently does nothing. Partial
			// application reads as success.
			//
			// Declared on the NODE, so no #8921 collision check is owed: this
			// reaches these four binding sites and not the top-level
			// classifier/rewrite-rule DEFINITIONS, which are a different shape.
			"rewrite-rules": {desc: "Rewrite rules applied to traffic leaving this unit", packedStatements: true, children: map[string]*schemaNode{
				"dscp":       {desc: "DSCP rewrite rule to apply", args: 1, placeholder: "<rewrite-rule-name>", children: nil},
				"ieee-802.1": {desc: "IEEE 802.1p (PCP) rewrite rule to apply (accepted-but-inert; dataplane rewrites dscp only)", args: 1, placeholder: "<rewrite-rule-name>", children: nil},
			}},
			"shaping-rate":                   cosShapingRateSchema("Shaping rate for this unit in bits per second (k/m/g suffixes)"),
			"scheduler-map":                  {desc: "Scheduler map to apply to this unit", args: 1, placeholder: "<map-name>", children: nil},
			"output-traffic-control-profile": {desc: "Bind a traffic-control-profile to this unit's egress (applies its shaping-rate + scheduler-map)", args: 1, placeholder: "<profile-name>", children: nil},
			"oversubscription-policy":        cosOversubscriptionPolicySchema(),
			"priority-low-min-share":         cosPriorityLowMinShareSchema(),
		}},
		// #4021: interface-level (physical, no unit) bindings. In Junos these
		// apply to every logical unit on the port; a unit-level binding
		// overrides per knob. The compiler folds them into the configured
		// units (applyCoSInterfaceLevelBindings). Same knobs as the unit
		// level so flat-set grouping nests them identically.
		// issue 8939: packedStatements so a run written on one line --
		// `classifiers dscp c1 ieee-802.1 c2;` -- splits into siblings
		// instead of landing whole on this node's Keys, where the compiler
		// reads the first binding and drops the rest.
		//
		// The loss is the FALLBACK shape rather than the missing shape:
		// pkg/dataplane/userspace/interfaces.go records that an unpublished
		// classifier binding means "the dataplane sees no classifier and
		// every packet falls through to the DEFAULT QUEUE". Traffic is
		// still classified, into the wrong queue -- and because the FIRST
		// binding survives, the interface visibly carries a working
		// classifier while the second silently does nothing. Partial
		// application reads as success.
		//
		// Declared on the NODE, so no #8921 collision check is owed: this
		// reaches these four binding sites and not the top-level
		// classifier/rewrite-rule DEFINITIONS, which are a different shape.
		"classifiers": {desc: "Classifiers applied at the interface level (all units)", packedStatements: true, children: map[string]*schemaNode{
			"dscp":       {desc: "DSCP classifier to apply", args: 1, placeholder: "<classifier-name>", children: nil},
			"ieee-802.1": {desc: "IEEE 802.1p classifier to apply", args: 1, placeholder: "<classifier-name>", children: nil},
		}},
		// issue 8939: packedStatements so a run written on one line --
		// `classifiers dscp c1 ieee-802.1 c2;` -- splits into siblings
		// instead of landing whole on this node's Keys, where the compiler
		// reads the first binding and drops the rest.
		//
		// The loss is the FALLBACK shape rather than the missing shape:
		// pkg/dataplane/userspace/interfaces.go records that an unpublished
		// classifier binding means "the dataplane sees no classifier and
		// every packet falls through to the DEFAULT QUEUE". Traffic is
		// still classified, into the wrong queue -- and because the FIRST
		// binding survives, the interface visibly carries a working
		// classifier while the second silently does nothing. Partial
		// application reads as success.
		//
		// Declared on the NODE, so no #8921 collision check is owed: this
		// reaches these four binding sites and not the top-level
		// classifier/rewrite-rule DEFINITIONS, which are a different shape.
		"rewrite-rules": {desc: "Rewrite rules applied at the interface level (all units)", packedStatements: true, children: map[string]*schemaNode{
			"dscp":       {desc: "DSCP rewrite rule to apply", args: 1, placeholder: "<rewrite-rule-name>", children: nil},
			"ieee-802.1": {desc: "IEEE 802.1p (PCP) rewrite rule to apply (accepted-but-inert; dataplane rewrites dscp only)", args: 1, placeholder: "<rewrite-rule-name>", children: nil},
		}},
		"shaping-rate":                   cosShapingRateSchema("Shaping rate applied at the interface level in bits per second (k/m/g suffixes)"),
		"scheduler-map":                  {desc: "Scheduler map to apply at the interface level (all units)", args: 1, placeholder: "<map-name>", children: nil},
		"output-traffic-control-profile": {desc: "Bind a traffic-control-profile at the interface level (all units)", args: 1, placeholder: "<profile-name>", children: nil},
		"oversubscription-policy":        cosOversubscriptionPolicySchema(),
		"priority-low-min-share":         cosPriorityLowMinShareSchema(),
	}},
	"fairness": {desc: "Dataplane fairness observability configuration", children: map[string]*schemaNode{
		"rss-expectation": {desc: "Declarative RSS flow-distribution expectations evaluated against live dataplane status (shown in fairness output and exported as Prometheus gauges)", children: map[string]*schemaNode{
			"interface": {desc: "Stable interface name to evaluate (resolved to the current kernel ifindex at evaluate time)", args: 1, multi: true, placeholder: "<interface-name>", children: map[string]*schemaNode{
				"queue": {desc: "CoS queue ID to evaluate (0..255; exactly one expectation per queue)", args: 1, multi: true, placeholder: "<queue-id>", children: map[string]*schemaNode{
					"any":                     {desc: "No expectation; always passes", children: nil},
					"balanced":                {desc: "Expect flows spread across min(flows, workers) workers with per-worker flow counts within 1", children: nil},
					"active-workers":          {desc: "Alias for at-least-active-workers", args: 1, placeholder: "<count>", children: nil},
					"at-least-active-workers": {desc: "Expect at least this many workers with active flows", args: 1, placeholder: "<count>", children: nil},
					"max-worker-flow-share":   {desc: "Expect the busiest worker's share of active flows to be at most this threshold (fraction 0..1 or percent)", args: 1, placeholder: "<share>", children: nil},
					"cstruct":                 {desc: "Alias for cstruct-max", args: 1, placeholder: "<threshold>", children: nil},
					"cstruct-max":             {desc: "Expect the structural CoV ceiling (Cstruct) of the observed flow distribution to be at most this threshold (non-negative number or percent)", args: 1, placeholder: "<threshold>", children: nil},
				}},
			}},
		}},
	}},
}}

// cosShapingRateSchema builds the `shaping-rate` CoS binding leaf shared by
// the unit level and the #4021 interface level. shaping-rate is a CONTAINER
// (it carries the burst-size child), so its rate value is typed via the
// container `keyValidator` (ValidateRate) — NOT `valueType`, which would flip
// the walker into the typed-LEAF branch and mis-treat burst-size as a
// presence-only modifier. Before #4217 both leaves were untyped, so
// `shaping-rate 10gg` committed as 0 (parseBandwidthLimit's silent
// zero-on-garbage), which the compiler reads as "unset" — the root shaper
// silently disappeared and egress ran unshaped.
func cosShapingRateSchema(desc string) *schemaNode {
	return &schemaNode{
		desc:             desc,
		args:             1,
		placeholder:      "<rate>",
		keyValueType:     ValueRate,
		keyValueDesc:     "Shaping rate (e.g. 100k, 10m, 1g) or bps integer; >= 8 bps",
		keyValueExamples: []string{"10m", "1g", "10g"},
		keyValidator:     ValidateRate,
		children: map[string]*schemaNode{
			"burst-size": {
				desc:          "Shaping burst size in bytes (explicit k/m/g suffix)",
				args:          1,
				placeholder:   "<bytes>",
				valueType:     ValueByteSize,
				valueDesc:     "Byte-size with an explicit k/m/g suffix (e.g. 15k, 1m)",
				valueExamples: []string{"15k", "1m"},
				validator:     ValidateByteSize,
			},
		},
	}
}

// cosOversubscriptionPolicySchema builds the #1614 A1 `oversubscription-policy`
// binding leaf shared by the unit level and the interface level. It is a
// container `{ guarantee-rate <fraction 0..1> | proportional }`; the compiler
// (parseCoSInterfaceUnitBody) reads guarantee-rate's fraction and clamps to
// [0,1], so the schema rejects an out-of-range fraction at commit rather than
// silently clamping (#4219). Before #4219 the whole leaf was absent from the
// schema — no completion, no validation, unknown policy strings committing.
func cosOversubscriptionPolicySchema() *schemaNode {
	return &schemaNode{
		desc: "Oversubscription allocation policy when exact-class transmit-rates exceed the shaping-rate (#1614)",
		children: map[string]*schemaNode{
			"guarantee-rate": {
				desc:          "Fraction of the shaping-rate guaranteed to each exact class before proportional sharing (0..1)",
				args:          1,
				placeholder:   "<fraction>",
				valueType:     ValuePercent,
				valueDesc:     "Guaranteed fraction of the shaping-rate in the range 0..1 (e.g. 0.7)",
				valueExamples: []string{"0.5", "0.7", "1"},
				validator:     ValidatePercent(0, 1),
			},
			"proportional": {desc: "Share the shaping-rate proportionally to configured rates (default)", children: nil},
		},
	}
}

// cosPriorityLowMinShareSchema builds the #1614 A2 `priority-low-min-share`
// binding leaf shared by the unit level and the interface level. The value is
// typed + validated at commit (so garbage is rejected, not silently zeroed by
// parseBandwidthLimit) and offers `?` completion, but the knob is currently
// INERT in the dataplane: it is WIRE-SURFACE-ONLY (the cap_eff reservation
// that would enforce it is deferred research). A commit warning
// (compiler_validate_warn.go CoS interface loop) surfaces the inertness
// (#4220 / #4219).
func cosPriorityLowMinShareSchema() *schemaNode {
	return &schemaNode{
		desc:          "Minimum guaranteed share for the priority-low queue in bits/sec (#1614 A2; accepted but NOT yet enforced by the dataplane)",
		args:          1,
		placeholder:   "<rate>",
		valueType:     ValueRate,
		valueDesc:     "Bandwidth (e.g. 100k, 10m, 1g) or bps integer; >= 8 bps (accepted but currently inert)",
		valueExamples: []string{"100m", "1g"},
		validator:     ValidateRate,
	}
}

var schemaFirewall = &schemaNode{desc: "Firewall filters and policers", children: map[string]*schemaNode{
	"policer": {desc: "Traffic policer", args: 1, multi: true, placeholder: "<name>", children: map[string]*schemaNode{
		"if-exceeding": {desc: "Rate limits for the policer", packedStatements: true, children: map[string]*schemaNode{
			// #5299: both leaves were untyped (ValueAny), so the legacy
			// parsers (parseBandwidthLimit / parseBurstSizeLimit) silently
			// coerced garbage / zero / overflow to 0 bps/bytes. A typo like
			// `bandwidth-limit 10mm` then committed clean and fail-closed the
			// meter to a drop-all (default `then discard`) or an inert meter.
			// Typing them rejects malformed/zero/overflowing input loud at
			// commit; the tolerant Store.Load / SyncApply ingress downgrades
			// the same violation to a warning (#1319 doctrine).
			"bandwidth-limit": {
				desc:          "Bandwidth limit in bits per second (k|m|g suffix)",
				args:          1,
				placeholder:   "<bps>",
				valueType:     ValueRate,
				valueDesc:     "Bandwidth in bits/sec (e.g. 100k, 10m, 1g) or bps integer; must compile to a non-zero byte/sec rate",
				valueExamples: []string{"10m", "1g"},
				validator:     ValidateRate,
				children:      nil,
			},
			"burst-size-limit": {
				desc:          "Burst size limit in bytes (k|m|g suffix)",
				args:          1,
				placeholder:   "<bytes>",
				valueType:     ValueByteSize,
				valueDesc:     "Burst size in bytes (e.g. 15k, 100000, 1m); must be greater than zero and must not overflow",
				valueExamples: []string{"15k", "100000"},
				validator:     ValidatePolicerBurstSize,
				children:      nil,
			},
		}},
		"logical-interface-policer": {desc: "Logical interface policer (shared across protocol families)", children: nil},
		"then": {desc: "Action for traffic exceeding the limits", children: map[string]*schemaNode{
			"discard":          {desc: "Discard excess traffic (default)", children: nil},
			"loss-priority":    {desc: "Set loss priority for excess traffic (high|medium-high|medium-low|low)", args: 1, placeholder: "<priority>", children: nil},
			"forwarding-class": {desc: "Set forwarding class for excess traffic (marks and forwards; meter-only on this dataplane — #9882)", args: 1, placeholder: "<class>", children: nil},
		}},
	}},
	"three-color-policer": {desc: "Three-color policer", args: 1, multi: true, placeholder: "<name>", children: map[string]*schemaNode{
		"single-rate": {desc: "Single-rate three-color policer (CIR/CBS/EBS)", children: map[string]*schemaNode{
			"color-blind":                {desc: "Color-blind mode", children: nil},
			"color-aware":                {desc: "Color-aware mode", children: nil},
			"committed-information-rate": {desc: "Committed information rate in bits per second (k|m|g suffix)", args: 1, placeholder: "<bps>", children: nil},
			"committed-burst-size":       {desc: "Committed burst size in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
			"excess-burst-size":          {desc: "Excess burst size in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
		}},
		"two-rate": {desc: "Two-rate three-color policer (CIR/CBS/PIR/PBS)", children: map[string]*schemaNode{
			"color-blind":                {desc: "Color-blind mode", children: nil},
			"color-aware":                {desc: "Color-aware mode", children: nil},
			"committed-information-rate": {desc: "Committed information rate in bits per second (k|m|g suffix)", args: 1, placeholder: "<bps>", children: nil},
			"committed-burst-size":       {desc: "Committed burst size in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
			"peak-information-rate":      {desc: "Peak information rate in bits per second (k|m|g suffix)", args: 1, placeholder: "<bps>", children: nil},
			"peak-burst-size":            {desc: "Peak burst size in bytes (k|m|g suffix)", args: 1, placeholder: "<bytes>", children: nil},
		}},
		"then": {desc: "Action for out-of-profile traffic", children: map[string]*schemaNode{
			"discard":          {desc: "Discard out-of-profile traffic (default)", children: nil},
			"loss-priority":    {desc: "Set loss priority for out-of-profile traffic", args: 1, placeholder: "<priority>", children: nil},
			"forwarding-class": {desc: "Set forwarding class for out-of-profile traffic (marks and forwards; meter-only on this dataplane — #9882)", args: 1, placeholder: "<class>", children: nil},
		}},
	}},
	// #9017: an undeclared address-family token here used to collapse the
	// flat-set nesting and mint ZERO filters, so `family inett` -- a typo --
	// committed clean and voided the filter with no diagnostic. That is gated
	// by validateFirewallFilterFamilyTokensAST (compiler_firewall_family_9017.go)
	// rather than by `closedWorld: true`, because closedWorld INHERITS: arming
	// it here closed the ENTIRE filter grammar beneath it and started rejecting
	// `from source-prefix-list trusted`, which is valid and shipped. The gate
	// below is scoped to the family token itself.
	"family": {desc: "Protocol family for firewall filters", compoundKey: true, children: map[string]*schemaNode{
		"inet": {desc: "IPv4 firewall filters", children: map[string]*schemaNode{
			"filter": {desc: "Firewall filter", args: 1, placeholder: "<filter-name>", children: map[string]*schemaNode{
				// #4316 (fable-167 F-3a): interface-specific instantiates a
				// per-interface counter/policer instance in Junos. xpf accepts
				// it (completion + ? help) but keeps a single shared counter;
				// a commit advisory (compiler_validate_warn.go) surfaces the
				// divergence.
				"interface-specific": {desc: "Instantiate per-interface counter/policer instances (accepted; xpf keeps a single shared counter — advisory at commit)", children: nil},
				"term": {desc: "Filter term", args: 1, placeholder: "<term-name>", children: map[string]*schemaNode{
					"from": {desc: "Match conditions", children: map[string]*schemaNode{
						"source-address":          {desc: "Match source address", args: 1, multi: true, placeholder: "<address>", children: nil},
						"destination-address":     {desc: "Match destination address", args: 1, multi: true, placeholder: "<address>", children: nil},
						"source-prefix-list":      {desc: "Match source addresses from a prefix list", args: 1, multi: true, placeholder: "<prefix-list>", children: nil},
						"destination-prefix-list": {desc: "Match destination addresses from a prefix list", args: 1, multi: true, placeholder: "<prefix-list>", children: nil},
						"protocol":                {desc: "Match IP protocol", args: 1, multi: true, placeholder: "<protocol>", children: nil},
						// #8781: the IPv6 spelling of `protocol`. Declared for the same
						// reason `traffic-class` is declared here (#8773) — the compiler
						// has handled it since #3307, and the PACKED spelling is read
						// through this schema, so without the declaration
						// `from next-header tcp;` was dropped SILENTLY while the braced
						// spelling applied it. Advisory at commit.
						"next-header": {desc: "Match IPv6 next header (IPv6 spelling of protocol; accepted in family inet — advisory at commit)", args: 1, multi: true, placeholder: "<next-header>", children: nil},
						"dscp":        {desc: "Match DSCP value (name or number)", args: 1, multi: true, placeholder: "<dscp>", children: nil},
						// #8773: Junos spells this field `dscp` for IPv4; `traffic-class`
						// is the IPv6 spelling of the same six bits. It is declared here
						// because the compiler already ACCEPTS it in a braced `from`
						// block, and the packed spelling (`from traffic-class 0;`) is
						// read through this schema -- so without the declaration the two
						// spellings disagreed: braced accepted, packed dropped the
						// criterion silently. Accepted with a commit advisory rather than
						// refused, because refusing would break configurations that
						// commit today for a pure parity gain.
						"traffic-class":           {desc: "Match traffic class (IPv6 spelling of dscp; accepted in family inet — advisory at commit)", args: 1, multi: true, placeholder: "<traffic-class>", children: nil},
						"destination-port":        {desc: "Match destination port", args: 1, multi: true, groupReplace: true, placeholder: "<port>", children: nil},
						"source-port":             {desc: "Match source port", args: 1, multi: true, groupReplace: true, placeholder: "<port>", children: nil},
						"destination-port-except": {desc: "Match all destination ports EXCEPT these", args: 1, multi: true, groupReplace: true, placeholder: "<port>", children: nil},
						"source-port-except":      {desc: "Match all source ports EXCEPT these", args: 1, multi: true, groupReplace: true, placeholder: "<port>", children: nil},
						"icmp-type":               {desc: "Match ICMP type (numeric)", args: 1, multi: true, placeholder: "<type>", children: nil},
						"icmp-code":               {desc: "Match ICMP code (numeric)", args: 1, multi: true, placeholder: "<code>", children: nil},
						"tcp-flags":               {desc: "Match TCP flags", args: 1, multi: true, placeholder: "<flags>", children: nil},
						"is-fragment":             {desc: "Match fragmented packets", children: nil},
						"flexible-match-range": {desc: "Flexible packet field match", children: map[string]*schemaNode{
							"range": {desc: "Named flexible match range", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
								"match-start": {desc: "Match start point (only layer-3 supported)", args: 1, placeholder: "<start>", children: nil},
								"byte-offset": {desc: "Byte offset from match start", args: 1, placeholder: "<bytes>", children: nil},
								"bit-length":  {desc: "Match length in bits (default 32)", args: 1, placeholder: "<bits>", children: nil},
								"range":       {desc: "Match value and mask (0xVALUE[/0xMASK])", args: 1, placeholder: "<value>", children: nil},
								"match-value": {desc: "Value to match (0xVALUE[/0xMASK])", args: 1, placeholder: "<value>", children: nil},
								"match-mask":  {desc: "Mask applied to the match value (hex)", args: 1, placeholder: "<mask>", children: nil},
							}},
						}},
					}},
					// issue 8939: packedStatements so a run written on ONE line --
					// `then count c1 dscp af11;` -- splits into siblings instead
					// of landing whole on this node's Keys, where the compiler
					// reads the first statement and drops the rest.
					//
					// Declared on the NODE, not on a (container, head) pair, so
					// the #8921 collision hazard does not apply: there are 14
					// containers named `then` and this reaches only the two
					// filter-term ones. See docs/config-schema.md.
					"then": {desc: "Actions for matching packets", packedStatements: true, children: map[string]*schemaNode{
						"accept": {desc: "Accept the packet", children: nil},
						// #8807-followup: the compiler reads a message type after `reject`
						// (compiler_firewall.go: child.Keys[1] for the packed form, a
						// CHILD node for `reject { tcp-reset; }`) while the schema
						// declared none, so `then reject <TAB>` offered nothing and an
						// operator could not discover the types through `?` help.
						// Declared as CHILDREN rather than args because the compiler
						// already reads both shapes and children is the one completion
						// can enumerate. Bare `then reject;` stays valid — these are
						// optional children, not a required argument.
						"reject": {desc: "Reject the packet", children: map[string]*schemaNode{
							"administratively-prohibited": {desc: "ICMP/TCP reject message type", children: nil},
							"bad-host-tos":                {desc: "ICMP/TCP reject message type", children: nil},
							"bad-network-tos":             {desc: "ICMP/TCP reject message type", children: nil},
							"host-prohibited":             {desc: "ICMP/TCP reject message type", children: nil},
							"host-unreachable":            {desc: "ICMP/TCP reject message type", children: nil},
							"network-prohibited":          {desc: "ICMP/TCP reject message type", children: nil},
							"network-unreachable":         {desc: "ICMP/TCP reject message type", children: nil},
							"port-unreachable":            {desc: "ICMP/TCP reject message type", children: nil},
							"precedence-cutoff":           {desc: "ICMP/TCP reject message type", children: nil},
							"precedence-violation":        {desc: "ICMP/TCP reject message type", children: nil},
							"protocol-unreachable":        {desc: "ICMP/TCP reject message type", children: nil},
							"source-host-isolated":        {desc: "ICMP/TCP reject message type", children: nil},
							"source-route-failed":         {desc: "ICMP/TCP reject message type", children: nil},
							"tcp-reset":                   {desc: "ICMP/TCP reject message type", children: nil},
						}},
						"discard":          {desc: "Discard the packet", children: nil},
						"log":              {desc: "Log matching packets", children: nil},
						"syslog":           {desc: "Log matching packets to the system log", children: nil},
						"routing-instance": {desc: "Forward via routing instance (filter-based forwarding)", args: 1, placeholder: "<instance>", children: nil},
						"count":            {desc: "Count matching packets in a named counter", args: 1, placeholder: "<counter-name>", children: nil},
						// #1319 PR 3 tree-based cross-ref: the dataplane
						// resolves this name against the CONFIGURED
						// forwarding classes and silently defaults the
						// queue on a miss (see validateForwardingClassRef
						// for the runtime citations and the best-effort
						// special case).
						"forwarding-class": {
							desc:          "Assign forwarding class",
							args:          1,
							valueType:     ValueIdentifier,
							valueDesc:     "Forwarding class to assign (must be defined under class-of-service forwarding-classes, or best-effort)",
							valueExamples: []string{"best-effort"},
							treeValidator: validateForwardingClassRef,
							children:      nil,
						},
						"loss-priority": {desc: "Set packet loss priority (low|medium-low|medium-high|high)", args: 1, placeholder: "<priority>", children: nil},
						"dscp":          {desc: "Rewrite the DSCP value (name or number)", args: 1, placeholder: "<dscp>", children: nil},
						"traffic-class": {desc: "Rewrite the traffic class (DSCP name or number)", args: 1, placeholder: "<traffic-class>", children: nil},
						"policer":       {desc: "Apply a policer to matching traffic", args: 1, placeholder: "<policer-name>", children: nil},
					}},
				}},
			}},
		}},
		"inet6": {desc: "IPv6 firewall filters", children: map[string]*schemaNode{
			"filter": {desc: "Firewall filter", args: 1, placeholder: "<filter-name>", children: map[string]*schemaNode{
				// #4316 (fable-167 F-3a): interface-specific instantiates a
				// per-interface counter/policer instance in Junos. xpf accepts
				// it (completion + ? help) but keeps a single shared counter;
				// a commit advisory (compiler_validate_warn.go) surfaces the
				// divergence.
				"interface-specific": {desc: "Instantiate per-interface counter/policer instances (accepted; xpf keeps a single shared counter — advisory at commit)", children: nil},
				"term": {desc: "Filter term", args: 1, placeholder: "<term-name>", children: map[string]*schemaNode{
					"from": {desc: "Match conditions", children: map[string]*schemaNode{
						"source-address":          {desc: "Match source address", args: 1, multi: true, placeholder: "<address>", children: nil},
						"destination-address":     {desc: "Match destination address", args: 1, multi: true, placeholder: "<address>", children: nil},
						"source-prefix-list":      {desc: "Match source addresses from a prefix list", args: 1, multi: true, placeholder: "<prefix-list>", children: nil},
						"destination-prefix-list": {desc: "Match destination addresses from a prefix list", args: 1, multi: true, placeholder: "<prefix-list>", children: nil},
						"protocol":                {desc: "Match IP protocol (IPv4 spelling of next-header; accepted in family inet6 — advisory at commit)", args: 1, multi: true, placeholder: "<protocol>", children: nil},
						// #8781: the Junos spelling for IPv6, and the one that was
						// SILENTLY DROPPED in the packed form — a correctly-authored
						// IPv6 term lost its protocol match and therefore matched every
						// protocol. This is the defect #8781 exists for; the family-inet
						// declaration above is its cross-family counterpart.
						"next-header":   {desc: "Match IPv6 next header", args: 1, multi: true, placeholder: "<next-header>", children: nil},
						"traffic-class": {desc: "Match traffic class (DSCP name or number)", args: 1, multi: true, placeholder: "<traffic-class>", children: nil},
						// #8773: the IPv4 spelling of the same six bits, declared for the
						// same reason `traffic-class` is declared under family inet --
						// see the note there. Accepted with a commit advisory.
						"dscp":                    {desc: "Match DSCP value (IPv4 spelling of traffic-class; accepted in family inet6 — advisory at commit)", args: 1, multi: true, placeholder: "<dscp>", children: nil},
						"destination-port":        {desc: "Match destination port", args: 1, multi: true, groupReplace: true, placeholder: "<port>", children: nil},
						"source-port":             {desc: "Match source port", args: 1, multi: true, groupReplace: true, placeholder: "<port>", children: nil},
						"destination-port-except": {desc: "Match all destination ports EXCEPT these", args: 1, multi: true, groupReplace: true, placeholder: "<port>", children: nil},
						"source-port-except":      {desc: "Match all source ports EXCEPT these", args: 1, multi: true, groupReplace: true, placeholder: "<port>", children: nil},
						"icmp-type":               {desc: "Match ICMP type (numeric)", args: 1, multi: true, placeholder: "<type>", children: nil},
						"icmp-code":               {desc: "Match ICMP code (numeric)", args: 1, multi: true, placeholder: "<code>", children: nil},
						"tcp-flags":               {desc: "Match TCP flags", args: 1, multi: true, placeholder: "<flags>", children: nil},
						"is-fragment":             {desc: "Match fragmented packets", children: nil},
						"flexible-match-range": {desc: "Flexible packet field match", children: map[string]*schemaNode{
							"range": {desc: "Named flexible match range", args: 1, placeholder: "<name>", children: map[string]*schemaNode{
								"match-start": {desc: "Match start point (only layer-3 supported)", args: 1, placeholder: "<start>", children: nil},
								"byte-offset": {desc: "Byte offset from match start", args: 1, placeholder: "<bytes>", children: nil},
								"bit-length":  {desc: "Match length in bits (default 32)", args: 1, placeholder: "<bits>", children: nil},
								"range":       {desc: "Match value and mask (0xVALUE[/0xMASK])", args: 1, placeholder: "<value>", children: nil},
								"match-value": {desc: "Value to match (0xVALUE[/0xMASK])", args: 1, placeholder: "<value>", children: nil},
								"match-mask":  {desc: "Mask applied to the match value (hex)", args: 1, placeholder: "<mask>", children: nil},
							}},
						}},
					}},
					// issue 8939: packedStatements so a run written on ONE line --
					// `then count c1 dscp af11;` -- splits into siblings instead
					// of landing whole on this node's Keys, where the compiler
					// reads the first statement and drops the rest.
					//
					// Declared on the NODE, not on a (container, head) pair, so
					// the #8921 collision hazard does not apply: there are 14
					// containers named `then` and this reaches only the two
					// filter-term ones. See docs/config-schema.md.
					"then": {desc: "Actions for matching packets", packedStatements: true, children: map[string]*schemaNode{
						"accept": {desc: "Accept the packet", children: nil},
						// #8807-followup: the compiler reads a message type after `reject`
						// (compiler_firewall.go: child.Keys[1] for the packed form, a
						// CHILD node for `reject { tcp-reset; }`) while the schema
						// declared none, so `then reject <TAB>` offered nothing and an
						// operator could not discover the types through `?` help.
						// Declared as CHILDREN rather than args because the compiler
						// already reads both shapes and children is the one completion
						// can enumerate. Bare `then reject;` stays valid — these are
						// optional children, not a required argument.
						"reject": {desc: "Reject the packet", children: map[string]*schemaNode{
							"administratively-prohibited": {desc: "ICMP/TCP reject message type", children: nil},
							"bad-host-tos":                {desc: "ICMP/TCP reject message type", children: nil},
							"bad-network-tos":             {desc: "ICMP/TCP reject message type", children: nil},
							"host-prohibited":             {desc: "ICMP/TCP reject message type", children: nil},
							"host-unreachable":            {desc: "ICMP/TCP reject message type", children: nil},
							"network-prohibited":          {desc: "ICMP/TCP reject message type", children: nil},
							"network-unreachable":         {desc: "ICMP/TCP reject message type", children: nil},
							"port-unreachable":            {desc: "ICMP/TCP reject message type", children: nil},
							"precedence-cutoff":           {desc: "ICMP/TCP reject message type", children: nil},
							"precedence-violation":        {desc: "ICMP/TCP reject message type", children: nil},
							"protocol-unreachable":        {desc: "ICMP/TCP reject message type", children: nil},
							"source-host-isolated":        {desc: "ICMP/TCP reject message type", children: nil},
							"source-route-failed":         {desc: "ICMP/TCP reject message type", children: nil},
							"tcp-reset":                   {desc: "ICMP/TCP reject message type", children: nil},
						}},
						"discard":          {desc: "Discard the packet", children: nil},
						"log":              {desc: "Log matching packets", children: nil},
						"syslog":           {desc: "Log matching packets to the system log", children: nil},
						"routing-instance": {desc: "Forward via routing instance (filter-based forwarding)", args: 1, placeholder: "<instance>", children: nil},
						"count":            {desc: "Count matching packets in a named counter", args: 1, placeholder: "<counter-name>", children: nil},
						// #1319 PR 3 tree-based cross-ref: the dataplane
						// resolves this name against the CONFIGURED
						// forwarding classes and silently defaults the
						// queue on a miss (see validateForwardingClassRef
						// for the runtime citations and the best-effort
						// special case).
						"forwarding-class": {
							desc:          "Assign forwarding class",
							args:          1,
							valueType:     ValueIdentifier,
							valueDesc:     "Forwarding class to assign (must be defined under class-of-service forwarding-classes, or best-effort)",
							valueExamples: []string{"best-effort"},
							treeValidator: validateForwardingClassRef,
							children:      nil,
						},
						"loss-priority": {desc: "Set packet loss priority (low|medium-low|medium-high|high)", args: 1, placeholder: "<priority>", children: nil},
						"dscp":          {desc: "Rewrite the DSCP value (name or number)", args: 1, placeholder: "<dscp>", children: nil},
						"traffic-class": {desc: "Rewrite the traffic class (DSCP name or number)", args: 1, placeholder: "<traffic-class>", children: nil},
						"policer":       {desc: "Apply a policer to matching traffic", args: 1, placeholder: "<policer-name>", children: nil},
					}},
				}},
			}},
		}},
	}},
}}
