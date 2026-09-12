package config

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	fairnesscontract "github.com/psaab/xpf/pkg/fairness"
)

// numericCodePointRangeError marks a numeric DSCP/PCP code-point token that
// fell outside its valid domain (DSCP 0..63, PCP 0..7). It is a distinct error
// type so the tolerant load / peer-sync path (opts.lenientCoSNumericCodePoint)
// can downgrade JUST this class of finding to a warning while every other
// class-of-service compile error stays a hard reject.
//
// #2447 made an out-of-range numeric code-point a hard commit reject (before
// that it was silently dropped at the Go layer and the dataplane masked it —
// dscp&0x3f / pcp.min(7) — onto a DIFFERENT traffic class). #4953 keeps that
// reject STRICT at commit / commit-check but LENIENT on load / peer-sync so a
// config an older binary persisted (or a peer authored) still BOOTS (#1960
// no-brick): the leniently-loaded entry is dropped, exactly the pre-#2447
// fail-safe, and the operator's next strict commit rejects it loudly.
type numericCodePointRangeError struct{ msg string }

func (e *numericCodePointRangeError) Error() string { return e.msg }

// newCodePointRangeError builds a numericCodePointRangeError with a formatted,
// operator-facing message (the message text is unchanged from the #2447 gate;
// only the concrete error type is now distinguishable via errors.As).
func newCodePointRangeError(format string, args ...any) error {
	return &numericCodePointRangeError{msg: fmt.Sprintf(format, args...)}
}

// isNumericCodePointRangeError reports whether err (or anything it wraps) is a
// numericCodePointRangeError — the tolerant-path downgrade predicate.
func isNumericCodePointRangeError(err error) bool {
	var e *numericCodePointRangeError
	return errors.As(err, &e)
}

// unknownCodePointTokenError marks a class-of-service code-point token that is
// neither numeric nor a known symbolic DSCP alias — a typo such as `af99` or
// `foo`, or any non-numeric spelling on the PCP side (802.1p has no aliases)
// (#5194 A3-b2-F12). Before #5194 such a token was silently dropped in BOTH the
// strict and tolerant paths, inconsistent with the numeric out-of-range path
// (#2447) which rejects at commit and warns on tolerant load. This type gives
// the typo the SAME treatment: STRICT-reject at commit / commit-check, LENIENT
// warn-and-drop on load / peer-sync (opts.lenientCoSNumericCodePoint) so a
// config an older/looser binary persisted still boots and the operator's next
// strict commit rejects the typo loudly.
type unknownCodePointTokenError struct{ msg string }

func (e *unknownCodePointTokenError) Error() string { return e.msg }

func newUnknownCodePointTokenError(format string, args ...any) error {
	return &unknownCodePointTokenError{msg: fmt.Sprintf(format, args...)}
}

// isDowngradableCoSCodePointError reports whether err is one of the
// class-of-service code-point findings the tolerant path downgrades to a
// warning: a numeric out-of-range value (#2447) OR an unknown/typo symbolic
// token (#5194 A3-b2-F12). Every other compile error stays a hard reject.
func isDowngradableCoSCodePointError(err error) bool {
	if isNumericCodePointRangeError(err) {
		return true
	}
	var e *unknownCodePointTokenError
	return errors.As(err, &e)
}

func compileClassOfService(node *Node, cos *ClassOfServiceConfig, opts compileOpts, warnings *[]string) error {
	if cos == nil {
		return nil
	}
	if cos.ForwardingClasses == nil {
		cos.ForwardingClasses = make(map[string]*CoSForwardingClass)
	}
	if cos.DSCPClassifiers == nil {
		cos.DSCPClassifiers = make(map[string]*CoSDSCPClassifier)
	}
	if cos.IEEE8021Classifiers == nil {
		cos.IEEE8021Classifiers = make(map[string]*CoSIEEE8021Classifier)
	}
	if cos.DSCPRewriteRules == nil {
		cos.DSCPRewriteRules = make(map[string]*CoSDSCPRewriteRule)
	}
	if cos.IEEE8021RewriteRules == nil {
		cos.IEEE8021RewriteRules = make(map[string]*CoSIEEE8021RewriteRule)
	}
	if cos.Schedulers == nil {
		cos.Schedulers = make(map[string]*CoSScheduler)
	}
	if cos.SchedulerMaps == nil {
		cos.SchedulerMaps = make(map[string]*CoSSchedulerMap)
	}
	if cos.Interfaces == nil {
		cos.Interfaces = make(map[string]*CoSInterface)
	}
	if cos.TrafficControlProfiles == nil {
		cos.TrafficControlProfiles = make(map[string]*CoSTrafficControlProfile)
	}
	if fcNode := node.FindChild("forwarding-classes"); fcNode != nil {
		// Enforce the FC ↔ queue bijection. Junos semantics give
		// each queue ID one forwarding class, and each FC one
		// queue — schedulers attach to an FC, so two FCs on one
		// queue give the queue two conflicting rate targets, and
		// one FC on two queues leaves classifier / scheduler-map
		// references ambiguous.
		//
		// The userspace dataplane's compile path
		// (`forwarding_build.rs`) iterates the scheduler-map and
		// creates ONE `CoSQueueConfig` per FC. Without this guard
		// either direction of a bijection violation produces
		// inconsistent runtime state that downstream code
		// silently disambiguates three different ways:
		//
		//   * `resolve_cos_queue_idx` returns the first match by
		//     queue_id, so packets for an ambiguous queue go to
		//     whichever duplicate the scheduler-map produced
		//     first.
		//   * The shared-queue lease derives its rate from a
		//     separate path, which can land on yet another value.
		//   * `show class-of-service interface` displays one
		//     entry's FC name alongside a different entry's rate
		//     — a debugger-hostile mismatch on live output.
		//
		// Both directions are rejected:
		//
		//   * queue N → two different FCs (`queue 5 iperf-b`
		//     followed by `queue 5 iperf-c`) surfaced during the
		//     #785 investigation; the scheduler-map would attach
		//     both schedulers to queue 5 at conflicting rates.
		//   * FC X → two different queue numbers (`queue 4 iperf-a`
		//     followed by `queue 5 iperf-a`) — the second silently
		//     overwrote `ForwardingClasses[X].Queue`, leaving any
		//     `classifier`/`scheduler-map` reference to FC X
		//     resolving to the wrong queue at runtime.
		//     (Flagged by Codex review of PR #787; can arise from
		//     `apply-groups` / `${node}` expansion producing
		//     unintended duplicate entries in a user's config.)
		//
		// Idempotent reassignment of the SAME FC to the SAME
		// queue is explicitly allowed so `load merge` /
		// `load override` paths that re-apply the same line
		// remain clean.
		queueOwner := make(map[int]string) // queue_id → FC name
		fcQueue := make(map[string]int)    // FC name → queue_id
		for _, queueNode := range fcNode.FindChildren("queue") {
			if len(queueNode.Keys) < 3 {
				continue
			}
			name := queueNode.Keys[2]
			rawQueue := queueNode.Keys[1]
			queue, err := strconv.Atoi(rawQueue)
			if err != nil {
				// #5973: a non-numeric or integer-overflowing
				// forwarding-class queue token was previously
				// SILENTLY DROPPED here (strconv.Atoi -> continue):
				// the forwarding-class -> queue mapping never bound
				// and CompileConfig accepted the stanza with no
				// effect — the same mis-bind / fail-open class
				// #5963/#5933 closed on adjacent CoS slots, and
				// inconsistent with the sibling fairness
				// rss-expectation queue parse (which hard-rejects
				// `err != nil || queue < 0 || queue > 255`). This is
				// the ONE malformed case the downstream #4594
				// forwarding-class queue-range gate
				// (validateClassOfServiceForwardingClassQueueStrict)
				// can never see: a strconv error means the FC never
				// binds, so there is no Queue int left for the range
				// gate to check. A PARSEABLE but out-of-range value
				// (e.g. 999) or a negative one still flows through to
				// that downstream gate, which already rejects it
				// (strict) / warns (lenient). Reject at commit here;
				// downgrade to a warning on the tolerant load /
				// peer-sync path (opts.lenientCoSForwardingClassQueue,
				// the SAME #4594 flag that downstream gate uses) so an
				// already-persisted or peer-synced config an older
				// binary accepted still boots — #1960 no-brick; the
				// malformed queue was inert then too (the FC never
				// bound).
				detail := fmt.Errorf(
					"class-of-service forwarding-classes forwarding-class %q queue %q: expected queue 0..255: %w",
					name, rawQueue, err)
				if opts.lenientCoSForwardingClassQueue {
					if warnings != nil {
						*warnings = append(*warnings, fmt.Sprintf(
							"class-of-service forwarding-class queue (downgraded to warning on tolerant path): %v", detail))
					}
					continue
				}
				return detail
			}
			if existing, claimed := queueOwner[queue]; claimed && existing != name {
				return fmt.Errorf(
					"class-of-service forwarding-classes queue %d: "+
						"forwarding-class %q conflicts with %q "+
						"(a queue can only be owned by one "+
						"forwarding-class; schedulers attach to an "+
						"FC, so two FCs on one queue give the queue "+
						"two conflicting scheduler rates)",
					queue, name, existing,
				)
			}
			if existingQueue, claimed := fcQueue[name]; claimed && existingQueue != queue {
				return fmt.Errorf(
					"class-of-service forwarding-classes "+
						"forwarding-class %q: queue %d conflicts with "+
						"queue %d (an FC can only be assigned to one "+
						"queue; classifier and scheduler-map "+
						"references to %q would otherwise resolve to "+
						"different queues depending on evaluation order)",
					name, queue, existingQueue, name,
				)
			}
			queueOwner[queue] = name
			fcQueue[name] = queue
			cos.ForwardingClasses[name] = &CoSForwardingClass{
				Name:  name,
				Queue: queue,
			}
		}
	}

	if classifiersNode := node.FindChild("classifiers"); classifiersNode != nil {
		for _, inst := range namedInstances(classifiersNode.FindChildren("dscp")) {
			classifier := &CoSDSCPClassifier{Name: inst.name}
			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
				className := ""
				if len(fcNode.Keys) >= 2 {
					className = fcNode.Keys[1]
				}
				if className == "" {
					continue
				}
				for _, lpNode := range fcNode.FindChildren("loss-priority") {
					lossPriority := ""
					if len(lpNode.Keys) >= 2 {
						lossPriority = lpNode.Keys[1]
					}
					if lossPriority == "" {
						lossPriority = nodeVal(lpNode)
					}
					codePoints, err := collectCoSDSCPCodePoints(lpNode)
					if err != nil {
						if opts.lenientCoSNumericCodePoint && isDowngradableCoSCodePointError(err) {
							if warnings != nil {
								*warnings = append(*warnings, fmt.Sprintf(
									"class-of-service classifiers dscp %q (downgraded to warning on tolerant path): %v",
									classifier.Name, err))
							}
							continue
						}
						return fmt.Errorf("class-of-service classifiers dscp %q: %w", classifier.Name, err)
					}
					if len(codePoints) == 0 {
						continue
					}
					classifier.Entries = append(classifier.Entries, &CoSDSCPClassifierEntry{
						ForwardingClass: className,
						LossPriority:    lossPriority,
						DSCPValues:      codePoints,
					})
				}
			}
			if len(classifier.Entries) > 0 {
				cos.DSCPClassifiers[classifier.Name] = classifier
			}
		}
		for _, inst := range namedInstances(classifiersNode.FindChildren("ieee-802.1")) {
			classifier := &CoSIEEE8021Classifier{Name: inst.name}
			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
				className := ""
				if len(fcNode.Keys) >= 2 {
					className = fcNode.Keys[1]
				}
				if className == "" {
					continue
				}
				for _, lpNode := range fcNode.FindChildren("loss-priority") {
					lossPriority := ""
					if len(lpNode.Keys) >= 2 {
						lossPriority = lpNode.Keys[1]
					}
					if lossPriority == "" {
						lossPriority = nodeVal(lpNode)
					}
					codePoints, err := collectCoS8021CodePoints(lpNode)
					if err != nil {
						if opts.lenientCoSNumericCodePoint && isDowngradableCoSCodePointError(err) {
							if warnings != nil {
								*warnings = append(*warnings, fmt.Sprintf(
									"class-of-service classifiers ieee-802.1 %q (downgraded to warning on tolerant path): %v",
									classifier.Name, err))
							}
							continue
						}
						return fmt.Errorf("class-of-service classifiers ieee-802.1 %q: %w", classifier.Name, err)
					}
					if len(codePoints) == 0 {
						continue
					}
					classifier.Entries = append(classifier.Entries, &CoSIEEE8021ClassifierEntry{
						ForwardingClass: className,
						LossPriority:    lossPriority,
						CodePoints:      codePoints,
					})
				}
			}
			if len(classifier.Entries) > 0 {
				cos.IEEE8021Classifiers[classifier.Name] = classifier
			}
		}
		// #6847: inet-precedence classifiers are now COMPILED and enforced.
		// #4316 recorded only their names (for the accepted-but-inert
		// advisory) because nothing consumed the map and the unit schema had
		// no binding site. The name list is still populated for the
		// undefined-reference check; the entries drive the dataplane.
		for _, inst := range namedInstances(classifiersNode.FindChildren("inet-precedence")) {
			cos.INetPrecedenceClassifiers = append(cos.INetPrecedenceClassifiers, inst.name)
			classifier := &CoSINetPrecedenceClassifier{Name: inst.name}
			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
				className := ""
				if len(fcNode.Keys) >= 2 {
					className = fcNode.Keys[1]
				}
				if className == "" {
					continue
				}
				for _, lpNode := range fcNode.FindChildren("loss-priority") {
					lossPriority := ""
					if len(lpNode.Keys) >= 2 {
						lossPriority = lpNode.Keys[1]
					}
					if lossPriority == "" {
						lossPriority = nodeVal(lpNode)
					}
					codePoints, err := collectCoSINetPrecedenceCodePoints(lpNode)
					if err != nil {
						if opts.lenientCoSNumericCodePoint && isDowngradableCoSCodePointError(err) {
							if warnings != nil {
								*warnings = append(*warnings, fmt.Sprintf(
									"class-of-service classifiers inet-precedence %q (downgraded to warning on tolerant path): %v",
									classifier.Name, err))
							}
							continue
						}
						return fmt.Errorf("class-of-service classifiers inet-precedence %q: %w", classifier.Name, err)
					}
					if len(codePoints) == 0 {
						continue
					}
					classifier.Entries = append(classifier.Entries, &CoSINetPrecedenceClassifierEntry{
						ForwardingClass: className,
						LossPriority:    lossPriority,
						Precedences:     codePoints,
					})
				}
			}
			if len(classifier.Entries) > 0 {
				if cos.INetPrecedenceClassifierDefs == nil {
					cos.INetPrecedenceClassifierDefs = make(map[string]*CoSINetPrecedenceClassifier)
				}
				cos.INetPrecedenceClassifierDefs[classifier.Name] = classifier
			}
		}
	}

	if rewriteRulesNode := node.FindChild("rewrite-rules"); rewriteRulesNode != nil {
		// #4316 (fable-167 F-3b): inet-precedence and exp rewrite-rules are
		// accepted but inert; record their names for the commit advisory.
		for _, inst := range namedInstances(rewriteRulesNode.FindChildren("inet-precedence")) {
			cos.INetPrecedenceRewriteRules = append(cos.INetPrecedenceRewriteRules, inst.name)
		}
		for _, inst := range namedInstances(rewriteRulesNode.FindChildren("exp")) {
			cos.EXPRewriteRules = append(cos.EXPRewriteRules, inst.name)
		}
		for _, inst := range namedInstances(rewriteRulesNode.FindChildren("dscp")) {
			rewriteRule := &CoSDSCPRewriteRule{Name: inst.name}
			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
				className := ""
				if len(fcNode.Keys) >= 2 {
					className = fcNode.Keys[1]
				}
				if className == "" {
					continue
				}
				for _, lpNode := range fcNode.FindChildren("loss-priority") {
					lossPriority := ""
					if len(lpNode.Keys) >= 2 {
						lossPriority = lpNode.Keys[1]
					}
					if lossPriority == "" {
						lossPriority = nodeVal(lpNode)
					}
					codePoint, ok, err := collectCoSDSCPRewriteCodePoint(lpNode)
					if err != nil {
						if opts.lenientCoSNumericCodePoint && isDowngradableCoSCodePointError(err) {
							if warnings != nil {
								*warnings = append(*warnings, fmt.Sprintf(
									"class-of-service rewrite-rules dscp %q (downgraded to warning on tolerant path): %v",
									rewriteRule.Name, err))
							}
							continue
						}
						return fmt.Errorf("class-of-service rewrite-rules dscp %q: %w", rewriteRule.Name, err)
					}
					if !ok {
						continue
					}
					rewriteRule.Entries = append(rewriteRule.Entries, &CoSDSCPRewriteRuleEntry{
						ForwardingClass: className,
						LossPriority:    lossPriority,
						DSCPValue:       codePoint,
					})
				}
			}
			if len(rewriteRule.Entries) > 0 {
				cos.DSCPRewriteRules[rewriteRule.Name] = rewriteRule
			}
		}
		// #4228 Gap 4: ieee-802.1 (PCP) rewrite-rules. Fully modeled (mirror of
		// the dscp rewrite loop, PCP domain 0..7) so the mapping is validated at
		// commit, but accepted-but-inert — the dataplane rewrites dscp on egress
		// only (commit advisory).
		for _, inst := range namedInstances(rewriteRulesNode.FindChildren("ieee-802.1")) {
			rewriteRule := &CoSIEEE8021RewriteRule{Name: inst.name}
			for _, fcNode := range inst.node.FindChildren("forwarding-class") {
				className := ""
				if len(fcNode.Keys) >= 2 {
					className = fcNode.Keys[1]
				}
				if className == "" {
					continue
				}
				for _, lpNode := range fcNode.FindChildren("loss-priority") {
					lossPriority := ""
					if len(lpNode.Keys) >= 2 {
						lossPriority = lpNode.Keys[1]
					}
					if lossPriority == "" {
						lossPriority = nodeVal(lpNode)
					}
					codePoint, ok, err := collectCoS8021RewriteCodePoint(lpNode)
					if err != nil {
						if opts.lenientCoSNumericCodePoint && isDowngradableCoSCodePointError(err) {
							if warnings != nil {
								*warnings = append(*warnings, fmt.Sprintf(
									"class-of-service rewrite-rules ieee-802.1 %q (downgraded to warning on tolerant path): %v",
									rewriteRule.Name, err))
							}
							continue
						}
						return fmt.Errorf("class-of-service rewrite-rules ieee-802.1 %q: %w", rewriteRule.Name, err)
					}
					if !ok {
						continue
					}
					rewriteRule.Entries = append(rewriteRule.Entries, &CoSIEEE8021RewriteRuleEntry{
						ForwardingClass: className,
						LossPriority:    lossPriority,
						PCPValue:        codePoint,
					})
				}
			}
			if len(rewriteRule.Entries) > 0 {
				cos.IEEE8021RewriteRules[rewriteRule.Name] = rewriteRule
			}
		}
	}

	// #8436 FIND-OR-CREATE, the shared rule for the three class-of-service
	// containers below. A second hierarchical block used to construct a fresh
	// object and overwrite the first under the same map key, so everything the
	// first block set was silently discarded — while the flat-set spelling
	// merged, which is the conservation property the census exists for.
	//
	// THE DIFFERENT-NAMES CASE IS PRESERVED BY CONSTRUCTION: the lookup is
	// keyed on the authored name, so two blocks naming different objects occupy
	// different keys and both survive. Only two blocks naming the SAME one
	// merge — the case the census builds, and the only one that was ever wrong.
	// Each container has a paired different-names control in
	// cos_isis_block_conservation_8436_test.go; without it an over-broad merge
	// would pass every merge cell.
	for _, inst := range namedInstances(node.FindChildren("schedulers")) {
		sched := cos.Schedulers[inst.name]
		if sched == nil {
			sched = &CoSScheduler{Name: inst.name}
		}
		for _, child := range inst.node.Children {
			switch child.Name() {
			case "transmit-rate":
				rate, percent, remainder, exact := parseCoSTransmitRate(child)
				if rate > 0 {
					sched.TransmitRateBytes = rate
				}
				if percent > 0 {
					sched.TransmitRatePercent = percent
				}
				if remainder {
					sched.TransmitRateRemainder = true
				}
				sched.TransmitRateExact = sched.TransmitRateExact || exact
			case "priority":
				sched.Priority = nodeVal(child)
			case "buffer-size":
				// #4228 Gap 2 follow-up: `buffer-size temporal <us>` groups the
				// keyword + value onto the tail (gatherLeafTailTokens flattens the
				// flat-set container+child), so detect it before the byte/percent
				// path. temporal is accepted-but-inert — the microsecond value is
				// stored but not yet resolved to bytes (commit advisory).
				toks := gatherLeafTailTokens(child)
				if len(toks) >= 1 && toks[0] == "temporal" {
					if len(toks) >= 2 {
						if us, err := strconv.ParseUint(toks[1], 10, 64); err == nil && us > 0 {
							sched.BufferSizeTemporalUS = us
							sched.BufferSizeBytes = 0
							sched.BufferSizePercent = 0
						}
					}
				} else if v := nodeVal(child); v != "" {
					if percent, err := parsePercentWithSuffixStrict(v); err == nil {
						sched.BufferSizeBytes = 0
						sched.BufferSizePercent = percent
					} else {
						sched.BufferSizeBytes = parseBurstSizeLimit(v)
						sched.BufferSizePercent = 0
					}
				}
			case "surplus-sharing":
				// #915: leaf with no value; presence = true.
				sched.SurplusSharing = true
			case "equal-flow-enforcement":
				sched.EqualFlowEnforcement = true
			case "equal-flow-target-policy":
				// #1746: enum validated by the schema (set time) and
				// validateClassOfServiceStrict (commit time).
				sched.EqualFlowTargetPolicy = nodeVal(child)
			case "codel-target":
				// #1614 A3: value in milliseconds; store as
				// nanoseconds. Empty value = 0 = disabled.
				if v := nodeVal(child); v != "" {
					if ms, err := strconv.ParseUint(v, 10, 64); err == nil {
						sched.CodelTargetNS = ms * 1_000_000
					}
				}
			}
		}
		cos.Schedulers[sched.Name] = sched
	}

	// #4315 (fable-167 F-2): traffic-control-profiles. Each profile carries
	// the Junos hierarchical shaping knobs. The bounded ones (shaping-rate,
	// scheduler-map) are folded into the referencing interface unit by
	// resolveCoSTrafficControlProfiles; guaranteed-rate / delay-buffer-rate
	// are captured but currently inert (see CoSTrafficControlProfile).
	// #8436 find-or-create — see the schedulers loop above for the rule and for
	// why the different-names case is preserved.
	for _, inst := range namedInstances(node.FindChildren("traffic-control-profiles")) {
		// #8939: split a packed run before any lookup. This block asks
		// inst.node.FindChild(...) once per option, and `traffic-control-profiles
		// TCP delay-buffer-rate 100000 guaranteed-rate 200000 scheduler-map M`
		// is ONE child node carrying all three on its Keys — so the first
		// matched and the rest were dropped. A shaper missing its
		// guaranteed-rate or its scheduler-map does not fail; it shapes
		// differently from what the operator wrote.
		if expanded := expandFlatRun(inst.node.Children, cosTrafficControlProfileSchema8939()); len(expanded) != len(inst.node.Children) {
			clone := *inst.node
			clone.Children = expanded
			inst.node = &clone
		}
		tcp := cos.TrafficControlProfiles[inst.name]
		if tcp == nil {
			tcp = &CoSTrafficControlProfile{Name: inst.name}
		}
		// #4228 Gap 2: shaping-rate is an absolute bandwidth OR `percent <n>`.
		// Iterate ALL shaping-rate statements (not just FindChild's first): the
		// flat-set percent form (`shaping-rate percent 90`) lands as a SEPARATE
		// sibling node from an absolute `shaping-rate 1g`, so reading only the
		// first would be order-dependent AND would silently ignore a conflicting
		// second statement. Accumulating both fields lets
		// validateClassOfServiceStrict catch the bytes+percent conflict (mirrors
		// the transmit-rate per-child accumulation). Copilot #4320.
		for _, shapingNode := range inst.node.FindChildren("shaping-rate") {
			rate, percent := parseCoSShapingRate(shapingNode)
			if rate > 0 {
				tcp.ShapingRateBytes = rate
			}
			if percent > 0 {
				tcp.ShapingRatePercent = percent
			}
		}
		if grNode := inst.node.FindChild("guaranteed-rate"); grNode != nil {
			if v := nodeVal(grNode); v != "" {
				tcp.GuaranteedRateBytes = parseBandwidthLimit(v)
			}
		}
		if dbNode := inst.node.FindChild("delay-buffer-rate"); dbNode != nil {
			if v := nodeVal(dbNode); v != "" {
				tcp.DelayBufferRateBytes = parseBandwidthLimit(v)
			}
		}
		if smNode := inst.node.FindChild("scheduler-map"); smNode != nil {
			tcp.SchedulerMap = nodeVal(smNode)
		}
		cos.TrafficControlProfiles[tcp.Name] = tcp
	}

	for _, inst := range namedInstances(node.FindChildren("scheduler-maps")) {
		schedMap := &CoSSchedulerMap{
			Name:    inst.name,
			Entries: make(map[string]*CoSSchedulerMapEntry),
		}
		for _, child := range inst.node.Children {
			if child.Name() != "forwarding-class" || len(child.Keys) < 2 {
				continue
			}
			className := child.Keys[1]
			scheduler := ""
			if len(child.Keys) >= 4 && child.Keys[2] == "scheduler" {
				scheduler = child.Keys[3]
			} else if schedNode := child.FindChild("scheduler"); schedNode != nil {
				scheduler = nodeVal(schedNode)
			}
			schedMap.Entries[className] = &CoSSchedulerMapEntry{
				ForwardingClass: className,
				Scheduler:       scheduler,
			}
		}
		cos.SchedulerMaps[schedMap.Name] = schedMap
	}

	// #8436 find-or-create — see the schedulers loop above for the rule and for
	// why the different-names case is preserved.
	//
	// The per-unit map is reused too, not rebuilt: `unit 0` in the first
	// block and `unit 1` in the second are different keys and both stay,
	// and a repeated `unit N` takes the second block's body — the same
	// last-write-wins a single block already has for a repeated unit.
	for _, inst := range namedInstances(node.FindChildren("interfaces")) {
		iface := cos.Interfaces[inst.name]
		if iface == nil {
			iface = &CoSInterface{
				Name:  inst.name,
				Units: make(map[int]*CoSInterfaceUnit),
			}
		}
		// Interface-level (physical, no `unit`) binding. In Junos a
		// scheduler-map / shaping-rate / classifier / rewrite-rule bound
		// directly under `interfaces geX` applies to every logical unit on
		// the port. Read the same knobs from the interface node itself; the
		// per-unit `unit` children are separate nodes and are unaffected.
		// applyCoSInterfaceLevelBindings folds this into each configured
		// logical unit once the interface stanza is known (#4021).
		//
		// #8436: parse into the EXISTING interface-level unit, not a fresh one.
		// A fresh object carries only the SECOND block's leaves, so assigning it
		// wipes a `scheduler-map` the first block bound while the second bound
		// only a `shaping-rate` — the #8433 per-field wipe reached through a
		// container fix. Reuse is safe by construction:
		// parseCoSInterfaceUnitBody assigns only inside
		// `if node.FindChild(...) != nil` guards, so a block that never mentions
		// a leaf cannot reset it.
		level := iface.Level
		if level == nil {
			level = &CoSInterfaceUnit{Unit: -1}
		}
		parseCoSInterfaceUnitBody(inst.node, level)
		if coSInterfaceUnitHasBinding(level) {
			iface.Level = level
		}
		for _, unitNode := range inst.node.FindChildren("unit") {
			if len(unitNode.Keys) < 2 {
				continue
			}
			// #5963: the NESTED `class-of-service interfaces <if> unit <n>`
			// form (unit as a child node, distinct from the `.unit` suffix
			// references #5933 gated) previously SILENTLY DROPPED a malformed
			// unit here (strconv.Atoi -> continue): the shaper/classifier
			// never bound and CompileConfig accepted the stanza with no
			// effect — the same mis-bind / fail-open class #5829/#5933
			// closed. Route the identity through the canonical
			// CanonicalLogicalUnit normalizer (#5878) so a non-numeric /
			// negative / out-of-range unit is REJECTED at commit instead of
			// dropped. Strict on commit / commit-check (hard-reject); on the
			// tolerant load / peer-sync path (lenientInterfaceUnitRef, the
			// same flag the #5933 gate uses) downgrade to a cfg.Warnings
			// entry so an already-persisted or peer-synced config an older
			// binary accepted still boots — #1960 no-brick; the malformed
			// unit was inert then too (the shaper simply did not bind).
			unitID, _, err := CanonicalLogicalUnit(unitNode.Keys[1])
			if err != nil {
				if opts.lenientInterfaceUnitRef {
					if warnings != nil {
						*warnings = append(*warnings, fmt.Sprintf(
							"class-of-service interfaces %s unit %q (downgraded to warning on tolerant path): %v",
							iface.Name, unitNode.Keys[1], err))
					}
					continue
				}
				return fmt.Errorf("class-of-service interfaces %s unit %q: %w",
					iface.Name, unitNode.Keys[1], err)
			}
			// #8436: same find-or-create one level down — two blocks naming
			// `unit 0` merge their leaves instead of the second wiping the
			// first's; different units are different keys and both survive.
			unit := iface.Units[unitID]
			if unit == nil {
				unit = &CoSInterfaceUnit{Unit: unitID}
			}
			parseCoSInterfaceUnitBody(unitNode, unit)
			if coSInterfaceUnitHasBinding(unit) {
				iface.Units[unitID] = unit
			}
		}
		if len(iface.Units) > 0 || iface.Level != nil {
			cos.Interfaces[iface.Name] = iface
		}
	}

	if fairnessNode := node.FindChild("fairness"); fairnessNode != nil {
		if rssNode := fairnessNode.FindChild("rss-expectation"); rssNode != nil {
			seen := make(map[string]string)
			// #hb166 G-9: rss-expectation is keyed by the STABLE xpf
			// interface name (e.g. ge-0-0-2), not the transient kernel
			// ifindex. The name is resolved to the current ifindex at
			// evaluate time from the live status snapshot, so the
			// expectation survives NIC re-enumeration.
			for _, ifaceNode := range rssNode.FindChildren("interface") {
				if len(ifaceNode.Keys) < 2 {
					continue
				}
				ifaceName := ifaceNode.Keys[1]
				if ifaceName == "" {
					return fmt.Errorf("class-of-service fairness rss-expectation interface: expected non-empty interface name")
				}
				for _, queueNode := range ifaceNode.FindChildren("queue") {
					if len(queueNode.Keys) < 2 {
						continue
					}
					queue, err := strconv.Atoi(queueNode.Keys[1])
					if err != nil || queue < 0 || queue > 255 {
						return fmt.Errorf("class-of-service fairness rss-expectation interface %s queue %q: expected queue 0..255", ifaceName, queueNode.Keys[1])
					}
					expr, err := collectCoSFairnessRSSExpectation(queueNode)
					if err != nil {
						return fmt.Errorf("class-of-service fairness rss-expectation interface %s queue %d: %w", ifaceName, queue, err)
					}
					parsed, err := fairnesscontract.ParseRSSExpectation(expr)
					if err != nil {
						return fmt.Errorf("class-of-service fairness rss-expectation interface %s queue %d: %w", ifaceName, queue, err)
					}
					key := fmt.Sprintf("%s/%d", ifaceName, queue)
					canonical := parsed.Canonical()
					if existing, ok := seen[key]; ok {
						if existing == canonical {
							continue
						}
						return fmt.Errorf("class-of-service fairness rss-expectation interface %s queue %d: duplicate expectation %q conflicts with %q", ifaceName, queue, canonical, existing)
					}
					seen[key] = canonical
					cos.FairnessExpectations = append(cos.FairnessExpectations, &CoSFairnessExpectation{
						Interface:      ifaceName,
						QueueID:        uint8(queue),
						RSSExpectation: canonical,
					})
				}
			}
		}
	}

	return nil
}

// parseCoSInterfaceUnitBody reads the CoS binding knobs (shaping-rate +
// burst-size, scheduler-map, classifiers, rewrite-rules, and the #1614
// oversubscription / priority-low-min-share scheduler knobs) from the
// direct children of node into unit. node may be a `unit N` node or, for
// an interface-level binding, the `interfaces geX` node itself (#4021) —
// both expose the same knob children, and the interface node's `unit`
// children are separate nodes that are not read here.
func parseCoSInterfaceUnitBody(node *Node, unit *CoSInterfaceUnit) {
	node = expandResolvingRun9792(node, cosInterfaceSchema9792()) // #9792: expand a lenient-path packed run (#9235).
	if shapingNode := node.FindChild("shaping-rate"); shapingNode != nil {
		if v := nodeVal(shapingNode); v != "" {
			unit.ShapingRateBytes = parseBandwidthLimit(v)
		}
		if burstNode := shapingNode.FindChild("burst-size"); burstNode != nil {
			if v := nodeVal(burstNode); v != "" {
				unit.BurstSizeBytes = parseBurstSizeLimit(v)
			}
		}
	}
	if schedMapNode := node.FindChild("scheduler-map"); schedMapNode != nil {
		unit.SchedulerMap = nodeVal(schedMapNode)
	}
	if tcpNode := node.FindChild("output-traffic-control-profile"); tcpNode != nil {
		unit.OutputTrafficControlProfile = nodeVal(tcpNode)
	}
	if classifiersNode := node.FindChild("classifiers"); classifiersNode != nil {
		// issue 8939: the flat-set spelling nests the bindings into a chain, so
		// FindChild sees only the first. Flatten before reading.
		classifiersNode = flattenChainedNode(classifiersNode, cosBindingSchema8939("classifiers"))
		if dscpNode := classifiersNode.FindChild("dscp"); dscpNode != nil {
			unit.DSCPClassifier = nodeVal(dscpNode)
		}
		if ieeeNode := classifiersNode.FindChild("ieee-802.1"); ieeeNode != nil {
			unit.IEEE8021Classifier = nodeVal(ieeeNode)
		}
		// #6847: the inet-precedence unit binding — before this there was no
		// binding site at all, so the classifier was definable but not
		// bindable. A conflict with `dscp` on the same unit is rejected by
		// validateCoSUnitClassifierConflict rather than resolved here; the
		// compiler records what the operator wrote.
		if precNode := classifiersNode.FindChild("inet-precedence"); precNode != nil {
			unit.INetPrecedenceClassifier = nodeVal(precNode)
		}
	}
	if rewriteRulesNode := node.FindChild("rewrite-rules"); rewriteRulesNode != nil {
		rewriteRulesNode = flattenChainedNode(rewriteRulesNode, cosBindingSchema8939("rewrite-rules"))
		if dscpNode := rewriteRulesNode.FindChild("dscp"); dscpNode != nil {
			unit.DSCPRewriteRule = nodeVal(dscpNode)
		}
		if ieeeNode := rewriteRulesNode.FindChild("ieee-802.1"); ieeeNode != nil {
			unit.IEEE8021RewriteRule = nodeVal(ieeeNode)
		}
	}
	// #1614 A1: oversubscription-policy { guarantee-rate <X> | proportional }
	//
	// Junos set syntax `set ... oversubscription-policy guarantee-rate 0.7`
	// produces a flat-keys leaf node whose Keys are
	// ["oversubscription-policy", "guarantee-rate", "0.7"]. The
	// hierarchical text shape produces a parent node with a
	// child sub-node for "guarantee-rate" carrying "0.7" as a
	// trailing key or leaf value. Handle both forms.
	if oversubNode := node.FindChild("oversubscription-policy"); oversubNode != nil {
		// Flat-keys path: Keys = [policy_name, value, ...] all on
		// the parent node.
		if len(oversubNode.Keys) >= 2 && oversubNode.Keys[1] == "guarantee-rate" {
			unit.OversubscriptionPolicy = "guarantee-rate"
			if len(oversubNode.Keys) >= 3 {
				if f, err := strconv.ParseFloat(oversubNode.Keys[2], 64); err == nil {
					if f < 0 {
						f = 0
					} else if f > 1 {
						f = 1
					}
					unit.OversubscriptionGuaranteeFraction = f
				}
			}
		} else if len(oversubNode.Keys) >= 2 && oversubNode.Keys[1] == "proportional" {
			unit.OversubscriptionPolicy = "proportional"
		} else if grNode := oversubNode.FindChild("guarantee-rate"); grNode != nil {
			// Hierarchical child-node path.
			unit.OversubscriptionPolicy = "guarantee-rate"
			var raw string
			if v := nodeVal(grNode); v != "" {
				raw = v
			} else if len(grNode.Keys) >= 2 {
				raw = grNode.Keys[len(grNode.Keys)-1]
			}
			if raw != "" {
				if f, err := strconv.ParseFloat(raw, 64); err == nil {
					if f < 0 {
						f = 0
					} else if f > 1 {
						f = 1
					}
					unit.OversubscriptionGuaranteeFraction = f
				}
			}
		} else if oversubNode.FindChild("proportional") != nil {
			unit.OversubscriptionPolicy = "proportional"
		} else if v := nodeVal(oversubNode); v != "" {
			unit.OversubscriptionPolicy = v
		}
	}
	// #1614 A2: priority-low-min-share <bps>
	if minShareNode := node.FindChild("priority-low-min-share"); minShareNode != nil {
		if v := nodeVal(minShareNode); v != "" {
			unit.PriorityLowMinShareBytes = parseBandwidthLimit(v)
		}
	}
}

// coSInterfaceUnitHasBinding reports whether any CoS knob is set on unit.
// An all-zero unit carries no binding and is dropped so it never reaches
// the dataplane snapshot.
func coSInterfaceUnitHasBinding(unit *CoSInterfaceUnit) bool {
	if unit == nil {
		return false
	}
	// #6847: INetPrecedenceClassifier belongs in this set. A unit that binds
	// ONLY an inet-precedence classifier has a real binding; omitting it here
	// made parseCoSInterfaceUnitBody record the binding and then DISCARD the
	// whole unit (and, if it was the interface's only unit, the CoS interface
	// with it), so nothing reached the snapshot and the dataplane arm was
	// unreachable for the plain single-classifier config.
	return unit.ShapingRateBytes > 0 || unit.BurstSizeBytes > 0 || unit.SchedulerMap != "" ||
		unit.DSCPClassifier != "" || unit.IEEE8021Classifier != "" ||
		unit.INetPrecedenceClassifier != "" ||
		unit.DSCPRewriteRule != "" || unit.IEEE8021RewriteRule != "" ||
		unit.OversubscriptionPolicy != "" ||
		unit.PriorityLowMinShareBytes > 0 || unit.OutputTrafficControlProfile != ""
}

// applyCoSInterfaceLevelBindings folds each interface-level CoS binding
// (CoSInterface.Level, parsed from `class-of-service interfaces geX` with
// no `unit`) into the configured logical units of that interface (#4021).
//
// Junos precedence: an interface-level binding applies to every logical
// unit on the port, and a unit-level binding overrides it PER KNOB. This
// runs as a post-compile pass because the CoS compiler walks only the
// class-of-service subtree and does not know which logical units the
// interface stanza declares; here cfg.Interfaces is fully populated.
//
// After the fold, cos.Interfaces[name].Units carries the EFFECTIVE
// per-unit binding, so the dataplane snapshot and `show class-of-service`
// — which both iterate Units — apply interface-level CoS without any
// interface-level awareness of their own. An interface with an
// interface-level binding but no configured logical unit contributes no
// unit here (a CoS binding needs a logical interface to attach to); Level
// is retained for `show configuration` fidelity.
func applyCoSInterfaceLevelBindings(cfg *Config) {
	if cfg == nil || cfg.ClassOfService == nil {
		return
	}
	for name, cosIface := range cfg.ClassOfService.Interfaces {
		if cosIface == nil || cosIface.Level == nil {
			continue
		}
		ifCfg := cfg.Interfaces.Interfaces[name]
		if ifCfg == nil {
			continue
		}
		for unitNum := range ifCfg.Units {
			unit := cosIface.Units[unitNum]
			if unit == nil {
				unit = &CoSInterfaceUnit{Unit: unitNum}
				cosIface.Units[unitNum] = unit
			}
			mergeCoSInterfaceLevelInto(unit, cosIface.Level)
		}
	}
}

// mergeCoSInterfaceLevelInto fills any knob unset on unit from the
// interface-level binding level. The unit-level value wins whenever it is
// set (unit-level overrides interface-level).
func mergeCoSInterfaceLevelInto(unit, level *CoSInterfaceUnit) {
	if unit == nil || level == nil {
		return
	}
	if unit.ShapingRateBytes == 0 {
		unit.ShapingRateBytes = level.ShapingRateBytes
		// #hb166 G-10: burst-size is grammatically a child of
		// shaping-rate (see parseCoSInterfaceUnitBody), so a shaper is a
		// coupled (rate, burst) pair. Inherit the level burst-size ONLY
		// when the unit is also inheriting the level's rate. A unit that
		// overrides shaping-rate defines its own shaper; pairing the
		// level burst with the unit rate would mismatch them (a level
		// burst sized for a level rate applied to a different unit rate).
		// When the override unit leaves burst unset it stays 0 and the
		// dataplane applies its rate-independent COS_MIN_BURST_BYTES
		// floor, consistent with a fresh unit that sets shaping-rate
		// alone.
		if unit.BurstSizeBytes == 0 {
			unit.BurstSizeBytes = level.BurstSizeBytes
		}
	}
	if unit.SchedulerMap == "" {
		unit.SchedulerMap = level.SchedulerMap
	}
	if unit.OutputTrafficControlProfile == "" {
		unit.OutputTrafficControlProfile = level.OutputTrafficControlProfile
	}
	if unit.DSCPClassifier == "" {
		unit.DSCPClassifier = level.DSCPClassifier
	}
	if unit.IEEE8021Classifier == "" {
		unit.IEEE8021Classifier = level.IEEE8021Classifier
	}
	// #6847: inherit the interface-level inet-precedence binding, mirroring the
	// dscp / 802.1p fallbacks above.
	if unit.INetPrecedenceClassifier == "" {
		unit.INetPrecedenceClassifier = level.INetPrecedenceClassifier
	}
	if unit.DSCPRewriteRule == "" {
		unit.DSCPRewriteRule = level.DSCPRewriteRule
	}
	if unit.IEEE8021RewriteRule == "" {
		unit.IEEE8021RewriteRule = level.IEEE8021RewriteRule
	}
	if unit.OversubscriptionPolicy == "" {
		unit.OversubscriptionPolicy = level.OversubscriptionPolicy
		unit.OversubscriptionGuaranteeFraction = level.OversubscriptionGuaranteeFraction
	}
	if unit.PriorityLowMinShareBytes == 0 {
		unit.PriorityLowMinShareBytes = level.PriorityLowMinShareBytes
	}
}

// resolveCoSTrafficControlProfiles folds each interface unit's
// output-traffic-control-profile binding (fable-167 F-2, #4315) into the
// unit's existing per-unit shaper. For every CoSInterfaceUnit that names a
// profile, the referenced profile's shaping-rate and scheduler-map fill the
// unit's ShapingRateBytes / SchedulerMap when those are not already set
// directly on the unit — a DIRECT unit-level knob wins (Junos gives an
// explicit unit binding precedence over a profile). After this pass the
// dataplane snapshot and `show class-of-service`, which iterate Units and
// read ShapingRateBytes / SchedulerMap, enforce the profile's shaping with no
// awareness of traffic-control-profiles. This is what stops the silent
// zero-shaping: before modeling, output-traffic-control-profile was dropped
// and the shaper never materialized.
//
// A dangling reference (no such profile) leaves the unit's shaper knobs
// unset; ValidateConfig warns so the operator sees the inert binding.
// guaranteed-rate / delay-buffer-rate are NOT folded — the userspace shaper
// has no per-unit consumer for them (accepted-but-inert; warned separately).
//
// Runs AFTER applyCoSInterfaceLevelBindings so an interface-level
// output-traffic-control-profile has already been copied into each unit.
func resolveCoSTrafficControlProfiles(cfg *Config) {
	if cfg == nil || cfg.ClassOfService == nil {
		return
	}
	cos := cfg.ClassOfService
	resolve := func(unit *CoSInterfaceUnit, ifaceLineRateBytes uint64) {
		if unit == nil || unit.OutputTrafficControlProfile == "" {
			return
		}
		tcp := cos.TrafficControlProfiles[unit.OutputTrafficControlProfile]
		if tcp == nil {
			return
		}
		if unit.ShapingRateBytes == 0 {
			// #4228 Gap 2: fold the profile shaping-rate into the unit root
			// shaper. An absolute profile rate carries directly; a `percent
			// <n>` form resolves against the bound interface's configured line
			// rate (Junos resolves shaping-rate percent against the interface
			// speed). Resolution is per-BINDING — the same profile bound to
			// interfaces of different speeds folds a different absolute rate
			// onto each unit. When the interface has no configured speed we
			// cannot resolve the percent, so the unit is left unshaped and the
			// ValidateConfig advisory (compiler_validate_warn.go) surfaces it.
			if tcp.ShapingRateBytes > 0 {
				unit.ShapingRateBytes = tcp.ShapingRateBytes
			} else if resolved := resolveCoSPercentRateBytes(ifaceLineRateBytes, tcp.ShapingRatePercent); resolved > 0 {
				unit.ShapingRateBytes = resolved
			}
		}
		if unit.SchedulerMap == "" {
			unit.SchedulerMap = tcp.SchedulerMap
		}
	}
	for _, iface := range cos.Interfaces {
		if iface == nil {
			continue
		}
		lineRate := coSInterfaceLineRateBytes(cfg, iface.Name)
		resolve(iface.Level, lineRate)
		for _, unit := range iface.Units {
			resolve(unit, lineRate)
		}
	}
}

// coSInterfaceLineRateBytes returns the configured line rate of a physical
// interface in bytes/sec, or 0 when unknown. It is the base against which a
// `shaping-rate percent <n>` traffic-control-profile resolves (Junos resolves
// shaping-rate percent against the interface speed). An explicit `bandwidth`
// (already bits/sec) wins over the `speed` string; "auto"/"" (or an
// unparseable value) yields 0, which leaves the percent inert with a commit
// advisory rather than fabricating a rate.
func coSInterfaceLineRateBytes(cfg *Config, ifaceName string) uint64 {
	if cfg == nil || ifaceName == "" {
		return 0
	}
	iface := cfg.Interfaces.Interfaces[ifaceName]
	if iface == nil {
		return 0
	}
	if iface.Bandwidth > 0 {
		return iface.Bandwidth / 8
	}
	speed := strings.ToLower(strings.TrimSpace(iface.Speed))
	if speed == "" || speed == "auto" {
		return 0
	}
	return parseBandwidthLimit(speed)
}

// resolveCoSPercentRateBytes resolves a Junos CoS `percent <n>` rate against a
// base rate in bytes/sec. It mirrors the Rust `cos_percent_buffer_bytes` /
// `cos_percent_rate_bytes` resolution EXACTLY — same (0,100] domain guard,
// same `math.Ceil` rounding, same clamp to [1, MaxUint64] — so a
// shaping-rate/transmit-rate percent rounds identically on the Go and Rust
// sides. Returns 0 when the base is unknown (0) or the percent is out of
// range; the caller then leaves the knob inert.
//
// THE ROUNDING IS PART OF THE CONTRACT, not an implementation detail, and this
// is the package's ONE statement of it — every Go site that needs a CoS percent
// resolves through here. #6846 F6 is why that is written as a rule: the
// remainder advisory grew its own inline `uint64(float64(base) * pct / 100.0)`,
// which TRUNCATES. Truncating makes the control plane's claim lower, its
// leftover larger, so it answered "resolves" for a shape the dataplane rounds
// away — silent at commit and inert at runtime, on a config that compiles.
// `percent 33.3333333` + `percent 66.6666667` on a 1 Gbps shape reaches it:
// 124_999_999 truncated against 125_000_001 ceiled, over a 125_000_000 base.
//
// A second Go implementation of this rule would always be a bug rather than a
// legitimate divergence, so the answer is one function, not two bound by a
// test.
func resolveCoSPercentRateBytes(baseBytesPerSec uint64, percent float64) uint64 {
	if baseBytesPerSec == 0 || math.IsNaN(percent) || math.IsInf(percent, 0) ||
		percent <= 0 || percent > 100 {
		return 0
	}
	scaled := math.Ceil(float64(baseBytesPerSec) * percent / 100.0)
	if scaled < 1 {
		return 1
	}
	// float64(^uint64(0)) rounds UP to 2^64 (MaxUint64 is not float64-exact),
	// so a `scaled` of exactly 2^64 would slip past a `>` compare and then
	// overflow the float->uint64 conversion (out-of-range is implementation-
	// defined in Go, unlike Rust's saturating `as`). Use `>=` to clamp the
	// exact-boundary case deterministically to MaxUint64.
	if scaled >= float64(^uint64(0)) {
		return ^uint64(0)
	}
	return uint64(scaled)
}

func collectCoSFairnessRSSExpectation(queueNode *Node) (string, error) {
	var expr string
	set := func(kind string, nodes []*Node, next func(*Node) string) error {
		if len(nodes) == 0 {
			return nil
		}
		if len(nodes) > 1 {
			return fmt.Errorf("duplicate %s expectation leaf", kind)
		}
		value := next(nodes[0])
		if expr != "" && expr != value {
			return fmt.Errorf("multiple expectations configured: %q and %q", expr, value)
		}
		expr = value
		return nil
	}
	setFlag := func(kind string) error {
		return set(kind, queueNode.FindChildren(kind), func(*Node) string { return kind })
	}
	setValue := func(kind string, names ...string) error {
		var nodes []*Node
		for _, name := range names {
			nodes = append(nodes, queueNode.FindChildren(name)...)
		}
		return set(kind, nodes, func(n *Node) string { return kind + ":" + nodeVal(n) })
	}
	if err := setFlag("any"); err != nil {
		return "", err
	}
	if err := setFlag("balanced"); err != nil {
		return "", err
	}
	if err := setValue("at-least-active-workers", "active-workers", "at-least-active-workers"); err != nil {
		return "", err
	}
	if err := setValue("max-worker-flow-share", "max-worker-flow-share"); err != nil {
		return "", err
	}
	if err := setValue("cstruct-max", "cstruct", "cstruct-max"); err != nil {
		return "", err
	}
	if expr == "" {
		return "", fmt.Errorf("missing expectation; expected any, balanced, at-least-active-workers, max-worker-flow-share, or cstruct-max")
	}
	return expr, nil
}

// parseCoSTransmitRate reads a scheduler `transmit-rate` leaf. It returns the
// absolute byte/sec rate (0 when the operator used percent/remainder or no
// rate), the Junos `percent <n>` share (0 when unused), the `remainder` flag,
// and the `exact` modifier. #4228 Gap 2 added percent/remainder; the tail
// tokens are gathered identically to the schema tailValidator
// (gatherLeafTailTokens) so validation and compilation never drift.
func parseCoSTransmitRate(node *Node) (rateBytes uint64, percent float64, remainder bool, exact bool) {
	toks := gatherLeafTailTokens(node)
	for i := 0; i < len(toks); i++ {
		switch toks[i] {
		case "exact":
			exact = true
		case "remainder":
			remainder = true
		case "percent":
			if i+1 < len(toks) {
				if v, err := strconv.ParseFloat(toks[i+1], 64); err == nil {
					percent = v
				}
				i++
			}
		default:
			if parsed := parseBandwidthLimit(toks[i]); parsed > 0 {
				rateBytes = parsed
			}
		}
	}
	return rateBytes, percent, remainder, exact
}

// parseCoSShapingRate reads a `shaping-rate` leaf (traffic-control-profiles),
// returning the absolute byte/sec rate (0 when percent/no-rate) and the Junos
// `percent <n>` share (0 when unused). #4228 Gap 2.
func parseCoSShapingRate(node *Node) (rateBytes uint64, percent float64) {
	toks := gatherLeafTailTokens(node)
	for i := 0; i < len(toks); i++ {
		if toks[i] == "percent" {
			if i+1 < len(toks) {
				if v, err := strconv.ParseFloat(toks[i+1], 64); err == nil {
					percent = v
				}
				i++
			}
			continue
		}
		if parsed := parseBandwidthLimit(toks[i]); parsed > 0 {
			rateBytes = parsed
		}
	}
	return rateBytes, percent
}

// cosBindingSchema8939 resolves the class-of-service unit-level binding
// container (`classifiers` or `rewrite-rules`) so flattenChainedNode can tell a
// terminating binding from one that owns a body.
func cosBindingSchema8939(which string) *schemaNode {
	cos := resolveSchemaChild(setSchema, "class-of-service")
	ifs := resolveSchemaChild(cos, "interfaces")
	if ifs == nil {
		return nil
	}
	if ifs.wildcard != nil {
		ifs = ifs.wildcard
	}
	unit := resolveSchemaChild(ifs, "unit")
	if unit == nil {
		return nil
	}
	if unit.wildcard != nil {
		unit = unit.wildcard
	}
	return resolveSchemaChild(unit, which)
}
