package config

import (
	"fmt"
	"strconv"
	"strings"
)

func compileClassOfService(node *Node, cos *ClassOfServiceConfig) error {
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
	if cos.Schedulers == nil {
		cos.Schedulers = make(map[string]*CoSScheduler)
	}
	if cos.SchedulerMaps == nil {
		cos.SchedulerMaps = make(map[string]*CoSSchedulerMap)
	}
	if cos.Interfaces == nil {
		cos.Interfaces = make(map[string]*CoSInterface)
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
			queue, err := strconv.Atoi(queueNode.Keys[1])
			if err != nil {
				continue
			}
			name := queueNode.Keys[2]
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
					codePoints := collectCoSDSCPCodePoints(lpNode)
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
					codePoints := collectCoS8021CodePoints(lpNode)
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
	}

	if rewriteRulesNode := node.FindChild("rewrite-rules"); rewriteRulesNode != nil {
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
					codePoint, ok := collectCoSDSCPRewriteCodePoint(lpNode)
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
	}

	for _, inst := range namedInstances(node.FindChildren("schedulers")) {
		sched := &CoSScheduler{Name: inst.name}
		for _, child := range inst.node.Children {
			switch child.Name() {
			case "transmit-rate":
				rate, exact := parseCoSTransmitRate(child)
				if rate > 0 {
					sched.TransmitRateBytes = rate
				}
				sched.TransmitRateExact = sched.TransmitRateExact || exact
			case "priority":
				sched.Priority = nodeVal(child)
			case "buffer-size":
				if v := nodeVal(child); v != "" {
					sched.BufferSizeBytes = parseBurstSizeLimit(v)
				}
			case "surplus-sharing":
				// #915: leaf with no value; presence = true.
				sched.SurplusSharing = true
			}
		}
		cos.Schedulers[sched.Name] = sched
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

	for _, inst := range namedInstances(node.FindChildren("interfaces")) {
		iface := &CoSInterface{
			Name:  inst.name,
			Units: make(map[int]*CoSInterfaceUnit),
		}
		for _, unitNode := range inst.node.FindChildren("unit") {
			if len(unitNode.Keys) < 2 {
				continue
			}
			unitID, err := strconv.Atoi(unitNode.Keys[1])
			if err != nil {
				continue
			}
			unit := &CoSInterfaceUnit{Unit: unitID}
			if shapingNode := unitNode.FindChild("shaping-rate"); shapingNode != nil {
				if v := nodeVal(shapingNode); v != "" {
					unit.ShapingRateBytes = parseBandwidthLimit(v)
				}
				if burstNode := shapingNode.FindChild("burst-size"); burstNode != nil {
					if v := nodeVal(burstNode); v != "" {
						unit.BurstSizeBytes = parseBurstSizeLimit(v)
					}
				}
			}
			if schedMapNode := unitNode.FindChild("scheduler-map"); schedMapNode != nil {
				unit.SchedulerMap = nodeVal(schedMapNode)
			}
			if classifiersNode := unitNode.FindChild("classifiers"); classifiersNode != nil {
				if dscpNode := classifiersNode.FindChild("dscp"); dscpNode != nil {
					unit.DSCPClassifier = nodeVal(dscpNode)
				}
				if ieeeNode := classifiersNode.FindChild("ieee-802.1"); ieeeNode != nil {
					unit.IEEE8021Classifier = nodeVal(ieeeNode)
				}
			}
			if rewriteRulesNode := unitNode.FindChild("rewrite-rules"); rewriteRulesNode != nil {
				if dscpNode := rewriteRulesNode.FindChild("dscp"); dscpNode != nil {
					unit.DSCPRewriteRule = nodeVal(dscpNode)
				}
			}
			if unit.ShapingRateBytes > 0 || unit.BurstSizeBytes > 0 || unit.SchedulerMap != "" || unit.DSCPClassifier != "" || unit.IEEE8021Classifier != "" || unit.DSCPRewriteRule != "" {
				iface.Units[unitID] = unit
			}
		}
		if len(iface.Units) > 0 {
			cos.Interfaces[iface.Name] = iface
		}
	}

	return nil
}

func parseCoSTransmitRate(node *Node) (uint64, bool) {
	var rate uint64
	exact := false
	for _, key := range node.Keys[1:] {
		if key == "exact" {
			exact = true
			continue
		}
		if parsed := parseBandwidthLimit(key); parsed > 0 {
			rate = parsed
		}
	}
	if node.FindChild("exact") != nil {
		exact = true
	}
	return rate, exact
}

func collectCoSDSCPCodePoints(node *Node) []uint8 {
	var values []uint8
	seen := make(map[uint8]struct{})
	for _, child := range node.FindChildren("code-points") {
		for _, raw := range child.Keys[1:] {
			for _, value := range expandCoSCodePointToken(raw) {
				if _, ok := seen[value]; ok {
					continue
				}
				seen[value] = struct{}{}
				values = append(values, value)
			}
		}
	}
	return values
}

func collectCoS8021CodePoints(node *Node) []uint8 {
	var values []uint8
	seen := make(map[uint8]struct{})
	for _, child := range node.FindChildren("code-points") {
		for _, raw := range child.Keys[1:] {
			raw = strings.TrimSpace(strings.ToLower(raw))
			if raw == "" {
				continue
			}
			v, err := strconv.Atoi(raw)
			if err != nil || v < 0 || v > 7 {
				continue
			}
			value := uint8(v)
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			values = append(values, value)
		}
	}
	return values
}

func collectCoSDSCPRewriteCodePoint(node *Node) (uint8, bool) {
	for _, child := range node.FindChildren("code-point") {
		if len(child.Keys) < 2 {
			continue
		}
		if values := expandCoSCodePointToken(child.Keys[1]); len(values) > 0 {
			return values[0], true
		}
	}
	for _, child := range node.FindChildren("code-points") {
		for _, raw := range child.Keys[1:] {
			if values := expandCoSCodePointToken(raw); len(values) > 0 {
				return values[0], true
			}
		}
	}
	return 0, false
}

func expandCoSCodePointToken(raw string) []uint8 {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return nil
	}
	if value, ok := coSDSCPValues[raw]; ok {
		return []uint8{value}
	}
	if v, err := strconv.Atoi(raw); err == nil && v >= 0 && v <= 63 {
		return []uint8{uint8(v)}
	}
	return nil
}

var coSDSCPValues = map[string]uint8{
	"default": 0,
	"be":      0,
	"ef":      46,
	"af11":    10,
	"af12":    12,
	"af13":    14,
	"af21":    18,
	"af22":    20,
	"af23":    22,
	"af31":    26,
	"af32":    28,
	"af33":    30,
	"af41":    34,
	"af42":    36,
	"af43":    38,
	"cs0":     0,
	"cs1":     8,
	"cs2":     16,
	"cs3":     24,
	"cs4":     32,
	"cs5":     40,
	"cs6":     48,
	"cs7":     56,
}
