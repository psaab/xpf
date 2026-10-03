package config

import (
	"fmt"
	"sort"
)

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

// classOfServiceClassifierQueueWarnings (#hb166 T-4) flags a behavior-aggregate
// (DSCP / IEEE 802.1p) classifier code-point on this interface unit that maps
// to a DEFINED forwarding-class whose queue is NOT materialized on the unit
// (the forwarding-class has no scheduler-map entry, so the dataplane never
// builds that queue). Pre-fix such a code-point was a 100% silent blackhole;
// the dataplane now fails SAFE and forwards it on the best-effort queue
// (forwarding_build/cos.rs), but the operator should still see that the
// intended queue does not exist on this interface.
//
// This is a WARN, not a strict reject. A classifier steering to a
// forwarding-class that merely lacks a scheduler-map entry is a valid Junos
// config — Junos queues exist by default without a scheduler-map binding — so
// rejecting it (as the dangling-SCHEDULER gate does for an undefined scheduler
// name) would refuse configs Junos accepts and configs xpf's own test suite
// asserts compile.
//
// The materialization + admission model mirrors
// forwarding_build/cos.rs::build_cos_iface_config. An admitted interface with
// a blackholed code-point warns per class. A classifier-only (#11784 C9) or
// rewrite-only (C10) binding to all-non-best-effort classes is also reported
// when no CoS knob admits the interface: the dataplane builds no runtime and
// those bindings are inert.
func classOfServiceClassifierQueueWarnings(cos *ClassOfServiceConfig, ifaceName string, unit *CoSInterfaceUnit) []string {
	if cos == nil || unit == nil {
		return nil
	}
	dscpCls := cos.DSCPClassifiers[unit.DSCPClassifier]
	ieeeCls := cos.IEEE8021Classifiers[unit.IEEE8021Classifier]
	// #7082: include the third behavior-aggregate arm in the same
	// per-code-point analysis as DSCP and IEEE 802.1 classifiers. #6847
	// added inet-precedence to build_cos_iface_config; omitting it here
	// would miss the existing blackhole warning whenever that classifier
	// mapped a code-point to an unmaterialized queue.
	// Defs, not the name list, is right HERE — unlike the definedness check in
	// compiler_validate_warn.go — because this arm needs the ENTRIES to know
	// which forwarding-classes the classifier maps to. A classifier with no
	// entries maps no code-point and so can blackhole nothing, which is exactly
	// the nil case below.
	inetCls := cos.INetPrecedenceClassifierDefs[unit.INetPrecedenceClassifier]
	rewriteRule := cos.DSCPRewriteRules[unit.DSCPRewriteRule]
	if dscpCls == nil && ieeeCls == nil && inetCls == nil && rewriteRule == nil {
		// No classifier or rewrite-rule attached (or the reference is
		// undefined — flagged elsewhere): nothing can blackhole.
		return nil
	}

	// Queues this unit materializes: the DEFINED forwarding-classes named by
	// its scheduler-map, else the synthetic best-effort queue 0 when the
	// scheduler-map resolves to nothing.
	matQueues := map[int]bool{}
	schedMapResolved := false
	if unit.SchedulerMap != "" {
		if sm := cos.SchedulerMaps[unit.SchedulerMap]; sm != nil {
			for className := range sm.Entries {
				if fc := cos.ForwardingClasses[className]; fc != nil {
					matQueues[fc.Queue] = true
					schedMapResolved = true
				}
			}
		}
	}
	if !schedMapResolved {
		matQueues = map[int]bool{0: true}
	}

	// Partition the classifier's referenced forwarding-classes into
	// materialized-queue hits vs blackholed (DEFINED class, unmaterialized
	// queue). An UNDEFINED class is skipped — the dataplane drops it from the
	// classifier table and the undefined-class warn already flags it.
	anyHit := false
	blackholed := map[string]int{}
	seen := map[string]bool{}
	classify := func(class string) {
		if class == "" || seen[class] {
			return
		}
		seen[class] = true
		fc := cos.ForwardingClasses[class]
		if fc == nil {
			return
		}
		if matQueues[fc.Queue] {
			anyHit = true
		} else {
			blackholed[class] = fc.Queue
		}
	}
	if dscpCls != nil {
		for _, e := range dscpCls.Entries {
			if e != nil {
				classify(e.ForwardingClass)
			}
		}
	}
	if ieeeCls != nil {
		for _, e := range ieeeCls.Entries {
			if e != nil {
				classify(e.ForwardingClass)
			}
		}
	}
	if inetCls != nil {
		for _, e := range inetCls.Entries {
			if e != nil {
				classify(e.ForwardingClass)
			}
		}
	}

	// A rewrite rule targeting a materialized class also admits the interface.
	rewriteHit := false
	var rewriteMisses map[string]int
	if rewriteRule != nil {
		for _, e := range rewriteRule.Entries {
			if e == nil {
				continue
			}
			fc := cos.ForwardingClasses[e.ForwardingClass]
			if fc == nil {
				continue
			}
			if matQueues[fc.Queue] {
				rewriteHit = true
			} else {
				if rewriteMisses == nil {
					rewriteMisses = make(map[string]int)
				}
				rewriteMisses[e.ForwardingClass] = fc.Queue
			}
		}
	}

	admitted := schedMapResolved || unit.ShapingRateBytes > 0 || anyHit || rewriteHit
	if !admitted {
		// With no other admission knob, a classifier or rewrite targeting
		// only unmaterialized non-best-effort classes never gets a CoS
		// runtime. Make those otherwise-silent bindings visible.
		var warnings []string
		classes := make([]string, 0, len(blackholed))
		for class := range blackholed {
			classes = append(classes, class)
		}
		sort.Strings(classes)
		for _, class := range classes {
			warnings = append(warnings, fmt.Sprintf(
				"class-of-service interface %s unit %d has classifier binding(s) to forwarding-class %q (queue %d), but no CoS knob admits this all-non-best-effort binding; the userspace dataplane builds no CoS runtime for the unit",
				ifaceName, unit.Unit, class, blackholed[class]))
		}
		classes = classes[:0]
		for class := range rewriteMisses {
			classes = append(classes, class)
		}
		sort.Strings(classes)
		for _, class := range classes {
			warnings = append(warnings, fmt.Sprintf(
				"class-of-service interface %s unit %d has dscp rewrite-rule %q bound to forwarding-class %q (queue %d), but no CoS knob admits this all-non-best-effort binding; the userspace dataplane never rewrites egress traffic for the unit",
				ifaceName, unit.Unit, unit.DSCPRewriteRule, class, rewriteMisses[class]))
		}
		return warnings
	}
	if len(blackholed) == 0 {
		return nil
	}

	classes := make([]string, 0, len(blackholed))
	for class := range blackholed {
		classes = append(classes, class)
	}
	sort.Strings(classes)
	warnings := make([]string, 0, len(classes))
	for _, class := range classes {
		warnings = append(warnings, fmt.Sprintf(
			"class-of-service interface %s unit %d classifier maps code-point(s) to forwarding-class %q (queue %d) which has no scheduler-map entry on this interface; the userspace dataplane forwards matching traffic on the best-effort queue",
			ifaceName, unit.Unit, class, blackholed[class]))
	}
	return warnings
}

// classOfServiceMaterializedForwardingClasses returns the defined forwarding
// classes whose queues are built from a unit's scheduler-map and whether that
// map contains at least one usable class.
func classOfServiceMaterializedForwardingClasses(cos *ClassOfServiceConfig, unit *CoSInterfaceUnit) (map[string]bool, bool) {
	matClasses := map[string]bool{}
	if cos == nil || unit == nil || unit.SchedulerMap == "" {
		return matClasses, false
	}
	if sm := cos.SchedulerMaps[unit.SchedulerMap]; sm != nil {
		for className := range sm.Entries {
			if cos.ForwardingClasses[className] != nil {
				matClasses[className] = true
			}
		}
	}
	return matClasses, len(matClasses) > 0
}

// classOfServiceUnitHasRuntime mirrors the CoS admission gate in
// build_cos_iface_config. A filter alone does not create a CoS runtime.
func classOfServiceUnitHasRuntime(cos *ClassOfServiceConfig, unit *CoSInterfaceUnit) bool {
	if cos == nil || unit == nil {
		return false
	}
	_, schedulerMapResolved := classOfServiceMaterializedForwardingClasses(cos, unit)
	if schedulerMapResolved || unit.ShapingRateBytes > 0 {
		return true
	}

	// Without a usable scheduler-map, the dataplane's pre-admission candidate
	// queue set is the synthetic queue 0.
	classTargetsDefaultQueue := func(className string) bool {
		fc := cos.ForwardingClasses[className]
		return fc != nil && fc.Queue == 0
	}
	if classifier := cos.DSCPClassifiers[unit.DSCPClassifier]; classifier != nil {
		for _, entry := range classifier.Entries {
			if entry != nil && classTargetsDefaultQueue(entry.ForwardingClass) {
				return true
			}
		}
	}
	if classifier := cos.IEEE8021Classifiers[unit.IEEE8021Classifier]; classifier != nil {
		for _, entry := range classifier.Entries {
			if entry != nil && classTargetsDefaultQueue(entry.ForwardingClass) {
				return true
			}
		}
	}
	if classifier := cos.INetPrecedenceClassifierDefs[unit.INetPrecedenceClassifier]; classifier != nil {
		for _, entry := range classifier.Entries {
			if entry != nil && classTargetsDefaultQueue(entry.ForwardingClass) {
				return true
			}
		}
	}
	if rewrite := cos.DSCPRewriteRules[unit.DSCPRewriteRule]; rewrite != nil {
		for _, entry := range rewrite.Entries {
			if entry != nil && entry.ForwardingClass == "best-effort" {
				return true
			}
		}
	}
	return false
}

// classOfServiceFilterForwardingClassWarnings (#11787) reports a defined
// filter forwarding-class that has no queue built on a CoS egress unit. Output
// filters are local to that unit; input filter classes can survive to any egress.
func classOfServiceFilterForwardingClassWarnings(cfg *Config, cos *ClassOfServiceConfig, ifaceName string, unit *CoSInterfaceUnit) []string {
	if cfg == nil || cos == nil || unit == nil {
		return nil
	}
	iface := cfg.Interfaces.Interfaces[ifaceName]
	if iface == nil || iface.Units[unit.Unit] == nil {
		return nil
	}
	ifUnit := iface.Units[unit.Unit]
	if !classOfServiceUnitHasRuntime(cos, unit) {
		return nil
	}
	// An output filter directly classifies this unit. An input filter's class
	// survives to the packet's eventual egress, so conservatively check every
	// configured input filter against this unit's materialized queue map.
	type filterRef struct {
		name      string
		family    string
		direction string
		fw        *FirewallFilter
	}
	var filters []filterRef
	seenFilters := map[*FirewallFilter]bool{}
	addFilter := func(name, family, direction string, defs map[string]*FirewallFilter) {
		if name == "" || defs[name] == nil || seenFilters[defs[name]] {
			return
		}
		seenFilters[defs[name]] = true
		filters = append(filters, filterRef{
			name: name, family: family, direction: direction, fw: defs[name],
		})
	}
	addFilter(ifUnit.FilterOutputV4, "inet", "output", cfg.Firewall.FiltersInet)
	addFilter(ifUnit.FilterOutputV6, "inet6", "output", cfg.Firewall.FiltersInet6)
	for _, ingressIface := range cfg.Interfaces.Interfaces {
		if ingressIface == nil {
			continue
		}
		for _, ingressUnit := range ingressIface.Units {
			if ingressUnit == nil {
				continue
			}
			addFilter(ingressUnit.FilterInputV4, "inet", "input", cfg.Firewall.FiltersInet)
			addFilter(ingressUnit.FilterInputV6, "inet6", "input", cfg.Firewall.FiltersInet6)
		}
	}
	sort.Slice(filters, func(i, j int) bool {
		if filters[i].name != filters[j].name {
			return filters[i].name < filters[j].name
		}
		if filters[i].family != filters[j].family {
			return filters[i].family < filters[j].family
		}
		return filters[i].direction < filters[j].direction
	})
	matClasses, schedulerMapResolved := classOfServiceMaterializedForwardingClasses(cos, unit)
	if !schedulerMapResolved {
		matClasses = map[string]bool{"best-effort": true}
	} else if !matClasses["best-effort"] {
		// build_cos_iface_config synthesizes best-effort for every admitted
		// unit whose scheduler-map omits the class.
		matClasses["best-effort"] = true
	}

	var warnings []string
	type termRef struct {
		filter *FirewallFilter
		name   string
	}
	seenTerms := map[termRef]bool{}
	for _, ref := range filters {
		for _, term := range ref.fw.Terms {
			if term == nil || term.ForwardingClass == "" {
				continue
			}
			key := termRef{filter: ref.fw, name: term.Name}
			if seenTerms[key] {
				continue
			}
			seenTerms[key] = true
			fc := cos.ForwardingClasses[term.ForwardingClass]
			if fc == nil || matClasses[term.ForwardingClass] {
				continue
			}
			warnings = append(warnings, fmt.Sprintf(
				"class-of-service interface %s unit %d may receive filter %q family %s %s term %q that sets defined forwarding-class %q (queue %d) which has no materialized queue on this interface; the userspace dataplane uses the pinned best-effort fallback",
				ifaceName, unit.Unit, ref.name, ref.family, ref.direction, term.Name, term.ForwardingClass, fc.Queue))
		}
	}
	return warnings
}
