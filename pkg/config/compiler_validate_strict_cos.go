package config

import (
	"fmt"
	"math"
	"slices"
	"sort"
)

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

// validateClassOfServiceSchedulerMapRefsStrict hard-rejects a
// class-of-service scheduler-map entry whose `scheduler <name>`
// reference does not resolve to a defined `class-of-service schedulers`
// entry — a commit-time typo. Junos hard-rejects an unresolved
// scheduler reference at commit; this restores that behavior.
//
// Before this gate the reference was warn-only at commit
// (ValidateConfig, compiler_validate_warn.go) and then FAILED OPEN in
// the dataplane: the userspace helper's per-queue builder
// (userspace-dp forwarding_build/cos.rs) resolves the dangling name to
// `None`, leaves `guarantee_enabled` false, sets the queue's transmit
// rate to the WHOLE interface shaping rate, and derives the MAXIMUM
// surplus weight (16). So a premium class (e.g. `ef`) whose scheduler
// name is a typo did not merely lose its guarantee — it silently won
// the LARGEST best-effort surplus share, invisible outside the runtime
// queue rows.
//
// On the tolerant load / peer-sync paths the call site downgrades this
// to a warning (opts.lenientSchedulerMapRef) so a config persisted by
// an older binary (which only warned) or synced from a peer still boots
// (#1960 no-brick). The dataplane's render-path safety net (the
// scheduler-unresolved SAFE default in forwarding_build/cos.rs, which
// pins surplus_weight to 1) keeps a leniently-loaded dangling reference
// from fail-opening to the maximum best-effort share on that boot.
// Mirrors validatePolicySchedulerReferencesStrict, which rejects an
// undefined scheduler reference from a security policy.
//
// An EMPTY scheduler string is skipped: the grammar requires a name, so
// an empty value arises only in constructed configs and is the same
// "no scheduler assigned" placeholder the warn / strict buffer
// validators skip.
func validateClassOfServiceSchedulerMapRefsStrict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	// Iterate scheduler-maps and their entries in sorted order so
	// commit-check surfaces a STABLE first-error message (Go map
	// iteration order is randomized).
	mapNames := make([]string, 0, len(cos.SchedulerMaps))
	for name := range cos.SchedulerMaps {
		mapNames = append(mapNames, name)
	}
	sort.Strings(mapNames)
	for _, mapName := range mapNames {
		schedMap := cos.SchedulerMaps[mapName]
		if schedMap == nil {
			continue
		}
		classNames := make([]string, 0, len(schedMap.Entries))
		for className := range schedMap.Entries {
			classNames = append(classNames, className)
		}
		sort.Strings(classNames)
		for _, className := range classNames {
			entry := schedMap.Entries[className]
			if entry == nil || entry.Scheduler == "" {
				continue
			}
			if _, ok := cos.Schedulers[entry.Scheduler]; !ok {
				return fmt.Errorf(
					"class-of-service scheduler-map %q forwarding-class %q references undefined scheduler %q",
					schedMap.Name, className, entry.Scheduler)
			}
		}
	}
	return nil
}

// cosSchedulerPriorityValues is the complete Junos scheduler-priority set
// accepted by the Rust CoS queue builder. Keep this aligned with the schema's
// `priority` enum and `cos_priority_rank` in userspace-dp.
var cosSchedulerPriorityValues = map[string]struct{}{
	"low":         {},
	"medium-low":  {},
	"medium-high": {},
	"high":        {},
	"strict-high": {},
}

// CoSSchedulerPriorityValid reports whether priority is a known Junos
// scheduler priority or the legitimate empty/unset value. The userspace
// snapshot emitter uses this as a final boundary check.
func CoSSchedulerPriorityValid(priority string) bool {
	if priority == "" {
		return true
	}
	_, ok := cosSchedulerPriorityValues[priority]
	return ok
}

// validateClassOfServiceSchedulerPriorityStrict rejects a non-empty priority
// that the Rust queue builder would fail closed on. Visit schedulers in stable
// name order so commit-check errors are deterministic.
func validateClassOfServiceSchedulerPriorityStrict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	names := make([]string, 0, len(cos.Schedulers))
	for name := range cos.Schedulers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		sched := cos.Schedulers[name]
		if sched == nil || CoSSchedulerPriorityValid(sched.Priority) {
			continue
		}
		displayName := sched.Name
		if displayName == "" {
			displayName = name
		}
		return fmt.Errorf(
			"class-of-service scheduler %q priority %q is unrecognized "+
				"(must be one of: low, medium-low, medium-high, high, strict-high)",
			displayName, sched.Priority)
	}
	return nil
}

// sanitizeClassOfServiceSchedulerPriorities clears every unrecognized priority
// on tolerant loads. Empty is the documented legacy default (low) in Rust, so
// this keeps the load bootable without passing the fail-closed token onward.
func sanitizeClassOfServiceSchedulerPriorities(cos *ClassOfServiceConfig) []string {
	if cos == nil {
		return nil
	}
	names := make([]string, 0, len(cos.Schedulers))
	for name := range cos.Schedulers {
		names = append(names, name)
	}
	sort.Strings(names)
	var warnings []string
	for _, name := range names {
		sched := cos.Schedulers[name]
		if sched == nil || CoSSchedulerPriorityValid(sched.Priority) {
			continue
		}
		displayName := sched.Name
		if displayName == "" {
			displayName = name
		}
		warnings = append(warnings, fmt.Sprintf(
			"class-of-service scheduler %q priority %q (downgraded to warning on tolerant path; cleared to unset low default, issue #11798)",
			displayName, sched.Priority))
		sched.Priority = ""
	}
	return warnings
}

// cosLossPriorityValues is the set of loss-priority values Junos accepts on a
// class-of-service DSCP / 802.1p classifier or DSCP rewrite-rule. It mirrors
// cos_loss_priority_index in userspace-dp forwarding_build/cos.rs.
var cosLossPriorityValues = map[string]struct{}{
	"low":         {},
	"medium-low":  {},
	"medium-high": {},
	"high":        {},
}

// validateClassOfServiceLossPriorityStrict hard-rejects a class-of-service
// classifier or DSCP rewrite-rule entry whose `loss-priority` value is not one
// of the four Junos levels (low, medium-low, medium-high, high) — an operator
// typo like `medum-low` (#3995). Junos rejects an unknown loss-priority at
// commit; before this gate the raw string was threaded through to the
// dataplane, where `cos_loss_priority_index` maps an unrecognized value to the
// SAFE default (LOW for the classifier, a wildcard-over-all-loss-priorities for
// the rewrite-rule). That default is correct for fail-safe boot but WRONG for a
// fresh operator edit: the typo silently applies the wrong QoS class instead of
// surfacing the mistake. Reject it loudly at commit / commit-check.
//
// An EMPTY loss-priority is skipped: it is the legitimate "no explicit
// loss-priority" case (the rewrite-rule wildcard / classifier default), the
// same placeholder the other CoS validators skip.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientCoSLossPriority) so a config persisted by an older
// binary — or synced from a peer — still boots (#1960 no-brick); the dataplane
// applies the SAFE default on that boot. Entries are visited in sorted order so
// commit-check surfaces a STABLE first-error message.
// validateCoSUnitClassifierConflict rejects a logical unit that binds BOTH a
// `dscp` and an `inet-precedence` classifier (#6847).
//
// The two read the SAME IPv4 TOS byte — IP precedence is its top 3 bits — so
// binding both is a contradiction, not a composition. There is no defined
// answer to "which wins", and the BA resolution chain would silently pick one
// (DSCP is consulted first, so the inet-precedence binding would simply be
// dead). A silently-dead classifier is the quiet-wrong-QoS failure this gate
// family exists to stop, so reject at commit and make the operator choose.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientCoSUnitClassifierConflict) so a config persisted by an
// older binary — which had NO inet-precedence binding site and so could not
// have produced this combination, but might acquire it via a hand-edited or
// peer-synced file — still boots (#1960 no-brick). On that boot the DSCP
// classifier wins, matching the resolution order.
//
// Units are visited in sorted (interface, unit) order so commit-check surfaces
// a STABLE first-error message.
// validateClassOfServiceInterfaceRefsStrict hard-rejects a
// `class-of-service interfaces` binding whose named scheduler-map,
// traffic-control-profile, classifier or rewrite-rule does not resolve to a
// defined `class-of-service` entry — a commit-time typo (#7337).
//
// These are the INTERFACE-side references, distinct from
// validateClassOfServiceSchedulerMapRefsStrict above, which validates the
// scheduler-map -> scheduler link one level down. Both links could dangle
// independently and only the inner one was gated.
//
// Before this gate all seven were warn-only (compiler_validate_warn.go) and
// then FAILED OPEN in the dataplane: forwarding_build/cos.rs resolves each
// name with a bare `.get(...)` yielding None, with no Missing*Ref and no
// error. So the interface materializes no scheduler queues, or a classifier
// arm contributes nothing, and QoS silently degrades to best-effort while the
// committed config still says the interface is shaped and classified. The
// operator's only evidence is a warning they saw once at commit time.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientCoSInterfaceRefs) so a config persisted by an older
// binary — which only warned — or synced from a peer still boots (#1960
// no-brick). The dataplane's own None-resolution is the safety net on that
// boot: it is the fail-open being fixed, but it is not a crash, so a
// leniently-loaded config degrades exactly as it does today rather than
// failing to load.
//
// Iteration is sorted by interface name then unit so commit-check surfaces a
// STABLE first-error message; Go map iteration order is randomized and an
// unstable message makes a fixture flaky in a way that looks intermittent.
func validateClassOfServiceInterfaceRefsStrict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	ifNames := make([]string, 0, len(cos.Interfaces))
	for name := range cos.Interfaces {
		ifNames = append(ifNames, name)
	}
	sort.Strings(ifNames)
	for _, ifName := range ifNames {
		iface := cos.Interfaces[ifName]
		if iface == nil {
			continue
		}
		// Level is checked as well as Units. applyCoSInterfaceLevelBindings
		// (compiler.go, before the gates) folds an interface-level binding
		// into each CONFIGURED unit, so for an interface that has units this
		// is redundant — but an interface-level binding on a stanza with NO
		// configured units is folded nowhere, and its dangling name would
		// otherwise be invisible to this gate.
		if iface.Level != nil {
			if err := cosUnitRefsResolve(cos, ifName, -1, iface.Level); err != nil {
				return err
			}
		}
		units := make([]int, 0, len(iface.Units))
		for u := range iface.Units {
			units = append(units, u)
		}
		sort.Ints(units)
		for _, u := range units {
			if err := cosUnitRefsResolve(cos, ifName, u, iface.Units[u]); err != nil {
				return err
			}
		}
	}
	return nil
}

// cosUnitRefsResolve checks one CoS unit binding's seven outbound references.
// `unit` is -1 for an interface-level binding, which renders as the Junos
// interface-level form rather than a fake unit number.
func cosUnitRefsResolve(cos *ClassOfServiceConfig, ifName string, unit int, u *CoSInterfaceUnit) error {
	if u == nil {
		return nil
	}
	where := fmt.Sprintf("class-of-service interfaces %s unit %d", ifName, unit)
	if unit < 0 {
		where = fmt.Sprintf("class-of-service interfaces %s", ifName)
	}
	if u.SchedulerMap != "" {
		if _, ok := cos.SchedulerMaps[u.SchedulerMap]; !ok {
			return fmt.Errorf("%s references undefined scheduler-map %q", where, u.SchedulerMap)
		}
	}
	if u.OutputTrafficControlProfile != "" {
		if _, ok := cos.TrafficControlProfiles[u.OutputTrafficControlProfile]; !ok {
			return fmt.Errorf("%s references undefined output-traffic-control-profile %q",
				where, u.OutputTrafficControlProfile)
		}
	}
	if u.DSCPClassifier != "" {
		if _, ok := cos.DSCPClassifiers[u.DSCPClassifier]; !ok {
			return fmt.Errorf("%s references undefined dscp classifier %q", where, u.DSCPClassifier)
		}
	}
	if u.IEEE8021Classifier != "" {
		if _, ok := cos.IEEE8021Classifiers[u.IEEE8021Classifier]; !ok {
			return fmt.Errorf("%s references undefined ieee-802.1 classifier %q", where, u.IEEE8021Classifier)
		}
	}
	// INetPrecedenceClassifiers records NAMES only (#6847), so membership is a
	// slice scan rather than a map lookup — the same asymmetry the warn path has.
	if u.INetPrecedenceClassifier != "" {
		if !slices.Contains(cos.INetPrecedenceClassifiers, u.INetPrecedenceClassifier) {
			return fmt.Errorf("%s references undefined inet-precedence classifier %q",
				where, u.INetPrecedenceClassifier)
		}
	}
	if u.DSCPRewriteRule != "" {
		if _, ok := cos.DSCPRewriteRules[u.DSCPRewriteRule]; !ok {
			return fmt.Errorf("%s references undefined dscp rewrite-rule %q", where, u.DSCPRewriteRule)
		}
	}
	// IEEE8021RewriteRules is modeled but documented inert on this dataplane.
	// A dangling name is still an operator typo and still rejected: the gate is
	// about whether the NAME resolves, not whether the resolved rule has a
	// runtime effect. Gating only the enforced references would make commit
	// behaviour depend on an implementation detail invisible from the config.
	if u.IEEE8021RewriteRule != "" {
		if _, ok := cos.IEEE8021RewriteRules[u.IEEE8021RewriteRule]; !ok {
			return fmt.Errorf("%s references undefined ieee-802.1 rewrite-rule %q",
				where, u.IEEE8021RewriteRule)
		}
	}
	return nil
}

func validateCoSUnitClassifierConflict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	ifaceNames := make([]string, 0, len(cos.Interfaces))
	for name := range cos.Interfaces {
		ifaceNames = append(ifaceNames, name)
	}
	sort.Strings(ifaceNames)
	for _, ifaceName := range ifaceNames {
		iface := cos.Interfaces[ifaceName]
		if iface == nil {
			continue
		}
		unitNums := make([]int, 0, len(iface.Units))
		for unitNum := range iface.Units {
			unitNums = append(unitNums, unitNum)
		}
		sort.Ints(unitNums)
		for _, unitNum := range unitNums {
			unit := iface.Units[unitNum]
			if unit == nil {
				continue
			}
			if unit.DSCPClassifier != "" && unit.INetPrecedenceClassifier != "" {
				return fmt.Errorf(
					"class-of-service interfaces %s unit %d binds both a dscp classifier (%q) "+
						"and an inet-precedence classifier (%q); they classify the same IPv4 "+
						"TOS byte, so bind at most one",
					ifaceName, unitNum, unit.DSCPClassifier, unit.INetPrecedenceClassifier)
			}
		}
	}
	return nil
}

func validateClassOfServiceLossPriorityStrict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	checkEntry := func(kind, ruleName, className, lossPriority string) error {
		if lossPriority == "" {
			return nil
		}
		if _, ok := cosLossPriorityValues[lossPriority]; ok {
			return nil
		}
		return fmt.Errorf(
			"class-of-service %s %q forwarding-class %q has unrecognized loss-priority %q "+
				"(must be one of: low, medium-low, medium-high, high)",
			kind, ruleName, className, lossPriority)
	}

	dscpNames := make([]string, 0, len(cos.DSCPClassifiers))
	for name := range cos.DSCPClassifiers {
		dscpNames = append(dscpNames, name)
	}
	sort.Strings(dscpNames)
	for _, name := range dscpNames {
		classifier := cos.DSCPClassifiers[name]
		if classifier == nil {
			continue
		}
		for _, entry := range classifier.Entries {
			if entry == nil {
				continue
			}
			if err := checkEntry("classifiers dscp", classifier.Name, entry.ForwardingClass, entry.LossPriority); err != nil {
				return err
			}
		}
	}

	ieeeNames := make([]string, 0, len(cos.IEEE8021Classifiers))
	for name := range cos.IEEE8021Classifiers {
		ieeeNames = append(ieeeNames, name)
	}
	sort.Strings(ieeeNames)
	for _, name := range ieeeNames {
		classifier := cos.IEEE8021Classifiers[name]
		if classifier == nil {
			continue
		}
		for _, entry := range classifier.Entries {
			if entry == nil {
				continue
			}
			if err := checkEntry("classifiers ieee-802.1", classifier.Name, entry.ForwardingClass, entry.LossPriority); err != nil {
				return err
			}
		}
	}

	// #6847: the inet-precedence classifier is ENFORCED, so its entries carry
	// a loss-priority to the dataplane exactly as the dscp / ieee-802.1
	// classifiers do. Without this arm a typo (`hgih`) commits CLEAN and the
	// helper's cos_loss_priority_index() falls back to LOW
	// (`unwrap_or(0)` in forwarding_build/cos.rs) — silently wrong drop
	// precedence on the egress rewrite, which is the exact
	// accepted-but-silently-substituted failure this gate family exists to
	// stop and the reason #6847 wired the loss-priority arm at all.
	precNames := make([]string, 0, len(cos.INetPrecedenceClassifierDefs))
	for name := range cos.INetPrecedenceClassifierDefs {
		precNames = append(precNames, name)
	}
	sort.Strings(precNames)
	for _, name := range precNames {
		classifier := cos.INetPrecedenceClassifierDefs[name]
		if classifier == nil {
			continue
		}
		for _, entry := range classifier.Entries {
			if entry == nil {
				continue
			}
			if err := checkEntry("classifiers inet-precedence", classifier.Name, entry.ForwardingClass, entry.LossPriority); err != nil {
				return err
			}
		}
	}

	rewriteNames := make([]string, 0, len(cos.DSCPRewriteRules))
	for name := range cos.DSCPRewriteRules {
		rewriteNames = append(rewriteNames, name)
	}
	sort.Strings(rewriteNames)
	for _, name := range rewriteNames {
		rewriteRule := cos.DSCPRewriteRules[name]
		if rewriteRule == nil {
			continue
		}
		for _, entry := range rewriteRule.Entries {
			if entry == nil {
				continue
			}
			if err := checkEntry("rewrite-rules dscp", rewriteRule.Name, entry.ForwardingClass, entry.LossPriority); err != nil {
				return err
			}
		}
	}

	// #4228 Gap 4: apply the same loss-priority typo gate to ieee-802.1 (PCP)
	// rewrite-rules. Even though the rule is accepted-but-inert, a `medum-low`
	// typo should be surfaced at commit consistently with the dscp rewrite and
	// the classifiers.
	ieeeRewriteNames := make([]string, 0, len(cos.IEEE8021RewriteRules))
	for name := range cos.IEEE8021RewriteRules {
		ieeeRewriteNames = append(ieeeRewriteNames, name)
	}
	sort.Strings(ieeeRewriteNames)
	for _, name := range ieeeRewriteNames {
		rewriteRule := cos.IEEE8021RewriteRules[name]
		if rewriteRule == nil {
			continue
		}
		for _, entry := range rewriteRule.Entries {
			if entry == nil {
				continue
			}
			if err := checkEntry("rewrite-rules ieee-802.1", rewriteRule.Name, entry.ForwardingClass, entry.LossPriority); err != nil {
				return err
			}
		}
	}
	// #11811: these egress rewrite families have no dataplane consumer yet, but
	// their inner config must receive the same strict loss-priority validation
	// as the enforced DSCP and inert 802.1p rewrite rules.
	inetRewriteNames := make([]string, 0, len(cos.INetPrecedenceRewriteRuleDefs))
	for name := range cos.INetPrecedenceRewriteRuleDefs {
		inetRewriteNames = append(inetRewriteNames, name)
	}
	sort.Strings(inetRewriteNames)
	for _, name := range inetRewriteNames {
		rewriteRule := cos.INetPrecedenceRewriteRuleDefs[name]
		if rewriteRule == nil {
			continue
		}
		for _, entry := range rewriteRule.Entries {
			if entry == nil {
				continue
			}
			if err := checkEntry("rewrite-rules inet-precedence", rewriteRule.Name, entry.ForwardingClass, entry.LossPriority); err != nil {
				return err
			}
		}
	}

	expRewriteNames := make([]string, 0, len(cos.EXPRewriteRuleDefs))
	for name := range cos.EXPRewriteRuleDefs {
		expRewriteNames = append(expRewriteNames, name)
	}
	sort.Strings(expRewriteNames)
	for _, name := range expRewriteNames {
		rewriteRule := cos.EXPRewriteRuleDefs[name]
		if rewriteRule == nil {
			continue
		}
		for _, entry := range rewriteRule.Entries {
			if entry == nil {
				continue
			}
			if err := checkEntry("rewrite-rules exp", rewriteRule.Name, entry.ForwardingClass, entry.LossPriority); err != nil {
				return err
			}
		}
	}
	return nil
}

// validateClassOfServiceForwardingClassQueueStrict hard-rejects a
// class-of-service forwarding-class whose queue is outside the accepted
// 0..255 range (#4594). Before this gate the out-of-range queue was
// warn-only (ValidateConfig) and COMMITTED, but the userspace helper
// deserializes the queue id via a checked u8::try_from and fail-closes the
// ENTIRE CoS snapshot on CosQueueIdOutOfRange (#2410) — silently keeping the
// node's STALE CoS forwarding state. The operator sees a committed config that
// is not being enforced (a config/dataplane divergence). Reject it loudly at
// commit / commit-check instead, mirroring the fairness rss-expectation
// queue-range reject in compiler_class_of_service.go and the sibling CoS strict
// gates.
//
// xpf's valid queue range is 0..255 (the dataplane's u8 queue id), NOT the
// Junos-classic 0..7 — see the warn text in compiler_validate_warn.go and the
// CosQueueIdOutOfRange backstop.
//
// On the tolerant load / peer-sync paths the call site downgrades this to a
// warning (opts.lenientCoSForwardingClassQueue) so a config persisted by an
// older binary — which only warned, then committed — or synced from a peer
// still boots (#1960 no-brick); the dataplane's CosQueueIdOutOfRange fail-close
// keeps the stale-but-safe posture on that boot. Forwarding classes are visited
// in sorted order so commit-check surfaces a STABLE first-error message.
func validateClassOfServiceForwardingClassQueueStrict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	names := make([]string, 0, len(cos.ForwardingClasses))
	for name := range cos.ForwardingClasses {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		class := cos.ForwardingClasses[name]
		if class == nil {
			continue
		}
		if class.Queue < 0 || class.Queue > 255 {
			return fmt.Errorf(
				"class-of-service forwarding-class %q uses out-of-range queue %d (expected 0..255)",
				class.Name, class.Queue)
		}
	}
	return nil
}

func validateClassOfServiceStrict(cos *ClassOfServiceConfig) error {
	if cos == nil {
		return nil
	}
	for _, sched := range cos.Schedulers {
		if sched == nil {
			continue
		}
		// #9366: the guarantee must be EXACT and must express SOME rate --
		// but "some rate" is not only the absolute byte field.
		//
		// This gate read `TransmitRateBytes == 0` alone, so
		// `transmit-rate percent <n> exact` and `transmit-rate remainder exact`
		// were REJECTED AT COMMIT: both set `TransmitRateExact = true` and leave
		// `TransmitRateBytes` at 0, because the rate lives in
		// `TransmitRatePercent` / `TransmitRateRemainder`. The error then told
		// the operator to supply the exact transmit rate they had just written
		// as a percentage or a remainder.
		//
		// The gate predates #4228 Gap 2 (percent) and #6846 (remainder), which
		// made both forms first-class, and was not revisited. Three
		// corroborations that this is a defect rather than policy:
		//
		//   - The DATAPLANE resolves both forms. `forwarding_build/cos.rs`
		//     derives `guarantee_enabled` from
		//     `cos_effective_transmit_rate_bytes(...).or_else(remainder)` --
		//     `Some` for percent and for remainder -- then gates
		//     `equal_flow_enforcement` on `guarantee_enabled &&
		//     transmit_rate_exact`. This Go gate was the sole blocker.
		//   - The SCHEMA deliberately admits `exact` trailing a percent operand
		//     (`validateCoSRateTail` / `coSRateSiblingSuppliesValue`).
		//   - `surplus-sharing`, one field away, already accepts the percent
		//     form -- so the asymmetry was not a stated policy.
		//
		// Deliberately still rejected: `equal-flow-enforcement` with no `exact`
		// at all, and with an absolute rate of zero. The feature needs a
		// guarantee to enforce against, and this predicate says which forms
		// express one rather than assuming the absolute field is the only one.
		if sched.EqualFlowEnforcement &&
			(!sched.TransmitRateExact || !schedulerExpressesATransmitRate9366(sched)) {
			return fmt.Errorf(
				"class-of-service scheduler %q equal-flow-enforcement requires a positive "+
					"transmit-rate with `exact` (an absolute rate, `percent <n>`, or "+
					"`remainder`)",
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
		// #4228 Gap 2: transmit-rate accepts EITHER an absolute rate,
		// `percent <n>`, or `remainder`. The schema tailValidator enforces
		// mutual exclusivity on the operator commit path; re-check here so an
		// externally-assembled config (Load / HA SyncApply) cannot smuggle a
		// combination the dataplane would resolve ambiguously. The percent
		// operand range is likewise re-validated (the tail path checks it on
		// commit; a constructed config bypasses it).
		trHead := 0
		if sched.TransmitRateBytes > 0 {
			trHead++
		}
		if sched.TransmitRatePercent > 0 {
			trHead++
		}
		if sched.TransmitRateRemainder {
			trHead++
		}
		if trHead > 1 {
			return fmt.Errorf(
				"class-of-service scheduler %q transmit-rate: set exactly one of an absolute rate, `percent <n>`, or `remainder`",
				sched.Name)
		}
		// Reject non-finite explicitly: NaN compares false to BOTH range bounds,
		// so a constructed/peer-synced config could smuggle a NaN percent past a
		// bare `< 0 || > 100` check (Copilot #4320). Inf is caught by `> 100`,
		// but guard it too for a clear message.
		if math.IsNaN(sched.TransmitRatePercent) || math.IsInf(sched.TransmitRatePercent, 0) ||
			sched.TransmitRatePercent < 0 || sched.TransmitRatePercent > 100 {
			return fmt.Errorf(
				"class-of-service scheduler %q transmit-rate percent %.4g is not a finite value in range (0,100]",
				sched.Name, sched.TransmitRatePercent)
		}
		// The compiler clears unused buffer-size fields, so multiple populated
		// forms indicate a constructed or externally-assembled config. Reject
		// instead of silently applying the runtime's byte-size preference.
		bufferSizeForms := 0
		if sched.BufferSizeBytes > 0 {
			bufferSizeForms++
		}
		if sched.BufferSizePercent > 0 {
			bufferSizeForms++
		}
		if sched.BufferSizeTemporalUS > 0 {
			bufferSizeForms++
		}
		if bufferSizeForms > 1 {
			if sched.BufferSizeBytes > 0 && sched.BufferSizePercent > 0 &&
				sched.BufferSizeTemporalUS == 0 {
				return fmt.Errorf(
					"class-of-service scheduler %q has both buffer-size bytes (%d) "+
						"and buffer-size percent (%.4g%%) set; use one form only",
					sched.Name, sched.BufferSizeBytes, sched.BufferSizePercent)
			}
			return fmt.Errorf(
				"class-of-service scheduler %q has multiple buffer-size forms "+
					"set (bytes=%d, percent=%.4g%%, temporal=%d us); use one form only",
				sched.Name, sched.BufferSizeBytes, sched.BufferSizePercent,
				sched.BufferSizeTemporalUS)
		}
	}
	// #4228 Gap 2: a traffic-control-profile shaping-rate is EITHER an absolute
	// rate or `percent <n>`. The schema tailValidator enforces this on commit;
	// re-check for externally-assembled configs and re-validate the percent
	// operand range.
	for _, tcp := range cos.TrafficControlProfiles {
		if tcp == nil {
			continue
		}
		if tcp.ShapingRateBytes > 0 && tcp.ShapingRatePercent > 0 {
			return fmt.Errorf(
				"class-of-service traffic-control-profiles %q shaping-rate: set exactly one of an absolute rate or `percent <n>`",
				tcp.Name)
		}
		// Reject non-finite explicitly (NaN slips past a bare range check —
		// Copilot #4320).
		if math.IsNaN(tcp.ShapingRatePercent) || math.IsInf(tcp.ShapingRatePercent, 0) ||
			tcp.ShapingRatePercent < 0 || tcp.ShapingRatePercent > 100 {
			return fmt.Errorf(
				"class-of-service traffic-control-profiles %q shaping-rate percent %.4g is not a finite value in range (0,100]",
				tcp.Name, tcp.ShapingRatePercent)
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
	// The Rust scheduler rank parser is deliberately fail-closed for every
	// unknown non-empty priority. Keep the primary strict gate on the typed CoS
	// model so direct compiled-config callers cannot bypass schema validation.
	if err := validateClassOfServiceSchedulerPriorityStrict(cos); err != nil {
		return err
	}
	return nil
}

// schedulerExpressesATransmitRate9366 reports whether the scheduler names a
// transmit rate in ANY of the three first-class forms.
//
// #9366: extracted rather than inlined so each form can be driven directly.
// The predicate this replaces was a single `Bytes == 0` test, which is exactly
// the shape that silently excludes forms added later -- percent (#4228 Gap 2)
// and remainder (#6846) both leave `Bytes` at zero because their value lives in
// a different field. A named predicate makes the omission of a fourth form a
// visible edit here rather than an invisible one at every call site.
//
// This mirrors the dataplane's own resolution order
// (`cos_effective_transmit_rate_bytes(...).or_else(remainder)`); the two must
// agree, or a config the compiler accepts builds a lease the dataplane declines
// to arm, which is the silent direction.
func schedulerExpressesATransmitRate9366(sched *CoSScheduler) bool {
	if sched == nil {
		return false
	}
	return sched.TransmitRateBytes > 0 ||
		sched.TransmitRatePercent > 0 ||
		sched.TransmitRateRemainder
}
