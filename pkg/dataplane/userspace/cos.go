package userspace

import (
	"log/slog"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

func buildClassOfServiceSnapshot(cfg *config.Config) *ClassOfServiceSnapshot {
	if cfg == nil || cfg.ClassOfService == nil {
		return nil
	}
	cos := cfg.ClassOfService
	if len(cos.ForwardingClasses) == 0 && len(cos.DSCPClassifiers) == 0 && len(cos.IEEE8021Classifiers) == 0 && len(cos.INetPrecedenceClassifierDefs) == 0 && len(cos.DSCPRewriteRules) == 0 && len(cos.Schedulers) == 0 && len(cos.SchedulerMaps) == 0 && len(cos.Interfaces) == 0 {
		return nil
	}
	snap := &ClassOfServiceSnapshot{}

	if len(cos.ForwardingClasses) > 0 {
		names := make([]string, 0, len(cos.ForwardingClasses))
		for name := range cos.ForwardingClasses {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.ForwardingClasses = make([]CoSForwardingClassSnapshot, 0, len(names))
		for _, name := range names {
			class := cos.ForwardingClasses[name]
			if class == nil {
				continue
			}
			snap.ForwardingClasses = append(snap.ForwardingClasses, CoSForwardingClassSnapshot{
				Name:  class.Name,
				Queue: class.Queue,
			})
		}
	}

	if len(cos.DSCPClassifiers) > 0 {
		names := make([]string, 0, len(cos.DSCPClassifiers))
		for name := range cos.DSCPClassifiers {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.DSCPClassifiers = make([]CoSDSCPClassifierSnapshot, 0, len(names))
		for _, name := range names {
			classifier := cos.DSCPClassifiers[name]
			if classifier == nil {
				continue
			}
			classifierSnap := CoSDSCPClassifierSnapshot{Name: classifier.Name}
			for _, entry := range classifier.Entries {
				if entry == nil {
					continue
				}
				// #2704: an undefined forwarding-class ref in a DSCP
				// classifier is only a non-fatal commit-time warning
				// (compiler_validate_warn.go). Mirror the #2696/#2409
				// scheduler-map skip+warn so the loss is no longer SILENT
				// (the Rust side already drops unresolvable classifier
				// entries; filtering here keeps the drop visible and the
				// helper drift-backstop a true never-fires guard).
				if config.CoSForwardingClassUndefined(cos, entry.ForwardingClass) {
					slog.Warn("cos dscp-classifier references undefined forwarding-class; skipping entry (classifier partially absent)",
						"classifier", classifier.Name,
						"forwarding_class", entry.ForwardingClass,
					)
					continue
				}
				classifierSnap.Entries = append(classifierSnap.Entries, CoSDSCPClassifierEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					LossPriority:    entry.LossPriority,
					DSCPValues:      append([]uint8(nil), entry.DSCPValues...),
				})
			}
			snap.DSCPClassifiers = append(snap.DSCPClassifiers, classifierSnap)
		}
	}

	if len(cos.IEEE8021Classifiers) > 0 {
		names := make([]string, 0, len(cos.IEEE8021Classifiers))
		for name := range cos.IEEE8021Classifiers {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.IEEE8021Classifiers = make([]CoSIEEE8021ClassifierSnapshot, 0, len(names))
		for _, name := range names {
			classifier := cos.IEEE8021Classifiers[name]
			if classifier == nil {
				continue
			}
			classifierSnap := CoSIEEE8021ClassifierSnapshot{Name: classifier.Name}
			for _, entry := range classifier.Entries {
				if entry == nil {
					continue
				}
				// #2704: same skip+warn for 802.1p classifier entries.
				if config.CoSForwardingClassUndefined(cos, entry.ForwardingClass) {
					slog.Warn("cos ieee-802.1 classifier references undefined forwarding-class; skipping entry (classifier partially absent)",
						"classifier", classifier.Name,
						"forwarding_class", entry.ForwardingClass,
					)
					continue
				}
				classifierSnap.Entries = append(classifierSnap.Entries, CoSIEEE8021ClassifierEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					LossPriority:    entry.LossPriority,
					CodePoints:      append([]uint8(nil), entry.CodePoints...),
				})
			}
			snap.IEEE8021Classifiers = append(snap.IEEE8021Classifiers, classifierSnap)
		}
	}

	// #6847: publish the inet-precedence classifiers. Before this the
	// classifier compiled into INetPrecedenceClassifierDefs and stopped there
	// — nothing crossed the wire, so the dataplane had no table to consult.
	if len(cos.INetPrecedenceClassifierDefs) > 0 {
		names := make([]string, 0, len(cos.INetPrecedenceClassifierDefs))
		for name := range cos.INetPrecedenceClassifierDefs {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.INetPrecedenceClassifiers = make([]CoSINetPrecedenceClassifierSnapshot, 0, len(names))
		for _, name := range names {
			classifier := cos.INetPrecedenceClassifierDefs[name]
			if classifier == nil {
				continue
			}
			classifierSnap := CoSINetPrecedenceClassifierSnapshot{Name: classifier.Name}
			for _, entry := range classifier.Entries {
				if entry == nil {
					continue
				}
				// #2704: same skip+warn as the dscp / ieee-802.1 classifiers —
				// an undefined forwarding-class ref is a commit-time warning,
				// and the Rust builder drops the entry silently, so log it here
				// to keep the loss visible.
				if config.CoSForwardingClassUndefined(cos, entry.ForwardingClass) {
					slog.Warn("cos inet-precedence classifier references undefined forwarding-class; skipping entry (classifier partially absent)",
						"classifier", classifier.Name,
						"forwarding_class", entry.ForwardingClass,
					)
					continue
				}
				classifierSnap.Entries = append(classifierSnap.Entries, CoSINetPrecedenceClassifierEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					LossPriority:    entry.LossPriority,
					Precedences:     append([]uint8(nil), entry.Precedences...),
				})
			}
			snap.INetPrecedenceClassifiers = append(snap.INetPrecedenceClassifiers, classifierSnap)
		}
	}

	if len(cos.DSCPRewriteRules) > 0 {
		names := make([]string, 0, len(cos.DSCPRewriteRules))
		for name := range cos.DSCPRewriteRules {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.DSCPRewriteRules = make([]CoSDSCPRewriteRuleSnapshot, 0, len(names))
		for _, name := range names {
			rewriteRule := cos.DSCPRewriteRules[name]
			if rewriteRule == nil {
				continue
			}
			rewriteSnap := CoSDSCPRewriteRuleSnapshot{Name: rewriteRule.Name}
			for _, entry := range rewriteRule.Entries {
				if entry == nil {
					continue
				}
				// #2704: same skip+warn for DSCP rewrite entries. Without
				// this an undefined-class rewrite crossed the wire and the
				// Rust side only materialized rewrite for classes the
				// interface actually carries, so the rewrite was silently
				// no-op for the undefined class.
				if config.CoSForwardingClassUndefined(cos, entry.ForwardingClass) {
					slog.Warn("cos dscp rewrite-rule references undefined forwarding-class; skipping entry (rewrite absent for class)",
						"rewrite_rule", rewriteRule.Name,
						"forwarding_class", entry.ForwardingClass,
					)
					continue
				}
				rewriteSnap.Entries = append(rewriteSnap.Entries, CoSDSCPRewriteRuleEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					LossPriority:    entry.LossPriority,
					DSCPValue:       entry.DSCPValue,
				})
			}
			snap.DSCPRewriteRules = append(snap.DSCPRewriteRules, rewriteSnap)
		}
	}

	if len(cos.Schedulers) > 0 {
		names := make([]string, 0, len(cos.Schedulers))
		for name := range cos.Schedulers {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.Schedulers = make([]CoSSchedulerSnapshot, 0, len(names))
		for _, name := range names {
			sched := cos.Schedulers[name]
			if sched == nil {
				continue
			}
			schedulerName := sched.Name
			if schedulerName == "" {
				schedulerName = name
			}
			priority := sched.Priority
			if !config.CoSSchedulerPriorityValid(priority) {
				slog.Warn("cos scheduler priority is unknown; emitting the unset low-priority default",
					"scheduler", schedulerName,
					"priority", priority,
					"issue", "#11798",
				)
				priority = ""
			}
			snap.Schedulers = append(snap.Schedulers, CoSSchedulerSnapshot{
				Name:                sched.Name,
				TransmitRateBytes:   sched.TransmitRateBytes,
				TransmitRatePercent: sched.TransmitRatePercent,
				// #6846: carry the two forms that #4228 Gap 2 left
				// accepted-but-inert. Both are resolved per-interface in
				// forwarding_build::cos rather than here, for the same
				// reason percent is: a named scheduler maps onto interfaces
				// with different shaping rates, so the absolute value is a
				// property of the (scheduler, interface) pair.
				TransmitRateRemainder: sched.TransmitRateRemainder,
				TransmitRateExact:     sched.TransmitRateExact,
				Priority:              priority,
				BufferSizeBytes:       sched.BufferSizeBytes,
				BufferSizePercent:     sched.BufferSizePercent,
				BufferSizeTemporalUS:  sched.BufferSizeTemporalUS,
				// #915/#4966: surplus-sharing is a no-op without
				// transmit-rate exact. ValidateConfig warns but no
				// longer strips it (that made validation mutate the
				// config); the effective gate lives here so the
				// runtime never receives the inert flag while the
				// active config keeps the operator's configured intent.
				SurplusSharing:        sched.SurplusSharing && sched.TransmitRateExact,
				EqualFlowEnforcement:  sched.EqualFlowEnforcement,
				EqualFlowTargetPolicy: sched.EqualFlowTargetPolicy,
				CodelTargetNS:         sched.CodelTargetNS,
			})
		}
	}

	if len(cos.SchedulerMaps) > 0 {
		names := make([]string, 0, len(cos.SchedulerMaps))
		for name := range cos.SchedulerMaps {
			names = append(names, name)
		}
		sort.Strings(names)
		snap.SchedulerMaps = make([]CoSSchedulerMapSnapshot, 0, len(names))
		for _, name := range names {
			schedMap := cos.SchedulerMaps[name]
			if schedMap == nil {
				continue
			}
			entryNames := make([]string, 0, len(schedMap.Entries))
			for className := range schedMap.Entries {
				entryNames = append(entryNames, className)
			}
			sort.Strings(entryNames)
			mapSnap := CoSSchedulerMapSnapshot{Name: schedMap.Name}
			for _, className := range entryNames {
				entry := schedMap.Entries[className]
				if entry == nil {
					continue
				}
				// #2409: a scheduler-map entry referencing a forwarding-class
				// that is not defined in `class-of-service forwarding-classes`
				// is only a NON-FATAL warning at commit time
				// (compiler_validate_warn.go; the strict gate rejects only
				// buffer-percent overcommit, not undefined-class refs). So this
				// is a SUPPORTED, committable config shape — not corruption.
				// Skip the undefined entry here (degrade visibly, preserving the
				// historical "install the valid subset" semantics) with a
				// slog.Warn so the loss is no longer SILENT (the #2409
				// complaint was the silence, not the partial install). Keeping
				// the entry OFF THE WIRE means the Rust
				// SchedulerMapUnknownClass hard-error stays a true never-fires
				// drift backstop — it now fires only on a version/snapshot-
				// drifted helper that receives an entry this emitter would have
				// filtered, consistent with the VLAN/TTL/queue/address sites
				// (corruption a valid config never produces).
				if config.CoSForwardingClassUndefined(cos, entry.ForwardingClass) {
					slog.Warn("cos scheduler-map references undefined forwarding-class; skipping entry (degraded shaping)",
						"scheduler_map", schedMap.Name,
						"forwarding_class", entry.ForwardingClass,
					)
					continue
				}
				// A scheduler-map entry naming an undefined scheduler is
				// hard-rejected at strict commit
				// (validateClassOfServiceSchedulerMapRefsStrict) but a
				// leniently-loaded / peer-synced config can still carry it
				// (#1960). Unlike the undefined-forwarding-class case above we
				// KEEP the entry on the wire so the class's queue stays
				// materialized — dropping it would blackhole any traffic a
				// classifier steers to the class's queue. The Rust helper
				// applies the scheduler-unresolved SAFE default (minimal
				// best-effort surplus weight, no guarantee), NOT the fail-open
				// maximum share. Log a breadcrumb so the degraded shaping is
				// visible in the daemon journal.
				if entry.Scheduler != "" {
					if _, ok := cos.Schedulers[entry.Scheduler]; !ok {
						slog.Warn("cos scheduler-map references undefined scheduler; dataplane applies safe best-effort default (degraded shaping)",
							"scheduler_map", schedMap.Name,
							"forwarding_class", entry.ForwardingClass,
							"scheduler", entry.Scheduler,
						)
					}
				}
				mapSnap.Entries = append(mapSnap.Entries, CoSSchedulerMapEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					Scheduler:       entry.Scheduler,
				})
			}
			snap.SchedulerMaps = append(snap.SchedulerMaps, mapSnap)
		}
	}

	return snap
}
