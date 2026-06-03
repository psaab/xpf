package userspace

import (
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

func buildClassOfServiceSnapshot(cfg *config.Config) *ClassOfServiceSnapshot {
	if cfg == nil || cfg.ClassOfService == nil {
		return nil
	}
	cos := cfg.ClassOfService
	if len(cos.ForwardingClasses) == 0 && len(cos.DSCPClassifiers) == 0 && len(cos.IEEE8021Classifiers) == 0 && len(cos.DSCPRewriteRules) == 0 && len(cos.Schedulers) == 0 && len(cos.SchedulerMaps) == 0 && len(cos.Interfaces) == 0 && cos.FlowRebalance == nil {
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
				classifierSnap.Entries = append(classifierSnap.Entries, CoSIEEE8021ClassifierEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					LossPriority:    entry.LossPriority,
					CodePoints:      append([]uint8(nil), entry.CodePoints...),
				})
			}
			snap.IEEE8021Classifiers = append(snap.IEEE8021Classifiers, classifierSnap)
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
			snap.Schedulers = append(snap.Schedulers, CoSSchedulerSnapshot{
				Name:                 sched.Name,
				TransmitRateBytes:    sched.TransmitRateBytes,
				TransmitRateExact:    sched.TransmitRateExact,
				Priority:             sched.Priority,
				BufferSizeBytes:      sched.BufferSizeBytes,
				BufferSizePercent:    sched.BufferSizePercent,
				SurplusSharing:       sched.SurplusSharing,
				EqualFlowEnforcement: sched.EqualFlowEnforcement,
				CodelTargetNS:        sched.CodelTargetNS,
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
				mapSnap.Entries = append(mapSnap.Entries, CoSSchedulerMapEntrySnapshot{
					ForwardingClass: entry.ForwardingClass,
					Scheduler:       entry.Scheduler,
				})
			}
			snap.SchedulerMaps = append(snap.SchedulerMaps, mapSnap)
		}
	}

	// #1748: forward the opt-in rebalance knob. Presence (even all-zero
	// sub-fields) enables the userspace-dp controller; the Rust side fills
	// zeros with its defaults.
	if cos.FlowRebalance != nil {
		snap.FlowRebalance = &CoSFlowRebalanceSnapshot{
			ImbalanceThresholdPercent: cos.FlowRebalance.ImbalanceThresholdPercent,
			CountDelta:                cos.FlowRebalance.CountDelta,
			RebalanceIntervalSecs:     cos.FlowRebalance.RebalanceIntervalSecs,
			MaxRules:                  cos.FlowRebalance.MaxRules,
		}
	}

	return snap
}
