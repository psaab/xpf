package format

// #4228 Gap 7: Junos-style CoS `show` command formatters. These render the
// four vSRX class-of-service operational commands whose backing data already
// exists but had no operational-tree surface:
//
//   - `show interfaces queue [<interface>]`      (from CoSQueueStatus)
//   - `show class-of-service classifier ...`     (from cfg.ClassOfService)
//   - `show class-of-service scheduler-map [n]`  (from cfg.ClassOfService)
//   - `show class-of-service forwarding-class`   (from cfg.ClassOfService)
//   - `show class-of-service rewrite-rule ...`   (from cfg.ClassOfService)
//
// The renderers reuse the shared helpers in cos.go (formatCoSRate,
// formatCoSBytes, emptyDash, yesNo). No dataplane change — the four commands
// are pure presentation over data the config compiler and userspace status
// already carry.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/psaab/xpf/pkg/config"
	userspace "github.com/psaab/xpf/pkg/dataplane/userspace"
)

// FormatInterfacesQueue renders `show interfaces queue [<interface>]` from the
// live userspace CoS runtime snapshot. Junos reports per-egress-queue Queued /
// Transmitted / Dropped counters; xpf sources the equivalent fields from
// CoSQueueStatus (QueuedPackets/Bytes, DrainSentBytes, the admission-drop
// counters aggregated across worker instances by the Rust coordinator). An
// empty selector renders every CoS interface reported by the dataplane.
//
// The renderer distinguishes three states so operator uncertainty is never
// laundered into "no CoS" (#5326):
//
//   - statusErr != nil — the status fetch FAILED (helper down, control socket
//     unavailable, decode error). The CoS runtime state is UNKNOWN, not empty,
//     so surface the error instead of the empty-snapshot message. This upholds
//     the appliance invariant that uncertainty must not render as zero/empty
//     health.
//   - statusErr == nil, empty snapshot — a legitimately empty CoS runtime;
//     render the "No class-of-service queues active" message unchanged.
//   - statusErr == nil, non-empty snapshot — render the per-queue counters.
//
// Callers MUST pass the error returned alongside the status snapshot; a nil
// status with a nil error is still treated as the legitimate empty case.
func FormatInterfacesQueue(status *userspace.ProcessStatus, statusErr error, selector string) string {
	selector = strings.TrimSpace(selector)
	if statusErr != nil {
		if selector == "" {
			return fmt.Sprintf("error retrieving class-of-service queue status: %v\n", statusErr)
		}
		return fmt.Sprintf("error retrieving class-of-service queue status on %s: %v\n", selector, statusErr)
	}
	if status == nil || len(status.CoSInterfaces) == 0 {
		if selector == "" {
			return "No class-of-service queues active\n"
		}
		return fmt.Sprintf("No class-of-service queues active on %s\n", selector)
	}

	ifaces := make([]userspace.CoSInterfaceStatus, 0, len(status.CoSInterfaces))
	for _, iface := range status.CoSInterfaces {
		if selector != "" && !cosInterfaceMatchesSelector(iface.InterfaceName, selector) {
			continue
		}
		ifaces = append(ifaces, iface)
	}
	if len(ifaces) == 0 {
		return fmt.Sprintf("No class-of-service queues active on %s\n", selector)
	}
	sort.Slice(ifaces, func(i, j int) bool { return ifaces[i].InterfaceName < ifaces[j].InterfaceName })

	var b strings.Builder
	for idx, iface := range ifaces {
		if idx > 0 {
			b.WriteString("\n")
		}
		name := iface.InterfaceName
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(&b, "Physical interface: %s\n", name)
		queues := append([]userspace.CoSQueueStatus(nil), iface.Queues...)
		sort.Slice(queues, func(i, j int) bool { return queues[i].QueueID < queues[j].QueueID })
		// vSRX egress-queue space is 3-bit (queue IDs 0..7); report the
		// in-use count against that supported ceiling.
		fmt.Fprintf(&b, "  Egress queues: 8 supported, %d in use\n", len(queues))
		if len(queues) == 0 {
			b.WriteString("  No egress queues\n")
			continue
		}
		for _, q := range queues {
			fmt.Fprintf(&b, "  Queue: %d, Forwarding classes: %s\n", q.QueueID, emptyDash(q.ForwardingClass))
			b.WriteString("    Queued:\n")
			fmt.Fprintf(&b, "      Packets              : %20d\n", q.QueuedPackets)
			fmt.Fprintf(&b, "      Bytes                : %20d\n", q.QueuedBytes)
			b.WriteString("    Transmitted:\n")
			fmt.Fprintf(&b, "      Bytes                : %20d\n", q.DrainSentBytes)
			b.WriteString("    Dropped:\n")
			fmt.Fprintf(&b, "      Buffer-drop packets  : %20d\n", q.AdmissionBufferDrops)
			fmt.Fprintf(&b, "      Flow-share packets   : %20d\n", q.AdmissionFlowShareDrops)
			fmt.Fprintf(&b, "      ECN-marked packets   : %20d\n", q.AdmissionEcnMarked)
		}
	}
	return b.String()
}

// cosInterfaceMatchesSelector matches a runtime CoS interface name against an
// operator-supplied selector, tolerant of the vSRX-style name, its Linux
// kernel name, and a physical-name prefix of a unit-qualified runtime label
// (e.g. selector "ge-0-0-2" matches runtime "ge-0-0-2.80").
func cosInterfaceMatchesSelector(name, selector string) bool {
	if name == "" {
		return false
	}
	if name == selector || config.LinuxIfName(name) == selector {
		return true
	}
	return strings.HasPrefix(name, selector+".") ||
		strings.HasPrefix(config.LinuxIfName(name), selector+".")
}

// FormatCoSClassifiers renders `show class-of-service classifier [name <n>]
// [type <dscp|ieee-802.1>]` from the compiled classifiers. DSCP code points
// render as 6-bit binary and 802.1p PCP as 3-bit binary, matching the vSRX
// "Code point" column. A queue's loss priority defaults to "low" (the Junos
// classifier default) when the config omits it.
// noteUninstalledCoSEntries emits the #6534 annotation for classifier /
// rewrite-rule / scheduler-map entries the userspace snapshot builder SKIPS
// because they name an undefined forwarding-class. Such an object installs a
// PARTIAL table — the listed code points do not classify, and shaping for that
// class degrades to best-effort — while every row above rendered from config
// exactly like an installed one.
//
// The verdict comes from config.CoSForwardingClassUndefined, the same
// predicate the five builder loops in pkg/dataplane/userspace/cos.go consult,
// so this cannot claim something the dataplane disagrees with.
//
// Emitted as a note under the table rather than an extra column so that an
// all-healthy object's output stays byte-identical and the existing golden
// tests keep asserting the same bytes. Nothing is written when every entry
// installs.
func noteUninstalledCoSEntries(b *strings.Builder, cos *config.ClassOfServiceConfig, fcs []string) {
	seen := make(map[string]struct{}, len(fcs))
	var bad []string
	for _, fc := range fcs {
		if !config.CoSForwardingClassUndefined(cos, fc) {
			continue
		}
		if _, dup := seen[fc]; dup {
			continue
		}
		seen[fc] = struct{}{}
		bad = append(bad, fc)
	}
	if len(bad) == 0 {
		return
	}
	sort.Strings(bad)
	for _, fc := range bad {
		fmt.Fprintf(b, "  NOT INSTALLED: entries for forwarding-class %s are skipped "+
			"(no such class under `class-of-service forwarding-classes`)\n", emptyDash(fc))
	}
}

func FormatCoSClassifiers(cfg *config.Config, nameFilter, typeFilter string) string {
	if cfg == nil || cfg.ClassOfService == nil {
		return "No class-of-service classifiers configured\n"
	}
	cos := cfg.ClassOfService
	nameFilter = strings.TrimSpace(nameFilter)
	typeFilter = strings.TrimSpace(strings.ToLower(typeFilter))

	type cpRow struct {
		value uint16
		bits  int
		fc    string
		lp    string
	}
	type classifierBlock struct {
		name   string
		cpType string
		rows   []cpRow
	}
	var blocks []classifierBlock

	if typeFilter == "" || typeFilter == "dscp" {
		for _, name := range sortedMapKeys(cos.DSCPClassifiers) {
			if nameFilter != "" && name != nameFilter {
				continue
			}
			c := cos.DSCPClassifiers[name]
			blk := classifierBlock{name: name, cpType: "dscp"}
			for _, e := range c.Entries {
				for _, dscp := range e.DSCPValues {
					blk.rows = append(blk.rows, cpRow{
						value: uint16(dscp),
						bits:  6,
						fc:    e.ForwardingClass,
						lp:    lossPriorityOrDefault(e.LossPriority),
					})
				}
			}
			blocks = append(blocks, blk)
		}
	}
	if typeFilter == "" || typeFilter == "ieee-802.1" {
		for _, name := range sortedMapKeys(cos.IEEE8021Classifiers) {
			if nameFilter != "" && name != nameFilter {
				continue
			}
			c := cos.IEEE8021Classifiers[name]
			blk := classifierBlock{name: name, cpType: "ieee-802.1"}
			for _, e := range c.Entries {
				for _, cp := range e.CodePoints {
					blk.rows = append(blk.rows, cpRow{
						value: uint16(cp),
						bits:  3,
						fc:    e.ForwardingClass,
						lp:    lossPriorityOrDefault(e.LossPriority),
					})
				}
			}
			blocks = append(blocks, blk)
		}
	}

	// #7080: the third behavior-aggregate classifier. #6847 made
	// `classifiers inet-precedence` a LIVE classifier -- it compiles, crosses
	// the wire as inet_precedence_classifiers, and the dataplane selects the
	// egress queue and loss-priority from the top 3 bits of the DS field -- and
	// no operational command showed any of it. A configured, enforced
	// classifier rendered as "No class-of-service classifiers configured",
	// which is not a gap in detail but a statement that contradicts the running
	// config.
	//
	// Three bits, like ieee-802.1, so the existing cpRow rendering needs no
	// change. The type filter accepts the same token the config uses.
	if typeFilter == "" || typeFilter == "inet-precedence" {
		for _, name := range sortedMapKeys(cos.INetPrecedenceClassifierDefs) {
			if nameFilter != "" && name != nameFilter {
				continue
			}
			c := cos.INetPrecedenceClassifierDefs[name]
			blk := classifierBlock{name: name, cpType: "inet-precedence"}
			for _, e := range c.Entries {
				if e == nil {
					continue
				}
				for _, cp := range e.Precedences {
					blk.rows = append(blk.rows, cpRow{
						value: uint16(cp),
						bits:  3,
						fc:    e.ForwardingClass,
						lp:    lossPriorityOrDefault(e.LossPriority),
					})
				}
			}
			blocks = append(blocks, blk)
		}
	}

	if len(blocks) == 0 {
		if nameFilter != "" || typeFilter != "" {
			return "No class-of-service classifier matches the given filter\n"
		}
		return "No class-of-service classifiers configured\n"
	}

	var b strings.Builder
	for idx, blk := range blocks {
		if idx > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "Classifier: %s, Code point type: %s\n", blk.name, blk.cpType)
		sort.SliceStable(blk.rows, func(i, j int) bool { return blk.rows[i].value < blk.rows[j].value })
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  Code point\tForwarding class\tLoss priority")
		fcs := make([]string, 0, len(blk.rows))
		for _, r := range blk.rows {
			fmt.Fprintf(tw, "  %s\t%s\t%s\n",
				codePointBinary(r.value, r.bits), emptyDash(r.fc), r.lp)
			fcs = append(fcs, r.fc)
		}
		_ = tw.Flush()
		// #6534: both classifier families have a builder skip
		// (pkg/dataplane/userspace/cos.go, the DSCP and IEEE 802.1 loops).
		noteUninstalledCoSEntries(&b, cos, fcs)
	}
	return b.String()
}

// CoSRewriteRuleTypes is the set of `type` filter values FormatCoSRewriteRules
// accepts, in the order rules are rendered. It is exported so the cmdtree
// `type` completion node can be checked against it across the package
// boundary.
//
// It is NOT the SSOT, and the comment that used to say so was false in the
// load-bearing direction (#6858). The family list exists in three places: these
// values, the cmdtree `type` completion children, and the renderer's own
// hardcoded per-family branches below — and nothing in the renderer reads this
// variable, so pinning it against cmdtree alone was a closed loop that a
// deleted renderer branch walked straight through.
//
// The authority is the config schema: schemaClassOfService["rewrite-rules"]
// children in pkg/config/schema_cos.go, which is what an operator can commit.
// pkg/config cannot import this package (format imports config), so the
// three-way check lives in pkg/cmdtree, which can see all of them:
// TestCoSRewriteRuleTypeChildrenMatchRenderer holds these values and the
// completion children against the schema, and
// TestCoSRewriteRuleRendererCoversEverySchemaFamily renders a committed rule of
// every schema family, which is the only way to observe the branches.
var CoSRewriteRuleTypes = []string{"dscp", "ieee-802.1", "inet-precedence", "exp"}

// cosBoundDSCPRewriteRules returns the set of dscp rewrite-rule NAMES that at
// least one logical unit actually binds (#6858 fold), and the set of names that
// are referenced ONLY from a `class-of-service interfaces` stanza naming an
// interface/unit that does not exist under `interfaces` (#6858 round 3).
//
// The traversal deliberately MIRRORS buildInterfaceSnapshots
// (pkg/dataplane/userspace/interfaces.go): that builder walks
// cfg.Interfaces.Interfaces, and for each REAL logical unit looks up
// cfg.ClassOfService.Interfaces[name].Units[unitNum] to stamp
// CoSDSCPRewriteRule onto the snapshot. A class-of-service stanza whose
// interface or unit has no counterpart there is never read, so its binding
// cannot reach the helper.
//
// Walking cos.Interfaces alone — which is what this did before — reported
// "Enforced: yes" for exactly that config, and it commits clean: `set
// class-of-service interfaces ge-9-9-9 unit 0 rewrite-rules dscp rw` with no
// `interfaces ge-9-9-9` stanza produces no warning and no error. A typo in the
// interface name, or a unit number that does not match the logical unit, then
// yields a confidently wrong "this rewrite is being applied" — the dangerous
// direction, and the same failure class the unbound pin above exists to
// prevent, one level in.
//
// Scanning Units and not CoSInterface.Level is still correct: the compiler
// folds an interface-level binding into every configured unit
// (applyCoSInterfaceLevelBindings), and its own doc records that an interface
// with an interface-level binding but NO configured logical unit contributes no
// unit — which is precisely the case that must not report as enforced.
func cosBoundDSCPRewriteRules(cfg *config.Config) (bound map[string]bool, danglingRef, inertRef map[string]string) {
	bound, danglingRef, inertRef = map[string]bool{}, map[string]string{}, map[string]string{}
	if cfg == nil || cfg.ClassOfService == nil {
		return bound, danglingRef, inertRef
	}
	for name, iface := range cfg.Interfaces.Interfaces {
		if iface == nil {
			continue
		}
		cosIface := cfg.ClassOfService.Interfaces[name]
		if cosIface == nil {
			continue
		}
		for unitNum, unit := range iface.Units {
			if unit == nil {
				continue
			}
			cosUnit := cosIface.Units[unitNum]
			if cosUnit == nil || cosUnit.DSCPRewriteRule == "" {
				continue
			}
			// #7063: a binding is not enough. The helper builds the rewrite
			// matrix only over the queues THIS interface materializes
			// (build_cos_iface_config, forwarding_build/cos.rs), so a rule whose
			// forwarding-classes do not intersect them rewrites nothing.
			if !cosRuleTargetsUnitClass(cfg, cosUnit) {
				if _, ok := inertRef[cosUnit.DSCPRewriteRule]; !ok {
					inertRef[cosUnit.DSCPRewriteRule] = fmt.Sprintf("%s unit %d", name, unitNum)
				}
				continue
			}
			bound[cosUnit.DSCPRewriteRule] = true
		}
	}
	// A rule bound anywhere it actually applies is enforced, whatever other
	// interfaces do with it — so a real binding clears an inert note recorded
	// from a different unit. Without this an operator who bound the rule
	// correctly on one interface and pointlessly on another would be told it is
	// not enforced.
	for ruleName := range bound {
		delete(inertRef, ruleName)
	}
	// Second pass: every CoS reference the snapshot builder will NOT read.
	// Recorded so the operator is told WHERE the dead binding is rather than
	// being told the rule is simply unbound, which reads as "you forgot to
	// bind it" when they did bind it — to a name that does not exist.
	for _, name := range sortedMapKeys(cfg.ClassOfService.Interfaces) {
		cosIface := cfg.ClassOfService.Interfaces[name]
		if cosIface == nil {
			continue
		}
		iface := cfg.Interfaces.Interfaces[name]
		for _, unitNum := range sortedIntKeys(cosIface.Units) {
			cosUnit := cosIface.Units[unitNum]
			if cosUnit == nil || cosUnit.DSCPRewriteRule == "" {
				continue
			}
			if iface != nil && iface.Units[unitNum] != nil {
				continue // a real logical unit: counted above
			}
			if _, ok := danglingRef[cosUnit.DSCPRewriteRule]; !ok {
				danglingRef[cosUnit.DSCPRewriteRule] = fmt.Sprintf("%s unit %d", name, unitNum)
			}
		}
	}
	return bound, danglingRef, inertRef
}

// cosRewriteRuleEnforcement renders the `Enforced:` value for one rewrite rule.
//
// There are THREE states, not two, and collapsing the middle one into
// "enforced" is the defect this function exists to prevent (#6858 gate MAJOR):
//
//  1. `dscp` AND bound by some unit — actually applied on egress.
//  2. `dscp` and bound by NOTHING the dataplane will read — configured, but no
//     runtime effect. The rewrite table is populated only for the rule an
//     interface references (`tables.dscp_rewrite_rules.get(&iface.
//     cos_dscp_rewrite_rule)`, forwarding_build/cos.rs), so an unbound rule
//     rewrites nothing. A binding written against an interface or unit that
//     does not exist under `interfaces` is in this state too — it commits
//     clean and the snapshot builder never reads it — and is reported with the
//     reference named, because "not bound" alone reads as "you forgot to bind
//     it" to an operator who did bind it, just to a name with a typo in it.
//  3. Any other code-point type — the dataplane rewrites dscp only. Each
//     carries an accepted-but-inert commit advisory
//     (compiler_validate_warn.go: ieee-802.1 :1360, inet-precedence :1346,
//     exp :1350) that fires ONCE at commit.
//
// State 2 was originally reported as state 1: an unbound rule printed
// "Enforced: yes". That is strictly worse than having no command, because it
// converts an unanswered question into a confidently wrong answer — and it is
// the accepted-but-inert failure class one level in, inside the very command
// written to expose that class.
//
// For an unsupported TYPE the type reason is reported even if the rule also
// happens to be unbound: the type is the dominant, actionable fact, and such a
// rule would not act however it were bound.
//
// A type that starts being enforced must flip here in the SAME change that
// drops its commit advisory, or this command reports a working rewrite as
// inert. That is not left to a comment — see
// TestCoSInertAdvisoryAgreesWithRenderedEnforcement6858, which asserts the
// biconditional over every committable family: the commit emits an
// accepted-but-inert advisory if and only if this function returns the
// unsupported-TYPE reason. Deleting an advisory without flipping this function
// reds, and flipping this function without dropping the advisory reds too.
func cosRewriteRuleEnforcement(cpType string, bound bool, danglingRef, inertRef string) string {
	if cpType != "dscp" {
		return "no (accepted for Junos compatibility; the dataplane rewrites dscp only)"
	}
	if bound {
		return "yes"
	}
	if danglingRef != "" {
		return fmt.Sprintf("no (not bound — class-of-service interfaces %s is not a "+
			"configured logical interface unit)", danglingRef)
	}
	if inertRef != "" {
		return fmt.Sprintf("no (bound on %s, but none of this rule's forwarding-classes "+
			"are materialized there, so the helper builds no rewrite entry)", inertRef)
	}
	return "no (not bound — no interface unit references this rule)"
}

// cosRuleTargetsUnitClass reports whether the unit's DSCP rewrite rule names at
// least one forwarding class the unit will actually materialize.
//
// This MIRRORS `dscp_rewrite_targets_iface_class` in `build_cos_iface_config`
// (`userspace-dp/src/afxdp/forwarding_build/cos.rs`) and must keep agreeing with
// it. #7063 filed this as needing "state the config alone does not carry"; it
// does not. The helper's `iface_classes` is the scheduler-map's resolved classes
// when any resolve, and the synthetic `best-effort` queue when none do — both
// derivable here.
//
// The intersection is SUFFICIENT on its own, which is why no second predicate is
// mirrored. `dscp_rewrite_targets_iface_class` is itself one of the disjuncts of
// `contributes_usable_cos_state`, so a rule that targets a materialized class
// admits the interface by that fact alone; and the matrix loop then finds an
// entry for that class's queue. A rule that targets none is inert either way —
// the interface is dropped, or the matrix comes out empty.
func cosRuleTargetsUnitClass(cfg *config.Config, cosUnit *config.CoSInterfaceUnit) bool {
	rule := cfg.ClassOfService.DSCPRewriteRules[cosUnit.DSCPRewriteRule]
	if rule == nil {
		// An undefined rule name. Not this function's question — the caller's
		// existing dangling/unbound reporting owns it, and answering false here
		// would relabel an undefined rule as an inert one.
		return true
	}
	classes := cosUnitMaterializedClasses(cfg, cosUnit)
	for _, e := range rule.Entries {
		if e != nil && classes[e.ForwardingClass] {
			return true
		}
	}
	return false
}

// cosSyntheticDefaultForwardingClass is the class the helper materializes when a
// unit's scheduler-map resolves no queues (`vec!["best-effort"]`,
// forwarding_build/cos.rs). Named rather than inlined because
// TestCoSSyntheticDefaultClassMatchesRust_7063 parses the Rust for it: the two
// are one wire fact spelled in two languages, and a silent divergence would make
// this command confidently wrong for exactly the interfaces that have no
// scheduler map.
const cosSyntheticDefaultForwardingClass = "best-effort"

// cosUnitMaterializedClasses is the Go reading of the helper's `iface_classes`.
func cosUnitMaterializedClasses(cfg *config.Config, cosUnit *config.CoSInterfaceUnit) map[string]bool {
	out := map[string]bool{}
	if sm := cfg.ClassOfService.SchedulerMaps[cosUnit.SchedulerMap]; sm != nil {
		for className := range sm.Entries {
			// The SHARED #6534 predicate, not a hand-rolled map lookup. The
			// builder skips a scheduler-map entry naming an undefined class at
			// the same call, so a copy here could drift and this command would
			// claim enforcement against a queue the builder never materializes
			// — the exact class of defect #7063 is about. cos_exclusion_reason.go
			// states the one-predicate rule; pkg/showaudit's census enforces it.
			if !config.CoSForwardingClassUndefined(cfg.ClassOfService, className) {
				out[className] = true
			}
		}
	}
	if len(out) == 0 {
		// scheduler_map_resolved_to_queues == false: the helper adds the
		// synthetic default queue, so best-effort IS materialized here.
		out[cosSyntheticDefaultForwardingClass] = true
	}
	return out
}

// FormatCoSRewriteRules renders `show class-of-service rewrite-rule [name <n>]
// [type <t>]` from the compiled config (#6848, #4228 Gap 7 residual).
//
// Four rewrite-rule families are modeled, and they do NOT all carry the same
// depth of data — the renderer must not paper over that:
//
//   - `dscp` and `ieee-802.1` compile to full entry lists
//     (forwarding-class, loss-priority, code-point), so their code points are
//     rendered.
//   - `inet-precedence` and `exp` record only rule NAMES
//     (ClassOfServiceConfig.INetPrecedenceRewriteRules / EXPRewriteRules,
//     #4316) — the compiler builds no runtime structure for them because
//     nothing consumes one. There are no code points to print, and inventing a
//     table for them would imply a fidelity the config does not have, so they
//     render as a name + an explicit "code points not modeled" line.
//
// A nil/empty config yields the Junos-style "no rules configured" line rather
// than an error: an unconfigured rewrite-rule set is a normal state.
func FormatCoSRewriteRules(cfg *config.Config, nameFilter, typeFilter string) string {
	if cfg == nil || cfg.ClassOfService == nil {
		return "No class-of-service rewrite-rules configured\n"
	}
	cos := cfg.ClassOfService
	nameFilter = strings.TrimSpace(nameFilter)
	typeFilter = strings.TrimSpace(strings.ToLower(typeFilter))

	type cpRow struct {
		fc    string
		lp    string
		value uint16
		bits  int
	}
	type ruleBlock struct {
		name   string
		cpType string
		rows   []cpRow
		// modeled is false for the name-only families: the block renders its
		// header and an explanatory line instead of an empty code-point table.
		modeled bool
	}
	var blocks []ruleBlock

	wantType := func(t string) bool { return typeFilter == "" || typeFilter == t }
	wantName := func(n string) bool { return nameFilter == "" || n == nameFilter }

	if wantType("dscp") {
		for _, name := range sortedMapKeys(cos.DSCPRewriteRules) {
			if !wantName(name) {
				continue
			}
			blk := ruleBlock{name: name, cpType: "dscp", modeled: true}
			for _, e := range cos.DSCPRewriteRules[name].Entries {
				if e == nil {
					continue
				}
				blk.rows = append(blk.rows, cpRow{
					fc: e.ForwardingClass, lp: lossPriorityOrDefault(e.LossPriority),
					value: uint16(e.DSCPValue), bits: 6,
				})
			}
			blocks = append(blocks, blk)
		}
	}
	if wantType("ieee-802.1") {
		for _, name := range sortedMapKeys(cos.IEEE8021RewriteRules) {
			if !wantName(name) {
				continue
			}
			blk := ruleBlock{name: name, cpType: "ieee-802.1", modeled: true}
			for _, e := range cos.IEEE8021RewriteRules[name].Entries {
				if e == nil {
					continue
				}
				blk.rows = append(blk.rows, cpRow{
					fc: e.ForwardingClass, lp: lossPriorityOrDefault(e.LossPriority),
					value: uint16(e.PCPValue), bits: 3,
				})
			}
			blocks = append(blocks, blk)
		}
	}
	// Name-only families. Sorted independently so the output order is stable
	// regardless of config-file order (the slices preserve parse order).
	appendNameOnly := func(cpType string, names []string) {
		if !wantType(cpType) {
			return
		}
		sorted := append([]string(nil), names...)
		sort.Strings(sorted)
		for _, name := range sorted {
			if !wantName(name) {
				continue
			}
			blocks = append(blocks, ruleBlock{name: name, cpType: cpType})
		}
	}
	appendNameOnly("inet-precedence", cos.INetPrecedenceRewriteRules)
	appendNameOnly("exp", cos.EXPRewriteRules)

	if len(blocks) == 0 {
		if nameFilter != "" || typeFilter != "" {
			return "No class-of-service rewrite-rule matches the given filter\n"
		}
		return "No class-of-service rewrite-rules configured\n"
	}

	boundDSCP, danglingDSCP, inertDSCP := cosBoundDSCPRewriteRules(cfg)

	var b strings.Builder
	for idx, blk := range blocks {
		if idx > 0 {
			b.WriteString("\n")
		}
		// Say what the operator loses, not just that a flag is off. This line
		// is the whole point of the command: it answers "will this rule act?".
		enforced := cosRewriteRuleEnforcement(blk.cpType, boundDSCP[blk.name],
			danglingDSCP[blk.name], inertDSCP[blk.name])
		fmt.Fprintf(&b, "Rewrite rule: %s, Code point type: %s, Enforced: %s\n",
			blk.name, blk.cpType, enforced)
		if !blk.modeled {
			fmt.Fprintf(&b, "  Code points not modeled — only the rule name is recorded\n")
			continue
		}
		sort.SliceStable(blk.rows, func(i, j int) bool {
			if blk.rows[i].fc != blk.rows[j].fc {
				return blk.rows[i].fc < blk.rows[j].fc
			}
			return blk.rows[i].lp < blk.rows[j].lp
		})
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  Forwarding class\tLoss priority\tCode point")
		fcs := make([]string, 0, len(blk.rows))
		for _, r := range blk.rows {
			fmt.Fprintf(tw, "  %s\t%s\t%s\n",
				emptyDash(r.fc), r.lp, codePointBinary(r.value, r.bits))
			fcs = append(fcs, r.fc)
		}
		_ = tw.Flush()
		// #6534: ONLY the dscp family. The builder publishes and filters
		// DSCPRewriteRules (pkg/dataplane/userspace/cos.go); it never
		// publishes IEEE8021RewriteRules at all, so annotating an
		// ieee-802.1 entry here would claim a per-entry skip that does not
		// happen — a different and larger gap, tracked separately.
		if blk.cpType == "dscp" {
			noteUninstalledCoSEntries(&b, cos, fcs)
		}
	}
	return b.String()
}

// FormatCoSSchedulerMaps renders `show class-of-service scheduler-map [<name>]`
// from the compiled scheduler-maps, resolving each forwarding-class binding to
// its scheduler knobs (transmit rate, priority, buffer, exact) and the queue
// the forwarding class maps to.
func FormatCoSSchedulerMaps(cfg *config.Config, nameFilter string) string {
	if cfg == nil || cfg.ClassOfService == nil || len(cfg.ClassOfService.SchedulerMaps) == 0 {
		return "No class-of-service scheduler-maps configured\n"
	}
	cos := cfg.ClassOfService
	nameFilter = strings.TrimSpace(nameFilter)

	var b strings.Builder
	rendered := 0
	for _, name := range sortedMapKeys(cos.SchedulerMaps) {
		if nameFilter != "" && name != nameFilter {
			continue
		}
		sm := cos.SchedulerMaps[name]
		if rendered > 0 {
			b.WriteString("\n")
		}
		rendered++
		fmt.Fprintf(&b, "Scheduler map: %s\n", name)

		type mapRow struct {
			fc    string
			queue int
			hasQ  bool
		}
		rows := make([]mapRow, 0, len(sm.Entries))
		for fc := range sm.Entries {
			row := mapRow{fc: fc}
			if class := cos.ForwardingClasses[fc]; class != nil {
				row.queue = class.Queue
				row.hasQ = true
			}
			rows = append(rows, row)
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].hasQ != rows[j].hasQ {
				return rows[i].hasQ // configured-queue rows first
			}
			if rows[i].hasQ && rows[i].queue != rows[j].queue {
				return rows[i].queue < rows[j].queue
			}
			return rows[i].fc < rows[j].fc
		})

		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  Forwarding class\tScheduler\tQueue\tPriority\tTransmit rate\tBuffer\tExact")
		for _, row := range rows {
			entry := sm.Entries[row.fc]
			queue := "-"
			if row.hasQ {
				queue = strconv.Itoa(row.queue)
			}
			schedName := "-"
			priority := "-"
			rate := "-"
			buffer := "-"
			exact := "no"
			if entry != nil {
				schedName = emptyDash(entry.Scheduler)
				if sched := cos.Schedulers[entry.Scheduler]; sched != nil {
					if sched.Priority != "" {
						priority = sched.Priority
					}
					rate = formatCoSRate(sched.TransmitRateBytes)
					buffer = formatSchedulerBuffer(sched)
					exact = yesNo(sched.TransmitRateExact)
				}
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				emptyDash(row.fc), schedName, queue, priority, rate, buffer, exact)
		}
		_ = tw.Flush()
		// #6534: a scheduler-map entry naming an undefined forwarding-class is
		// skipped by the builder, so the class is not shaped. The Queue column
		// already renders "-" for it, but a dash reads as "no queue
		// configured", not "this entry is not installed" — state it.
		fcs := make([]string, 0, len(rows))
		for _, row := range rows {
			fcs = append(fcs, row.fc)
		}
		noteUninstalledCoSEntries(&b, cos, fcs)
	}
	if rendered == 0 {
		return fmt.Sprintf("No class-of-service scheduler-map matches %s\n", nameFilter)
	}
	return b.String()
}

// FormatCoSForwardingClasses renders `show class-of-service forwarding-class`
// — the forwarding-class -> queue table. xpf's forwarding-class ID is its
// queue number (the FC<->queue bijection enforced by the compiler), so ID and
// Queue render identically.
func FormatCoSForwardingClasses(cfg *config.Config) string {
	if cfg == nil || cfg.ClassOfService == nil || len(cfg.ClassOfService.ForwardingClasses) == 0 {
		return "No class-of-service forwarding-classes configured\n"
	}
	classes := make([]*config.CoSForwardingClass, 0, len(cfg.ClassOfService.ForwardingClasses))
	for _, c := range cfg.ClassOfService.ForwardingClasses {
		classes = append(classes, c)
	}
	sort.Slice(classes, func(i, j int) bool {
		if classes[i].Queue != classes[j].Queue {
			return classes[i].Queue < classes[j].Queue
		}
		return classes[i].Name < classes[j].Name
	})

	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "Forwarding class\tID\tQueue")
	for _, c := range classes {
		fmt.Fprintf(tw, "%s\t%d\t%d\n", emptyDash(c.Name), c.Queue, c.Queue)
	}
	_ = tw.Flush()
	return b.String()
}

// formatSchedulerBuffer renders a scheduler's buffer sizing for display: an
// explicit byte size, the Junos percent form, or "-" when unset.
func formatSchedulerBuffer(sched *config.CoSScheduler) string {
	if sched == nil {
		return "-"
	}
	if sched.BufferSizeBytes > 0 {
		return formatCoSBytes(sched.BufferSizeBytes)
	}
	if sched.BufferSizePercent > 0 {
		return strconv.FormatFloat(sched.BufferSizePercent, 'f', -1, 64) + "%"
	}
	return "-"
}

// codePointBinary renders a classifier code point as a fixed-width binary
// string (6 bits for DSCP, 3 bits for IP precedence / 802.1p), matching the
// vSRX "Code point" column.
func codePointBinary(value uint16, bits int) string {
	return fmt.Sprintf("%0*b", bits, value)
}

// lossPriorityOrDefault returns the configured loss priority, defaulting to
// "low" (the Junos classifier default) when the config omits it.
func lossPriorityOrDefault(lp string) string {
	if strings.TrimSpace(lp) == "" {
		return "low"
	}
	return lp
}

// sortedIntKeys returns the keys of an int-keyed map in ascending order, so a
// dangling-reference report names the same unit on every run.
func sortedIntKeys[V any](m map[int]V) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	return keys
}

// sortedMapKeys returns the keys of a string-keyed map in sorted order.
func sortedMapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
