package config

import (
	"fmt"
	"log/slog"
	"reflect"
	"slices"
)

const (
	packedTailGateName18771     = "packedTailGate18771"
	packedTailGateMaxSites18771 = 32
	packedTailGateEnforce18771  = false
)

type packedTailGateSource18771 struct {
	id18771             uint64
	container18771      string
	head18771           string
	identity18771       int
	line18771           int
	column18771         int
	keyIdentity18771    []string
	tailSpan18771       int
	groupLocalPath18771 []string
	inheritedFrom18771  string
	fromGroups18771     []string
}

type packedTailGateFinding18771 struct {
	verdict18771 string
	prose18771   string
}

type packedTailGateRun18771 struct {
	initialOpts18771                compileOpts
	nodeID18771                     *int
	nextID18771                     uint64
	sources18771                    map[uint64]*packedTailGateSource18771
	effective18771                  map[uint64]int
	effectiveOrder18771             []uint64
	effectiveNodes18771             map[*Node]bool
	snapshot18771                   *ConfigTree
	snapshotCount18771              int
	snapshotIdempotent18771         bool
	twinCompilations18771           int
	originalIGPIdentityExcused18771 bool
	twinIGPIdentityExcused18771     bool
}

func newPackedTailGateRun18771(opts compileOpts, nodeID *int) *packedTailGateRun18771 {
	return &packedTailGateRun18771{
		initialOpts18771:    opts,
		nodeID18771:         nodeID,
		sources18771:        make(map[uint64]*packedTailGateSource18771),
		effective18771:      make(map[uint64]int),
		effectiveNodes18771: make(map[*Node]bool),
	}
}

func (r *packedTailGateRun18771) recordPackedTail18771(node *Node, container, head string, identity int, effective bool) {
	if r == nil || node == nil {
		return
	}
	if effective {
		if r.effectiveNodes18771[node] {
			return
		}
		r.effectiveNodes18771[node] = true
		id := node.packedTailSite18771
		if source, ok := r.sources18771[id]; id == 0 || !ok {
			id = 0
		} else {
			if source.inheritedFrom18771 == "" {
				source.inheritedFrom18771 = node.InheritedFrom
			}
			if len(node.fromGroups) > 0 {
				source.fromGroups18771 = append([]string(nil), node.fromGroups...)
			}
			groupOrigin := source.inheritedFrom18771 != "" || len(source.fromGroups18771) > 0 ||
				(len(source.groupLocalPath18771) > 0 && source.groupLocalPath18771[0] == "groups")
			if !groupOrigin && r.effective18771[id] > 0 {
				return
			}
		}
		r.effectiveOrder18771 = append(r.effectiveOrder18771, id)
		if id != 0 {
			r.effective18771[id]++
		}
		return
	}
	if node.packedTailSite18771 == 0 {
		r.nextID18771++
		node.packedTailSite18771 = r.nextID18771
	}
	id := node.packedTailSite18771
	if _, ok := r.sources18771[id]; ok {
		return
	}
	r.sources18771[id] = &packedTailGateSource18771{
		id18771: id, container18771: container, head18771: head,
		identity18771: identity, line18771: node.Line, column18771: node.Column,
		keyIdentity18771:   append([]string(nil), node.Keys[:identity]...),
		tailSpan18771:      len(node.Keys) - identity,
		inheritedFrom18771: node.InheritedFrom,
		fromGroups18771:    append([]string(nil), node.fromGroups...),
	}
}

func normalizeCompactStanzasWithPackedTailGate18771(tree *ConfigTree, run *packedTailGateRun18771) int {
	if tree == nil {
		return 0
	}
	changed := normalizeCompactNodesWithPackedTailGate18771(tree.Children, setSchema, compactNormalizeInScope, run, false, 0, false)
	changed += normalizeElidedSecurityIdentity16296(tree.Children)
	return changed + normalizePackedStaticRouteQualifiedNextHop(tree)
}

func observePackedTailGateEffective18771(tree *ConfigTree, run *packedTailGateRun18771) {
	if tree == nil || run == nil {
		return
	}
	normalizeCompactNodesWithPackedTailGate18771(tree.Children, setSchema, compactNormalizeInScope, run, true, 0, false)
}

func packedTailGateSnapshotPoint18771(tree *ConfigTree, run *packedTailGateRun18771) *ConfigTree {
	if run == nil {
		return nil
	}
	run.snapshot18771 = tree.Clone()
	run.snapshotCount18771++
	var indexPaths func([]*Node, []string)
	indexPaths = func(nodes []*Node, parent []string) {
		for _, node := range nodes {
			if node == nil {
				continue
			}
			path := append(append([]string(nil), parent...), node.Keys...)
			if source := run.sources18771[node.packedTailSite18771]; source != nil && source.groupLocalPath18771 == nil {
				source.groupLocalPath18771 = path
			}
			indexPaths(node.Children, path)
		}
	}
	indexPaths(run.snapshot18771.Children, nil)
	replayed := tree.Clone()
	normalizeCompactStanzas(replayed)
	normalizeImplicitInetFilters9899(replayed)
	mergeDuplicateBlocks9023(replayed)
	if run.initialOpts18771.lenientDuplicatePolicyNames {
		mergeDuplicateNamedInstances(replayed)
	}
	run.snapshotIdempotent18771 = reflect.DeepEqual(tree, replayed)
	return run.snapshot18771
}

func packedTailGateRewriteTwin18771(snapshot *ConfigTree, siteID uint64, braced bool) (*ConfigTree, error) {
	if snapshot == nil || siteID == 0 {
		return nil, fmt.Errorf("packed-tail twin has no source site")
	}
	twin := snapshot.Clone()
	changes := normalizeCompactNodesWithPackedTailGate18771(
		twin.Children, setSchema,
		func(_, _ string) bool { return false },
		nil, false, siteID, !braced)
	if changes != 1 {
		return nil, fmt.Errorf("packed-tail twin rewrite was not site-local")
	}
	return twin, nil
}

func packedTailGateTwinOpts18771(initial compileOpts) compileOpts {
	initial.physicalInterfaces = nil
	initial.zoneQuarantineNames = nil
	initial.nodeID = nil
	initial.igpIdentityExcused16810 = false
	// The one twin re-entry tuple: (packedTailGateEligible18771=false, skipPackedTailGate18771=true).
	initial.packedTailGateEligible18771 = false
	initial.skipPackedTailGate18771 = true
	return initial
}

func packedTailGateDiagEqual18771(configs ...*Config) bool {
	return packedTailGateDiagEqualExcluding18771(configs, configs...)
}

func packedTailGateDiagEqualExcluding18771(exclusions []*Config, configs ...*Config) bool {
	if len(configs) < 2 {
		return true
	}
	excludedProse := make(map[string]bool)
	for _, cfg := range exclusions {
		if cfg == nil {
			continue
		}
		for _, d := range cfg.Diagnostics {
			if d.Gate == packedTailGateName18771 {
				excludedProse[d.Prose] = true
			}
		}
	}
	type diagnosticView struct {
		warnings    []string
		diagnostics []Diagnostic
	}
	views := make([]diagnosticView, len(configs))
	for i, cfg := range configs {
		if cfg == nil {
			continue
		}
		for _, w := range cfg.Warnings {
			if !excludedProse[w] {
				views[i].warnings = append(views[i].warnings, w)
			}
		}
		for _, d := range cfg.Diagnostics {
			if d.Gate != packedTailGateName18771 {
				views[i].diagnostics = append(views[i].diagnostics, d)
			}
		}
	}
	for i := 1; i < len(views); i++ {
		if !slices.Equal(views[0].warnings, views[i].warnings) ||
			!slices.Equal(views[0].diagnostics, views[i].diagnostics) {
			return false
		}
	}
	return true
}

func classifyPackedTailGate18771(original, braced, removed *Config) string {
	if original == nil || braced == nil || removed == nil {
		return "INDETERMINATE"
	}
	obTyped := ConfigFingerprint(original) == ConfigFingerprint(braced)
	orTyped := ConfigFingerprint(original) == ConfigFingerprint(removed)
	all := []*Config{original, braced, removed}
	obDiag := packedTailGateDiagEqualExcluding18771(all, original, braced)
	orDiag := packedTailGateDiagEqualExcluding18771(all, original, removed)
	switch {
	case obTyped && obDiag:
		return "CLEAN"
	case !obTyped && orTyped && orDiag:
		return "DROP"
	default:
		return "PARTIAL"
	}
}

func packedTailGateDerivedEqual18771(a, b *Config, originalIGP, twinIGP bool) bool {
	if originalIGP != twinIGP {
		return false
	}
	if a == nil || b == nil ||
		!reflect.DeepEqual(a.PhysicalInterfaces, b.PhysicalInterfaces) ||
		!reflect.DeepEqual(a.ZoneQuarantineNames, b.ZoneQuarantineNames) {
		return false
	}
	if a.Chassis.Cluster == nil || b.Chassis.Cluster == nil {
		return a.Chassis.Cluster == b.Chassis.Cluster
	}
	return a.Chassis.Cluster.NodeID == b.Chassis.Cluster.NodeID &&
		a.Chassis.Cluster.NodeIDSet == b.Chassis.Cluster.NodeIDSet
}

func (r *packedTailGateRun18771) compileTwin18771(snapshot *ConfigTree, siteID uint64, braced bool) (cfg *Config, err error) {
	r.twinCompilations18771++
	defer func() {
		if recover() != nil {
			cfg = nil
			err = fmt.Errorf("packed-tail twin compile panic")
		}
	}()
	tree, err := packedTailGateRewriteTwin18771(snapshot, siteID, braced)
	if err != nil {
		return nil, err
	}
	opts := packedTailGateTwinOpts18771(r.initialOpts18771)
	if opts.packedTailGateEligible18771 || !opts.skipPackedTailGate18771 {
		return nil, fmt.Errorf("packed-tail twin entry tuple is invalid")
	}
	var twinIGP bool
	cfg, err = compileTreeWithDerivedObserver18771(tree, opts, r.nodeID18771, func(post compileOpts) {
		twinIGP = post.igpIdentityExcused16810
	})
	r.twinIGPIdentityExcused18771 = twinIGP
	return cfg, err
}

func (r *packedTailGateRun18771) nodeLabel18771() string {
	if r.nodeID18771 == nil || *r.nodeID18771 < 0 {
		return "standalone"
	}
	return fmt.Sprintf("node%d", *r.nodeID18771)
}

func (r *packedTailGateRun18771) finding18771(source *packedTailGateSource18771, verdict string) packedTailGateFinding18771 {
	if source == nil {
		return packedTailGateFinding18771{verdict18771: verdict,
			prose18771: fmt.Sprintf("%s %s site unmapped node=%s", packedTailGateName18771, verdict, r.nodeLabel18771())}
	}
	return packedTailGateFinding18771{verdict18771: verdict,
		prose18771: fmt.Sprintf("%s %s site %d pair %s/%s source %d:%d node=%s",
			packedTailGateName18771, verdict, source.id18771, source.container18771,
			source.head18771, source.line18771, source.column18771, r.nodeLabel18771())}
}

func (r *packedTailGateRun18771) adjudicateSite18771(original *Config, source *packedTailGateSource18771) packedTailGateFinding18771 {
	if !r.snapshotIdempotent18771 || r.snapshot18771 == nil {
		return r.finding18771(source, "INDETERMINATE")
	}
	braced, err := r.compileTwin18771(r.snapshot18771, source.id18771, true)
	if err != nil || !packedTailGateDerivedEqual18771(original, braced, r.originalIGPIdentityExcused18771, r.twinIGPIdentityExcused18771) {
		return r.finding18771(source, "INDETERMINATE")
	}
	removed, err := r.compileTwin18771(r.snapshot18771, source.id18771, false)
	if err != nil || !packedTailGateDerivedEqual18771(original, removed, r.originalIGPIdentityExcused18771, r.twinIGPIdentityExcused18771) {
		return r.finding18771(source, "INDETERMINATE")
	}
	return r.finding18771(source, classifyPackedTailGate18771(original, braced, removed))
}

func (r *packedTailGateRun18771) adjudicate18771(original *Config) []packedTailGateFinding18771 {
	if r == nil || original == nil {
		return nil
	}
	unique := make(map[uint64]bool)
	eligible := 0
	for _, id := range r.effectiveOrder18771 {
		if id != 0 && r.effective18771[id] == 1 && !unique[id] {
			unique[id] = true
			eligible++
		}
	}
	findings := make([]packedTailGateFinding18771, 0, len(r.effectiveOrder18771)+1)
	if eligible > packedTailGateMaxSites18771 {
		for _, id := range r.effectiveOrder18771 {
			if id == 0 || r.effective18771[id] > 1 {
				findings = append(findings, r.finding18771(r.sources18771[id], "SKIPPED-PROVENANCE"))
			}
		}
		findings = append(findings, packedTailGateFinding18771{verdict18771: "SKIPPED-CAP",
			prose18771: fmt.Sprintf("%s SKIPPED-CAP sites %d node=%s", packedTailGateName18771, eligible, r.nodeLabel18771())})
	} else {
		seen := make(map[uint64]bool)
		for _, id := range r.effectiveOrder18771 {
			if id == 0 || r.effective18771[id] > 1 {
				findings = append(findings, r.finding18771(r.sources18771[id], "SKIPPED-PROVENANCE"))
				continue
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			findings = append(findings, r.adjudicateSite18771(original, r.sources18771[id]))
		}
	}
	for _, finding := range findings {
		original.Warnings = append(original.Warnings, finding.prose18771)
		original.Diagnostics = append(original.Diagnostics, Diagnostic{Gate: packedTailGateName18771, Prose: finding.prose18771})
		slog.Warn(finding.prose18771, "node", r.nodeLabel18771())
	}
	return findings
}
