package showaudit

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

// family is one class of fail-closed snapshot exclusion: a config object the
// builder may refuse to install, the pkg/config predicates that carry that
// verdict, and the census of surfaces that render the object.
type family struct {
	// Name is the failure message's subject.
	Name string

	// Collections are substrings of a `for ... range <expr>` expression that
	// identify iteration over this family's config collection, matched after
	// one round of local alias expansion (so `pm := cfg.ForwardingOptions.
	// PortMirroring; for ... range pm.Instances` matches
	// "PortMirroring.Instances").
	Collections []string

	// BuilderPredicates are the pkg/config drop predicates the SNAPSHOT
	// BUILDER consults. TestEveryBuilderDropPredicateIsRegistered6534 asserts
	// the union of these is exactly what pkg/dataplane/userspace calls.
	BuilderPredicates []string

	// SurfacePredicates are the predicates a RENDERER may consult to learn the
	// same verdict. It is a superset of BuilderPredicates wherever the two
	// halves reach the verdict through differently-shaped helpers: source NAT
	// publishes the rule carrying a PoolUnusable marker rather than dropping
	// it, so the builder asks SourceNATPoolUnusableReason while the renderer
	// asks SourceNATPoolDisarmedReason / SourceNATDisarmReasonText.
	SurfacePredicates []string

	// Unannotated is the EXACT census of render functions that iterate this
	// family's collection, emit output, and do NOT reach a surface predicate.
	// Empty means the family is closed. Asserted exactly in both directions:
	// a new lying renderer reds, and so does a repaired one still listed.
	Unannotated []string

	// Successor names the issue tracking a non-empty Unannotated census.
	Successor string
}

// surfacePkgs are the operator-facing render packages: the local CLI, the gRPC
// ShowText server, the REST API, and the two shared formatter packages the
// first three delegate to.
var surfacePkgs = []string{
	"pkg/cli",
	"pkg/grpcapi",
	"pkg/api",
	"pkg/natshow",
	"pkg/dataplane/userspace/format",
}

// builderPkg is the snapshot builder whose exclusions this gate is about.
const builderPkg = "pkg/dataplane/userspace"

// exemptRenderers are functions the collection scan reaches that do not render
// an object's enforcement state to an operator, keyed "<pkg>/<file>:<func>".
//
// Both entries are tab-completion value providers: they iterate the NAT
// rule-sets to offer rule NAMES for the next token. A completion list is not a
// claim that a rule is armed, and annotating one would put "NOT INSTALLED" in
// the middle of a completion menu.
var exemptRenderers = map[string]string{
	"pkg/cli/completion.go:valueProvider":                       "tab-completion name list, not an enforcement render",
	"pkg/grpcapi/server_cluster.go:valueProvider":               "tab-completion name list, not an enforcement render",
	"pkg/api/api.go:allInterfaceNames":                          "#10530 adjacency — internal interface-name lookup emits no zone value",
	"pkg/api/interfaces.go:interfacesHandler":                   "#10531 — REST structured interface wire needs explicit quarantine presence/counters",
	"pkg/api/interfaces.go:writeInterfacesTerse":                "#10530 adjacency — terse text view emits no zone value",
	"pkg/api/nat.go:natPoolStatsHandler":                        "#10531 — REST structured NAT pool wire needs explicit quarantine presence/counters",
	"pkg/api/security.go:zonesHandler":                          "deferred to #10531 — structured-wire quarantine enum/presence and counter truthfulness",
	"pkg/api/sessions.go:buildSessionView":                      "#10531 — REST structured session view needs explicit quarantine disposition",
	"pkg/api/sessions.go:sessionZonePairHandler":                "#10531 — REST structured zone-pair wire needs explicit quarantine disposition",
	"pkg/api/stats.go:ifaceStatsHandler":                        "#10531 — REST structured interface-stats wire needs explicit quarantine presence/counters",
	"pkg/cli/apply.go:syslogZoneNameMap":                        "#10530 adjacency — internal syslog ID map emits no zone text",
	"pkg/cli/cli_show_cluster.go:showChassisClusterStatus":      "#10530 adjacency — cluster status emits counters, not zone identity",
	"pkg/cli/cli_show_flow.go:showFlowSession":                  "#10530 — applied session IDs collapse collisions; text cannot truthfully qualify runtime traffic",
	"pkg/cli/cli_show_flow.go:showTopTalkers":                   "#10530 — applied session IDs collapse collisions; text cannot truthfully qualify runtime traffic",
	"pkg/cli/cli_show_security_log.go:showSecurityLog":          "#10530 — event-time zone names are historical; current config must not rewrite them",
	"pkg/cli/session_filter.go:populateIfaceMaps":               "#10530 adjacency — internal session filter map emits no zone text",
	"pkg/grpcapi/server_helpers.go:allInterfaceNames":           "#10530 adjacency — internal interface-name lookup emits no zone value",
	"pkg/grpcapi/server_nat.go:GetNATDestination":               "#10531 — gRPC structured NAT wire needs explicit quarantine presence/counters",
	"pkg/grpcapi/server_nat.go:GetNATPoolStats":                 "#10531 — gRPC structured NAT wire needs explicit quarantine presence/counters",
	"pkg/grpcapi/server_sessions.go:buildSessionFilter":         "#10530 adjacency — internal session filter emits no zone text",
	"pkg/grpcapi/server_sessions.go:computeZonePairSummary":     "#10531 — gRPC structured zone-pair wire needs explicit quarantine disposition",
	"pkg/grpcapi/server_show_events.go:GetEvents":               "#10531 — gRPC structured event wire needs event-time disposition fields",
	"pkg/grpcapi/server_show_flow.go:showSessionsTop":           "#10530 — applied session IDs collapse collisions; text cannot truthfully qualify runtime traffic",
	"pkg/grpcapi/server_show_interfaces.go:GetInterfaces":       "#10531 — gRPC structured interface wire needs explicit quarantine presence/counters",
	"pkg/grpcapi/server_show_interfaces.go:showInterfacesTerse": "#10530 adjacency — terse text view emits no zone value",
	"pkg/grpcapi/server_show_zones.go:GetZones":                 "deferred to #10531 — structured-wire quarantine enum/presence and counter truthfulness",
	"pkg/grpcapi/server_show_security_text.go:showSecurityLog":  "#10530 — event-time zone names are historical; current config must not rewrite them",
}

var families = []family{
	{
		Name:              "port-mirroring instance",
		Collections:       []string{"PortMirroring.Instances"},
		BuilderPredicates: []string{"PortMirroringInstanceExcludedReason"},
		SurfacePredicates: []string{"PortMirroringInstanceExcludedReason"},
		Unannotated:       nil, // closed by this change
	},
	{
		Name: "class-of-service classifier / rewrite-rule entry",
		Collections: []string{
			"ClassOfService.DSCPClassifiers",
			"ClassOfService.IEEE8021Classifiers",
			"ClassOfService.INetPrecedenceClassifierDefs",
			"ClassOfService.DSCPRewriteRules",
			"ClassOfService.IEEE8021RewriteRules",
		},
		BuilderPredicates: []string{"CoSForwardingClassUndefined"},
		SurfacePredicates: []string{"CoSForwardingClassUndefined"},
		Unannotated:       nil, // closed by #7348
	},
	{
		// #7357 items 3-5, plus the #5830 per-instance case the issue does not
		// list, and #10000's unusable ordinary destination. buildRouteSnapshots
		// drops five classes of static route and the `show routing-options` /
		// `show routing-instances` renderers must not print any of them as
		// installed. Sharpest for `next-table`, whose entire content IS a
		// forwarding decision.
		//
		// This family has TWO builder predicates because one of the five
		// reasons is order-dependent: the kernel caps global next-table leaks
		// at NextTableRuleWindow ip rules, so whether a route falls outside the
		// window depends on how many eligible ones precede it.
		// StaticRouteExcludedReason answers the four per-route causes;
		// StaticRouteExclusions walks the whole config for the fifth.
		Name:        "static route",
		Collections: []string{"RoutingOptions.StaticRoutes", "RoutingOptions.Inet6StaticRoutes"},
		// The builder calls the whole-config map, not the per-route helper:
		// the map owns the order-dependent window, so routing the builder
		// through it is what makes the window a SINGLE implementation.
		BuilderPredicates: []string{"StaticRouteExclusions"},
		SurfacePredicates: []string{"StaticRouteExclusions"},
		Unannotated:       nil, // closed by #7357
	},
	{
		// #6565 row 11 / #7422. Unlike its siblings this family is NOT a
		// lenient-path-only backstop: nothing validates a flow-server port at
		// commit time, so `flow-server 10.0.0.1` with no `port` commits
		// cleanly, is skipped by buildFlowExportSnapshots, and used to render
		// as `Collector: 10.0.0.1` — the `:0` suffix suppressed, so it read as
		// a healthy collector on the default port.
		Name:              "flow-export collector (flow-server)",
		Collections:       []string{"FlowServers"},
		BuilderPredicates: []string{"FlowServerExcludedReason"},
		SurfacePredicates: []string{"FlowServerExcludedReason"},
		Unannotated:       nil, // closed by #7422
	},
	{
		Name:              "static NAT / NPTv6 rule",
		Collections:       []string{"NAT.Static"},
		BuilderPredicates: []string{"StaticNATRuleExcludedReason", "NPTv6ScopeUnsupported"},
		SurfacePredicates: []string{"StaticNATRuleExcludedReason", "NPTv6ScopeUnsupported"},
		Unannotated:       nil, // closed by #7330 — every surface delegates to pkg/natshow
	},
	{
		Name:              "source NAT rule",
		Collections:       []string{"NAT.Source"},
		BuilderPredicates: []string{"SourceNATPoolUnusableReason", "SourceNATRuleExcludedReason"},
		// #7473: `SourceNATRuleNotInstalledReason` is the exported COMPOSITION
		// — which pool map to consult and what to answer when the pool is
		// absent — that pkg/cli, pkg/api and pkg/grpcapi now share instead of
		// each re-deriving. It carries the verdict, so a renderer reaching it
		// is annotated; without it here, moving that composition out of
		// pkg/cli would report three correct renderers as lying.
		SurfacePredicates: []string{"SourceNATPoolUnusableReason", "SourceNATPoolDisarmedReason", "SourceNATDisarmReasonText", "SourceNATRuleNotInstalledReason", "SourceNATRuleExcludedReason"},
		// #7473 closed the CLI text renderers (showNATSourceRuleAll,
		// showNATSourceRuleSet, showNATSourceSummary). What remains is the
		// STRUCTURED half: a JSON or protobuf rule object cannot be fixed by
		// appending a line, it needs a not_installed field, which is a wire
		// surface change; and collectNATPoolMetrics is a third shape again, a
		// Prometheus gauge computed over rules including the disarmed ones.
		// #7473 closed the STRUCTURED half: the JSON and protobuf rule/pool
		// objects now carry `not_installed` / `not_installed_reason` from the
		// same composition the text renderers use.
		//
		// `collectNATPoolMetrics` REMAINS, deliberately. It is a Prometheus
		// gauge, so there is no object to carry a field: its remedy is to omit
		// the sample, which #7473's first half did for `xpf_nat_pool_used_ports`
		// — but the gate cannot see that, because it reaches the verdict only
		// transitively through `SourceNATPoolReportablePorts` and
		// `reachesPredicate` does not follow calls into pkg/config. Registering
		// that helper here WOULD drop the entry, and was rejected: it would
		// delete the guard for the annotation work this surface still owes.
		Unannotated: []string{
			"pkg/api/metrics_nat.go:collectNATPoolMetrics",
		},
		Successor: "#7473",
	},
	{
		Name:              "destination NAT rule",
		Collections:       []string{"NAT.Destination"},
		BuilderPredicates: []string{"DestinationNATRuleExcludedReason"},
		// #7473: plus the exported composition the three surfaces share — see
		// the source family's note.
		SurfacePredicates: []string{"DestinationNATRuleExcludedReason", "DestinationNATRuleNotInstalledReason"},
		// #7473 closed the five CLI text renderers and then the structured
		// half; every destination render surface now consults the verdict.
		Unannotated: nil, // closed by #7473
	},
	{
		// #10490: StableZoneID collisions quarantine the later-sorting zone
		// from the userspace snapshot while cfg.Security.Zones still carries
		// the authored object. Scan both config-backed and compiled ZoneIDs
		// surfaces so either representation cannot silently lie.
		Name:              "security zone",
		Collections:       []string{"Security.Zones", "ZoneIDs"},
		BuilderPredicates: []string{"ZoneQuarantineExclusions"},
		SurfacePredicates: []string{"ZoneQuarantineExclusions", "ZoneQuarantineExcludedReason"},
		Unannotated:       nil, // every remaining census member is annotated or exempted above
	},
}

// dropPredicateName matches the naming family the repo uses for a shared
// fail-closed verdict. The convention is what makes the population
// enumerable, so the gate enforces it rather than trusting it: a builder
// exclusion spelled outside this family has no row and no test.
//
// #7357 added the `*Exclusions` shape, and it is a WIDENING of what this gate
// sees rather than a loosening. Every name matched before is still matched; a
// builder call to a new `*Exclusions` function now also REQUIRES a registry
// row, where previously it would have passed unseen.
//
// The shape exists because one verdict in the static-route family is
// ORDER-DEPENDENT — whether a next-table route falls outside the kernel's
// capped ip-rule window depends on how many eligible routes precede it — so it
// cannot be a `func(x) string` over a single object. A whole-config walk
// returning a per-object map is the only form that can express it, and the
// alternative was to implement the window TWICE (once in the builder's loop,
// once for the renderer) and bind the pair with a test. One implementation the
// gate can see beats two implementations it cannot.
var dropPredicateName = regexp.MustCompile(`(?:Excluded|Unusable|Disarmed)Reason$|Exclusions$|Unsupported$|Undefined$`)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestEveryBuilderDropPredicateIsRegistered6534 is the anti-recurrence gate.
//
// It asserts EXACT equality between the drop predicates pkg/dataplane/userspace
// actually calls and the union of the registry's BuilderPredicates. A new
// fail-closed exclusion wired into the builder therefore cannot land without a
// registry row, and the row forces its author to declare which surfaces render
// the object — which is the step every previous instance of this bug skipped.
//
// Equality, not containment, on purpose: containment would let a row rot in
// place after its predicate was deleted, and a registry describing a predicate
// that no longer exists is worse than no registry, because the family it claims
// to cover would read as covered.
func TestEveryBuilderDropPredicateIsRegistered6534(t *testing.T) {
	pkgs := parsePackage(t, builderPkg)
	called := map[string]bool{}
	for _, fn := range pkgs.order {
		for _, sym := range configCallsIn(pkgs.fset, pkgs.funcs[fn].fd) {
			if dropPredicateName.MatchString(sym) {
				called[sym] = true
			}
		}
	}
	// Non-vacuity. A scan that parsed nothing, or a regexp that stopped
	// matching, would otherwise report an empty set that trivially equals an
	// empty registry and read as "no drift".
	if len(pkgs.order) < 100 {
		t.Fatalf("scan of %s found only %d functions; the gate is not reading the "+
			"builder it claims to audit", builderPkg, len(pkgs.order))
	}
	if len(called) == 0 {
		t.Fatalf("scan of %s found ZERO drop predicates. Either every fail-closed "+
			"exclusion stopped using a shared pkg/config verdict, or "+
			"dropPredicateName no longer matches the naming convention. Both are "+
			"a broken gate, not a clean tree.", builderPkg)
	}

	registered := map[string]bool{}
	for _, f := range families {
		for _, p := range f.BuilderPredicates {
			registered[p] = true
		}
	}

	for _, sym := range sortedKeys(called) {
		if !registered[sym] {
			t.Errorf("pkg/dataplane/userspace calls config.%s to decide a "+
				"fail-closed exclusion, but no #6534 registry row covers it.\n"+
				"Add a family to `families` naming the config collection it "+
				"drops and the surfaces that render it — otherwise the object "+
				"keeps rendering from config as though the dataplane installed "+
				"it, which is the entire defect #6534 exists for.", sym)
		}
	}
	for _, sym := range sortedKeys(registered) {
		if !called[sym] {
			t.Errorf("#6534 registry declares config.%s as a builder drop "+
				"predicate, but no non-test file in %s calls it. Either the "+
				"builder stopped consulting the shared verdict (the two halves "+
				"can now disagree) or the row is stale and must be removed.",
				sym, builderPkg)
		}
	}
}

// TestEveryFamilyHasABuilderAndASurfaceCaller6534 is EXISTENCE closure: the
// weak half, asserted because its absence is unambiguous. A family whose
// predicate no surface consults at all is a builder that knows the object is
// disarmed and an operator who is never told.
//
// This is deliberately NOT the property the class needs — see
// TestSurfaceAnnotationCensusIsExact6534 for guardedness — and it is stated
// separately so a reader cannot mistake one for the other.
func TestEveryFamilyHasABuilderAndASurfaceCaller6534(t *testing.T) {
	builder := parsePackage(t, builderPkg)
	for _, f := range families {
		for _, p := range f.BuilderPredicates {
			if !packageCallsPredicate(builder, p) {
				t.Errorf("%s: no non-test file in %s calls config.%s",
					f.Name, builderPkg, p)
			}
		}
		found := ""
		for _, dir := range surfacePkgs {
			pkg := parsePackage(t, dir)
			for _, p := range f.SurfacePredicates {
				if packageCallsPredicate(pkg, p) {
					found = dir + " -> config." + p
				}
			}
		}
		if found == "" {
			t.Errorf("%s: the builder consults a drop verdict for this object "+
				"and NO surface package does. Every render of a dropped %s is a "+
				"lie the operator has no way to detect.", f.Name, f.Name)
		} else {
			t.Logf("%s: surface caller %s", f.Name, found)
		}
	}
}

// TestSurfaceAnnotationCensusIsExact6534 is GUARDEDNESS closure, and it is the
// test that would have caught cli.showForwardingOptions.
//
// For every family it enumerates the render functions across all surface
// packages — a function that iterates the family's config collection AND emits
// output — and partitions them by whether they reach one of the family's
// surface predicates, directly or through a same-package helper. The
// unannotated partition must equal the registry's declared census EXACTLY.
//
// Both directions matter and they fail for opposite reasons:
//
//   - an unlisted unannotated renderer is a NEW instance of #6534;
//   - a listed renderer that now annotates means the census is describing a
//     defect that no longer exists, which is how a deferral list quietly
//     becomes a permanent allowlist.
func TestSurfaceAnnotationCensusIsExact6534(t *testing.T) {
	for _, f := range families {
		t.Run(strings.ReplaceAll(f.Name, " ", "_"), func(t *testing.T) {
			var population, unannotated []string
			for _, dir := range surfacePkgs {
				pkg := parsePackage(t, dir)
				for _, key := range pkg.order {
					rec := pkg.funcs[key]
					// Population = every non-test function in a surface package
					// that ITERATES this family's config collection. There is
					// deliberately no "and prints text" filter: the REST and
					// gRPC handlers serve the same objects as JSON and protobuf,
					// and a rule serialised without a not-installed field is the
					// same lie as one printed without an annotation. Anything
					// that touches the collection for a non-enforcement reason
					// belongs in exemptRenderers, with the reason written down.
					if !rangesOverAny(pkg.fset, rec.fd, f.Collections) {
						continue
					}
					id := dir + "/" + filepath.Base(rec.file) + ":" + rec.fd.Name.Name
					if _, ok := exemptRenderers[id]; ok {
						continue
					}
					population = append(population, id)
					if !reachesPredicate(pkg, key, f.SurfacePredicates, 3, map[string]bool{}) {
						unannotated = append(unannotated, id)
					}
				}
			}
			sort.Strings(population)
			sort.Strings(unannotated)

			// Non-vacuity, two ways. An empty population means the collection
			// selectors stopped matching and every assertion below is over
			// nothing; a population with no ANNOTATED member means the
			// reachesPredicate detector could be broken-shut and the test could
			// not tell.
			if len(population) < 2 {
				t.Fatalf("found %d render functions for %s (%v). The collection "+
					"selectors %v no longer match this family's renderers, so "+
					"this cell asserts nothing.", len(population), f.Name, population, f.Collections)
			}
			if len(unannotated) == len(population) {
				t.Fatalf("every one of the %d render functions for %s reads as "+
					"unannotated. Either the whole family regressed at once, or "+
					"reachesPredicate is broken and would report a lie as clean.\n"+
					"population: %v", len(population), f.Name, population)
			}

			want := append([]string(nil), f.Unannotated...)
			sort.Strings(want)
			for _, got := range unannotated {
				if !contains(want, got) {
					t.Errorf("%s: %s renders an object the snapshot builder can "+
						"REFUSE TO INSTALL and never consults %v, so a dropped "+
						"object prints as enforced.\nEither annotate it (the "+
						"predicate is already exported and shared with the "+
						"builder) or, if this is genuinely not an enforcement "+
						"surface, add it to exemptRenderers with a reason.",
						f.Name, got, f.SurfacePredicates)
				}
			}
			for _, w := range want {
				if !contains(unannotated, w) {
					if !contains(population, w) {
						t.Errorf("%s: census names %s but no such render function "+
							"was found. It was renamed, moved or deleted; update "+
							"the census so it keeps describing the tree.", f.Name, w)
						continue
					}
					t.Errorf("%s: census names %s as unannotated, but it now "+
						"consults the drop verdict. Remove it from the census — "+
						"a list of known-lying surfaces that outlives the lie is "+
						"an allowlist, and the next unannotated renderer would "+
						"hide inside it.", f.Name, w)
				}
			}
			if len(unannotated) > 0 && f.Successor == "" {
				t.Errorf("%s: %d render functions still do not annotate and the "+
					"registry names no successor issue tracking them: %v",
					f.Name, len(unannotated), unannotated)
			}
			t.Logf("%s: %d render functions, %d annotated, %d not (%s)",
				f.Name, len(population), len(population)-len(unannotated),
				len(unannotated), f.Successor)
		})
	}
}

// TestExemptionsNameRealRenderers6534 keeps the exemption table from outliving
// what it exempts. An exemption for a function that no longer exists is dead
// text that reads, to the next author, as coverage.
func TestExemptionsNameRealRenderers6534(t *testing.T) {
	seen := map[string]bool{}
	for _, dir := range surfacePkgs {
		pkg := parsePackage(t, dir)
		for _, key := range pkg.order {
			rec := pkg.funcs[key]
			seen[dir+"/"+filepath.Base(rec.file)+":"+rec.fd.Name.Name] = true
		}
	}
	if len(seen) < 200 {
		t.Fatalf("surface scan found only %d functions across %v; the gate is "+
			"not reading the packages it claims to audit", len(seen), surfacePkgs)
	}
	for _, id := range sortedKeys(exemptRenderers) {
		if !seen[id] {
			t.Errorf("exemptRenderers names %s (%q) but no such function exists",
				id, exemptRenderers[id])
		}
	}
}

// ---------------------------------------------------------------------------
// Source scanning
//
// Every parse discards comments (parser.ParseFile with mode 0), so no
// assertion in this file can be satisfied by prose — including the prose in
// this file. The gate keys on call expressions and range expressions only.
// ---------------------------------------------------------------------------

type fnRec struct {
	fd   *ast.FuncDecl
	file string
}

type parsedPkg struct {
	fset  *token.FileSet
	funcs map[string]*fnRec
	order []string
}

var pkgCache = map[string]*parsedPkg{}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller(0) failed; cannot locate the repository root")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(self)))
}

func parsePackage(t *testing.T, dir string) *parsedPkg {
	t.Helper()
	if p, ok := pkgCache[dir]; ok {
		return p
	}
	files, err := filepath.Glob(filepath.Join(repoRoot(t), dir, "*.go"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	if len(files) == 0 {
		t.Fatalf("no Go files under %s — the gate's package list is stale", dir)
	}
	sort.Strings(files)
	p := &parsedPkg{fset: token.NewFileSet(), funcs: map[string]*fnRec{}}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(p.fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			key := fd.Name.Name
			if _, dup := p.funcs[key]; dup {
				key = fmt.Sprintf("%s#%d", fd.Name.Name, len(p.order))
			}
			p.funcs[key] = &fnRec{fd: fd, file: path}
			p.order = append(p.order, key)
		}
	}
	pkgCache[dir] = p
	return p
}

// configCallsIn returns the `config.X` selector names called in fd.
func configCallsIn(fset *token.FileSet, fd *ast.FuncDecl) []string {
	var out []string
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		se, ok := ce.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if id, ok := se.X.(*ast.Ident); ok && id.Name == "config" {
			out = append(out, se.Sel.Name)
		}
		return true
	})
	return out
}

func packageCallsPredicate(p *parsedPkg, pred string) bool {
	for _, key := range p.order {
		for _, sym := range configCallsIn(p.fset, p.funcs[key].fd) {
			if sym == pred {
				return true
			}
		}
		// A package may declare the predicate itself (pkg/config) or call it
		// unqualified from within that package.
		if callsUnqualified(p.funcs[key].fd, pred) {
			return true
		}
	}
	return false
}

func callsUnqualified(fd *ast.FuncDecl, name string) bool {
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := ce.Fun.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return true
	})
	return found
}

// reachesPredicate reports whether fn, or a same-package function it calls
// within `depth` hops, consults one of preds. The hop budget exists because
// both shared formatters delegate the verdict to a private helper
// (natshow.staticRuleNotInstalledReason, format.noteUninstalledCoSEntries); a
// direct-call-only check would report those correct renderers as lying.
func reachesPredicate(p *parsedPkg, key string, preds []string, depth int, seen map[string]bool) bool {
	if depth < 0 || seen[key] {
		return false
	}
	seen[key] = true
	rec := p.funcs[key]
	if rec == nil {
		return false
	}
	for _, sym := range configCallsIn(p.fset, rec.fd) {
		for _, pred := range preds {
			if sym == pred {
				return true
			}
		}
	}
	for _, pred := range preds {
		if callsUnqualified(rec.fd, pred) {
			return true
		}
	}
	for _, callee := range calleeNames(rec.fd) {
		if reachesPredicate(p, callee, preds, depth-1, seen) {
			return true
		}
	}
	return false
}

func calleeNames(fd *ast.FuncDecl) []string {
	var out []string
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch f := ce.Fun.(type) {
		case *ast.Ident:
			out = append(out, f.Name)
		case *ast.SelectorExpr:
			out = append(out, f.Sel.Name)
		}
		return true
	})
	return out
}

// rangesOverAny reports whether fd iterates a collection named by any of subs,
// after expanding local aliases: `pm := cfg.ForwardingOptions.PortMirroring`
// followed by `for ... range pm.Instances` must match "PortMirroring.Instances".
func rangesOverAny(fset *token.FileSet, fd *ast.FuncDecl, subs []string) bool {
	alias := map[string]string{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		id, ok := as.Lhs[0].(*ast.Ident)
		if !ok || id.Name == "_" {
			return true
		}
		if _, dup := alias[id.Name]; dup {
			return true // first binding wins; a rebound name is ambiguous
		}
		rhs := exprString(fset, as.Rhs[0])
		// A self-referential binding (x := f(x), x = append(x, ...)) would
		// make the substitution loop grow the string without converging.
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(id.Name) + `\b`).MatchString(rhs) {
			return true
		}
		alias[id.Name] = rhs
		return true
	})
	// Substitution is global, not prefix-only: the shared CoS formatter ranges
	// over `sortedMapKeys(cos.DSCPClassifiers)`, so the alias sits INSIDE a
	// call expression and a prefix-anchored expansion would miss it — and miss
	// it silently, reporting the family as having no renderers at all.
	expand := func(s string) string {
		for i := 0; i < 4; i++ {
			changed := false
			for _, v := range sortedKeys(alias) {
				re := regexp.MustCompile(`\b` + regexp.QuoteMeta(v) + `\.`)
				if next := re.ReplaceAllString(s, alias[v]+"."); next != s {
					s = next
					changed = true
				}
			}
			if !changed {
				break
			}
		}
		return strings.ReplaceAll(strings.ReplaceAll(s, "&", ""), "*", "")
	}
	found := false
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		rs, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		s := expand(exprString(fset, rs.X))
		for _, sub := range subs {
			if strings.Contains(s, sub) {
				found = true
			}
		}
		return true
	})
	return found
}

func exprString(fset *token.FileSet, e ast.Expr) string {
	var b bytes.Buffer
	if err := printer.Fprint(&b, fset, e); err != nil {
		return ""
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
