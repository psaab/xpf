package dataplane

import (
	"go/ast"
	"go/parser"
	"go/token"

	"github.com/psaab/xpf/pkg/config"
	"testing"
)

// rowProductionSymbol maps each `validationPhases` row to the PRODUCTION
// function whose position inside CompileConfig defines that row's precedence.
//
// Two rows are not a plain compileX call and are mapped deliberately:
//
//   - "zone screen references" -> compileZones. The sweep is hoisted to the TOP
//     of compileZones, so its precedence is compileZones' position, which is
//     first.
//   - "firewall filter protocols" -> compileFirewallFilters. The row runs
//     validateFilterProtocols, a pure check that production performs inside
//     that phase rather than as a call of its own in CompileConfig.
var rowProductionSymbol = map[string]string{
	"zone screen references":    "compileZones",
	"address book":              "compileAddressBook",
	"applications":              "compileApplications",
	"policies":                  "compilePolicies",
	"nat":                       "compileNATWithStaging",
	"static nat":                "compileStaticNAT",
	"nat64":                     "compileNAT64WithStaging",
	"nptv6":                     "compileNPTv6",
	"screen profiles":           "compileScreenProfiles",
	"default policy":            "compileDefaultPolicy",
	"flow timeouts":             "compileFlowTimeouts",
	"firewall filter protocols": "compileFirewallFilters",
	"flow config":               "compileFlowConfig",
}

// TestPrePassRowOrderMatchesCompileConfig_4960 binds the ordering claim against
// PRODUCTION, which is what the claim is about (#6894 r7 C3).
//
// `validationPhases` says it lists phases "in the same order CompileConfig runs
// them". Two earlier guards both failed to bind that:
//
//   - TestValidationPhaseTableMatchesDocumentedCoverage compares the table
//     against a hand-written `want` list. Both are written by the same person in
//     the same round, so they agree with each other and can be wrong together —
//     which is exactly what happened when the zone-screen row sat eighth.
//   - TestPrePassReportsTheSamePhaseProductionWould calls only
//     `validateBeforeMutate`. Moving the TABLE reds it; swapping the production
//     calls in CompileConfig does NOT, because CompileConfig is never on its
//     path. Measured by an independent reviewer, fresh cache.
//
// So neither observed production. This derives the order FROM CompileConfig's
// source — the only artifact the claim refers to — and compares it to the table.
// Swapping two phase calls in CompileConfig reds this; nothing else here does.
func TestPrePassRowOrderMatchesCompileConfig_4960(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "compiler.go", nil, 0)
	if err != nil {
		t.Fatalf("parse compiler.go: %v", err)
	}

	// Every phase symbol we care about, in the order CompileConfig calls them.
	wanted := map[string]bool{}
	for _, sym := range rowProductionSymbol {
		wanted[sym] = true
	}
	var productionOrder []string
	seen := map[string]bool{}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "CompileConfig" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || !wanted[id.Name] || seen[id.Name] {
				return true
			}
			seen[id.Name] = true
			productionOrder = append(productionOrder, id.Name)
			return true
		})
	}

	// FLOOR: if CompileConfig were renamed or the calls reshaped, the scan would
	// find nothing and the comparison below would pass over an empty list.
	if len(productionOrder) != len(rowProductionSymbol) {
		t.Fatalf("derived %d phase calls from CompileConfig, expected %d — the scan "+
			"is not seeing the real call sequence, so it cannot bind the ordering "+
			"claim.\n  derived: %v", len(productionOrder), len(rowProductionSymbol),
			productionOrder)
	}

	table := validationPhases(discardingDataPlane{}, &config.Config{}, newValidationResult())
	if len(table) != len(rowProductionSymbol) {
		t.Fatalf("validationPhases has %d rows but rowProductionSymbol maps %d — a row "+
			"was added or removed without mapping it to the production symbol whose "+
			"position defines its precedence", len(table), len(rowProductionSymbol))
	}

	for i, row := range table {
		sym, ok := rowProductionSymbol[row.name]
		if !ok {
			t.Fatalf("row %d %q has no production symbol mapped — add it to "+
				"rowProductionSymbol so its precedence can be derived from "+
				"CompileConfig rather than asserted", i, row.name)
		}
		if productionOrder[i] != sym {
			t.Errorf("row %d is %q (production %s), but CompileConfig runs %s in that "+
				"position.\n  table:      %v\n  production: %v\n\n"+
				"`validationPhases` claims to list phases in the same order "+
				"CompileConfig runs them. It no longer does, so a config tripping two "+
				"phases is reported by the pre-pass as a DIFFERENT first failure than "+
				"an un-pre-passed apply would have shown, and the operator is pointed "+
				"at the wrong stanza. Reorder the table to match production, or drop "+
				"the ordering claim (#6894 r7 C3).",
				i, row.name, sym, productionOrder[i], rowNames(table), productionOrder)
			return
		}
	}
}

func rowNames(rows []validationPhase) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.name)
	}
	return out
}
