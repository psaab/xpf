package refactoraudit

// Struct-heterogeneity signal for the modularity audit (#6937).
//
// The LOC heatmap measures one dimension: production file LOC. That
// dimension cannot see field accretion: `Daemon` reached 255 fields inside
// a 1167-LOC file, legitimately under the [WATCH] floor. The struct census
// below adds a second, advisory signal, but undercounts anonymous nesting
// and is not a complete measure of struct heterogeneity.
//
// # Why this counts DISTINCT FIELD TYPES and not fields (#6937)
//
// Field count was the obvious second dimension and it is the wrong one.
// Measured over 1095 named top-level Go structs at b7096f4d1, a
// `fields >= 100` rule flags seven structs and FOUR are false positives:
//
//	347 fields  11 types  xpfCollector             334 of them *prometheus.Desc
//	255 fields 109 types  Daemon                   the real target
//	159 fields   7 types  BindingStatus            protocol DTO
//	151 fields   2 types  compileOpts              99% bool
//	139 fields  34 types  ProcessStatus            protocol DTO
//	135 fields  56 types  SessionSync              the real target
//	104 fields   2 types  statusSummaryAggregates  92% uint64
//
// The TOP hit is `xpfCollector`, ranked above the target the issue was
// filed about — and it is one `*prometheus.Desc` per exported metric,
// with nothing to decompose. A gate whose first row is a false positive
// is ignored, and an ignored gate protects nothing.
//
// The property that separates them is HETEROGENEITY. A god-struct holds
// many different concerns; a legitimate aggregate holds one type repeated.
// `Daemon`'s most common type is `sync.Mutex` at 27 of 255 — twenty-seven
// independently-locked concerns in one struct — against a 109-type tail.
// `xpfCollector` has 11 distinct types and disappears from the ranking.
//
// # Calibration, and the pair that carries it
//
// Thresholds are chosen from the measured distribution, not guessed. Over
// the same 1095 structs, `>= 20` distinct types selects 16 (1.5%) and
// `>= 40` selects 7 (0.6); the existing LOC heatmap lists 50 rows.
//
// The extremes do not calibrate a threshold — the pair astride it does:
//
//	eventengine.Engine      25 fields  20 types   FLAGS   (just over)
//	dataplane.CompileResult 30 fields  19 types   passes  (just under)
//
// Engine has FEWER fields and MORE concerns than CompileResult. That
// single comparison is the whole argument for measuring types rather than
// fields, which is why it is recorded here and not only in the PR.
//
// # Deliberately one-dimensional
//
// A modal-share filter (what fraction of a struct is its single most
// common type) would additionally exclude `ProcessStatus`, a 139-field
// wire DTO that is 57% uint64. It is NOT applied, because at these floors
// it changes exactly one verdict — a parameter fitted to one data point
// rather than calibrated against a population. If a second such case
// appears, add it then, with both cases as its justification, and check it
// does not also drop a true positive.
//
// # Advisory-only: anonymous nesting undercounts by design (#10901)
//
// Each direct anonymous nested `struct { ... }` field counts as ONE
// distinct type — `struct{...}` — regardless of its inner fields;
// multiple such fields share the same token. For example, an outer struct
// with `int` and two nested structs containing many different inner field
// types still reads as 2 types, not the many concerns it contains.
// This collapse is deliberate: counting the printer's multi-line
// rendering inflated the census to "7 structs with >= 100 distinct
// types" when the truth was 1, failing in the alarming direction that gets
// acted on.
// Pinned by TestGoCounterCollapsesAnonymousNestedStructs6937.
//
// This signal is ADVISORY-ONLY: it ranks review candidates; it never
// fails a build. The separate enforced floor is the touched-file LOC gate
// (TestTouchedFileCrossedModularityThreshold), which rejects growth that
// carries a touched file past 1500/2000 LOC. It is not a struct-heterogeneity
// threshold, so this census's anonymous-nesting blind spot remains visible.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Distinct-field-type floors. Mirrored by AUDIT_STRUCT_FLOOR /
// AUDIT_STRUCT_REFACTOR_FLOOR in scripts/refactoring-audit-lib.sh and
// pinned by TestStructFloorsMatchShellConstants6937.
const (
	StructWatchFloor    = 20
	StructRefactorFloor = 40
)

// StructRow is one audited struct.
type StructRow struct {
	Name          string
	Path          string
	Fields        int
	DistinctTypes int
}

// Tag is [REFACTOR] at or above the refactor floor, [WATCH] at or above
// the watch floor, empty below it.
func (r StructRow) Tag() string {
	switch {
	case r.DistinctTypes >= StructRefactorFloor:
		return "[REFACTOR]"
	case r.DistinctTypes >= StructWatchFloor:
		return "[WATCH]"
	default:
		return ""
	}
}

var wsRun = regexp.MustCompile(`\s+`)

// normalizeFieldType renders a field's type as a single-line token.
//
// The collapse of an anonymous nested struct to one opaque token is not
// cosmetic (#6937). `printer.Fprint` renders a nested `struct { ... }`
// across MULTIPLE LINES, and a naive implementation counts each rendering
// as its own distinct type. Measured: that inflated the census to "7 Go
// structs with >= 100 distinct types" when the true count is 1, and it
// produced 92 malformed rows. It fails in the alarming direction, which
// is the direction that gets acted on.
//
// The issue's "not counting nested/anonymous inner fields" reads as an
// aside; it is the trap.
func normalizeFieldType(fset *token.FileSet, expr ast.Expr) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, expr); err != nil {
		return "?"
	}
	t := wsRun.ReplaceAllString(b.String(), " ")
	if strings.HasPrefix(t, "struct {") {
		return "struct{...}"
	}
	return t
}

// GoStructs returns every named top-level struct under root whose path is
// audited, with its field and distinct-type counts.
//
// Only NAMED TOP-LEVEL declarations are walked. An ast.Inspect descent
// would also surface anonymous nested structs as separate "structs",
// which is both out of scope and the other half of the trap above.
func GoStructs(root string, audited func(relPath string) bool) ([]StructRow, error) {
	var rows []StructRow
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || !strings.HasSuffix(p, ".go") {
			return err
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil || !audited(rel) {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", rel, perr)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok || st.Fields == nil {
					continue
				}
				fields, types := 0, map[string]struct{}{}
				for _, fl := range st.Fields.List {
					n := len(fl.Names)
					if n == 0 {
						n = 1 // embedded
					}
					fields += n
					types[normalizeFieldType(fset, fl.Type)] = struct{}{}
				}
				rows = append(rows, StructRow{
					Name: ts.Name.Name, Path: rel,
					Fields: fields, DistinctTypes: len(types),
				})
			}
		}
		return nil
	})
	return rows, err
}

// SortStructRows orders rows for a stable, diffable artifact: most
// distinct types first, then fields, then path/name so the output does
// not move when two structs tie.
func SortStructRows(rows []StructRow) {
	sort.Slice(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.DistinctTypes != b.DistinctTypes {
			return a.DistinctTypes > b.DistinctTypes
		}
		if a.Fields != b.Fields {
			return a.Fields > b.Fields
		}
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		return a.Name < b.Name
	})
}
