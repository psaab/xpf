// Command structaudit emits the #6937 struct-heterogeneity rows for the
// modularity audit.
//
// It takes the exclusion regex and the audited roots as ARGUMENTS rather
// than reimplementing them. scripts/refactoring-audit-lib.sh is the single
// source of truth for "which paths are audited" and a second copy in Go
// would drift from it — which is the exact failure the lib was factored
// out to prevent (#6232/#7253).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/psaab/xpf/pkg/refactoraudit"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("structaudit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	skip := flags.String("skip", "", "AUDIT_SKIP_RE from refactoring-audit-lib.sh (required)")
	goRoots := flags.String("go-roots", "", "AUDIT_ROOTS_GO, space separated")
	rsRoots := flags.String("rs-roots", "", "AUDIT_ROOTS_RS, space separated")
	all := flags.Bool("all", false, "emit every struct, not only those at or above the watch floor")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}

	if *skip == "" {
		fmt.Fprintln(stderr, "structaudit: -skip is required; pass $AUDIT_SKIP_RE so the "+
			"shell lib stays the single source of truth for exclusions")
		return 2
	}
	skipRe, err := regexp.Compile(*skip)
	if err != nil {
		fmt.Fprintf(stderr, "structaudit: bad -skip regex: %v\n", err)
		return 2
	}
	audited := func(rel string) bool { return !skipRe.MatchString(rel) }

	var rows []refactoraudit.StructRow
	collect := func(roots string, fn func(string, func(string) bool) ([]refactoraudit.StructRow, error)) error {
		for _, r := range strings.Fields(roots) {
			if _, statErr := os.Stat(r); statErr != nil {
				return fmt.Errorf("configured root %q is unavailable: %w", r, statErr)
			}
			got, ferr := fn(r, func(rel string) bool { return audited(filepath.Join(r, rel)) })
			if ferr != nil {
				return ferr
			}
			for i := range got {
				got[i].Path = filepath.Join(r, got[i].Path)
			}
			rows = append(rows, got...)
		}
		return nil
	}
	if err := collect(*goRoots, refactoraudit.GoStructs); err != nil {
		fmt.Fprintf(stderr, "structaudit: %v\n", err)
		return 1
	}
	if err := collect(*rsRoots, refactoraudit.RustStructs); err != nil {
		fmt.Fprintf(stderr, "structaudit: %v\n", err)
		return 1
	}

	refactoraudit.SortStructRows(rows)
	for _, r := range rows {
		tag := r.Tag()
		if tag == "" && !*all {
			continue
		}
		if *all && tag == "" {
			tag = "[-]"
		}
		fmt.Fprintf(stdout, "%-12s %4d types  %5d fields  %s.%s\n", tag, r.DistinctTypes, r.Fields, r.Path, r.Name)
	}
	return 0
}
