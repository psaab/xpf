package daemon

import (
	"go/build"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestReleaseBuildExcludesTheBulkExportFault19115: a release build must not
// contain the #19115 lab fault (faultinject_bulk_export_19115.go).
//
//  1. File selection: with no build tags the package compiles the release
//     twin and ignores the fault; with -tags xpf_faultinject it is the
//     reverse. The second direction is the control: it shows the tag, and
//     nothing else, is what keeps the fault out.
//  2. The build: `make build` adds the tag only through XPF_FAULTINJECT=1,
//     refuses a GOFLAGS that smuggles it in, and `make deb` refuses a fault
//     build whose DEB_VERSION does not say "faultinject".
//  3. Nothing else in the build or packaging recipes names the tag (the
//     `make test-faultinject` recipe runs the fault's cells with it).
func TestReleaseBuildExcludesTheBulkExportFault19115(t *testing.T) {
	const fault, release = "faultinject_bulk_export_19115.go", "faultinject_bulk_export_19115_release.go"
	for _, tc := range []struct {
		tags          []string
		built, ignore string
	}{
		{tags: nil, built: release, ignore: fault},
		{tags: []string{"xpf_faultinject"}, built: fault, ignore: release},
	} {
		ctx := build.Default
		ctx.BuildTags = tc.tags
		pkg, err := ctx.ImportDir(".", 0)
		if err != nil {
			t.Fatalf("list the package with tags %v: %v", tc.tags, err)
		}
		if !slices.Contains(pkg.GoFiles, tc.built) || slices.Contains(pkg.GoFiles, tc.ignore) {
			t.Errorf("#19115: with tags %v the package must compile %s and not %s; it compiles %d files (%s in it: %v; %s in it: %v)",
				tc.tags, tc.built, tc.ignore, len(pkg.GoFiles),
				tc.built, slices.Contains(pkg.GoFiles, tc.built), tc.ignore, slices.Contains(pkg.GoFiles, tc.ignore))
		}
		if !slices.Contains(pkg.IgnoredGoFiles, tc.ignore) {
			t.Errorf("#19115: with tags %v, %s must be excluded by its build constraint", tc.tags, tc.ignore)
		}
	}

	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	mk, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read the Makefile: %v", err)
	}
	makefile := string(mk)
	for _, want := range []string{
		"XPF_GO_BUILD_TAGS := $(if $(filter 1,$(XPF_FAULTINJECT)),-tags xpf_faultinject,)",
		"CGO_ENABLED=0 $(GO) build $(XPF_GO_BUILD_TAGS) -ldflags \"$(LDFLAGS)\" -o $(BINARY) ./cmd/xpfd",
		"case \"$$GOFLAGS\" in *xpf_faultinject*)",
		"case \"$(DEB_VERSION)\" in *faultinject*)",
	} {
		if !strings.Contains(makefile, want) {
			t.Errorf("#19115: the Makefile no longer carries %q; the release build's exclusion of the lab fault is not enforced", want)
		}
	}
	// Every Makefile line that names the tag is one of the guards above (or
	// their comment); anything else could build the fault unmarked.
	for i, line := range strings.Split(makefile, "\n") {
		if !strings.Contains(line, "xpf_faultinject") {
			continue
		}
		trim := strings.TrimSpace(line)
		if strings.HasPrefix(trim, "#") ||
			strings.HasPrefix(trim, "XPF_GO_BUILD_TAGS :=") ||
			strings.Contains(trim, `case "$$GOFLAGS" in *xpf_faultinject*)`) ||
			strings.Contains(trim, `"$(GO)" -tags xpf_faultinject `) {
			continue
		}
		t.Errorf("#19115: Makefile:%d names xpf_faultinject outside the guarded build: %s", i+1, trim)
	}
	for _, rel := range []string{"debian/rules", "scripts/image/bake.py"} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if strings.Contains(string(raw), "xpf_faultinject") || strings.Contains(string(raw), "XPF_FAULTINJECT") {
			t.Errorf("#19115: %s names the lab fault; release packaging must not", rel)
		}
	}
}
