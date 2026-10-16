package dataplane

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUserspaceXDPShimObjectMatchesSourceManifest is the #4977 source→
// object freshness gate. It recomputes the freshness manifest from the
// working tree and asserts it byte-equals the committed
// userspace_xdp_manifest.json.
//
// A mismatch means the tracked pkg/dataplane/userspace_xdp_bpfel.o and
// the userspace-xdp/** source that produced it are out of lockstep —
// either:
//   - a userspace-xdp/** source or the build recipe changed without a
//     `make generate` (the embedded object is STALE), or
//   - a new *.rs module was added but not regenerated, or
//   - the tracked object changed without refreshing the manifest.
//
// The remedy is always `make generate`, which rebuilds the object
// (verifier-gated) and refreshes the manifest in one step.
func TestUserspaceXDPShimObjectMatchesSourceManifest(t *testing.T) {
	t.Parallel()

	const repoRoot = "../.."

	committedPath := filepath.Join(repoRoot, filepath.FromSlash(UserspaceXDPManifestRelPath))
	committedBytes, err := os.ReadFile(committedPath)
	if err != nil {
		t.Fatalf("read committed manifest %s: %v (run `make generate`)", UserspaceXDPManifestRelPath, err)
	}

	want, err := ComputeUserspaceXDPManifest(repoRoot)
	if err != nil {
		t.Fatalf("recompute manifest from working tree: %v", err)
	}
	wantBytes, err := MarshalUserspaceXDPManifest(want)
	if err != nil {
		t.Fatalf("marshal recomputed manifest: %v", err)
	}

	if want.BuildDigest == "" {
		t.Fatalf("no current verifier-gated build digest for shim inputs; a hand-run of cmd/shim-manifest cannot refresh the gate verdict (run `make generate`)")
	}
	if string(committedBytes) == string(wantBytes) {
		return
	}

	// Drifted: build an operator-actionable diff instead of dumping two
	// blobs. Parse the committed manifest so we can point at the exact
	// input(s) that moved.
	got, perr := parseUserspaceXDPManifest(committedBytes)
	if perr != nil {
		t.Fatalf("committed manifest %s is not valid JSON: %v\nrun `make generate`",
			UserspaceXDPManifestRelPath, perr)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "userspace-xdp shim source is out of lockstep with the tracked object.\n")
	fmt.Fprintf(&b, "The embedded pkg/dataplane/userspace_xdp_bpfel.o may be STALE.\n")
	// The rule, not the fact. This guard was documented as "the manifest hashes
	// the shim sources by content", which is true and does not fire when you
	// need it -- a fact has to be recalled, a rule attached to the action does
	// not. Someone editing ONLY a comment in a shim source reasonably expects
	// no rebuild, and that is exactly the edit that reds here.
	fmt.Fprintf(&b, "This fires on ANY change to a shim source, INCLUDING a comment-only\n")
	fmt.Fprintf(&b, "edit: the manifest hashes these files by content, not by meaning.\n")
	fmt.Fprintf(&b, "Fix: run `make generate` to rebuild the object and refresh %s.\n\n",
		UserspaceXDPManifestRelPath)

	if got.Object.SHA256 != want.Object.SHA256 {
		fmt.Fprintf(&b, "tracked object %s changed but the manifest was not refreshed:\n", want.Object.Path)
		fmt.Fprintf(&b, "  manifest %s\n  actual   %s\n\n", got.Object.SHA256, want.Object.SHA256)
	}

	gotInputs := make(map[string]string, len(got.Inputs))
	for _, e := range got.Inputs {
		gotInputs[e.Path] = e.SHA256
	}
	wantInputs := make(map[string]string, len(want.Inputs))
	for _, e := range want.Inputs {
		wantInputs[e.Path] = e.SHA256
	}

	for _, e := range want.Inputs {
		gh, ok := gotInputs[e.Path]
		switch {
		case !ok:
			fmt.Fprintf(&b, "new build input not in manifest: %s (added without `make generate`)\n", e.Path)
		case gh != e.SHA256:
			fmt.Fprintf(&b, "build input changed: %s\n  manifest %s\n  actual   %s\n", e.Path, gh, e.SHA256)
		}
	}
	for _, e := range got.Inputs {
		if _, ok := wantInputs[e.Path]; !ok {
			fmt.Fprintf(&b, "manifest input no longer present in tree: %s (removed without `make generate`)\n", e.Path)
		}
	}

	// #4555: the emitted shim facts are recomputed from the OBJECT, so they
	// can drift from the committed manifest even when the object and every
	// input hash still match — a hand-edited or tool-corrupted `shim_facts`
	// block is exactly that case. Report it explicitly: without this branch
	// the operator gets the generic "the object may be STALE, run `make
	// generate`" preamble followed by an EMPTY diff, which misdiagnoses the
	// cause and shows nothing. The parity guard in userspace-dp trusts these
	// numbers, so a falsified block is the one way to make it compare
	// stale-fact against stale-fact.
	reportFactDrift(&b, got.ShimFacts, want.ShimFacts)

	t.Fatal(b.String())
}

// TestUserspaceXDPManifestCoversTrackedShimInputs guards the input SET
// itself: the manifest must list the tracked object plus every
// freshness-relevant build input the enumerator finds, with no extras.
// This catches manifest hand-edits that drop or invent entries
// independently of any hash change.
func TestUserspaceXDPManifestCoversTrackedShimInputs(t *testing.T) {
	t.Parallel()

	const repoRoot = "../.."

	committedBytes, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(UserspaceXDPManifestRelPath)))
	if err != nil {
		t.Fatalf("read committed manifest: %v", err)
	}
	got, err := parseUserspaceXDPManifest(committedBytes)
	if err != nil {
		t.Fatalf("parse committed manifest: %v", err)
	}

	if got.Object.Path != userspaceXDPObjectRelPath {
		t.Fatalf("manifest object path = %q, want %q", got.Object.Path, userspaceXDPObjectRelPath)
	}

	wantPaths, err := userspaceXDPFreshnessInputPaths(repoRoot)
	if err != nil {
		t.Fatalf("enumerate freshness inputs: %v", err)
	}
	want := make(map[string]bool, len(wantPaths))
	for _, p := range wantPaths {
		want[p] = true
	}
	gotPaths := make(map[string]bool, len(got.Inputs))
	for _, e := range got.Inputs {
		gotPaths[e.Path] = true
	}

	for p := range want {
		if !gotPaths[p] {
			t.Errorf("freshness input %q missing from manifest (run `make generate`)", p)
		}
	}
	for p := range gotPaths {
		if !want[p] {
			t.Errorf("manifest lists %q which is not a recognized freshness input", p)
		}
	}

	// The build recipe and the Cargo lock/manifest are the highest-value
	// non-source inputs; assert they are present so a future refactor of
	// the fixed-input list cannot silently drop them.
	for _, must := range []string{
		"pkg/dataplane/build-userspace-xdp.sh",
		"userspace-xdp/Cargo.lock",
		"userspace-xdp/Cargo.toml",
		"userspace-xdp/rust-toolchain.toml",
	} {
		if !gotPaths[must] {
			t.Errorf("manifest must cover critical build input %q", must)
		}
	}
}

func TestUserspaceXDPBuildDigestMatchesManifestInputSet13963(t *testing.T) {
	t.Parallel()

	const repoRoot = "../.."
	manifest, err := ComputeUserspaceXDPManifest(repoRoot)
	if err != nil {
		t.Fatalf("compute manifest: %v", err)
	}
	digest, err := UserspaceXDPBuildDigest(repoRoot)
	if err != nil {
		t.Fatalf("compute build digest: %v", err)
	}
	if got := userspaceXDPBuildDigest(manifest.Inputs); got != digest {
		t.Fatalf("manifest input digest = %q, command digest = %q", got, digest)
	}
}

// reportFactDrift appends a description of any #4555 emitted-fact drift.
//
// It reports only the fields that actually moved. An earlier version dumped
// both 512-character `eh_classes` hex strings unconditionally, which buried
// a one-field difference (`max_ext_hdrs=6` vs `7`) between two walls of
// identical hex — the reader could not see what changed.
func reportFactDrift(b *strings.Builder, got, want *ShimFacts) {
	switch {
	case got == nil && want == nil:
		return
	case got == nil:
		fmt.Fprintf(b, "manifest has no shim_facts block (#4555), but the object emits one.\n"+
			"  Run `make generate`; the userspace-dp parity guard needs it.\n")
		return
	case want == nil:
		fmt.Fprintf(b, "manifest carries a shim_facts block (#4555) but the object emits none.\n")
		return
	}

	var diffs []string
	if got.MaxExtHdrs != want.MaxExtHdrs {
		diffs = append(diffs, fmt.Sprintf("  max_ext_hdrs:  manifest %d, object %d", got.MaxExtHdrs, want.MaxExtHdrs))
	}
	if got.FragHdrSize != want.FragHdrSize {
		diffs = append(diffs, fmt.Sprintf("  frag_hdr_size: manifest %d, object %d", got.FragHdrSize, want.FragHdrSize))
	}
	if got.EHClassesHex != want.EHClassesHex {
		gc, gerr := got.EHClasses()
		wc, werr := want.EHClasses()
		if gerr != nil || werr != nil {
			diffs = append(diffs, fmt.Sprintf("  eh_classes:    undecodable (manifest err=%v, object err=%v)", gerr, werr))
		} else {
			var changed []string
			for i := range wc {
				if gc[i] != wc[i] {
					changed = append(changed, fmt.Sprintf("next-header %d: manifest class %d, object class %d", i, gc[i], wc[i]))
				}
			}
			diffs = append(diffs, "  eh_classes:    "+strings.Join(changed, "; "))
		}
	}
	if len(diffs) == 0 {
		return
	}

	fmt.Fprintf(b, "emitted shim facts (#4555) differ from the object's own XPF_SHIM_FACTS:\n")
	for _, d := range diffs {
		fmt.Fprintf(b, "%s\n", d)
	}
	fmt.Fprintf(b, "  The manifest's shim_facts block does not match what the tracked object\n")
	fmt.Fprintf(b, "  actually emits. If the object and inputs above are unchanged, the block was\n")
	fmt.Fprintf(b, "  edited by hand or corrupted — the userspace-dp parity guard trusts these\n")
	fmt.Fprintf(b, "  numbers, so a falsified block is how it would compare stale against stale.\n")
	fmt.Fprintf(b, "  Run `make generate` to restore them from the object.\n")
}
