package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/psaab/xpf/pkg/networkd"
)

// richLink17042 is networkd's full rendering for a RETH member with MTU
// 9000, 10g, full duplex — the content the daemon's stripped copies used
// to overwrite (#17042, R4-Q43-01).
const richLink17042 = "# Managed by xpfd — do not edit\n" +
	"[Match]\nOriginalName=enp8s0\n\n[Link]\nName=ge-0-0-1\n" +
	"MTUBytes=9000\nBitsPerSecond=10000000000\nDuplex=full\nDescription=reth member\n"

// TestBootWriterByteIdenticalToNetworkd17042 pins the B2 acceptance
// shape (#17042 fold): seed networkd's RICH rendering, run the boot
// writer, and the file must be untouched (changed=false) with
// MTUBytes/BitsPerSecond still on disk — the boot writer seeds its
// spec from the on-disk unit instead of stripping it every boot.
func TestBootWriterByteIdenticalToNetworkd17042(t *testing.T) {
	dir := withTempLinkDir(t)
	path := filepath.Join(dir, linkPrefix+"ge-0-0-1.link")
	rich, err := networkd.RenderLink(networkd.LinkSpec{
		Name: "ge-0-0-1", OriginalName: "enp8s0", MTU: 9000, Speed: "10g", Duplex: "full", Description: "reth member",
	})
	if err != nil {
		t.Fatal(err)
	}
	if rich != richLink17042 {
		t.Fatalf("RenderLink rich rendering differs:\n got=%q\nwant=%q", rich, richLink17042)
	}
	if err := os.WriteFile(path, []byte(rich), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := writeLinkFile("ge-0-0-1", "enp8s0")
	if err != nil || changed {
		t.Fatalf("boot writer over networkd RICH rendering = (changed=%v, err=%v), want (false, nil)", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != rich {
		t.Fatalf("boot writer stripped networkd's rich rendering:\n got=%q\nwant=%q (err=%v)", got, rich, err)
	}
	for _, want := range []string{"MTUBytes=9000", "BitsPerSecond=10000000000", "Duplex=full", "Description=reth member"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("boot writer lost %q:\n%s", want, got)
		}
	}

	// A rich unit for a DIFFERENT [Link] Name= must not seed this
	// target: the writer owns the file and rewrites it minimal.
	foreign := strings.Replace(rich, "Name=ge-0-0-1", "Name=ge-0-0-9", 1)
	if err := os.WriteFile(path, []byte(foreign), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err = writeLinkFile("ge-0-0-1", "enp8s0")
	if err != nil || !changed {
		t.Fatalf("boot writer over foreign rich unit = (changed=%v, err=%v), want (true, nil)", changed, err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	minimal, err := networkd.RenderLink(networkd.LinkSpec{Name: "ge-0-0-1", OriginalName: "enp8s0"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != minimal {
		t.Fatalf("boot writer over foreign unit =\n got=%q\nwant minimal %q", got, minimal)
	}
}

// TestWriteLinkFileRefusesMixedUnsafeTargets17042 pins B1: a target that
// mixes a glob/'!' byte with an unsafe byte (space, newline directive
// injection, trailing line-continuation backslash) must be REFUSED —
// the old gate wrote it verbatim through the literal fallback. Pure
// glob/'!' targets stay writable (pinned #10089/#15079 cells).
func TestWriteLinkFileRefusesMixedUnsafeTargets17042(t *testing.T) {
	dir := withTempLinkDir(t)
	for _, tc := range []struct{ name, target string }{
		{"glob plus space", "ge *"},
		{"bang plus space", "!ge 0"},
		{"glob plus trailing backslash", `ge*\`},
		{"glob plus newline injection", "ge*\nDHCP=yes"},
		{"bang plus newline injection", "!ge-0\nDHCP=yes"},
		{"glob plus control byte", "ge*\x010"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrote, err := writeLinkFile(tc.target, "enp9s0")
			if err == nil || wrote {
				t.Fatalf("writeLinkFile(%q) = (%v, %v), want (false, refusal error)", tc.target, wrote, err)
			}
			if !strings.Contains(err.Error(), "#9886") {
				t.Errorf("error must mention #9886, got %v", err)
			}
		})
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("refused mixed targets must leave no files, found %v", entries)
	}
	// Controls: pure glob and pure bang targets remain writable.
	if wrote, err := writeLinkFile("ge*", "enp9s0"); err != nil || !wrote {
		t.Fatalf("pure glob target = (%v, %v), want (true, nil)", wrote, err)
	}
	if wrote, err := writeLinkFile("!ge-0-0-9", "enp9s0"); err != nil || !wrote {
		t.Fatalf("pure bang target = (%v, %v), want (true, nil)", wrote, err)
	}
}

// TestWriteLinkFileGlobTargetPreservesRich17042 pins B2 for the
// fallback arm: a glob target seeded from a rich on-disk unit keeps its
// MTU/speed/duplex/description instead of being stripped to the
// literal Name=/OriginalName= skeleton.
func TestWriteLinkFileGlobTargetPreservesRich17042(t *testing.T) {
	dir := withTempLinkDir(t)
	path := filepath.Join(dir, linkPrefix+"ge*.link")
	seeded := "# Managed by xpfd — do not edit\n[Match]\nOriginalName=enp9s0\n\n[Link]\nName=ge*\nMTUBytes=9000\nBitsPerSecond=10000000000\nDuplex=full\nDescription=reth member\n"
	if err := os.WriteFile(path, []byte(seeded), 0o644); err != nil {
		t.Fatal(err)
	}
	changed, err := writeLinkFile("ge*", "enp9s0")
	if err != nil || changed {
		t.Fatalf("boot writer over rich glob unit = (changed=%v, err=%v), want (false, nil)", changed, err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != seeded {
		t.Fatalf("glob boot writer stripped rich unit:\n got=%q\nwant=%q (err=%v)", got, seeded, err)
	}
}

// TestRethRenamePathPreservesRichLink17042 pins the second acceptance
// shape: seed a MAC-form rich file (the shape ensureRethLinkOriginalName
// exists to fix), run the RETH rename paths, and MTUBytes/BitsPerSecond
// must still be on disk — only the match line changes.
func TestRethRenamePathPreservesRichLink17042(t *testing.T) {
	dir := withTempLinkDir(t)
	path := filepath.Join(dir, linkPrefix+"ge-0-0-1.link")
	macForm := strings.Replace(richLink17042, "OriginalName=enp8s0", "MACAddress=52:54:00:aa:bb:cc", 1)

	// ensure path: derives the kernel name via the seam.
	saved := deriveKernelNameFn
	deriveKernelNameFn = func(string) string { return "enp8s0" }
	t.Cleanup(func() { deriveKernelNameFn = saved })
	if err := os.WriteFile(path, []byte(macForm), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureRethLinkOriginalName("ge-0-0-1"); err != nil {
		t.Fatalf("ensureRethLinkOriginalName: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != richLink17042 {
		t.Fatalf("RETH ensure downgraded the rich unit:\n got=%q\nwant=%q", got, richLink17042)
	}

	// fix path (rename recovery): same preservation.
	if err := os.WriteFile(path, []byte(macForm), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fixRethLinkFile("ge-0-0-1", "enp8s0"); err != nil {
		t.Fatalf("fixRethLinkFile: %v", err)
	}
	got, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != richLink17042 {
		t.Fatalf("RETH fix downgraded the rich unit:\n got=%q\nwant=%q", got, richLink17042)
	}
	for _, want := range []string{"MTUBytes=9000", "BitsPerSecond=10000000000", "OriginalName=enp8s0"} {
		if !strings.Contains(string(got), want) {
			t.Errorf("RETH rewrite lost %q:\n%s", want, got)
		}
	}

	// Already-OriginalName rich file: neither path touches it.
	if err := os.WriteFile(path, []byte(richLink17042), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ensureRethLinkOriginalName("ge-0-0-1"); err != nil {
		t.Fatal(err)
	}
	if err := fixRethLinkFile("ge-0-0-1", "enp8s0"); err != nil {
		t.Fatal(err)
	}
	got, _ = os.ReadFile(path)
	if string(got) != richLink17042 {
		t.Fatalf("OriginalName rich file was downgraded:\n got=%q\nwant=%q", got, richLink17042)
	}
}

// TestRethLinkWriteFailureReturnsError17042 pins the fail-closed error
// policy: a blocked .link path makes the RETH path return an error (the
// old fixRethLinkFile only logged a WARN and returned nothing). The
// apply caller joins this into Phase.Networkd (daemon_apply_dataplane.go).
func TestRethLinkWriteFailureReturnsError17042(t *testing.T) {
	dir := withTempLinkDir(t)
	path := filepath.Join(dir, linkPrefix+"ge-0-0-1.link")
	// Block the atomic write: a directory where the file belongs, so the
	// missing-file arm's writeLinkFile write fails.
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fixRethLinkFile("ge-0-0-1", "enp8s0"); err == nil {
		t.Fatal("fixRethLinkFile over a blocked .link path must return an error, got nil (Warn-only policy)")
	}
}

// TestRethLinkRefusalsReturnErrors17042 pins that refusals are errors and
// write nothing, for both RETH entry points.
func TestRethLinkRefusalsReturnErrors17042(t *testing.T) {
	dir := withTempLinkDir(t)
	path := filepath.Join(dir, linkPrefix+"ge-0-0-3.link")
	macForm := strings.Replace(richLink17042, "OriginalName=enp8s0", "MACAddress=52:54:00:aa:bb:cc", 1)
	macForm = strings.Replace(macForm, "Name=ge-0-0-1", "Name=ge-0-0-3", 1)
	if err := os.WriteFile(path, []byte(macForm), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, kernelName := range []string{"ge*", "!enp9s0", "enp 9s0"} {
		if err := fixRethLinkFile("ge-0-0-3", kernelName); err == nil {
			t.Errorf("fixRethLinkFile(kernelName=%q) = nil, want refusal error", kernelName)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != macForm {
			t.Errorf("refused kernelName %q changed the file: got=%q err=%v", kernelName, got, err)
		}
	}
}

// TestRethEnsureErrorJoinsPhaseNetworkd17042 drives the real
// applyConfigLocked: a MAC-form .link whose rewrite is refused (the
// derived kernel name carries a glob) must fail the apply — the error
// reaches the caller through Phase.Networkd, not a Warn log. Hermetic:
// fake netlink ops, fake networkctl, temp linkDir.
func TestRethEnsureErrorJoinsPhaseNetworkd17042(t *testing.T) {
	dir := withTempLinkDir(t)
	var events []string
	withRethOps(t, newRecordingRethOps(t, &events, virtMAC5103, false))
	d, _ := rethCallsiteDaemon(t, nil)

	path := filepath.Join(dir, linkPrefix+"ge-0-0-1.link")
	macForm := strings.Replace(richLink17042, "OriginalName=enp8s0", "MACAddress=52:54:00:aa:bb:cc", 1)
	if err := os.WriteFile(path, []byte(macForm), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := deriveKernelNameFn
	deriveKernelNameFn = func(string) string { return "enp*" }
	t.Cleanup(func() { deriveKernelNameFn = saved })

	err := d.applyConfigLocked(context.Background(), rethCallsiteConfig())
	if err == nil {
		t.Fatal("apply over a refused RETH .link rewrite reported success; the refusal never reached Phase.Networkd")
	}
	if !strings.Contains(err.Error(), "#10089") {
		t.Fatalf("apply error must carry the glob refusal, got %v", err)
	}
	got, rerr := os.ReadFile(path)
	if rerr != nil || string(got) != macForm {
		t.Fatalf("refused rewrite changed the file: got=%q err=%v", got, rerr)
	}
}

// TestPreserveLinkFieldsSectionScoped17042 pins B3: preserveLinkFields
// rewrites EVERY [Match] MACAddress= line (not first-match only) and
// leaves a [Link] MACAddress= directive untouched — the old
// section-blind first-match rewrite could corrupt a [Link] directive
// and strand later [Match] MAC lines.
func TestPreserveLinkFieldsSectionScoped17042(t *testing.T) {
	multi := "# Managed by xpfd — do not edit\n" +
		"[Match]\nMACAddress=52:54:00:aa:bb:cc\nMACAddress=52:54:00:aa:bb:dd\n" +
		"\n[Link]\nName=ge-0-0-1\nMACAddress=52:54:00:11:22:33\nMTUBytes=9000\n"
	got, err := preserveLinkFields(multi, "enp8s0")
	if err != nil {
		t.Fatalf("preserveLinkFields(multi): %v", err)
	}
	want := "# Managed by xpfd — do not edit\n" +
		"[Match]\nOriginalName=enp8s0\nOriginalName=enp8s0\n" +
		"\n[Link]\nName=ge-0-0-1\nMACAddress=52:54:00:11:22:33\nMTUBytes=9000\n"
	if got != want {
		t.Fatalf("section-scoped rewrite differs:\n got=%q\nwant=%q", got, want)
	}
	if err := validatePreservedLink(got, "ge-0-0-1", "enp8s0"); err != nil {
		t.Fatalf("validatePreservedLink(rewritten): %v", err)
	}

	// A [Link]-only MACAddress= (no [Match] MAC) is not a match: the
	// old first-match code rewrote it into a bogus [Link]
	// OriginalName=; now content is unchanged.
	linkOnly := "# Managed by xpfd — do not edit\n[Match]\nOriginalName=enp8s0\n\n[Link]\nName=ge-0-0-1\nMACAddress=52:54:00:11:22:33\n"
	got, err = preserveLinkFields(linkOnly, "enp8s0")
	if err != nil {
		t.Fatalf("preserveLinkFields(linkOnly): %v", err)
	}
	if got != linkOnly {
		t.Fatalf("[Link] MACAddress= was corrupted:\n got=%q\nwant=%q", got, linkOnly)
	}

	// Validation must reject a leftover [Match] MAC match.
	leftover := "# Managed by xpfd — do not edit\n[Match]\nOriginalName=enp8s0\nMACAddress=52:54:00:aa:bb:cc\n\n[Link]\nName=ge-0-0-1\n"
	if err := validatePreservedLink(leftover, "ge-0-0-1", "enp8s0"); err == nil {
		t.Fatal("validatePreservedLink must reject a leftover [Match] MACAddress= match")
	}

	// End-to-end: a multi-MAC rich file through fixRethLinkFile lands
	// with no [Match] MACAddress= left and MTU preserved.
	dir := withTempLinkDir(t)
	path := filepath.Join(dir, linkPrefix+"ge-0-0-1.link")
	if err := os.WriteFile(path, []byte(multi), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := fixRethLinkFile("ge-0-0-1", "enp8s0"); err != nil {
		t.Fatalf("fixRethLinkFile(multi): %v", err)
	}
	gotB, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotB) != want {
		t.Fatalf("fixRethLinkFile multi-MAC rewrite differs:\n got=%q\nwant=%q", gotB, want)
	}
}
