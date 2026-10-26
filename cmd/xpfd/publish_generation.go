package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/psaab/xpf/pkg/upgrade"
	"github.com/psaab/xpf/pkg/upgrade/lock"
	"github.com/psaab/xpf/pkg/upgrade/stagedgen"
)

// runPublishGenerationSubcommand implements `xpfd publish-generation` — the
// #1981 Option B publish step: copy the dpkg-staged binary set into a fresh,
// immutable staged-gen/<genid>/ and atomically repoint current-gen at it, so a
// later cut reads a whole, single-generation source that dpkg is NOT rewriting.
//
// It is invoked:
//   - by the .deb postinst (configure) AFTER a complete unpack, BEFORE the
//     auto-cut, so every cut sees a fresh generation;
//   - by an operator as the DEFERRED-PUBLISH RECOVERY verb (plan B-P2b): if the
//     postinst deferred the publish because the host-wide upgrade lock was busy
//     (another upgrade in progress), the new binaries are staged but
//     unpublished and a bare `xpfd upgrade` would re-read the OLD current-gen
//     and no-op. The operator runs `xpfd publish-generation` (which publishes
//     the now-complete staged set) and THEN `xpfd upgrade`. (`dpkg-reconfigure
//     xpf` is the equivalent — it re-runs the postinst publish + cut.)
//
// It takes the host-wide upgrade lock so it is mutually exclusive with an
// operator cut (and so its GC cannot delete a generation a cut is reading). A
// busy lock is reported and the publish is skipped (the prior generation stays
// the cut source — never a torn read).
//
// Exit codes: 0 success, 1 error, 2 lock busy (publish deferred).
func runPublishGenerationSubcommand(args []string) {
	flags, err := parsePublishGenerationArgs(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "publish-generation: %v\n", err)
		os.Exit(1)
	}

	// Take the host-wide upgrade lock so the publish (and its GC) is mutually
	// exclusive with an operator cut. A busy lock means another upgrade
	// operation owns it: defer (exit 2), do NOT publish — the prior generation
	// remains a valid cut source.
	h, lerr := lock.Acquire("publish-generation", "")
	if lerr != nil {
		if lock.IsBusy(lerr) {
			fmt.Fprintf(os.Stderr,
				"publish-generation: another upgrade holds the lock; deferred. "+
					"Re-run after it completes: %v\n", lerr)
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "publish-generation: acquire upgrade lock: %v\n", lerr)
		os.Exit(1)
	}
	defer func() { _ = h.Release() }()
	versionOutput, err := exec.Command("dpkg-query", "-W", "-f=${Version}", "xpf").Output()
	if err != nil {
		fmt.Fprintf(os.Stderr, "publish-generation: read installed Debian package version: %v\n", err)
		os.Exit(1)
	}
	packageVersion := strings.TrimSpace(string(versionOutput))
	if err := upgrade.ValidateDebianPackageVersion(packageVersion); err != nil {
		fmt.Fprintf(os.Stderr, "publish-generation: installed package version is not orderable: %v\n", err)
		os.Exit(1)
	}

	// #10848 (B1): the postinst runs the JUST-UNPACKED package's xpfd, so
	// a replayed pre-floor .deb would otherwise publish and cut with no
	// floor logic at all. The unpack-time dpkg-query IS this binary's
	// candidate ordinal: check it against the enrolled floor BEFORE
	// publishing, from the durable floor file (which lives outside the
	// package payload). Refusal ("this package is below the floor") vs
	// silent postinst warning distinguishes attacker replay from a
	// legitimate older repair only via the named rollback path — the
	// operator clears/reinstalls deliberately in that case.
	if ferr := upgrade.CheckBinaryFloorAt(upgrade.DefaultBinaryFloorPath, packageVersion); ferr != nil {
		fmt.Fprintf(os.Stderr, "publish-generation: %v\n", ferr)
		os.Exit(1)
	}

	cfg := stagedgen.Config{
		StagedDir:      flags.stagedDir,
		Dir:            flags.stagedGenDir,
		PackageVersion: packageVersion,
		Logf:           func(format string, a ...any) { fmt.Printf(format+"\n", a...) },
	}
	genid, err := cfg.Publish()
	if err != nil {
		fmt.Fprintf(os.Stderr, "publish-generation: %v\n", err)
		os.Exit(1)
	}
	// GC the staged-generation root (current + 1 prior), PROTECTING any
	// generation a crashed/resumable cut's journal still pins. The host-wide
	// lock serializes us against a RUNNING cut, but a CRASHED cut leaves a
	// durable journal with the lock released — so the GC must read the journal
	// and protect its SourceGeneration, else a resume hard-fails on a GC'd
	// source (and a crash-after-STOP would be left daemon-down with no
	// recoverable cut).
	//
	// The protection set MUST be known before running destructive GC (#4876):
	// if the journal is present but unreadable (I/O error) or malformed, we
	// cannot see which generation a crashed cut pins, so GC is SKIPPED rather
	// than run with an empty protection set that could reap the pinned source.
	// Skipping is safe — the extra staged generations are harmless and the
	// next publish with a readable journal reclaims them.
	protected, runGC, warn := gcProtectionForPublish(flags.journalPath)
	if warn != "" {
		fmt.Fprintf(os.Stderr, "publish-generation: WARN %s\n", warn)
	}
	if runGC {
		if gcErr := cfg.GC(protected); gcErr != nil {
			fmt.Fprintf(os.Stderr, "publish-generation: WARN gc: %v\n", gcErr)
		}
	}
	fmt.Printf("publish-generation complete (generation %s)\n", genid)
}

// publishGenerationFlags holds the parsed `xpfd publish-generation` flags. Kept
// in a struct so the flag parsing + positional-arg validation is unit-testable
// without the os.Exit / lock / real-Publish side effects of the dispatch.
type publishGenerationFlags struct {
	stagedDir, stagedGenDir, journalPath string
}

// parsePublishGenerationArgs parses the `xpfd publish-generation [flags]`
// argument set.
//
// #5322: publish-generation takes NO positional arguments; like #4869's `xpfd
// upgrade`, it REJECTS any leftover operand rather than silently dropping it.
// `flag.FlagSet.Parse` stops at the first non-flag token, so before this guard
// `xpfd publish-generation typo --staged-gen-dir /lab` left the PRODUCTION
// default staged-gen dir in place (the flag intent silently discarded) and
// still repointed/GC'd the live generation while reporting success. The
// validation runs BEFORE the host-wide lock is taken, so a mistyped operand is
// rejected with no side effects.
func parsePublishGenerationArgs(args []string) (publishGenerationFlags, error) {
	fs := flag.NewFlagSet("publish-generation", flag.ContinueOnError)
	stagedDir := fs.String("staged-dir", upgrade.DefaultStagedDir, "dpkg-staged binary set dir")
	stagedGenDir := fs.String("staged-gen-dir", upgrade.DefaultStagedGenDir, "staged-generation root")
	journalPath := fs.String("journal", upgrade.DefaultJournalPath, "upgrade journal path (its pinned generation is protected from GC)")
	if err := fs.Parse(args); err != nil {
		return publishGenerationFlags{}, err
	}
	if fs.NArg() != 0 {
		return publishGenerationFlags{}, fmt.Errorf("unexpected argument(s) %v; "+
			"usage: xpfd publish-generation [flags] (this verb takes no positional arguments)", fs.Args())
	}
	return publishGenerationFlags{
		stagedDir:    *stagedDir,
		stagedGenDir: *stagedGenDir,
		journalPath:  *journalPath,
	}, nil
}

// gcProtectionForPublish computes the staged-generation GC protection set for
// publish-generation and reports whether destructive GC may proceed.
//
// It reads the upgrade journal's pinned source generation. An absent or
// legacy (no-pin) journal is genuinely unprotected: GC proceeds (runGC=true)
// with the resolved protection set. A journal that is PRESENT but unreadable
// (I/O error) or malformed makes the protection set UNKNOWN — GC MUST be
// skipped (runGC=false) so a crashed/resumable cut's pinned source is never
// reaped and the resume bricked (#4876). warn is a non-empty operator message
// on the skip path, empty otherwise.
func gcProtectionForPublish(journalPath string) (protected map[string]bool, runGC bool, warn string) {
	protected = map[string]bool{}
	pinned, err := upgrade.ReadJournalSourceGeneration(journalPath)
	if err != nil {
		return protected, false, fmt.Sprintf(
			"read journal for GC protection: %v; skipping GC to avoid reaping a pinned generation", err)
	}
	if pinned != "" {
		protected[pinned] = true
	}
	return protected, true, ""
}
