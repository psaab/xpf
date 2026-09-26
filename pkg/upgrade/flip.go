package upgrade

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
)

// unitDropinName is the drop-in file basename written under
// /etc/systemd/system/<unit>.service.d/ to pin ExecStart to the concrete
// versioned path.
const unitDropinName = "10-xpf-version.conf"

// flip performs the three journaled-idempotent FLIP substeps (plan §6.1
// step 6 / §8 inv. 2). All three are DERIVED from ver so a crash between
// substeps re-runs idempotently to the same target:
//
//	6a. repoint versions/current -> <ver> (atomic symlink rename)
//	6b. repoint /usr/local/sbin/<bin> -> versions/current/<bin>
//	6c. template the xpfd unit ExecStart/ExecStartPre to the CONCRETE
//	    versions/<ver>/xpfd path + daemon-reload
//
// 6c uses the concrete versioned path (NOT the `current` symlink) because
// systemd does NOT symlink-resolve argv[0]: a symlink ExecStart would
// leave dir(os.Args[0]) = /usr/local/sbin and a helper respawn would grab
// the flipped /usr/local/sbin/xpf-userspace-dp. Pinning the version dir
// makes dir(os.Args[0]) the matching-version dir.
func (r *Runner) flip(ver string) error {
	// 6a: current -> <ver>
	if err := r.repointSymlink(r.currentPath(), ver); err != nil {
		return fmt.Errorf("flip current symlink: %w", err)
	}
	// 6b: /usr/local/sbin/<bin> -> versions/current/<bin>
	for _, b := range managedBins {
		linkPath := filepath.Join(r.cfg.SbinDir, b)
		target := filepath.Join(r.cfg.VersionsDir, currentLink, b)
		if err := r.repointSymlinkAbs(linkPath, target); err != nil {
			return fmt.Errorf("flip sbin link %s: %w", b, err)
		}
	}
	// 6c: unit ExecStart pinned to the concrete version path.
	if err := r.writeUnitDropin(ver); err != nil {
		return fmt.Errorf("template unit ExecStart: %w", err)
	}
	if err := r.cfg.Sys.DaemonReload(); err != nil {
		return fmt.Errorf("daemon-reload after unit template: %w", err)
	}
	// 6d (#6639): if a kernel candidate is ARMED, re-stamp the arm record at
	// the binary this cut just made live.
	//
	// LAST, deliberately. The record must never name a binary the unit does not
	// yet point at, so a crash between 6c and here leaves the OLD record — which
	// is today's behaviour: safe, refusing, and repaired by re-running the cut.
	if err := r.restampKernelArmRecord(ver); err != nil {
		return fmt.Errorf("re-stamp kernel arm record: %w", err)
	}
	return nil
}

// restampKernelArmRecord points the kernel channel's arm record at the xpfd
// this cut just made live (#6639).
//
// THE DEFECT. `xpfd upgrade kernel arm` records the arming binary's resolved
// path — `/var/lib/xpf/versions/<A>/xpfd` — into both the journal's
// `PromoteBinary` field and the `kernel-promote-binary` sidecar. An in-place
// binary cut then repoints `current`, the sbin links and the unit's ExecStart at
// version B and touches neither record. On the candidate boot the POSIX-sh outer
// hop compares the recorded path against what the unit independently resolves,
// finds two genuinely different files, and refuses.
//
// It is the SIDECAR that has to move. The refusal fires in the shell, before it
// execs anything, so the Go-side cross-check (VerifyPromoteBinaryMatchesRecord)
// is never reached — a Go-only change could not fix this.
//
// WHY RE-STAMP RATHER THAN RELAX THE COMPARISON. What #6601 built is the
// property that the promotion gate executes the LIVE xpfd and never a stale
// leftover, because a stale verifier's PASS permanently promotes a kernel
// nothing actually validated. Making the comparison version-aware or
// identity-aware would re-admit `versions/<OLD>/xpfd` — a retained, valid,
// executable binary — which is exactly the stale leftover that design
// eliminates. The recorded path is a PROXY for "live", established by
// authority-of-construction at arm time; a cut has that same authority, because
// it CREATED the new binary and repointed `current`, the sbin link and
// ExecStart at it. "Which xpfd is live" is not inferred here — it is this
// function's own output. So the proxy is updated by a party entitled to update
// it, and both gates stay byte-identical.
//
// The consequence of leaving it is worse than a lost candidate. The shell
// refuses BEFORE exec'ing xpfd, so Promote() never runs and the journal is never
// cleared: the gate re-refuses on every subsequent boot from a unit that reports
// success, and on an HA node `reconcileKernelUpgradeHold` releases the SECONDARY
// hold only when a promotion marker names the running kernel — a marker that
// will never be written — so the node holds SECONDARY indefinitely.
//
// A no-op unless a candidate is ARMED: with nothing armed there is no record to
// re-stamp and none is created, so a cut on a box that never used the kernel
// channel is byte-identical to before.
//
// FAILS CLOSED. A half-updated record naming a binary that may not exist is
// strictly worse than an untouched one, so the sidecar and the journal field are
// written from ONE resolved value and any failure fails the cut. Leaving the old
// record intact degrades to exactly this issue, which is the safe fallback.
func (r *Runner) restampKernelArmRecord(ver string) error {
	// The struct is built directly rather than through NewKernelRunner, which
	// requires a KernelSystem. Nothing here touches the system: this is a
	// journal read, a path join and two durable writes. Demanding a Sys would
	// mean the binary channel constructing UEFI/apt/systemd plumbing it never
	// uses, purely to read a file.
	kr := &KernelRunner{cfg: KernelConfig{JournalPath: kernelArmRestampJournalPath}}
	j, err := kr.loadKernelJournal()
	if err != nil {
		// An unreadable journal is NOT "nothing armed" — it may be an armed one
		// this cut is about to invalidate. Refuse rather than cut past it.
		return fmt.Errorf("read kernel journal: %w", err)
	}
	if !j.State.atLeast(KernelStateArmed) ||
		j.State == KernelStatePromoted || j.State == KernelStateReverted {
		return nil // nothing armed — no record exists to re-stamp
	}
	bin := filepath.Join(r.cfg.VersionsDir, ver, "xpfd")
	if err := validateGateBin(bin); err != nil {
		return fmt.Errorf("cut target %s is not usable as the promotion gate: %w", bin, err)
	}
	j.PromoteBinary = bin
	if err := kr.saveKernelJournal(j); err != nil {
		return err
	}
	path := ArmRecordPath(kr.cfg.JournalPath)
	if err := fsatomic.MkdirAllDurable(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("create arm-record dir: %w", err)
	}
	return fsatomic.WriteFileDurable(path, []byte(bin+"\n"), 0o644)
}

// kernelArmRestampJournalPath is the kernel journal the cut re-stamps against.
//
// A package var seeded from the production default, matching bootGateJournalPath
// (kernel_arm_journal_path.go): a unit test that drives flip() over a t.TempDir()
// layout must not write to the real /var/lib/xpf, and nothing outside this
// package can reach it, so production is structurally incapable of pointing it
// elsewhere. #6631 already refuses to ARM against a non-default journal, so
// there is exactly one path this can legitimately be.
var kernelArmRestampJournalPath = DefaultKernelJournalPath

// repointSymlink atomically points linkPath at a RELATIVE target (basename
// within the same dir, e.g. current -> <ver>). Atomic via temp+rename.
func (r *Runner) repointSymlink(linkPath, relTarget string) error {
	dir := filepath.Dir(linkPath)
	tmp := filepath.Join(dir, "."+filepath.Base(linkPath)+".tmp")
	// #8597 (muse-004 K55): RemoveAll, not Remove.
	//
	// A stale DIRECTORY at the temp path — manual intervention, or a previous
	// run that died between MkdirAll and Symlink — makes os.Remove fail, and
	// the Symlink below then fails EEXIST. The symlink flip is the step that
	// makes an upgrade take effect, so a leftover directory wedges every
	// subsequent attempt until someone removes it by hand.
	//
	// The sibling seed path already fixed exactly this and says so:
	// pkg/upgrade/runtime/seed.go's RemoveAll carries the reasoning, and the
	// stagedgen atomic-symlink helper uses RemoveAll too. flip.go — the one
	// that performs the actual cutover — was the copy left behind.
	_ = os.RemoveAll(tmp)
	if err := os.Symlink(relTarget, tmp); err != nil {
		return fmt.Errorf("create temp symlink: %w", err)
	}
	if err := os.Rename(tmp, linkPath); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("rename symlink into place: %w", err)
	}
	if err := fsatomic.SyncDir(dir); err != nil {
		return fmt.Errorf("fsync symlink dir: %w", err)
	}
	return nil
}

// repointSymlinkAbs atomically points linkPath at an ABSOLUTE target.
func (r *Runner) repointSymlinkAbs(linkPath, absTarget string) error {
	dir := filepath.Dir(linkPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(linkPath)+".tmp")
	// #8597 (muse-004 K55): RemoveAll — see repointSymlink above.
	_ = os.RemoveAll(tmp)
	if err := os.Symlink(absTarget, tmp); err != nil {
		return fmt.Errorf("create temp symlink: %w", err)
	}
	if err := os.Rename(tmp, linkPath); err != nil {
		_ = os.RemoveAll(tmp)
		return fmt.Errorf("rename symlink into place: %w", err)
	}
	if err := fsatomic.SyncDir(dir); err != nil {
		return fmt.Errorf("fsync symlink dir: %w", err)
	}
	return nil
}

// writeUnitDropin templates the xpfd unit ExecStart/ExecStartPre to the
// concrete versioned path.
func (r *Runner) writeUnitDropin(ver string) error {
	xpfd := filepath.Join(r.versionDir(ver), "xpfd")
	content := fmt.Sprintf(`# Managed by xpf-upgrade (#1917 increment B). Pins ExecStart to the
# concrete versioned binary so a helper respawn resolves the matching
# version's xpf-userspace-dp (systemd does not symlink-resolve argv[0]).
[Service]
ExecStartPre=
ExecStartPre=%s verify-dataplane
ExecStart=
ExecStart=%s
`, xpfd, xpfd)
	return r.cfg.Sys.WriteUnitDropin(r.cfg.Unit, unitDropinName, content)
}

// rollback performs binary+DB-atomic rollback to the previous version
// (standalone auto-rollback, plan §6.4). Order is mandatory:
//
//  1. stop the (failed) new daemon
//  2. restore the config DB from the cut-boundary snapshot (the PREFLIGHT
//     baseline is refreshed after STOP, so the old binary never boots against
//     a too-new envelope DB and fatal-rejects)
//  3. re-flip current/sbin/unit back to the previous version
//  4. start the old daemon
//
// If there is no previous version (first cut) or no DB snapshot, rollback
// is best-effort and surfaces a clear error.
func (r *Runner) rollback(j *Journal) error {
	if j.PreviousVersion == "" {
		return fmt.Errorf("no previous version to roll back to (first cut); the new "+
			"version %s is unhealthy and there is no prior runtime version — "+
			"operator intervention required", j.TargetVersion)
	}
	// PRE-ROLLBACK PREFLIGHT (#6374): the rollback is destructive — it stops
	// the (failed) new daemon, restores the config DB from the pre-upgrade
	// snapshot, then re-flips to PreviousVersion. If PreviousVersion's dir is
	// missing / non-directory / lockstep-incomplete (storage damage, a stale
	// pre-#6374 journal that recorded a dangling `current`, or a raced GC), the
	// re-flip at step 3 would fail AFTER the DB was already rolled back and the
	// unit stopped — turning a recoverable new-version failure into a
	// control-plane outage. Validate the target BEFORE any destructive step so
	// we surface a clear operator-actionable error and leave the pre-rollback
	// state (the new daemon, still running) untouched.
	if verr := r.validateRestorableVersion(j.PreviousVersion); verr != nil {
		return fmt.Errorf("refuse-rollback: previous version %s is not restorable "+
			"(%w); refusing to stop the daemon and roll back the config DB to a "+
			"missing/incomplete runtime, which would strand the control plane "+
			"offline. The new version %s is unhealthy — operator intervention "+
			"required (re-seed the versioned runtime, then retry)",
			j.PreviousVersion, verr, j.TargetVersion)
	}
	// Journal the rollback so a crash mid-rollback resumes the rollback,
	// NOT the failed forward cut. Codex r1 Critical#1: an auto-rollback
	// that re-flips to PreviousVersion but leaves the journal at FLIPPED
	// (target=failed) would let a re-run resume at START for the FAILED
	// target and mark it COMMITTED. We retarget the journal to the
	// previous version and mark the state ROLLINGBACK; on terminal success
	// the journal is CLEARED (the failed cut is abandoned — the operator
	// re-stages to retry).
	j.State = StateRollingBack
	if err := r.saveJournal(j); err != nil {
		return fmt.Errorf("rollback: journal rollback intent: %w", err)
	}

	// 1. stop the failed new daemon.
	if err := r.cfg.Sys.StopUnit(r.cfg.Unit); err != nil {
		return fmt.Errorf("rollback: stop failed new daemon: %w", err)
	}
	// 2. restore the DB BEFORE re-flipping the binary.
	if j.AdvancedStateFloor && j.DBSnapshotPath != "" {
		if err := r.restoreDBSnapshot(j.DBSnapshotPath); err != nil {
			return fmt.Errorf("rollback: restore config DB snapshot: %w", err)
		}
		r.logf("upgrade: rollback restored config DB from %s", j.DBSnapshotPath)
	}
	// 3. re-flip to the previous version.
	if err := r.flip(j.PreviousVersion); err != nil {
		return fmt.Errorf("rollback: re-flip to previous version %s: %w", j.PreviousVersion, err)
	}
	// 4. start the old daemon.
	if err := r.cfg.Sys.StartUnit(r.cfg.Unit); err != nil {
		return fmt.Errorf("rollback: start previous daemon: %w", err)
	}
	// 5. Terminal: clear the journal. The previous version is live; the
	//    failed cut is abandoned. A re-run of `xpfd upgrade` starts fresh
	//    against whatever is now staged (it will not resume the failed
	//    target).
	return r.clearJournal()
}

// recoverFromFlipFailure handles a flip() error. The STOP step already ran,
// so the unit is DOWN. Recovery depends on the path:
//
//   - STANDALONE, PreviousVersion != "": auto-roll back to it (re-flip + DB
//     restore + start the old daemon) so the daemon is never left offline.
//   - STANDALONE, PreviousVersion == "" (sanctioned first cut): no prior
//     version, but versions/current was seeded (A/B) and the flip's only
//     possibly-completed substep (6a) repoints current to the SAME
//     first-install version, so current still resolves to a launchable
//     binary. Restart the unit so the first-install daemon comes back up.
//   - HA path (SkipStartHealthRollback): rollback is OPERATOR-DRIVEN by
//     design — an automatic re-flip mid-rolling un-coordinates the cluster
//     (plan §8 inv. 8). This INTENTIONALLY leaves the node's unit STOPPED on
//     a flip failure and surfaces a clear error, exactly mirroring the
//     existing HA START-failure behavior (cutover.go: SkipStartHealthRollback
//     returns without rollback). So on HA the mechanism-C "daemon never
//     offline" property is delegated to the operator (and to the peer, which
//     is still forwarding because the node was drained before the cut) — it
//     is a documented, signed-off exception, NOT a silent contradiction.
//
// In all cases recoverFromFlipFailure returns a NON-NIL error (AGY-r2-4b):
// a flip failure is never a successful cut, even after a clean recovery.
func (r *Runner) recoverFromFlipFailure(j *Journal, opts Options, flipErr error) error {
	// HA: rollback is operator-driven for BOTH the has-previous and
	// first-cut cases — never auto-recover mid-rolling. Surface the stopped
	// unit for operator action (the drained-to peer keeps forwarding).
	if opts.SkipStartHealthRollback {
		return fmt.Errorf("flip failed after STOP (HA: rollback is operator-driven; "+
			"the unit is stopped — recover the node): %w", flipErr)
	}
	if j.PreviousVersion != "" {
		r.logf("upgrade: flip to %s failed after STOP (%v); AUTO-ROLLBACK to %s",
			j.TargetVersion, flipErr, j.PreviousVersion)
		if rbErr := r.rollback(j); rbErr != nil {
			return fmt.Errorf("flip failed (%v) AND rollback failed: %w", flipErr, rbErr)
		}
		return fmt.Errorf("flip to %s failed; rolled back to %s: %w",
			j.TargetVersion, j.PreviousVersion, flipErr)
	}

	// Sanctioned first cut (PreviousVersion==""): no prior version, but the
	// first-install binary is present in versions/current. Restart it so the
	// daemon is not left offline.
	r.logf("upgrade: flip to %s failed after STOP on a sanctioned first cut (%v); "+
		"restarting the first-install daemon from versions/current", j.TargetVersion, flipErr)
	if startErr := r.cfg.Sys.StartUnit(r.cfg.Unit); startErr != nil {
		return fmt.Errorf("flip failed (%v) on a first cut AND restart of the first-install "+
			"daemon failed (%v) — daemon is OFFLINE, operator intervention required",
			flipErr, startErr)
	}
	// Clear the journal (Copilot r3): leaving it at StateStopped would let a
	// subsequent Run() SKIP the STOP step (the unit is already running again),
	// run flip/start as a no-op against the live unit, and mark the cut
	// COMMITTED without ever restarting to the new ExecStart/drop-in. The cut
	// failed and we restored the first-install daemon, so the attempt is
	// abandoned — a re-run must start fresh against whatever is staged (which,
	// after this restart, has a real PreviousVersion in versions/current).
	if cerr := r.clearJournal(); cerr != nil {
		r.logf("upgrade: WARN clear journal after first-cut flip-failure restart: %v", cerr)
	}
	return fmt.Errorf("flip to %s failed on a sanctioned first cut; restarted the "+
		"first-install daemon from versions/current (no rollback target existed): %w",
		j.TargetVersion, flipErr)
}

// restoreDBSnapshot replaces the live config DB dir with the snapshot taken
// in PREFLIGHT, crash-safely. Strategy:
//
//  1. stage the snapshot into a sibling .restore.partial (copy+fsync);
//  2. if a leftover .old exists from a prior interrupted swap, the live
//     dir may be absent — recover by completing the swap first;
//  3. swap: move the (current) live dir to .old, then rename the staged
//     restore into place. If a crash lands between those two renames, the
//     live dir is absent BUT BOTH .old (the failed-new DB) AND
//     .restore.partial (the snapshot to install) exist on disk, so the
//     next rollback re-run completes the swap. A re-run NEVER finds the
//     live DB permanently destroyed.
//
// restoreDBSnapshot is the forward-cut auto-rollback behavior: complete the
// crash-safe swap and clean the temporary .old rotation after success.
func (r *Runner) restoreDBSnapshot(snapDir string) error {
	return r.restoreDBSnapshotWithRetention(snapDir, false)
}

// restoreDBSnapshotRetainOld is the operator rollback variant. The failed
// runtime's live DB remains at ConfigDBDir+".old" after the new snapshot is
// promoted, matching the manual celle sequence and giving operators a
// byte-preserving recovery point.
func (r *Runner) restoreDBSnapshotRetainOld(snapDir string) error {
	return r.restoreDBSnapshotWithRetention(snapDir, true)
}

func (r *Runner) restoreDBSnapshotWithRetention(snapDir string, retainOld bool) error {
	parent := filepath.Dir(r.cfg.ConfigDBDir)
	restore := r.cfg.ConfigDBDir + ".restore.partial"
	old := r.cfg.ConfigDBDir + ".old"
	// A prior operator rollback may have completed the directory swap and
	// retained .old, then crashed before FLIP. If the live tree is byte
	// identical to the requested snapshot, it is already installed: do not
	// rotate it again or delete the original failed-runtime DB.
	if retainOld {
		if _, oldErr := os.Stat(old); oldErr == nil {
			if _, liveErr := os.Stat(r.cfg.ConfigDBDir); liveErr == nil {
				liveSum, liveSumErr := copyTreeChecksum(r.cfg.ConfigDBDir)
				snapSum, snapSumErr := copyTreeChecksum(snapDir)
				if liveSumErr == nil && snapSumErr == nil && liveSum == snapSum {
					return nil
				}
			}
		}
	}

	// Recovery: a prior interrupted swap may have left ConfigDBDir absent
	// with .restore.partial already staged. If so, complete the install
	// from the staged restore without re-copying.
	_, liveErr := os.Stat(r.cfg.ConfigDBDir)
	_, restErr := os.Stat(restore)
	if os.IsNotExist(liveErr) && restErr == nil {
		if err := os.Rename(restore, r.cfg.ConfigDBDir); err != nil {
			return fmt.Errorf("complete interrupted DB restore swap: %w", err)
		}
		if err := fsatomic.SyncDir(parent); err != nil {
			return err
		}
		if !retainOld {
			_ = os.RemoveAll(old)
		}
		return nil
	}

	// Fresh stage of the snapshot.
	_ = os.RemoveAll(restore)
	if _, err := copyTree(snapDir, restore); err != nil {
		_ = os.RemoveAll(restore)
		return fmt.Errorf("stage DB restore copy: %w", err)
	}
	if err := fsatomic.SyncDir(restore); err != nil {
		_ = os.RemoveAll(restore)
		return err
	}
	if err := fsatomic.SyncDir(parent); err != nil { // make .restore.partial entry durable
		return err
	}

	// Swap. Both .old and .restore.partial are durable on disk before the
	// live dir is moved aside, so a crash between the two renames is
	// recoverable by the recovery branch above on re-run.
	_ = os.RemoveAll(old)
	if _, err := os.Stat(r.cfg.ConfigDBDir); err == nil {
		if err := os.Rename(r.cfg.ConfigDBDir, old); err != nil {
			return fmt.Errorf("move live DB aside: %w", err)
		}
	}
	if err := os.Rename(restore, r.cfg.ConfigDBDir); err != nil {
		// Put the live dir back.
		_ = os.Rename(old, r.cfg.ConfigDBDir)
		return fmt.Errorf("move restored DB into place: %w", err)
	}
	if err := fsatomic.SyncDir(parent); err != nil {
		return err
	}
	if !retainOld {
		_ = os.RemoveAll(old)
	}
	return nil
}

// gc removes version dirs beyond the N=3 retention, NEVER removing the
// running (current) version or its immediate predecessor (the rollback
// target), and removes orphaned DB snapshots for GC'd versions.
func (r *Runner) gc(j *Journal) error {
	entries, err := os.ReadDir(r.cfg.VersionsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	// Protected: current target + previous (rollback) version.
	protected := map[string]bool{}
	if j.TargetVersion != "" {
		protected[j.TargetVersion] = true
	}
	if j.PreviousVersion != "" {
		protected[j.PreviousVersion] = true
	}
	cur, _ := r.readCurrentVersion()
	if cur != "" {
		protected[cur] = true
	}

	type vdir struct {
		name   string
		mod    int64
		stamp  *committedStamp
		record bool
	}
	var versions []vdir
	for _, e := range entries {
		n := e.Name()
		if n == currentLink {
			continue
		}
		// Skip dotfiles (.partial, .dbsnap, temp symlinks).
		if len(n) > 0 && n[0] == '.' {
			continue
		}
		if !e.IsDir() {
			continue
		}
		info, ierr := e.Info()
		if ierr != nil {
			continue
		}
		stamp, record := r.readCommittedStamp(n)
		versions = append(versions, vdir{name: n, mod: info.ModTime().UnixNano(), stamp: stamp, record: record})
	}
	// Committed history is authoritative; mutable directory mtime is only a
	// tie-break among records (or the explicitly warned legacy/failed groups).
	rank := func(v vdir) int {
		if v.record && v.stamp != nil && v.stamp.Committed {
			return 2
		}
		if !v.record {
			return 1 // legacy version with no history record
		}
		return 0 // known in-flight/failed or unreadable/corrupt record
	}
	sort.Slice(versions, func(i, j int) bool {
		ri, rj := rank(versions[i]), rank(versions[j])
		if ri != rj {
			return ri > rj
		}
		if ri == 2 && versions[i].stamp.CommittedAtUnixNano != versions[j].stamp.CommittedAtUnixNano {
			return versions[i].stamp.CommittedAtUnixNano > versions[j].stamp.CommittedAtUnixNano
		}
		if versions[i].mod != versions[j].mod {
			return versions[i].mod > versions[j].mod
		}
		return versions[i].name < versions[j].name
	})
	var ordering []string
	for _, v := range versions {
		switch rank(v) {
		case 2:
			ordering = append(ordering, fmt.Sprintf("%s(commit=%d mtime=%d)", v.name, v.stamp.CommittedAtUnixNano, v.mod))
		case 1:
			ordering = append(ordering, fmt.Sprintf("%s(legacy mtime=%d)", v.name, v.mod))
		default:
			ordering = append(ordering, fmt.Sprintf("%s(non-committed mtime=%d)", v.name, v.mod))
		}
	}
	if len(versions) > 0 {
		r.logf("upgrade: gc version order (committed time first; mtime tie-break/legacy fallback): %s", strings.Join(ordering, ", "))
	}

	kept := 0
	for _, v := range versions {
		if protected[v.name] {
			kept++
			continue
		}
		if kept < retainVersions {
			kept++
			continue
		}
		r.logf("upgrade: gc removing old version %s", v.name)
		if err := os.RemoveAll(r.versionDir(v.name)); err != nil {
			r.logf("upgrade: WARN gc remove %s: %v", v.name, err)
		}
		// Remove its DB snapshot too, if any.
		_ = os.RemoveAll(filepath.Join(r.cfg.VersionsDir, "."+v.name+".dbsnap"))
	}

	// Sweep ORPHAN DB snapshots (AGY r2): a PREFLIGHT abort takes the
	// snapshot before the version dir exists, so a `.<ver>.dbsnap` can be
	// left with no matching version dir. Remove any `.<ver>.dbsnap` whose
	// base version is not protected (current/target/previous) and has no
	// surviving version dir.
	for _, e := range entries {
		n := e.Name()
		if !strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".dbsnap") {
			continue
		}
		ver := strings.TrimSuffix(strings.TrimPrefix(n, "."), ".dbsnap")
		if protected[ver] {
			continue
		}
		if _, err := os.Stat(r.versionDir(ver)); err == nil {
			continue // version dir survives; keep its snapshot
		}
		r.logf("upgrade: gc removing orphan DB snapshot %s", n)
		_ = os.RemoveAll(filepath.Join(r.cfg.VersionsDir, n))
	}

	// GC the staged-generation root too (#1981 Option B): keep current-gen +
	// 1 prior, protecting any generation THIS cut still references (its pinned
	// SourceGeneration) so a commit/preflight GC cannot delete the source a
	// resumable cut is reading (the GC-vs-resume race). Best-effort: a
	// staged-gen GC failure is logged, never failing the cut.
	protectedGens := map[string]bool{}
	if j.SourceGeneration != "" {
		protectedGens[j.SourceGeneration] = true
	}
	if sgErr := r.stagedGenConfig().GC(protectedGens); sgErr != nil {
		r.logf("upgrade: WARN staged-gen gc failed: %v", sgErr)
	}
	return nil
}

// copyTreeChecksum recomputes the same sha256 stream copyTree produces,
// for a post-copy integrity re-check.
func copyTreeChecksum(dir string) (string, error) {
	h := sha256.New()
	type ent struct {
		rel  string
		path string
		reg  bool
	}
	var ents []ent
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		ents = append(ents, ent{rel: rel, path: p, reg: info.Mode().IsRegular()})
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].rel < ents[j].rel })
	for _, e := range ents {
		if !e.reg {
			continue
		}
		f, oerr := os.Open(e.path)
		if oerr != nil {
			return "", oerr
		}
		io.WriteString(h, e.rel+"\x00")
		if _, cerr := io.Copy(h, f); cerr != nil {
			f.Close()
			return "", cerr
		}
		f.Close()
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
