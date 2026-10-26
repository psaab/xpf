package upgrade

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/fsatomic"
	"github.com/psaab/xpf/pkg/upgrade/stagedgen"
)

// ── persisted anti-rollback high-water floors (#10848) ───────────────
//
// No anti-rollback floor existed on the binary or kernel forward
// channels: a validly-signed OLD package is a first-class upgrade, so an
// attacker (or a stale mirror) replaying an old-but-signed build cuts
// the host back to that code with every signature check satisfied. This
// file is the durable boundary that closes the replay: a per-channel
// high-water mark, persisted OUTSIDE the versioned runtime and outside
// every journal, recording the highest Debian package version that
// channel has ever VERIFIED-COMMITTED on this host.
//
// Contract (from the issue acceptance):
//   - Persisted under /var/lib/xpf, checked in the binary Run's INIT
//     phase and in the kernel channel's Arm preflight — an older forward
//     target dies there, pre-STOP / pre-apt, naming both versions.
//   - The ordinal is the Debian package version, compared with
//     compareDebianVersions (dpkg ordering). The binary's git-describe
//     self-report is NEVER an ordinal: it is unorderable (a bare hash on
//     tagless HEADs), so the floor binds only identities that carry a
//     real package version — the version staged-gen metadata records at
//     publish time, and the dpkg package version of a kernel candidate.
//   - Absent floor = not enrolled. The first verified commit establishes
//     it; forward cuts are not refused before any floor exists (a floor
//     cannot be seeded from an unorderable self-report, and refusing
//     first-ever cuts would brick fresh installs).
//   - Once enrolled, a MISSING candidate ordinal refuses: a replayed
//     pre-floor package supplies no package-version metadata, and that
//     must not silently disable enforcement.
//   - A corrupt or unparseable floor fails CLOSED on forward paths.
//     The escape is the operator's named rollback (RollbackTo), which
//     never consults the floor, and the dpkg purge path (postrm purge
//     removes the floor files), which is the clean-slate reset.
//   - Named rollback never lowers the floor: the floor survives
//     RollbackTo, so a rollback cannot become a downgrade-replay
//     primitive. Forward cuts below the floor stay refused afterwards.
//   - The floor advances ONLY on a verified commit — the binary cut's
//     COMMIT stamp and the kernel candidate's verified promotion —
//     never at stage/arm time, so an aborted or reverted attempt does
//     not strand the host above the version it actually runs.
//
// The two channels floor independently: the binary floor binds the xpf
// package version; the kernel floor binds the linux-image package
// version. One channel's advance never raises the other's bar.

// DefaultBinaryFloorPath is the durable binary-channel high-water file.
const DefaultBinaryFloorPath = "/var/lib/xpf/binary-floor"

// DefaultKernelFloorPath is the durable kernel-channel high-water file.
const DefaultKernelFloorPath = "/var/lib/xpf/kernel-floor"

// highWaterFloor is one channel's persisted anti-rollback floor: the
// highest Debian package version that channel has verified-committed.
type highWaterFloor struct {
	// Version is the Debian package version of the highest
	// verified-committed build on this channel ("" when unenrolled).
	Version string
	// Enrolled reports whether a floor file exists at all. An unenrolled
	// channel imposes no ordering constraint (yet).
	Enrolled bool
	// Path is the file the floor was loaded from (for operator-facing
	// refusal text).
	Path string
}

// loadHighWaterFloor reads the floor at path. A missing file is the
// unenrolled state, not an error. A present-but-unparseable file IS an
// error: callers on forward paths fail closed rather than guess (a
// rotted floor must never read as "no floor").
func loadHighWaterFloor(path string) (highWaterFloor, error) {
	floor := highWaterFloor{Path: path}
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return floor, nil
		}
		return floor, fmt.Errorf("stat anti-rollback floor %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return floor, fmt.Errorf("anti-rollback floor %s is not a regular file; refusing forward cuts", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return floor, fmt.Errorf("read anti-rollback floor %s: %w", path, err)
	}
	version := strings.TrimSpace(string(data))
	if version == "" {
		return floor, fmt.Errorf("anti-rollback floor %s is empty; refusing to guess the floor — "+
			"recover via named rollback (`xpfd upgrade --rollback`) or purge/reinstall", path)
	}
	if _, err := compareDebianVersions(version, version); err != nil {
		return floor, fmt.Errorf("anti-rollback floor %s holds unorderable version %q (%v); "+
			"refusing forward cuts until it is repaired — recover via named rollback "+
			"(`xpfd upgrade --rollback`) or purge/reinstall", path, version, err)
	}
	floor.Version = version
	floor.Enrolled = true
	return floor, nil
}

// advance raises the floor to version when version is strictly above
// the recorded floor, persisting durably (temp+fsync+rename). It is a
// no-op when version is at or below the floor, so re-committing the
// same build never rewrites the file. version must be Debian-orderable;
// an unorderable version is an error and leaves the floor untouched.
func (f highWaterFloor) advance(version string) error {
	if _, err := compareDebianVersions(version, version); err != nil {
		return fmt.Errorf("refusing to advance anti-rollback floor %s to unorderable version %q: %w",
			f.Path, version, err)
	}
	if f.Enrolled {
		cmp, err := compareDebianVersions(version, f.Version)
		if err != nil {
			return fmt.Errorf("compare candidate %q against anti-rollback floor %s: %w", version, f.Path, err)
		}
		if cmp <= 0 {
			return nil
		}
	}
	if err := fsatomic.MkdirAllDurable(filepath.Dir(f.Path), 0o755); err != nil {
		return fmt.Errorf("create anti-rollback floor dir for %s: %w", f.Path, err)
	}
	if err := fsatomic.WriteFileDurable(f.Path, []byte(version+"\n"), 0o644); err != nil {
		return fmt.Errorf("persist anti-rollback floor %s: %w", f.Path, err)
	}
	return nil
}

// checkForward refuses a forward cut/arm of candidate against this
// floor. The rules, in order:
//   - unenrolled floor: allow (nothing to be below yet);
//   - enrolled floor + empty candidate: refuse — an enrolled channel
//     must not accept a target whose package identity is unknown (the
//     pre-floor replay case);
//   - candidate below floor: refuse, naming both versions;
//   - candidate at or above floor: allow.
//
// what names the channel in refusal text ("binary upgrade target",
// "kernel candidate").
// CheckBinaryFloorAt checks candidate against the binary-channel
// floor persisted at floorPath — the publish-time half of the
// anti-rollback floor for the postinst auto-cut. The publish path
// below (stagedgen.Publish) stamps the dpkg package version from
// dpkg-query rather than a package-embedded identity, so the
// replayed old package cannot supply a spoofed caller version.
func CheckBinaryFloorAt(floorPath, candidate string) error {
	f, err := loadHighWaterFloor(floorPath)
	if err != nil {
		return fmt.Errorf("read binary anti-rollback floor: %w", err)
	}
	return f.checkForward("binary package", candidate, "publish")
}

func (f highWaterFloor) checkForward(what, candidate, phase string) error {
	if !f.Enrolled {
		return nil
	}
	if candidate == "" {
		return fmt.Errorf("refuse-before-%s: %s carries no Debian package version, so it cannot be "+
			"proven at or above the enrolled anti-rollback floor %s (%s); refusing the forward operation. "+
			"A replayed pre-floor package supplies no package identity and must not bypass the floor — "+
			"use the named rollback (`xpfd upgrade --rollback`) to move deliberately, or purge/reinstall",
			phase, what, f.Version, f.Path)
	}
	cmp, err := compareDebianVersions(candidate, f.Version)
	if err != nil {
		return fmt.Errorf("refuse-before-%s: cannot order %s %q against the anti-rollback floor %s (%s): %w",
			phase, what, candidate, f.Version, f.Path, err)
	}
	if cmp < 0 {
		return fmt.Errorf("refuse-before-%s: %s %s is BELOW the anti-rollback floor %s (%s); "+
			"a validly-signed old build is a replay, not a forward operation. Named rollback "+
			"(`xpfd upgrade --rollback`) remains available and does not lower the floor",
			phase, what, candidate, f.Version, f.Path)
	}
	return nil
}

// ── staged-generation package identity ───────────────────────────────
//
// A generation's Debian package version is recorded at publish time in a
// dotfile inside the (immutable) generation directory. It cannot be
// derived later: the binary self-report is git-describe (unorderable),
// and dpkg's live status describes whatever package was unpacked LAST,
// not the generation a pinned resume is cutting from. Recording it in
// the generation makes the identity a property of the immutable source
// the cut actually copies — the same generation the journal pins.

// writeStagedPackageVersion records version inside dir (a staged
// generation or gen-shaped directory). An empty version REMOVES any
// recorded identity: an unidentified publish must not inherit a stale
// identity from a reused directory.
func writeStagedPackageVersion(dir, version string) error {
	path := filepath.Join(dir, stagedgen.PackageVersionFile)
	if version == "" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("clear staged package version in %s: %w", dir, err)
		}
		return nil
	}
	if _, err := compareDebianVersions(version, version); err != nil {
		return fmt.Errorf("refusing to record unorderable staged package version %q: %w", version, err)
	}
	if err := fsatomic.WriteFileDurable(path, []byte(version+"\n"), 0o644); err != nil {
		return fmt.Errorf("record staged package version in %s: %w", dir, err)
	}
	return nil
}

// readStagedPackageVersion returns the Debian package version recorded
// in dir, or "" when none was recorded (a pre-floor generation). A
// recorded-but-unorderable value is an error: the metadata exists but
// cannot be trusted, and callers on forward paths fail closed.
func readStagedPackageVersion(dir string) (string, error) {
	path := filepath.Join(dir, stagedgen.PackageVersionFile)
	info, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("stat staged package version in %s: %w", dir, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("staged package version in %s is not a regular file", dir)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", nil
		}
		return "", fmt.Errorf("read staged package version in %s: %w", dir, err)
	}
	version := strings.TrimSpace(string(data))
	if version == "" {
		return "", nil
	}
	if _, err := compareDebianVersions(version, version); err != nil {
		return "", fmt.Errorf("staged package version %q in %s is unorderable: %w", version, dir, err)
	}
	return version, nil
}

// binaryPackageVersionForJournal reads the Debian version from the immutable
// source generation pinned in j. A legacy journal with no generation has no
// trustworthy package ordinal; it is allowed only while the binary channel is
// still unenrolled.
func (r *Runner) binaryPackageVersionForJournal(j *Journal) (string, error) {
	if j == nil || j.SourceGeneration == "" {
		return "", nil
	}
	if !stagedgen.ValidGenID(j.SourceGeneration) {
		return "", fmt.Errorf("journal source generation %q is not a safe staged-generation id", j.SourceGeneration)
	}
	return readStagedPackageVersion(filepath.Join(r.cfg.StagedGenDir, j.SourceGeneration))
}

// advanceBinaryFloor records a new binary high-water mark only for a
// verified-healthy cut. If a prior generation has no package identity, an
// unenrolled channel remains usable; once enrolled, that missing identity
// prevents a commit rather than silently ceasing to enforce the floor.
func (r *Runner) advanceBinaryFloor(j *Journal) error {
	floor, err := loadHighWaterFloor(r.cfg.BinaryFloorPath)
	if err != nil {
		return err
	}
	version, err := r.binaryPackageVersionForJournal(j)
	if err != nil {
		return err
	}
	if version == "" {
		if floor.Enrolled {
			return fmt.Errorf("cannot commit binary target %s without a Debian package version while "+
				"anti-rollback floor %s is enrolled at %s", j.TargetVersion, floor.Path, floor.Version)
		}
		return nil
	}
	if err := floor.advance(version); err != nil {
		return fmt.Errorf("advance binary anti-rollback floor for %s: %w", j.TargetVersion, err)
	}
	return nil
}

// kernelPackageVersionForJournal returns the Debian version recorded at Arm.
// It fills the field from dpkg for a journal created before package-version
// identity was added, then validates the result before any promotion decision.
func (r *KernelRunner) kernelPackageVersionForJournal(j *KernelJournal) (string, error) {
	if j == nil || j.CandidateVersion == "" {
		return "", fmt.Errorf("kernel journal has no candidate version")
	}
	version := j.CandidatePackageVersion
	if version == "" {
		var err error
		version, err = r.cfg.Sys.InstalledKernelPackageVersion(j.CandidateVersion)
		if err != nil {
			return "", fmt.Errorf("read installed Debian package version for candidate %s: %w",
				j.CandidateVersion, err)
		}
		j.CandidatePackageVersion = version
	}
	if err := ValidateDebianPackageVersion(version); err != nil {
		return "", fmt.Errorf("kernel candidate %s package version %q is not orderable: %w",
			j.CandidateVersion, version, err)
	}
	return version, nil
}

// checkKernelFloor is used on the candidate boot before verification can
// authorize promotion. Old journals recover identity from the installed
// linux-image package; an unknown identity fails closed.
func (r *KernelRunner) checkKernelFloor(j *KernelJournal) error {
	version, err := r.kernelPackageVersionForJournal(j)
	if err != nil {
		return err
	}
	floor, err := loadHighWaterFloor(r.cfg.KernelFloorPath)
	if err != nil {
		return err
	}
	return floor.checkForward("kernel candidate", version, "promotion")
}

// advanceKernelFloor raises the floor only after the candidate has passed
// verification and BootOrder has been durably pointed at it.
func (r *KernelRunner) advanceKernelFloor(j *KernelJournal) error {
	version, err := r.kernelPackageVersionForJournal(j)
	if err != nil {
		return err
	}
	floor, err := loadHighWaterFloor(r.cfg.KernelFloorPath)
	if err != nil {
		return err
	}
	if err := floor.checkForward("kernel candidate", version, "promotion"); err != nil {
		return err
	}
	return floor.advance(version)
}
