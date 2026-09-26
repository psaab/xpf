package upgrade

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/psaab/xpf/pkg/configstore"
)

// RollbackOptions controls a single operator rollback. ClusterCoordinated is
// set only by the rolling driver after it has drained this node to its peer;
// LockAlreadyHeld is set by that driver while it holds the host-wide lock.
type RollbackOptions struct {
	ClusterCoordinated bool
	LockAlreadyHeld    bool
	// SkipHealthCheck is test-only plumbing for a caller that supplies its own
	// post-start readiness gate. The production CLI leaves it false; HA uses
	// the normal target-version helper-health gate before rejoining.
	SkipHealthCheck bool
}

type rollbackPlan struct {
	fromVersion string
	toVersion   string
	snapshotDir string
}

// RollbackTo performs the operator-facing binary+DB atomic rollback. It is
// deliberately separate from rollback(), which is the forward-cut failure
// recovery path and receives a journal describing the failed cut. This method
// owns the complete pre-STOP policy gate, then composes the same proven
// stop -> restore -> flip -> start sequence.
//
// Journal field semantics remain identical to the existing StateRollingBack
// invariant: TargetVersion is the version being rolled back FROM and
// PreviousVersion is the rollback destination. A crash resume through the
// ordinary Runner.Run therefore continues toward the destination rather than
// undoing the operator rollback.
func (r *Runner) RollbackTo(target string, opts RollbackOptions) error {
	if !opts.ClusterCoordinated {
		present, err := r.clusterNodeIDPresent()
		if err != nil {
			return fmt.Errorf("upgrade --rollback: refusing standalone rollback with indeterminate cluster membership (%w); resolve the marker lookup failure or run `xpfd upgrade --rollback --rolling`; the unit was NOT stopped", err)
		}
		if present {
			return fmt.Errorf("upgrade --rollback: refusing standalone rollback on clustered node (%s present); use `xpfd upgrade --rollback --rolling` for a coordinated drain; the unit was NOT stopped", r.cfg.NodeIDPath)
		}
	}

	if !opts.LockAlreadyHeld {
		h, err := acquireUpgradeLock("upgrade --rollback", target)
		if err != nil {
			return fmt.Errorf("upgrade --rollback: %w", err)
		}
		defer func() { _ = h.Release() }()
	}

	plan, j, err := r.rollbackInvocationPlan(target)
	if err != nil {
		return fmt.Errorf("upgrade --rollback: %w", err)
	}
	if j.State == StateRollingBack {
		return r.executeRollback(plan, j, opts)
	}
	j = &Journal{
		// Preserve StateRollingBack's established source/destination meaning.
		TargetVersion:      plan.fromVersion,
		PreviousVersion:    plan.toVersion,
		DBSnapshotPath:     plan.snapshotDir,
		AdvancedStateFloor: true,
		OperatorRollback:   true,
		State:              StateRollingBack,
	}
	if err := r.saveJournal(j); err != nil {
		return fmt.Errorf("upgrade --rollback: journal rollback intent: %w", err)
	}
	return r.executeRollback(plan, j, opts)
}

// rollbackInvocationPlan resolves a fresh rollback or validates an existing
// StateRollingBack journal. Keeping this resolver journal-aware is essential
// after a crash post-FLIP: current already points at the destination then, so
// selecting from the live symlink would otherwise lose the persisted plan.
func (r *Runner) rollbackInvocationPlan(target string) (rollbackPlan, *Journal, error) {
	j, err := r.loadJournal()
	if err != nil {
		return rollbackPlan{}, nil, err
	}
	if j.State == StateRollingBack {
		if j.TargetVersion == "" || j.PreviousVersion == "" {
			return rollbackPlan{}, nil, fmt.Errorf("journal records an incomplete rollback without both source and destination versions; operator intervention required")
		}
		if target != "" && target != j.PreviousVersion {
			return rollbackPlan{}, nil, fmt.Errorf("rollback journal is already targeting %s (requested %s); resume the journaled rollback first", j.PreviousVersion, target)
		}
		if err := r.validateOperatorRollbackJournal(j); err != nil {
			return rollbackPlan{}, nil, err
		}
		plan := rollbackPlan{fromVersion: j.TargetVersion, toVersion: j.PreviousVersion, snapshotDir: j.DBSnapshotPath}
		if err := r.validateRollbackPlan(plan); err != nil {
			return rollbackPlan{}, nil, fmt.Errorf("refusing journal resume: %w", err)
		}
		return plan, j, nil
	}
	if j.State != StateInit {
		return rollbackPlan{}, nil, fmt.Errorf("refusing while upgrade journal is in-flight (state=%s target=%s previous=%s); complete or recover that cut before rolling back", j.State, j.TargetVersion, j.PreviousVersion)
	}
	plan, err := r.prepareRollback(target)
	if err != nil {
		return rollbackPlan{}, nil, err
	}

	return plan, j, nil
}
func (r *Runner) validateOperatorRollbackJournal(j *Journal) error {
	if !j.RollbackDBRestored {
		return nil
	}
	if _, err := os.Stat(r.cfg.ConfigDBDir + ".old"); err != nil {
		return fmt.Errorf("rollback journal says config DB was restored but %s is missing: %w; refusing to stop the daemon", r.cfg.ConfigDBDir+".old", err)
	}
	return nil
}

// prepareRollback performs all refusal checks before the first live mutation.
func (r *Runner) prepareRollback(target string) (rollbackPlan, error) {
	from, present := r.restorableCurrentTarget()
	if !present || from == "" {
		return rollbackPlan{}, fmt.Errorf("current runtime is not a restorable version; re-seed the versioned runtime and retry; refusing to stop the daemon")
	}

	to := target
	if to == "" {
		var err error
		to, err = r.defaultRollbackTarget(from)
		if err != nil {
			return rollbackPlan{}, err
		}
	}
	if to == from {
		return rollbackPlan{}, fmt.Errorf("rollback target %s is already current; choose a different restorable version", to)
	}
	if err := r.validateRestorableVersion(to); err != nil {
		return rollbackPlan{}, fmt.Errorf("rollback target %s is not restorable (%w); re-seed the versioned runtime and retry", to, err)
	}

	snapshotDir := filepath.Join(r.cfg.VersionsDir, "."+from+".dbsnap")
	if err := validateDBSnapshot(snapshotDir); err != nil {
		return rollbackPlan{}, fmt.Errorf("config DB snapshot for current version %s is unavailable (%w); re-stage a compatible target and retry", from, err)
	}
	plan := rollbackPlan{fromVersion: from, toVersion: to, snapshotDir: snapshotDir}
	if err := r.validateEnvelopeCompatibility(plan); err != nil {
		return rollbackPlan{}, err
	}
	return plan, nil
}

func (r *Runner) validateRollbackPlan(plan rollbackPlan) error {
	if plan.fromVersion == "" || plan.toVersion == "" || plan.snapshotDir == "" {
		return fmt.Errorf("rollback journal is missing source, destination, or DB snapshot")
	}
	if plan.fromVersion == plan.toVersion {
		return fmt.Errorf("rollback source and destination are both %s", plan.fromVersion)
	}
	if err := r.validateRestorableVersion(plan.toVersion); err != nil {
		return fmt.Errorf("target %s is not restorable (%w); re-seed the versioned runtime and retry", plan.toVersion, err)
	}
	if err := validateDBSnapshot(plan.snapshotDir); err != nil {
		return fmt.Errorf("config DB snapshot %s is unavailable: %w", plan.snapshotDir, err)
	}
	return r.validateEnvelopeCompatibility(plan)
}

func validateDBSnapshot(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("snapshot path is not a directory")
	}
	active := filepath.Join(dir, "active.json")
	if _, err := os.Stat(active); err != nil {
		return fmt.Errorf("active.json: %w", err)
	}
	return nil
}

func (r *Runner) validateEnvelopeCompatibility(plan rollbackPlan) error {
	data, err := os.ReadFile(filepath.Join(plan.snapshotDir, "active.json"))
	if err != nil {
		return fmt.Errorf("read rollback snapshot envelope: %w", err)
	}
	compat, enveloped, err := configstore.InspectEnvelopeHeader(data)
	if err != nil {
		return fmt.Errorf("refusing rollback from current %s to target %s: malformed snapshot envelope (%w); roll forward or re-stage an envelope-compatible rollback target", plan.fromVersion, plan.toVersion, err)
	}
	if !enveloped {
		return nil
	}
	targetBin := filepath.Join(r.versionDir(plan.toVersion), "xpfd")
	reader, err := r.cfg.Sys.EnvelopeReaderVersion(targetBin)
	if err != nil {
		return fmt.Errorf("refusing rollback from current %s to target %s: cannot prove target envelope reader (snapshot v=%d min-reader=%d): %w; roll forward or re-stage an envelope-compatible rollback target", plan.fromVersion, plan.toVersion, compat.FormatVersion, compat.MinReader, err)
	}
	if !envelopeCompatibleWithReader(compat, reader) {
		return fmt.Errorf("refusing rollback from current %s to target %s: snapshot envelope v=%d min-reader=%d exceeds target reader v=%d; booting the target would fail closed; roll forward or re-stage an envelope-compatible rollback target", plan.fromVersion, plan.toVersion, compat.FormatVersion, compat.MinReader, reader)
	}
	return nil
}

func (r *Runner) executeRollback(plan rollbackPlan, j *Journal, opts RollbackOptions) error {
	if err := r.cfg.Sys.StopUnit(r.cfg.Unit); err != nil {
		return fmt.Errorf("upgrade --rollback: stop current daemon %s: %w", plan.fromVersion, err)
	}
	if !j.RollbackDBRestored {
		if err := r.restoreDBSnapshotRetainOld(plan.snapshotDir); err != nil {
			return fmt.Errorf("upgrade --rollback: restore config DB snapshot: %w", err)
		}
		r.logf("upgrade: rollback restored config DB from %s", plan.snapshotDir)
		j.RollbackDBRestored = true
		if err := r.saveJournal(j); err != nil {
			return fmt.Errorf("upgrade --rollback: journal restored config DB: %w", err)
		}
	} else {
		if _, err := os.Stat(r.cfg.ConfigDBDir + ".old"); err != nil {
			return fmt.Errorf("upgrade --rollback: rollback journal says config DB was restored but %s is missing: %w", r.cfg.ConfigDBDir+".old", err)
		}
		r.logf("upgrade: resuming rollback with restored config DB from %s", plan.snapshotDir)
	}
	if err := r.flip(plan.toVersion); err != nil {
		return fmt.Errorf("upgrade --rollback: re-flip to target %s: %w", plan.toVersion, err)
	}
	if err := r.cfg.Sys.StartUnit(r.cfg.Unit); err != nil {
		return fmt.Errorf("upgrade --rollback: start target daemon %s: %w", plan.toVersion, err)
	}
	if !opts.SkipHealthCheck {
		if err := r.cfg.Sys.HelperHealthy(plan.toVersion, r.cfg.StartHealthDeadline); err != nil {
			return fmt.Errorf("upgrade --rollback: target %s started but helper health did not confirm: %w; rollback state is preserved for operator recovery", plan.toVersion, err)
		}
	}
	if err := r.clearJournal(); err != nil {
		return fmt.Errorf("upgrade --rollback: clear rollback journal: %w", err)
	}
	_ = j // j documents the persisted invariant; execute uses the immutable plan.
	return nil
}

func (r *Runner) defaultRollbackTarget(current string) (string, error) {
	entries, err := os.ReadDir(r.cfg.VersionsDir)
	if err != nil {
		return "", fmt.Errorf("cannot enumerate rollback targets: %w", err)
	}
	type candidate struct {
		name string
		mod  int64
	}
	var candidates []candidate
	for _, entry := range entries {
		name := entry.Name()
		if name == current || name == currentLink || strings.HasPrefix(name, ".") || !entry.IsDir() {
			continue
		}
		if err := r.validateRestorableVersion(name); err != nil {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		candidates = append(candidates, candidate{name: name, mod: info.ModTime().UnixNano()})
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no restorable non-current rollback target found; re-seed a compatible version and retry")
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].mod > candidates[j].mod })
	return candidates[0].name, nil
}
