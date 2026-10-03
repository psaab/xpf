package daemon

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/fsatomic"
)

// archiveConfig transfers the active config to remote archive sites
// when system { archival { configuration { transfer-on-commit; } } } is set.
//
// #3867: the uploaded bytes are the CURRENT ACTIVE configuration serialized
// from the configstore — the same hierarchical text `show configuration`
// renders via Store.ShowActive() and the same source the local auto-archive
// (writeArchive) uses — NOT d.opts.ConfigFile. The boot file
// /etc/xpf/xpf.conf is written once at install and is never rewritten after
// the configstore became DB-canonical, so scp'ing it uploaded the day-0
// config on every commit: the DR/compliance archive silently diverged from
// the running config from the first commit onward while scp still logged
// success. We serialize the just-committed active config to a temp file and
// scp THAT, preserving the historical remote filename (the boot-file
// basename) and the scp transport.
func (d *Daemon) archiveConfig(cfg *config.Config) {
	var archival *config.ArchivalConfig
	if cfg != nil {
		archival = cfg.System.Archival
	}
	if archival == nil || !archival.TransferOnCommit || len(archival.ArchiveSites) == 0 {
		// A non-transfer-on-commit commit still owes periodic sites their
		// current-config copy. Retain only sites that remain configured for
		// periodic archival; otherwise the obligation has been withdrawn.
		var periodicSites []string
		if archival != nil && archival.TransferInterval > 0 {
			periodicSites = append([]string(nil), archival.ArchiveSites...)
		}
		d.enqueueArchive(func() { d.archiveDebt.retain(periodicSites) })
		return
	}
	d.archiveToSites(archival.ArchiveSites)
}

// enqueueArchive orders archive snapshots and debt transitions. An archive site
// holds one canonical remote filename; FIFO attempts ensure an old snapshot can
// never finish after and overwrite a newer one. Work is serialized with periodic
// ticks and config changes while callers remain non-blocking.
func (d *Daemon) enqueueArchive(run func()) {
	d.archiveQueueMu.Lock()
	previous := d.archiveQueueTail
	done := make(chan struct{})
	d.archiveQueueTail = done
	d.archiveQueueMu.Unlock()

	go func() {
		if previous != nil {
			<-previous
		}
		defer close(done)
		run()
	}()
}

// archiveToSites queues serialization of the CURRENT active configuration
// (Store.ShowActive) and its remote transfers. The queue prevents an older
// asynchronous transfer from finishing after a newer snapshot and overwriting
// the remote copy.
func (d *Daemon) archiveToSites(sites []string) {
	if len(sites) == 0 {
		return
	}
	sitesCopy := append([]string(nil), sites...)
	d.enqueueArchive(func() { d.archiveToSitesNow(sitesCopy) })
}

// archiveToSitesNow performs one serialized remote archive attempt. Its caller
// owns the archive queue until every site has finished reading the staged file.
func (d *Daemon) archiveToSitesNow(sites []string) {
	// The config compiler preserves archive-site order; collapse duplicate
	// destinations here so one attempt cannot concurrently write the same
	// remote filename twice.
	seen := make(map[string]struct{}, len(sites))
	uniqueSites := sites[:0]
	for _, site := range sites {
		if _, exists := seen[site]; exists {
			continue
		}
		seen[site] = struct{}{}
		uniqueSites = append(uniqueSites, site)
	}
	sites = uniqueSites
	if len(sites) == 0 {
		return
	}
	attempt := d.archiveDebt.begin(sites)
	failAllSites := func(err error) {
		for _, site := range sites {
			d.archiveDebt.record(attempt, site, err)
		}
	}
	if d.store == nil {
		err := errors.New("no configuration store")
		slog.Warn("config archival skipped: no configuration store")
		failAllSites(err)
		return
	}

	// Serialize the CURRENT active config (the just-committed tree) — the
	// same hierarchical text `show configuration` renders. This is the
	// config the operator expects the DR/compliance archive to reflect, not
	// the stale install-time boot file.
	active := d.store.ShowActive()
	if active == "" {
		err := errors.New("active configuration is empty")
		slog.Warn("config archival skipped: active configuration is empty")
		failAllSites(err)
		return
	}

	// Write to a temp file whose basename matches the historical remote name
	// (the boot-file basename, default xpf.conf) so an archive-site directory
	// destination keeps the same archived filename as before this fix.
	base := filepath.Base(d.opts.ConfigFile)
	if base == "" || base == "." || base == string(filepath.Separator) {
		base = "xpf.conf"
	}
	tmpDir, err := os.MkdirTemp("", "xpf-archive-")
	if err != nil {
		slog.Warn("config archival failed: create temp dir", "err", err)
		failAllSites(err)
		return
	}
	srcPath := filepath.Join(tmpDir, base)
	// AtomicGeneratedConfig (#1894/#1916): the staged snapshot is a
	// regenerated config file, not durable state — it is deleted after the
	// SCP uploads finish, so power-loss durability (fsync) is neither
	// needed nor wanted on this transient copy. WriteFileAtomic writes a
	// ".<base>.tmp-*" sibling in tmpDir and renames to srcPath, so the
	// snapshot appears complete-or-not (a lister/reader never observes a
	// torn file) while preserving the historical remote basename.
	// 0600 — the active config may contain encrypted secrets; keep the
	// transient copy owner-only (MkdirTemp already made the dir 0700).
	if err := fsatomic.WriteFileAtomic(srcPath, []byte(active), 0600); err != nil {
		slog.Warn("config archival failed: write temp config", "err", err)
		os.RemoveAll(tmpDir)
		failAllSites(err)
		return
	}

	transfer := d.archiveTransfer
	if transfer == nil {
		transfer = scpArchiveTransfer
	}

	var wg sync.WaitGroup
	for _, site := range sites {
		wg.Add(1)
		go func(dest string) {
			defer wg.Done()
			redactedDest := config.RedactURL(dest)
			slog.Info("archiving config", "destination", redactedDest)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			err := transfer(ctx, srcPath, dest)
			d.archiveDebt.record(attempt, dest, err)
			if err != nil {
				// scp output may echo argv; scrub the exact destination first.
				redactedErr := strings.ReplaceAll(err.Error(), dest, redactedDest)
				slog.Warn("config archival failed", "destination", redactedDest, "err", redactedErr)
			} else {
				slog.Info("config archived successfully", "destination", redactedDest)
			}
		}(site)
	}

	wg.Wait()
	os.RemoveAll(tmpDir)
}

// scpArchiveTransfer is the default transfer-on-commit transport: scp the
// serialized active-config file to one archive site. It is split out of
// archiveConfig behind the Daemon.archiveTransfer seam so tests can inject a
// capturing transfer and assert archiveConfig serializes the CURRENT active
// config rather than the stale boot file (#3867).
//
// #10298: scp trusts only the rendered sshKnownHostsPath: StrictHostKeyChecking=yes,
// UserKnownHostsFile=<rendered>, and GlobalKnownHostsFile=/dev/null reject MITM
// and unapproved rotations; BatchMode=yes fails fast without prompting.
// Missing/empty trust fails closed before exec. Update security { ssh-known-hosts ... }
// and commit to trust a rotated key before the next transfer.
func scpArchiveTransfer(ctx context.Context, srcPath, dest string) error {
	if config.URLHasPassword(dest) {
		return fmt.Errorf("config archival refused: inline URL password is not supported; use SSH key authentication")
	}
	knownHosts := sshKnownHostsPath
	if fi, err := os.Stat(knownHosts); err != nil || fi.Size() == 0 {
		if err == nil {
			return fmt.Errorf("config archival refused: SSH host-key trust file %s is empty — configure security { ssh-known-hosts { host <archive-host> { ...; }; }; } and commit", knownHosts)
		}
		if os.IsNotExist(err) {
			return fmt.Errorf("config archival refused: no SSH host-key trust at %s — configure security { ssh-known-hosts { host <archive-host> { ...; }; }; } and commit", knownHosts)
		}
		return fmt.Errorf("config archival refused: cannot stat SSH host-key trust file %s: %w", knownHosts, err)
	}
	if strings.HasPrefix(dest, "-") {
		return fmt.Errorf("config archival refused: archive-site destination must not begin with '-'")
	}
	// #4589 A7 F-02: `dest` is an operator-configured `archive-sites` URL
	// taken verbatim (compiler_system.go). A leading-dash value is rejected
	// both at commit and at this transport boundary, preventing it from being
	// parsed by scp's getopt as an OPTION — CWE-88 argv injection running as
	// the xpfd root user. The source is an absolute temp-file path, so no
	// option-like source can reach scp.
	out, err := exec.CommandContext(ctx, "scp",
		"-o", "StrictHostKeyChecking=yes",
		"-o", "UserKnownHostsFile="+knownHosts,
		"-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		srcPath, dest,
	).CombinedOutput()
	if err != nil {
		if trimmed := strings.TrimSpace(string(out)); trimmed != "" {
			trimmed = strings.ReplaceAll(trimmed, dest, config.RedactURL(dest))
			return fmt.Errorf("%w: %s", err, trimmed)
		}
		return err
	}
	return nil
}
