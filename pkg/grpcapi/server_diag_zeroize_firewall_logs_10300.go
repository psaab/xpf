package grpcapi

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/psaab/xpf/pkg/config"
	"github.com/psaab/xpf/pkg/configstore"
)

// ZeroizeLogInventory is the firewall-log wipe scope for a factory reset
// (#10300): the operator-configured log basenames the static legs cannot know.
// Both paths that drive the shared wipe (gRPC runZeroize and the console
// performConsoleZeroize) snapshot it from the store's ActiveConfig BEFORE the
// wipe runs — the config leg erases the very files the names come from, so
// resolving them after (or during) the wipe would find nothing and the reset
// would report clean with the prior tenant's logs intact. A zero value means
// "no configured names known" (no syslog/trace configured, or a store with no
// loaded config, e.g. console offline recovery): the static legs still run.
type ZeroizeLogInventory struct {
	// SyslogFiles are the `system syslog file <name>` destination basenames,
	// each written by rsyslog to /var/log/<name> (daemon applySyslogFiles).
	SyslogFiles []string
	// TraceFile is the `security flow traceoptions file <name>` basename,
	// written by logging.TraceWriter to /var/log/<name> plus .<N> rotations.
	// "" means persistent tracing was not configured.
	TraceFile string
}

// ZeroizeLogInventoryFromConfig derives the wipe inventory from a compiled
// config. It is nil-safe at every level: a nil config (or one with no syslog
// block / no traceoptions) yields the zero inventory, never a panic.
func ZeroizeLogInventoryFromConfig(cfg *config.Config) ZeroizeLogInventory {
	if cfg == nil {
		return ZeroizeLogInventory{}
	}
	inv := ZeroizeLogInventory{SyslogFiles: cfg.SyslogLogFileNames()}
	if to := cfg.Security.Flow.Traceoptions; to != nil {
		inv.TraceFile = to.File
	}
	return inv
}

var (
	// zeroizeVarLogDir is the shared /var/log root the persistent flow-trace
	// file and the rsyslog-written syslog outputs live directly under. A
	// package var (not a const) only so tests drive the wipe against a
	// throwaway tree; production is always /var/log.
	zeroizeVarLogDir = "/var/log"
	// zeroizeSecurityLogDir holds the event-mode security log
	// (security.log plus .<N> rotations, logging.NewLocalLogWriter). Seamed
	// for the same hermeticity reason; production is always /var/log/xpf.
	zeroizeSecurityLogDir = "/var/log/xpf"
	// zeroizeFlowTraceDir is the dedicated interactive-monitor trace
	// namespace (cli.openTraceFile, #5038). Every entry in it is
	// xpf-written flow telemetry. Seamed like the others; production is
	// always /var/log/xpf-flow-trace.
	zeroizeFlowTraceDir = "/var/log/xpf-flow-trace"
	// zeroizeRsyslogConfDir holds xpf's persistent rsyslog selectors. Leaving
	// these drop-ins behind lets a post-zeroize rsyslog restart recreate the
	// prior tenant's log outputs before the next config reconcile.
	zeroizeRsyslogConfDir = "/etc/rsyslog.d"
)

// zeroizeSecurityLogBase is the security-log basename (pkg/logging/locallog.go
// LocalLogConfig default; production writers always use the default — daemon
// applySyslogConfig and cli apply both pass LocalLogConfig{}).
const zeroizeSecurityLogBase = "security.log"

// zeroizeValidLogBaseName gates a configured log name before it is joined
// under a wipe root. The writers this mirrors (TraceWriter, applySyslogFiles,
// SyslogLogFilePath) all demand a bare basename; a leniently-loaded or
// peer-synced value that is not one was NEVER written (the writers fail safe),
// so refusing it here both matches what exists and keeps a hostile
// "../../etc/x" from steering the wipe outside /var/log. Invalid names are
// skipped with a warning, never an error: there is nothing to erase and a
// factory reset must not fail closed on a file that was never created.
func zeroizeValidLogBaseName(name string) bool {
	if name == "" || name == "." || name == ".." {
		return false
	}
	if name != filepath.Base(name) {
		return false
	}
	if strings.ContainsAny(name, `/\`) {
		return false
	}
	return true
}

// zeroizeIsLogGeneration reports whether entry is the active log file (base)
// or one of the rotated generations. xpf's writers use path.1, path.2, ...
// and host logrotate commonly adds either numeric/compressed forms
// (path.1.gz) or dateext forms (path-YYYYMMDD / path-YYYY-MM-DD, optionally
// compressed). The match is exact-base plus one recognized suffix, so a
// sibling such as "messages-other" is never treated as xpf's log.
func zeroizeIsLogGeneration(entry, base string) bool {
	if entry == base {
		return true
	}
	rest, ok := strings.CutPrefix(entry, base+".")
	if ok {
		if strings.HasSuffix(rest, ".gz") {
			rest = strings.TrimSuffix(rest, ".gz")
		}
		if rest == "" {
			return false
		}
		for i := 0; i < len(rest); i++ {
			if rest[i] < '0' || rest[i] > '9' {
				return false
			}
		}
		return true
	}
	rest, ok = strings.CutPrefix(entry, base+"-")
	if !ok {
		return false
	}
	if strings.HasSuffix(rest, ".gz") {
		rest = strings.TrimSuffix(rest, ".gz")
	}
	switch len(rest) {
	case 8: // dateext -YYYYMMDD
		for i := 0; i < len(rest); i++ {
			if rest[i] < '0' || rest[i] > '9' {
				return false
			}
		}
		return true
	case 10: // dateformat -%Y-%m-%d
		for i, want := range []byte("0000-00-00") {
			if want == '-' {
				if rest[i] != '-' {
					return false
				}
				continue
			}
			if rest[i] < '0' || rest[i] > '9' {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// zeroizeRemoveSyslogGenerations is the configured-rsyslog counterpart to
// zeroizeRemoveLogGenerations. Rsyslog follows an output symlink, so every
// matching active/rotated name is checked and refused as a typed skip rather
// than unlinked while the routed tenant logs survive at the target.
func zeroizeRemoveSyslogGenerations(dir, base string, fail func(error), skipped *[]configstore.SymlinkedTarget, hardlinks *[]configstore.HardlinkedPath) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fail(err)
		return
	}
	for _, e := range entries {
		if !zeroizeIsLogGeneration(e.Name(), base) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		found, herr := configstore.CollectHardlinkedFiles(path, "")
		*hardlinks = append(*hardlinks, found...)
		fail(herr)
		if sk, isLink := configstore.SymlinkTarget(path); isLink {
			slog.Warn("zeroize: syslog output generation is a symlink; NOT erasing it",
				"path", sk.Path, "target", sk.Target)
			*skipped = append(*skipped, sk)
			continue
		}
		fail(os.Remove(path))
	}
}

// zeroizeRemoveLogGenerations removes the active log file plus every rotated
// generation under dir, and nothing else: entries are ReadDir-enumerated and
// only exact base / recognized rotation names are Removed, so host logs
// sharing the directory (auth.log, syslog, ...) are never touched. An absent
// dir is the goal state (os.ErrNotExist excluded by fail). Hardlinked files
// are removed at the managed name but reported so the surviving sibling
// cannot be mistaken for a clean wipe. A link at a log path is unlinked
// WITHOUT a #9013 refusal: both xpf writers open O_NOFOLLOW and verify a
// regular file, so a pre-planted link was never written through and its
// target holds no xpf log content — unlinking it erases everything xpf owns,
// and refusing would fail a factory reset over a file that is not ours.
// (The rsyslog-written syslog outputs below CANNOT take this branch: rsyslog
// follows links, so a link there may route tenant logs to the target volume.)
func zeroizeRemoveLogGenerations(dir, base string, fail func(error), hardlinks *[]configstore.HardlinkedPath) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fail(err)
		return
	}
	for _, e := range entries {
		if !zeroizeIsLogGeneration(e.Name(), base) {
			continue
		}
		path := filepath.Join(dir, e.Name())
		found, herr := configstore.CollectHardlinkedFiles(path, "")
		*hardlinks = append(*hardlinks, found...)
		fail(herr)
		fail(os.Remove(path))
	}
}

// zeroizeRemoveRsyslogDropins removes the xpf-owned output selectors so a
// daemon restart cannot recreate a configured log destination after zeroize.
// Only the exact generated `10-xpf-*.conf` shape is owned; neighboring
// distribution/operator drop-ins remain untouched.
func zeroizeRemoveRsyslogDropins(dir string, fail func(error), skipped *[]configstore.SymlinkedTarget, hardlinks *[]configstore.HardlinkedPath) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		fail(err)
		return
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "10-xpf-") || !strings.HasSuffix(e.Name(), ".conf") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		found, herr := configstore.CollectHardlinkedFiles(path, "")
		*hardlinks = append(*hardlinks, found...)
		fail(herr)
		if sk, isLink := configstore.SymlinkTarget(path); isLink {
			slog.Warn("zeroize: rsyslog drop-in is a symlink; NOT erasing it",
				"path", sk.Path, "target", sk.Target)
			*skipped = append(*skipped, sk)
			continue
		}
		fail(os.Remove(path))
	}
}

// zeroizeFirewallLogs erases the prior tenant's firewall logs as part of a
// factory reset (#10300): without it `request system zeroize` returned a clean
// receipt while the session/policy/NAT forensics survived under /var/log for
// the next tenant (or disk owner) to read. Security-critical: any error is
// surfaced so a partial wipe is never reported as a clean factory reset.
//
// The wiped surface, enumerated from the logging paths (miss none):
//   - /var/log/xpf/security.log plus .<N> rotations (static default);
//   - /var/log/xpf-flow-trace/*, the whole dedicated interactive-trace dir;
//   - /var/log/<trace> plus .<N> rotations (configured persistent trace);
//   - /var/log/<name> and recognized host-rotation forms for each configured
//     `system syslog file` output;
//   - /etc/rsyslog.d/10-xpf-*.conf, the xpf-owned selectors that would
//     otherwise recreate those outputs after a daemon restart.
//
// Explicitly NOT covered (receipt scope): journald copies and the remote
// syslog collector (the durable cross-wipe record lives there by design,
// #4108 F8). The console offline path with no loaded config cannot name
// custom syslog/trace destinations (same honest disposition as a custom
// archive dir there, #7173); its static xpf log surfaces are still erased.
func zeroizeFirewallLogs(inv ZeroizeLogInventory) error {
	var firstErr error
	fail := func(err error) {
		if err != nil && !errors.Is(err, os.ErrNotExist) && firstErr == nil {
			firstErr = err
		}
	}
	var skipped []configstore.SymlinkedTarget
	var hardlinks []configstore.HardlinkedPath

	// Static legs: the security log (fixed default path) and the dedicated
	// interactive-trace namespace. RemoveAll on a symlinked trace dir unlinks
	// the LINK only and is honest here: openTraceFile refuses a symlinked dir
	// (#8482), so nothing xpf owns was ever written through it.
	zeroizeRemoveLogGenerations(zeroizeSecurityLogDir, zeroizeSecurityLogBase, fail, &hardlinks)
	found, herr := configstore.CollectHardlinkedFiles(zeroizeFlowTraceDir, "")
	hardlinks = append(hardlinks, found...)
	fail(herr)
	fail(os.RemoveAll(zeroizeFlowTraceDir))

	// Configured persistent trace, plus the writer's rotated generations.
	if inv.TraceFile != "" {
		if !zeroizeValidLogBaseName(inv.TraceFile) {
			slog.Warn("zeroize: ignoring invalid flow-trace filename; the writer refuses it too, so no trace was written",
				"name", inv.TraceFile)
		} else {
			zeroizeRemoveLogGenerations(zeroizeVarLogDir, inv.TraceFile, fail, &hardlinks)
		}
	}

	// Configured syslog file outputs. Rsyslog itself does not rotate these
	// destinations (#7146), but host logrotate may leave numeric/compressed or
	// dateext generations. They are still firewall logs for this basename and
	// are removed by the same exact-name recognizer.
	for _, name := range inv.SyslogFiles {
		if err := config.ValidateSyslogFileName(name, nil); err != nil {
			slog.Warn("zeroize: ignoring invalid syslog file name; no drop-in was rendered for it, so rsyslog wrote nothing",
				"name", name, "err", err)
			continue
		}
		zeroizeRemoveSyslogGenerations(zeroizeVarLogDir, name, fail, &skipped, &hardlinks)
	}

	// Remove xpf-owned rsyslog selectors as part of the same firewall-log
	// surface. This leg is independent of the config inventory because stale
	// selectors are exactly what can recreate configured outputs after the
	// config state has been erased.
	zeroizeRemoveRsyslogDropins(zeroizeRsyslogConfDir, fail, &skipped, &hardlinks)

	// Durability (#5197): make the unlinks stable before the reboot that
	// completes the reset. A dir that no longer exists (or never did) holds
	// nothing to make durable, so only existing dirs are synced.
	if st, err := os.Stat(zeroizeSecurityLogDir); err == nil && st.IsDir() {
		fail(zeroizeSyncDir(zeroizeSecurityLogDir))
	}
	if st, err := os.Stat(zeroizeVarLogDir); err == nil && st.IsDir() {
		fail(zeroizeSyncDir(zeroizeVarLogDir))
	}
	if st, err := os.Stat(zeroizeRsyslogConfDir); err == nil && st.IsDir() {
		fail(zeroizeSyncDir(zeroizeRsyslogConfDir))
	}

	var result []error
	if len(skipped) > 0 {
		result = append(result, &configstore.FactoryResetSymlinkError{Skipped: skipped})
	}
	if len(hardlinks) > 0 {
		result = append(result, &configstore.FactoryResetHardlinkError{Paths: hardlinks})
	}
	if firstErr != nil {
		result = append(result, firstErr)
	}
	switch len(result) {
	case 0:
		return nil
	case 1:
		return result[0]
	default:
		return errors.Join(result...)
	}
}

// PerformZeroizeWipeWithLogInventory is the shared factory-reset primitive
// entry point for callers that can snapshot the configured log names before
// the config leg erases them. The legacy PerformZeroizeWipe wrapper below
// supplies an empty inventory for callers that do not have a config store.
func PerformZeroizeWipeWithLogInventory(configDir, configBase, archiveDir string, inv ZeroizeLogInventory) error {
	return performZeroizeWipeWithLogInventory(configDir, configBase, archiveDir, inv)
}

// performZeroizeWipeWithLogInventory keeps the existing three-argument wipe
// seam intact for older tests/callers while adding the log leg after it. The
// production gRPC and console paths call this four-argument entry point with
// the pre-wipe inventory.
var performZeroizeWipeWithLogInventory = func(configDir, configBase, archiveDir string, inv ZeroizeLogInventory) error {
	var errs []error
	if err := performZeroizeWipe(configDir, configBase, archiveDir); err != nil {
		errs = append(errs, err)
	}
	if err := zeroizeFirewallLogs(inv); err != nil {
		errs = append(errs, err)
	}
	switch len(errs) {
	case 0:
		return nil
	case 1:
		return errs[0]
	default:
		return errors.Join(errs...)
	}
}
