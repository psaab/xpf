package upgrade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/fsatomic"
	"golang.org/x/sys/unix"
)

// realSystem is the production System backed by systemctl + the OS.
type realSystem struct {
	// systemdUnitDir is /etc/systemd/system (drop-ins go under
	// <unit>.service.d/). Overridable for tests.
	systemdUnitDir string
	// unit is the systemd unit name (without .service) the health probe
	// polls. Must match the Runner's Config.Unit (Codex r1 Medium: a
	// custom --unit must not be ignored by the health check).
	unit string
	// helperHealth is an optional hook the daemon wires to check its
	// running helper's reported version (set by the caller in xpfd, which
	// has the userspace manager). When nil, HelperHealthy degrades to a
	// fixed settle wait (the unit being active is the signal).
	helperHealth func(expectVersion string, deadline time.Duration) error
}

// NewSystem returns the production System implementation for the given
// systemd unit.
func NewSystem(unit string) System {
	if unit == "" {
		unit = DefaultUnit
	}
	return &realSystem{systemdUnitDir: "/etc/systemd/system", unit: unit}
}

// NewSystemWithHelperHealth returns the production System with a helper
// health probe (used by xpfd, which can query its own helper version).
func NewSystemWithHelperHealth(unit string, probe func(expectVersion string, deadline time.Duration) error) System {
	if unit == "" {
		unit = DefaultUnit
	}
	return &realSystem{systemdUnitDir: "/etc/systemd/system", unit: unit, helperHealth: probe}
}

func (s *realSystem) StopUnit(unit string) error {
	return runCmd("systemctl", "stop", unit+".service")
}

func (s *realSystem) StartUnit(unit string) error {
	return runCmd("systemctl", "start", unit+".service")
}

func (s *realSystem) DaemonReload() error {
	return runCmd("systemctl", "daemon-reload")
}

func (s *realSystem) WriteUnitDropin(unit, name, content string) error {
	dir := filepath.Join(s.systemdUnitDir, unit+".service.d")
	if err := fsatomic.MkdirAllDurable(dir, 0755); err != nil {
		return fmt.Errorf("create drop-in dir: %w", err)
	}
	return fsatomic.WriteFileDurable(filepath.Join(dir, name), []byte(content), 0644)
}

func (s *realSystem) FreeBytes(path string) (uint64, error) {
	var st unix.Statfs_t
	// Stat the nearest existing ancestor so a not-yet-created versions dir
	// still yields the backing filesystem's free space.
	p := path
	for {
		if _, err := os.Stat(p); err == nil {
			break
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
		p = parent
	}
	if err := unix.Statfs(p, &st); err != nil {
		return 0, fmt.Errorf("statfs %s: %w", p, err)
	}
	return st.Bavail * uint64(st.Bsize), nil
}

func (s *realSystem) VerifyDataplane(bin string, env []string) (bool, error) {
	cmd := exec.Command(bin, "verify-dataplane")
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err == nil {
		return true, nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		// exit 3 = REJECT (verifier rejected the shim). main.go contract.
		if ee.ExitCode() == 3 {
			return false, nil
		}
	}
	return false, fmt.Errorf("verify-dataplane exec failed: %w (output: %s)", err, strings.TrimSpace(out.String()))
}

func (s *realSystem) BinaryVersion(bin string) (string, error) {
	cmd := exec.Command(bin, "version")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s version: %w (output: %s)", bin, err, strings.TrimSpace(out.String()))
	}
	// Output shape: "xpfd <version> (commit <c>, built <t>)".
	//
	// The extracted token keys the on-disk runtime layout (versions/<ver>/,
	// the `current` symlink target, the per-version DB-snapshot dotfile, the
	// unit drop-in ExecStart). A corrupt binary, an arch/lib mismatch that
	// still execs but prints garbage, or a benign future change to the
	// `version` output format must NOT yield a path-escaping or whitespace-
	// laden "version" that strands the cut or escapes VersionsDir (#1967 C1).
	// So validate the extracted token as a safe single path segment and hard-
	// fail otherwise — NEVER fall back to returning the whole trimmed output.
	trimmed := strings.TrimSpace(out.String())
	fields := strings.Fields(out.String())
	if len(fields) >= 2 && fields[0] == "xpfd" {
		if verr := ValidateVersionSegment(fields[1]); verr != nil {
			return "", fmt.Errorf("%s version: token %q is not a safe path "+
				"segment: %w (full output: %q)", bin, fields[1], verr, trimmed)
		}
		return fields[1], nil
	}
	return "", fmt.Errorf("%s version: unrecognized output format "+
		"(want \"xpfd <version> ...\"): %q", bin, trimmed)
}

// EnvelopeReaderVersion invokes the target's side-effect-free
// `--capability-check` probe and parses its envelope reader major. The target
// path is supplied by the validated rollback version directory, never PATH.
func (s *realSystem) EnvelopeReaderVersion(bin string) (int, error) {
	cmd := exec.Command(bin, "--capability-check")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("%s capability-check: %w (output: %s)",
			bin, err, strings.TrimSpace(out.String()))
	}
	for _, line := range strings.Split(out.String(), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if key != "configdb-envelope-version" || !ok {
			continue
		}
		reader, err := strconv.Atoi(value)
		if err != nil || reader < 1 {
			return 0, fmt.Errorf("%s capability-check: invalid "+
				"configdb-envelope-version=%q", bin, value)
		}
		return reader, nil
	}
	return 0, fmt.Errorf("%s capability-check: missing configdb-envelope-version "+
		"in output %q", bin, strings.TrimSpace(out.String()))
}

// unitActiveProbeCtx reports whether <unit>.service is active per `systemctl
// is-active`, BOUNDED by ctx (#5808): a wedged systemctl / hung DBus is KILLED
// when ctx is canceled (exec.CommandContext) instead of blocking the caller past
// its deadline. It is the SINGLE production is-active primitive — the
// is-active-only fallback below, the wired HelperHealthProbe precondition, AND
// cmd/xpfd's probe (via the exported UnitActive) all route through it, so there
// is exactly ONE timeout behavior (no more two divergent exec.Command impls).
//
// A package var so a test can force it. Forcing it is the hinge of the #5286
// RED-on-revert (process ACTIVE but helper NOT armed+forwarding is healthy under
// the OLD is-active-only path, fails closed under the new gate) AND the #5808
// deadline tests (a fake that blocks until ctx cancels).
//
// Return semantics (#5808): (active, nil) is definitive; (false, ctx.Err()) when
// the deadline/cancel killed the probe (errors.Is-able); (false, err) for a
// genuine command failure (systemctl missing / DBus error). `systemctl
// is-active` exits non-zero (3) for inactive/failed/activating and prints the
// state to stdout — a recognized state under an *exec.ExitError is a DEFINITIVE
// answer, NOT a command failure.
var unitActiveProbeCtx = func(ctx context.Context, unit string) (bool, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "is-active", unit+".service").Output()
	state := strings.TrimSpace(string(out))
	if err != nil {
		if ctx.Err() != nil {
			return false, ctx.Err() // deadline/cancel killed the probe
		}
		var ee *exec.ExitError
		if errors.As(err, &ee) && state != "" {
			return state == "active", nil // definitive not-active, not a failure
		}
		return false, fmt.Errorf("systemctl is-active %s: %w (output: %q)", unit, err, state)
	}
	return state == "active", nil
}

// UnitActive is the exported, ctx-bounded is-active primitive so cmd/xpfd wires
// ONE shared impl (through the unitActiveProbeCtx seam) rather than duplicating
// exec.Command with its own, unbounded timeout behavior (#5808 unification).
func UnitActive(ctx context.Context, unit string) (bool, error) {
	return unitActiveProbeCtx(ctx, unit)
}

func (s *realSystem) HelperHealthy(expectVersion string, deadline time.Duration) error {
	if s.helperHealth != nil {
		return s.helperHealth(expectVersion, deadline)
	}
	// Fallback (NO probe wired — e.g. a non-xpfd caller or a test): poll
	// `systemctl is-active` until active or deadline.
	//
	// #5286: this is the WEAK is-active-only signal production no longer relies
	// on. A Type=simple xpfd reports active immediately, so this proxy admits a
	// daemon whose helper is down / stale / crash-looping and NOT forwarding.
	// The production upgrade path wires a real probe via
	// NewSystemWithHelperHealth (cmd/xpfd) that ADDITIONALLY requires the
	// dataplane to be armed+forwarding on the target version. This branch
	// remains only for callers that inject no probe.
	// #5808: bound the whole fallback poll by one context — the is-active probe
	// (killed if it wedges) and the poll wait — so this weak path also honors the
	// deadline authoritatively and never strands on a hung systemctl/DBus.
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()
	for {
		active, err := unitActiveProbeCtx(ctx, s.unit)
		if err == nil && active {
			return nil
		}
		if ctx.Err() != nil {
			return fmt.Errorf("unit %s did not become active within %s (last: %v): %w",
				s.unit, deadline, err, ctx.Err())
		}
		timer := time.NewTimer(500 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("unit %s did not become active within %s (last: %v): %w",
				s.unit, deadline, err, ctx.Err())
		case <-timer.C:
		}
	}
}

func (s *realSystem) Now() time.Time { return time.Now() }

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(out.String()))
	}
	return nil
}
