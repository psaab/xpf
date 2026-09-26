package cli

import (
	"fmt"
	"io"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/psaab/xpf/pkg/config"
	dpuserspace "github.com/psaab/xpf/pkg/dataplane/userspace"
	"github.com/psaab/xpf/pkg/monitoriface"
	"golang.org/x/sys/unix"
)

type ifaceSnapshot = monitoriface.Snapshot
type userspaceIfaceSnapshot = monitoriface.UserspaceSnapshot

var _ monitoriface.RuntimeDataPlane = monitorInterfaceRuntimeDataPlane{}

type monitorInterfaceRuntimeDataPlane struct {
	cli *CLI
}

func (a monitorInterfaceRuntimeDataPlane) IsLoaded() bool {
	return a.cli != nil && a.cli.dp != nil && a.cli.dp.IsLoaded()
}

func (a monitorInterfaceRuntimeDataPlane) ReadInterfaceCounters(ifindex int) (monitoriface.InterfaceCounters, error) {
	if a.cli == nil || a.cli.dp == nil {
		return monitoriface.InterfaceCounters{}, fmt.Errorf("dataplane unavailable")
	}
	ctrs, err := a.cli.dp.ReadInterfaceCounters(ifindex)
	if err != nil {
		return monitoriface.InterfaceCounters{}, err
	}
	return monitoriface.InterfaceCounters{
		RxPackets: ctrs.RxPackets,
		RxBytes:   ctrs.RxBytes,
		TxPackets: ctrs.TxPackets,
		TxBytes:   ctrs.TxBytes,
	}, nil
}

// setRawMode puts the terminal into raw mode for single-character reads.
//
// VMIN=0/VTIME=1 selects a poll-with-timeout read: os.Stdin.Read returns
// immediately when a key is available and otherwise returns (0, nil) after
// 100ms with no data. This lets the key-reader goroutine observe its stop
// signal between reads and return, instead of staying parked forever in a
// blocking Read after the monitor exits (which would steal the next command's
// keystroke — #3985). VMIN=1/VTIME=0 would block indefinitely and could not be
// stopped without a keypress.
func setRawMode(fd int) (*unix.Termios, error) {
	old, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return nil, err
	}
	raw := *old
	raw.Lflag &^= unix.ECHO | unix.ICANON | unix.ISIG
	raw.Cc[unix.VMIN] = 0
	raw.Cc[unix.VTIME] = 1
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &raw); err != nil {
		return nil, err
	}
	return old, nil
}

// keyReader reads single bytes from r and forwards them on keyCh until done is
// closed, then returns. r must be a poll-mode reader (a raw tty configured with
// VMIN=0/VTIME>0 via setRawMode) so that Read returns periodically with n==0
// when idle, letting the loop observe done and return. Without this the
// goroutine would remain blocked in Read after the monitor exits and consume
// the operator's next keystroke (#3985). A byte read after done is closed is
// discarded rather than forwarded, so no stale monitor input reaches a caller.
func keyReader(r io.Reader, keyCh chan<- byte, done <-chan struct{}) {
	buf := make([]byte, 1)
	for {
		select {
		case <-done:
			return
		default:
		}
		n, err := r.Read(buf)
		if err != nil {
			return
		}
		if n == 0 {
			// VTIME poll timeout with no data — loop and re-check done.
			continue
		}
		select {
		case keyCh <- buf[0]:
		case <-done:
			return
		}
	}
}

// startKeyReader launches a keyReader goroutine reading from r and returns the
// key channel plus a stop function. The stop function closes the done channel
// and blocks until the goroutine has returned, guaranteeing that no reader is
// left competing for stdin once the monitor exits (#3985). Callers defer stop
// so it runs before the terminal is restored and control returns to the CLI.
func startKeyReader(r io.Reader) (<-chan byte, func()) {
	keyCh := make(chan byte, 8)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		keyReader(r, keyCh, done)
	}()
	var once sync.Once
	return keyCh, func() {
		once.Do(func() {
			close(done)
			wg.Wait()
		})
	}
}

func restoreTermMode(fd int, old *unix.Termios) {
	_ = unix.IoctlSetTermios(fd, unix.TCSETS, old)
}

const (
	enterAltScreen = "\x1b[?1049h"
	exitAltScreen  = "\x1b[?1049l"
	clearAndHome   = "\x1b[2J\x1b[H"
	hideCursor     = "\x1b[?25l"
	showCursor     = "\x1b[?25h"
)

func resolveFabricParent(name string) string {
	return monitoriface.ResolvePhysicalParent(name)
}

func aggregateUserspaceIfaceSnapshot(kernelName string, status dpuserspace.ProcessStatus) *userspaceIfaceSnapshot {
	return monitoriface.AggregateUserspaceSnapshot(kernelName, status)
}

func renderSingleInterface(w io.Writer, hostname, displayName, kernelName string, snap, prev, baseline *ifaceSnapshot, startTime time.Time) {
	monitoriface.RenderSingleInterface(w, hostname, displayName, kernelName, snap, prev, baseline, startTime, "")
}

// handleMonitorInterface dispatches monitor interface sub-commands.
func (c *CLI) handleMonitorInterface(args []string) error {
	if len(args) == 0 {
		monTree := operationalTree["monitor"].Children["interface"]
		fmt.Println("monitor interface:")
		writeCompletionHelp(os.Stdout, treeHelpCandidates(monTree.Children))
		cfg := c.store.ActiveConfig()
		if monTree.DynamicFn != nil && cfg != nil {
			names := monTree.DynamicFn(cfg)
			sort.Strings(names)
			for _, n := range names {
				fmt.Printf("  %-30s Interface name\n", n)
			}
		}
		return nil
	}

	if args[0] == "traffic" {
		mode, err := parseMonitorSummaryMode(args[1:])
		if err != nil {
			return err
		}
		return c.monitorInterfaceTraffic(mode)
	}

	return c.monitorInterfaceSingle(args[0])
}

func parseMonitorSummaryMode(args []string) (monitoriface.SummaryMode, error) {
	if len(args) == 0 {
		return monitoriface.SummaryModeCombined, nil
	}
	mode, ok := monitoriface.ParseSummaryMode(args[0])
	if !ok {
		return monitoriface.SummaryModeCombined, fmt.Errorf("unknown monitor interface traffic mode: %s", args[0])
	}
	return mode, nil
}

// sortedConfiguredInterfaces returns sorted interface names from active config.
func (c *CLI) sortedConfiguredInterfaces() []string {
	cfg := c.store.ActiveConfig()
	if cfg == nil || cfg.Interfaces.Interfaces == nil {
		return nil
	}
	names := make([]string, 0, len(cfg.Interfaces.Interfaces))
	for name := range cfg.Interfaces.Interfaces {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (c *CLI) sortedMonitorInterfaces() []string {
	names, _ := monitoriface.TrafficSummaryInterfaces(c.store.ActiveConfig())
	if len(names) > 0 {
		return names
	}
	return c.sortedConfiguredInterfaces()
}

func (c *CLI) summaryInterfaces() ([]string, map[string]string) {
	names, kernelNames := monitoriface.TrafficSummaryInterfaces(c.store.ActiveConfig())
	if len(names) > 0 {
		return names, kernelNames
	}
	names = c.sortedConfiguredInterfaces()
	kernelNames = make(map[string]string, len(names))
	for _, name := range names {
		kernelNames[name] = monitoriface.ResolvePhysicalParent(c.resolveToKernel(name))
	}
	return names, kernelNames
}

// resolveToKernel converts a config-level name (ge-0/0/0, reth0, fab0) to kernel name.
func (c *CLI) resolveToKernel(cfgName string) string {
	cfg := c.store.ActiveConfig()
	if cfg != nil {
		cfgName = cfg.ResolveReth(cfgName)
		cfgName = cfg.ResolveFab(cfgName)
	}
	return config.LinuxIfName(cfgName)
}

func (c *CLI) readMonitorSnapshot(kernelName string) (monitoriface.Snapshot, error) {
	return monitoriface.ReadSnapshot(c.monitorInterfaceDataplane(), c.userspaceDataplaneStatus, kernelName)
}

func (c *CLI) monitorInterfaceDataplane() monitoriface.RuntimeDataPlane {
	if c == nil || c.dp == nil {
		return nil
	}
	return monitorInterfaceRuntimeDataPlane{cli: c}
}

// monitorInterfaceSingle shows full-screen stats for a single interface.
func (c *CLI) monitorInterfaceSingle(ifaceName string) error {
	displayName := ifaceName
	kernelName := monitoriface.ResolvePhysicalParent(c.resolveToKernel(ifaceName))
	if _, err := c.readMonitorSnapshot(kernelName); err != nil {
		return fmt.Errorf("interface %s not found", ifaceName)
	}

	fd := int(os.Stdin.Fd())
	old, err := setRawMode(fd)
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer restoreTermMode(fd, old)

	fmt.Print(enterAltScreen + hideCursor)
	defer fmt.Print(showCursor + exitAltScreen)

	// Stop the stdin reader before restoring the terminal so no goroutine is
	// left parked in os.Stdin.Read stealing the next command's key (#3985).
	keyCh, stopKeys := startKeyReader(os.Stdin)
	defer stopKeys()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	var prev *monitoriface.Snapshot
	var baseline *monitoriface.Snapshot
	trackedKernel := kernelName
	deviceNote := ""
	frozen := false
	allIfaces := c.sortedMonitorInterfaces()

	renderNow := func() {
		kn := monitoriface.ResolvePhysicalParent(c.resolveToKernel(displayName))
		// #10838: the display name can re-resolve to a different kernel device
		// mid-stream (RG failover, member change, config commit). Deltas against
		// the old device's prev/baseline would be cross-device garbage
		// (clamped-0 or spikes), so drop them and say so — the same
		// reset/annotate contract the gRPC stream applies.
		if note := monitoriface.ResetOnDeviceChange(displayName, &trackedKernel, kn, &prev, &baseline); note != "" {
			deviceNote = note
		}
		snap, err := c.readMonitorSnapshot(kn)
		if err != nil {
			return
		}
		if baseline == nil {
			snapCopy := snap
			baseline = &snapCopy
		}
		fmt.Print(clearAndHome)
		monitoriface.RenderSingleInterface(os.Stdout, c.hostname, displayName, kn, &snap, prev, baseline, startTime, deviceNote)
		snapCopy := snap
		prev = &snapCopy
	}
	renderNow()

	for {
		select {
		case <-ticker.C:
			if !frozen {
				renderNow()
			}
		case key := <-keyCh:
			switch key {
			case 'q', 'Q', 0x1b, 0x03:
				return nil
			case 'f', 'F':
				frozen = true
			case 't', 'T':
				frozen = false
			case 'c', 'C':
				baseline = nil
				prev = nil
				renderNow()
			case 'n', 'N':
				if len(allIfaces) > 1 {
					idx := 0
					for i, n := range allIfaces {
						if n == displayName {
							idx = (i + 1) % len(allIfaces)
							break
						}
					}
					displayName = allIfaces[idx]
					prev = nil
					baseline = nil
					deviceNote = ""
					trackedKernel = monitoriface.ResolvePhysicalParent(c.resolveToKernel(displayName))
					startTime = time.Now()
					renderNow()
				}
			}
		}
	}
}

// monitorInterfaceTraffic shows a full-screen all-interfaces summary table.
func (c *CLI) monitorInterfaceTraffic(mode monitoriface.SummaryMode) error {
	fd := int(os.Stdin.Fd())
	old, err := setRawMode(fd)
	if err != nil {
		return fmt.Errorf("failed to set raw mode: %w", err)
	}
	defer restoreTermMode(fd, old)

	fmt.Print(enterAltScreen + hideCursor)
	defer fmt.Print(showCursor + exitAltScreen)

	// Stop the stdin reader before restoring the terminal so no goroutine is
	// left parked in os.Stdin.Read stealing the next command's key (#3985).
	keyCh, stopKeys := startKeyReader(os.Stdin)
	defer stopKeys()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	startTime := time.Now()
	prevSnaps := make(map[string]*monitoriface.Snapshot)

	renderNow := func() {
		names, kernelNames := c.summaryInterfaces()
		snaps := make(map[string]*monitoriface.Snapshot, len(names))
		for _, name := range names {
			snap, err := c.readMonitorSnapshot(kernelNames[name])
			if err != nil {
				continue
			}
			snapCopy := snap
			snaps[name] = &snapCopy
		}
		fmt.Print(clearAndHome)
		monitoriface.RenderTrafficSummary(os.Stdout, c.hostname, names, kernelNames, snaps, prevSnaps, mode, startTime)
		prevSnaps = snaps
	}
	renderNow()

	for {
		select {
		case <-ticker.C:
			renderNow()
		case key := <-keyCh:
			switch key {
			case 'q', 'Q', 0x1b, 0x03:
				return nil
			case 'c', 'C':
				mode = monitoriface.SummaryModeCombined
				renderNow()
			case 'p', 'P':
				mode = monitoriface.SummaryModePackets
				renderNow()
			case 'b', 'B':
				mode = monitoriface.SummaryModeBytes
				renderNow()
			case 'd', 'D':
				mode = monitoriface.SummaryModeDelta
				renderNow()
			case 'r', 'R':
				mode = monitoriface.SummaryModeRate
				renderNow()
			}
		}
	}
}
