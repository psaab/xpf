package cli

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/psaab/xpf/pkg/diagcmd"
)

func (c *CLI) handlePing(args []string) error {
	if len(args) == 0 {
		fmt.Println("usage: ping <target> [count <N>] [source <IP>] [size <N>] [routing-instance <name>]")
		return nil
	}

	target := args[0]
	count := "5"
	source := ""
	size := ""
	vrfName := ""

	for i := 1; i < len(args)-1; i++ {
		switch args[i] {
		case "count":
			count = args[i+1]
			i++
		case "source":
			source = args[i+1]
			i++
		case "size":
			size = args[i+1]
			i++
		case "routing-instance":
			vrfName = args[i+1]
			i++
		}
	}

	// #10727 A10-F5: the local path must enforce the same field bounds as
	// REST/gRPC (diagcmd.CheckArgs) instead of handing raw tokens to exec.
	if err := diagcmd.CheckArgs(target, source, vrfName); err != nil {
		return err
	}
	cmdArgs := buildPingArgv(target, count, source, size, vrfName)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	c.cmdMu.Lock()
	c.cmdCancel = cancel
	c.cmdMu.Unlock()
	defer func() {
		c.cmdMu.Lock()
		c.cmdCancel = nil
		c.cmdMu.Unlock()
	}()

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	// #7389: sanitize this command's output before it reaches the
	// terminal. See wireSanitizedOutput for why both streams go through one
	// call.
	defer wireSanitizedOutput(cmd)()
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil // cancelled by Ctrl-C or timeout
	}
	return err
}

// buildPingArgv builds the argv for the local CLI ping command. It
// delegates to the shared diagcmd builder so the VRF-device
// normalization (apply "vrf-" exactly once, #2143) and the "--"
// end-of-options separator (#2084) match the REST and gRPC surfaces
// byte-for-byte. Before #2143 this path prepended "vrf-"
// unconditionally, turning `routing-instance vrf-red` into the
// non-existent device `vrf-vrf-red`.
//
// The payload size is clamped to diagcmd.MaxPingSize so this third
// control surface shares the single upper ceiling the REST and gRPC
// buildPingArgv callers already enforce (#6382, mirroring #5250 A8-b1
// F4): a -s above the max valid ICMP echo data could never yield a
// valid probe.
//
// size arrives here as the RAW operator token, unlike the structured
// int the REST/gRPC surfaces receive (where 0 means "unset" and -s is
// omitted unless positive). Only the upper MaxPingSize ceiling is
// enforced here — the console INTENTIONALLY preserves an explicit
// operator -s for zero, negative, and non-numeric tokens, handing them
// to the ping child to reject rather than silently dropping input the
// operator typed. Silently swallowing an explicit `-s 0` would be less
// faithful to intent than the structured-int surfaces' "0 == unset".
//
// A numeric token that is too large is clamped whether it merely
// exceeds MaxPingSize (parses fine, n > ceiling) OR overflows int64
// (strconv.ErrRange on a non-negative literal) — the latter is the
// bug the naive strconv.Atoi guard missed, since Atoi returns ErrRange
// and would leave the huge token to reach `ping -s <huge>` unclamped.
// A leading '-' overflow stays a huge negative the child rejects,
// consistent with the ≤0 pass-through above.
func buildPingArgv(target, count, source, size, vrfName string) []string {
	// #10727 A10-F5: a parseable count clamps to the shared 1..100 rule;
	// a non-numeric token is preserved for the ping child to reject,
	// mirroring the -s handling below (never silently rewrite input).
	if n, err := strconv.Atoi(count); err == nil {
		count = strconv.Itoa(diagcmd.ClampPingCount(n))
	} else if errors.Is(err, strconv.ErrRange) && !strings.HasPrefix(count, "-") {
		count = strconv.Itoa(diagcmd.MaxPingCount)
	}
	if n, err := strconv.ParseInt(size, 10, 64); err == nil {
		if n > diagcmd.MaxPingSize {
			size = strconv.Itoa(diagcmd.MaxPingSize)
		}
	} else if errors.Is(err, strconv.ErrRange) && !strings.HasPrefix(size, "-") {
		size = strconv.Itoa(diagcmd.MaxPingSize)
	}
	return diagcmd.PingArgv(diagcmd.PingOptions{
		Target:          target,
		Count:           count,
		Source:          source,
		Size:            size,
		RoutingInstance: vrfName,
	})
}

func (c *CLI) handleTraceroute(args []string) error {
	if len(args) == 0 {
		fmt.Println("usage: traceroute <target> [source <IP>] [routing-instance <name>]")
		return nil
	}

	target := args[0]
	source := ""
	vrfName := ""

	for i := 1; i < len(args)-1; i++ {
		switch args[i] {
		case "source":
			source = args[i+1]
			i++
		case "routing-instance":
			vrfName = args[i+1]
			i++
		}
	}

	// #10727 A10-F5: same shared field bounds as ping (see handlePing).
	if err := diagcmd.CheckArgs(target, source, vrfName); err != nil {
		return err
	}
	cmdArgs := buildTracerouteArgv(target, source, vrfName)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	c.cmdMu.Lock()
	c.cmdCancel = cancel
	c.cmdMu.Unlock()
	defer func() {
		c.cmdMu.Lock()
		c.cmdCancel = nil
		c.cmdMu.Unlock()
	}()

	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	// #7389: sanitize this command's output before it reaches the
	// terminal. See wireSanitizedOutput for why both streams go through one
	// call.
	defer wireSanitizedOutput(cmd)()
	err := cmd.Run()
	if ctx.Err() != nil {
		return nil // cancelled by Ctrl-C or timeout
	}
	return err
}

// buildTracerouteArgv builds the argv for the local CLI traceroute
// command. Like buildPingArgv it delegates to the shared diagcmd builder
// so VRF normalization (#2143) and the "--" separator (#2084) stay
// identical across the CLI, REST, and gRPC surfaces.
func buildTracerouteArgv(target, source, vrfName string) []string {
	return diagcmd.TracerouteArgv(diagcmd.TracerouteOptions{
		Target:          target,
		Source:          source,
		RoutingInstance: vrfName,
	})
}
