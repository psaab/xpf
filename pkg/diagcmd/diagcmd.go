// Package diagcmd holds the shared argv-construction logic for the
// ping/traceroute diagnostics that the local CLI, the REST API, and the
// gRPC API all expose. Keeping the VRF-device normalization and the
// option-confusion hardening in one place prevents the three control
// surfaces from drifting apart: before this package existed the local
// CLI unconditionally prepended "vrf-" while REST and gRPC guarded
// against a name that already started with "vrf-", so the same
// `routing-instance vrf-red` produced a non-existent `vrf-vrf-red`
// device on the CLI but the correct `vrf-red` device on the APIs
// (#2143). The "--" end-of-options separator (#2084) likewise had to be
// applied three times; it now lives here too.
package diagcmd

import (
	"fmt"
	"strconv"
	"strings"
)

// PingRequestOptions is the validated CLI ping selector set. Numeric values
// are parsed here so command surfaces cannot silently ignore malformed input.
type PingRequestOptions struct {
	Target, Source, RoutingInstance string
	Count, Size                     int
	SizeSet                         bool
}

// TracerouteRequestOptions is the validated CLI traceroute selector set.
type TracerouteRequestOptions struct {
	Target, Source, RoutingInstance string
}

// ParsePingOptions parses the positional target and its optional selectors.
func ParsePingOptions(args []string) (PingRequestOptions, error) {
	if len(args) == 0 {
		return PingRequestOptions{}, fmt.Errorf("ping requires a target")
	}
	out := PingRequestOptions{Target: args[0], Count: DefaultPingCount}
	seen := map[string]bool{}
	for i := 1; i < len(args); i++ {
		key := args[i]
		if key != "count" && key != "source" && key != "size" && key != "routing-instance" {
			return PingRequestOptions{}, fmt.Errorf("ping: unknown option %q", key)
		}
		if seen[key] {
			return PingRequestOptions{}, fmt.Errorf("ping: duplicate option %q", key)
		}
		seen[key] = true
		if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
			return PingRequestOptions{}, fmt.Errorf("ping: option %q requires a value", key)
		}
		value := args[i+1]
		if value == "count" || value == "source" || value == "size" || value == "routing-instance" {
			return PingRequestOptions{}, fmt.Errorf("ping: option %q requires a non-option value", key)
		}
		i++
		switch key {
		case "count":
			n, err := strconv.Atoi(value)
			if err != nil {
				return PingRequestOptions{}, fmt.Errorf("ping: invalid count %q: must be a number", value)
			}
			out.Count = n
		case "size":
			n, err := strconv.Atoi(value)
			if err != nil {
				return PingRequestOptions{}, fmt.Errorf("ping: invalid size %q: must be a number", value)
			}
			out.Size = n
			out.SizeSet = true
		case "source":
			out.Source = value
		case "routing-instance":
			out.RoutingInstance = value
		}
	}
	return out, nil
}

// ParseTracerouteOptions parses the positional target and its optional selectors.
func ParseTracerouteOptions(args []string) (TracerouteRequestOptions, error) {
	if len(args) == 0 {
		return TracerouteRequestOptions{}, fmt.Errorf("traceroute requires a target")
	}
	out := TracerouteRequestOptions{Target: args[0]}
	seen := map[string]bool{}
	for i := 1; i < len(args); i++ {
		key := args[i]
		if key != "source" && key != "routing-instance" {
			return TracerouteRequestOptions{}, fmt.Errorf("traceroute: unknown option %q", key)
		}
		if seen[key] {
			return TracerouteRequestOptions{}, fmt.Errorf("traceroute: duplicate option %q", key)
		}
		seen[key] = true
		if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
			return TracerouteRequestOptions{}, fmt.Errorf("traceroute: option %q requires a value", key)
		}
		value := args[i+1]
		if value == "source" || value == "routing-instance" {
			return TracerouteRequestOptions{}, fmt.Errorf("traceroute: option %q requires a non-option value", key)
		}
		i++
		if key == "source" {
			out.Source = value
		} else {
			out.RoutingInstance = value
		}
	}
	return out, nil
}

// ParseTestInterface parses test security-zone's one required interface selector.
func ParseTestInterface(args []string) (value string, present bool, err error) {
	if len(args) == 0 {
		return "", false, nil
	}
	if args[0] != "interface" {
		return "", false, fmt.Errorf("unknown selector %q (want \"interface <name>\")", args[0])
	}
	if len(args) < 2 || strings.TrimSpace(args[1]) == "" {
		return "", false, fmt.Errorf("selector \"interface\" requires a value")
	}
	if strings.ContainsAny(args[1], ",=") {
		return "", false, fmt.Errorf("interface %q contains a comma or equals, which the test security-zone topic cannot carry", args[1])
	}
	if len(args) > 2 {
		return "", false, fmt.Errorf("unknown selector %q (want \"interface <name>\")", args[2])
	}
	return args[1], true, nil
}

// vrfPrefix is the prefix the daemon uses for the kernel VRF master
// device that backs a Junos routing-instance (a routing-instance named
// "red" is realized as the VRF device "vrf-red"). See pkg/cli/apply.go,
// where the daemon creates the device with this exact prefix.
const vrfPrefix = "vrf-"

// VRFDeviceName maps a Junos routing-instance name to the kernel VRF
// master device name the daemon created for it, applying the "vrf-"
// prefix exactly once. A name that the operator already typed with the
// prefix (e.g. "vrf-red") is returned unchanged; a bare name (e.g.
// "red") gets the prefix added. An empty name yields an empty result so
// callers can branch on "no routing-instance requested".
//
// This is the single source of truth for the prefix: applying it again
// at the call site would re-introduce the #2143 double-prefix bug.
func VRFDeviceName(name string) string {
	if name == "" {
		return ""
	}
	if strings.HasPrefix(name, vrfPrefix) {
		return name
	}
	return vrfPrefix + name
}

// MaxPingSize is the largest ping payload (ping -s) any control surface
// accepts. It is the maximum ICMP echo data an IPv4 datagram can carry —
// 65535 (max IP total length) − 20 (IP header) − 8 (ICMP header) = 65507
// — so a request above it could never produce a valid probe anyway. All
// three callers — REST, gRPC, and the local console CLI — clamp the
// operator size to this bound before building the options so an oversized
// -s can neither be passed to the ping child nor wrapped negative;
// validation and clamping stay with the callers per the PingOptions
// contract, but the shared ceiling lives here so every surface stays in
// lockstep (#5250 A8-b1 F4 for REST/gRPC; #6382 for the console CLI).
const MaxPingSize = 65507

// MaxArgLen bounds each operator-supplied diagnostic STRING argument
// (target, source, routing-instance) at every control surface (#6904).
//
// It is a CHOSEN ceiling, not a protocol constant, and it lives here for the
// same reason MaxPingSize does: two surfaces enforcing the same rule from two
// literals is how they drift. #6904 is that drift — gRPC bounded these fields
// and REST did not, so the guarantee the gRPC check was supposed to give was
// not a system property.
//
// The value is derived from the largest LEGITIMATE input with headroom: a DNS
// name is capped at 253 octets (RFC 1035), an IPv6 literal at ~45, and a VRF
// name is short. 512 accepts every legitimate value while rejecting a
// pathological field far below the streamDiagCmd line-scanner token cap. The
// gRPC receive limit is 16 MiB, so without this bound a multi-kilobyte target
// reaches exec and surfaces as a single combined-output line larger than the
// scanner token size — the ErrTooLong leak vector fixed in streamDiagCmd
// (#5060). REST has no equivalent receive cap of its own.
const MaxArgLen = 512

// CheckArg rejects an over-length diagnostic argument so an oversized field
// never reaches exec or the combined-output line scanner (#6904).
//
// It returns a plain error naming the field and both lengths; each surface
// reports it in its own vocabulary — gRPC as codes.InvalidArgument, REST as
// a 400, the CLI unwrapped — so the surfaces share the RULE without sharing
// a status vocabulary.
func CheckArg(name, v string) error {
	if len(v) > MaxArgLen {
		return fmt.Errorf("%s exceeds %d bytes (%d)", name, MaxArgLen, len(v))
	}
	return nil
}

// CheckArgs bounds the shared ping/traceroute string fields in one pass, in a
// FIXED order so every surface reports the same field first for a request that
// violates more than one.
func CheckArgs(target, source, routingInstance string) error {
	for _, f := range []struct{ name, val string }{
		{"target", target},
		{"source", source},
		{"routing-instance", routingInstance},
	} {
		if err := CheckArg(f.name, f.val); err != nil {
			return err
		}
	}
	return nil
}

// DefaultPingCount is the probe count used when the operator does not supply
// one (a REST/gRPC 0, an omitted CLI `count`), and MaxPingCount is the ceiling
// every control surface enforces. They live here next to MaxPingSize and
// MaxArgLen for the same reason: three surfaces enforcing one rule from three
// literals is how they drift (#10727 DR-26:A10-F5 — the local CLI never clamped
// count at all while REST and gRPC each clamped to their own inline 5/100).
const (
	DefaultPingCount = 5
	MaxPingCount     = 100
)

// ClampPingCount maps an operator-supplied probe count to the 1..100 range
// every control surface enforces: <= 0 means "unset" and yields the default 5,
// above 100 is capped at 100. REST and gRPC call it on their structured count;
// the CLI calls it on a successfully-parsed count token (a non-numeric token is
// preserved for the ping child to reject, mirroring the -s handling in the CLI
// builder).
func ClampPingCount(n int) int {
	if n <= 0 {
		return DefaultPingCount
	}
	if n > MaxPingCount {
		return MaxPingCount
	}
	return n
}

// PingOptions carries the already-validated, already-clamped ping
// parameters the three control surfaces collect from their respective
// request shapes (CLI argv, REST JSON, gRPC protobuf). The builder owns
// argv layout only — validation and clamping stay with the callers.
type PingOptions struct {
	Target string
	// Count is the ICMP probe count passed to ping -c. Callers clamp it
	// with ClampPingCount before constructing the options.
	Count string
	// Source is an optional source address (ping -I); empty means omit.
	Source string
	// Size is an optional payload size (ping -s); empty means omit.
	Size string
	// RoutingInstance is the Junos routing-instance name (NOT the
	// vrf-prefixed device name); empty means the global/default table.
	RoutingInstance string
}

// PingArgv builds the full argv for a ping diagnostic. When a
// routing-instance is requested the command is wrapped in
// `ip vrf exec <device> ...` with the device name normalized by
// VRFDeviceName. The user-supplied target is placed after a "--"
// end-of-options separator so a "-"-prefixed target is treated as the
// destination operand rather than a ping flag (#2084).
func PingArgv(opts PingOptions) []string {
	var cmd []string
	if dev := VRFDeviceName(opts.RoutingInstance); dev != "" {
		cmd = append(cmd, "ip", "vrf", "exec", dev)
	}
	cmd = append(cmd, "ping", "-c", opts.Count)
	if opts.Source != "" {
		cmd = append(cmd, "-I", opts.Source)
	}
	if opts.Size != "" {
		cmd = append(cmd, "-s", opts.Size)
	}
	cmd = append(cmd, "--", opts.Target)
	return cmd
}

// TracerouteOptions carries the already-validated traceroute parameters
// the three control surfaces collect from their request shapes.
type TracerouteOptions struct {
	Target string
	// Source is an optional source address (traceroute -s); empty means
	// omit.
	Source string
	// RoutingInstance is the Junos routing-instance name (NOT the
	// vrf-prefixed device name); empty means the global/default table.
	RoutingInstance string
}

// TracerouteArgv builds the full argv for a traceroute diagnostic,
// mirroring PingArgv: VRF wrapping with single-application normalization
// and the "--" end-of-options separator before the target (#2084).
func TracerouteArgv(opts TracerouteOptions) []string {
	var cmd []string
	if dev := VRFDeviceName(opts.RoutingInstance); dev != "" {
		cmd = append(cmd, "ip", "vrf", "exec", dev)
	}
	cmd = append(cmd, "traceroute")
	if opts.Source != "" {
		cmd = append(cmd, "-s", opts.Source)
	}
	cmd = append(cmd, "--", opts.Target)
	return cmd
}
