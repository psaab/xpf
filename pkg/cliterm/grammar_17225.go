package cliterm

import (
	"fmt"
	"strings"
)

// Show-command argument grammars shared by BOTH CLI surfaces: the
// in-process interactive CLI (pkg/cli) and the remote gRPC client
// (cmd/cli).
//
// WHY THIS LIVES HERE. #13199 made the remote natPoolArg strict and left
// the local copy lenient; #15775 promised trailing-token rejection on
// both chassis-cluster dispatchers and left the remote leaf views
// accepting `statistics junk`. Each fix landed on one transcription of
// the grammar. Two copies can drift; one cannot (#17225). cliterm is
// the dependency-light home both surfaces already import (see
// pipefilter.go), so the grammar lives here once.

// ParseNATPoolSelector parses the optional trailing `pool <name>`
// selector of `show security nat source deterministic-nat ...`
// (#13199's strict form). Empty rest means no selector. Anything else
// — an incomplete `pool`, a wrong keyword, an empty name, or trailing
// tokens — is an error rather than a silently dropped selector.
func ParseNATPoolSelector(rest []string) (string, error) {
	if len(rest) == 0 {
		return "", nil
	}
	if len(rest) != 2 || rest[0] != "pool" || rest[1] == "" {
		return "", fmt.Errorf("expected optional pool <name>")
	}
	return rest[1], nil
}

// ClusterSubsystemView maps a `show chassis cluster <sub> [arg ...]`
// request to the text-proxy topic (and optional filter) to render.
// sub is the subsystem token; rest is everything after it.
//
// A bare subsystem keeps its historical default view (#5459), but a
// present token must be a recognized leaf with exact arity (#15775):
// `statistics junk`, `status junk`, `statistics|interfaces|fairness
// junk` and the like error instead of rendering the leaf view.
// `data-plane flows` is the one leaf that takes trailing arguments,
// joined as its filter. `fence-status` is a leaf view of
// `show chassis cluster` itself, not a subsystem: both dispatchers
// handle it before delegating here, so it is rejected as an unknown
// subsystem.
func ClusterSubsystemView(sub string, rest []string) (topic, filter string, err error) {
	switch sub {
	case "control-plane":
		if len(rest) == 0 || (len(rest) == 1 && rest[0] == "statistics") {
			return "chassis-cluster-control-plane-statistics", "", nil
		}
		return "", "", fmt.Errorf("unknown control-plane target: %s (expected `statistics`)", strings.Join(rest, " "))
	case "data-plane":
		if len(rest) == 0 {
			return "chassis-cluster-data-plane-statistics", "", nil
		}
		switch rest[0] {
		case "statistics":
			if len(rest) == 1 {
				return "chassis-cluster-data-plane-statistics", "", nil
			}
		case "interfaces":
			if len(rest) == 1 {
				return "chassis-cluster-data-plane-interfaces", "", nil
			}
		case "fairness":
			if len(rest) == 1 {
				return "chassis-cluster-data-plane-fairness", "", nil
			}
		case "flows":
			return "chassis-cluster-data-plane-flows", strings.Join(rest[1:], " "), nil
		default:
			return "", "", fmt.Errorf("unknown data-plane target: %s (expected `statistics`, `interfaces`, `fairness`, or `flows`)", rest[0])
		}
		return "", "", fmt.Errorf("unknown data-plane target: %s (expected `statistics`, `interfaces`, `fairness`, or `flows`)", strings.Join(rest, " "))
	case "ip-monitoring":
		if len(rest) == 0 || (len(rest) == 1 && rest[0] == "status") {
			return "chassis-cluster-ip-monitoring-status", "", nil
		}
		return "", "", fmt.Errorf("unknown ip-monitoring target: %s (expected `status`)", strings.Join(rest, " "))
	case "fabric":
		if len(rest) == 0 || (len(rest) == 1 && rest[0] == "statistics") {
			return "chassis-cluster-fabric-statistics", "", nil
		}
		return "", "", fmt.Errorf("unknown fabric target: %s (expected `statistics`)", strings.Join(rest, " "))
	}
	return "", "", fmt.Errorf("unknown cluster subsystem: %s", sub)
}
