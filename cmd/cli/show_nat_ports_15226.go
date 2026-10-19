package main

import (
	"fmt"
	"strings"

	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// show_nat_ports_15226.go — #15226 (A42-02).
//
// The ctl destination views rendered a multi-port DNAT rule as
// ":<first port>" because NATDestInfo carried only the singular dst_port.
// The daemon now also carries the complete dst_ports set (#15226 proto
// field 11); render it compactly (contiguous runs as low-high), falling
// back to the singular field for a daemon predating the field.

// natDestPortsSuffix renders ":<ports>" for a GetNATDestination rule row,
// or "" when the rule carries no destination-port constraint.
func natDestPortsSuffix(r *pb.NATDestInfo) string {
	if r == nil {
		return ""
	}
	ports := r.GetDstPorts()
	if len(ports) == 0 {
		if r.GetDstPort() > 0 {
			return fmt.Sprintf(":%d", r.GetDstPort())
		}
		return ""
	}
	var parts []string
	lo, hi := ports[0], ports[0]
	flush := func() {
		if lo == hi {
			parts = append(parts, fmt.Sprintf("%d", lo))
		} else {
			parts = append(parts, fmt.Sprintf("%d-%d", lo, hi))
		}
	}
	for _, p := range ports[1:] {
		if p == hi+1 {
			hi = p
			continue
		}
		flush()
		lo, hi = p, p
	}
	flush()
	return ":" + strings.Join(parts, ",")
}
