package firewallshow

import (
	"fmt"

	"github.com/psaab/xpf/pkg/dataplane"
)

// DSCPRewriteLine renders one `then dscp` / `then traffic-class` line for
// the raw `show firewall` view, annotating a rewrite the dataplane does
// NOT install.
//
// #6565 row 8 / #7422: the snapshot builder DROPS an unresolvable rewrite
// (pkg/dataplane/userspace/filters.go — "CoS marking lost — the term still
// matches and acts") while the renderers printed it unconditionally, so
// `show firewall` reported a marking the dataplane was not applying. The
// commit gate (config.validateFilterDSCPStrict, #3309) hard-rejects such a
// token, but the tolerant load / cluster config-sync path (#1960 no-brick)
// downgrades that to a warning and the config goes ACTIVE — which is the
// state this renderer is reached in.
//
// Annotate rather than hide: the operator authored the line and needs to
// see BOTH that it is configured and that it is not installed. Hiding it
// would make `show firewall` disagree with `show configuration`.
func DSCPRewriteLine(rewrite string) string {
	if _, ok := dataplane.ResolveFilterDSCP(rewrite); ok {
		return fmt.Sprintf("    then dscp %s\n", rewrite)
	}
	return fmt.Sprintf("    then dscp %s  [NOT INSTALLED: unresolvable dscp/"+
		"traffic-class value — no CoS marking is applied; the term still "+
		"matches and acts]\n", rewrite)
}
