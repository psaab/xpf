package grpcapi

import (
	"strings"

	"github.com/psaab/xpf/pkg/cmdtree"
	pb "github.com/psaab/xpf/pkg/grpcapi/xpfv1"
)

// #16605 (R3-A41-01): a typed RPC performed by two different remote-cli
// lines was charged only its one fixed methodCanonicalCommand string, so
// a path-scoped deny written against the OTHER typed line never fired
// remotely — and an allowlist naming only that line locked it out. The
// silent rows were the ones where the charged string happened to share a
// prefix with the typed line (e.g. `show system` matches the ListHistory
// charge while ShowRollback/ShowCompare were charged `show
// configuration`), so the #8189 commit advisory said nothing.
//
// The fix is NOT to add client-supplied selectors: the request types for
// these RPCs carry no line identity (GetIPsecSA{}, GetNATPoolStats{} …
// are empty), and a client-supplied command string would be
// attacker-controlled authz input (see authz_command_table.go). Instead
// the gate judges the RPC under EVERY canonical line that performs it:
// the registry charge plus the typed-line aliases below. The aliases are
// alternative spellings of the same RPC under EvaluateForms unanimity
// (a deny on any spelling vetoes), EXCEPT that a sibling-spelling tier
// denial can be rescued only by an affirmative allow with a strictly
// longer matched extent. If the request discriminates the typed line,
// an affirmative allow on that exact executed spelling also rescues;
// otherwise the fixed charge is not evidence of execution. Thus an
// ambiguous RPC cannot let an allow on a shorter/equal sibling lift a
// longer/equal deny, while allowlist naming only one alias still admits.
//
// Census (every `c.client.<RPC>(` site in cmd/cli paired with its
// dispatching line; charged spelling first, aliases after):
//
//	GetIPsecSA         show security ipsec security-associations (charge)
//	                   show security ike security-associations
//	ShowInterfacesDetail
//	                   show interfaces detail (charge)
//	                   show interfaces [<name>]  (Terse=false, bare/filtered)
//	                   show interfaces terse     (Terse=true, unfiltered)
//	                   show interfaces <name>    (Terse=true, filtered —
//	                   handler prefix-filters the terse table by name)
//	ShowRollback       show configuration (charge)
//	                   show system rollback [<N>]
//	ShowCompare        show configuration (charge)
//	                   show system rollback [compare <N> | <N> | compare]
//	                   (+ config-mode `show … | compare`, whose operational
//	                   charge is already `show configuration`)
//	ListHistory        show system commit history (charge)
//	                   show system rollback (bare — lists rollback slots)
//	GetGlobalStats     show security flow statistics (charge)
//	                   show security statistics [detail]
//	                   show security flow statistics (also via flow arm)
//	GetVRRPStatus      show vrrp (charge)
//	                   show security vrrp
//	GetNATPoolStats    show security nat source pool (charge)
//	                   show security nat source summary
//	                   show security nat source pool [<name>]
//	GetNATDestination  show security nat destination pool (charge)
//	                   show security nat destination summary
//	                   show security nat destination
//	                   show security nat destination pool [<name>]
//	GetNATSource       show security nat source pool (charge) — sibling of
//	                   GetNATPoolStats sharing that charge; its only line
//	                   is `show security nat source`, censused here so the
//	                   shared charge does not leave it un-aliased.
//
// ShowRollback/ShowCompare keep `show configuration` as a form: the
// #14707 config-read gate separately prices the rendered subtree, and
// existing `show configuration`-scoped deny-commands verdicts on these
// RPCs must not regress.

var rpcAliasCommands16605 = map[string][]string{
	"GetIPsecSA": {
		"show security ike security-associations",
	},
	"ShowInterfacesDetail": {
		"show interfaces",
		"show interfaces terse",
	},
	"ShowRollback": {
		"show system rollback",
	},
	"ShowCompare": {
		"show system rollback",
	},
	"ListHistory": {
		"show system rollback",
	},
	"GetGlobalStats": {
		"show security statistics",
	},
	"GetVRRPStatus": {
		"show security vrrp",
	},
	"GetNATPoolStats": {
		"show security nat source summary",
		"show security nat source pool",
	},
	"GetNATDestination": {
		"show security nat destination summary",
		"show security nat destination",
		"show security nat destination pool",
	},
	"GetNATSource": {
		"show security nat source",
	},
}

// rpcTypedCommand16605 returns the executed typed line for the RPCs
// whose request DOES discriminate the line, or "" when the request
// cannot discriminate (judge charge + all aliases then). Today only
// ShowInterfacesDetail discriminates (Terse/Filter); the NAT/IPsec/
// stats/VRRP/history requests are empty structs, so both of their lines
// genuinely perform the identical RPC with identical server work and
// both spellings must be judged.
func rpcTypedCommand16605(method string, req any) string {
	if method != "ShowInterfacesDetail" {
		return ""
	}
	sd, ok := req.(*pb.ShowInterfacesDetailRequest)
	if !ok || sd == nil {
		return ""
	}
	switch {
	case sd.GetTerse() && sd.GetFilter() != "":
		// Filtered terse: `show interfaces <name>` judged with the
		// name as argument text by rpcArgumentForms; the keyword
		// spelling here is the name-less family.
		return "show interfaces"
	case sd.GetTerse():
		return "show interfaces terse"
	case sd.GetFilter() != "":
		return "show interfaces"
	default:
		return "show interfaces"
	}
}

// withAliasForms16605 merges the charge forms (forms[0] is the executed
// / reconstructed spelling from rpcArgumentForms) with every alias
// spelling for the method and each alias's canonical base/full/selector
// forms. Order: executed spelling first (EvaluateForms verdicts[0]
// convention), then charge, then aliases.
func withAliasForms16605(method string, req any, forms []string) []string {
	aliases, ok := rpcAliasCommands16605[method]
	if !ok || len(aliases) == 0 {
		return forms
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(forms)+8)
	add := func(f string) {
		if f != "" && !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	for _, f := range forms {
		add(f)
	}
	typed := rpcTypedCommand16605(method, req)
	// Executed typed line first among the aliases if discriminated.
	if typed != "" {
		add(typed)
		addCanonicalFormsOf16605(add, typed)
	}
	for _, a := range aliases {
		add(a)
		addCanonicalFormsOf16605(add, a)
	}
	return out
}

func addCanonicalFormsOf16605(add func(string), cmd string) {
	canon, res := cmdtree.Canonicalize(cmdtree.OperationalTree, strings.Fields(cmd))
	if res != cmdtree.CanonicalOK {
		return
	}
	b, f, sels, _ := cmdtree.CanonicalForms(canon)
	add(b)
	add(f)
	for _, s := range sels {
		add(s)
	}
}

// executedSpellings16605 returns the spellings that identify the executed
// line for the rescue geometry. Only request-discriminated RPCs provide
// that evidence: forms[0] then carries the reconstructed executed spelling
// and rpcTypedCommand16605 adds its typed-line family. For nondiscriminating
// requests forms[0] is just the fixed charge, not evidence of execution.
func executedSpellings16605(method string, req any, forms []string) map[string]bool {
	out := map[string]bool{}
	typed := rpcTypedCommand16605(method, req)
	if typed == "" {
		return out
	}
	out[typed] = true
	if len(forms) > 0 {
		out[forms[0]] = true
	}
	return out
}
