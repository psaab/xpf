package firewallshow

import (
	"fmt"
	"strings"

	"github.com/psaab/xpf/pkg/config"
)

// ImplicitDiscardTermName is the name of the synthetic final term that
// carries the Junos implicit final discard (#18728). It mirrors
// dpuserspace.ImplicitDiscardTermName; this package does not import the
// dataplane package, and pkg/firewallshow's test pins the two equal.
const ImplicitDiscardTermName = config.ImplicitDiscardTermName

// ImplicitDiscardCounter is one surface's reading of a filter's
// implicit-discard counter. Have is false when the surface has no reading
// (no dataplane status, or the helper has not published the row yet).
type ImplicitDiscardCounter struct {
	Packets uint64
	Bytes   uint64
	Have    bool
}

// WriteImplicitDiscard renders the synthetic implicit-discard term after a
// filter's authored terms (#18728). It writes nothing for a filter that has a
// terminal catch-all term (config.FirewallFilterHasCatchAll): such a filter
// never reaches the implicit discard, and the dataplane carries no such term
// for it. The name and the `then discard` line mirror an authored term, so
// the view reads as what is enforced: every packet that matched no term
// above is dropped here and counted.
//
// leadingBlank mirrors WriteTerm's: the single-filter views separate terms
// with a blank line, the all-filters views do not.
func WriteImplicitDiscard(buf *strings.Builder, filter *config.FirewallFilter, counter ImplicitDiscardCounter, leadingBlank bool) {
	if filter == nil || config.FirewallFilterHasCatchAll(filter) {
		return
	}
	if leadingBlank {
		buf.WriteString("\n")
	}
	fmt.Fprintf(buf, "  Term: %s (Junos implicit final discard: no term above matched)\n", ImplicitDiscardTermName)
	buf.WriteString("    then discard\n")
	// Like an authored counted term (#16454), the Hit count line is printed
	// only when the surface has a reading.
	if counter.Have {
		fmt.Fprintf(buf, "    Hit count: %d packets, %d bytes\n", counter.Packets, counter.Bytes)
	}
}
