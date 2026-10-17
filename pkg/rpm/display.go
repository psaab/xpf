package rpm

import (
	"fmt"
	"io"
	"sort"

	"github.com/psaab/xpf/pkg/config"
)

// SortedProbeNames returns RPM probe names in deterministic order.
func SortedProbeNames(probes map[string]*config.RPMProbe) []string {
	names := make([]string, 0, len(probes))
	for name := range probes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// SortedTestNames returns RPM test names in deterministic order.
func SortedTestNames(tests map[string]*config.RPMTest) []string {
	names := make([]string, 0, len(tests))
	for name := range tests {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// WriteConfiguredTest renders a single configured RPM test using effective defaults.
func WriteConfiguredTest(w io.Writer, probeName, testName string, test *config.RPMTest) {
	fmt.Fprintf(w, "  Probe: %s, Test: %s\n", probeName, testName)
	fmt.Fprintf(w, "    Type: %s, Target: %s\n", test.EffectiveProbeType(), config.RedactURL(test.Target))
	if test.SourceAddress != "" {
		fmt.Fprintf(w, "    Source: %s\n", test.SourceAddress)
	}
	if test.RoutingInstance != "" {
		fmt.Fprintf(w, "    Routing instance: %s\n", test.RoutingInstance)
	}
	fmt.Fprintf(w, "    Probe interval: %ds\n", test.EffectiveProbeInterval())
	fmt.Fprintf(w, "    Probe count: %d\n", test.EffectiveProbeCount())
	fmt.Fprintf(w, "    Test interval: %ds\n", test.EffectiveTestInterval())
	fmt.Fprintf(w, "    Successive loss threshold: %d\n", test.EffectiveSuccessiveLossThreshold())
	if test.ProbeLimit > 0 {
		fmt.Fprintf(w, "    Probe limit: %d\n", test.ProbeLimit)
	} else {
		fmt.Fprintln(w, "    Probe limit: unlimited")
	}
	if test.EffectiveProbeType() == "tcp-ping" || test.DestPort > 0 {
		fmt.Fprintf(w, "    Destination port: %d\n", test.EffectiveDestinationPort())
	}
}
