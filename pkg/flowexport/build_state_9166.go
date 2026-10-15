package flowexport

// BuildState is one flow-export family's build health, in the shape the metrics
// surface needs to answer three questions that used to have two answers
// (#9166).
//
// Before this, a failed exporter build was INDISTINGUISHABLE from "flow export
// is not configured" on every surface:
//
//   - the daemon's `FlowExportError()` had zero production readers;
//   - the xpf_flow_export_collector_* family is omitted entirely when the
//     health slice is empty, which is exactly what a failed build produces; and
//   - `show` renders the configuration as present, because the config IS
//     present.
//
// The triggering fault is ordinary — a collector hostname unresolvable at boot,
// or a pinned source-address bind attempted before the interface is up — and
// both clear on their own minutes later. NetFlow is frequently the only record
// of what traversed the box, and its absence looks exactly like a deployment
// where it was never turned on, which is why nobody investigates.
//
// It lives here rather than in pkg/daemon so pkg/api can read it without the
// import cycle a daemon-owned type would create.
type BuildState struct {
	// Family is "netflow-v9" or "ipfix".
	Family string
	// ConfiguredGroups is how many template groups the ACTIVE config asks for.
	// Zero means not configured — the state a build failure used to imitate.
	// The count of RUNNING exporters cannot stand in for it: on a build
	// failure with nothing previously running it is also 0.
	ConfiguredGroups int
	// BuildFailed reports that the last reconcile for this family could not
	// construct its exporters. Any previously-running set is still exporting:
	// the #3742 build-before-swap keeps export UP rather than tearing a healthy
	// set down.
	BuildFailed bool
	// ExcludedFlowServers is the active config's excluded stanza count,
	// including instances that produced no surviving exporter group.
	ExcludedFlowServers int
}
