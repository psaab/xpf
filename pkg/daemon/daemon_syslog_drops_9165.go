package daemon

import "github.com/psaab/xpf/pkg/logging"

// syslogDropStats snapshots every installed remote-syslog client's drop
// counters for the xpf_syslog_messages_dropped_total family (#9165, #16769).
//
// Before this reader existed, all three SyslogClient drop accessors had ZERO
// production consumers: a counted drop reached an operator through exactly one
// channel — the logging package's own ≤1/s slog.Warn — so a warning that had
// already been rate-limited away left nothing behind. Syslog is where an
// operator looks AFTER an incident, and a dead collector means that record does
// not exist while `show` still renders the collector as configured.
//
// #16769: the EventReader set is only the security-log streams. The
// `system syslog host` clients live behind d.slogHandler and carry the
// authorization/commit records; their drops are appended here, labelled
// sink="system" (security rows carry sink="security"), and both sets fold
// retired generations so the counters stay cumulative per destination
// across rebuilds.
//
// Nil-safe on purpose: this is called from a metrics scrape, which races the
// daemon's own startup and every commit that rebuilds the client set.
func (d *Daemon) syslogDropStats() []logging.SyslogDropStat {
	if d == nil {
		return nil
	}
	var out []logging.SyslogDropStat
	if d.eventReader != nil {
		out = d.eventReader.SyslogDropStats()
	}
	if d.slogHandler != nil {
		out = append(out, d.slogHandler.SyslogDropStats()...)
	}
	return out
}
