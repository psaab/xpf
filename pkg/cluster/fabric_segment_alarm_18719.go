package cluster

// SetFabricSegmentAlarmsFn installs the source of the #18719 fabric-segment
// alarm lines (pkg/fabricsegment's Monitor.Alarms) that FormatStatus renders.
// The function is called outside every Manager lock. Nil disables the lines.
func (m *Manager) SetFabricSegmentAlarmsFn(fn func() []string) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.fabricSegmentAlarmsFn = fn
	m.mu.Unlock()
}
