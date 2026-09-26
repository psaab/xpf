package eventengine

// SetPublishEnabled controls whether the action worker may publish local
// remediation commits. The daemon closes the gate on RG0 demotion and opens it
// after the store becomes writable on promotion. Actions already accepted by
// the worker remain pending while the gate is closed.
func (e *Engine) SetPublishEnabled(enabled bool) {
	if e.publishEnabled.Swap(enabled) == enabled {
		return
	}
	select {
	case e.publishWake <- struct{}{}:
	default:
	}
}

// PublishEnabled reports whether local remediation publication is currently
// allowed by the HA gate.
func (e *Engine) PublishEnabled() bool {
	return e.publishEnabled.Load()
}

// waitForPublishEnabled parks the single action worker on a standby instead of
// consuming an edge-only RPM event as a permanent rejection. It returns false
// only when engine shutdown abandons the in-flight action.
func (e *Engine) waitForPublishEnabled() bool {
	for !e.publishEnabled.Load() {
		select {
		case <-e.stopCh:
			return false
		case <-e.publishWake:
		}
	}
	return true
}
