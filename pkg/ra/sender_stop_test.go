package ra

// stop tears the sender down WITHOUT a goodbye (Clear / Apply-remove) and
// waits for the owner to exit. Test-only helper (#17160): production code
// signals via signalStop and joins through Manager.releaseDrain, which owns
// the tombstone discipline. The owner closes the conn in finishShutdown.
func (s *sender) stop() { s.signalStop(modeHard); <-s.stopped }
