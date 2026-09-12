package userspace

// transitCloseOnLastDetach, when set, closes kernel transit because the pass
// that just ran left NO shim XDP link attached (#9725).
//
// Why a hook rather than a direct read of the daemon's gate: this package
// cannot import pkg/daemon, and the gate must be driven from the moment the
// last link goes, not when ApplyConfig eventually returns.
//
// It is deliberately COUNT-FREE on the daemon side. The daemon wires it to
// closeTransitUntilAttached, which drives the two sysctls and the #7191 barrier
// and records NOTHING about the arm — the dataplane is still armed here, only
// its links are gone. A close that also un-armed would make the next apply
// tail's re-read judge by a flag this pass invented.
//
// Lock order: syncInterfaceAttachments calls this while the Manager holds its
// own mu, so the hook must not re-enter the Manager. closeTransitUntilAttached
// takes only the daemon's transitGateMu and touches sysctls and nftables, which
// keeps transitGateMu a LEAF on this path. A hook that read the attached-link
// count back through the published runtime would not be a leaf, and the #9725
// review recorded "both ApplyConfig callers release runtime locks before taking
// transitGateMu" as the reason no inversion exists today.
var transitCloseOnLastDetach func(stage string)

// SetTransitCloseOnLastDetach wires the daemon's transit close into the
// attachment reconcile. Passing nil unwires it. The daemon calls this once, when
// it publishes the runtime; a nil hook (tests, the null adapter) simply means the
// reconcile closes nothing and the apply tail's re-read remains the only gate
// write, which is the pre-#9725 behaviour.
func SetTransitCloseOnLastDetach(fn func(stage string)) {
	transitCloseOnLastDetach = fn
}

// SetTransitCloseOnLastDetachForTest sets the hook and returns the function that
// restores the previous one, so a cell cannot leak its hook into the next.
func SetTransitCloseOnLastDetachForTest(fn func(stage string)) (restore func()) {
	prev := transitCloseOnLastDetach
	transitCloseOnLastDetach = fn
	return func() { transitCloseOnLastDetach = prev }
}
