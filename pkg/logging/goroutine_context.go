package logging

import (
	"runtime"
	"strconv"
	"sync"
)

// goroutineContext tracks the set of goroutines currently inside a scope so a
// nested entry on the SAME goroutine can be distinguished from a concurrent
// entry on a DIFFERENT goroutine. SyslogSlogHandler uses it per client
// (#16083): a record emitted from inside a client's own writer loop (e.g. a
// drop warning from SendAt) must be dropped-and-counted, while an unrelated
// concurrent record for the same client must still be queued. A global or
// per-handler flag cannot make that distinction and would either wedge the
// writer or silently drop legitimate forwarding under concurrent logging.
//
// It is the narrowed survivor of the #2287 handler-wide re-entrancy guard:
// that guard tracked every forwarding goroutine; #16083 tracks only writer
// goroutines (one per client), so the map stays tiny, and Handle pays the
// runtime.Stack cost only when at least one syslog client is configured —
// the no-client fast path (#2295) returns before the check. It never runs
// per-packet or per-session; the buffer is small because only the stack
// header line is needed.
type goroutineContext struct {
	mu  sync.Mutex
	ids map[uint64]struct{}
}

func (g *goroutineContext) enter() {
	id := currentGoID()
	if id == 0 {
		return
	}
	g.mu.Lock()
	if g.ids == nil {
		g.ids = make(map[uint64]struct{})
	}
	g.ids[id] = struct{}{}
	g.mu.Unlock()
}

func (g *goroutineContext) exit() {
	id := currentGoID()
	if id == 0 {
		return
	}
	g.mu.Lock()
	delete(g.ids, id)
	g.mu.Unlock()
}

func (g *goroutineContext) active() bool {
	id := currentGoID()
	if id == 0 {
		return false
	}
	g.mu.Lock()
	_, ok := g.ids[id]
	g.mu.Unlock()
	return ok
}

// currentGoID returns the current goroutine's ID, parsed from the runtime
// stack header ("goroutine <id> [running]:\n...").
func currentGoID() uint64 {
	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	// Format: "goroutine 123 [running]:\n..."
	const prefix = "goroutine "
	s := buf[:n]
	if len(s) < len(prefix) {
		return 0
	}
	s = s[len(prefix):]
	// The ID is the digits up to the first space.
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	id, err := strconv.ParseUint(string(s[:i]), 10, 64)
	if err != nil {
		return 0
	}
	return id
}
