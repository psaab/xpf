package logging

import (
	"strings"
	"sync"
	"time"
)

// EventRecord is a formatted event stored in the event buffer.
type EventRecord struct {
	Time            time.Time
	Type            string // "SESSION_OPEN", "POLICY_DENY", etc.
	SrcAddr         string // "10.0.1.5:443"
	DstAddr         string
	Protocol        string // "TCP", "UDP"
	Action          string // "permit", "deny"
	PolicyID        uint32
	RuleID          uint32
	TermID          uint32
	Reason          string
	OwnerRGID       int16
	InZone          uint16
	OutZone         uint16
	ScreenCheck     string // for SCREEN_DROP
	SessionPkts     uint64 // for SESSION_CLOSE (client→server)
	SessionBytes    uint64
	NATSrcAddr      string // "172.16.1.1:12345" (post-NAT source)
	NATDstAddr      string // "10.0.2.1:80" (post-NAT destination)
	InZoneName      string // resolved zone name
	OutZoneName     string // resolved zone name
	ElapsedTime     uint32 // seconds since session creation (for CLOSE)
	PolicyName      string // resolved policy name (e.g. "allow-everything")
	RevSessionPkts  uint64 // packets from server (for SESSION_CLOSE)
	RevSessionBytes uint64 // bytes from server (for SESSION_CLOSE)
	AppName         string // resolved application name (e.g. "junos-http")
	IngressIface    string // resolved interface name (e.g. "trust0")
	CloseReason     string // "idle Timeout", "TCP FIN", "TCP RST", etc.
	SessionID       uint64 // unique session identifier
}

// EventBuffer is a thread-safe circular buffer for recent events.
type EventBuffer struct {
	mu    sync.RWMutex
	buf   []EventRecord
	size  int
	head  int    // next write position
	count int    // number of events stored
	seq   uint64 // monotonically increasing sequence number

	subMu sync.RWMutex
	subs  map[*Subscription]struct{}
}

// Subscription receives new events from an EventBuffer.
type Subscription struct {
	C  chan EventRecord
	eb *EventBuffer
}

// Close unsubscribes and closes the channel.
func (s *Subscription) Close() {
	s.eb.unsubscribe(s)
}

// NewEventBuffer creates a new event buffer with the given capacity.
func NewEventBuffer(size int) *EventBuffer {
	return &EventBuffer{
		buf:  make([]EventRecord, size),
		size: size,
		subs: make(map[*Subscription]struct{}),
	}
}

// Add appends an event to the buffer, overwriting the oldest if full.
// Subscribers are notified non-blocking.
func (eb *EventBuffer) Add(rec EventRecord) {
	eb.mu.Lock()
	eb.buf[eb.head] = rec
	eb.head = (eb.head + 1) % eb.size
	if eb.count < eb.size {
		eb.count++
	}
	eb.seq++
	eb.mu.Unlock()

	eb.subMu.RLock()
	for sub := range eb.subs {
		select {
		case sub.C <- rec:
		default: // drop if subscriber is slow
		}
	}
	eb.subMu.RUnlock()
}

// Subscribe returns a Subscription that receives new events.
// Call Close() on the subscription when done.
func (eb *EventBuffer) Subscribe(bufSize int) *Subscription {
	if bufSize < 1 {
		bufSize = 64
	}
	sub := &Subscription{
		C:  make(chan EventRecord, bufSize),
		eb: eb,
	}
	eb.subMu.Lock()
	eb.subs[sub] = struct{}{}
	eb.subMu.Unlock()
	return sub
}

func (eb *EventBuffer) unsubscribe(sub *Subscription) {
	eb.subMu.Lock()
	delete(eb.subs, sub)
	eb.subMu.Unlock()
}

// EventFilter specifies criteria for filtering events.
type EventFilter struct {
	Zone     uint16 // match if InZone or OutZone equals this; 0 = no filter
	Protocol string // case-insensitive substring match on Protocol
	Action   string // case-insensitive substring match on Action
}

// IsEmpty returns true if no filter criteria are set.
func (f EventFilter) IsEmpty() bool {
	return f.Zone == 0 && f.Protocol == "" && f.Action == ""
}

func (f EventFilter) matches(rec *EventRecord) bool {
	if f.Zone != 0 && rec.InZone != f.Zone && rec.OutZone != f.Zone {
		return false
	}
	if f.Protocol != "" && !strings.Contains(strings.ToLower(rec.Protocol), strings.ToLower(f.Protocol)) {
		return false
	}
	if f.Action != "" && !strings.Contains(strings.ToLower(rec.Action), strings.ToLower(f.Action)) {
		return false
	}
	return true
}

// LatestFiltered returns the most recent n events matching the filter, newest first.
func (eb *EventBuffer) LatestFiltered(n int, f EventFilter) []EventRecord {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	if n <= 0 {
		return nil
	}

	var result []EventRecord
	for i := 0; i < eb.count && len(result) < n; i++ {
		idx := (eb.head - 1 - i + eb.size) % eb.size
		if f.matches(&eb.buf[idx]) {
			result = append(result, eb.buf[idx])
		}
	}
	return result
}

// Latest returns the most recent n events, newest first.
func (eb *EventBuffer) Latest(n int) []EventRecord {
	eb.mu.RLock()
	defer eb.mu.RUnlock()

	if n > eb.count {
		n = eb.count
	}
	if n == 0 {
		return nil
	}

	result := make([]EventRecord, n)
	for i := 0; i < n; i++ {
		// Walk backwards from the most recent entry
		idx := (eb.head - 1 - i + eb.size) % eb.size
		result[i] = eb.buf[idx]
	}
	return result
}
