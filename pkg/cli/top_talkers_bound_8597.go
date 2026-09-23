package cli

import (
	"container/heap"
	"fmt"
	"net"
	"sort"
	"strconv"

	"github.com/psaab/xpf/pkg/appid"
	"github.com/psaab/xpf/pkg/dataplane"
)

// #8597 (muse-004 K05) — `show security flow session sort-by bytes|packets`
// used to build one topTalkerEntry per session in the daemon process, sort the
// whole slice, and print twenty rows.
//
// The console runs IN xpfd (daemon_run.go), with no recover, so the allocation
// is the control plane's. MaxSessions is dynamic and large by design
// (worker_count × per-worker, #5323); a busy box carries millions of sessions,
// and each entry holds six freshly allocated strings. It is a legitimate,
// unprivileged show command whose memory scales with the session table — an
// operator, or on-box automation, OOM-kills the control plane by running a
// diagnostic on the box they are diagnosing.
//
// The REST side already treats a full conntrack walk as an admission decision
// (`sessionCountCap`, #5318). The console path had no equivalent.
//
// Bounding the COLLECTION rather than the print is the whole change: memory
// becomes O(K) instead of O(table), and — because a candidate is only
// materialised when it survives — the per-session `fmt.Sprintf` pair and
// `appid.ResolveSessionName` move off the scan entirely, from O(N) to O(K).
//
// The output is unchanged. The "(of N total)" figure still counts every
// session the filter admitted, because that count is kept separately from the
// heap; a fix that reported the heap's size there would silently redefine what
// the operator is reading.

// topTalkerLimit is how many rows the view prints, and now also how many
// candidates it keeps. It was a print-time constant; making it the collection
// bound is what closes the hole.
const topTalkerLimit = 20

// topTalkerMetric is the single definition of "top" for both sort modes.
//
// It replaces two sort.Slice comparators that each restated the sum. A metric
// computed in one place cannot disagree with itself between the v4 and v6
// scans, and the heap needs a scalar rather than a comparator anyway.
func topTalkerMetric(sortBy string, fwdBytes, revBytes, fwdPkts, revPkts uint64) uint64 {
	if sortBy == "bytes" {
		return fwdBytes + revBytes
	}
	return fwdPkts + revPkts
}

// topTalkerCandidate holds the RAW session, not a formatted row.
//
// #8597: the scan must not allocate. A formatted row means six strings and two
// Sprintf calls; a closure deferring that work still heap-allocates the closure
// itself, on every session. Both were measured and both are proportional to the
// table. Copying fixed-size key/value structs into an already-allocated heap
// slot allocates nothing at all, so the scan's cost is the scan.
//
// The v4/v6 union is a small waste of stack per candidate (at most
// topTalkerLimit of them) in exchange for one heap and one ordering. The
// alternative — a per-family heap merged at the end — has to decide the cut
// twice and gets the "(of N total)" figure wrong if either side is bounded
// separately.
type topTalkerCandidate struct {
	metric uint64
	isV6   bool
	v4Key  dataplane.SessionKey
	v4Val  dataplane.SessionValue
	v6Key  dataplane.SessionKeyV6
	v6Val  dataplane.SessionValueV6
}

// topTalkerHeap is a MIN-heap on metric, so the cheapest survivor is at index 0
// and a new candidate is compared against exactly one element.
type topTalkerHeap []topTalkerCandidate

func (h topTalkerHeap) Len() int           { return len(h) }
func (h topTalkerHeap) Less(i, j int) bool { return h[i].metric < h[j].metric }
func (h topTalkerHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *topTalkerHeap) Push(x any)        { *h = append(*h, x.(topTalkerCandidate)) }
func (h *topTalkerHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

// topTalkerCollector keeps the highest-metric `limit` candidates seen, and the
// total number offered.
//
// total is deliberately NOT len(heap): the view prints "(of N total)", and N
// means "sessions the filter admitted", not "rows kept". A bound that redefined
// that figure would change what the operator is reading, which is the thing
// this change must not do.
type topTalkerCollector struct {
	h     topTalkerHeap
	limit int
	total int
}

func newTopTalkerCollector(limit int) *topTalkerCollector {
	c := &topTalkerCollector{limit: limit}
	if limit > 0 {
		c.h = make(topTalkerHeap, 0, limit)
	}
	return c
}

// admit counts the session and reports whether it beats the current weakest
// survivor, returning the slot to overwrite (or -1 to append).
func (c *topTalkerCollector) admit(metric uint64) (slot int, keep bool) {
	c.total++
	if c.limit <= 0 {
		return 0, false
	}
	if len(c.h) < c.limit {
		return -1, true
	}
	// Strictly greater: an equal metric does not evict an incumbent. The old
	// full sort used sort.Slice, which is not stable, so no documented
	// behaviour depends on which of a tied pair survived; preferring the
	// incumbent makes the choice deterministic for a given scan order rather
	// than leaving it to heap internals.
	if metric <= c.h[0].metric {
		return 0, false
	}
	return 0, true
}

func (c *topTalkerCollector) offerV4(metric uint64, key dataplane.SessionKey, val dataplane.SessionValue) {
	slot, keep := c.admit(metric)
	if !keep {
		return
	}
	cand := topTalkerCandidate{metric: metric, v4Key: key, v4Val: val}
	if slot < 0 {
		c.h = append(c.h, cand)
		heap.Fix(&c.h, len(c.h)-1)
		return
	}
	c.h[slot] = cand
	heap.Fix(&c.h, slot)
}

func (c *topTalkerCollector) offerV6(metric uint64, key dataplane.SessionKeyV6, val dataplane.SessionValueV6) {
	slot, keep := c.admit(metric)
	if !keep {
		return
	}
	cand := topTalkerCandidate{metric: metric, isV6: true, v6Key: key, v6Val: val}
	if slot < 0 {
		c.h = append(c.h, cand)
		heap.Fix(&c.h, len(c.h)-1)
		return
	}
	c.h[slot] = cand
	heap.Fix(&c.h, slot)
}

// top materialises the survivors in descending metric order. This is where all
// the formatting happens — for at most `limit` rows, not for the table.
func (c *topTalkerCollector) top(f sessionFilter, zoneNames map[uint16]string, now uint64) []topTalkerEntry {
	cands := make([]topTalkerCandidate, len(c.h))
	copy(cands, c.h)
	sort.Slice(cands, func(i, j int) bool { return cands[i].metric > cands[j].metric })
	out := make([]topTalkerEntry, 0, len(cands))
	for i := range cands {
		out = append(out, cands[i].entry(f, zoneNames, now))
	}
	return out
}

// zoneLabel renders the ingress->egress pair, falling back to the numeric id
// for a zone the apply result does not name.
func zoneLabel(f sessionFilter, zoneNames map[uint16]string, in, out uint16) string {
	inZone := zoneNames[in]
	outZone := zoneNames[out]
	if inZone == "" {
		inZone = strconv.FormatUint(uint64(in), 10)
	}
	if outZone == "" {
		outZone = strconv.FormatUint(uint64(out), 10)
	}
	inZone = f.zoneDisplay(in, inZone)
	outZone = f.zoneDisplay(out, outZone)
	return inZone + "->" + outZone
}

func (cd *topTalkerCandidate) entry(f sessionFilter, zoneNames map[uint16]string, now uint64) topTalkerEntry {
	if cd.isV6 {
		key, val := cd.v6Key, cd.v6Val
		srcIP := net.IP(key.SrcIP[:])
		dstIP := net.IP(key.DstIP[:])
		var age uint64
		if now > val.Created {
			age = now - val.Created
		}
		return topTalkerEntry{
			src:      fmt.Sprintf("[%s]:%d", srcIP, ntohs(key.SrcPort)),
			dst:      fmt.Sprintf("[%s]:%d", dstIP, ntohs(key.DstPort)),
			proto:    protoNameFromNum(key.Protocol),
			zone:     zoneLabel(f, zoneNames, val.IngressZone, val.EgressZone),
			state:    sessionStateName(val.State),
			app:      appid.ResolveSessionName(f.appNames, f.cfg, key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID),
			fwdPkts:  val.FwdPackets,
			revPkts:  val.RevPackets,
			fwdBytes: val.FwdBytes,
			revBytes: val.RevBytes,
			age:      age,
		}
	}
	key, val := cd.v4Key, cd.v4Val
	srcIP := net.IP(key.SrcIP[:])
	dstIP := net.IP(key.DstIP[:])
	var age uint64
	if now > val.Created {
		age = now - val.Created
	}
	return topTalkerEntry{
		src:      fmt.Sprintf("%s:%d", srcIP, ntohs(key.SrcPort)),
		dst:      fmt.Sprintf("%s:%d", dstIP, ntohs(key.DstPort)),
		proto:    protoNameFromNum(key.Protocol),
		zone:     zoneLabel(f, zoneNames, val.IngressZone, val.EgressZone),
		state:    sessionStateName(val.State),
		app:      appid.ResolveSessionName(f.appNames, f.cfg, key.Protocol, ntohs(key.SrcPort), ntohs(key.DstPort), val.AppID),
		fwdPkts:  val.FwdPackets,
		revPkts:  val.RevPackets,
		fwdBytes: val.FwdBytes,
		revBytes: val.RevBytes,
		age:      age,
	}
}
