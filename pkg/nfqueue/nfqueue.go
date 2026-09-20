// Package nfqueue is a minimal NFQNL (libnetfilter_queue-equivalent) speaker
// for #9506 Phase-0 measurement.
//
// Route-based IPsec plaintext surfaces on an xfrmi excluded from AF_XDP
// adjudication while the armed forward hook stays open, so decrypted ingress
// is kernel-forwarded with no zone policy (#9506). Both r4 reviewers retain
// NFQUEUE as the research transport (GLM PLAN-READY vs Codex NEEDS-MAJOR,
// converging via measured Phase 0 per the owner). This package is the Phase-0
// transport: it binds a queue, receives held packets, and disposes each by
// verdict, so per-shape stage rates, memory accounting, teardown behavior and
// fragment head-of-line cost can be measured synthetically in-container with
// cluster integration explicitly gated.
//
// Honesty boundary: numbers transfer as NFQUEUE transport economics; SA/route/
// cluster integration re-validates on the loss cluster. Nothing here claims
// cluster validation, adjudicated re-entry, or any mark mechanism (the r4
// section 4.5 SO_MARK-on-TUN proposal stands factually rejected per Codex r4
// and is not implemented).
//
// Transport only: no queue allocator, no epoch, no generation fence (r4
// lifecycle stays full-plan scope). Fail-closed throughout: no FAIL_OPEN
// flag, timeouts and errors drop-or-report, never silently accept.
package nfqueue

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Verdict is a disposition for a held packet.
type Verdict int

const (
	// VerdictDrop swallows the held packet (NF_DROP).
	VerdictDrop Verdict = 0
	// VerdictAccept releases the held packet to continue traversal (NF_ACCEPT).
	VerdictAccept Verdict = 1
)

// String names the verdict for logs and counters.
func (v Verdict) String() string {
	switch v {
	case VerdictDrop:
		return "DROP"
	case VerdictAccept:
		return "ACCEPT"
	default:
		return fmt.Sprintf("Verdict(%d)", int(v))
	}
}

// ErrClosed is returned by Verdict after Close: the queue is gone, so the
// packet cannot be disposed. Never panics, never silently accepts.
var ErrClosed = errors.New("nfqueue: queue closed")

// ErrVerdictTimeout reports a bounded verdict gate or nonblocking socket send
// that could not complete. The held packet is terminal-but-uncertain.
var ErrVerdictTimeout = errors.New("nfqueue: bounded verdict send timeout")

// ErrTimeout reports a Recv deadline expiry with no packet. The hold is
// unaffected: packets stay queued until a verdict or queue destruction.
var ErrTimeout = errors.New("nfqueue: recv deadline exceeded")

// ErrAlreadyVerdicted is returned when a caller attempts to issue a second
// terminal verdict for one packet. The first attempt remains authoritative,
// including when its transport result was uncertain.
var ErrAlreadyVerdicted = errors.New("nfqueue: packet already has a verdict attempt")

// NFQNL wire constants from linux/netfilter/nfnetlink.h and
// linux/netfilter/nfnetlink_queue.h. Netlink headers use host byte order
// (this package targets Linux, little-endian); nfgenmsg res_id,
// packet/verdict IDs and copy params use network order per __be annotations.
const (
	nfnlSubsysQueue = 3

	nfqnlMsgPacket       = 0
	nfqnlMsgVerdict      = 1
	nfqnlMsgConfig       = 2
	nfqnlMsgVerdictBatch = 3

	nfqnlMsgPacketType  = (nfnlSubsysQueue << 8) | nfqnlMsgPacket
	nfqnlMsgVerdictType = (nfnlSubsysQueue << 8) | nfqnlMsgVerdict
	nfqnlMsgConfigType  = (nfnlSubsysQueue << 8) | nfqnlMsgConfig

	nfqnlCfgCmdBind     = 1
	nfqnlCfgCmdUnbind   = 2
	nfqnlCfgCmdPFBind   = 3
	nfqnlCfgCmdPFUnbind = 4

	nfqaCfgCmd         = 1
	nfqaCfgParams      = 2
	nfqaCfgQueueMaxlen = 3

	nfqnlCopyPacket = 2

	nfqaPacketHdr      = 1
	nfqaVerdictHdr     = 2
	nfqaIfindexIndev   = 5
	nfqaIfindexOutdev  = 6
	nfqaIfindexPhysIn  = 7
	nfqaIfindexPhysOut = 8
	nfqaHwaddr         = 9
	nfqaPayload        = 10
	nlmsgError         = 2

	nlmFRequest = 1
	nlmFAck     = 4

	nfnetlinkV0 = 0

	copyRangeFull      = 0xffff
	nfqueueQueueMaxLen = 8192

	// recvBufSize bounds one Recvfrom datagram. The kernel may batch several
	// queued packets per datagram; excess is held in Queue.pending.
	recvBufSize = 1 << 20
)

// QueueStats is a snapshot of Queue counters.
type QueueStats struct {
	Held              uint64
	Accepted          uint64
	Dropped           uint64
	VerdictErrors     uint64
	BatchVerdicts     uint64
	RecvOverruns      uint64
	VerdictAttempted  uint64
	VerdictSuccessful uint64
	VerdictUncertain  uint64
}

// Queue is one bound NFQUEUE. A Queue is safe for concurrent Verdict calls;
// Close must not race with Recv (the caller ensures Recv has returned).
// Verdict after Close returns ErrClosed.
type Queue struct {
	id int
	fd int

	mu     sync.Mutex // protects close state and terminal reservation
	closed bool

	sendGateOnce sync.Once
	sendGate     chan struct{}

	seq     atomic.Uint32
	pending []*Packet
	recvBuf []byte

	held              atomic.Uint64
	accepted          atomic.Uint64
	dropped           atomic.Uint64
	verdictErrors     atomic.Uint64
	batchVerdicts     atomic.Uint64
	recvOverruns      atomic.Uint64
	verdictAttempted  atomic.Uint64
	verdictSuccessful atomic.Uint64
	verdictUncertain  atomic.Uint64
}

const verdictGateTimeout = 5 * time.Millisecond

func (q *Queue) initSendGate() chan struct{} {
	q.sendGateOnce.Do(func() {
		q.sendGate = make(chan struct{}, 1)
		q.sendGate <- struct{}{}
	})
	return q.sendGate
}

func (q *Queue) acquireSend() error {
	select {
	case <-q.initSendGate():
		return nil
	case <-time.After(verdictGateTimeout):
		q.verdictUncertain.Add(1)
		q.verdictErrors.Add(1)
		return ErrVerdictTimeout
	}
}

func (q *Queue) releaseSend() {
	q.initSendGate() <- struct{}{}
}

func (q *Queue) acquireSendBlocking() {
	<-q.initSendGate()
}

// linuxMmsghdr mirrors Linux's struct mmsghdr ABI. x/sys/unix exposes
// Msghdr but not the mmsghdr/sendmmsg wrapper.
type linuxMmsghdr struct {
	msg unix.Msghdr
	len uint32
	_   uint32
}

// Open binds NFQUEUE number queueID with full-payload copy mode. It binds
// AF_INET and AF_INET6 protocol families (EBUSY on an already-bound family
// is tolerated), binds the queue (EBUSY fails with an error naming the queue;
// never silently renumbers), and sets NFQNL_COPY_PACKET. No FAIL_OPEN flag is
// set: a full or unresponsive queue drops (fail-closed).
func Open(queueID uint16) (*Queue, error) {
	return openWithFamilies(queueID, []int{unix.AF_INET, unix.AF_INET6})
}

// OpenFamily binds one protocol family to an NFQUEUE. This is used for
// AF_BRIDGE queues, which must not be included in Open's shared IP-family
// binding loop: a bridge PF_BIND failure must not prevent IPv4/IPv6 queues
// from starting.
func OpenFamily(queueID uint16, protocolFamily int) (*Queue, error) {
	switch protocolFamily {
	case unix.AF_INET, unix.AF_INET6, unix.AF_BRIDGE:
	default:
		return nil, fmt.Errorf("nfqueue: unsupported protocol family %d", protocolFamily)
	}
	return openWithFamilies(queueID, []int{protocolFamily})
}

func openWithFamilies(queueID uint16, protocolFamilies []int) (*Queue, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("nfqueue: socket NETLINK_NETFILTER: %w", err)
	}
	closeOnErr := func() { _ = unix.Close(fd) }
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		closeOnErr()
		return nil, fmt.Errorf("nfqueue: bind netlink: %w", err)
	}
	// Connect once to the kernel endpoint so one-packet Send and sendmmsg use
	// the same peer without rebuilding a sockaddr for every verdict.
	if err := unix.Connect(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK, Pid: 0}); err != nil {
		closeOnErr()
		return nil, fmt.Errorf("nfqueue: connect netlink: %w", err)
	}
	// Best-effort buffer growth; failure keeps kernel defaults.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<22)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF, 1<<22)

	q := &Queue{id: int(queueID), fd: fd, recvBuf: make([]byte, recvBufSize)}
	q.seq.Store(uint32(time.Now().UnixNano() & 0xffffff))
	// Protocol-family binds. Another socket may already hold a family in this
	// netns; that is not our queue, so EBUSY is tolerated here.
	for _, pf := range protocolFamilies {
		if err := q.configure(0, nfqnlCfgCmdPFBind, pf, nil); err != nil {
			if errors.Is(err, unix.EBUSY) {
				continue
			}
			closeOnErr()
			return nil, fmt.Errorf("nfqueue: PF_BIND pf=%d: %w", pf, err)
		}
	}
	if err := q.configure(queueID, nfqnlCfgCmdBind, 0, nil); err != nil {
		closeOnErr()
		if errors.Is(err, unix.EBUSY) {
			return nil, fmt.Errorf("nfqueue: bind queue %d: already bound (%v)", queueID, err)
		}
		return nil, fmt.Errorf("nfqueue: bind queue %d: %w", queueID, err)
	}
	params := make([]byte, 5)
	binary.BigEndian.PutUint32(params[:4], copyRangeFull)
	params[4] = nfqnlCopyPacket
	if err := q.configure(queueID, 0, 0, []nlAttr{{Type: nfqaCfgParams, Data: params}}); err != nil {
		_ = q.sendConfig(queueID, nfqnlCfgCmdUnbind, 0, nil, false)
		closeOnErr()
		return nil, fmt.Errorf("nfqueue: set copy mode queue %d: %w", queueID, err)
	}
	maxlen := make([]byte, 4)
	binary.BigEndian.PutUint32(maxlen, nfqueueQueueMaxLen)
	if err := q.configure(queueID, 0, 0, []nlAttr{{Type: nfqaCfgQueueMaxlen, Data: maxlen}}); err != nil {
		_ = q.sendConfig(queueID, nfqnlCfgCmdUnbind, 0, nil, false)
		closeOnErr()
		return nil, fmt.Errorf("nfqueue: set queue length %d: %w", queueID, err)
	}
	_ = unix.SetNonblock(fd, true)
	return q, nil
}

// ID returns the bound queue number.
func (q *Queue) ID() uint16 { return uint16(q.id) }

// Stats snapshots the queue counters.
func (q *Queue) Stats() QueueStats {
	return QueueStats{
		Held:              q.held.Load(),
		Accepted:          q.accepted.Load(),
		Dropped:           q.dropped.Load(),
		VerdictErrors:     q.verdictErrors.Load(),
		BatchVerdicts:     q.batchVerdicts.Load(),
		RecvOverruns:      q.recvOverruns.Load(),
		VerdictAttempted:  q.verdictAttempted.Load(),
		VerdictSuccessful: q.verdictSuccessful.Load(),
		VerdictUncertain:  q.verdictUncertain.Load(),
	}
}

// Close unbinds the queue and closes the socket. It is idempotent: a second
// Close returns nil. Close must not race with Recv; Verdict after Close returns
// ErrClosed. Packets still held when the socket is destroyed die by the
// kernel's default queue teardown behavior.
func (q *Queue) Close() error {
	q.acquireSendBlocking()
	defer q.releaseSend()
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return nil
	}
	q.closed = true
	// Unbind this queue first. Do not issue PF_UNBIND here: PF binding is
	// shared by all queue sockets in the namespace, and this socket may have
	// observed EBUSY because another live socket owns it. Closing the socket
	// releases any PF bind that this socket itself acquired without touching
	// another queue's family registration.
	_ = q.sendConfig(q.ID(), nfqnlCfgCmdUnbind, 0, nil, false)
	return unix.Close(q.fd)
}
func (q *Queue) Recv(deadline time.Time) (*Packet, error) {
	if len(q.pending) > 0 {
		pkt := q.pending[0]
		q.pending[0] = nil
		q.pending = q.pending[1:]
		return pkt, nil
	}
	for {
		timeoutMs := int(time.Until(deadline).Milliseconds())
		if timeoutMs < 0 {
			timeoutMs = 0
		}
		pfds := []unix.PollFd{{Fd: int32(q.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pfds, timeoutMs)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return nil, fmt.Errorf("nfqueue: poll: %w", err)
		}
		if n == 0 {
			if !time.Now().Before(deadline) {
				return nil, ErrTimeout
			}
			continue
		}
		nr, _, err := unix.Recvfrom(q.fd, q.recvBuf, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			if err == unix.ENOBUFS {
				q.recvOverruns.Add(1)
				continue
			}
			return nil, fmt.Errorf("nfqueue: recv: %w", err)
		}
		pkts, err := q.parsePackets(q.recvBuf[:nr])
		if err != nil {
			return nil, err
		}
		if len(pkts) == 0 {
			continue
		}
		q.pending = append(q.pending, pkts[1:]...)
		return pkts[0], nil
	}
}

// Packet is one held packet. Payload is a copy valid after Recv returns.
// The provenance fields mirror the nfgenmsg family and NFQA_* attributes
// carried by the kernel. They are observational only; callers must validate
// them against an OriginRegistry before any non-drop disposition.
type Packet struct {
	q        *Queue
	id       uint32
	payload  []byte
	recvTime time.Time
	queueID  uint16

	nfgenFamily   uint8
	hook          uint8
	indevIfindex  uint32
	outdevIfindex uint32

	done      atomic.Bool
	verdictAt atomic.Int64 // unix-nano of first successful verdict, 0 until then
}

// NfgenFamily is the raw nfgenmsg address family (AF_INET, AF_INET6, or
// AF_BRIDGE). Normalize it with ValidateProvenance before use.
func (p *Packet) NfgenFamily() uint8 {
	if p == nil {
		return 0
	}
	return p.nfgenFamily
}

// Hook is the raw NF_INET_* hook number from NFQA_PACKET_HDR.
func (p *Packet) Hook() uint8 {
	if p == nil {
		return 0
	}
	return p.hook
}

// IndevIfindex is NFQA_IFINDEX_INDEV, or zero when the kernel did not carry it.
func (p *Packet) IndevIfindex() uint32 {
	if p == nil {
		return 0
	}
	return p.indevIfindex
}

// OutdevIfindex is NFQA_IFINDEX_OUTDEV, or zero when the kernel did not carry it.
func (p *Packet) OutdevIfindex() uint32 {
	if p == nil {
		return 0
	}
	return p.outdevIfindex
}

// Payload returns the captured packet bytes.
func (p *Packet) Payload() []byte { return p.payload }

// RecvTime is the userspace receive time (capture event, not kernel-hook time:
// unread queue entries cannot be timed from a hook the design cannot observe).
func (p *Packet) RecvTime() time.Time { return p.recvTime }

// VerdictTime is the first successful verdict time, or zero until verdict.
func (p *Packet) VerdictTime() time.Time {
	if ns := p.verdictAt.Load(); ns != 0 {
		return time.Unix(0, ns)
	}
	return time.Time{}
}

// QueueID is the queue the packet was held on.
func (p *Packet) QueueID() uint16 { return p.queueID }

// PacketID returns the kernel packet identifier used by the terminal verdict.
func (p *Packet) PacketID() uint32 {
	if p == nil {
		return 0
	}
	return p.id
}

// Verdict disposes the held packet. After Close it returns ErrClosed (never
// panics, never silently accepts). A packet has one terminal verdict attempt:
// an error is ambiguous and MUST NOT be retried, because the kernel may have
// already applied it.
func (p *Packet) Verdict(v Verdict) error {
	q := p.q
	if q == nil {
		return ErrClosed
	}
	if v != VerdictAccept && v != VerdictDrop {
		q.verdictErrors.Add(1)
		return fmt.Errorf("nfqueue: unsupported verdict %d", v)
	}
	if err := q.acquireSend(); err != nil {
		if p.done.CompareAndSwap(false, true) {
			return err
		}
		return ErrAlreadyVerdicted
	}
	defer q.releaseSend()
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		q.verdictErrors.Add(1)
		return ErrClosed
	}
	if !p.done.CompareAndSwap(false, true) {
		q.mu.Unlock()
		q.verdictErrors.Add(1)
		return ErrAlreadyVerdicted
	}
	msg := buildVerdict(q.ID(), p.id, uint32(v))
	q.verdictAttempted.Add(1)
	q.mu.Unlock()
	if err := unix.Send(q.fd, msg, unix.MSG_DONTWAIT); err != nil {
		q.verdictUncertain.Add(1)
		q.verdictErrors.Add(1)
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			// MSG_DONTWAIT reports local backpressure before the verdict
			// datagram is accepted. Release the terminal reservation so the
			// caller can retry; other send errors remain terminal-but-uncertain.
			p.done.CompareAndSwap(true, false)
			return fmt.Errorf("%w: verdict %s id=%d: %w", ErrVerdictTimeout, v, p.id, err)
		}
		return fmt.Errorf("nfqueue: verdict %s id=%d: %w", v, p.id, err)
	}
	q.verdictSuccessful.Add(1)
	p.verdictAt.CompareAndSwap(0, time.Now().UnixNano())
	switch v {
	case VerdictAccept:
		q.accepted.Add(1)
	case VerdictDrop:
		q.dropped.Add(1)
	}
	return nil
}

// VerdictBatch disposes a batch with one sendmmsg. An empty batch is nil.
// Contract is transport all-or-error: a failed sendmmsg returns an error and
// counts it; the kernel applies each datagram independently, so a partial
// transport failure may dispose a prefix. The error reports how far the
// transport got; the suffix is terminal-but-uncertain and must be reconciled
// by the supervisor rather than retried. No partial silent accept: every
// packet is either verdict-sent or error-reported.
func (q *Queue) VerdictBatch(v Verdict, pkts []*Packet) error {
	if len(pkts) == 0 {
		return nil
	}
	if v != VerdictAccept && v != VerdictDrop {
		q.verdictErrors.Add(uint64(len(pkts)))
		return fmt.Errorf("nfqueue: unsupported verdict %d", v)
	}
	if err := q.acquireSend(); err != nil {
		for _, pkt := range pkts {
			if pkt != nil && pkt.q == q {
				pkt.done.CompareAndSwap(false, true)
			}
		}
		q.verdictUncertain.Add(uint64(len(pkts)))
		return err
	}
	defer q.releaseSend()
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		q.verdictErrors.Add(uint64(len(pkts)))
		return ErrClosed
	}
	// Prevalidate before reserving any packet. The lock prevents a concurrent
	// per-packet verdict on this queue from winning between validation and
	// reservation, and packets from another queue are never accepted.
	seen := make(map[*Packet]struct{}, len(pkts))
	for _, pkt := range pkts {
		if pkt == nil || pkt.q != q || pkt.done.Load() {
			q.mu.Unlock()
			q.verdictErrors.Add(1)
			return ErrAlreadyVerdicted
		}
		if _, ok := seen[pkt]; ok {
			q.mu.Unlock()
			q.verdictErrors.Add(1)
			return ErrAlreadyVerdicted
		}
		seen[pkt] = struct{}{}
	}
	for _, pkt := range pkts {
		if !pkt.done.CompareAndSwap(false, true) {
			q.mu.Unlock()
			q.verdictErrors.Add(1)
			return ErrAlreadyVerdicted
		}
	}
	q.mu.Unlock()
	msgs := make([]linuxMmsghdr, len(pkts))
	iovs := make([]unix.Iovec, len(pkts))
	bufs := make([][]byte, len(pkts))
	for i, pkt := range pkts {
		bufs[i] = buildVerdict(q.ID(), pkt.id, uint32(v))
		iovs[i] = unix.Iovec{Base: &bufs[i][0], Len: uint64(len(bufs[i]))}
		msgs[i].msg.Iov = &iovs[i]
		msgs[i].msg.Iovlen = 1
	}
	q.verdictAttempted.Add(uint64(len(pkts)))
	n, err := sendmmsg(q.fd, msgs)
	sent := n
	if sent < 0 {
		sent = 0
	}
	if sent > len(pkts) {
		sent = len(pkts)
	}
	now := time.Now().UnixNano()
	for i := 0; i < sent; i++ {
		pkts[i].verdictAt.CompareAndSwap(0, now)
	}
	q.batchVerdicts.Add(uint64(sent))
	q.verdictSuccessful.Add(uint64(sent))
	q.verdictUncertain.Add(uint64(len(pkts) - sent))
	switch v {
	case VerdictAccept:
		q.accepted.Add(uint64(sent))
	case VerdictDrop:
		q.dropped.Add(uint64(sent))
	}
	if err != nil {
		q.verdictErrors.Add(uint64(len(pkts) - sent))
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			return fmt.Errorf("%w: batch verdict %s: sent %d/%d: %w", ErrVerdictTimeout, v, sent, len(pkts), err)
		}
		return fmt.Errorf("nfqueue: batch verdict %s: sent %d/%d: %w", v, sent, len(pkts), err)
	}
	if sent != len(pkts) {
		q.verdictErrors.Add(uint64(len(pkts) - sent))
		return fmt.Errorf("%w: batch verdict %s: sent %d/%d (short send)", ErrVerdictTimeout, v, sent, len(pkts))
	}
	return nil
}

// sendmmsg invokes Linux sendmmsg directly because x/sys/unix does not expose
// its mmsghdr wrapper. The local mmsghdr layout is the Linux ABI:
// struct msghdr followed by unsigned int msg_len and four bytes padding.
func sendmmsg(fd int, msgs []linuxMmsghdr) (int, error) {
	if len(msgs) == 0 {
		return 0, nil
	}
	r1, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd),
		uintptr(unsafe.Pointer(&msgs[0])), uintptr(len(msgs)), 0, 0, 0)
	if errno != 0 {
		return int(r1), errno
	}
	return int(r1), nil
}

// nlAttr is one NLA attribute (host-order header, payload, NLA-aligned).
type nlAttr struct {
	Type uint16
	Data []byte
}

// nlaAlign rounds l up to the NLA alignment (4).
func nlaAlign(l int) int { return (l + 3) &^ 3 }

// appendNlAttr appends one attribute with padding.
func appendNlAttr(b []byte, a nlAttr) []byte {
	l := 4 + len(a.Data)
	hdr := make([]byte, 4)
	binary.LittleEndian.PutUint16(hdr[0:2], uint16(l))
	binary.LittleEndian.PutUint16(hdr[2:4], a.Type)
	b = append(b, hdr...)
	b = append(b, a.Data...)
	if pad := nlaAlign(l) - l; pad > 0 {
		b = append(b, make([]byte, pad)...)
	}
	return b
}

// buildNfgenmsg returns family/version/res_id (res_id big-endian).
func buildNfgenmsg(family byte, resID uint16) []byte {
	b := make([]byte, 4)
	b[0] = family
	b[1] = nfnetlinkV0
	binary.BigEndian.PutUint16(b[2:4], resID)
	return b
}

// buildNlmsg wraps payload in an nlmsghdr (host order).
func buildNlmsg(msgType uint16, flags uint16, seq uint32, payload []byte) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], uint32(16+len(payload)))
	binary.LittleEndian.PutUint16(b[4:6], msgType)
	binary.LittleEndian.PutUint16(b[6:8], flags)
	binary.LittleEndian.PutUint32(b[8:12], seq)
	binary.LittleEndian.PutUint32(b[12:16], 0)
	return append(b, payload...)
}

// buildVerdict builds one NFQNL_MSG_VERDICT (no ACK: fire-and-forget).
func buildVerdict(queueID uint16, id uint32, verdict uint32) []byte {
	payload := buildNfgenmsg(unix.AF_UNSPEC, queueID)
	vh := make([]byte, 8)
	binary.BigEndian.PutUint32(vh[0:4], verdict)
	binary.BigEndian.PutUint32(vh[4:8], id)
	payload = appendNlAttr(payload, nlAttr{Type: nfqaVerdictHdr, Data: vh})
	return buildNlmsg(nfqnlMsgVerdictType, nlmFRequest, 0, payload)
}

// configure sends one NFQNL_MSG_CONFIG and waits for its ACK.
func (q *Queue) configure(resID uint16, cmd int, pf int, attrs []nlAttr) error {
	seq := q.seq.Add(1)
	if err := q.sendConfig(resID, cmd, pf, attrs, true); err != nil {
		return err
	}
	return q.waitAck(seq)
}

// sendConfig sends one NFQNL_MSG_CONFIG. With wantSeq it stamps the current
// sequence and asks for an ACK; Close uses a best-effort unbind without wait.
func (q *Queue) sendConfig(resID uint16, cmd int, pf int, attrs []nlAttr, wantSeq bool) error {
	payload := buildNfgenmsg(unix.AF_UNSPEC, resID)
	if cmd != 0 {
		cc := make([]byte, 4)
		cc[0] = byte(cmd)
		binary.BigEndian.PutUint16(cc[2:4], uint16(pf))
		payload = appendNlAttr(payload, nlAttr{Type: nfqaCfgCmd, Data: cc})
	}
	for _, a := range attrs {
		payload = appendNlAttr(payload, a)
	}
	var seq uint32
	flags := uint16(nlmFRequest)
	if wantSeq {
		seq = q.seq.Load()
		flags |= nlmFAck
	}
	msg := buildNlmsg(nfqnlMsgConfigType, flags, seq, payload)
	if err := unix.Send(q.fd, msg, 0); err != nil {
		return fmt.Errorf("nfqueue: send config: %w", err)
	}
	return nil
}

// waitAck reads until the ACK (NLMSG_ERROR with code 0) or failure for seq.
func (q *Queue) waitAck(seq uint32) error {
	buf := make([]byte, recvBufSize)
	deadline := time.Now().Add(5 * time.Second)
	for {
		timeoutMs := int(time.Until(deadline).Milliseconds())
		if timeoutMs < 0 {
			return fmt.Errorf("nfqueue: config ack seq=%d: timeout", seq)
		}
		pfds := []unix.PollFd{{Fd: int32(q.fd), Events: unix.POLLIN}}
		n, err := unix.Poll(pfds, timeoutMs)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return fmt.Errorf("nfqueue: config ack poll: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("nfqueue: config ack seq=%d: timeout", seq)
		}
		nr, _, err := unix.Recvfrom(q.fd, buf, 0)
		if err != nil {
			if err == unix.ENOBUFS {
				continue
			}
			return fmt.Errorf("nfqueue: config ack recv: %w", err)
		}
		off := 0
		for off+16 <= nr {
			mlen := int(binary.LittleEndian.Uint32(buf[off : off+4]))
			mtype := binary.LittleEndian.Uint16(buf[off+4 : off+6])
			mseq := binary.LittleEndian.Uint32(buf[off+8 : off+12])
			if mlen < 16 || off+mlen > nr {
				break
			}
			if mtype == nlmsgError && mseq == seq {
				if off+20 > nr {
					return fmt.Errorf("nfqueue: config ack seq=%d: truncated error", seq)
				}
				code := int32(binary.LittleEndian.Uint32(buf[off+16 : off+20]))
				if code == 0 {
					return nil
				}
				return unix.Errno(-code)
			}
			off += nlaAlign(mlen)
		}
	}
}

// parsePackets extracts NFQNL_MSG_PACKET messages from one netlink datagram.
func (q *Queue) parsePackets(buf []byte) ([]*Packet, error) {
	var out []*Packet
	now := time.Now()
	off := 0
	for off+16 <= len(buf) {
		mlen := int(binary.LittleEndian.Uint32(buf[off : off+4]))
		mtype := binary.LittleEndian.Uint16(buf[off+4 : off+6])
		if mlen < 16 || off+mlen > len(buf) {
			break
		}
		end := off + mlen
		if mtype == uint16(nfqnlMsgPacketType) && off+20 <= end {
			nfgenFamily := buf[off+16]
			resID := binary.BigEndian.Uint16(buf[off+18 : off+20])
			if resID == q.ID() {
				if pkt, ok := parseOnePacket(q, buf[off+20:end], now, nfgenFamily); ok {
					q.held.Add(1)
					out = append(out, pkt)
				}
			}
		}
		off += nlaAlign(mlen)
	}
	return out, nil
}

// parseOnePacket parses the attribute stream of one NFQNL_MSG_PACKET.
func parseOnePacket(q *Queue, attrs []byte, now time.Time, nfgenFamily uint8) (*Packet, bool) {
	var id uint32
	var haveID bool
	var hook uint8
	var indevIfindex, outdevIfindex uint32
	var payload []byte
	off := 0
	for off+4 <= len(attrs) {
		alen := int(binary.LittleEndian.Uint16(attrs[off : off+2]))
		atype := binary.LittleEndian.Uint16(attrs[off+2 : off+4])
		if alen < 4 || off+alen > len(attrs) {
			break
		}
		body := attrs[off+4 : off+alen]
		switch atype {
		case nfqaPacketHdr:
			if len(body) >= 4 {
				id = binary.BigEndian.Uint32(body[:4])
				haveID = true
			}
			if len(body) >= 7 {
				hook = body[6]
			}
		case nfqaIfindexIndev:
			if len(body) >= 4 {
				indevIfindex = binary.BigEndian.Uint32(body[:4])
			}
		case nfqaIfindexOutdev:
			if len(body) >= 4 {
				outdevIfindex = binary.BigEndian.Uint32(body[:4])
			}
		case nfqaPayload:
			payload = append([]byte(nil), body...)
		}
		off += nlaAlign(alen)
	}
	if !haveID {
		return nil, false
	}
	return &Packet{
		q: q, id: id, payload: payload, recvTime: now, queueID: q.ID(),
		nfgenFamily: nfgenFamily, hook: hook,
		indevIfindex: indevIfindex, outdevIfindex: outdevIfindex,
	}, true
}
