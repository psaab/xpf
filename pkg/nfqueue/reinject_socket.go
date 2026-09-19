package nfqueue

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	reinjectMsgSubmitBatch = 1
	reinjectMsgCancel      = 2
	reinjectMsgAnnounce    = 3
	reinjectMsgAdmit       = 11
	reinjectMsgComplete    = 12
	reinjectMaxFrames      = 64
	reinjectMaxData        = 65535
	reinjectMaxMessage     = 1 << 20
	reinjectMaxQueues      = 128
	reinjectOriginInet     = 1
	reinjectOriginBridge   = 2
	reinjectOriginForward  = 1
	reinjectOriginInput    = 2
)

// ReinjectQueueEpoch is the allocator identity the Rust authority accepts for
// one NFQUEUE. It intentionally lives in nfqueue so the socket client does not
// create a package cycle with the userspace manager.
type ReinjectQueueEpoch struct {
	Queue uint16
	Epoch uint64
}

// SocketReinjectSubmitter is the dedicated Go↔Rust data-plane handoff. It
// never uses the JSON control socket. The submit and completion streams are
// independently serialized so a slow completion reader cannot block submit
// admission, while every request remains bounded by the wire caps.
type SocketReinjectSubmitter struct {
	submitPath   string
	completePath string
	timeout      time.Duration

	submitMu        sync.Mutex
	submit          net.Conn
	announceSet     bool
	announcePayload []byte

	completeMu sync.Mutex
	complete   net.Conn
}

// NewSocketReinjectSubmitter constructs a lazy two-socket client. Dialing is
// deferred until the first operation so daemon startup can order helper spawn
// before capture admission without an unbounded retry loop.
func NewSocketReinjectSubmitter(submitPath, completePath string) (*SocketReinjectSubmitter, error) {
	if strings.TrimSpace(submitPath) == "" || strings.TrimSpace(completePath) == "" {
		return nil, errors.New("nfqueue: reinject socket paths are required")
	}
	return &SocketReinjectSubmitter{
		submitPath:   submitPath,
		completePath: completePath,
		timeout:      5 * time.Millisecond,
	}, nil
}

func (s *SocketReinjectSubmitter) dial(path string) (net.Conn, error) {
	return net.DialTimeout("unix", path, s.timeout)
}

// ensureSubmitLocked dials the submit stream and replays the latest authority
// before any new request. A Rust helper restart creates a fresh Unix connection;
// replaying here closes the window where q0 submissions would otherwise be
// refused under an empty authority.
func (s *SocketReinjectSubmitter) ensureSubmitLocked() error {
	if s.submit != nil {
		return nil
	}
	conn, err := s.dial(s.submitPath)
	if err != nil {
		return err
	}
	if s.announceSet {
		if err := writeReinjectMessage(conn, reinjectMsgAnnounce, s.announcePayload, s.timeout); err != nil {
			_ = conn.Close()
			return err
		}
	}
	s.submit = conn
	return nil
}

func (s *SocketReinjectSubmitter) SubmitAdjudicated(frames []AdjudicatedFrame) ([]ReinjectAdmission, error) {
	if s == nil {
		return nil, errors.New("nfqueue: nil reinject socket client")
	}
	if len(frames) == 0 {
		return nil, nil
	}
	if len(frames) > reinjectMaxFrames {
		return nil, fmt.Errorf("nfqueue: reinject batch %d exceeds cap %d", len(frames), reinjectMaxFrames)
	}
	s.submitMu.Lock()
	defer s.submitMu.Unlock()
	if err := s.ensureSubmitLocked(); err != nil {
		return nil, fmt.Errorf("nfqueue: connect reinject submit: %w", err)
	}
	payload, err := encodeSubmitBatch(frames)
	if err != nil {
		return nil, err
	}
	admitPayload, err := s.roundTripLocked(s.submit, reinjectMsgSubmitBatch, payload)
	if err != nil {
		_ = s.submit.Close()
		s.submit = nil
		return nil, err
	}
	admissions, err := decodeAdmissions(admitPayload)
	if err != nil {
		_ = s.submit.Close()
		s.submit = nil
		return nil, err
	}
	return admissions, nil
}

func (s *SocketReinjectSubmitter) DrainReinjectCompletions(max uint32) ([]ReinjectCompletion, error) {
	if s == nil {
		return nil, errors.New("nfqueue: nil reinject socket client")
	}
	if max == 0 {
		return nil, nil
	}
	if max > reinjectMaxFrames {
		max = reinjectMaxFrames
	}
	s.completeMu.Lock()
	defer s.completeMu.Unlock()
	if s.complete == nil {
		conn, err := s.dial(s.completePath)
		if err != nil {
			return nil, fmt.Errorf("nfqueue: connect reinject complete: %w", err)
		}
		s.complete = conn
	}
	_ = s.complete.SetReadDeadline(time.Now().Add(s.timeout))
	typ, payload, err := readReinjectMessage(s.complete)
	if err != nil {
		if isTimeout(err) {
			// readReinjectMessage may have consumed a partial header/body before
			// the deadline. Never reuse that stream: the next frame would be
			// decoded from the middle of the timed-out one.
			_ = s.complete.Close()
			s.complete = nil
			return nil, nil
		}
		_ = s.complete.Close()
		s.complete = nil
		return nil, fmt.Errorf("nfqueue: read reinject completion: %w", err)
	}
	if typ != reinjectMsgComplete {
		_ = s.complete.Close()
		s.complete = nil
		return nil, fmt.Errorf("nfqueue: unexpected reinject completion type %d", typ)
	}
	completions, err := decodeCompletions(payload)
	if err != nil {
		_ = s.complete.Close()
		s.complete = nil
		return nil, err
	}
	if len(completions) > int(max) {
		return completions[:max], nil
	}
	return completions, nil
}

func (s *SocketReinjectSubmitter) CancelReinject(requestIDs []uint64, permitEpoch uint64, scopes []ReinjectQueueScope) ([]uint64, error) {
	if s == nil {
		return nil, errors.New("nfqueue: nil reinject socket client")
	}
	if len(requestIDs) == 0 && permitEpoch == 0 && len(scopes) == 0 {
		return nil, nil
	}
	payload, err := encodeCancel(requestIDs, permitEpoch, scopes)
	if err != nil {
		return nil, err
	}
	s.submitMu.Lock()
	defer s.submitMu.Unlock()
	if err := s.ensureSubmitLocked(); err != nil {
		return nil, fmt.Errorf("nfqueue: connect reinject cancel: %w", err)
	}
	if err := writeReinjectMessage(s.submit, reinjectMsgCancel, payload, s.timeout); err != nil {
		_ = s.submit.Close()
		s.submit = nil
		return nil, fmt.Errorf("nfqueue: write reinject cancel: %w", err)
	}
	return append([]uint64(nil), requestIDs...), nil
}

func (s *SocketReinjectSubmitter) roundTripLocked(conn net.Conn, typ byte, payload []byte) ([]byte, error) {
	if err := writeReinjectMessage(conn, typ, payload, s.timeout); err != nil {
		return nil, fmt.Errorf("nfqueue: write reinject message: %w", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, fmt.Errorf("nfqueue: set reinject read deadline: %w", err)
	}
	responseType, response, err := readReinjectMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("nfqueue: read reinject admission: %w", err)
	}
	if responseType != reinjectMsgAdmit {
		return nil, fmt.Errorf("nfqueue: unexpected reinject response type %d", responseType)
	}
	return response, nil
}

// AnnounceReinject publishes the current permit/queue authority on the
// persistent submit stream. Unlike submit/cancel it has no response frame;
// subsequent submits still receive their normal ADMIT response.
func (s *SocketReinjectSubmitter) AnnounceReinject(permitEpoch uint64, permitOpen bool, epochs []ReinjectQueueEpoch) error {
	if s == nil {
		return errors.New("nfqueue: nil reinject socket client")
	}
	if len(epochs) > reinjectMaxQueues {
		return fmt.Errorf("nfqueue: reinject authority has %d queues, cap %d", len(epochs), reinjectMaxQueues)
	}
	if permitOpen && permitEpoch == 0 {
		return errors.New("nfqueue: open reinject authority requires permit epoch")
	}
	payload, err := encodeAnnounce(permitEpoch, permitOpen, epochs)
	if err != nil {
		return err
	}
	s.submitMu.Lock()
	defer s.submitMu.Unlock()
	s.announceSet = true
	s.announcePayload = append(s.announcePayload[:0], payload...)
	existing := s.submit != nil
	if err := s.ensureSubmitLocked(); err != nil {
		return fmt.Errorf("nfqueue: connect reinject announce: %w", err)
	}
	if existing {
		if err := writeReinjectMessage(s.submit, reinjectMsgAnnounce, payload, s.timeout); err != nil {
			_ = s.submit.Close()
			s.submit = nil
			return fmt.Errorf("nfqueue: write reinject announce: %w", err)
		}
	}
	return nil
}

// Close releases both lazy streams. It is idempotent and is called while a
// staged generation is retired so no descriptor survives a failed apply.
func (s *SocketReinjectSubmitter) Close() error {
	if s == nil {
		return nil
	}
	var firstErr error
	s.submitMu.Lock()
	if s.submit != nil {
		if err := s.submit.Close(); err != nil {
			firstErr = err
		}
		s.submit = nil
	}
	s.submitMu.Unlock()
	s.completeMu.Lock()
	if s.complete != nil {
		if err := s.complete.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		s.complete = nil
	}
	s.completeMu.Unlock()
	return firstErr
}

func encodeAnnounce(permitEpoch uint64, permitOpen bool, epochs []ReinjectQueueEpoch) ([]byte, error) {
	if len(epochs) > reinjectMaxQueues {
		return nil, fmt.Errorf("nfqueue: reinject authority has %d queues, cap %d", len(epochs), reinjectMaxQueues)
	}
	if permitOpen && permitEpoch == 0 {
		return nil, errors.New("nfqueue: open reinject authority requires permit epoch")
	}
	out := make([]byte, 0, 11+len(epochs)*10)
	putU64(&out, permitEpoch)
	if permitOpen {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	putU16(&out, uint16(len(epochs)))
	seen := make(map[uint16]struct{}, len(epochs))
	for _, item := range epochs {
		if item.Queue == 0 || item.Epoch == 0 {
			return nil, errors.New("nfqueue: reinject authority contains zero queue/epoch")
		}
		if _, ok := seen[item.Queue]; ok {
			return nil, fmt.Errorf("nfqueue: duplicate reinject authority queue %d", item.Queue)
		}
		seen[item.Queue] = struct{}{}
		putU16(&out, item.Queue)
		putU64(&out, item.Epoch)
	}
	return out, nil
}

func encodeSubmitBatch(frames []AdjudicatedFrame) ([]byte, error) {
	out := make([]byte, 2, 2+len(frames)*128)
	binary.BigEndian.PutUint16(out, uint16(len(frames)))
	for _, item := range frames {
		if item.Frame.Packet == nil {
			return nil, errors.New("nfqueue: nil packet in reinject batch")
		}
		family, hook, err := originWire(item.Origin)
		if err != nil {
			return nil, err
		}
		if item.Origin.OwnedIfindex == 0 {
			return nil, errors.New("nfqueue: reinject origin ifindex is required")
		}
		owner, stn := item.Origin.Owner, item.Origin.STN
		if len(owner) > 64 || len(stn) > 16 || owner == "" || stn == "" || !utf8.ValidString(owner) || !utf8.ValidString(stn) {
			return nil, errors.New("nfqueue: invalid reinject origin owner/STN")
		}
		data := item.Frame.Packet.Payload()
		if len(data) == 0 || len(data) > reinjectMaxData {
			return nil, fmt.Errorf("nfqueue: reinject payload length %d outside 1..%d", len(data), reinjectMaxData)
		}
		putU64(&out, item.Lease.RequestID)
		putU64(&out, item.Lease.PermitEpoch)
		putU64(&out, item.Lease.QueueEpoch)
		putU16(&out, item.Lease.QueueNumber)
		putU64(&out, flowTag(item.Frame.FlowKey))
		out = append(out, 0, family, hook)
		putU32(&out, item.Origin.OwnedIfindex)
		out = append(out, byte(len(owner)))
		out = append(out, owner...)
		out = append(out, byte(len(stn)))
		out = append(out, stn...)
		putU32(&out, uint32(len(data)))
		out = append(out, data...)
	}
	return out, nil
}

func encodeCancel(ids []uint64, permit uint64, scopes []ReinjectQueueScope) ([]byte, error) {
	if len(ids) > 65535 || len(scopes) > 65535 {
		return nil, errors.New("nfqueue: reinject cancel scope too large")
	}
	var flags byte
	if len(ids) != 0 {
		flags |= 0x01
	}
	if permit != 0 {
		flags |= 0x02
	}
	if len(scopes) != 0 {
		flags |= 0x04
	}
	out := []byte{flags}
	if flags&0x01 != 0 {
		putU16(&out, uint16(len(ids)))
		for _, id := range ids {
			putU64(&out, id)
		}
	}
	if flags&0x02 != 0 {
		putU64(&out, permit)
	}
	if flags&0x04 != 0 {
		putU16(&out, uint16(len(scopes)))
		for _, scope := range scopes {
			putU16(&out, scope.QueueNumber)
			putU64(&out, scope.QueueEpoch)
		}
	}
	return out, nil
}

func decodeAdmissions(payload []byte) ([]ReinjectAdmission, error) {
	if len(payload) < 2 {
		return nil, errors.New("nfqueue: truncated reinject admissions")
	}
	n := int(binary.BigEndian.Uint16(payload[:2]))
	if n > reinjectMaxFrames {
		return nil, errors.New("nfqueue: too many reinject admissions")
	}
	off := 2
	out := make([]ReinjectAdmission, 0, n)
	for i := 0; i < n; i++ {
		if off+34 > len(payload) {
			return nil, errors.New("nfqueue: truncated reinject admission row")
		}
		row := ReinjectAdmission{
			RequestID:    binary.BigEndian.Uint64(payload[off : off+8]),
			PermitEpoch:  binary.BigEndian.Uint64(payload[off+8 : off+16]),
			QueueEpoch:   binary.BigEndian.Uint64(payload[off+16 : off+24]),
			QueueNumber:  binary.BigEndian.Uint16(payload[off+24 : off+26]),
			Family:       payload[off+26],
			Hook:         payload[off+27],
			OwnedIfindex: binary.BigEndian.Uint32(payload[off+28 : off+32]),
			Admitted:     payload[off+32] == 1,
		}
		reason := payload[off+33]
		row.Reason = fmt.Sprintf("reason-%d", reason)
		out = append(out, row)
		off += 34
	}
	if off != len(payload) {
		return nil, errors.New("nfqueue: trailing reinject admissions")
	}
	return out, nil
}

func decodeCompletions(payload []byte) ([]ReinjectCompletion, error) {
	if len(payload) < 2 {
		return nil, errors.New("nfqueue: truncated reinject completions")
	}
	n := int(binary.BigEndian.Uint16(payload[:2]))
	if n > reinjectMaxFrames {
		return nil, errors.New("nfqueue: too many reinject completions")
	}
	off := 2
	out := make([]ReinjectCompletion, 0, n)
	for i := 0; i < n; i++ {
		if off+37 > len(payload) {
			return nil, errors.New("nfqueue: truncated reinject completion row")
		}
		row := ReinjectCompletion{
			RequestID:    binary.BigEndian.Uint64(payload[off : off+8]),
			PermitEpoch:  binary.BigEndian.Uint64(payload[off+8 : off+16]),
			QueueEpoch:   binary.BigEndian.Uint64(payload[off+16 : off+24]),
			QueueNumber:  binary.BigEndian.Uint16(payload[off+24 : off+26]),
			Family:       payload[off+26],
			Hook:         payload[off+27],
			OwnedIfindex: binary.BigEndian.Uint32(payload[off+28 : off+32]),
			Outcome:      decodeOutcome(payload[off+32]),
			BytesWritten: binary.BigEndian.Uint32(payload[off+33 : off+37]),
		}
		if row.Outcome == "" {
			return nil, errors.New("nfqueue: unknown reinject completion outcome")
		}
		out = append(out, row)
		off += 37
	}
	if off != len(payload) {
		return nil, errors.New("nfqueue: trailing reinject completions")
	}
	return out, nil
}

func decodeOutcome(code byte) CompletionOutcome {
	switch code {
	case 1:
		return CompletionWritten
	case 2:
		return CompletionStale
	case 3:
		return CompletionCancelled
	case 4:
		return CompletionRefused
	case 5:
		return CompletionUncertain
	case 6:
		return CompletionFenced
	case 7:
		return CompletionDenied
	case 8:
		return CompletionAccepted
	case 9:
		return CompletionWouldReinject
	default:
		return ""
	}
}

func originWire(origin CaptureOrigin) (byte, byte, error) {
	var family byte
	switch origin.Family {
	case CaptureFamilyInet:
		family = reinjectOriginInet
	case CaptureFamilyBridge:
		family = reinjectOriginBridge
	default:
		return 0, 0, fmt.Errorf("nfqueue: unsupported reinject family %q", origin.Family)
	}
	var hook byte
	switch origin.Hook {
	case CaptureHookForward:
		hook = reinjectOriginForward
	case CaptureHookInput:
		hook = reinjectOriginInput
	default:
		return 0, 0, fmt.Errorf("nfqueue: unsupported reinject hook %q", origin.Hook)
	}
	return family, hook, nil
}

func flowTag(flow string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(flow))
	return h.Sum64()
}

func putU16(out *[]byte, value uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], value)
	*out = append(*out, b[:]...)
}
func putU32(out *[]byte, value uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], value)
	*out = append(*out, b[:]...)
}
func putU64(out *[]byte, value uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], value)
	*out = append(*out, b[:]...)
}

func writeReinjectMessage(conn net.Conn, typ byte, payload []byte, timeout time.Duration) error {
	if len(payload)+1 > reinjectMaxMessage {
		return errors.New("nfqueue: reinject message exceeds cap")
	}
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return err
	}
	var header [5]byte
	binary.BigEndian.PutUint32(header[:4], uint32(len(payload)+1))
	header[4] = typ
	if err := writeReinjectBytes(conn, header[:]); err != nil {
		return err
	}
	return writeReinjectBytes(conn, payload)
}

func writeReinjectBytes(conn net.Conn, data []byte) error {
	for len(data) != 0 {
		n, err := conn.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readReinjectMessage(conn net.Conn) (byte, []byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > reinjectMaxMessage {
		return 0, nil, errors.New("nfqueue: invalid reinject message length")
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, err
	}
	return body[0], body[1:], nil
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
