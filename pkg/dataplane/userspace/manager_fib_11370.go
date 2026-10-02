package userspace

import (
	"encoding/json"
	"errors"
	"io"
)

// fibDumpResponseFrameReader tracks the required newline boundary while
// streaming a FIB response through json.Decoder. The caller drains it after
// Decode so a complete JSON prefix cannot hide trailing bytes or cap overflow.
type fibDumpResponseFrameReader struct {
	reader            io.Reader
	newlineSeen       bool
	bytesAfterNewline bool
}

func (r *fibDumpResponseFrameReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	for _, b := range p[:n] {
		if r.newlineSeen {
			r.bytesAfterNewline = true
		} else if b == '\n' {
			r.newlineSeen = true
		}
	}
	return n, err
}

func decodeFIBDumpResponse(bounded *limitedResponseReader, response *ControlResponse) error {
	framed := &fibDumpResponseFrameReader{reader: bounded}
	if err := json.NewDecoder(framed).Decode(response); err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, framed); err != nil {
		return err
	}
	if bounded.truncated {
		return io.ErrUnexpectedEOF
	}
	if !framed.newlineSeen {
		return errors.New("control socket response to fib_dump is missing its newline terminator")
	}
	if framed.bytesAfterNewline {
		return errors.New("control socket response to fib_dump has bytes after its newline terminator")
	}
	return nil
}

// DumpFIB reads the installed userspace helper FIB (#11370).
//
// This is an operator-triggered read, not a polling API: it uses the shared
// control socket once and returns the helper's current generation with the
// rows captured under the same server-state lock.
func (m *Manager) DumpFIB() (uint32, []FibRouteWire, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.proc == nil {
		return 0, nil, errors.New("userspace dataplane helper not running")
	}
	resp, err := m.requestDetailedLocked(ControlRequest{
		Type:           "fib_dump",
		SuppressStatus: true,
	})
	if err != nil {
		return 0, nil, err
	}
	return resp.FIBGeneration, resp.FIBRoutes, nil
}

// DumpFIB forwards the helper-side read through the adapter published to the
// CLI and other daemon surfaces.
func (a *LegacyDataPlaneAdapter) DumpFIB() (uint32, []FibRouteWire, error) {
	m, err := a.managerOrErr()
	if err != nil {
		return 0, nil, err
	}
	return m.DumpFIB()
}
