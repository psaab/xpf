package configstore

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

// ErrExceedsLimit is returned (wrapped) when a bounded read refuses a source
// for being over its ceiling. It exists so callers can identify THIS refusal
// structurally with errors.Is rather than by matching an error string.
//
// #7469: the #6753 tests originally distinguished the bounded read's refusal
// from the store's post-materialisation "config too large" rejection by
// checking for the substring "limit". Both messages are maintained
// independently, so rewording either one silently changed the verdict — and
// rewording the STORE's to contain "limit" would have made the test pass
// against the very code #6753 fixed, with no change to any #6753 file.
var ErrExceedsLimit = errors.New("exceeds size limit")

// ReadBounded reads at most max+1 bytes from r and rejects a source that
// exceeds max, allocating no more than max+1 bytes REGARDLESS of how much data
// r would supply. This is the load-bearing half of the #4909 fix: a plain
// io.ReadAll materializes the WHOLE source before any cap, so a FUSE/racing
// file that under-reported its Stat size could still stream an unbounded body
// and balloon memory. io.LimitReader(max+1) caps the read; reaching the
// (max+1)-th byte proves the source is over-cap.
func ReadBounded(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: %d byte ceiling", ErrExceedsLimit, max)
	}
	return data, nil
}

// ReadBoundedFile reads path, refusing anything larger than max bytes while
// allocating at most max+1 bytes REGARDLESS of the file's reported size.
//
// The pre-#4909 pattern was os.Stat (size gate) then os.ReadFile (whole-file
// alloc) then a post-read len(data) cap — a TOCTOU: an adversarial or
// FUSE-backed file can under-report its size to Stat and then stream an
// unbounded body to ReadFile, ballooning memory before the post-read cap
// fires. Reading through an io.LimitReader(max+1) on a single opened
// descriptor closes the window: the allocation is bounded by the limit, not by
// what Stat claimed, and reaching the (max+1)-th byte proves the file is
// over-cap. A non-regular file (dir/device/FIFO) is refused up front.
//
// The IsRegular check MUST precede the read, and the ordering is load-bearing
// rather than stylistic (#7469). On a pipe, O_NONBLOCK silently turns a
// would-be 24-byte read into a 0-byte read with err == nil — a truncation that
// reports success. Refusing every non-regular path before any read is the only
// thing that keeps this function from returning a silently short payload, and
// it is exported, so a caller reordering these two steps would reintroduce
// that. O_NONBLOCK being a no-op for regular files is the half that is NOT the
// risk.
//
// #6753: the open uses O_NONBLOCK. Opening a FIFO for reading BLOCKS until a
// writer appears, so a plain os.Open hangs before Stat can classify the path
// and reject it — the "or blocks" half of the defect, which a size cap alone
// does not address. O_NONBLOCK is a no-op for regular files, so the fast path
// is unchanged; it only ensures a non-regular path can be reached, classified
// and refused instead of hanging the process.
func ReadBoundedFile(path string, max int64) ([]byte, error) {
	// Authoritative config-store reads must not follow a symlink at the final
	// path component. O_NONBLOCK keeps FIFO rejection nonblocking; both flags
	// are no-ops for regular files.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	data, err := ReadBounded(f, max)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return data, nil
}

// ReadBoundedConfigFile reads a configuration file under the same MaxConfigSize
// ceiling the store enforces on any payload it accepts.
//
// It exists because that ceiling was previously enforced only AFTER the whole
// file was resident: checkConfigSize takes an already-materialised string, so
// it bounds what the store will ACCEPT, never what a caller will ALLOCATE. The
// CLI load paths read with os.ReadFile and then handed the result over, so a
// multi-gigabyte file was fully read and only then rejected (#6753).
//
// Both CLI surfaces call this rather than each bounding its own read: #4883-D
// fixed a directly analogous divergence between the local and remote CLI by
// moving the shared logic to one place, and the comment at that site records
// that the divergence itself is what produced the bug.
func ReadBoundedConfigFile(path string) ([]byte, error) {
	return ReadBoundedFile(path, MaxConfigSize)
}
