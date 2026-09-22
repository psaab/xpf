package configstore

// RenameDescriptor records one candidate-tree Rename operation. Paths are
// copied at capture time so callers may reuse their input slices after the
// store mutation returns.
//
// The descriptor is intentionally transport-neutral. The daemon expands the
// source and destination paths against the old and new compiled configs before
// using it for policy retention; an absent descriptor therefore preserves the
// existing delete/teardown behavior.
type RenameDescriptor struct {
	SourcePath      []string
	DestinationPath []string
}

func cloneRenameDescriptors(in []RenameDescriptor) []RenameDescriptor {
	if len(in) == 0 {
		return nil
	}
	out := make([]RenameDescriptor, len(in))
	for i, descriptor := range in {
		out[i] = RenameDescriptor{
			SourcePath:      append([]string(nil), descriptor.SourcePath...),
			DestinationPath: append([]string(nil), descriptor.DestinationPath...),
		}
	}
	return out
}

// PendingRenameAncestry returns all currently retained descriptors. It exists
// for diagnostics; apply paths should use PendingRenameAncestryForGeneration.
func (s *Store) PendingRenameAncestry() []RenameDescriptor {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []RenameDescriptor
	for _, descriptors := range s.pendingRenameAncestry {
		out = append(out, cloneRenameDescriptors(descriptors)...)
	}
	return out
}

// PendingRenameAncestryForGeneration returns descriptors captured while the
// exact candidate generation was edited.
func (s *Store) PendingRenameAncestryForGeneration(gen uint64) []RenameDescriptor {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRenameDescriptors(s.pendingRenameAncestry[gen])
}

// recordRenameAncestryLocked associates descriptors with the post-mutation
// candidate generation. Caller holds s.mu.
func (s *Store) recordRenameAncestryLocked(gen uint64, descriptor RenameDescriptor) {
	if s.pendingRenameAncestry == nil {
		s.pendingRenameAncestry = make(map[uint64][]RenameDescriptor)
	}
	s.pendingRenameAncestry[gen] = append(
		s.pendingRenameAncestry[gen],
		RenameDescriptor{
			SourcePath:      append([]string(nil), descriptor.SourcePath...),
			DestinationPath: append([]string(nil), descriptor.DestinationPath...),
		},
	)
}

// ClearPendingRenameAncestryForGeneration retires the descriptor set for a
// consumed candidate generation. The daemon calls it at bind time in
// commitWithGenBinding, which transfers ownership to its own copy; no apply
// outcome retains store-side state.
func (s *Store) ClearPendingRenameAncestryForGeneration(gen uint64) {
	if s == nil {
		return
	}
	s.mu.Lock()
	delete(s.pendingRenameAncestry, gen)
	s.mu.Unlock()
}
