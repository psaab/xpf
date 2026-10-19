// Tests for afxdp/umem/ — the UMEM memory region only. The binding-
// state concern tests moved to `binding_state/tests/` in #6436 when
// the binding-state cluster was extracted from this module (#4667
// per-concern layout maps 1:1 onto the new location).
//
// Submodules by concern (see each file):
//   drop_order  — #5192 UMEM-before-munmap field destruction order
//   mmap_area

use super::*;

mod drop_order;
mod mmap_area;
mod shared_clone_15730;
