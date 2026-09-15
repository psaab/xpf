// MmapArea slice-bounds tests. Split from umem/tests.rs (#4667).

use super::*;

#[test]
fn mmap_area_rejects_access_beyond_registered_len_even_if_mapping_is_rounded() {
    let area = MmapArea::new(128).expect("mmap");

    assert!(area.slice(0, 128).is_some());
    assert!(area.slice(128, 1).is_none());
    assert!(area.slice(512, 1).is_none());
}

#[test]
fn mmap_area_rejects_span_across_frame_boundary_9900() {
    // Two frames; a descriptor crossing from frame 0 into frame 1 must fail
    // closed instead of forwarding the adjacent frame's bytes (F-091). Both
    // the shared and the mutable accessors enforce the bound.
    let area = MmapArea::new(8192).expect("mmap");
    assert!(area.slice(4090, 16).is_none());
    assert!(area.slice(0, 4097).is_none());
    assert!(area.slice(0, 8192).is_none());
    assert!(area.slice(256, 3840).is_some());
    assert!(area.slice(256, 3841).is_none());
    let mut area = area;
    assert!(area.slice_mut(4090, 16).is_none());
    assert!(unsafe { area.slice_mut_unchecked(0, 8192) }.is_none());
    assert!(unsafe { area.slice_mut_unchecked(4096, 4096) }.is_some());
}

#[test]
fn mmap_area_admits_single_frame_boundary_shapes_9900() {
    // Every legitimate production shape is boundary-exact and must keep
    // working: a full frame at an aligned base, a native RX descriptor at
    // base + 512 (UMEM_HEADROOM + XDP_PACKET_HEADROOM) with len <= 3584,
    // the 96-byte meta read ending exactly at desc.addr, and in-place
    // views around the headroom point.
    let area = MmapArea::new(8192).expect("mmap");
    assert!(area.slice(0, 4096).is_some());
    assert!(area.slice(4096, 4096).is_some());
    assert!(area.slice(512, 1500).is_some());
    assert!(area.slice(4096 + 512, 3584).is_some());
    assert!(area.slice(256, 1500).is_some());
    assert!(area.slice(4096 + 256, 3840).is_some());
    assert!(area.slice(416, 96).is_some());
    assert!(area.slice(4096 + 416, 96).is_some());
    assert!(area.slice(508, 1500).is_some());
    assert!(area.slice(516, 1500).is_some());
    assert!(area.slice(0, 0).is_some());
    assert!(area.slice(8192, 0).is_some());
}

#[test]
fn mmap_area_contained_slice_is_byte_identical_9900() {
    // Control: a contained slice exposes the same bytes as before — the
    // bound only turns would-be spans into None.
    let mut area = MmapArea::new(8192).expect("mmap");
    let frame = area.slice_mut(4096 + 256, 64).expect("contained write");
    for (i, b) in frame.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }
    let frame = area.slice(4096 + 256, 64).expect("contained read");
    assert!((0..64).all(|i| frame[i] == (i & 0xff) as u8));
}
