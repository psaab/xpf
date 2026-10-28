//! #17152: crate-wide `#[cfg(test)]` support shared by unrelated gates.
//!
//! Declared `#[cfg(test)]`-only in `main.rs`; nothing here is compiled
//! into production builds.

pub(crate) mod source_scan;
