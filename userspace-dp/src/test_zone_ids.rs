//! #919: canonical zone-ID constants for test fixtures.
//!
//! Production zone IDs are assigned by the Go control plane as a STABLE
//! name-hash (`config.StableZoneID`, FNV-1a fold into [1, 65533]) — the
//! compiler (`pkg/dataplane.assignZoneIDs`), the live wire builder
//! (`pkg/dataplane/userspace/zones.go:buildZoneSnapshots`, #3704), and the
//! HA name fallback (`pkg/daemon.buildZoneIDs`) all agree by construction.
//! These constants are ARBITRARY small ids for test code only; the dataplane
//! reads whatever id the snapshot carries (name -> id via `zone_name_to_id`),
//! so tests may use any distinct values. They give test code stable, named IDs
//! for `SessionMetadata` constructors and `zone_name_to_id` / `zone_id_to_name`
//! test maps, mirroring the conventional zone names used across most fixtures.
//!
//! Tests that construct a custom `ForwardingState` should populate
//! `zone_name_to_id` and `zone_id_to_name` consistently with these
//! IDs, e.g.:
//!
//! ```ignore
//! forwarding.zone_name_to_id.insert("lan".to_string(), TEST_LAN_ZONE_ID);
//! forwarding.zone_id_to_name.insert(TEST_LAN_ZONE_ID, "lan".to_string());
//! ```

#![cfg(test)]

pub(crate) const TEST_LAN_ZONE_ID: u32 = 1;
pub(crate) const TEST_WAN_ZONE_ID: u32 = 2;
pub(crate) const TEST_TRUST_ZONE_ID: u32 = 3;
pub(crate) const TEST_UNTRUST_ZONE_ID: u32 = 4;
pub(crate) const TEST_SFMIX_ZONE_ID: u32 = 5;
pub(crate) const TEST_FABRIC_ZONE_ID: u32 = 6;
pub(crate) const TEST_DMZ_ZONE_ID: u32 = 7;
pub(crate) const TEST_MGMT_ZONE_ID: u32 = 8;
