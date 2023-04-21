//! # Statically allocated structures
//!
//! We use a `make_manifest` macro to define the manifest used by stage 2. This macros ensures
//! that manifest symbols is properly exposed and can be picked up by stage 1.

use stage_two_abi::make_manifest;

// ————————————————————— Static Resources Configuration ————————————————————— //

pub const NB_CORES: usize = 32;
pub const NB_PAGES: usize = 200;
pub const NB_DOMAINS: usize = 16;
pub const NB_REGIONS: usize = 64;
pub const NB_REGIONS_PER_DOMAIN: usize = 46;
pub const NB_SWITCH_PER_DOMAIN: usize = 10;

// ————————————————————————— Second Stage Manifest —————————————————————————— //

make_manifest!();
