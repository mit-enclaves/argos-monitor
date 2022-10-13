//! # Statically allocated structures
//!
//! We use a `make_static` macro to define the static structures of stage 2. This macros ensures
//! that symbols are properly exposed and can be picked up by stage 1. Stage 2 get access to the
//! statics trough the manifest, which will contain a single mutable reference to those static,
//! therefore creating a safe wrapper around mutable statics.
//!
//! Important: To add a new statics, there are three steps:
//! 1. Add a new static in this file within the `make_static` macro.
//! 2. Add the name of the static in the `find_statics` macro withing the second stage ABI crate.
//! 3. Add the name of the symbol preceeded by `__` at the top of the linker script (next to other
//!    symbols). The linker script is called `second-stage-linker-script.x` and is located at the
//!    root of the repository.

use crate::allocator::{Page, PAGE_SIZE};
use crate::arena::Handle;
use crate::hypercalls::{Domain, Region, RegionCapability};
use stage_two_abi::make_static;

// ————————————————————— Static Resources Configuration ————————————————————— //

pub const NB_PAGES: usize = 40;
pub const NB_DOMAINS: usize = 16;
pub const NB_REGIONS: usize = 64;
pub const NB_REGIONS_PER_DOMAIN: usize = 16;

// —————————————————————— Static Resources Declaration —————————————————————— //

const EMPTY_PAGE: Page = Page {
    data: [0; PAGE_SIZE as usize],
};

const EMPTY_REGION_CAPABILITY: RegionCapability = RegionCapability {
    do_own: false,
    is_shared: false,
    is_valid: false,
    handle: Handle::new_unchecked(0),
};

const EMPTY_DOMAIN: Domain = Domain {
    sealed: false,
    regions: [EMPTY_REGION_CAPABILITY; NB_REGIONS_PER_DOMAIN],
};

const EMPTY_REGION: Region = Region {
    ref_count: 0,
    start: 0,
    end: 0,
};

make_static! {
    static mut pages: [Page; NB_PAGES] = [EMPTY_PAGE; NB_PAGES];
    static mut current_domain: Handle<Domain> = Handle::new_unchecked(0);
    static mut domains_arena: [Domain; NB_DOMAINS] = [EMPTY_DOMAIN; NB_DOMAINS];
    static mut regions_arena: [Region; NB_REGIONS] = [EMPTY_REGION; NB_REGIONS];
}
