//! # Statically allocated structures
//!
//! We use a `make_manifest` macro to define the manifest used by stage 2. This macros ensures
//! that manifest symbols is properly exposed and can be picked up by stage 1.
//! Mutable statics are also defined here, and made accessible through safe helper functions using
//! the `make_static!` macro. The helper function owns an atomic boolean that is set the first time
//! the function is called, and panic on following calls. This ensures we don"t emit more than one
//! mutable reference with static lifetime.

use crate::allocator::{FreeListAllocator, Page, PAGE_SIZE};
use crate::arena::{Handle, TypedArena};
use crate::hypercalls::{access, Backend, Domain, Region, RegionCapability, RevokInfo, Switch};
use stage_two_abi::make_manifest;

// ————————————————————— Static Resources Configuration ————————————————————— //

pub const NB_PAGES: usize = 200;
pub const NB_DOMAINS: usize = 16;
pub const NB_REGIONS: usize = 64;
pub const NB_REGIONS_PER_DOMAIN: usize = 46;
pub const NB_SWITCH_PER_DOMAIN: usize = 10;

// —————————————————————— Static Resources Declaration —————————————————————— //

const EMPTY_PAGE: Page = Page {
    data: [0; PAGE_SIZE as usize],
};

const EMPTY_REGION_CAPABILITY: RegionCapability = RegionCapability {
    is_owned: false,
    is_shared: false,
    is_valid: false,
    access: access::NONE,
    revok: RevokInfo {
        domain: 0,
        handle: 0,
        local_handle: 0,
    },
    handle: Handle::new_unchecked(0),
};

type Arch = crate::arch::Arch;

const EMPTY_SWITCH: Switch<Arch> = Switch {
    is_valid: false,
    domain: 0,
    context: <Arch as Backend>::EMPTY_CONTEXT,
};

const EMPTY_DOMAIN: Domain<Arch> = Domain {
    is_sealed: false,
    is_valid: false,
    regions: TypedArena::new([EMPTY_REGION_CAPABILITY; NB_REGIONS_PER_DOMAIN]),
    nb_initial_regions: 0,
    initial_regions_capa: [Handle::new_unchecked(0); NB_REGIONS_PER_DOMAIN],
    store: <Arch as Backend>::EMPTY_STORE,
    switches: TypedArena::new([EMPTY_SWITCH; NB_SWITCH_PER_DOMAIN]),
};

const EMPTY_REGION: Region = Region {
    ref_count: 0,
    start: 0,
    end: 0,
};

macro_rules! make_static {
    ($(static mut $name:ident : $type:ty = $init:expr;)*) => {
        // Create accessor functions
        $(
            /// Returns a mutable static reference to a global static.
            ///
            /// This function will panic if called twide, ensuring the mutable reference is unique.
            pub(crate) fn $name() -> &'static mut $type {
                use core::sync::atomic::{AtomicBool, Ordering};

                #[allow(non_upper_case_globals)]
                static mut $name: $type = $init;
                static mut TAKEN: AtomicBool = AtomicBool::new(false);

                // SAFETY: We return a static mutable to the static only once. This is ensured by
                // using an atomic boolean that we set to true the first time the reference is
                // taken.
                unsafe {
                    TAKEN.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                        .expect("Statics can be accesses only once");
                    &mut $name
                }
            }
        )*
    };
}

make_static! {
    static mut allocator: FreeListAllocator<NB_PAGES> =
        FreeListAllocator::new([EMPTY_PAGE; NB_PAGES]);
    static mut domains_arena: TypedArena<Domain<Arch>, NB_DOMAINS> =
        TypedArena::new([EMPTY_DOMAIN; NB_DOMAINS]);
    static mut regions_arena: TypedArena<Region, NB_REGIONS> =
        TypedArena::new([EMPTY_REGION; NB_REGIONS]);
}

make_manifest!();
