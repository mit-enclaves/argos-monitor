//! # Statically allocated structures
//!
//! We use a `make_manifest` macro to define the manifest used by stage 2. This macros ensures
//! that manifest symbols is properly exposed and can be picked up by stage 1.
//! Mutable statics are also defined here, and made accessible through safe helper functions using
//! the `make_static!` macro. The helper function owns an atomic boolean that is set the first time
//! the function is called, and panic on following calls. This ensures we don"t emit more than one
//! mutable reference with static lifetime.

use arena::TypedArena;
#[cfg(target_arch = "riscv64")]
use capabilities::backend;
use capabilities::memory::{EMPTY_MEMORY_REGION, EMPTY_MEMORY_REGION_CAPA};
use capabilities::{OPool, CAPA_POOL_SIZE, CPU_POOL_SIZE, DOMAIN_POOL_SIZE, MEMORY_POOL_SIZE};
use stage_two_abi::make_manifest;

use crate::allocator::{FreeListAllocator, Page, PAGE_SIZE};
#[cfg(target_arch = "x86_64")]
use crate::x86_64::backend;

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

//type Arch = crate::arch::Arch;

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
                static TAKEN: AtomicBool = AtomicBool::new(false);

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
}

#[cfg(target_arch = "x86_64")]
make_static! {
    static mut pool: OPool<backend::BackendX86> = OPool {
        domains: TypedArena::new([backend::EMPTY_DOMAIN; DOMAIN_POOL_SIZE]),
        domain_capas: TypedArena::new([backend::EMPTY_DOMAIN_CAPA; CAPA_POOL_SIZE]),
        regions: TypedArena::new([EMPTY_MEMORY_REGION; MEMORY_POOL_SIZE]),
        region_capas: TypedArena::new([EMPTY_MEMORY_REGION_CAPA; CAPA_POOL_SIZE]),
        cpus: TypedArena::new([backend::EMPTY_CPU; CPU_POOL_SIZE]),
        cpu_capas: TypedArena::new([backend::EMPTY_CPU_CAPA; CAPA_POOL_SIZE]),
    };
}

#[cfg(target_arch = "risc64")]
make_static! {
    static mut pool: OPool<NoBackend> = OPool {
        domains: TypedArena::new([backend::EMPTY_DOMAIN; DOMAIN_POOL_SIZE]),
        domain_capas: TypedArena::new([backend::EMPTY_DOMAIN_CAPA; CAPA_POOL_SIZE]),
        regions: TypedArena::new([EMPTY_MEMORY_REGION; MEMORY_POOL_SIZE]),
        region_capas: TypedArena::new([EMPTY_MEMORY_REGION_CAPA; CAPA_POOL_SIZE]),
        cpus: TypedArena::new([backend::EMPTY_CPU_CAPA; CPU_POOL_SIZE]),
        cpu_capas: TypedArena::new([backend::EMPTY_CPU_CAPA; CAPA_POOL_SIZE]),
    };
}

make_manifest!();
