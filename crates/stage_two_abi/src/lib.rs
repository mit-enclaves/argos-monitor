//! Second Stage ABI
//!
//! This crate defines the ABI used to bootstrap the second stage, it is intended to be consumed by
//! both the first and second stage so that they agree on a common ABI.
#![no_std]

// —————————————————————————————— Entry Point ——————————————————————————————— //

/// Signature of the second stage entry point.
pub type EntryPoint = extern "C" fn(&'static Manifest) -> !;

/// A transparent wrapper for the entry point which enables type-checking between the first and
/// second stage.
#[macro_export]
macro_rules! entry_point {
    ($path:path) => {
        #[cfg(not(test))]
        #[no_mangle]
        pub extern "C" fn _start(manifest: &'static Manifest) -> ! {
            // Validate the signature of the entry point.
            let f: $crate::EntryPoint = $path;
            f(manifest);
        }
    };
}

// ———————————————————————————————— Manifest ———————————————————————————————— //

/// The symbol name of the second stage static manifest.
pub static MANIFEST_SYMBOL: &'static str = "__second_stage_manifest";

/// The second stage manifest, describing the state of the system at the time the second stage is
/// entered.
#[repr(C)]
pub struct Manifest {
    /// The root of the page tables for stage 2.
    pub cr3: u64,
    /// Physical offset of stage 2.
    pub poffset: u64,
    /// Virtual offset of stage 2.
    pub voffset: u64,
    pub info: GuestInfo,
}

/// Defines a static manifest and corresponding symbol to be filled-up by the first stage.
#[macro_export]
macro_rules! add_manifest {
    () => {
        #[doc(hidden)]
        #[used]
        #[export_name = "__second_stage_manifest"]
        pub static __MANIFEST: Manifest = Manifest {
            cr3: 0,
            poffset: 0,
            voffset: 0,
            info: GuestInfo::default_config(),
        };
    };
}

/// GuestInfo passed from stage 1 to stage 2.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct GuestInfo {
    // Guest information.
    pub ept_root: usize,
    pub cr3: usize,
    pub rip: usize,
    pub rsp: usize,
    pub rsi: usize,
    // Host segments.
    pub cs: u16,
    pub ds: u16,
    pub es: u16,
    pub fs: u16,
    pub gs: u16,
    pub ss: u16,
    pub efer: u64,
}

impl GuestInfo {
    pub const fn default_config() -> Self {
        GuestInfo {
            ept_root: 0,
            cr3: 0,
            rip: 0,
            rsp: 0,
            rsi: 0,
            cs: 0,
            ds: 0,
            es: 0,
            fs: 0,
            gs: 0,
            ss: 0,
            efer: 0,
        }
    }
}
