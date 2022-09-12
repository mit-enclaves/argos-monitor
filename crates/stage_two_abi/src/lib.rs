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
        };
    };
}
