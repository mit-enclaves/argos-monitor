//! Second Stage ABI
//!
//! This crate defines the ABI used to bootstrap the second stage, it is intended to be consumed by
//! both the first and second stage so that they agree on a common ABI.

#![no_std]

// —————————————————————————————— Entry Point ——————————————————————————————— //

/// Signature of the second stage entry point.
pub type EntryPoint = extern "C" fn() -> !;

/// A transparent wrapper for the entry point which enables type-checking between the first and
/// second stage.
#[macro_export]
macro_rules! entry_point {
    ($path:path) => {
        #[no_mangle]
        pub extern "C" fn _start() -> ! {
            // Validate the signature of the entry point.
            let f: fn() -> ! = $path;
            f();
        }
    };
}

// ———————————————————————————————— Manifest ———————————————————————————————— //

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
    /// Optionnal address of the I/O MMU. Absent if set to 0.
    pub iommu: u64,
}

impl Manifest {
    /// Find the symbol corresponding to the manifest and fill up the references to other
    /// static objects.
    ///
    /// SAFETY: This function must be called only once and rely on the correctness of the
    /// symbol finder.
    pub unsafe fn from_symbol_finder<F>(find_symbol: F) -> Option<&'static mut Self>
    where
        F: Fn(&str) -> Option<usize>,
    {
        // Find manifest
        let manifest = find_symbol("__manifest")? as usize;
        let manifest = &mut *(manifest as *mut Manifest);

        Some(manifest)
    }
}

// ———————————————————————————————— Statics ————————————————————————————————— //

/// Create a static manifest symbol with a well known symbol name ("__manifest").
///
/// The manifest can be retrieved with as a `&'static mut` (only once) using the `get_manifest`
/// function.
#[macro_export]
macro_rules! make_manifest {
    () => {
        pub fn get_manifest() -> &'static mut $crate::Manifest {
            use core::sync::atomic::{AtomicBool, Ordering};

            // Crearte the manifest
            #[used]
            #[export_name = "__manifest"]
            static mut __MANIFEST: $crate::Manifest = $crate::Manifest {
                cr3: 0,
                poffset: 0,
                voffset: 0,
                info: $crate::GuestInfo::default_config(),
                iommu: 0,
            };
            static mut TAKEN: AtomicBool = AtomicBool::new(false);

            /// SAFETY: We return the manifest only once. This is ensured using an atomic boolean
            /// that we set to true the first time the reference is taken.
            unsafe {
                TAKEN
                    .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                    .expect("The manifest can only be retrieved once");
                &mut __MANIFEST
            }
        }
    };
}

// ——————————————————————————————— Guest Info ——————————————————————————————— //

/// GuestInfo passed from stage 1 to stage 2.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct GuestInfo {
    // Guest information.
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
    // Guest is loaded
    pub loaded: bool,
}

impl GuestInfo {
    pub const fn default_config() -> Self {
        GuestInfo {
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
            loaded: false,
        }
    }
}
