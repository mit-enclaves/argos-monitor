//! Second Stage ABI
//!
//! This crate defines the ABI used to bootstrap the second stage, it is intended to be consumed by
//! both the first and second stage so that they agree on a common ABI.
#![no_std]

// —————————————————————————————— Entry Point ——————————————————————————————— //

/// Signature of the second stage entry point.
pub type EntryPoint<S> = extern "C" fn(&'static mut Manifest<S>) -> !;

/// A transparent wrapper for the entry point which enables type-checking between the first and
/// second stage.
#[macro_export]
macro_rules! entry_point {
    ($path:path, $statics:ty) => {
        #[no_mangle]
        pub extern "C" fn _start(manifest: &'static mut Manifest<$statics>) -> ! {
            // Validate the signature of the entry point.
            let f: $crate::EntryPoint<$statics> = $path;
            f(manifest);
        }
    };
}

// ———————————————————————————————— Manifest ———————————————————————————————— //

/// The second stage manifest, describing the state of the system at the time the second stage is
/// entered.
#[repr(C)]
pub struct Manifest<S: 'static> {
    /// The root of the page tables for stage 2.
    pub cr3: u64,
    /// Physical offset of stage 2.
    pub poffset: u64,
    /// Virtual offset of stage 2.
    pub voffset: u64,
    pub info: GuestInfo,
    pub statics: Option<&'static mut S>,
}

// ———————————————————————————————— Statics ————————————————————————————————— //

/// Creates a RawStatics struct from a list of static symbols, and creates an helper method to
/// pupulate that struct from a symbol reader.
macro_rules! find_statics {
    ($($name:ident $(,)?)*) => {
        pub struct RawStatics {
            $(pub $name: usize,)*
        }

        impl RawStatics {
            pub fn from_symbol_finder<F>(find_symbol: F) -> Option<Self>
            where F: Fn(&str) -> Option<usize> {
                Some(RawStatics {
                    $($name: find_symbol(core::concat!("__", core::stringify!($name)))?,)*
                })
            }
        }

        impl Manifest<RawStatics> {
            /// Find the symbol corresponding to the manifest and fill up the references to other
            /// static objects.
            ///
            /// SAFETY: This function must be called only once and rely on the correctness of the
            /// symbol finder.
            pub unsafe fn from_symbol_finder<F>(find_symbol: F) -> Option<&'static mut Self>
            where F: Fn(&str) -> Option<usize> {
                // Find and fill statics
                let statics = find_symbol("__statics")? as usize;
                let statics = &mut *(statics as *mut RawStatics);
                $(
                    statics.$name = find_symbol(core::concat!("__", core::stringify!($name)))?;
                )*

                // Find manifest
                let manifest = find_symbol("__manifest")? as usize;
                let manifest = &mut *(manifest as *mut Manifest<RawStatics>);
                manifest.statics = Some(statics);

                Some(manifest)
            }
        }
    };
}

find_statics!(pages, current_domain, domains_arena, regions_arena);

/// Crate static symbols using a familiar static declaration statement.
/// A `Statics` struct and a manifest are created and are expected to be populated by stage 1.
#[macro_export]
macro_rules! make_static {
    ($(static mut $name:ident : $type:ty = $init:expr;)*) => {
        // Create a structure listing the static items
        pub struct Statics {
            $(pub $name: Option<&'static mut $type>,)*
        }

        // Create the static items
        $(
            #[allow(non_upper_case_globals)]
            #[doc(hidden)]
            #[used]
            #[export_name = core::concat!("__", core::stringify!($name))]
            pub static mut $name: $type = $init;
        )*

        // Crearte the manifest
        #[doc(hidden)]
        #[used]
        #[export_name = "__manifest"]
        pub static mut __MANIFEST: $crate::Manifest::<Statics> = $crate::Manifest::<Statics> {
            cr3: 0,
            poffset: 0,
            voffset: 0,
            info: $crate::GuestInfo::default_config(),

            // The reference will be patched by stage 1
            statics: None,
        };

        // Create the list of statics
        #[doc(hidden)]
        #[used]
        #[export_name = "__statics"]
        pub static mut __STATICS: Statics = Statics {
            $($name: None::<&'static mut $type>,)*
        };

        // Check that both statics have the same size at compile time.
        // This will throw a compile error if the sizes doesn't match.
        const __STATIC_SIZE_CHECK: [u8; core::mem::size_of::<$crate::RawStatics>()] =
            [0; core::mem::size_of::<Statics>()];
    };
}

// ——————————————————————————————— Guest Info ——————————————————————————————— //

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
    // Guest is loaded
    pub loaded: bool,
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
            loaded: false,
        }
    }
}
