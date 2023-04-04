//! Stage 2 initialization on x86_64

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use stage_two_abi::Manifest;
pub use vmx::VmxError as BackendError;

use super::{arch, cpuid, launch_guest};
use crate::debug::qemu;
use crate::println;
use crate::statics::get_manifest;

// ————————————————————————————— Entry Barrier —————————————————————————————— //

/// APs will wait for the entry barrier to be `true` before jumping into stage 2.
#[used]
#[export_name = "__entry_barrier"]
static ENTRY_BARRIER: AtomicBool = AtomicBool::new(false);

// ————————————————————————————— Initialization ————————————————————————————— //

const FALSE: AtomicBool = AtomicBool::new(false);
static BSP_READY: AtomicBool = FALSE;
static CPU_STATUS: [AtomicBool; 256] = [FALSE; 256];
static NB_BOOTED_CORES: AtomicUsize = AtomicUsize::new(0);
static mut MANIFEST: Option<&'static Manifest> = None;

pub fn arch_entry_point() -> ! {
    if cpuid() == 0 {
        println!("CPU{}: Hello from second stage!", cpuid());
        // Safety: The BSP is responsible for retrieving the manifest
        let manifest = unsafe {
            MANIFEST = Some(get_manifest());
            MANIFEST.as_ref().unwrap()
        };
        init(manifest, 0);
        println!("Waiting for {} cores", manifest.smp);
        while NB_BOOTED_CORES.load(Ordering::SeqCst) + 1 < manifest.smp {
            core::hint::spin_loop();
        }
        println!("Stage 2 initialized");

        // TODO: mark the BSP as ready to launch guest on all APs.
        // BSP_READY.store(true, Ordering::SeqCst);
    }
    // The APs spin until the manifest is fetched, and then initialize the second stage
    else {
        println!("CPU{}: Hello from second stage!", cpuid());

        // SAFETY: we only perform read accesses and we ensure the BSP initialized the manifest.
        let manifest = unsafe {
            assert!(!MANIFEST.is_none());
            MANIFEST.as_ref().unwrap()
        };

        init(manifest, cpuid());

        // Wait until the BSP mark second stage as initialized (e.g. all APs are up).
        NB_BOOTED_CORES.fetch_add(1, Ordering::SeqCst);
        while !BSP_READY.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }

        println!("CPU{}: Hello from second stage!", cpuid());

        CPU_STATUS[cpuid()].store(true, Ordering::SeqCst);

        // Sync barrier to make sure all cores enter 2nd stage
        for i in 0..(manifest.smp - 1) {
            while !CPU_STATUS[i].load(Ordering::SeqCst) {
                core::hint::spin_loop();
            }
        }

        // Launch guest and exit
        launch_guest(manifest);
        qemu::exit(qemu::ExitCode::Success);
    }

    // Launch guest and exit
    unsafe {
        launch_guest(MANIFEST.as_mut().unwrap());
    }
    qemu::exit(qemu::ExitCode::Success);
}

/// Architecture specific initialization.
pub fn init(manifest: &Manifest, cpuid: usize) {
    unsafe {
        asm!(
            "mov cr3, {}",
            in(reg) manifest.cr3,
            options(nomem, nostack, preserves_flags)
        );
        if cpuid == 0 {
            arch::init();
        }
        arch::setup(cpuid);
    }

    // In case we use VGA, setup the VGA driver
    #[cfg(feature = "vga")]
    if manifest.vga.is_valid {
        let framebuffer =
            unsafe { core::slice::from_raw_parts_mut(manifest.vga.framebuffer, manifest.vga.len) };
        let writer = vga::Writer::new(
            framebuffer,
            manifest.vga.h_rez,
            manifest.vga.v_rez,
            manifest.vga.stride,
            manifest.vga.bytes_per_pixel,
        );
        vga::init_print(writer);
    }

    // The ENTRY_BARRIER is consumed (set to false) when an AP enters stage 2, once stage 2
    // initialization is done, the AP set the ENTRY_BARRIER back to true.
    ENTRY_BARRIER
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .expect("Unexpected ENTRY_BARRIER value");
}
