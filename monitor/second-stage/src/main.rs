#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use second_stage;
use second_stage::arch::guest::launch_guest;
use second_stage::debug::qemu;
use second_stage::statics::get_manifest;
use second_stage::{arch, println};
use stage_two_abi::{entry_point, Manifest};

entry_point!(second_stage_entry_point);

static BSP_READY: AtomicBool = AtomicBool::new(false);
static mut MANIFEST: Option<&'static Manifest> = None;

fn second_stage_entry_point() -> ! {
    if arch::cpuid() == 0 {
        // Safety: The BSP is responsible for retrieving the manifest
        unsafe {
            MANIFEST = Some(get_manifest());
            second_stage::init(MANIFEST.as_ref().unwrap());
            BSP_READY.store(true, Ordering::SeqCst);
        }
    }
    // The APs spin until the manifest is fetched, and then initialize the second stage
    else {
        while !BSP_READY.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }
        // SAFETY: we only perform read accesses and we ensure the BSP initialized the manifest.
        unsafe {
            assert!(!MANIFEST.is_none());
            second_stage::init(MANIFEST.as_ref().unwrap());
        }
    }
    println!("CPU{}: Hello from second stage!", arch::cpuid());

    // Launch guest and exit
    unsafe {
        launch_guest(MANIFEST.as_mut().unwrap());
    }
    qemu::exit(qemu::ExitCode::Success);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    qemu::exit(qemu::ExitCode::Failure);
}
