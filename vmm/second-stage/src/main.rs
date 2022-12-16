#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::*;
use second_stage;
use second_stage::arch;
use second_stage::arch::guest::launch_guest;
use second_stage::debug::qemu;
use second_stage::println;
use second_stage::statics::get_manifest;
use stage_two_abi::{entry_point, Manifest};

entry_point!(second_stage_entry_point);

const FALSE: AtomicBool = AtomicBool::new(false);
static BSP_READY: AtomicBool = FALSE;
static CPU_STATUS: [AtomicBool; 256] = [FALSE; 256];
static mut MANIFEST: Option<&'static mut Manifest> = None;

fn second_stage_entry_point() -> ! {
    unsafe {
        // The BSP is responsible for retrieving the manifest
        if arch::cpuid() == 0 {
            MANIFEST = Some(get_manifest());
            second_stage::init(MANIFEST.as_ref().unwrap(), 0);
            BSP_READY.store(true, Ordering::SeqCst);
        }
        // The APs spin until the manifest is fetched, and then initialize the second stage
        else {
            while !BSP_READY.load(Ordering::SeqCst) {
                core::hint::spin_loop();
            }
            assert!(!MANIFEST.is_none());
            second_stage::init(MANIFEST.as_ref().unwrap(), arch::cpuid());
        }
        println!("CPU{}: Hello from second stage!", arch::cpuid());

        CPU_STATUS[arch::cpuid()].store(true, Ordering::SeqCst);

        // Sync barrier to make sure all cores enter 2nd stage
        for i in 0..(MANIFEST.as_ref().unwrap().smp - 1) {
            while !CPU_STATUS[i].load(Ordering::SeqCst) {
                core::hint::spin_loop();
            }
        }

        // Launch guest and exit
        launch_guest(MANIFEST.as_mut().unwrap());
        qemu::exit(qemu::ExitCode::Success);
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("CPU {}: Panicked", arch::cpuid());
    println!("{:?}", info);
    qemu::exit(qemu::ExitCode::Failure);
}
