#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use second_stage;
use second_stage::arch::launch_guest;
use second_stage::debug::qemu;
use second_stage::statics::get_manifest;
use second_stage::{arch, println};
use stage_two_abi::{entry_point, Manifest};

entry_point!(second_stage_entry_point);

const FALSE: AtomicBool = AtomicBool::new(false);
static BSP_READY: AtomicBool = FALSE;
static CPU_STATUS: [AtomicBool; 256] = [FALSE; 256];
static NB_BOOTED_CORES: AtomicUsize = AtomicUsize::new(0);
static mut MANIFEST: Option<&'static Manifest> = None;

#[cfg(target_arch = "x86_64")]
fn second_stage_entry_point() -> ! {
    if arch::cpuid() == 0 {
        println!("CPU{}: Hello from second stage!", arch::cpuid());
        // Safety: The BSP is responsible for retrieving the manifest
        let manifest = unsafe {
            MANIFEST = Some(get_manifest());
            MANIFEST.as_ref().unwrap()
        };
        second_stage::init(manifest, 0);
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
        println!("CPU{}: Hello from second stage!", arch::cpuid());

        // SAFETY: we only perform read accesses and we ensure the BSP initialized the manifest.
        let manifest = unsafe {
            assert!(!MANIFEST.is_none());
            MANIFEST.as_ref().unwrap()
        };

        second_stage::init(manifest, arch::cpuid());

        // Wait until the BSP mark second stage as initialized (e.g. all APs are up).
        NB_BOOTED_CORES.fetch_add(1, Ordering::SeqCst);
        while !BSP_READY.load(Ordering::SeqCst) {
            core::hint::spin_loop();
        }

        println!("CPU{}: Hello from second stage!", arch::cpuid());

        CPU_STATUS[arch::cpuid()].store(true, Ordering::SeqCst);

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

#[cfg(target_arch = "riscv64")]
fn second_stage_entry_point(hartid: u64, arg1: u64, next_addr: u64, next_mode: u64) -> ! {

    second_stage::init();

    println!("============= Second Stage =============");
    println!("Hello from second stage!");

    //TODO: Change function name to be arch independent. Not launching guest in RV.
    launch_guest(hartid, arg1, next_addr, next_mode);
    qemu::exit(qemu::ExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("CPU {}: Panicked", arch::cpuid());
    println!("{:#?}", info);
    qemu::exit(qemu::ExitCode::Failure);
}
