#![no_std]
#![no_main]

use core::panic::PanicInfo;
use second_stage;
use second_stage::allocator::BumpAllocator;
use second_stage::arch::guest::launch_guest;
use second_stage::arch::Arch;
use second_stage::debug::qemu;
use second_stage::hypercalls::Hypercalls;
use second_stage::println;
use second_stage::statics::Statics;
use stage_two_abi::{entry_point, Manifest};

entry_point!(second_stage_entry_point, Statics);

pub extern "C" fn second_stage_entry_point(manifest: &'static mut Manifest<Statics>) -> ! {
    println!("============= Second Stage =============");
    println!("Hello from second stage!");
    second_stage::init(manifest);
    println!("Initialization: done");
    let mut statics = manifest
        .statics
        .take()
        .expect("Missing statics in manifest");
    let mut allocator = BumpAllocator::new(
        manifest.poffset,
        manifest.voffset,
        statics.pages.take().expect("No pages in statics"),
    );
    let arch = Arch::new(manifest.iommu);
    let mut hypercalls = Hypercalls::new(&mut statics, &manifest, arch);
    manifest.info.ept_root = hypercalls.set_root_ept(&mut allocator, manifest.poffset as usize);
    launch_guest(&mut allocator, &manifest.info, hypercalls);
    // Exit
    qemu::exit(qemu::ExitCode::Success);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    qemu::exit(qemu::ExitCode::Failure);
}
