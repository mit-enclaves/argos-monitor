#![no_std]
#![no_main]

use core::panic::PanicInfo;
use second_stage;
use second_stage::debug::qemu;
use second_stage::{hlt, println};
use stage_two_abi::{entry_point, add_manifest, Manifest};

entry_point!(second_stage_entry_point);
add_manifest!();

pub extern "C" fn second_stage_entry_point(manifest: &'static Manifest) -> ! {
    second_stage::init();
    println!("============= Second Stage =============");
    println!("Hello from second stage!");
    println!("Manifest CR3: 0x{:x}", manifest.cr3);

    // Exit
    qemu::exit(qemu::ExitCode::Success);
    hlt();
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    qemu::exit(qemu::ExitCode::Failure);
    hlt();
}
