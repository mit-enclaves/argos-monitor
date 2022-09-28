#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]

#[cfg(not(test))]
use core::panic::PanicInfo;
use second_stage::debug::qemu;
use second_stage::println;
use stage_two_abi::{add_manifest, entry_point, GuestInfo, Manifest};

entry_point!(second_stage_entry_point);
add_manifest!();

pub extern "C" fn second_stage_entry_point(manifest: &'static Manifest) -> ! {
    println!("============= Second Stage =============");
    println!("Hello from second stage!");
    println!("Manifest CR3: 0x{:x}", manifest.cr3);
    second_stage::init(manifest);
    println!("Initialization: done");

    // Exit
    qemu::exit(qemu::ExitCode::Success);
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    qemu::exit(qemu::ExitCode::Failure);
}
