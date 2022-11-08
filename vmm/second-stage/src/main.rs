#![no_std]
#![no_main]

use core::panic::PanicInfo;
use second_stage;
use second_stage::arch::guest::launch_guest;
use second_stage::arch::Arch;
use second_stage::debug::qemu;
use second_stage::println;
use second_stage::statics::Statics;
use stage_two_abi::{entry_point, Manifest};

entry_point!(second_stage_entry_point, Statics<Arch>);

pub extern "C" fn second_stage_entry_point(manifest: &'static mut Manifest<Statics<Arch>>) -> ! {
    println!("============= Second Stage =============");
    println!("Hello from second stage!");
    second_stage::init(manifest);
    println!("Initialization: done");

    // Launch guest and exit
    launch_guest(manifest);
    qemu::exit(qemu::ExitCode::Success);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    qemu::exit(qemu::ExitCode::Failure);
}
