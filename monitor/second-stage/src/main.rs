#![no_std]
#![no_main]

use core::panic::PanicInfo;

use second_stage;
use second_stage::arch::guest::launch_guest;
use second_stage::debug::qemu;
use second_stage::println;
use second_stage::statics::get_manifest;
use stage_two_abi::entry_point;

entry_point!(second_stage_entry_point);

fn second_stage_entry_point() -> ! {
    let manifest = get_manifest();
    second_stage::init(manifest);

    println!("============= Second Stage =============");
    println!("Hello from second stage!");

    // Launch guest and exit
    launch_guest(manifest);
    qemu::exit(qemu::ExitCode::Success);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    qemu::exit(qemu::ExitCode::Failure);
}
