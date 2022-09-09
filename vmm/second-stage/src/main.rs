#![no_std]
#![no_main]

use core::panic::PanicInfo;
use second_stage;
use second_stage::debug::qemu;
use second_stage::{hlt, println};

#[export_name = "_start"]
pub extern "C" fn second_stage_entry_point() -> ! {
    second_stage::init();
    println!("============= Second Stage =============");
    println!("Hello from second stage!");

    // Exit
    qemu::exit(qemu::ExitCode::Success);
    hlt();
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    qemu::exit(qemu::ExitCode::Failure);
    hlt();
}
