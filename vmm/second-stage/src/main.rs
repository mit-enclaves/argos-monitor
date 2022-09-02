#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[no_mangle]
fn second_stage_entry_point() {}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}
