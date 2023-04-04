#![no_std]
#![no_main]

use core::panic::PanicInfo;

use second_stage;
use second_stage::arch::arch_entry_point;
use second_stage::debug::qemu;
use second_stage::{arch, println};
use stage_two_abi::entry_point;

entry_point!(second_stage_entry_point);

#[cfg(target_arch = "x86_64")]
fn second_stage_entry_point() -> ! {
    arch_entry_point();
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
