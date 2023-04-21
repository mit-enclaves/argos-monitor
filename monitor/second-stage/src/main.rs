#![no_std]
#![no_main]

use core::panic::PanicInfo;

use log::LevelFilter;
use second_stage;
use second_stage::debug::qemu;
use second_stage::{arch, println, logging};
use stage_two_abi::entry_point;

entry_point!(second_stage_entry_point);

const LOG_LEVEL: LevelFilter = LevelFilter::Trace;

#[cfg(target_arch = "x86_64")]
fn second_stage_entry_point() -> ! {
    logging::init(LOG_LEVEL);
    arch::arch_entry_point();
}

#[cfg(target_arch = "riscv64")]
fn second_stage_entry_point(hartid: u64, arg1: u64, next_addr: u64, next_mode: u64) -> ! {
    logging::init(LOG_LEVEL);
    second_stage::init();

    println!("============= Second Stage =============");
    println!("Hello from second stage!");

    //TODO: Change function name to be arch independent. Not launching guest in RV.
    arch::launch_guest(hartid, arg1, next_addr, next_mode);
    qemu::exit(qemu::ExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("CPU {}: Panicked", arch::cpuid());
    println!("{:#?}", info);
    qemu::exit(qemu::ExitCode::Failure);
}
