#![no_std]
#![no_main]

use core::panic::PanicInfo;

use log::LevelFilter;
#[cfg(target_arch = "riscv64")]
use riscv_tyche::RVManifest;
use stage_two_abi::entry_point;
use tyche;
use tyche::debug::qemu;
use tyche::{arch, println};

use core::arch::asm; 

entry_point!(tyche_entry_point);

const LOG_LEVEL: LevelFilter = LevelFilter::Info;

#[cfg(target_arch = "x86_64")]
fn tyche_entry_point() -> ! {
    arch::arch_entry_point(LOG_LEVEL);
}

#[cfg(all(target_arch = "riscv64"), not(feature = "visionfive2"))]
fn tyche_entry_point(hartid: usize, manifest: RVManifest) -> ! {
    arch::arch_entry_point(hartid, manifest, LOG_LEVEL);
}

#[cfg(all(target_arch = "riscv64"), feature = "visionfive2")]
fn tyche_entry_point(hartid: u64, arg1: u64, next_addr: u64, next_mode: u64) -> ! {
    use tyche::riscv::launch_guest;

    unsafe { 
        asm!("ecall");
    }
    //logger::init(LOG_LEVEL);
    //arch::arch_entry_point(hartid, arg1, next_addr, next_mode, LOG_LEVEL);
    launch_guest(hartid, arg1, next_addr, next_mode);
    qemu::exit(qemu::ExitCode::Success); 
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("CPU {}: Panicked", arch::cpuid());
    println!("{:#?}", info);
    qemu::exit(qemu::ExitCode::Failure);
}
