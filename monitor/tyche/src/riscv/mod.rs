//! Risc-V backend

// TODO: remove this once the backend is implemented.
// The line just removes the unused warnings.
#![allow(unused)]

mod arch;
pub mod guest;
mod monitor;
mod init; 

use core::arch::asm;

use mmu::FrameAllocator;

pub use init::arch_entry_point;

use riscv_csrs::mstatus;

use crate::debug::qemu::ExitCode;
use crate::println;

// TODO: some empty types to be filled.
#[derive(Debug)]
pub enum BackendError {}

// launch the initial domain.
pub fn launch_guest(hartid: u64, arg1: u64, next_addr: u64, next_mode: u64) {
    // 0. TODO: Sanity check for next_mode and misa-extension.

    println!("============= Launching Linux from Tyche =============");
    println!("========= ARGS to Linux: {:x} {:x} {:x} {:x} ========", hartid, arg1, next_addr, next_mode);

    // 1. Update MSTATUS - MPP=01 (S-mode), and MPIE = 0.
    let mut mstatus: usize;
    let zero: usize = 0;
    unsafe {
        asm!("csrr {}, mstatus", out(reg) mstatus);
    }
    //clear MPP
    mstatus = mstatus & !(mstatus::MPP_MASK << mstatus::MPP_LOW);
    //set MPP = 01 i.e. S-mode
    mstatus |= 1 << mstatus::MPP_LOW;

    //reset mpie
    mstatus = mstatus & !(1 << mstatus::MPIE);

    //write updated mstatus
    unsafe {
        asm!("csrw mstatus, {}", in(reg) mstatus);
    }

    // 2. Update MEPC to next_addr
    //mepc::write(next_addr);
    unsafe {
        asm!("csrw mepc, {}",
         in(reg) next_addr,);
    }

    // 3. Update S-mode registers - stvec = next_addr, sscratch = 0, sie = 0, satp = 0
    //stvec::write(next_addr);
    unsafe {
        asm!("csrw stvec, {}",
         in(reg) next_addr,);
        asm!("csrw sscratch, {}",
         in(reg) zero,);
        asm!("csrw sie, {}",
         in(reg) zero,);
        asm!("csrw satp, {}",
         in(reg) zero,);

        // 4. writing args to a0 and a1
        asm!("mv a0, {}",
         in(reg) hartid,);
        asm!("mv a1, {}",
         in(reg) arg1,);

        // 5. mret
        asm!("mret", options(noreturn));
    }
}

/// Halt the CPU in a spinloop;
pub fn hlt() -> ! {
    loop {
        // See core::arch::asm::riscv64:
        //
        // The PAUSE instruction is a HINT that indicates the current hart's rate of instruction retirement
        // should be temporarily reduced or paused. The duration of its effect must be bounded and may be zero.
        unsafe { asm!(".insn i 0x0F, 0, x0, x0, 0x010", options(nomem, nostack)) }
    }
}

pub fn exit_qemu(exit_code: ExitCode) {
    // TODO: find exit address
    const RISCV_EXIT_ADDR: u64 = 0xdeadbeef;

    unsafe {
        let exit_code = exit_code as u32;
        asm!(
            "sw {0}, 0({1})",
            in(reg) exit_code,
            in(reg) RISCV_EXIT_ADDR
        );
    }
}

/// Architecture specific initialization.
pub fn init() {
    arch::init();
}

pub fn cpuid() -> usize {
    todo!();
}
