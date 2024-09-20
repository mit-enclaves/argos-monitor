//! Architecture specific structures

use core::arch::asm;

use riscv_csrs::*;
use riscv_sbi::*;
use riscv_tyche::*;
use riscv_utils::*;

use crate::println;
use crate::riscv::platform::machine_trap_handler;

pub fn init(hartid: usize) {
    unsafe {
        asm!("csrw mscratch, {}", in(reg) TYCHE_STACK_POINTER[hartid]);
    }

    // Configuring mtvec direct base address to point to Tyche's trap handler.
    let mtvec_ptr = machine_trap_handler as *const ();
    log::info!("mtvec_ptr to be set by Tyche {:p}", mtvec_ptr);
    set_mtvec(mtvec_ptr);
}

// ------------------------------ Trap Handler Setup -------------------------- //

pub fn set_mtvec(addr: *const ()) {
    unsafe {
        asm!("csrw mtvec, {}", in(reg) addr);
    }

    let mut mtvec: usize;
    unsafe {
        asm!("csrr {}, mtvec", out(reg) mtvec);
    }

    log::info!("Updated mtvec {:x}", mtvec);
}
