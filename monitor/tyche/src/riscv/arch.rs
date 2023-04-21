//! Architecture specific structures

use core::arch::asm;

use riscv_csrs::*;
use riscv_pmp::pmpaddr_write;
use riscv_sbi::trap::*;
use riscv_sbi::*;
use riscv_tyche::*;
use riscv_utils::*;

use crate::println;

pub fn init() {
    //Configuring PMP to protect the monitor's memory.
    //Writing only pmpaddr for now, pmpcfg is already configured with the correct permissions and
    //addressing mode. TODO: Update this to pmp_set once it is implemented.
    println!(
        "Protecting Tyche Region in PMP with pmpaddr value: {:x}",
        pmpaddr_write(TYCHE_START_ADDRESS, TYCHE_SIZE_NAPOT)
    );

    //Making sure that ecalls from user mode trap into Tyche.
    //println!("Updating medeleg");
    //write_medeleg(ECALL_FROM_UMODE, 0);

    unsafe {
        asm!("csrw mscratch, {}", in(reg) TYCHE_STACK_POINTER);
    }

    //Configuring mtvec direct base address to point to Tyche's trap handler.
    let mtvec_ptr = machine_trap_handler as *const ();
    println!("mtvec_ptr to be set by Tyche {:p}", mtvec_ptr);
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

    println!("Updated mtvec {:x}", mtvec);
}

pub fn write_medeleg(pos: usize, value: usize) {
    let mut medeleg: usize;
    unsafe {
        asm!("csrr {}, medeleg", out(reg) medeleg);
    }

    println!("Medeleg set by OpenSBI {:x}", medeleg);

    //update the value at position pos.
    medeleg &= (!(1 << pos) | (value << pos));

    println!("Medeleg to be set by Tyche {:x}", medeleg);

    unsafe {
        asm!("csrw medeleg, {}", in(reg) medeleg);
    }

    unsafe {
        asm!("csrr {}, medeleg", out(reg) medeleg);
    }

    println!("Medeleg set by Tyche {:x}", medeleg);
}
