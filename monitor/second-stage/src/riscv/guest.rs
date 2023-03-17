//! Risc-V guest

use core::arch::asm;

use riscv_csrs::mstatus;

use crate::println;

pub fn launch_guest(hartid: u64, arg1: u64, next_addr: u64, next_mode: u64) {
    // 0. TODO: Sanity check for next_mode and misa-extension.

    println!("============= Launching Linux from Tyche =============");

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
