#![no_std]
//RISC-V PMP Configuration.

use core::arch::asm;

pub const PMP_SHIFT: usize = 2; //Neelu: TODO: Rename this. used in pmpaddr_write.

pub fn pmpaddr_write(addr: usize, log2len: usize) -> usize {
    let addrmask: usize;
    let mut pmpaddr: usize;

    if log2len == PMP_SHIFT {
        pmpaddr = addr >> PMP_SHIFT;
    } else {
        // TODO: Define __riscv_xlen
        // if log2len == __riscv_xlen {
        //       pmpaddr = -1;
        // } else {
        addrmask = (1usize << (log2len - PMP_SHIFT)) - 1;
        pmpaddr = (addr >> PMP_SHIFT) & !addrmask;
        pmpaddr |= addrmask >> 1;
        // }
    }

    //TODO: Write pmpaddr"index" instead of 1 in the following code while making it generic.
    unsafe {
        asm!("csrw pmpaddr1, {}", in(reg) pmpaddr);
    }

    return pmpaddr;
}
