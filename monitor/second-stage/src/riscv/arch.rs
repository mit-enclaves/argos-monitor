//! Architecture specific structures

use core::arch::asm;
use riscv_utils::{SERIAL_PORT_BASE_ADDRESS,PMP_SHIFT,TYCHE_START_ADDRESS,TYCHE_SIZE_NAPOT};
use crate::println;

pub fn init() {
    
    //Configuring PMP to protect the monitor's memory. 
    //Writing only pmpaddr for now, pmpcfg is already configured with the correct permissions and
    //addressing mode. TODO: Update this to pmp_set once it is implemented. 
    println!("Protecting Tyche Region in PMP with pmpaddr value: {}",pmpaddr_write(TYCHE_START_ADDRESS,TYCHE_SIZE_NAPOT));

}

pub fn pmpaddr_write(addr: u64, log2len: u64) -> u64 {
    let addrmask: u64;
    let mut pmpaddr: u64;

    if log2len == PMP_SHIFT {
        pmpaddr = addr >> PMP_SHIFT;
    } else {
        // TODO: Define __riscv_xlen
       // if log2len == __riscv_xlen {
       //       pmpaddr = -1;
       // } else {
       addrmask = (1u64 << (log2len - PMP_SHIFT)) - 1;
       pmpaddr = (addr >> PMP_SHIFT) & !addrmask;
       pmpaddr |= addrmask >> 1;
        // }
    }

    //TODO: Write pmpaddr"index" instead of 1 in the following code.
    unsafe { asm!("csrw pmpaddr1, {}", in(reg) pmpaddr); }

    return pmpaddr;
}
