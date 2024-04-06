//! Architecture specific structures

use core::arch::asm;

use riscv_csrs::*;
use riscv_sbi::*;
use riscv_tyche::*;
use riscv_utils::*;

use crate::println;
use crate::riscv::guest::machine_trap_handler;

#[cfg(not(feature = "visionfive2"))]
pub fn init(hartid: usize) {
    unsafe {
        asm!("csrw mscratch, {}", in(reg) TYCHE_STACK_POINTER[hartid]);
    }

    clear_mstatus_sie();
    set_mstatus_mie();
    // Configuring mtvec direct base address to point to Tyche's trap handler.
    let mtvec_ptr = machine_trap_handler as *const ();
    log::info!("mtvec_ptr to be set by Tyche {:p}", mtvec_ptr);
    set_mtvec(mtvec_ptr);
}

//Todo: Keeping it separate for vf2 for now, since I add a lot of debug logs. 
//But this can easily be code common to all RV platforms by picking the appropriate stack pointers in the background. 
#[cfg(feature = "visionfive2")]
pub fn init(hartid: usize) {

    //let mut medeleg: usize;
    unsafe {
        asm!("csrw mscratch, {}", in(reg) VF2_TYCHE_STACK_POINTER[hartid]);
    }

    let mut mideleg: usize;
    unsafe {
        asm!("csrr {}, mideleg", out(reg) mideleg);
    }
    
    mideleg = mideleg & !(0x200);

    unsafe {
        asm!("csrw mideleg, {}", in(reg) mideleg);
    }


    /* let mip: usize; 
    unsafe {
        asm!("csrr {}, mip", out(reg) mip);
    }

    let toggle_seip_mip: usize;
    toggle_seip_mip = (mip ^ 0x200);

    unsafe {
        asm!("csrw mip, {}",in(reg) toggle_seip_mip);
    }

    let new_mip: usize; 
    unsafe {
        asm!("csrr {}, mip", out(reg) new_mip);
    } 

    if (new_mip & 0x200) == (mip & 0x200) {
        panic!("MIP.SEIP didn't change. MIP: {:x} TOGGLED: {:x} UPDATED: {:x}",mip, toggle_seip_mip, new_mip);
    }

    //Write back the original value.
    unsafe {
        asm!("csrw mip, {}",in(reg) mip);
    } */


    //Neelu: Enabling TW so wfi results into illegal instr - for debugging purposes.
    /* let mut mstatus: usize;
    unsafe {
        asm!("csrr {}, mstatus", out(reg) mstatus);
    }
    mstatus |= (1 << 21);
    unsafe {
        asm!("csrw mstatus, {}", in(reg) mstatus);
    } */

    /* let mtimer: usize;
    unsafe {
        asm!("ld {}, 0({})", out(reg) mtimer, in(reg) ACLINT_MTIMER_VALUE_ADDRESS);
    }
    println!("Mtimer value read: {:x}",mtimer); */
    //aclint_mtimer_set_mtimecmp(hartid, 0x42fc3c1); //I just selected a random value sampled from
                                                    //some interrupts.  

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
