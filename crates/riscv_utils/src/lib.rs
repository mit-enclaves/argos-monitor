#![no_std]

use core::arch::asm; 

//uart base address
pub const SERIAL_PORT_BASE_ADDRESS: usize = 0x1000_0000;

pub const PAGING_MODE_SV48: usize = 0x9000000000000000;

#[derive(Copy, Clone, Debug)]
pub struct RegisterState {
    pub ra: usize,
    pub a0: usize,
    pub a1: usize,
    pub a2: usize,
    pub a3: usize,
    pub a4: usize,
    pub a5: usize,
    pub a6: usize,
    pub a7: usize,
    pub t0: usize,
    pub t1: usize,
    pub t2: usize,
    pub t3: usize,
    pub t4: usize,
    pub t5: usize,
    pub t6: usize,
    pub zero: usize,
    pub gp: usize,
    pub tp: usize,
    pub s0: usize,
    pub s1: usize,
    pub s2: usize,
    pub s3: usize,
    pub s4: usize,
    pub s5: usize,
    pub s6: usize,
    pub s7: usize,
    pub s8: usize,
    pub s9: usize,
    pub s10: usize,
    pub s11: usize,
    //pub mepc: usize,
    //pub mstatus: usize,
}

impl RegisterState {
    pub const fn const_default() -> RegisterState {
        RegisterState {
            ra: 0,
            a0: 0,
            a1: 0,
            a2: 0,
            a3: 0,
            a4: 0,
            a5: 0,
            a6: 0,
            a7: 0,
            t0: 0,
            t1: 0,
            t2: 0,
            t3: 0,
            t4: 0,
            t5: 0,
            t6: 0,
            zero: 0,
            tp: 0,
            gp: 0,
            s0: 0,
            s1: 0,
            s2: 0,
            s3: 0,
            s4: 0,
            s5: 0,
            s6: 0,
            s7: 0,
            s8: 0,
            s9: 0,
            s10: 0,
            s11: 0,
        }
    }
}

pub fn read_mscratch() -> usize {
    let mut mscratch: usize = 0; 

    unsafe { 
        asm!("csrr {}, mscratch", out(reg) mscratch);
    }

    return mscratch; 
}

pub fn write_mscratch(mscratch: usize) {
    unsafe { 
        asm!("csrw mscratch, {}", in(reg) mscratch);
    }
}

pub fn read_mepc() -> usize {
    let mut mepc: usize = 0; 

    unsafe { 
        asm!("csrr {}, mepc", out(reg) mepc); 
    }

    return mepc; 
}

pub fn write_mepc(mepc: usize) {
    unsafe { 
        asm!("csrw mepc, {}", in(reg) mepc);
    }
}

pub fn read_satp() -> usize {
    let mut satp: usize = 0; 

    unsafe { 
        asm!("csrr {}, satp", out(reg) satp); 
    }

    return satp; 
}

pub fn write_satp(satp: usize) {
    unsafe { 
        asm!("csrw satp, {}", in(reg) satp);
        asm!("sfence.vma");
    }
}

pub fn write_ra(ra: usize) {
    unsafe {
        asm!("mv ra, {}", in(reg) ra);
    }
}

pub fn write_sp(sp: usize) {
    unsafe {
        asm!("mv sp, {}", in(reg) sp);
    }
}

pub fn clear_mstatus_xie() {
    unsafe {
        asm!(
            "li t0, 0xa",
            "not t1, t0",
            "csrr t2, mstatus",
            "and t2, t2, t1",
            "csrw mstatus, t2",
        //asm!("csrrci t0, mstatus, 0x2");
            //"clear_sie: 
             //"csrrci t0, mstatus, 0x2"
             //bnez t0, clear_sie",
             //options(nostack)
        );
    }
}

pub fn clear_mstatus_spie() {
    unsafe {
        asm!(
            "li t0, 0x20",
            "not t1, t0",
            "csrr t2, mstatus",
            "and t2, t2, t1",
            "csrw mstatus, t2",
            );
    }
}

pub fn clear_mideleg() {
    unsafe {
        asm!( 
            "li t0, 0",
            "csrw mideleg, t0",
        );
    }
}

pub fn disable_supervisor_interrupts() {
    unsafe {
        asm!(
            "li t0, 0x222",
            "not t1, t0",
            "csrr t2, mie",
            "and t2, t2, t1",
            "csrw mie, t2",
            //"csrci mie, 0x2",
            //"li t0, 0x20",
            //"csrrci t0, mie, t0",
            //"li t0, 0x200",
            //"csrrci t0, mie, t0",
        );
    }
}

pub fn clear_medeleg() {
    unsafe { 
        asm!(
            "li t0, 0",
            "csrw medeleg, t0",
        );
    }
}

pub fn read_medeleg() -> usize {
    let mut medeleg: usize = 0; 

    unsafe { 
        asm!("csrr {}, medeleg", out(reg) medeleg); 
    }

    return medeleg; 
}

pub fn write_medeleg(medeleg: usize) {
    unsafe { 
        asm!("csrw medeleg, {}", in(reg) medeleg);
    }
}

