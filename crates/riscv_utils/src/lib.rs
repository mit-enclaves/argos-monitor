#![no_std]

//Mstatus register fields
pub const MPP_LOW: usize = 11;
pub const MPP_HIGH: usize = 12;
pub const MPP_MASK: usize = 3; // i.e. 2 bits - TODO: simplify this stuff.
pub const MPIE: usize = 7;
pub const PMP_SHIFT: u64 = 2;

//uart base address
pub const SERIAL_PORT_BASE_ADDRESS: usize = 0x1000_0000;

//tyche monitor base address and size
pub const TYCHE_START_ADDRESS: u64 = 0x80100000;
pub const TYCHE_SIZE_NAPOT: u64 = 14; //If updating, check if TYCHE_STACK_POINTER needs to be updated too.

//tyche stack pointer
//Should be fine as long as Tyche size doesn't exceed half an MB.
//TODO: Need to protect it. Perhaps protect entire 1 MB memory region?
pub static TYCHE_STACK_POINTER: u64 = 0x80150000;

pub static mut SUP_STACK_POINTER: u64 = 0;

//Medeleg Register Fields or possible MCAUSE values
pub const ECALL_FROM_UMODE: u64 = 8;
pub const ECALL_FROM_SMODE: u64 = 9;
pub const ILLEGAL_INSTRUCTION: u64 = 2;

//SBI Trap Related
pub const TYCHE_SBI_VERSION: u64 = 0x10001;
pub const SBI_ECALL_IMPID: u64 = 0x1;
pub const SBI_EXT_BASE: u64 = 0x10;
pub const SBI_EXT_BASE_GET_SPEC_VERSION: u64 = 0;
pub const SBI_EXT_BASE_GET_IMP_ID: u64 = 1;
pub const SBI_EXT_BASE_GET_IMP_VERSION: u64 = 2;
pub const SBI_EXT_BASE_PROBE_EXT: u64 = 3;
pub const SBI_EXT_BASE_GET_MVENDORID: u64 = 4;
pub const SBI_EXT_BASE_GET_MARCHID: u64 = 5;
pub const SBI_EXT_BASE_GET_MIMPID: u64 = 6;
pub const SBI_EXT_TIME: u64 = 0x54494D45;
pub const SBI_EXT_IPI: u64 = 0x735049;
pub const SBI_EXT_RFENCE: u64 = 0x52464E43;
pub const SBI_EXT_SRST: u64 = 0x53525354;
pub const SBI_EXT_HSM: u64 = 0x48534D;
pub const SBI_ECALL_VERSION_MINOR: u64 = 0;
pub const SBI_ECALL_VERSION_MAJOR: u64 = 1;
pub const SBI_SPEC_VERSION_MAJOR_MASK: u64 = 0x7f;
pub const SBI_SPEC_VERSION_MAJOR_OFFSET: u64 = 24;

pub struct Register_State {
    pub ra: u64,
    pub a0: u64,
    pub a1: u64,
    pub a2: u64,
    pub a3: u64,
    pub a4: u64,
    pub a5: u64,
    pub a6: u64,
    pub a7: u64,
    pub t0: u64,
    pub t1: u64,
    pub t2: u64,
    pub t3: u64,
    pub t4: u64,
    pub t5: u64,
    pub t6: u64,
    pub zero: u64,
    pub gp: u64,
    pub tp: u64,
    pub s0: u64,
    pub s1: u64,
    pub s2: u64,
    pub s3: u64,
    pub s4: u64,
    pub s5: u64,
    pub s6: u64,
    pub s7: u64,
    pub s8: u64,
    pub s9: u64,
    pub s10: u64,
    pub s11: u64,
    //pub mepc: u64,
    //pub mstatus: u64,
}

impl Register_State {
    pub const fn const_default() -> Register_State {
        Register_State {
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
