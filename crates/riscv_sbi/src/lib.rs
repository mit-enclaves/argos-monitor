#![no_std]
#![feature(fn_align)]
#![feature(naked_functions)]

//SBI Trap Related

pub mod ecall;

pub const TYCHE_SBI_VERSION: usize = 0x10001;

pub mod sbi {
    pub const ECALL_IMPID: usize = 0x1;
    pub const ECALL_VERSION_MINOR: usize = 0;
    pub const ECALL_VERSION_MAJOR: usize = 1;
    pub const SPEC_VERSION_MAJOR_MASK: usize = 0x7f;
    pub const SPEC_VERSION_MAJOR_OFFSET: usize = 24;
    pub const EXT_BASE: usize = 0x10;
    pub const EXT_TIME: usize = 0x54494D45;
    pub const EXT_IPI: usize = 0x735049;
    pub const EXT_RFENCE: usize = 0x52464E43;
    pub const EXT_SRST: usize = 0x53525354;
    pub const EXT_HSM: usize = 0x48534D;
    pub const EXT_BASE_GET_SPEC_VERSION: usize = 0;
    pub const EXT_BASE_GET_IMP_ID: usize = 1;
    pub const EXT_BASE_GET_IMP_VERSION: usize = 2;
    pub const EXT_BASE_PROBE_EXT: usize = 3;
    pub const EXT_BASE_GET_MVENDORID: usize = 4;
    pub const EXT_BASE_GET_MARCHID: usize = 5;
    pub const EXT_BASE_GET_MIMPID: usize = 6;
}
