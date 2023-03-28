#![no_std]

//mstatus register fields. mask for fields with width > 1 bit.
pub mod mstatus {
    pub const MPP_LOW: usize = 11;
    pub const MPP_HIGH: usize = 12;
    pub const MPP_MASK: usize = 0x3; // 2 bits
    pub const MPIE: usize = 7;
    pub const MPRV: usize = 17;
}

//MEDELEG register fields or mcause register valid values.
pub mod mcause {
    pub const ILLEGAL_INSTRUCTION: usize = 2;
    pub const ECALL_FROM_UMODE: usize = 8;
    pub const ECALL_FROM_SMODE: usize = 9;
}
