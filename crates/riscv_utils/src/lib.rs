#![no_std]

//Mstatus register fields
pub const MPP_LOW: usize = 11;
pub const MPP_HIGH: usize = 12;
pub const MPP_MASK: usize = 3;
pub const MPIE: usize = 7;
pub const PMP_SHIFT: u64 = 2;

//uart base address
pub const SERIAL_PORT_BASE_ADDRESS: usize = 0x1000_0000; 

//tyche monitor base address and size
pub const TYCHE_START_ADDRESS: u64 = 0x80100000;
pub const TYCHE_SIZE_NAPOT: u64 = 14;

