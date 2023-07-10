#![no_std]

//tyche monitor base address and size
pub const TYCHE_START_ADDRESS: usize = 0x80100000;
pub const TYCHE_SIZE_NAPOT: usize = 14;

//tyche stack pointer
//Should be fine as long as Tyche size doesn't exceed half an MB.
//TODO: Need to protect it. Perhaps protect entire 1 MB memory region?
pub static TYCHE_STACK_POINTER: usize = 0x80150000;

pub static mut SMODE_STACK_POINTER: usize = 0;
