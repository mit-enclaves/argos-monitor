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
pub const TYCHE_SIZE_NAPOT: u64 = 14;   //If updating, check if TYCHE_STACK_POINTER needs to be updated too. 

//tyche stack pointer
//Should be fine as long as Tyche size doesn't exceed half an MB.  
//TODO: Need to protect it. Perhaps protect entire 1 MB memory region? 
pub static TYCHE_STACK_POINTER: u64 = 0x80150000;

pub static mut SUP_STACK_POINTER: u64 = 0;

//Medeleg Register Fields
pub const ECALL_FROM_UMODE: usize = 8;

pub struct Register_State { 
    pub ra: u64,
    pub sp: u64,
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
}

impl Register_State { 
    pub const fn const_default() -> Register_State { 
        Register_State{ ra:0, sp:0, a0:0, a1:0, a2:0, a3:0, a4:0, a5:0, a6:0, a7:0, t0:0, t1:0, t2:0, t3:0, t4:0, t5:0, t6:0 }
    }
}

impl Default for Register_State {
    fn default () -> Register_State { 
        Register_State::const_default()
    }
}

