#![no_std]

//tyche monitor base address and size
pub const TYCHE_START_ADDRESS: usize = 0x80250000;
pub const TYCHE_SIZE_NAPOT: usize = 14;

//tyche stack pointer
//Should be fine as long as Tyche size doesn't exceed half an MB.
//TODO: Need to protect it. Perhaps protect entire 1 MB memory region?
pub static TYCHE_STACK_POINTER: [usize; 4] = [0x80390000, 0x8038b000, 0x80386000, 0x80381000];

pub const DOM0_ROOT_REGION_START: usize = 0x80400000;
pub const DOM0_ROOT_REGION_END: usize = 0x800000000;

#[repr(C)]
pub struct RVManifest {
    pub next_arg1: usize,
    pub next_addr: usize,
    pub next_mode: usize,
    pub coldboot_hartid: usize,
    pub num_harts: usize,
}

// For the VF2 board  
pub const VF2_TYCHE_START_ADDRESS: usize = 0x23fa00000;
pub const VF2_TYCHE_STACK_POINTER: [usize; 5] = [0x23ffff000, 0x23fffb000, 0x23fff8000, 0x23fff4000, 0x23fff0000];

pub const VF2_DOM0_ROOT_REGION_START: usize = 0x40200000;
pub const VF2_DOM0_ROOT_REGION_END: usize = 0x23fa00000;

//pub const VF2_DOM0_ROOT_REGION_END: usize = 0xffffffffffffffff;

//This one includes cache controller, plic, pcie, syscon. (Basically overprivileged to confine it to 1 PMP)
//pub const VF2_DOM0_ROOT_REGION_2_START: usize = 0x2010000;  
//pub const VF2_DOM0_ROOT_REGION_2_END: usize = 0x2bffffff;
//
//Question is: Do I care about protecting opensbi's memory at this point? No - clear it out and
//then let linux have it back! Basically, doesn't need to be reserved in the FDT either!  
//Then we should just use 1 PMP entry (start: 0x0, end: tyche_start_addr)
pub const VF2_DOM0_ROOT_REGION_2_START: usize = 0x0; 
pub const VF2_DOM0_ROOT_REGION_2_END: usize = 0x3fffffff;
