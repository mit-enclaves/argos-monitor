#![no_std]
//RISC-V PMP Configuration.

use core::arch::asm;

pub const PMP_SHIFT: usize = 2; //Neelu: TONOTNEEDEDDO: Rename this. used in pmpaddr_write.
const PMP_ENTRIES: usize = 16; 

//The number of PMP entries used to protect for instance memory mapped CSRs related to interrupts,
//in this case, 1 entry for SiFive CLINT (the highest priority entry) 
const FROZEN_PMP_ENTRIES: usize = 1; 

const PMP_CFG: usize = 0; 
const PMP_ADDR: usize = 1; 

const XWR_MASK: usize = 7; 
const RV64_PAGESIZE: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(usize)]
pub enum PMPAddressingMode { 
    pub const NULL: usize = 0,   
    pub const TOR: usize = 1,
    pub const NA4: usize = 2, 
    pub const NAPOT: usize = 3,
}

#[derive(Debug, Clone, Copy, PartialEq)]
#[repr(usize)]
pub enum PMPErrorCode: usize {
    Success = 1,
    InvalidCSRID = 2,
    NotPageAligned = 3,
    InvalidPermissions = 4,
    InvalidIndex = 5,
}

//The csr_id is explicitly providing support to only read either pmpcfg or pmpaddr. Todo: Is this useful? 
pub fn pmp_read(csr_id: usize, csr_index: usize) -> (usize, PMPErrorCode) { 
    let mut ret: usize = 0; 
    let mut ret_code: PMPErrorCode = PMPErrorCode::Success;
    //This will ensure that the index is in expected range
    if csr_index < 0 || csr_index >= PMP_ENTRIES  { 
        return (0, PMPErrorCode::InvalidIndex); 
    }

    match csr_id {
        PMP_CFG => {ret = pmpcfg_read(csr_index);},
        PMP_ADDR => {ret = pmpaddr_read(csr_index);},
        _ => {ret_code = PMPErrorCode::InvalidCSRID;}
    }
    return (ret, ret_code);
}

//Returns PMP addressing mode and PMPErrorCode
pub fn pmp_write(csr_index: usize, region_addr: usize, region_size:usize, region_perm: usize) -> (PMPAddressingMode, PMPErrorCode) { 
    //This will ensure that the index is in expected range
    if csr_index < 0 || csr_index >= PMP_ENTRIES { 
        return (PMPAddressingMode::NULL, PMPErrorCode::InvalidIndex);
    }
   
    //To enforce that the region_addr is the start of a page and the region_size is a multiple of
    //page_size. 
    if (!(region_addr & (RV64_PAGESIZE - 1)) && !(region_size & (RV64_PAGESIZE))) {
        return (PMPAddressingMode::NULL, PMPErrorCode::NotPageAligned);
    }

    if (region_perm & XWR_MASK != XWR_MASK) {
        return (PMPAddressingMode::NULL, PMPErrorCode::InvalidPermissions);
    }

    let mut pmpaddr: usize = 0;
    let mut pmpcfg: usize = 0; 
    let mut addressing_mode: PMPAddressingMode = PMPAddressingMode::NULL; 

    //Determine addressing mode: 
    //NAPOT addressing mode conditions: The region_addr must contain enough trailing zeroes to encode the region_size in the
    //pmpaddr register together with the address and the region_size is a power of two. 
    if (!(region_addr & (region_size - 1)) && !(region_size & (region_size - 1))) {
        pmpaddr = region_addr | ((region_size - 1) >> 3);
        addressing_mode = PMPAddressingMode::NAPOT; 
        pmpcfg = region_perm | (addressing_mode << 3);
        pmpcfg_write(csr_index, pmpcfg);
        asm!("csrw pmpaddr{}, {}", in(reg) csr_index, in(reg) pmpaddr);

    }
    else { //TOR addressing mode 
        if csr_index == (PMP_ENTRIES-1) {
            //Last PMP entry - Don't have enough PMP entries for protecting this region with TOR addressing mode. 
           return (PMPAddressingMode::NULL, PMPErrorCode::InvalidIndex);
        }
        let csr_index_2: usize = csr_index + 1;
        //Initialize two PMP entries 
        //First PMP entry (index i) contains the top address and pmpcfg value
        pmpaddr = (region_addr + region_size) >> 2; //TODO: Does this need to be generic or can we assume a fixed
                                    //PMP granularity? 
        addressing_mode = PMPAddressingMode::TOR;
        pmpcfg = region_perm | (addressing_mode << 3); 
        pmpcfg_write(csr_index_2, pmpcfg);
        asm!("csrw pmpaddr{}, {}", in(reg) csr_index_2, in(reg) pmpaddr);

        //Second PMP entry (index i-1) contains the bottom address and pmpcfg = 0 
        pmpcfg = 0; 
        pmpaddr = region_addr >> 2; 
        pmpcfg_write(csr_index, pmpcfg);
        asm!("csrw pmpaddr{}, {}", in(reg) csr_index, in(reg) pmpaddr);
    }

    //Sfence after writing the PMP. 
    asm!("sfence.vma");

    return (addressing_mode, PMPErrorCode::Success); 
}

pub fn pmpcfg_update_perm(csr_index: usize, region_perm: usize) -> PMPErrorCode {

    let mut pmpcfg: usize = pmpcfg_read(csr_index); 

    pmpcfg = pmpcfg & (!XWR_MASK); 

    if (region_perm & XWR_MASK != XWR_MASK) {
        return PMPErrorCode::InvalidPermissions;
    }
 
    pmpcfg = pmpcfg | region_perm; 

    return pmpcfg_write(csr_index, pmpcfg); 
}

//Returns written value
fn tbdeprecated_pmpaddr_write(addr: usize, log2len: usize) -> usize {
    let addrmask: usize;
    let mut pmpaddr: usize;

    if log2len == PMP_SHIFT {
        pmpaddr = addr >> PMP_SHIFT;
    } else {
        // TONOTNEEDEDDO: Define __riscv_xlen
        // if log2len == __riscv_xlen {
        //       pmpaddr = -1;
        // } else {
        addrmask = (1usize << (log2len - PMP_SHIFT)) - 1;
        pmpaddr = (addr >> PMP_SHIFT) & !addrmask;
        pmpaddr |= addrmask >> 1;
        // }
    }

    //TONOTNEEDEDDO: Write pmpaddr"index" instead of 1 in the following code while making it generic.
    unsafe {
        asm!("csrw pmpaddr1, {}", in(reg) pmpaddr);
    }

    return pmpaddr;
}

//Returns read value 
fn pmpaddr_read(index: usize) -> usize { 
    let pmpaddr: usize = 0; 
    unsafe { asm!("csrr {}, pmpaddr{}", out(reg) pmpaddr, in(reg) index); } 
    return pmpaddr;
}

//Returns read value from pmpcfg[n] 
fn pmpcfg_read(index: usize) -> usize { 
    
    let mut ret: usize = 0; 
    let mut pmpcfg: usize = 0;

    //The following code supports 64 PMP entries regardless of the value of PMP_ENTRIES. The
    //check in pmp_read is what will ensure that the index is valid. The following code should
    //execute only if that check passes, and thus should not access an index which shouldn't be supported. 
  

    /* if index >= 0 && index <= 7 { 
        unsafe { asm!("csrr {}, pmpcfg0", out(reg) pmpcfg);} 
    } else if index >= 8 && index <= 15 { 
        unsafe { asm!("csrr {}, pmpcfg2", out(reg) pmpcfg);}
    } else if index >= 16 && index <= 23 { 
        unsafe { asm!("csrr {}, pmpcfg4", out(reg) pmpcfg);}
    } else if index >= 24 && index <= 31 { 
        unsafe { asm!("csrr {}, pmpcfg6", out(reg) pmpcfg);}
    } else if index >= 32 && index <= 39 {
        unsafe { asm!("csrr {}, pmpcfg8", out(reg) pmpcfg);}
    } else if index >= 40 && index <= 47 {
        unsafe { asm!("csrr {}, pmpcfg10", out(reg) pmpcfg);}
    } else if index >= 48 && index <= 55 {
        unsafe { asm!("csrr {}, pmpcfg12", out(reg) pmpcfg);}
    } else if index >= 56 && index <= 63 {
        unsafe { asm!("csrr {}, pmpcfg14", out(reg) pmpcfg);}
    }*/
  
    //Need to extract the pmpcfg value based on the index. Assumes 8 bit pmpcfg as specified in the
    //RV Specification Vol 2 - Privileged Arch. 

    let pmpcfg_id: usize = (index/8)*2;

    unsafe { asm!("csrr {}, pmpcfg{}", out(reg) pmpcfg, in(reg) pmpcfg_id);}
 
    let index_pos: usize = index % 8; 
    let pmpcfg_mask: usize = 0xff << (index_pos*8);

    pmpcfg = (pmpcfg & pmpcfg_mask) >> (index_pos*8); 

    return pmpcfg; 
}

fn pmpcfg_write(index: usize, value: usize) -> PMPErrorCode { 
    let mut pmpcfg: usize = 0; 
    let pmpcfg_id: usize = (index/8)*2;

    unsafe { asm!("csrr {}, pmpcfg{}", out(reg) pmpcfg, in(reg) pmpcfg_id);}

    let index_pos: usize = index % 8; 

    let pmpcfg_mask: usize =  0xff << (index_pos*8);
    pmpcfg = pmpcfg & !(pmpcfg_mask); 

    pmpcfg = pmpcfg | (value << (index_pos*8));

    unsafe { asm!("csrw pmpcfg{}, {}", in(reg) pmpcfg_id, in(reg) pmpcfg); }
    //TODO: Should I read it back and double check or will that be redundant? 

    //Sfence after writing the PMP. 
    asm!("sfence.vma");

    return PMPErrorCode::Success;

}
