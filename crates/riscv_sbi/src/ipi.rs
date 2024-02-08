use core::arch::asm;
use core::sync::atomic::Ordering;
use riscv_utils::{ACLINT_MSWI_BASE_ADDR, ACLINT_MSWI_WORD_SIZE, set_mip_ssip, HART_IPI_SYNC};
use crate::{IPIRequest, ecall::HART_IPI_BUFFER, rfence::local_sfence_vma_asid};

pub fn aclint_mswi_send_ipi(target_hartid: usize) {
    let target_addr: usize = ACLINT_MSWI_BASE_ADDR + target_hartid * ACLINT_MSWI_WORD_SIZE;
    unsafe {
        asm!("sw {}, 0({})", in(reg) 1, in(reg) target_addr);
    }
}

pub fn aclint_mswi_clear_ipi(target_hartid: usize) {
    let target_addr: usize = ACLINT_MSWI_BASE_ADDR + target_hartid * ACLINT_MSWI_WORD_SIZE;
    unsafe {
        asm!("sw {}, 0({})", in(reg) 0, in(reg) target_addr);
    }
}

pub fn process_ipi(current_hartid: usize) {

    aclint_mswi_clear_ipi(current_hartid);

    let mut ipi_requests = HART_IPI_BUFFER[current_hartid].lock(); 

    while let Some(ipi_req) = ipi_requests.pop() {
        match ipi_req { 
            IPIRequest::SMode => {
                set_mip_ssip();
            } 
            IPIRequest::RfenceSfenceVMAASID {
                src_hartid, start, size, asid,
            } => {
                local_sfence_vma_asid(start, size, asid);
                HART_IPI_SYNC[src_hartid].fetch_sub(1, Ordering::SeqCst);
            },
            _ => ipi_handling_failed(),
        }
    }
}

pub fn ipi_handling_failed() {
    log::debug!("Cannot handle IPI!");
}
