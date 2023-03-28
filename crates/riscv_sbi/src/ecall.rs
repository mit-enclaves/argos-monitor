use core::arch::asm;

use qemu::println;

use crate::{sbi, TYCHE_SBI_VERSION};

pub fn ecall_handler(mut ret: &mut usize, mut err: &mut usize, a0: usize, a6: usize, a7: usize) {
    //println!("ecall handler a7: {:x}",a7);
    match a7 {
        sbi::EXT_BASE => sbi_ext_base_handler(&mut ret, &mut err, a0, a6),
        _ => ecall_handler_failed(),
    }
}

// ------------------------------- SBI BASE CALL HANDLER and HELPERS ----------------------- //
pub fn sbi_ext_base_handler(ret: &mut usize, _err: &mut usize, a0: usize, a6: usize) {
    //let mut a6: usize;
    //unsafe { asm!("mv {}, a6", out(reg) a6); }
    //println!("base_handler a6: {:x}",a6);
    match a6 {
        sbi::EXT_BASE_GET_SPEC_VERSION => *ret = get_sbi_spec_version(),
        sbi::EXT_BASE_GET_IMP_ID => *ret = sbi::ECALL_IMPID,
        sbi::EXT_BASE_GET_IMP_VERSION => *ret = TYCHE_SBI_VERSION,
        sbi::EXT_BASE_GET_MVENDORID | sbi::EXT_BASE_GET_MARCHID | sbi::EXT_BASE_GET_MIMPID => {
            *ret = get_m_x_id(a6)
        }
        sbi::EXT_BASE_PROBE_EXT => *ret = probe(a0),
        _ => ecall_handler_failed(),
    }
}

pub fn get_sbi_spec_version() -> usize {
    let mut spec_ver: usize;

    spec_ver = (sbi::ECALL_VERSION_MAJOR << sbi::SPEC_VERSION_MAJOR_OFFSET)
        & (sbi::SPEC_VERSION_MAJOR_MASK << sbi::SPEC_VERSION_MAJOR_OFFSET);
    spec_ver |= sbi::ECALL_VERSION_MINOR;
    //println!("Computed spec_version: {:x}",spec_ver);
    return spec_ver;
}

pub fn probe(a0: usize) -> usize {
    //println!("probing a0 {:x}",a0);
    let mut ret: usize = 0;

    match a0 {
        sbi::EXT_TIME | sbi::EXT_IPI | sbi::EXT_HSM => {
            ret = 1;
            println!("PROBING sbi::EXT_TIME/IPI/HSM.")
        }
        //Handlers for the corresponding ecall are not yet implemented.
        sbi::EXT_RFENCE => {
            ret = 1;
            println!("PROBING sbi::EXT_RFENCE")
        }
        sbi::EXT_SRST => ret = sbi_ext_srst_probe(a0),
        _ => ecall_handler_failed(),
    }

    //println!("Returning from probe {}",ret);

    return ret;
}

pub fn get_m_x_id(a6: usize) -> usize {
    let mut ret: usize = 0;
    match a6 {
        sbi::EXT_BASE_GET_MVENDORID => unsafe {
            asm!("csrr {}, mvendorid", out(reg) ret);
        },
        sbi::EXT_BASE_GET_MARCHID => unsafe {
            asm!("csrr {}, marchid", out(reg) ret);
        },
        sbi::EXT_BASE_GET_MIMPID => unsafe {
            asm!("csrr {}, mimpid", out(reg) ret);
        },
        _ => println!("Invalid get_m_x_id request!"),
    }
    //println!("Returning m_x_id {:x}",ret);
    return ret;
}

pub fn sbi_ext_srst_probe(_a0: usize) -> usize {
    //TODO For now this function pretends that srst extension probe works as expected.
    //If needed in the future, this must be implemented fully - refer to openSBI for this.
    return 1;
}

pub fn ecall_handler_failed() {
    //TODO: Print information about requested ecall.
    println!("Cannot service SBI ecall - invalid ecall.");
}
