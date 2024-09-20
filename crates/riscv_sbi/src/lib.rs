#![no_std]
#![feature(fn_align)]
#![feature(naked_functions)]

//SBI Trap Related

pub mod ecall;
pub mod ipi;
pub mod rfence;

pub const TYCHE_SBI_VERSION: usize = 0x10002;
pub const ECALL_IMPID: usize = 0x1;
pub const ECALL_VERSION_MINOR: usize = 0;
pub const ECALL_VERSION_MAJOR: usize = 1;
pub const SPEC_VERSION_MAJOR_MASK: usize = 0x7f;
pub const SPEC_VERSION_MAJOR_OFFSET: usize = 24;

pub mod sbi {
    pub const EXT_PUTCHAR_LEGACY: usize = 0x1;
    pub const EXT_BASE: usize = 0x10;
    pub const EXT_TIME: usize = 0x54494D45;
    pub const EXT_IPI: usize = 0x735049;
    pub const EXT_RFENCE: usize = 0x52464E43;
    pub const EXT_SRST: usize = 0x53525354;
    pub const EXT_HSM: usize = 0x48534D;
}

pub mod sbi_ext_base {
    pub const GET_SPEC_VERSION: usize = 0;
    pub const GET_IMP_ID: usize = 1;
    pub const GET_IMP_VERSION: usize = 2;
    pub const PROBE_EXT: usize = 3;
    pub const GET_MVENDORID: usize = 4;
    pub const GET_MARCHID: usize = 5;
    pub const GET_MIMPID: usize = 6;
    pub const PMU_EXT: usize = 0x504D55;
}

pub mod sbi_ext_hsm {
    pub const HART_START: usize = 0;
    pub const HART_STOP: usize = 1;
    pub const HART_GET_STATUS: usize = 2;
    pub const HART_SUSPEND: usize = 3;
}

pub mod sbi_ext_ipi {
    pub const SEND_IPI: usize = 0;
}

pub mod sbi_ext_rfence {
    pub const REMOTE_FENCE_I: usize = 0;
    pub const REMOTE_SFENCE_VMA: usize = 1;
    pub const REMOTE_SFENCE_VMA_ASID: usize = 2;
}

#[derive(Debug, Clone, Copy)]
pub enum IPIRequest {
    SMode,
    RfenceSfenceVMAASID {
        src_hartid: usize,
        start: usize,
        size: usize,
        asid: usize,
    },
    RfenceIfence {
        src_hartid: usize,
    },
}

impl core::fmt::Display for IPIRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IPIRequest::SMode => write!(f, "SMode IPI"),
            IPIRequest::RfenceSfenceVMAASID { src_hartid, .. } => {
                write!(f, "Sfence VMA ASID from hart {}", src_hartid)
            }
            IPIRequest::RfenceIfence { src_hartid } => {
                write!(f, "Ifence from hart {}", src_hartid)
            }
        }
    }
}
