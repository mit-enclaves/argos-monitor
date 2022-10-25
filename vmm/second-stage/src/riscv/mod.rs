//! Risc-V backend

pub mod guest;

use crate::debug::ExitCode;
use crate::hypercalls::{Backend, HypercallResult};
use crate::statics;
use core::arch::asm;
use stage_two_abi::Manifest;

pub struct Arch {}

impl Arch {
    pub fn new(_iommu_addr: u64) -> Self {
        Self {}
    }
}

impl Backend for Arch {
    fn debug_iommu(&mut self) -> HypercallResult {
        // No I/O MMU with Risc-V backend
        Ok(Default::default())
    }
}

/// Halt the CPU in a spinloop;
pub fn hlt() -> ! {
    loop {
        // See core::arch::asm::riscv64:
        //
        // The PAUSE instruction is a HINT that indicates the current hart's rate of instruction retirement
        // should be temporarily reduced or paused. The duration of its effect must be bounded and may be zero.
        unsafe { asm!(".insn i 0x0F, 0, x0, x0, 0x010", options(nomem, nostack)) }
    }
}

pub fn exit_qemu(exit_code: ExitCode) {
    // TODO: find exit address
    const RISCV_EXIT_ADDR: u64 = 0xdeadbeef;

    unsafe {
        let exit_code = exit_code as u32;
        asm!(
            "sw {0}, 0({1})",
            in(reg) exit_code,
            in(reg) RISCV_EXIT_ADDR
        );
    }
}

/// Architecture specific initialization.
pub fn init(_manifest: &Manifest<statics::Statics>) {
    // TODO
}
