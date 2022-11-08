//! Risc-V backend

pub mod guest;

use crate::debug::ExitCode;
use crate::hypercalls::{Backend, DomainArena, DomainHandle, HypercallResult};
use crate::statics;
use core::arch::asm;
use mmu::FrameAllocator;
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

    fn identity_add(
        &mut self,
        allocator: &impl FrameAllocator,
        ept: usize,
        start: usize,
        end: usize,
    ) -> Result<(), vmx::VmxError> {
        todo!();
    }

    fn identity_remove(
        &mut self,
        allocator: &impl FrameAllocator,
        ept: usize,
        start: usize,
        end: usize,
    ) -> Result<(), vmx::VmxError> {
        todo!();
    }

    fn transition(&self, handle: DomainHandle, domains: &DomainArena) -> HypercallResult {
        todo!();
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
