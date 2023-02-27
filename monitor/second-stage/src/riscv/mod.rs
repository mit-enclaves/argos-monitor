//! Risc-V backend

// TODO: remove this once the backend is implemented.
// The line just removes the unused warnings.
#![allow(unused)]

mod arch;
pub mod backend;
pub mod guest;

use core::arch::asm;

pub use guest::launch_guest;
use mmu::FrameAllocator;

use crate::debug::qemu::ExitCode;
use crate::statics::{allocator, pool};

// TODO: some empty types to be filled.
#[derive(Debug)]
pub enum BackendError {}

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
pub fn init() {
    arch::init();
}

pub fn cpuid() -> usize {
    todo!();
}
