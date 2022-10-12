//! Second-stage
#![no_std]

use core::arch::asm;
use stage_two_abi::Manifest;

pub mod hypercalls;
pub mod allocator;
mod arch;
mod arena;
pub mod debug;
pub mod guest;
pub mod statics;

pub fn init(manifest: &Manifest<statics::Statics>) {
    unsafe {
        set_cr3(manifest.cr3);
    }
}

unsafe fn set_cr3(cr3: u64) {
    asm!(
        "mov cr3, {}",
        in(reg) cr3,
        options(nomem, nostack, preserves_flags)
    );
    arch::init();
}

/// Halt the CPU in a spinloop;
pub fn hlt() -> ! {
    loop {
        unsafe { core::arch::x86_64::_mm_pause() };
    }
}
