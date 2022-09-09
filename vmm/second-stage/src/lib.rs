//! Second-stage
#![no_std]

pub mod debug;

pub fn init() {}

/// Halt the CPU in a spinloop;
pub fn hlt() -> ! {
    loop {
        unsafe { core::arch::x86_64::_mm_pause() };
    }
}
