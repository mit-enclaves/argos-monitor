//! Second-stage
#![no_std]

use stage_two_abi::Manifest;

pub mod allocator;
pub mod debug;
pub mod error;
pub mod guest;
pub mod statics;

#[cfg(target_arch = "riscv64")]
pub mod riscv;
#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub mod arch {
    pub use crate::x86_64::*;
}

#[cfg(target_arch = "riscv64")]
pub mod arch {
    pub use crate::riscv::*;
}

pub fn init(manifest: &Manifest, cpuid: usize) {
    arch::init(manifest, cpuid);
}
