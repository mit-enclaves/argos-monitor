//! Second-stage
#![no_std]

use stage_two_abi::Manifest;

pub mod allocator;
mod arena;
pub mod debug;
pub mod guest;
pub mod hypercalls;
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

pub fn init(manifest: &Manifest<statics::Statics<arch::Arch>>) {
    arch::init(manifest);
}
