//! Second-stage
#![no_std]
#![feature(fn_align)]
#![feature(naked_functions)]

pub mod allocator;
mod calls;
pub mod debug;
pub mod error;
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

