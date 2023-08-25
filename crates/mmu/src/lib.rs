//! Memory Management Unit

#![no_std]
pub mod frame_allocator;
pub mod ptmapper;
pub mod walker;

pub use frame_allocator::{FrameAllocator, RangeAllocator};
pub use ptmapper::{PtFlag, PtMapper};

// ————————————————————————————————— x86_64 ————————————————————————————————— //
#[cfg(target_arch = "x86_64")]
pub mod ioptmapper;
#[cfg(target_arch = "x86_64")]
pub use ioptmapper::{IoPtFlag, IoPtMapper};
#[cfg(target_arch = "x86_64")]
pub mod eptmapper;
#[cfg(target_arch = "x86_64")]
pub use eptmapper::EptMapper;
