//! Memory Management Unit
#![no_std]

pub mod frame_allocator;
pub mod ptmapper;
pub mod ioptmapper;
pub mod walker;

pub use frame_allocator::{FrameAllocator, RangeAllocator};
pub use ioptmapper::{IoPtFlag, IoPtMapper};
pub use ptmapper::{PtFlag, PtMapper};

// ————————————————————————————————— x86_64 ————————————————————————————————— //
#[cfg(target_arch = "x86_64")]
pub mod eptmapper;
#[cfg(target_arch = "x86_64")]
pub use eptmapper::EptMapper;
