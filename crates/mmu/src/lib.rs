//! Memory Management Unit

#![no_std]
pub mod eptmapper;
pub mod frame_allocator;
pub mod ioptmapper;
pub mod ptmapper;
pub mod walker;

pub use eptmapper::EptMapper;
pub use frame_allocator::FrameAllocator;
pub use ioptmapper::{IoPtFlag, IoPtMapper};
pub use ptmapper::{PtFlag, PtMapper};
