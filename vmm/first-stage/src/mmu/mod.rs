//! Memory Management unit

pub mod frames;

pub use frames::{get_physical_memory_offset, init, MemoryMap, PAGE_SIZE};
