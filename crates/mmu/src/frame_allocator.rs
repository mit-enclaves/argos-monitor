//! The trait for the FrameAllocator used in both stage 1 and 2.

use utils::{Frame, HostPhysAddr, HostVirtAddr};

pub unsafe trait FrameAllocator {
    /// Allocates a frame.
    fn allocate_frame(&self) -> Option<Frame>;

    /// Allocates a range of physical memory.
    fn allocate_range(&self, size: usize) -> Option<PhysRange>;

    /// Frees a frame.
    fn free_frame(&self) -> Result<(), ()> {
        // Default implementation: leak all the pages
        Ok(())
    }

    /// Returns the boundaries of usable physical memory.
    fn get_boundaries(&self) -> (usize, usize);

    /// Returns the offset between physical and virtual addresses.
    fn get_physical_offset(&self) -> HostVirtAddr;
}

#[derive(Debug, Clone, Copy)]
/// A range of physical memory.
pub struct PhysRange {
    /// Start of the physical range (inclusive).
    pub start: HostPhysAddr,
    /// End of the physical range (exclusive).
    pub end: HostPhysAddr,
}

impl PhysRange {
    pub fn size(&self) -> usize {
        (self.end.as_u64() - self.start.as_u64()) as usize
    }
}
